//! Script execution: one interpreter process per dispatch, fed from a
//! temporary file, killed at the timeout, with bounded output capture.
//!
//! Remotely keeps a long-lived shell per connection and writes commands to its
//! stdin (`Agent/Services/ExternalScriptingShell.cs`), which is right for an
//! interactive terminal but leaks state between runs. For scheduled and ad-hoc
//! RMM scripts a fresh process per run (the Tactical RMM agent model, idea
//! only) gives a clean environment, a real exit code and a timeout that cannot
//! wedge the next script. Remotely's `AppConstants.ScriptRunExpirationMinutes`
//! inspired the default timeout.

use std::path::PathBuf;
use std::process::Stdio;
use std::time::{Duration, Instant};

use omegadesk_protocol::control::v1 as control;
use rand_core::{OsRng, RngCore};
use tokio::io::AsyncReadExt;
use tokio::process::Command;
use tracing::warn;

/// Bytes of stdout and of stderr kept per run; the rest is drained and dropped.
pub const MAX_OUTPUT_BYTES: usize = 64 * 1024;

/// Timeout applied when the dispatch carries none.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(300);

/// After a kill, how long the output readers may wait for a grandchild that
/// still holds the pipes before they are abandoned.
const DRAIN_AFTER_KILL: Duration = Duration::from_secs(3);

/// Terminates the interpreter together with every process it started: a shell
/// killed alone leaves `ping`, `sleep` or an installer running and holding the
/// output pipes. Windows uses a job object with `KILL_ON_JOB_CLOSE` (the same
/// mechanism the Cargo jobserver and Tactical RMM's Go agent rely on); Unix puts
/// the interpreter in its own process group and signals the group.
mod tree {
    #[cfg(windows)]
    pub(super) use windows_impl::ProcessTree;

    #[cfg(unix)]
    pub(super) use unix_impl::ProcessTree;

    #[cfg(windows)]
    mod windows_impl {
        #![allow(unsafe_code, reason = "Win32 job object APIs")]

        use std::ffi::c_void;

        use windows::Win32::Foundation::{CloseHandle, HANDLE};
        use windows::Win32::System::JobObjects::{
            AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
            SetInformationJobObject, TerminateJobObject,
        };
        use windows::core::PCWSTR;

        /// A job object the interpreter is assigned to right after it spawns.
        /// The handle is kept as an address so the owning future stays `Send`.
        pub(in super::super) struct ProcessTree {
            job: Option<usize>,
        }

        fn handle(address: usize) -> HANDLE {
            HANDLE(std::ptr::with_exposed_provenance_mut(address))
        }

        impl ProcessTree {
            pub(in super::super) fn prepare(_command: &mut tokio::process::Command) {}

            pub(in super::super) fn attach(child: &tokio::process::Child) -> Self {
                let Some(raw) = child.raw_handle() else {
                    return Self { job: None };
                };
                // SAFETY: anonymous job object with default security attributes.
                let created = unsafe { CreateJobObjectW(None, PCWSTR::null()) };
                let Ok(job) = created else {
                    return Self { job: None };
                };
                let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
                info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
                let size =
                    u32::try_from(size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>()).unwrap_or(0);
                // SAFETY: `info` is a valid extended limit block of `size` bytes.
                let configured = unsafe {
                    SetInformationJobObject(
                        job,
                        JobObjectExtendedLimitInformation,
                        (&raw const info).cast::<c_void>(),
                        size,
                    )
                };
                // SAFETY: `raw` is the live process handle tokio holds for the child.
                let assigned =
                    unsafe { AssignProcessToJobObject(job, HANDLE(raw.cast::<c_void>())) };
                if configured.is_err() || assigned.is_err() {
                    // SAFETY: `job` was created above and is closed exactly once.
                    let _ = unsafe { CloseHandle(job) };
                    return Self { job: None };
                }
                Self {
                    job: Some(job.0.expose_provenance()),
                }
            }

            pub(in super::super) fn kill(&self) {
                if let Some(job) = self.job {
                    // SAFETY: `job` is open; terminating it ends every assigned process.
                    let _ = unsafe { TerminateJobObject(handle(job), 1) };
                }
            }
        }

        impl Drop for ProcessTree {
            fn drop(&mut self) {
                if let Some(job) = self.job.take() {
                    // SAFETY: closes the handle we own; KILL_ON_JOB_CLOSE reaps any survivor.
                    let _ = unsafe { CloseHandle(handle(job)) };
                }
            }
        }
    }

    #[cfg(unix)]
    mod unix_impl {
        #![allow(unsafe_code, reason = "POSIX process group signalling")]

        /// The interpreter's process group (its pid, because of `setpgid(0, 0)`).
        pub(in super::super) struct ProcessTree {
            pgid: Option<i32>,
        }

        impl ProcessTree {
            pub(in super::super) fn prepare(command: &mut tokio::process::Command) {
                command.process_group(0);
            }

            pub(in super::super) fn attach(child: &tokio::process::Child) -> Self {
                Self {
                    pgid: child.id().and_then(|pid| i32::try_from(pid).ok()),
                }
            }

            pub(in super::super) fn kill(&self) {
                if let Some(pgid) = self.pgid
                    && pgid > 0
                {
                    // SAFETY: plain syscall; a negative pid addresses the whole group
                    // the interpreter was made leader of.
                    let _ = unsafe { libc::kill(-pgid, libc::SIGKILL) };
                }
            }
        }
    }
}

/// How a shell is invoked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Interpreter {
    /// Program name (resolved through `PATH`).
    pub program: &'static str,
    /// Arguments placed before the script path.
    pub args: &'static [&'static str],
    /// Extension of the temporary script file.
    pub extension: &'static str,
    /// Lines prepended to the script (UTF-8 output, code page).
    pub prelude: &'static str,
    /// Whether the file gets a UTF-8 BOM and CRLF line endings.
    pub windows_text: bool,
}

const POWERSHELL_PRELUDE: &str = "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; $OutputEncoding = [System.Text.Encoding]::UTF8\n";

/// Interpreter candidates for a shell, in order of preference.
#[must_use]
pub fn interpreters(shell: control::ScriptShell) -> Vec<Interpreter> {
    let ps_args: &'static [&'static str] = &[
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
    ];
    match shell {
        control::ScriptShell::Powershell => {
            let mut out = Vec::new();
            if cfg!(windows) {
                out.push(Interpreter {
                    program: "powershell.exe",
                    args: ps_args,
                    extension: ".ps1",
                    prelude: POWERSHELL_PRELUDE,
                    windows_text: true,
                });
            }
            // Off Windows the only PowerShell is Core.
            out.push(Interpreter {
                program: "pwsh",
                args: ps_args,
                extension: ".ps1",
                prelude: POWERSHELL_PRELUDE,
                windows_text: cfg!(windows),
            });
            out
        }
        control::ScriptShell::Pwsh => vec![Interpreter {
            program: "pwsh",
            args: ps_args,
            extension: ".ps1",
            prelude: POWERSHELL_PRELUDE,
            windows_text: cfg!(windows),
        }],
        control::ScriptShell::Sh => vec![
            Interpreter {
                program: "bash",
                args: &[],
                extension: ".sh",
                prelude: "",
                windows_text: false,
            },
            Interpreter {
                program: "sh",
                args: &[],
                extension: ".sh",
                prelude: "",
                windows_text: false,
            },
        ],
        control::ScriptShell::Cmd => vec![Interpreter {
            program: "cmd.exe",
            args: &["/D", "/C"],
            extension: ".cmd",
            prelude: "@chcp 65001 >nul\r\n",
            windows_text: true,
        }],
        control::ScriptShell::Unspecified => Vec::new(),
    }
}

fn script_file_contents(interpreter: &Interpreter, content: &str) -> Vec<u8> {
    let mut text = String::with_capacity(interpreter.prelude.len() + content.len() + 8);
    if interpreter.windows_text {
        text.push('\u{FEFF}');
    }
    text.push_str(interpreter.prelude);
    text.push_str(content);
    if !text.ends_with('\n') {
        text.push('\n');
    }
    if interpreter.windows_text {
        text = text.replace("\r\n", "\n").replace('\n', "\r\n");
    }
    text.into_bytes()
}

fn temp_script_path(run_id: u64, extension: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "omegadesk-rmm-{run_id}-{:016x}{extension}",
        OsRng.next_u64()
    ))
}

/// Reads at most `limit` bytes, draining the rest so the child never blocks on
/// a full pipe. Returns the kept bytes and whether output was truncated.
async fn read_bounded<R: AsyncReadExt + Unpin>(mut reader: R, limit: usize) -> (Vec<u8>, bool) {
    let mut kept = Vec::new();
    let mut truncated = false;
    let mut chunk = vec![0u8; 8192];
    loop {
        match reader.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                let room = limit.saturating_sub(kept.len());
                if n > room {
                    truncated = true;
                }
                kept.extend_from_slice(&chunk[..n.min(room)]);
            }
        }
    }
    (kept, truncated)
}

fn lossy(bytes: &[u8], truncated: bool) -> String {
    let mut text = String::from_utf8_lossy(bytes).into_owned();
    if truncated {
        text.push_str("\n[output truncated]");
    }
    text
}

fn failed_to_start(
    dispatch: &control::ScriptDispatch,
    error: impl std::fmt::Display,
) -> control::ScriptResult {
    control::ScriptResult {
        run_id: dispatch.run_id,
        script_id: dispatch.script_id.clone(),
        exit_code: -1,
        failed_to_start: true,
        error: error.to_string(),
        started_at_unix_secs: crate::inventory::unix_now(),
        ..Default::default()
    }
}

/// Runs `dispatch` and returns its result (never fails: every problem is a
/// `ScriptResult` with `failed_to_start`, `timed_out` or an exit code).
pub async fn run_script(
    dispatch: &control::ScriptDispatch,
    default_timeout: Duration,
) -> control::ScriptResult {
    let shell =
        control::ScriptShell::try_from(dispatch.shell).unwrap_or(control::ScriptShell::Unspecified);
    let candidates = interpreters(shell);
    if candidates.is_empty() {
        return failed_to_start(dispatch, "no interpreter for the requested shell");
    }
    let timeout = if dispatch.timeout_secs == 0 {
        default_timeout
    } else {
        Duration::from_secs(u64::from(dispatch.timeout_secs))
    };
    let mut last_error = String::new();
    for interpreter in &candidates {
        match run_with(interpreter, dispatch, timeout).await {
            Ok(result) => return result,
            Err(error) => last_error = format!("{}: {error}", interpreter.program),
        }
    }
    failed_to_start(dispatch, last_error)
}

/// Spawns `interpreter` on the dispatch; `Err` only when the process could not
/// be started (so the next candidate can be tried).
async fn run_with(
    interpreter: &Interpreter,
    dispatch: &control::ScriptDispatch,
    timeout: Duration,
) -> std::io::Result<control::ScriptResult> {
    let path = temp_script_path(dispatch.run_id, interpreter.extension);
    tokio::fs::write(&path, script_file_contents(interpreter, &dispatch.content)).await?;
    let mut command = Command::new(interpreter.program);
    command
        .args(interpreter.args)
        .arg(&path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    tree::ProcessTree::prepare(&mut command);
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            let _ = tokio::fs::remove_file(&path).await;
            return Err(error);
        }
    };
    let process_tree = tree::ProcessTree::attach(&child);
    let started_at = crate::inventory::unix_now();
    let started = Instant::now();
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let stdout_task = tokio::spawn(async move {
        match stdout {
            Some(reader) => read_bounded(reader, MAX_OUTPUT_BYTES).await,
            None => (Vec::new(), false),
        }
    });
    let stderr_task = tokio::spawn(async move {
        match stderr {
            Some(reader) => read_bounded(reader, MAX_OUTPUT_BYTES).await,
            None => (Vec::new(), false),
        }
    });

    let (exit_code, timed_out, error) = match tokio::time::timeout(timeout, child.wait()).await {
        Ok(Ok(status)) => (status.code().unwrap_or(-1), false, String::new()),
        Ok(Err(error)) => (-1, false, format!("wait failed: {error}")),
        Err(_) => {
            process_tree.kill();
            if let Err(error) = child.kill().await {
                warn!(run = dispatch.run_id, %error, "script could not be killed after its timeout");
            }
            (-1, true, format!("killed after {}s", timeout.as_secs()))
        }
    };
    let drain = if timed_out {
        DRAIN_AFTER_KILL
    } else {
        Duration::MAX
    };
    let (out_bytes, out_truncated) = match tokio::time::timeout(drain, stdout_task).await {
        Ok(Ok(output)) => output,
        Ok(Err(_)) | Err(_) => (Vec::new(), true),
    };
    let (err_bytes, err_truncated) = match tokio::time::timeout(drain, stderr_task).await {
        Ok(Ok(output)) => output,
        Ok(Err(_)) | Err(_) => (Vec::new(), true),
    };
    #[cfg(windows)]
    drop(process_tree);
    let _ = tokio::fs::remove_file(&path).await;

    Ok(control::ScriptResult {
        run_id: dispatch.run_id,
        script_id: dispatch.script_id.clone(),
        exit_code,
        stdout: lossy(&out_bytes, out_truncated),
        stderr: lossy(&err_bytes, err_truncated),
        started_at_unix_secs: started_at,
        duration_ms: u32::try_from(started.elapsed().as_millis()).unwrap_or(u32::MAX),
        timed_out,
        failed_to_start: false,
        error,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shell every CI runner has: `cmd.exe` on Windows, `sh` elsewhere.
    fn native_shell() -> control::ScriptShell {
        if cfg!(windows) {
            control::ScriptShell::Cmd
        } else {
            control::ScriptShell::Sh
        }
    }

    fn dispatch(
        run_id: u64,
        shell: control::ScriptShell,
        content: &str,
        timeout_secs: u32,
    ) -> control::ScriptDispatch {
        control::ScriptDispatch {
            run_id,
            script_id: "test".to_owned(),
            name: "test".to_owned(),
            shell: shell as i32,
            content: content.to_owned(),
            timeout_secs,
        }
    }

    #[tokio::test]
    async fn runs_a_script_and_captures_output_and_exit_code() {
        let script = if cfg!(windows) {
            "@echo rmm-stdout-ok\r\n@echo rmm-stderr-ok 1>&2\r\n@exit /b 3\r\n"
        } else {
            "echo rmm-stdout-ok\necho rmm-stderr-ok >&2\nexit 3\n"
        };
        let result = run_script(&dispatch(7, native_shell(), script, 30), DEFAULT_TIMEOUT).await;
        assert_eq!(result.run_id, 7);
        assert_eq!(result.script_id, "test");
        assert!(!result.failed_to_start, "{}", result.error);
        assert!(!result.timed_out);
        assert_eq!(result.exit_code, 3);
        assert!(
            result.stdout.contains("rmm-stdout-ok"),
            "{:?}",
            result.stdout
        );
        assert!(
            result.stderr.contains("rmm-stderr-ok"),
            "{:?}",
            result.stderr
        );
        assert!(result.started_at_unix_secs > 0);
    }

    #[tokio::test]
    async fn times_out_and_kills_the_interpreter() {
        let script = if cfg!(windows) {
            "@ping -n 30 127.0.0.1 >nul\r\n@echo never\r\n"
        } else {
            "sleep 30\necho never\n"
        };
        let started = Instant::now();
        let result = run_script(&dispatch(8, native_shell(), script, 1), DEFAULT_TIMEOUT).await;
        assert!(result.timed_out, "{result:?}");
        assert_eq!(result.exit_code, -1);
        assert!(!result.stdout.contains("never"));
        assert!(result.error.contains("killed after 1s"));
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "the whole process tree dies with the interpreter: {:?}",
            started.elapsed()
        );
    }

    #[tokio::test]
    async fn missing_interpreter_is_reported_not_panicked() {
        let shell = if cfg!(windows) {
            control::ScriptShell::Pwsh
        } else {
            control::ScriptShell::Cmd
        };
        // `pwsh` may exist on a developer machine; only assert the failure path on the
        // shell that cannot exist on this platform.
        if cfg!(windows) {
            let result = run_script(
                &dispatch(9, control::ScriptShell::Unspecified, "x", 1),
                DEFAULT_TIMEOUT,
            )
            .await;
            assert!(result.failed_to_start);
            assert!(result.error.contains("no interpreter"));
        } else {
            let result = run_script(&dispatch(9, shell, "ver", 1), DEFAULT_TIMEOUT).await;
            assert!(result.failed_to_start, "{result:?}");
            assert!(result.error.contains("cmd.exe"), "{}", result.error);
        }
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn windows_powershell_runs_with_utf8_output() {
        let result = run_script(
            &dispatch(
                10,
                control::ScriptShell::Powershell,
                "Write-Output 'olá powershell'; exit 5",
                60,
            ),
            DEFAULT_TIMEOUT,
        )
        .await;
        assert!(!result.failed_to_start, "{}", result.error);
        assert_eq!(result.exit_code, 5);
        assert!(
            result.stdout.contains("olá powershell"),
            "{:?}",
            result.stdout
        );
    }

    #[test]
    fn script_files_get_bom_and_crlf_only_for_windows_text() {
        let cmd = &interpreters(control::ScriptShell::Cmd)[0];
        let bytes = script_file_contents(cmd, "echo a\necho b");
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.starts_with('\u{FEFF}'));
        assert!(text.contains("chcp 65001"));
        assert!(text.ends_with("echo a\r\necho b\r\n"));
        assert!(!text.contains("\r\r\n"));

        let sh = &interpreters(control::ScriptShell::Sh)[1];
        assert_eq!(sh.program, "sh");
        let bytes = script_file_contents(sh, "echo a");
        assert_eq!(bytes, b"echo a\n");
        assert_eq!(interpreters(control::ScriptShell::Unspecified).len(), 0);
        assert_eq!(
            interpreters(control::ScriptShell::Powershell)
                .last()
                .unwrap()
                .program,
            "pwsh"
        );
    }

    #[tokio::test]
    async fn output_is_bounded() {
        let big = vec![b'x'; MAX_OUTPUT_BYTES * 3];
        let (kept, truncated) = read_bounded(&big[..], MAX_OUTPUT_BYTES).await;
        assert_eq!(kept.len(), MAX_OUTPUT_BYTES);
        assert!(truncated);
        let (kept, truncated) = read_bounded(&b"small"[..], MAX_OUTPUT_BYTES).await;
        assert_eq!(kept, b"small");
        assert!(!truncated);
        assert!(lossy(&kept, true).ends_with("[output truncated]"));
    }
}
