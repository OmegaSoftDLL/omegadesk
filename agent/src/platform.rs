//! Operating system process and thread priority tuning for low-latency capture.

/// Requests that the operating system not throttle the agent process.
///
/// On Windows 11, background processes without a foreground window are placed
/// under power throttling (`EcoQoS`) and scheduled onto efficiency cores. On
/// an Intel Core Ultra 5 135U that slowed 1080p encoding by 17x (from ~40 ms
/// to ~680 ms per frame). We disable `EcoQoS` execution-speed and timer
/// throttling in addition to raising the process priority class
/// (`HIGH_PRIORITY_CLASS`, as Sunshine does).
pub(crate) fn prefer_performance() {
    #[cfg(windows)]
    windows_impl::prefer_performance();
}

/// Raises the priority of the calling thread (capture and encoding), matching
/// Sunshine's video thread (`src/platform/windows/misc.cpp`).
pub(crate) fn boost_current_thread() {
    #[cfg(windows)]
    windows_impl::boost_current_thread();
}

#[cfg(windows)]
mod windows_impl {
    #![allow(unsafe_code, reason = "Win32 process and thread priority APIs")]

    use std::ffi::c_void;

    use tracing::{info, warn};
    use windows::Win32::System::Threading::{
        GetCurrentProcess, GetCurrentThread, HIGH_PRIORITY_CLASS,
        PROCESS_POWER_THROTTLING_CURRENT_VERSION, PROCESS_POWER_THROTTLING_EXECUTION_SPEED,
        PROCESS_POWER_THROTTLING_IGNORE_TIMER_RESOLUTION, PROCESS_POWER_THROTTLING_STATE,
        ProcessPowerThrottling, SetPriorityClass, SetProcessInformation, SetThreadPriority,
        THREAD_PRIORITY_HIGHEST,
    };
    use windows::Win32::UI::HiDpi::{
        DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2, SetProcessDpiAwarenessContext,
    };

    pub(super) fn prefer_performance() {
        // Opt into Per-Monitor V2 DPI awareness so `GetSystemMetrics` and DXGI
        // desktop coordinates always report physical pixels across mixed-DPI
        // multi-monitor setups (matching Sunshine `display_base.cpp`).
        // SAFETY: `DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2` is a valid system
        // constant; fails harmlessly if DPI awareness was already locked.
        let _ =
            unsafe { SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2) };
        let state = PROCESS_POWER_THROTTLING_STATE {
            Version: PROCESS_POWER_THROTTLING_CURRENT_VERSION,
            // Control both execution speed and timer resolution, clearing the
            // state mask (0) to disable throttling for both.
            ControlMask: PROCESS_POWER_THROTTLING_EXECUTION_SPEED
                | PROCESS_POWER_THROTTLING_IGNORE_TIMER_RESOLUTION,
            StateMask: 0,
        };
        let size = u32::try_from(size_of::<PROCESS_POWER_THROTTLING_STATE>()).unwrap_or(0);
        // SAFETY: takes no arguments and returns a pseudo-handle to the current
        // process that does not need to be closed.
        let process = unsafe { GetCurrentProcess() };
        // SAFETY: `process` is the current process pseudo-handle; for
        // `ProcessPowerThrottling` the API expects a
        // `PROCESS_POWER_THROTTLING_STATE` buffer of `size` bytes, which
        // `state` provides on the stack for the duration of the call.
        let throttling = unsafe {
            SetProcessInformation(
                process,
                ProcessPowerThrottling,
                (&raw const state).cast::<c_void>(),
                size,
            )
        };
        if let Err(error) = throttling {
            warn!("failed to disable process power throttling: {error}");
        }
        // SAFETY: `process` is the current process pseudo-handle and
        // `HIGH_PRIORITY_CLASS` is a valid priority class constant.
        match unsafe { SetPriorityClass(process, HIGH_PRIORITY_CLASS) } {
            Ok(()) => info!("agent running at high priority with power throttling disabled"),
            Err(error) => warn!("failed to raise process priority class: {error}"),
        }
    }

    pub(super) fn boost_current_thread() {
        // SAFETY: takes no arguments and returns a pseudo-handle to the calling
        // thread that does not need to be closed.
        let thread = unsafe { GetCurrentThread() };
        // SAFETY: `thread` is the calling thread pseudo-handle and
        // `THREAD_PRIORITY_HIGHEST` is a valid thread priority level.
        if let Err(error) = unsafe { SetThreadPriority(thread, THREAD_PRIORITY_HIGHEST) } {
            warn!("failed to raise capture thread priority: {error}");
        }
    }
}
