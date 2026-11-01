//! Local administration API: the server side ([`serve`], [`handle_request`])
//! and the client side ([`call`] plus the table renderers used by
//! `omegadesk-server admin ...`).
//!
//! Headscale exposes its CLI through a gRPC listener on a unix socket next to
//! the daemon (`hscontrol/app.go` `ensureUnixSocketIsAbsent`, `cmd/headscale/cli/utils.go`
//! `newSocketClient`), so `headscale nodes list` needs no password: being able
//! to reach the socket is the credential. Windows has no portable unix sockets
//! for tokio, so OmegaDesk binds a loopback TCP port instead and compensates
//! with a bearer token the server prints at startup (or reads from
//! `--admin-token`), compared in constant time. One request per connection,
//! both directions framed as a 4-byte big-endian length plus protobuf.

use std::fmt::Write as _;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use omegadesk_identity::DeviceId;
use omegadesk_policy::{AlertTemplate, TemplateAction};
use omegadesk_protocol::control::v1 as control;
use omegadesk_protocol::control::v1::admin_request::Request;
use omegadesk_protocol::control::v1::admin_response::Response;
use prost::Message;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{info, warn};

use crate::Coordinator;
use crate::control_server::unix_now;
use crate::rmm::{SavedScript, ScriptSchedule, ScriptingShell};
use crate::rmm_service::{
    Dispatch, RmmService, RmmServiceError, check_from_proto, check_to_proto, interval_from_proto,
    interval_to_proto, slug,
};

/// Largest admin frame accepted in either direction (scripts and inventories
/// are small; 4 MiB leaves room for long outputs).
pub const MAX_ADMIN_FRAME: usize = 4 * 1024 * 1024;

/// Time an admin connection has to send its request and read the reply.
pub const ADMIN_TIMEOUT: Duration = Duration::from_secs(10);

/// Errors of the admin client.
#[derive(Debug, thiserror::Error)]
pub enum AdminClientError {
    /// TCP failure.
    #[error("admin connection: {0}")]
    Io(#[from] std::io::Error),
    /// The server did not answer in time.
    #[error("admin request timed out")]
    Timeout,
    /// The reply did not decode.
    #[error("malformed admin reply: {0}")]
    Decode(#[from] prost::DecodeError),
    /// The frame exceeded [`MAX_ADMIN_FRAME`].
    #[error("admin frame of {0} bytes exceeds the limit")]
    FrameTooLarge(usize),
    /// The server rejected the request.
    #[error("{0}")]
    Rejected(String),
    /// The server answered with an unexpected message.
    #[error("unexpected admin reply")]
    Unexpected,
}

async fn write_frame<W: AsyncWriteExt + Unpin>(writer: &mut W, body: &[u8]) -> std::io::Result<()> {
    let len = u32::try_from(body.len())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "frame too large"))?;
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(body).await?;
    writer.flush().await
}

async fn read_frame<R: AsyncReadExt + Unpin>(reader: &mut R) -> Result<Vec<u8>, AdminClientError> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).await?;
    let len = usize::try_from(u32::from_be_bytes(len_buf)).unwrap_or(usize::MAX);
    if len > MAX_ADMIN_FRAME {
        return Err(AdminClientError::FrameTooLarge(len));
    }
    let mut body = vec![0u8; len];
    reader.read_exact(&mut body).await?;
    Ok(body)
}

/// Sends one request to the admin socket and returns the server's answer.
///
/// # Errors
///
/// Returns [`AdminClientError`] on connection, framing or server-side failure.
pub async fn call(addr: &str, token: &str, request: Request) -> Result<Response, AdminClientError> {
    let fut = async {
        let mut stream = TcpStream::connect(addr).await?;
        let body = control::AdminRequest {
            token: token.to_owned(),
            request: Some(request),
        }
        .encode_to_vec();
        write_frame(&mut stream, &body).await?;
        let reply = read_frame(&mut stream).await?;
        let response = control::AdminResponse::decode(reply.as_slice())?;
        match response.response {
            Some(Response::Error(error)) => Err(AdminClientError::Rejected(error.message)),
            Some(other) => Ok(other),
            None => Err(AdminClientError::Unexpected),
        }
    };
    tokio::time::timeout(ADMIN_TIMEOUT, fut)
        .await
        .map_err(|_| AdminClientError::Timeout)?
}

/// Generates a random admin token (32 bytes, hex).
#[must_use]
pub fn generate_token() -> String {
    use rand_core::{OsRng, RngCore};
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    data_encoding::HEXLOWER.encode(&bytes)
}

/// Token comparison that does not stop at the first differing byte (the token
/// length is public, the bytes are not). `black_box` keeps the fold from being
/// short-circuited by the optimizer.
#[must_use]
pub fn token_matches(expected: &str, presented: &str) -> bool {
    let expected = expected.as_bytes();
    let presented = presented.as_bytes();
    if expected.len() != presented.len() {
        return false;
    }
    let difference = expected
        .iter()
        .zip(presented)
        .fold(0u8, |acc, (a, b)| acc | (a ^ b));
    std::hint::black_box(difference) == 0
}

/// Shared state of the admin server.
#[derive(Clone)]
pub struct AdminState {
    /// Bearer token every request must carry.
    pub token: Arc<String>,
    /// Coordinator (pre-auth keys).
    pub coordinator: Arc<Mutex<Coordinator>>,
    /// RMM service (everything else).
    pub rmm: Arc<Mutex<RmmService>>,
}

/// Serves admin requests on `listener` until it fails.
///
/// # Errors
///
/// Returns the `accept` error that ended the loop.
pub async fn serve(listener: TcpListener, state: AdminState) -> anyhow::Result<()> {
    loop {
        let (stream, peer) = listener.accept().await?;
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(error) = tokio::time::timeout(ADMIN_TIMEOUT, serve_one(stream, &state)).await
            {
                warn!(%peer, %error, "admin connection timed out");
            }
        });
    }
}

async fn serve_one(mut stream: TcpStream, state: &AdminState) {
    let request = match read_frame(&mut stream).await {
        Ok(body) => match control::AdminRequest::decode(body.as_slice()) {
            Ok(request) => request,
            Err(error) => {
                warn!(%error, "malformed admin request");
                return;
            }
        },
        Err(error) => {
            warn!(%error, "admin request not read");
            return;
        }
    };
    let response = if token_matches(&state.token, &request.token) {
        match request.request {
            Some(request) => handle_request(request, &state.coordinator, &state.rmm, unix_now()),
            None => error_response("empty request"),
        }
    } else {
        warn!("admin request with a bad token rejected");
        error_response("invalid admin token")
    };
    if let Err(error) = write_frame(&mut stream, &response.encode_to_vec()).await {
        warn!(%error, "admin reply not written");
    }
    let _ = stream.shutdown().await;
}

fn error_response(message: impl Into<String>) -> control::AdminResponse {
    control::AdminResponse {
        response: Some(Response::Error(control::AdminError {
            message: message.into(),
        })),
    }
}

fn ok(response: Response) -> control::AdminResponse {
    control::AdminResponse {
        response: Some(response),
    }
}

fn poisoned() -> control::AdminResponse {
    error_response("server state unavailable")
}

/// Answers one authenticated admin request. Pure apart from the locks, so tests
/// drive it without sockets.
#[must_use]
pub fn handle_request(
    request: Request,
    coordinator: &Arc<Mutex<Coordinator>>,
    rmm: &Arc<Mutex<RmmService>>,
    now_unix_secs: u64,
) -> control::AdminResponse {
    let Ok(mut rmm) = rmm.lock() else {
        return poisoned();
    };
    let result = match request {
        Request::ListDevices(req) => Ok(list_devices(&rmm, &req.tenant, now_unix_secs)),
        Request::ShowDevice(req) => show_device(&rmm, &req.device, now_unix_secs),
        Request::UpdateDevice(req) => update_device(&mut rmm, &req, now_unix_secs),
        Request::ListAlerts(req) => Ok(list_alerts(&rmm, req.include_resolved)),
        Request::ListScripts(_) => Ok(Response::Scripts(control::ScriptList {
            scripts: rmm.scripts().iter().map(script_to_proto).collect(),
        })),
        Request::SaveScript(req) => save_script(&mut rmm, &req),
        Request::RunScript(req) => run_script(&mut rmm, &req),
        Request::AddSchedule(req) => add_schedule(&mut rmm, &req, now_unix_secs),
        Request::ListSchedules(_) => Ok(Response::Schedules(control::ScheduleList {
            schedules: rmm.schedules().iter().map(schedule_to_proto).collect(),
        })),
        Request::ListScriptResults(req) => list_results(&rmm, &req),
        Request::AddCheck(req) => add_check(&mut rmm, req.check.as_ref()),
        Request::ListChecks(_) => Ok(Response::Checks(control::CheckList {
            checks: rmm
                .checks()
                .iter()
                .map(|(scope, check)| check_to_proto(scope, check))
                .collect(),
        })),
        Request::CreateDeploymentLink(req) => {
            create_deployment_link(&mut rmm, coordinator, &req, now_unix_secs)
        }
        Request::CreatePreauthKey(req) => create_preauth_key(coordinator, &req, now_unix_secs),
        Request::AddAlertTemplate(req) => add_alert_template(&mut rmm, &req),
    };
    match result {
        Ok(response) => ok(response),
        Err(error) => error_response(error.to_string()),
    }
}

fn list_devices(rmm: &RmmService, tenant: &str, now: u64) -> Response {
    Response::Devices(control::DeviceList {
        devices: rmm
            .inventories()
            .into_iter()
            .filter(|inv| tenant.is_empty() || inv.tenant_id == tenant)
            .map(|inv| rmm.device_summary(inv, now))
            .collect(),
    })
}

fn device_detail(
    rmm: &RmmService,
    device_id: DeviceId,
    now: u64,
) -> Result<Response, RmmServiceError> {
    let inventory = rmm
        .inventory(device_id)
        .ok_or_else(|| RmmServiceError::UnknownDevice(device_id.to_string()))?;
    Ok(Response::Device(control::DeviceDetail {
        summary: Some(rmm.device_summary(inventory, now)),
        inventory: Some(inventory.to_report()),
        alerts: rmm
            .alerts(true)
            .iter()
            .filter(|(alert, _)| alert.device_id == device_id)
            .map(|(alert, detail)| rmm.alert_info(alert, detail))
            .collect(),
        recent_results: rmm
            .results(Some(device_id), 20)
            .iter()
            .map(crate::rmm_service::ScriptResultRecord::to_proto)
            .collect(),
        queued_scripts: rmm.queued_scripts(device_id).to_vec(),
    }))
}

fn show_device(rmm: &RmmService, device: &str, now: u64) -> Result<Response, RmmServiceError> {
    let device_id = rmm.resolve_device(device)?;
    device_detail(rmm, device_id, now)
}

fn update_device(
    rmm: &mut RmmService,
    req: &control::UpdateDeviceRequest,
    now: u64,
) -> Result<Response, RmmServiceError> {
    fn field(value: &str) -> Option<&str> {
        match value {
            "" => None,
            "-" => Some(""),
            other => Some(other),
        }
    }
    let device_id = rmm.resolve_device(&req.device)?;
    rmm.update_device(device_id, field(&req.site_id), field(&req.alias))?;
    device_detail(rmm, device_id, now)
}

fn list_alerts(rmm: &RmmService, include_resolved: bool) -> Response {
    Response::Alerts(control::AlertList {
        alerts: rmm
            .alerts(include_resolved)
            .iter()
            .map(|(alert, detail)| rmm.alert_info(alert, detail))
            .collect(),
    })
}

fn script_to_proto(script: &SavedScript) -> control::SavedScriptInfo {
    control::SavedScriptInfo {
        script_id: script.script_id.clone(),
        name: script.name.clone(),
        shell: script.shell.to_proto() as i32,
        content: script.content.clone(),
    }
}

fn shell_from_i32(shell: i32) -> Option<ScriptingShell> {
    ScriptingShell::from_proto(
        control::ScriptShell::try_from(shell).unwrap_or(control::ScriptShell::Unspecified),
    )
}

fn save_script(
    rmm: &mut RmmService,
    req: &control::SaveScriptRequest,
) -> Result<Response, RmmServiceError> {
    let shell = shell_from_i32(req.shell)
        .ok_or_else(|| RmmServiceError::InvalidArgument("script shell is required".to_owned()))?;
    if req.content.trim().is_empty() {
        return Err(RmmServiceError::InvalidArgument(
            "script content is empty".to_owned(),
        ));
    }
    if req.name.trim().is_empty() {
        return Err(RmmServiceError::InvalidArgument(
            "script name is required".to_owned(),
        ));
    }
    let script = SavedScript {
        script_id: if req.script_id.trim().is_empty() {
            slug(&req.name)
        } else {
            req.script_id.trim().to_owned()
        },
        name: req.name.trim().to_owned(),
        shell,
        content: req.content.clone(),
    };
    rmm.save_script(script.clone());
    Ok(Response::Script(script_to_proto(&script)))
}

fn run_script(
    rmm: &mut RmmService,
    req: &control::RunScriptRequest,
) -> Result<Response, RmmServiceError> {
    let (device_id, dispatch) = rmm.run_script(
        &req.device,
        &req.script_id,
        shell_from_i32(req.shell),
        &req.content,
        req.timeout_secs,
    )?;
    let (run_id, queued) = match dispatch {
        Dispatch::Sent(run_id) => (run_id, false),
        Dispatch::Queued => (0, true),
    };
    Ok(Response::Run(control::RunScriptResponse {
        device_id: device_id.to_string(),
        run_id,
        queued,
    }))
}

fn schedule_to_proto(schedule: &ScriptSchedule) -> control::ScheduleInfo {
    control::ScheduleInfo {
        schedule_id: schedule.schedule_id.clone(),
        name: schedule.name.clone(),
        tenant: schedule.tenant_id.clone(),
        script_id: schedule.saved_script_id.clone(),
        interval: interval_to_proto(schedule.interval) as i32,
        next_run_unix_secs: schedule.next_run_unix_secs,
        last_run_unix_secs: schedule.last_run_unix_secs.unwrap_or(0),
        run_on_next_connect: schedule.run_on_next_connect,
        device_ids: schedule
            .device_ids
            .iter()
            .map(ToString::to_string)
            .collect(),
        site_ids: schedule.site_ids.clone(),
    }
}

fn add_schedule(
    rmm: &mut RmmService,
    req: &control::AddScheduleRequest,
    now: u64,
) -> Result<Response, RmmServiceError> {
    let interval = interval_from_proto(
        control::ScheduleInterval::try_from(req.interval)
            .unwrap_or(control::ScheduleInterval::Unspecified),
    )
    .ok_or_else(|| RmmServiceError::InvalidArgument("schedule interval is required".to_owned()))?;
    if req.tenant.trim().is_empty() {
        return Err(RmmServiceError::InvalidArgument(
            "schedule tenant is required".to_owned(),
        ));
    }
    if req.name.trim().is_empty() {
        return Err(RmmServiceError::InvalidArgument(
            "schedule name is required".to_owned(),
        ));
    }
    if req.device_ids.is_empty() && req.site_ids.is_empty() {
        return Err(RmmServiceError::InvalidArgument(
            "schedule needs at least one device or site".to_owned(),
        ));
    }
    let device_ids = req
        .device_ids
        .iter()
        .map(|reference| rmm.resolve_device(reference))
        .collect::<Result<Vec<_>, _>>()?;
    let schedule = rmm.add_schedule(
        ScriptSchedule {
            schedule_id: req.schedule_id.trim().to_owned(),
            name: req.name.trim().to_owned(),
            tenant_id: req.tenant.trim().to_owned(),
            saved_script_id: req.script_id.trim().to_owned(),
            interval,
            start_at_unix_secs: req.start_at_unix_secs,
            next_run_unix_secs: 0,
            last_run_unix_secs: None,
            run_on_next_connect: req.run_on_next_connect,
            device_ids,
            site_ids: req.site_ids.clone(),
        },
        now,
    )?;
    Ok(Response::Schedule(schedule_to_proto(&schedule)))
}

fn list_results(
    rmm: &RmmService,
    req: &control::ListScriptResultsRequest,
) -> Result<Response, RmmServiceError> {
    let device_id = if req.device.trim().is_empty() {
        None
    } else {
        Some(rmm.resolve_device(&req.device)?)
    };
    Ok(Response::ScriptResults(control::ScriptResultList {
        results: rmm
            .results(device_id, usize::try_from(req.limit).unwrap_or(usize::MAX))
            .iter()
            .map(crate::rmm_service::ScriptResultRecord::to_proto)
            .collect(),
    }))
}

fn add_check(
    rmm: &mut RmmService,
    info: Option<&control::CheckInfo>,
) -> Result<Response, RmmServiceError> {
    let info =
        info.ok_or_else(|| RmmServiceError::InvalidArgument("check is required".to_owned()))?;
    // Accept hostnames and aliases for the device layer too.
    let mut resolved = info.clone();
    if !info.device_id.trim().is_empty() {
        resolved.device_id = rmm.resolve_device(&info.device_id)?.to_string();
    }
    let (scope, check) = check_from_proto(&resolved)?;
    rmm.add_check(&scope, check.clone());
    Ok(Response::Check(check_to_proto(&scope, &check)))
}

fn create_deployment_link(
    rmm: &mut RmmService,
    coordinator: &Arc<Mutex<Coordinator>>,
    req: &control::CreateDeploymentLinkRequest,
    now: u64,
) -> Result<Response, RmmServiceError> {
    if req.tenant.trim().is_empty() || req.site_id.trim().is_empty() {
        return Err(RmmServiceError::InvalidArgument(
            "deployment link needs a tenant and a site".to_owned(),
        ));
    }
    let expires_at = if req.expires_in_secs == 0 {
        now.saturating_add(7 * 24 * 3_600)
    } else {
        now.saturating_add(req.expires_in_secs)
    };
    let preauth_key = {
        let mut coordinator = coordinator
            .lock()
            .map_err(|_| RmmServiceError::State("coordinator unavailable".to_owned()))?;
        coordinator
            .create_preauth_key(
                req.tenant.trim(),
                true,
                req.ephemeral,
                req.tags.clone(),
                Some(expires_at),
            )
            .map_err(|error| RmmServiceError::InvalidArgument(error.to_string()))?
    };
    let (link, token) = rmm.create_deployment_link(
        req.tenant.trim(),
        req.site_id.trim(),
        preauth_key,
        expires_at,
        req.max_uses,
    );
    info!(link = %link.link_id, tenant = %link.tenant_id, site = %link.site_id, "deployment link created");
    Ok(Response::DeploymentLink(control::DeploymentLinkInfo {
        link_id: link.link_id,
        token,
        tenant: link.tenant_id,
        site_id: link.site_id,
        expires_at_unix_secs: link.expires_at_unix_secs,
        max_uses: link.max_uses,
    }))
}

fn create_preauth_key(
    coordinator: &Arc<Mutex<Coordinator>>,
    req: &control::CreatePreauthKeyRequest,
    now: u64,
) -> Result<Response, RmmServiceError> {
    if req.tenant.trim().is_empty() {
        return Err(RmmServiceError::InvalidArgument(
            "tenant is required".to_owned(),
        ));
    }
    let mut coordinator = coordinator
        .lock()
        .map_err(|_| RmmServiceError::State("coordinator unavailable".to_owned()))?;
    let key = coordinator
        .create_preauth_key(
            req.tenant.trim(),
            req.reusable,
            req.ephemeral,
            req.tags.clone(),
            (req.expires_in_secs > 0).then(|| now.saturating_add(req.expires_in_secs)),
        )
        .map_err(|error| RmmServiceError::InvalidArgument(error.to_string()))?;
    Ok(Response::PreauthKey(control::PreauthKeyInfo { key }))
}

fn add_alert_template(
    rmm: &mut RmmService,
    req: &control::AddAlertTemplateRequest,
) -> Result<Response, RmmServiceError> {
    if req.tenant.trim().is_empty() || req.template_id.trim().is_empty() {
        return Err(RmmServiceError::InvalidArgument(
            "alert template needs a tenant and an id".to_owned(),
        ));
    }
    let script_action = |script_id: &str| -> Result<Vec<TemplateAction>, RmmServiceError> {
        let script_id = script_id.trim();
        if script_id.is_empty() {
            return Ok(Vec::new());
        }
        if rmm.script(script_id).is_none() {
            return Err(RmmServiceError::UnknownScript(script_id.to_owned()));
        }
        Ok(vec![TemplateAction::RunScript {
            script_id: script_id.to_owned(),
        }])
    };
    let template = AlertTemplate {
        template_id: req.template_id.trim().to_owned(),
        name: if req.name.trim().is_empty() {
            req.template_id.trim().to_owned()
        } else {
            req.name.trim().to_owned()
        },
        on_failure_actions: script_action(&req.on_failure_script_id)?,
        on_resolution_actions: script_action(&req.on_resolution_script_id)?,
    };
    let describe = |actions: &[TemplateAction]| -> Vec<String> {
        actions
            .iter()
            .map(|action| match action {
                TemplateAction::RunScript { script_id } => format!("run-script {script_id}"),
                TemplateAction::WebhookNotify { endpoint_url } => format!("webhook {endpoint_url}"),
            })
            .collect()
    };
    let info = control::AlertTemplateInfo {
        template_id: template.template_id.clone(),
        name: template.name.clone(),
        tenant: req.tenant.trim().to_owned(),
        on_failure_actions: describe(&template.on_failure_actions),
        on_resolution_actions: describe(&template.on_resolution_actions),
    };
    rmm.set_tenant_template(req.tenant.trim(), template);
    Ok(Response::AlertTemplate(info))
}

// ---------------------------------------------------------------------------
// Rendering (client side)
// ---------------------------------------------------------------------------

/// Fixed-width text table.
#[derive(Debug, Default)]
pub struct Table {
    header: Vec<String>,
    rows: Vec<Vec<String>>,
}

impl Table {
    /// A table with the given column headers.
    #[must_use]
    pub fn new(header: &[&str]) -> Self {
        Self {
            header: header.iter().map(|h| (*h).to_owned()).collect(),
            rows: Vec::new(),
        }
    }

    /// Appends a row (missing cells render empty).
    pub fn row(&mut self, cells: Vec<String>) {
        self.rows.push(cells);
    }

    /// Renders the table with two spaces between columns.
    #[must_use]
    pub fn render(&self) -> String {
        let columns = self.header.len();
        let mut widths: Vec<usize> = self.header.iter().map(|h| h.chars().count()).collect();
        for row in &self.rows {
            for (i, cell) in row.iter().enumerate().take(columns) {
                widths[i] = widths[i].max(cell.chars().count());
            }
        }
        let mut out = String::new();
        let mut write_row = |cells: &[String]| {
            let mut line = String::new();
            for (i, width) in widths.iter().enumerate() {
                let cell = cells.get(i).map_or("", String::as_str);
                if i + 1 == columns {
                    line.push_str(cell);
                } else {
                    let pad = width.saturating_sub(cell.chars().count());
                    line.push_str(cell);
                    line.extend(std::iter::repeat_n(' ', pad + 2));
                }
            }
            out.push_str(line.trim_end());
            out.push('\n');
        };
        write_row(&self.header);
        for row in &self.rows {
            write_row(row);
        }
        out
    }
}

/// `3d 4h`, `12m`, `45s` style age of a timestamp (`-` when unknown).
#[must_use]
pub fn format_age(now_unix_secs: u64, then_unix_secs: u64) -> String {
    if then_unix_secs == 0 {
        return "-".to_owned();
    }
    let secs = now_unix_secs.saturating_sub(then_unix_secs);
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3_600 {
        format!("{}m", secs / 60)
    } else if secs < 86_400 {
        format!("{}h {}m", secs / 3_600, (secs % 3_600) / 60)
    } else {
        format!("{}d {}h", secs / 86_400, (secs % 86_400) / 3_600)
    }
}

/// Binary-prefixed byte count (`15.6 GiB`).
#[must_use]
pub fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    let mut value = bytes;
    let mut remainder = 0u64;
    let mut unit = 0;
    while value >= 1024 && unit + 1 < UNITS.len() {
        remainder = value % 1024;
        value /= 1024;
        unit += 1;
    }
    if unit == 0 {
        format!("{value} B")
    } else {
        format!("{value}.{} {}", remainder * 10 / 1024, UNITS[unit])
    }
}

fn status_name(status: i32) -> &'static str {
    match control::DeviceStatus::try_from(status).unwrap_or(control::DeviceStatus::Unspecified) {
        control::DeviceStatus::Online => "online",
        control::DeviceStatus::Offline => "offline",
        control::DeviceStatus::Overdue => "overdue",
        control::DeviceStatus::Unspecified => "?",
    }
}

fn shell_name(shell: i32) -> &'static str {
    match control::ScriptShell::try_from(shell).unwrap_or(control::ScriptShell::Unspecified) {
        control::ScriptShell::Powershell => "powershell",
        control::ScriptShell::Pwsh => "pwsh",
        control::ScriptShell::Sh => "sh",
        control::ScriptShell::Cmd => "cmd",
        control::ScriptShell::Unspecified => "?",
    }
}

fn interval_name(interval: i32) -> &'static str {
    match control::ScheduleInterval::try_from(interval)
        .unwrap_or(control::ScheduleInterval::Unspecified)
    {
        control::ScheduleInterval::Hourly => "hourly",
        control::ScheduleInterval::Daily => "daily",
        control::ScheduleInterval::Weekly => "weekly",
        control::ScheduleInterval::Monthly => "monthly",
        control::ScheduleInterval::Unspecified => "?",
    }
}

fn check_kind_name(kind: i32) -> &'static str {
    match control::CheckKind::try_from(kind).unwrap_or(control::CheckKind::Unspecified) {
        control::CheckKind::Cpu => "cpu",
        control::CheckKind::Memory => "memory",
        control::CheckKind::Disk => "disk",
        control::CheckKind::ProcessRunning => "process",
        control::CheckKind::ServiceRunning => "service",
        control::CheckKind::ScriptExitCode => "script",
        control::CheckKind::Offline => "offline",
        control::CheckKind::Unspecified => "?",
    }
}

fn severity_name(severity: i32) -> &'static str {
    match control::CheckSeverity::try_from(severity).unwrap_or(control::CheckSeverity::Unspecified)
    {
        control::CheckSeverity::Info => "info",
        control::CheckSeverity::Warning => "warning",
        control::CheckSeverity::Critical => "critical",
        control::CheckSeverity::Unspecified => "?",
    }
}

/// Device table.
#[must_use]
pub fn render_devices(list: &control::DeviceList, now_unix_secs: u64) -> String {
    let mut table = Table::new(&[
        "HOSTNAME",
        "TENANT",
        "SITE",
        "STATUS",
        "LAST SEEN",
        "CPU",
        "MEM",
        "DISK",
        "ALERTS",
        "USER",
        "OS",
        "DEVICE ID",
    ]);
    for d in &list.devices {
        table.row(vec![
            if d.alias.is_empty() {
                d.hostname.clone()
            } else {
                format!("{} ({})", d.hostname, d.alias)
            },
            d.tenant.clone(),
            d.site_id.clone(),
            status_name(d.status).to_owned(),
            format_age(now_unix_secs, d.last_seen_unix_secs),
            format!("{}%", d.cpu_pct),
            format!("{}%", d.memory_pct),
            format!("{}%", d.storage_pct),
            d.open_alerts.to_string(),
            d.current_user.clone(),
            d.os_description.clone(),
            d.device_id.clone(),
        ]);
    }
    if list.devices.is_empty() {
        "no devices enrolled\n".to_owned()
    } else {
        table.render()
    }
}

/// Full device view.
#[must_use]
pub fn render_device(detail: &control::DeviceDetail, now_unix_secs: u64) -> String {
    let mut out = String::new();
    if let Some(s) = &detail.summary {
        let _ = writeln!(out, "device     {}", s.device_id);
        let _ = writeln!(out, "hostname   {}", s.hostname);
        if !s.alias.is_empty() {
            let _ = writeln!(out, "alias      {}", s.alias);
        }
        let _ = writeln!(out, "tenant     {}", s.tenant);
        let _ = writeln!(out, "site       {}", s.site_id);
        let _ = writeln!(
            out,
            "status     {} (last seen {} ago)",
            status_name(s.status),
            format_age(now_unix_secs, s.last_seen_unix_secs)
        );
        let _ = writeln!(out, "agent      {}", s.agent_version);
    }
    if let Some(inv) = &detail.inventory {
        out.push_str(&render_inventory(inv, now_unix_secs));
    }
    if !detail.queued_scripts.is_empty() {
        let _ = writeln!(out, "queued     {}", detail.queued_scripts.join(", "));
    }
    if !detail.alerts.is_empty() {
        out.push('\n');
        out.push_str(&render_alerts(
            &control::AlertList {
                alerts: detail.alerts.clone(),
            },
            now_unix_secs,
        ));
    }
    if !detail.recent_results.is_empty() {
        out.push('\n');
        out.push_str(&render_results(
            &control::ScriptResultList {
                results: detail.recent_results.clone(),
            },
            now_unix_secs,
        ));
    }
    out
}

fn render_inventory(inv: &control::InventoryReport, now_unix_secs: u64) -> String {
    let mut out = String::new();
    {
        let _ = writeln!(
            out,
            "os         {} {} (build {}) {}",
            inv.os_description, inv.os_version, inv.os_build, inv.architecture
        );
        let _ = writeln!(
            out,
            "cpu        {} x{} at {}%",
            inv.cpu_model, inv.processor_count, inv.cpu_utilization_pct
        );
        let _ = writeln!(
            out,
            "memory     {} / {}",
            format_bytes(inv.used_memory_bytes),
            format_bytes(inv.total_memory_bytes)
        );
        let _ = writeln!(out, "user       {}", inv.current_user);
        let _ = writeln!(
            out,
            "uptime     {}",
            format_age(inv.uptime_secs, 1).replace(" ago", "")
        );
        for d in &inv.drives {
            let pct = d
                .used_bytes
                .saturating_mul(100)
                .checked_div(d.total_bytes)
                .unwrap_or(0);
            let _ = writeln!(
                out,
                "drive      {} {} {} / {} ({pct}%)",
                d.name,
                d.filesystem,
                format_bytes(d.used_bytes),
                format_bytes(d.total_bytes)
            );
        }
        for n in &inv.nics {
            let _ = writeln!(
                out,
                "nic        {} {} {}",
                n.name,
                n.mac_address,
                n.addresses.join(" ")
            );
        }
        if let Some(wu) = &inv.windows_update {
            let _ = writeln!(
                out,
                "updates    reboot required: {}{}; pending: {}{}",
                wu.reboot_required,
                if wu.reboot_reasons.is_empty() {
                    String::new()
                } else {
                    format!(" ({})", wu.reboot_reasons.join(", "))
                },
                if wu.scanned {
                    format!(
                        "{} security, {} optional",
                        wu.pending_security_updates, wu.pending_optional_updates
                    )
                } else {
                    "not scanned".to_owned()
                },
                if wu.last_scan_unix_secs == 0 {
                    String::new()
                } else {
                    format!(
                        "; last detection {} ago",
                        format_age(now_unix_secs, wu.last_scan_unix_secs)
                    )
                }
            );
        }
        let _ = writeln!(
            out,
            "processes  {} running; services {} running",
            inv.running_processes.len(),
            inv.running_services.len()
        );
    }
    out
}

/// Alert table.
#[must_use]
pub fn render_alerts(list: &control::AlertList, now_unix_secs: u64) -> String {
    if list.alerts.is_empty() {
        return "no alerts\n".to_owned();
    }
    let mut table = Table::new(&[
        "STATE", "SEVERITY", "HOSTNAME", "CHECK", "DETAIL", "OPENED", "RESOLVED", "ACTIONS",
    ]);
    for a in &list.alerts {
        table.row(vec![
            a.state.clone(),
            a.severity.clone(),
            a.hostname.clone(),
            if a.check_name.is_empty() {
                a.check_id.clone()
            } else {
                format!("{} ({})", a.check_name, a.check_id)
            },
            a.detail.clone(),
            format!("{} ago", format_age(now_unix_secs, a.opened_at_unix_secs)),
            if a.resolved_at_unix_secs == 0 {
                "-".to_owned()
            } else {
                format!("{} ago", format_age(now_unix_secs, a.resolved_at_unix_secs))
            },
            a.actions.join("; "),
        ]);
    }
    table.render()
}

/// Saved scripts table.
#[must_use]
pub fn render_scripts(list: &control::ScriptList) -> String {
    if list.scripts.is_empty() {
        return "no saved scripts\n".to_owned();
    }
    let mut table = Table::new(&["ID", "NAME", "SHELL", "LINES"]);
    for s in &list.scripts {
        table.row(vec![
            s.script_id.clone(),
            s.name.clone(),
            shell_name(s.shell).to_owned(),
            s.content.lines().count().to_string(),
        ]);
    }
    table.render()
}

/// Schedules table.
#[must_use]
pub fn render_schedules(list: &control::ScheduleList, now_unix_secs: u64) -> String {
    if list.schedules.is_empty() {
        return "no schedules\n".to_owned();
    }
    let mut table = Table::new(&[
        "ID",
        "NAME",
        "TENANT",
        "SCRIPT",
        "INTERVAL",
        "NEXT RUN",
        "LAST RUN",
        "QUEUE OFFLINE",
        "TARGETS",
    ]);
    for s in &list.schedules {
        let next = if s.next_run_unix_secs > now_unix_secs {
            format!(
                "in {}",
                format_age(s.next_run_unix_secs, now_unix_secs.max(1))
            )
        } else {
            "due".to_owned()
        };
        let mut targets: Vec<String> = s
            .site_ids
            .iter()
            .map(|site| format!("site:{site}"))
            .collect();
        targets.extend(s.device_ids.iter().cloned());
        table.row(vec![
            s.schedule_id.clone(),
            s.name.clone(),
            s.tenant.clone(),
            s.script_id.clone(),
            interval_name(s.interval).to_owned(),
            next,
            if s.last_run_unix_secs == 0 {
                "-".to_owned()
            } else {
                format!("{} ago", format_age(now_unix_secs, s.last_run_unix_secs))
            },
            s.run_on_next_connect.to_string(),
            targets.join(" "),
        ]);
    }
    table.render()
}

/// Script results, newest first, with output under each row.
#[must_use]
pub fn render_results(list: &control::ScriptResultList, now_unix_secs: u64) -> String {
    if list.results.is_empty() {
        return "no script results\n".to_owned();
    }
    let mut out = String::new();
    for r in &list.results {
        let Some(result) = &r.result else {
            continue;
        };
        let status = if result.failed_to_start {
            format!("failed to start: {}", result.error)
        } else if result.timed_out {
            format!("timed out after {} ms", result.duration_ms)
        } else {
            format!("exit {} in {} ms", result.exit_code, result.duration_ms)
        };
        let _ = writeln!(
            out,
            "run {} {} on {} ({}) {} ago: {status}",
            result.run_id,
            result.script_id,
            r.hostname,
            r.device_id,
            format_age(now_unix_secs, r.received_at_unix_secs)
        );
        for line in result.stdout.lines() {
            let _ = writeln!(out, "  | {line}");
        }
        for line in result.stderr.lines() {
            let _ = writeln!(out, "  ! {line}");
        }
    }
    out
}

/// Checks table.
#[must_use]
pub fn render_checks(list: &control::CheckList) -> String {
    if list.checks.is_empty() {
        return "no checks\n".to_owned();
    }
    let mut table = Table::new(&[
        "ID",
        "NAME",
        "KIND",
        "CONDITION",
        "SEVERITY",
        "FAILURES",
        "SCOPE",
    ]);
    for c in &list.checks {
        let condition = match control::CheckKind::try_from(c.kind)
            .unwrap_or(control::CheckKind::Unspecified)
        {
            control::CheckKind::Cpu | control::CheckKind::Memory => format!("> {}%", c.max_percent),
            control::CheckKind::Disk => format!("{} > {}%", c.target, c.max_percent),
            control::CheckKind::ProcessRunning | control::CheckKind::ServiceRunning => {
                format!("{} not running", c.target)
            }
            control::CheckKind::ScriptExitCode => {
                format!("{} exit != {}", c.target, c.expected_exit_code)
            }
            control::CheckKind::Offline => format!("offline > {}s", c.max_offline_secs),
            control::CheckKind::Unspecified => String::new(),
        };
        let scope = if !c.device_id.is_empty() {
            format!("device {}", c.device_id)
        } else if !c.site_id.is_empty() {
            format!("{}/{}", c.tenant, c.site_id)
        } else {
            c.tenant.clone()
        };
        table.row(vec![
            c.check_id.clone(),
            c.name.clone(),
            check_kind_name(c.kind).to_owned(),
            condition,
            severity_name(c.severity).to_owned(),
            c.failures_before_alert.to_string(),
            scope,
        ]);
    }
    table.render()
}

#[cfg(test)]
mod tests {
    use omegadesk_identity::DeviceIdentity;
    use tokio::sync::mpsc;

    use super::*;

    struct Fixtures {
        coordinator: Arc<Mutex<Coordinator>>,
        rmm: Arc<Mutex<RmmService>>,
        device: DeviceId,
        /// Keeps the device's control stream open (a dropped receiver means offline).
        _rx: mpsc::Receiver<control::ControlEnvelope>,
    }

    fn fixtures() -> Fixtures {
        let coordinator = Arc::new(Mutex::new(Coordinator::new([1u8; 32])));
        let rmm = Arc::new(Mutex::new(RmmService::in_memory()));
        let device = DeviceIdentity::generate().id();
        let (tx, rx) = mpsc::channel(8);
        rmm.lock().unwrap().device_connected(
            &crate::rmm_service::DeviceSession {
                device_id: device,
                tenant: "acme",
                hostname: "srv-01",
                site_id: None,
                generation: 1,
            },
            tx,
            1_000,
        );
        Fixtures {
            coordinator,
            rmm,
            device,
            _rx: rx,
        }
    }

    fn save_cleanup_script(coordinator: &Arc<Mutex<Coordinator>>, rmm: &Arc<Mutex<RmmService>>) {
        let Response::Script(script) = handle(
            Request::SaveScript(control::SaveScriptRequest {
                script_id: String::new(),
                name: "Disk Cleanup".to_owned(),
                shell: control::ScriptShell::Sh as i32,
                content: "df -h".to_owned(),
            }),
            coordinator,
            rmm,
        ) else {
            panic!("expected Script");
        };
        assert_eq!(script.script_id, "disk-cleanup");
    }

    fn handle(
        request: Request,
        coordinator: &Arc<Mutex<Coordinator>>,
        rmm: &Arc<Mutex<RmmService>>,
    ) -> Response {
        handle_request(request, coordinator, rmm, 2_000)
            .response
            .unwrap()
    }

    #[test]
    fn admin_requests_drive_scripts_and_schedules() {
        let Fixtures {
            coordinator,
            rmm,
            device,
            _rx,
        } = fixtures();
        save_cleanup_script(&coordinator, &rmm);
        assert!(matches!(
            handle(
                Request::SaveScript(control::SaveScriptRequest {
                    name: "x".to_owned(),
                    content: "y".to_owned(),
                    ..Default::default()
                }),
                &coordinator,
                &rmm,
            ),
            Response::Error(_)
        ));

        let Response::Run(run) = handle(
            Request::RunScript(control::RunScriptRequest {
                device: "SRV-01".to_owned(),
                script_id: "disk-cleanup".to_owned(),
                ..Default::default()
            }),
            &coordinator,
            &rmm,
        ) else {
            panic!("expected Run");
        };
        assert_eq!(run.device_id, device.to_string());
        assert_eq!(run.run_id, 1);
        assert!(!run.queued);

        let Response::Schedule(schedule) = handle(
            Request::AddSchedule(control::AddScheduleRequest {
                name: "Hourly df".to_owned(),
                tenant: "acme".to_owned(),
                script_id: "disk-cleanup".to_owned(),
                interval: control::ScheduleInterval::Hourly as i32,
                device_ids: vec!["srv-01".to_owned()],
                run_on_next_connect: true,
                ..Default::default()
            }),
            &coordinator,
            &rmm,
        ) else {
            panic!("expected Schedule");
        };
        assert_eq!(schedule.device_ids, vec![device.to_string()]);
        assert_eq!(schedule.next_run_unix_secs, 2_000);
        assert!(matches!(
            handle(
                Request::AddSchedule(control::AddScheduleRequest {
                    name: "no targets".to_owned(),
                    tenant: "acme".to_owned(),
                    script_id: "disk-cleanup".to_owned(),
                    interval: control::ScheduleInterval::Hourly as i32,
                    ..Default::default()
                }),
                &coordinator,
                &rmm,
            ),
            Response::Error(_)
        ));
    }

    #[test]
    fn admin_requests_manage_checks_templates_links_and_keys() {
        let Fixtures {
            coordinator,
            rmm,
            device,
            _rx,
        } = fixtures();
        save_cleanup_script(&coordinator, &rmm);

        let Response::Check(check) = handle(
            Request::AddCheck(control::AddCheckRequest {
                check: Some(control::CheckInfo {
                    check_id: "svc".to_owned(),
                    kind: control::CheckKind::ServiceRunning as i32,
                    target: "Spooler".to_owned(),
                    tenant: "acme".to_owned(),
                    device_id: "srv-01".to_owned(),
                    ..Default::default()
                }),
            }),
            &coordinator,
            &rmm,
        ) else {
            panic!("expected Check");
        };
        assert_eq!(
            check.device_id,
            device.to_string(),
            "hostnames resolve for device scope"
        );
        let Response::Checks(checks) = handle(
            Request::ListChecks(control::ListChecksRequest {}),
            &coordinator,
            &rmm,
        ) else {
            panic!("expected Checks");
        };
        assert_eq!(checks.checks.len(), 1);

        let Response::AlertTemplate(template) = handle(
            Request::AddAlertTemplate(control::AddAlertTemplateRequest {
                template_id: "tpl".to_owned(),
                name: String::new(),
                tenant: "acme".to_owned(),
                on_failure_script_id: "disk-cleanup".to_owned(),
                on_resolution_script_id: String::new(),
            }),
            &coordinator,
            &rmm,
        ) else {
            panic!("expected AlertTemplate");
        };
        assert_eq!(
            template.on_failure_actions,
            vec!["run-script disk-cleanup".to_owned()]
        );
        assert!(matches!(
            handle(
                Request::AddAlertTemplate(control::AddAlertTemplateRequest {
                    template_id: "tpl2".to_owned(),
                    tenant: "acme".to_owned(),
                    on_failure_script_id: "ghost".to_owned(),
                    ..Default::default()
                }),
                &coordinator,
                &rmm,
            ),
            Response::Error(_)
        ));
    }

    #[test]
    fn admin_requests_create_deployment_links_bound_to_preauth_keys() {
        let Fixtures {
            coordinator,
            rmm,
            device: _,
            _rx,
        } = fixtures();
        let Response::DeploymentLink(link) = handle(
            Request::CreateDeploymentLink(control::CreateDeploymentLinkRequest {
                tenant: "acme".to_owned(),
                site_id: "site-sp".to_owned(),
                expires_in_secs: 3_600,
                max_uses: 5,
                tags: vec!["tag:workstation".to_owned()],
                ephemeral: false,
            }),
            &coordinator,
            &rmm,
        ) else {
            panic!("expected DeploymentLink");
        };
        assert!(link.token.starts_with("odl_"));
        assert_eq!(link.expires_at_unix_secs, 5_600);
        // The token maps to a pre-auth key the coordinator accepts.
        let binding = rmm
            .lock()
            .unwrap()
            .redeem_deployment_token(DeviceIdentity::generate().id(), &link.token, 2_100)
            .unwrap();
        let installer = DeviceIdentity::generate();
        let bundle = coordinator
            .lock()
            .unwrap()
            .enroll_machine(
                &binding.preauth_key,
                installer.public(),
                "pc",
                vec![],
                2_200,
            )
            .unwrap();
        assert_eq!(bundle.node.tenant, "acme");
        assert_eq!(bundle.node.tags, vec!["tag:workstation".to_owned()]);
    }

    #[test]
    fn admin_requests_create_preauth_keys() {
        let Fixtures {
            coordinator,
            rmm,
            device: _,
            _rx,
        } = fixtures();
        let Response::PreauthKey(key) = handle(
            Request::CreatePreauthKey(control::CreatePreauthKeyRequest {
                tenant: "acme".to_owned(),
                reusable: false,
                ephemeral: true,
                tags: vec![],
                expires_in_secs: 0,
            }),
            &coordinator,
            &rmm,
        ) else {
            panic!("expected PreauthKey");
        };
        assert!(key.key.starts_with("odk_"));
    }

    #[test]
    fn admin_requests_read_devices_alerts_and_results_and_render_tables() {
        let Fixtures {
            coordinator,
            rmm,
            device,
            _rx,
        } = fixtures();
        rmm.lock().unwrap().ingest_report(
            device,
            "acme",
            &control::InventoryReport {
                hostname: "srv-01".to_owned(),
                os_description: "Ubuntu 24.04".to_owned(),
                cpu_utilization_pct: 12,
                total_memory_bytes: 8 << 30,
                used_memory_bytes: 2 << 30,
                drives: vec![control::DriveReport {
                    name: "/".to_owned(),
                    filesystem: "ext4".to_owned(),
                    total_bytes: 100,
                    used_bytes: 95,
                }],
                current_user: "ricardo".to_owned(),
                ..Default::default()
            },
            1_500,
        );

        let Response::Devices(devices) = handle(
            Request::ListDevices(control::ListDevicesRequest {
                tenant: String::new(),
            }),
            &coordinator,
            &rmm,
        ) else {
            panic!("expected Devices");
        };
        assert_eq!(devices.devices.len(), 1);
        let rendered = render_devices(&devices, 2_000);
        assert!(rendered.contains("srv-01"), "{rendered}");
        assert!(rendered.contains("online"), "{rendered}");
        assert!(rendered.contains("95%"), "{rendered}");
        let Response::Devices(filtered) = handle(
            Request::ListDevices(control::ListDevicesRequest {
                tenant: "globex".to_owned(),
            }),
            &coordinator,
            &rmm,
        ) else {
            panic!("expected Devices");
        };
        assert_eq!(filtered.devices.len(), 0);

        let Response::Device(detail) = handle(
            Request::UpdateDevice(control::UpdateDeviceRequest {
                device: device.to_string(),
                site_id: "site-sp".to_owned(),
                alias: "Web".to_owned(),
            }),
            &coordinator,
            &rmm,
        ) else {
            panic!("expected Device");
        };
        assert_eq!(detail.summary.as_ref().unwrap().alias, "Web");
        let rendered = render_device(&detail, 2_000);
        assert!(rendered.contains("alias      Web"), "{rendered}");
        assert!(rendered.contains("Ubuntu 24.04"), "{rendered}");
        let Response::Device(cleared) = handle(
            Request::UpdateDevice(control::UpdateDeviceRequest {
                device: "web".to_owned(),
                site_id: String::new(),
                alias: "-".to_owned(),
            }),
            &coordinator,
            &rmm,
        ) else {
            panic!("expected Device");
        };
        assert_eq!(cleared.summary.as_ref().unwrap().alias, "");
        assert_eq!(cleared.summary.as_ref().unwrap().site_id, "site-sp");
        assert!(matches!(
            handle(
                Request::ShowDevice(control::ShowDeviceRequest {
                    device: "nobody".to_owned(),
                }),
                &coordinator,
                &rmm,
            ),
            Response::Error(e) if e.message.contains("unknown device")
        ));
    }

    #[test]
    fn admin_requests_list_alerts_and_results_and_render_helpers_format() {
        let Fixtures {
            coordinator,
            rmm,
            device,
            _rx,
        } = fixtures();
        let Response::Alerts(alerts) = handle(
            Request::ListAlerts(control::ListAlertsRequest {
                include_resolved: true,
            }),
            &coordinator,
            &rmm,
        ) else {
            panic!("expected Alerts");
        };
        assert_eq!(render_alerts(&alerts, 2_000), "no alerts\n");

        rmm.lock().unwrap().ingest_script_result(
            device,
            &control::ScriptResult {
                run_id: 9,
                script_id: "s".to_owned(),
                exit_code: 2,
                stdout: "line1\nline2".to_owned(),
                stderr: "oops".to_owned(),
                duration_ms: 42,
                ..Default::default()
            },
            1_900,
        );
        let Response::ScriptResults(results) = handle(
            Request::ListScriptResults(control::ListScriptResultsRequest {
                device: "srv-01".to_owned(),
                limit: 5,
            }),
            &coordinator,
            &rmm,
        ) else {
            panic!("expected ScriptResults");
        };
        let rendered = render_results(&results, 2_000);
        assert!(rendered.contains("run 9 s on srv-01"));
        assert!(rendered.contains("exit 2 in 42 ms"));
        assert!(rendered.contains("  | line2"));
        assert!(rendered.contains("  ! oops"));

        assert_eq!(format_age(2_000, 0), "-");
        assert_eq!(format_age(2_000, 1_990), "10s");
        assert_eq!(format_age(10_000, 2_000), "2h 13m");
        assert_eq!(format_age(200_000, 2_000), "2d 7h");
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1_536), "1.5 KiB");
        assert_eq!(format_bytes(8 << 30), "8.0 GiB");
        let mut table = Table::new(&["A", "BB"]);
        table.row(vec!["xxx".to_owned()]);
        table.row(vec!["y".to_owned(), "z".to_owned()]);
        assert_eq!(table.render(), "A    BB\nxxx\ny    z\n");
    }

    #[tokio::test]
    async fn admin_socket_requires_the_token_and_answers_one_request_per_connection() {
        let Fixtures {
            coordinator,
            rmm,
            device: _,
            _rx,
        } = fixtures();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let token = generate_token();
        assert_eq!(token.len(), 64);
        tokio::spawn(serve(
            listener,
            AdminState {
                token: Arc::new(token.clone()),
                coordinator,
                rmm,
            },
        ));

        let response = call(
            &addr,
            &token,
            Request::ListDevices(control::ListDevicesRequest::default()),
        )
        .await
        .unwrap();
        assert!(matches!(response, Response::Devices(list) if list.devices.len() == 1));

        let error = call(
            &addr,
            "wrong",
            Request::ListDevices(control::ListDevicesRequest::default()),
        )
        .await
        .unwrap_err();
        assert!(matches!(error, AdminClientError::Rejected(message) if message.contains("token")));
        assert!(token_matches("abc", "abc"));
        assert!(!token_matches("abc", "abz"));
        assert!(!token_matches("abc", "ab"));
    }
}
