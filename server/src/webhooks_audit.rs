//! Dashboard webhooks with `X-Webhook-Signature: sha256=<hex>` HMAC signing, linear retry
//! backoff, and cursor-keyset administrative audit log service (`docs/plan.md` §2.12 line 168).
//!
//! Ported directly from the Apache-2.0 reference implementation in
//! `barry-ran_QuickDesk/SignalingServer/internal/`:
//! - `models/webhook.go` (lines 5–16) & `service/webhook_service.go` (lines 51–141):
//!   [`WebhookRecord`] (`id`, `name`, `url`, `signing_key`, `events`, `enabled`,
//!   `last_triggered_ms`, `last_status`), [`compute_webhook_signature_header`]
//!   (`X-Webhook-Signature: sha256=<hex>`), [`webhook_retry_backoff_secs`]
//!   (`(attempt + 1) * 2` seconds across `MAX_WEBHOOK_ATTEMPTS = 3`), and event subscription
//!   matching.
//! - `models/audit_log.go` (lines 5–15) & `service/audit_service.go` (lines 20–73):
//!   [`DashboardAuditEntry`] (`id`, `admin_id`, `admin_username`, `action`, `resource_type`,
//!   `resource_id`, `details`, `ip`, `created_at_ms`), [`AuditListParams`] cursor-keyset
//!   filter (`after_id`, `limit`, `action`, `admin_username`, `from_ms`, `to_ms`), and
//!   [`AuditLogStore::list`] returning `(entries, total_matching)` ordered by `id DESC`.

use data_encoding::HEXLOWER;
use ring::hmac;

/// HTTP header carrying the HMAC-SHA256 signature of a webhook JSON payload
/// (`webhook_service.go` line 100).
pub const WEBHOOK_SIGNATURE_HEADER: &str = "X-Webhook-Signature";

/// Maximum delivery attempts per webhook event (`webhook_service.go` line 89).
pub const MAX_WEBHOOK_ATTEMPTS: u32 = 3;

/// Registered webhook endpoint (`models/webhook.go` lines 5–16).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebhookRecord {
    /// Primary key identifier.
    pub id: u64,
    /// Human-readable webhook name.
    pub name: String,
    /// Destination HTTPS endpoint URL.
    pub url: String,
    /// Optional HMAC-SHA256 signing key material (`models/webhook.go` line 9).
    pub signing_key: Vec<u8>,
    /// Subscribed event names (e.g., `["session.started", "device.offline"]`).
    pub events: Vec<String>,
    /// Whether this webhook is enabled.
    pub enabled: bool,
    /// Timestamp of the last delivery attempt in milliseconds since the Unix epoch.
    pub last_triggered_ms: Option<u64>,
    /// HTTP status code of the last delivery attempt (`0` on transport failure).
    pub last_status: u16,
}

impl WebhookRecord {
    /// Returns `true` if this webhook is enabled and subscribed to `event`
    /// (`webhook_service.go` lines 68–77).
    #[must_use]
    pub fn matches_event(&self, event: &str) -> bool {
        self.enabled && self.events.iter().any(|e| e == event || e == "*")
    }
}

/// Computes the `X-Webhook-Signature` header value `"sha256=<hex>"` over `body`
/// using `signing_key` (`webhook_service.go` lines 96–101).
#[must_use]
pub fn compute_webhook_signature_header(signing_key: &[u8], body: &[u8]) -> String {
    let key = hmac::Key::new(hmac::HMAC_SHA256, signing_key);
    let tag = hmac::sign(&key, body);
    format!("sha256={}", HEXLOWER.encode(tag.as_ref()))
}

/// Linear retry backoff delay in seconds for 0-based `attempt` (`0..3`):
/// `(attempt + 1) * 2` seconds (`2 s`, `4 s`, `6 s`, `webhook_service.go` lines 107 & 115).
#[must_use]
pub const fn webhook_retry_backoff_secs(attempt: u32) -> u64 {
    (attempt as u64 + 1) * 2
}

/// Outbound webhook delivery job queued by [`WebhookDispatcher`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebhookDeliveryJob {
    /// Target webhook ID.
    pub webhook_id: u64,
    /// Target HTTPS URL.
    pub url: String,
    /// Serialized JSON body `{"event":"...","timestamp_ms":...,"data":...}`.
    pub body: Vec<u8>,
    /// Optional `X-Webhook-Signature: sha256=<hex>` header value when `signing_key` is non-empty.
    pub signature_header: Option<String>,
}

/// Manages registered [`WebhookRecord`]s and prepares signed [`WebhookDeliveryJob`]s
/// (`service/webhook_service.go`).
#[derive(Debug, Default, Clone)]
pub struct WebhookDispatcher {
    next_id: u64,
    webhooks: Vec<WebhookRecord>,
}

impl WebhookDispatcher {
    /// Creates an empty [`WebhookDispatcher`].
    #[must_use]
    pub const fn new() -> Self {
        Self {
            next_id: 1,
            webhooks: Vec::new(),
        }
    }

    /// Registers a new webhook and returns its assigned `id`.
    pub fn register(
        &mut self,
        name: impl Into<String>,
        url: impl Into<String>,
        signing_key: Vec<u8>,
        events: Vec<String>,
    ) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        self.webhooks.push(WebhookRecord {
            id,
            name: name.into(),
            url: url.into(),
            signing_key,
            events,
            enabled: true,
            last_triggered_ms: None,
            last_status: 0,
        });
        id
    }

    /// Prepares signed [`WebhookDeliveryJob`]s for all enabled webhooks subscribed to `event`
    /// (`WebhookService.Dispatch`, `webhook_service.go` lines 51–80).
    #[must_use]
    pub fn prepare_dispatch(
        &self,
        event: &str,
        timestamp_ms: u64,
        data_json: &str,
    ) -> Vec<WebhookDeliveryJob> {
        let body =
            format!(r#"{{"event":"{event}","timestamp_ms":{timestamp_ms},"data":{data_json}}}"#)
                .into_bytes();

        self.webhooks
            .iter()
            .filter(|wh| wh.matches_event(event))
            .map(|wh| {
                let signature_header = if wh.signing_key.is_empty() {
                    None
                } else {
                    Some(compute_webhook_signature_header(&wh.signing_key, &body))
                };
                WebhookDeliveryJob {
                    webhook_id: wh.id,
                    url: wh.url.clone(),
                    body: body.clone(),
                    signature_header,
                }
            })
            .collect()
    }

    /// Records the final HTTP status code of a delivery attempt (`webhook_service.go` lines 118–124).
    pub fn record_delivery_status(&mut self, webhook_id: u64, triggered_ms: u64, status_code: u16) {
        if let Some(wh) = self.webhooks.iter_mut().find(|w| w.id == webhook_id) {
            wh.last_triggered_ms = Some(triggered_ms);
            wh.last_status = status_code;
        }
    }
}

/// Administrative dashboard audit log entry (`models/audit_log.go` lines 5–15).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DashboardAuditEntry {
    /// Monotonically increasing primary key ID.
    pub id: u64,
    /// Numeric administrator ID.
    pub admin_id: u64,
    /// Administrator username.
    pub admin_username: String,
    /// Action verb (`"device.delete"`, `"webhook.create"`, `"policy.update"`, etc.).
    pub action: String,
    /// Resource type (`"device"`, `"webhook"`, `"policy"`, `"user"`).
    pub resource_type: String,
    /// Resource identifier.
    pub resource_id: String,
    /// Structured JSON or human-readable details.
    pub details: String,
    /// Client IP address.
    pub ip: String,
    /// Creation timestamp in milliseconds since the Unix epoch.
    pub created_at_ms: u64,
}

/// Cursor-keyset filter parameters for `GET /v1/admin/audit-logs`
/// (`service/audit_service.go` lines 34–40).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct AuditListParams {
    /// Keyset pagination cursor: when `> 0`, only entries with `id < after_id` are returned.
    pub after_id: u64,
    /// Maximum number of entries to return (`0` defaults to `50`).
    pub limit: usize,
    /// Exact action filter (`""` matches all).
    pub action: Option<String>,
    /// Case-insensitive substring filter on `admin_username`.
    pub admin_username: Option<String>,
    /// Inclusive lower bound on `created_at_ms`.
    pub date_from_ms: Option<u64>,
    /// Inclusive upper bound on `created_at_ms`.
    pub date_to_ms: Option<u64>,
}

/// In-memory cursor-keyset administrative audit log service (`service/audit_service.go` lines 12–73).
#[derive(Debug, Default, Clone)]
pub struct AuditLogStore {
    next_id: u64,
    entries: Vec<DashboardAuditEntry>,
}

impl AuditLogStore {
    /// Creates an empty [`AuditLogStore`].
    #[must_use]
    pub const fn new() -> Self {
        Self {
            next_id: 1,
            entries: Vec::new(),
        }
    }

    /// Appends a new [`DashboardAuditEntry`] (`AuditService.Log`, `audit_service.go` lines 20–32).
    #[allow(clippy::too_many_arguments)]
    pub fn log(
        &mut self,
        admin_id: u64,
        admin_username: impl Into<String>,
        action: impl Into<String>,
        resource_type: impl Into<String>,
        resource_id: impl Into<String>,
        details: impl Into<String>,
        ip: impl Into<String>,
        created_at_ms: u64,
    ) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        self.entries.push(DashboardAuditEntry {
            id,
            admin_id,
            admin_username: admin_username.into(),
            action: action.into(),
            resource_type: resource_type.into(),
            resource_id: resource_id.into(),
            details: details.into(),
            ip: ip.into(),
            created_at_ms,
        });
        id
    }

    /// Queries audit logs using `params`, returning `(page_entries_desc, total_matching)`
    /// (`AuditService.List`, `audit_service.go` lines 42–73).
    #[must_use]
    pub fn list(&self, params: &AuditListParams) -> (Vec<DashboardAuditEntry>, usize) {
        let matching: Vec<&DashboardAuditEntry> = self
            .entries
            .iter()
            .filter(|e| {
                if let Some(ref act) = params.action
                    && !act.is_empty()
                    && &e.action != act
                {
                    return false;
                }
                if let Some(ref admin_sub) = params.admin_username
                    && !admin_sub.is_empty()
                    && !e
                        .admin_username
                        .to_ascii_lowercase()
                        .contains(&admin_sub.to_ascii_lowercase())
                {
                    return false;
                }
                if let Some(from_ms) = params.date_from_ms
                    && e.created_at_ms < from_ms
                {
                    return false;
                }
                if let Some(to_ms) = params.date_to_ms
                    && e.created_at_ms > to_ms
                {
                    return false;
                }
                true
            })
            .collect();

        let total = matching.len();
        let limit = if params.limit == 0 { 50 } else { params.limit };

        let page: Vec<DashboardAuditEntry> = matching
            .into_iter()
            .rev()
            .filter(|e| params.after_id == 0 || e.id < params.after_id)
            .take(limit)
            .cloned()
            .collect();

        (page, total)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn webhook_hmac_signature_and_cursor_keyset_audit_log() {
        let mut dispatcher = WebhookDispatcher::new();
        let wh_id = dispatcher.register(
            "SIEM Hook",
            "https://siem.omega.example/hook",
            b"webhook-hmac-key".to_vec(),
            vec!["session.started".to_owned()],
        );

        let jobs =
            dispatcher.prepare_dispatch("session.started", 1_700_000_000_000, r#"{"node":"srv1"}"#);
        assert_eq!(jobs.len(), 1);
        assert!(
            jobs[0]
                .signature_header
                .as_deref()
                .is_some_and(|h| h.starts_with("sha256="))
        );
        assert_eq!(webhook_retry_backoff_secs(0), 2);
        assert_eq!(webhook_retry_backoff_secs(1), 4);
        assert_eq!(webhook_retry_backoff_secs(2), 6);

        dispatcher.record_delivery_status(wh_id, 1_700_000_001_000, 200);

        let mut audit = AuditLogStore::new();
        audit.log(
            1,
            "ricardo",
            "device.enroll",
            "device",
            "d1",
            "ok",
            "10.0.0.1",
            100,
        );
        audit.log(
            1,
            "ricardo",
            "policy.update",
            "policy",
            "p1",
            "ok",
            "10.0.0.1",
            200,
        );
        audit.log(
            2,
            "alice",
            "policy.update",
            "policy",
            "p2",
            "ok",
            "10.0.0.2",
            300,
        );

        let (page, total) = audit.list(&AuditListParams {
            after_id: 3,
            limit: 10,
            action: Some("policy.update".to_owned()),
            ..AuditListParams::default()
        });
        assert_eq!(total, 2);
        assert_eq!(page.len(), 1);
        assert_eq!(page[0].id, 2);
    }
}
