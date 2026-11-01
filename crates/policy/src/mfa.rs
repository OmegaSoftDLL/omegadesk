//! Per-connection MFA step-up verification (RFC 6238 TOTP + challenge binding)
//! and brute-force lockout protection.
//!
//! Reference implementations:
//! - `jumpserver_jumpserver/apps/authentication/` & `apps/acls/` (`docs/plan.md` §2.9 & §4 Phase 5):
//!   per-connection MFA step-up challenges when connecting to sensitive hosts, and IP/account
//!   brute-force lockout after repeated failed authentication attempts.
//! - `apache_guacamole-client` (`guacamole-ext` authentication brute-force guard): temporary
//!   address/account quarantine window after exceeding the failure threshold.

use std::collections::HashMap;

use omegadesk_identity::DeviceId;
use ring::hmac;
use thiserror::Error;

/// Default RFC 6238 TOTP time step in seconds (`30 s`).
pub const TOTP_STEP_SECS: u64 = 30;

/// Errors returned by per-connection MFA verification or brute-force protection.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum MfaError {
    /// Subject or source IP is currently locked out due to repeated failures.
    #[error("subject '{subject}' is locked out until {locked_until_ms} ms")]
    LockedOut {
        /// Locked user or IP key.
        subject: String,
        /// Expiration timestamp in milliseconds since the Unix epoch.
        locked_until_ms: u64,
    },
    /// Step-up MFA challenge has expired.
    #[error("per-connection MFA challenge expired")]
    ChallengeExpired,
    /// Provided 6-digit TOTP code did not match the expected step window.
    #[error("invalid MFA verification code")]
    InvalidCode,
    /// Challenge identifier is unknown or was already consumed by a previous grant.
    #[error("unknown or already consumed MFA challenge '{0}'")]
    UnknownChallenge(String),
    /// The TOTP code was already accepted for this user during its validity window and
    /// cannot issue a second grant (replay).
    #[error("MFA verification code was already used by '{user_id}'")]
    CodeAlreadyUsed {
        /// Operator who already consumed this code.
        user_id: String,
    },
    /// Federated OIDC/SAML/LDAP claim or `WebAuthn` passkey assertion failed validation.
    #[error("authentication assertion rejected: {0}")]
    InvalidAssertion(&'static str),
}

/// Enterprise and passwordless authentication provider kinds (`docs/plan.md` §2.10 line 147,
/// modeled after `apache_guacamole-client/extensions/` and `jumpserver_jumpserver/apps/authentication/`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityProviderKind {
    /// `OpenID` Connect (`OIDC` ID token claims).
    Oidc,
    /// SAML 2.0 enterprise SSO assertion.
    Saml2,
    /// Active Directory / `OpenLDAP` bind & group mapping.
    Ldap,
    /// FIDO2 / `WebAuthn` hardware passkey.
    WebAuthnPasskey,
}

/// Verified identity claim produced by an OIDC, SAML 2.0, or LDAP provider (`JumpServer` & `Guacamole`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FederatedIdentityClaim {
    /// Originating enterprise identity provider.
    pub provider: IdentityProviderKind,
    /// Issuer URL or `EntityID` (`iss`).
    pub issuer: String,
    /// Intended audience / Relying Party ID (`aud`).
    pub audience: String,
    /// Unique subject identifier within the `IdP` (`sub` or LDAP `objectGUID`).
    pub subject: String,
    /// Verified email or UPN.
    pub email: String,
    /// `IdP` group names mapped into OmegaDesk `UserGroup`s.
    pub groups: Vec<String>,
    /// Expiration timestamp in milliseconds since the Unix epoch (`exp`).
    pub expires_at_ms: u64,
}

impl FederatedIdentityClaim {
    /// Validates `issuer`, `audience`, non-empty `subject`, and expiration timestamp at `now_ms`.
    ///
    /// # Errors
    ///
    /// Returns [`MfaError::InvalidAssertion`] if issuer/audience mismatch or the claim has expired.
    pub fn validate(
        &self,
        expected_issuer: &str,
        expected_audience: &str,
        now_ms: u64,
    ) -> Result<(), MfaError> {
        if self.issuer != expected_issuer {
            return Err(MfaError::InvalidAssertion("issuer mismatch"));
        }
        if self.audience != expected_audience {
            return Err(MfaError::InvalidAssertion("audience mismatch"));
        }
        if self.subject.trim().is_empty() {
            return Err(MfaError::InvalidAssertion("empty subject claim"));
        }
        if now_ms >= self.expires_at_ms {
            return Err(MfaError::InvalidAssertion("federated claim expired"));
        }
        Ok(())
    }
}

/// Registered FIDO2 / `WebAuthn` passkey credential with monotonic signature counter
/// clone detection (`docs/plan.md` §2.10 line 147).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebAuthnPasskeyRecord {
    /// Credential ID bytes.
    pub credential_id: Vec<u8>,
    /// Relying Party ID (`"omega.example.com"`).
    pub rp_id: String,
    /// Owner user identifier.
    pub user_id: String,
    /// Ed25519 CBOR Object Signing public key (`alg = -8 / EdDSA`).
    pub public_key: omegadesk_identity::DevicePublic,
    /// Last accepted authenticator `signCount` for cloned-authenticator detection.
    pub last_sign_count: u32,
}

impl WebAuthnPasskeyRecord {
    /// Verifies a `WebAuthn` assertion signature over `authenticator_data || client_data_hash`
    /// and enforces strictly increasing `sign_count` to detect cloned authenticators.
    ///
    /// # Errors
    ///
    /// Returns [`MfaError::InvalidAssertion`] if `sign_count <= self.last_sign_count` or the
    /// Ed25519 signature over the assertion payload is invalid.
    pub fn verify_assertion(
        &mut self,
        authenticator_data: &[u8],
        client_data_hash: &[u8; 32],
        sign_count: u32,
        signature: &[u8; 64],
    ) -> Result<(), MfaError> {
        if sign_count <= self.last_sign_count {
            return Err(MfaError::InvalidAssertion(
                "WebAuthn sign_count did not advance (possible cloned authenticator)",
            ));
        }
        let mut signed_payload = Vec::with_capacity(authenticator_data.len() + 32);
        signed_payload.extend_from_slice(authenticator_data);
        signed_payload.extend_from_slice(client_data_hash);

        self.public_key
            .verify(&signed_payload, signature)
            .map_err(|_| MfaError::InvalidAssertion("invalid WebAuthn passkey signature"))?;
        self.last_sign_count = sign_count;
        Ok(())
    }
}

/// Computes a 6-digit RFC 6238 TOTP code using `HMAC-SHA256` over the 8-byte big-endian
/// time counter `unix_secs / TOTP_STEP_SECS`.
#[must_use]
pub fn compute_totp_sha256(shared_key_bytes: &[u8], unix_secs: u64) -> u32 {
    let counter = unix_secs / TOTP_STEP_SECS;
    let key = hmac::Key::new(hmac::HMAC_SHA256, shared_key_bytes);
    let tag = hmac::sign(&key, &counter.to_be_bytes());
    let bytes = tag.as_ref();
    let offset = (bytes[bytes.len() - 1] & 0x0f) as usize;
    let binary = ((u32::from(bytes[offset]) & 0x7f) << 24)
        | (u32::from(bytes[offset + 1]) << 16)
        | (u32::from(bytes[offset + 2]) << 8)
        | u32::from(bytes[offset + 3]);
    binary % 1_000_000
}

/// Returns every RFC 6238 time counter (`unix_secs / TOTP_STEP_SECS`) inside the `±1`
/// time-step clock skew window (`±30 s`) whose code equals `code`, in ascending order. The
/// vector is empty when no step matches.
///
/// All matched counters are what a caller must remember to refuse replays: RFC 6238 §5.2
/// requires that a verifier "MUST NOT accept the second attempt of the OTP after the
/// successful validation has been issued for the first OTP". Two adjacent counters can
/// legitimately produce the same six-digit code, so remembering only one of them would let
/// the other re-issue a grant one step later.
#[must_use]
pub fn match_totp_counters_sha256(shared_key_bytes: &[u8], code: u32, unix_secs: u64) -> Vec<u64> {
    let steps = [
        unix_secs.saturating_sub(TOTP_STEP_SECS),
        unix_secs,
        unix_secs.saturating_add(TOTP_STEP_SECS),
    ];
    let mut counters: Vec<u64> = steps
        .into_iter()
        .filter(|ts| compute_totp_sha256(shared_key_bytes, *ts) == code)
        .map(|ts| ts / TOTP_STEP_SECS)
        .collect();
    counters.dedup();
    counters
}

/// Verifies a 6-digit TOTP code allowing a `±1` time-step clock skew window (`±30 s`).
///
/// This is a stateless check: it does not detect replays. Per-connection grants must go
/// through [`ConnectionMfaVerifier::verify_and_consume`], which also consumes the challenge
/// and remembers accepted counters per user.
#[must_use]
pub fn verify_totp_sha256(shared_key_bytes: &[u8], code: u32, unix_secs: u64) -> bool {
    !match_totp_counters_sha256(shared_key_bytes, code, unix_secs).is_empty()
}

/// Per-connection MFA challenge binding an operator, a target [`DeviceId`], and an expiration time.
///
/// A challenge is single-use: register it with [`ConnectionMfaVerifier::issue`] and redeem it
/// exactly once with [`ConnectionMfaVerifier::verify_and_consume`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionMfaChallenge {
    /// Unique challenge identifier.
    pub challenge_id: String,
    /// Operator requesting the connection.
    pub user_id: String,
    /// Target device requiring step-up MFA.
    pub target_device: DeviceId,
    /// Challenge expiration timestamp in milliseconds since the Unix epoch.
    pub expires_at_ms: u64,
}

/// Stateful per-connection MFA verifier: holds the pending [`ConnectionMfaChallenge`]s and the
/// TOTP counters already accepted per user, so a challenge and a code can each issue at most
/// one [`VerifiedConnectionGrant`].
///
/// Modeled on `jumpserver_jumpserver/apps/authentication/mixins.py` (`MFAMixin.mark_mfa_ok`,
/// `clean_mfa_mark`, `clear_auth_mark`), where the step-up state lives in server-side session
/// storage and is popped once it has been consumed. JumpServer's `MFAOtp._check_code`
/// (`apps/authentication/mfa/otp.py`) is a stateless code check, so this verifier additionally
/// remembers the accepted counters per user, as RFC 6238 §5.2 requires. The window of remembered
/// counters covers the `±1` step skew accepted by [`match_totp_counters_sha256`], so a code that
/// has issued a grant can never issue another one for the same user.
///
/// The verifier is deliberately not `Clone`: a copy would duplicate the pending challenges and
/// the replay history, letting the same challenge and code succeed once per copy. Share one
/// instance (behind a lock when needed) instead.
#[derive(Debug, Default)]
pub struct ConnectionMfaVerifier {
    pending: HashMap<String, ConnectionMfaChallenge>,
    accepted_counters: HashMap<String, Vec<u64>>,
}

impl ConnectionMfaVerifier {
    /// Creates a verifier with no pending challenges.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers `challenge` as pending. Re-issuing an identifier replaces the previous
    /// unredeemed challenge with that identifier.
    pub fn issue(&mut self, challenge: ConnectionMfaChallenge) {
        self.pending
            .insert(challenge.challenge_id.clone(), challenge);
    }

    /// Returns the number of challenges still waiting for a code.
    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Returns `true` if `challenge_id` is still pending (not consumed, not dropped as expired).
    #[must_use]
    pub fn is_pending(&self, challenge_id: &str) -> bool {
        self.pending.contains_key(challenge_id)
    }

    /// Verifies `code` for the pending challenge `challenge_id` against the operator's TOTP key
    /// material at `now_ms`, atomically consuming the challenge and recording every counter in
    /// the skew window that produces `code` for the operator on success.
    ///
    /// On [`MfaError::InvalidCode`] the challenge stays pending so the operator may retry under
    /// the limits of a [`BruteForceGuard`]; every other failure leaves no reusable state.
    ///
    /// # Errors
    ///
    /// - [`MfaError::UnknownChallenge`] if `challenge_id` was never issued or was already consumed;
    /// - [`MfaError::ChallengeExpired`] if `now_ms > expires_at_ms` (the challenge is dropped);
    /// - [`MfaError::InvalidCode`] if `code` matches no step in the skew window;
    /// - [`MfaError::CodeAlreadyUsed`] if this code (through any of its matching counters)
    ///   already issued a grant for the same user.
    pub fn verify_and_consume(
        &mut self,
        challenge_id: &str,
        shared_key_bytes: &[u8],
        code: u32,
        now_ms: u64,
    ) -> Result<VerifiedConnectionGrant, MfaError> {
        let Some(challenge) = self.pending.get(challenge_id) else {
            return Err(MfaError::UnknownChallenge(challenge_id.to_owned()));
        };
        if now_ms > challenge.expires_at_ms {
            self.pending.remove(challenge_id);
            return Err(MfaError::ChallengeExpired);
        }
        let now_secs = now_ms / 1_000;
        let counters = match_totp_counters_sha256(shared_key_bytes, code, now_secs);
        if counters.is_empty() {
            return Err(MfaError::InvalidCode);
        }

        let user_id = challenge.user_id.clone();
        let accepted = self.accepted_counters.entry(user_id.clone()).or_default();
        // Counters older than the earliest step still inside the skew window can never match
        // again, so forgetting them keeps the per-user list bounded.
        let oldest_valid = (now_secs / TOTP_STEP_SECS).saturating_sub(1);
        accepted.retain(|c| *c >= oldest_valid);
        // A code that matches two adjacent counters is consumed for both: otherwise the counter
        // that was not recorded would re-issue a grant for the same digits one step later.
        if counters.iter().any(|c| accepted.contains(c)) {
            return Err(MfaError::CodeAlreadyUsed { user_id });
        }
        accepted.extend(counters);

        let Some(challenge) = self.pending.remove(challenge_id) else {
            return Err(MfaError::UnknownChallenge(challenge_id.to_owned()));
        };
        Ok(VerifiedConnectionGrant {
            challenge_id: challenge.challenge_id,
            user_id: challenge.user_id,
            target_device: challenge.target_device,
            verified_at_ms: now_ms,
        })
    }
}

/// Proof that an operator satisfied per-connection MFA for a specific target device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedConnectionGrant {
    /// Challenge identifier that was satisfied.
    pub challenge_id: String,
    /// Verified operator identifier.
    pub user_id: String,
    /// Target device unlocked by this step-up verification.
    pub target_device: DeviceId,
    /// Timestamp in milliseconds when verification succeeded.
    pub verified_at_ms: u64,
}

#[derive(Debug, Clone)]
struct FailureState {
    failures: u32,
    locked_until_ms: u64,
}

/// Brute-force lockout tracker protecting authentication and MFA endpoints (`JumpServer` & `Guacamole`).
#[derive(Debug, Clone)]
pub struct BruteForceGuard {
    max_failures: u32,
    lockout_duration_ms: u64,
    subjects: HashMap<String, FailureState>,
}

impl BruteForceGuard {
    /// Creates a new brute-force tracker that locks a subject for `lockout_duration_ms`
    /// after `max_failures` consecutive failed attempts.
    #[must_use]
    pub fn new(max_failures: u32, lockout_duration_ms: u64) -> Self {
        Self {
            max_failures: max_failures.max(1),
            lockout_duration_ms,
            subjects: HashMap::new(),
        }
    }

    /// Checks whether `subject` (a user ID or client IP) is currently locked out at `now_ms`.
    ///
    /// # Errors
    ///
    /// Returns [`MfaError::LockedOut`] if the lockout window has not yet expired.
    pub fn check_allowed(&self, subject: &str, now_ms: u64) -> Result<(), MfaError> {
        if let Some(state) = self.subjects.get(subject)
            && state.locked_until_ms > now_ms
        {
            return Err(MfaError::LockedOut {
                subject: subject.to_owned(),
                locked_until_ms: state.locked_until_ms,
            });
        }
        Ok(())
    }

    /// Records a failed authentication attempt for `subject` at `now_ms`, returning
    /// `Err(MfaError::LockedOut)` if this attempt triggered a lockout.
    ///
    /// # Errors
    ///
    /// Returns [`MfaError::LockedOut`] if the failure threshold is reached.
    pub fn record_failure(&mut self, subject: &str, now_ms: u64) -> Result<u32, MfaError> {
        let entry = self
            .subjects
            .entry(subject.to_owned())
            .or_insert(FailureState {
                failures: 0,
                locked_until_ms: 0,
            });
        if entry.locked_until_ms > 0 && entry.locked_until_ms <= now_ms {
            entry.failures = 0;
            entry.locked_until_ms = 0;
        }
        entry.failures += 1;
        if entry.failures >= self.max_failures {
            entry.locked_until_ms = now_ms.saturating_add(self.lockout_duration_ms);
            return Err(MfaError::LockedOut {
                subject: subject.to_owned(),
                locked_until_ms: entry.locked_until_ms,
            });
        }
        Ok(entry.failures)
    }

    /// Clears the failure counter for `subject` after a successful authentication.
    pub fn record_success(&mut self, subject: &str) {
        self.subjects.remove(subject);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use omegadesk_identity::DeviceIdentity;

    #[test]
    fn per_connection_mfa_and_brute_force_lockout() {
        let key_material = [0x37u8; 32];
        let device_id = DeviceIdentity::generate().id();
        let now_ms = 1_700_000_000_000u64;

        let challenge = ConnectionMfaChallenge {
            challenge_id: "chal-1".to_owned(),
            user_id: "alice".to_owned(),
            target_device: device_id,
            expires_at_ms: now_ms + 60_000,
        };

        let code = compute_totp_sha256(&key_material, now_ms / 1_000);
        let mut verifier = ConnectionMfaVerifier::new();
        verifier.issue(challenge);
        let grant = verifier.verify_and_consume("chal-1", &key_material, code, now_ms);
        assert!(grant.is_ok());

        let mut guard = BruteForceGuard::new(3, 300_000);
        assert_eq!(guard.record_failure("192.0.2.10", now_ms), Ok(1));
        assert_eq!(guard.record_failure("192.0.2.10", now_ms + 1_000), Ok(2));
        assert!(guard.record_failure("192.0.2.10", now_ms + 2_000).is_err());
        assert!(guard.check_allowed("192.0.2.10", now_ms + 5_000).is_err());
        assert!(guard.check_allowed("192.0.2.10", now_ms + 305_000).is_ok());

        // Federated OIDC claim & WebAuthn Passkey verification with sign_count clone check
        let claim = FederatedIdentityClaim {
            provider: IdentityProviderKind::Oidc,
            issuer: "https://idp.omega.example".to_owned(),
            audience: "omegadesk-coordinator".to_owned(),
            subject: "sub-alice-01".to_owned(),
            email: "alice@omega.example".to_owned(),
            groups: vec!["netops".to_owned()],
            expires_at_ms: now_ms + 60_000,
        };
        assert!(
            claim
                .validate("https://idp.omega.example", "omegadesk-coordinator", now_ms)
                .is_ok()
        );

        let passkey_id = DeviceIdentity::generate();
        let mut passkey = WebAuthnPasskeyRecord {
            credential_id: vec![1, 2, 3, 4],
            rp_id: "omega.example".to_owned(),
            user_id: "alice".to_owned(),
            public_key: passkey_id.public(),
            last_sign_count: 10,
        };
        let auth_data = b"rp-id-hash-and-flags";
        let client_hash = [0x55u8; 32];
        let mut msg = Vec::new();
        msg.extend_from_slice(auth_data);
        msg.extend_from_slice(&client_hash);
        let sig = passkey_id.sign(&msg);

        assert!(
            passkey
                .verify_assertion(auth_data, &client_hash, 11, &sig)
                .is_ok()
        );
        // Replaying with sign_count <= 11 must be rejected as a cloned authenticator
        assert!(
            passkey
                .verify_assertion(auth_data, &client_hash, 11, &sig)
                .is_err()
        );
    }

    /// Issue #29 `mfa.rs:100`: a verified code and its challenge must not be reusable. The
    /// challenge is consumed atomically and the accepted counter is remembered per user.
    #[test]
    fn totp_code_and_challenge_cannot_issue_two_grants() {
        let key_material = [0x42u8; 32];
        let device_id = DeviceIdentity::generate().id();
        let now_ms = 1_700_000_000_000u64;
        let challenge = |id: &str, user: &str| ConnectionMfaChallenge {
            challenge_id: id.to_owned(),
            user_id: user.to_owned(),
            target_device: device_id,
            expires_at_ms: now_ms + 60_000,
        };

        let mut verifier = ConnectionMfaVerifier::new();
        verifier.issue(challenge("chal-1", "alice"));
        verifier.issue(challenge("chal-2", "alice"));
        verifier.issue(challenge("chal-bob", "bob"));
        let code = compute_totp_sha256(&key_material, now_ms / 1_000);

        // A wrong code keeps the challenge pending (retry is governed by BruteForceGuard).
        let wrong = (code + 1) % 1_000_000;
        assert_eq!(
            verifier.verify_and_consume("chal-1", &key_material, wrong, now_ms),
            Err(MfaError::InvalidCode)
        );
        assert!(verifier.is_pending("chal-1"));

        // First redemption succeeds and consumes the challenge.
        let grant = verifier
            .verify_and_consume("chal-1", &key_material, code, now_ms)
            .unwrap();
        assert_eq!(grant.challenge_id, "chal-1");
        assert!(!verifier.is_pending("chal-1"));

        // Replaying the same challenge fails: it no longer exists.
        assert_eq!(
            verifier.verify_and_consume("chal-1", &key_material, code, now_ms + 1_000),
            Err(MfaError::UnknownChallenge("chal-1".to_owned()))
        );

        // Replaying the same code against another challenge of the same user fails, and the
        // second challenge stays pending for a fresh code.
        assert_eq!(
            verifier.verify_and_consume("chal-2", &key_material, code, now_ms + 1_000),
            Err(MfaError::CodeAlreadyUsed {
                user_id: "alice".to_owned()
            })
        );
        assert!(verifier.is_pending("chal-2"));

        // The counter list is per user: Bob's own key producing the same counter is unaffected.
        assert!(
            verifier
                .verify_and_consume("chal-bob", &key_material, code, now_ms + 1_000)
                .is_ok()
        );

        // The next time step issues a new code that Alice can redeem.
        let later_ms = now_ms + TOTP_STEP_SECS * 1_000;
        let next_code = compute_totp_sha256(&key_material, later_ms / 1_000);
        assert!(
            verifier
                .verify_and_consume("chal-2", &key_material, next_code, later_ms)
                .is_ok()
        );
        assert_eq!(verifier.pending_count(), 0);

        // An expired challenge is dropped rather than left around.
        verifier.issue(challenge("chal-late", "alice"));
        assert_eq!(
            verifier.verify_and_consume("chal-late", &key_material, next_code, now_ms + 61_000),
            Err(MfaError::ChallengeExpired)
        );
        assert!(!verifier.is_pending("chal-late"));
    }

    /// PR #36 review: when two adjacent counters inside the skew window produce the same
    /// six-digit code, both must be consumed by the first grant, otherwise the second counter
    /// re-issues a grant for the same digits one step later.
    #[test]
    fn code_matching_two_counters_is_consumed_for_both() {
        let key_material = [0x42u8; 32];
        let now_ms = 1_744_070_490_000u64;
        let code = 777_880u32;

        // Precondition: this code is produced by two different counters in the ±1 step window.
        let counters = match_totp_counters_sha256(&key_material, code, now_ms / 1_000);
        assert_eq!(
            counters.len(),
            2,
            "test vector must collide on two counters"
        );
        assert!(verify_totp_sha256(&key_material, code, now_ms / 1_000));

        let device_id = DeviceIdentity::generate().id();
        let challenge = |id: &str| ConnectionMfaChallenge {
            challenge_id: id.to_owned(),
            user_id: "alice".to_owned(),
            target_device: device_id,
            expires_at_ms: now_ms + 120_000,
        };
        let mut verifier = ConnectionMfaVerifier::new();
        verifier.issue(challenge("chal-1"));
        verifier.issue(challenge("chal-2"));

        assert!(
            verifier
                .verify_and_consume("chal-1", &key_material, code, now_ms)
                .is_ok()
        );
        // One step later the first counter has been pruned, but the second one still matches
        // and must also be remembered as consumed.
        assert_eq!(
            verifier.verify_and_consume(
                "chal-2",
                &key_material,
                code,
                now_ms + TOTP_STEP_SECS * 1_000
            ),
            Err(MfaError::CodeAlreadyUsed {
                user_id: "alice".to_owned()
            })
        );
        assert!(verifier.is_pending("chal-2"));
    }
}
