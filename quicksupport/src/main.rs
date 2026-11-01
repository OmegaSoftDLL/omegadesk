//! OmegaDesk QuickSupport single-executable entrypoint.

use omegadesk_identity::DeviceIdentity;
use omegadesk_quicksupport::{
    ClientPermissions, ConsentManager, ConsentPolicy, TemporaryPasswordGuard,
    format_quicksupport_id,
};

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let identity = DeviceIdentity::generate();
    let device_id = identity.id();
    let formatted_id = format_quicksupport_id(device_id);
    let password_guard = TemporaryPasswordGuard::new(6);
    let consent_mgr = ConsentManager::new(ConsentPolicy::default());
    let default_perms = ClientPermissions::DEFAULT;

    tracing::info!(
        quicksupport_id = %formatted_id,
        one_time_password = %password_guard.password(),
        consent_flags = consent_mgr.policy().effective_flags().bits(),
        default_permissions = default_perms.bits(),
        "OmegaDesk QuickSupport ready for incoming support session"
    );
}
