#![no_main]

use libfuzzer_sys::fuzz_target;
use omegadesk_identity::DeviceIdentity;

fuzz_target!(|data: &[u8]| {
    if let Ok(identity) = DeviceIdentity::from_secret_bytes(data) {
        let round_trip = DeviceIdentity::from_secret_bytes(&identity.to_secret_bytes())
            .expect("serialized DeviceIdentity must decode back");
        assert_eq!(identity.id(), round_trip.id());
        assert_eq!(
            identity.signing_public_key(),
            round_trip.signing_public_key()
        );
        assert_eq!(
            identity.exchange_public_key(),
            round_trip.exchange_public_key()
        );
    }
});
