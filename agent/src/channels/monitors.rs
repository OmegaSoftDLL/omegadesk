//! Monitor catalog published to the client and display switching.
//!
//! The agent enumerates the desktop once per session with
//! `omegadesk_capture::list_displays` (same indexes as `open_display`), sends a
//! `DisplayList`, and answers `SelectDisplay` by retargeting the capture thread
//! (RustDesk `src/server/connection.rs` `handle_switch_display` sets the
//! `display` option and restarts the video service on the new monitor;
//! `display_service.rs` builds the `DisplayInfo` list the same way).

use omegadesk_capture::DisplayInfo;
use omegadesk_protocol::v1::{DisplayDescriptor, Envelope, SelectDisplay, envelope::Payload};
use omegadesk_session::{ChannelError, MonitorCatalog};
use tracing::warn;

/// Builds the session's catalog, making `preferred` (the `--display` argument)
/// the active display when it exists.
///
/// When the desktop cannot be enumerated (no DXGI/GDI access yet, as at a
/// locked console) the catalog still contains the configured display with
/// unknown (`0`) dimensions, so the client can show and keep requesting it; the
/// capture thread reports the real size with the first frame.
pub(crate) fn build_catalog(preferred: u32) -> MonitorCatalog {
    let displays = match omegadesk_capture::list_displays() {
        Ok(displays) => displays.iter().map(describe).collect(),
        Err(error) => {
            warn!("monitor enumeration unavailable ({error}); only display {preferred} is offered");
            vec![DisplayDescriptor {
                index: preferred,
                name: format!("display {preferred}"),
                width: 0,
                height: 0,
                origin_x: 0,
                origin_y: 0,
                scale_percent: 100,
                primary: preferred == 0,
            }]
        }
    };
    let mut catalog = MonitorCatalog::new(displays);
    if catalog
        .select(&SelectDisplay {
            display_index: preferred,
        })
        .is_err()
    {
        warn!(
            "--display {preferred} is not attached; sharing display {} instead",
            catalog.active_index()
        );
    }
    catalog
}

/// Converts a capture-side description into the protocol descriptor.
pub(crate) fn describe(info: &DisplayInfo) -> DisplayDescriptor {
    DisplayDescriptor {
        index: info.index,
        name: info.name.clone(),
        width: info.bounds.width,
        height: info.bounds.height,
        origin_x: info.bounds.x,
        origin_y: info.bounds.y,
        scale_percent: info.scale_percent,
        primary: info.primary,
    }
}

/// `DisplayList` message advertising the catalog and its active display.
pub(crate) fn display_list(catalog: &MonitorCatalog) -> Envelope {
    Envelope {
        payload: Some(Payload::DisplayList(catalog.to_proto_list())),
    }
}

/// Applies a client `SelectDisplay`: returns the newly active index, or the
/// error to log when the index is not in the catalog (the active display is unchanged).
pub(crate) fn select(
    catalog: &mut MonitorCatalog,
    request: SelectDisplay,
) -> Result<u32, ChannelError> {
    catalog.select(&request).map(|display| display.index)
}

#[cfg(test)]
mod tests {
    use omegadesk_capture::DisplayBounds;

    use super::*;

    #[test]
    fn describe_maps_every_field() {
        let info = DisplayInfo {
            index: 1,
            name: "\\\\.\\DISPLAY2".into(),
            bounds: DisplayBounds {
                x: -2560,
                y: 0,
                width: 2560,
                height: 1440,
            },
            scale_percent: 125,
            primary: false,
        };
        let descriptor = describe(&info);
        assert_eq!(descriptor.index, 1);
        assert_eq!(descriptor.name, "\\\\.\\DISPLAY2");
        assert_eq!((descriptor.width, descriptor.height), (2560, 1440));
        assert_eq!((descriptor.origin_x, descriptor.origin_y), (-2560, 0));
        assert_eq!(descriptor.scale_percent, 125);
        assert!(!descriptor.primary);
    }

    #[test]
    fn catalog_always_offers_a_display_and_select_validates_the_index() {
        let mut catalog = build_catalog(0);
        let list = catalog.to_proto_list();
        assert_ne!(list.displays.len(), 0);
        assert!(
            list.displays
                .iter()
                .any(|d| d.index == list.active_display_index)
        );
        assert_eq!(
            select(&mut catalog, SelectDisplay { display_index: 999 }),
            Err(ChannelError::UnknownDisplayIndex(999))
        );
        let first = list.displays[0].index;
        assert_eq!(
            select(
                &mut catalog,
                SelectDisplay {
                    display_index: first
                }
            ),
            Ok(first)
        );
        assert!(matches!(
            display_list(&catalog).payload,
            Some(Payload::DisplayList(_))
        ));
    }
}
