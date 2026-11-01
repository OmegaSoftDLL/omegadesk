//! OmegaDesk remote session channels, adaptive video quality control (`video_qos`),
//! Reed-Solomon forward error correction (`GF(2^8)`), and serverless LAN mode
//! (`mDNS` + signed transcript + `TOFU`).

pub mod channels;
pub mod connection_manager;
pub mod dlp;
pub mod fec;
pub mod lan;
pub mod qos;

pub use channels::{
    ChannelError, ChatChannel, ClipboardSync, DEFAULT_FILE_CHUNK_SIZE, FileTransferReceiver,
    FileTransferSender, MAX_CLIPBOARD_BYTES, MonitorCatalog, OPUS_SAMPLE_RATE, OpusStreamProfile,
    TerminalChannel, validate_relative_path,
};
pub use connection_manager::{
    ConnectionEntry, ConnectionFolder, ConnectionProperties, ConnectionProtocol, ConnectionTree,
    DecodedQuery, ImportError, InheritanceFlags, KeywordMatcher, TagFilter, TagFilterKind,
    decode_keyword, import_putty_xml, import_rdcman_rdg, import_rdp_file, rectify_tag_name,
    split_rdp_full_address,
};
pub use dlp::{
    ClipboardDirection, DlpEnforcer, DlpPolicy, DlpViolation, RedactedRegion, WatermarkConfig,
    WatermarkOverlay, redact_bgra_region,
};
pub use fec::{
    DEFAULT_SHARD_SIZE, FecError, MAX_TOTAL_SHARDS, adaptive_parity_count, encode_fec_block,
    reconstruct_fec_block,
};
pub use lan::{
    DEFAULT_LAN_PORT, LanAnnouncement, LanClientHello, LanError, LanServerHello, SERVICE_TYPE,
    TRANSCRIPT_PREFIX, TofuDecision, TofuStore, build_lan_transcript,
};
pub use qos::{
    DELAY_THRESHOLD_MS, INIT_FPS, MAX_FPS, MAX_REF_INVALIDATION_SPAN, MIN_AUTO_FPS, MIN_FPS,
    RecoveryAction, SEVERE_DELAY_THRESHOLD_MS, VideoQosController,
};
