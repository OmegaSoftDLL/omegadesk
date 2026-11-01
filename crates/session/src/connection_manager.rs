//! Connection Manager with folder property inheritance, `#tag` / `-#tag`
//! filterable search launcher, and `.rdp`, `RDCMan` `.rdg`, and `PuTTY` XML importers.
//!
//! Ported from the reference implementations in `omegadesk-ref`:
//! - **Tag & Keyword Launcher** (`1Remote_1Remote/Ui/Utils/TagAndKeywordEncodeHelper.cs`,
//!   `Ui/Model/TagFilter.cs`, and `Ui/Service/KeywordMatchService.cs`):
//!   - [`rectify_tag_name`]: strips `#`, replaces whitespace with `-`, and
//!     normalizes to lowercase (`TagAndKeywordEncodeHelper.RectifyTagName`).
//!   - [`decode_keyword`]: parses search strings into included (`#tag`, `+#tag`),
//!     excluded (`-#tag`), and partial prefix tags (`TagFilter.FilterType`),
//!     plus general search keywords (`TagAndKeywordEncodeHelper.DecodeKeyword`).
//!   - [`KeywordMatcher`]: evaluates `DirectMatch` (case-insensitive substring),
//!     `InitialsMatch` (first letter of each word, e.g. `"ws"` matching
//!     `"Web Server"`), and `DiscreteMatch` (ordered character subsequence)
//!     (`KeywordMatchService.cs`).
//! - **Folder Hierarchy & Property Inheritance**
//!   (`mRemoteNG_mRemoteNG/mRemoteNG/Connection/ConnectionInfoInheritance.cs`):
//!   [`ConnectionTree`] resolves effective properties (`username`, `domain`,
//!   `port`, `protocol`, `gateway_hostname`, `use_console_session`,
//!   `redirect_clipboard`, `redirect_audio`) from parent folders unless
//!   overridden by child [`InheritanceFlags`].
//! - **Importers**:
//!   - **`.rdp` files** (`Devolutions_IronRDP/crates/ironrdp-rdpfile/src/lib.rs` +
//!     `mRemoteNG/Config/Serializers/MiscSerializers/RemoteDesktopConnectionDeserializer.cs`):
//!     parses `key:i:<int>` and `key:s:<string>` lines, handles bare IPv6 `full address`
//!     values (`[2001:db8::1]:3389` or `2001:db8::1`), `server port`, `username`, `domain`,
//!     `connect to console` / `administrative session`, and RD Gateway settings
//!     (`gatewayusagemethod`, `gatewayhostname`).
//!   - **`RDCMan` `.rdg` XML** (`RemoteDesktopConnectionManagerDeserializer.cs`):
//!     imports `<RDCMan schemaVersion="1|3">` nested `<group>` and `<server>`
//!     hierarchies with inherited `<logonCredentials>` and `<connectionSettings>`.
//!   - **`PuTTY` Connection Manager XML** (`PuttyConnectionManagerDeserializer.cs`):
//!     imports `<configuration><root type="database">` nested `<container type="folder">`
//!     and `<connection type="PuTTY">` SSH/Telnet entries.

use std::collections::HashMap;

/// Remote connection protocol supported by an entry in the Connection Manager.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionProtocol {
    /// Native OmegaDesk QUIC/WebRTC session.
    OmegaDesk,
    /// Microsoft Remote Desktop Protocol (`RDP`, default port `3389`).
    Rdp,
    /// Secure Shell (`SSH`, default port `22`).
    Ssh,
    /// Telnet (`default port 23`).
    Telnet,
    /// Virtual Network Computing (`VNC`, default port `5900`).
    Vnc,
}

impl ConnectionProtocol {
    /// Default TCP/UDP port for this protocol.
    #[must_use]
    pub const fn default_port(self) -> u16 {
        match self {
            Self::OmegaDesk => 4433,
            Self::Rdp => 3389,
            Self::Ssh => 22,
            Self::Telnet => 23,
            Self::Vnc => 5900,
        }
    }
}

/// Per-field inheritance flags modeled after mRemoteNG's
/// `ConnectionInfoInheritance` (`mRemoteNG/Connection/ConnectionInfoInheritance.cs`).
///
/// When a flag is `true` on a child folder or connection entry, the corresponding
/// property is inherited from its parent folder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct InheritanceFlags {
    /// Inherit `username` from parent folder.
    pub username: bool,
    /// Inherit `domain` from parent folder.
    pub domain: bool,
    /// Inherit `protocol` from parent folder.
    pub protocol: bool,
    /// Inherit `port` from parent folder.
    pub port: bool,
    /// Inherit `gateway_hostname` from parent folder.
    pub gateway_hostname: bool,
    /// Inherit `use_console_session` from parent folder.
    pub use_console_session: bool,
    /// Inherit `redirect_clipboard` from parent folder.
    pub redirect_clipboard: bool,
    /// Inherit `redirect_audio` from parent folder.
    pub redirect_audio: bool,
}

impl InheritanceFlags {
    /// No properties are inherited (used by root folders or standalone entries).
    #[must_use]
    pub const fn none() -> Self {
        Self {
            username: false,
            domain: false,
            protocol: false,
            port: false,
            gateway_hostname: false,
            use_console_session: false,
            redirect_clipboard: false,
            redirect_audio: false,
        }
    }

    /// All inheritable properties are inherited from the parent folder.
    #[must_use]
    pub const fn all() -> Self {
        Self {
            username: true,
            domain: true,
            protocol: true,
            port: true,
            gateway_hostname: true,
            use_console_session: true,
            redirect_clipboard: true,
            redirect_audio: true,
        }
    }
}

impl Default for InheritanceFlags {
    fn default() -> Self {
        Self::none()
    }
}

/// Configurable connection properties shared between folders and connection entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionProperties {
    /// Login username.
    pub username: String,
    /// Windows / Active Directory domain.
    pub domain: String,
    /// Remote protocol.
    pub protocol: ConnectionProtocol,
    /// Target TCP/UDP port.
    pub port: u16,
    /// Optional RD Gateway or jump-host hostname.
    pub gateway_hostname: Option<String>,
    /// Connect to console / administrative session (`/admin`).
    pub use_console_session: bool,
    /// Synchronize clipboard during session.
    pub redirect_clipboard: bool,
    /// Stream remote audio to local output.
    pub redirect_audio: bool,
}

impl Default for ConnectionProperties {
    fn default() -> Self {
        Self {
            username: String::new(),
            domain: String::new(),
            protocol: ConnectionProtocol::OmegaDesk,
            port: ConnectionProtocol::OmegaDesk.default_port(),
            gateway_hostname: None,
            use_console_session: false,
            redirect_clipboard: true,
            redirect_audio: true,
        }
    }
}

impl ConnectionProperties {
    /// Resolves effective properties by overlaying `child` onto `parent`
    /// according to `inheritance` (`ConnectionInfoInheritance.cs`).
    #[must_use]
    pub fn resolve_from_parent(&self, parent: &Self, inheritance: InheritanceFlags) -> Self {
        Self {
            username: if inheritance.username {
                parent.username.clone()
            } else {
                self.username.clone()
            },
            domain: if inheritance.domain {
                parent.domain.clone()
            } else {
                self.domain.clone()
            },
            protocol: if inheritance.protocol {
                parent.protocol
            } else {
                self.protocol
            },
            port: if inheritance.port {
                parent.port
            } else {
                self.port
            },
            gateway_hostname: if inheritance.gateway_hostname {
                parent.gateway_hostname.clone()
            } else {
                self.gateway_hostname.clone()
            },
            use_console_session: if inheritance.use_console_session {
                parent.use_console_session
            } else {
                self.use_console_session
            },
            redirect_clipboard: if inheritance.redirect_clipboard {
                parent.redirect_clipboard
            } else {
                self.redirect_clipboard
            },
            redirect_audio: if inheritance.redirect_audio {
                parent.redirect_audio
            } else {
                self.redirect_audio
            },
        }
    }
}

/// Folder node in the [`ConnectionTree`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionFolder {
    /// Unique folder identifier.
    pub id: String,
    /// Display name of the folder.
    pub name: String,
    /// Optional parent folder identifier.
    pub parent_id: Option<String>,
    /// Folder-level default properties passed down to children.
    pub properties: ConnectionProperties,
    /// Which properties this folder itself inherits from its parent folder.
    pub inheritance: InheritanceFlags,
}

/// Saved remote host entry in the [`ConnectionTree`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionEntry {
    /// Unique entry identifier.
    pub id: String,
    /// Display name (e.g., `"Prod Web Server 01"`).
    pub display_name: String,
    /// Target hostname, IPv4, IPv6, or `*.omega` FQDN.
    pub hostname: String,
    /// Optional parent folder identifier.
    pub parent_folder_id: Option<String>,
    /// Normalized lowercase tags (rectified via [`rectify_tag_name`]).
    pub tags: Vec<String>,
    /// Entry-specific properties.
    pub properties: ConnectionProperties,
    /// Which properties this entry inherits from `parent_folder_id`.
    pub inheritance: InheritanceFlags,
}

/// Hierarchical connection book with mRemoteNG-style folder inheritance and
/// 1Remote-style `#tag` / keyword launcher filtering.
#[derive(Debug, Default, Clone)]
pub struct ConnectionTree {
    folders: HashMap<String, ConnectionFolder>,
    entries: Vec<ConnectionEntry>,
}

impl ConnectionTree {
    /// Creates an empty [`ConnectionTree`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts or updates a folder in the hierarchy.
    pub fn upsert_folder(&mut self, folder: ConnectionFolder) {
        self.folders.insert(folder.id.clone(), folder);
    }

    /// Adds a connection entry, normalizing all of its tags via [`rectify_tag_name`].
    pub fn add_entry(&mut self, mut entry: ConnectionEntry) {
        entry.tags = entry
            .tags
            .iter()
            .map(|t| rectify_tag_name(t))
            .filter(|t| !t.is_empty())
            .collect();
        self.entries.push(entry);
    }

    /// Returns all stored entries.
    #[must_use]
    pub fn entries(&self) -> &[ConnectionEntry] {
        &self.entries
    }

    /// Returns a folder by identifier.
    #[must_use]
    pub fn folder(&self, id: &str) -> Option<&ConnectionFolder> {
        self.folders.get(id)
    }

    /// Resolves the effective [`ConnectionProperties`] for `folder_id` by walking
    /// up the ancestor folder chain (`ConnectionInfoInheritance.cs`).
    #[must_use]
    pub fn effective_folder_properties(&self, folder_id: &str) -> Option<ConnectionProperties> {
        let mut chain = Vec::new();
        let mut cur = Some(folder_id);
        while let Some(id) = cur {
            if chain.contains(&id) {
                break; // Guard against cycles
            }
            let folder = self.folders.get(id)?;
            chain.push(id);
            cur = folder.parent_id.as_deref();
        }
        // Resolve from root ancestor down to `folder_id`.
        chain.reverse();
        let mut acc: Option<ConnectionProperties> = None;
        for id in chain {
            let folder = self.folders.get(id)?;
            acc = Some(match acc {
                None => folder.properties.clone(),
                Some(parent_props) => folder
                    .properties
                    .resolve_from_parent(&parent_props, folder.inheritance),
            });
        }
        acc
    }

    /// Resolves the effective [`ConnectionProperties`] for `entry`, applying
    /// ancestor folder inheritance when `entry.parent_folder_id` is set.
    #[must_use]
    pub fn effective_entry_properties(&self, entry: &ConnectionEntry) -> ConnectionProperties {
        if let Some(ref parent_id) = entry.parent_folder_id
            && let Some(parent_props) = self.effective_folder_properties(parent_id)
        {
            return entry
                .properties
                .resolve_from_parent(&parent_props, entry.inheritance);
        }
        entry.properties.clone()
    }

    /// Filters entries using 1Remote's `#tag` / `+#tag` / `-#tag` and
    /// multi-keyword launcher syntax (`TagAndKeywordEncodeHelper.cs` +
    /// `KeywordMatchService.cs`).
    #[must_use]
    pub fn search(&self, raw_query: &str) -> Vec<&ConnectionEntry> {
        let decoded = decode_keyword(raw_query);
        if decoded.is_empty() {
            return self.entries.iter().collect();
        }

        self.entries
            .iter()
            .filter(|entry| matches_tag_filters(&entry.tags, &decoded.tag_filters))
            .filter(|entry| {
                if decoded.keywords.is_empty() {
                    return true;
                }
                KeywordMatcher::match_keywords(
                    &[entry.display_name.as_str(), entry.hostname.as_str()],
                    &decoded.keywords,
                )
            })
            .collect()
    }
}

/// Normalizes a tag name according to 1Remote's
/// `TagAndKeywordEncodeHelper.RectifyTagName`: strips `#`, replaces spaces with
/// `-`, trims, and converts to ASCII lowercase.
#[must_use]
pub fn rectify_tag_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for ch in name.trim().chars() {
        if ch == '#' {
            continue;
        }
        if ch.is_whitespace() {
            out.push('-');
        } else {
            out.push(ch.to_ascii_lowercase());
        }
    }
    out.trim_matches('-').to_owned()
}

/// Tag filter Polarity, ported from 1Remote's `TagFilter.FilterType`
/// (`Ui/Model/TagFilter.cs`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TagFilterKind {
    /// Entry must possess this exact tag (`+#tag` or complete `#tag`).
    Included,
    /// Entry must NOT possess this tag (`-#tag`).
    Excluded,
    /// Entry must possess at least one tag starting with this prefix (trailing
    /// `#prefix` still being typed by the user).
    PrefixIncluded,
}

/// Single tag filter parsed from a search query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TagFilter {
    /// Normalized lowercase tag name (without `#`).
    pub tag_name: String,
    /// Inclusion/exclusion mode.
    pub kind: TagFilterKind,
}

/// Decoded search query produced by [`decode_keyword`], modeled after 1Remote's
/// `TagAndKeywordEncodeHelper.DecodeKeyword`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DecodedQuery {
    /// Parsed `#tag` / `+#tag` / `-#tag` filters.
    pub tag_filters: Vec<TagFilter>,
    /// Remaining non-tag search keywords.
    pub keywords: Vec<String>,
}

impl DecodedQuery {
    /// Returns `true` if the query contains neither tag filters nor keywords.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.tag_filters.is_empty() && self.keywords.is_empty()
    }
}

/// Parses a launcher query string into [`TagFilter`]s and plain keywords,
/// ported from `1Remote/Ui/Utils/TagAndKeywordEncodeHelper.cs` (`DecodeKeyword`).
///
/// Rules matching 1Remote:
/// - Words starting with `#` or `+#` add an included [`TagFilter`]. If the
///   query does not end with a space and the `#tag` is the last token, it uses
///   [`TagFilterKind::PrefixIncluded`] so partial tag typing works live.
/// - Words starting with `-#` add an [`TagFilterKind::Excluded`] filter.
/// - All other space-separated tokens become general search `keywords`.
#[must_use]
pub fn decode_keyword(raw_query: &str) -> DecodedQuery {
    if raw_query.trim().is_empty() {
        return DecodedQuery::default();
    }
    let ends_with_space = raw_query.ends_with(' ');
    let words: Vec<&str> = raw_query.split(' ').filter(|w| !w.is_empty()).collect();
    let mut tag_filters = Vec::new();
    let mut keywords = Vec::new();

    for (idx, &word) in words.iter().enumerate() {
        let is_last_incomplete = !ends_with_space && idx + 1 == words.len();
        if word.starts_with('#') || word.starts_with("+#") || word.starts_with("-#") {
            let is_excluded = word.starts_with("-#");
            let stripped = word
                .trim_start_matches('+')
                .trim_start_matches('-')
                .trim_start_matches('#');
            let tag_name = rectify_tag_name(stripped);
            if !tag_name.is_empty() {
                let kind = if is_excluded {
                    TagFilterKind::Excluded
                } else if is_last_incomplete && word.starts_with('#') {
                    TagFilterKind::PrefixIncluded
                } else {
                    TagFilterKind::Included
                };
                tag_filters.push(TagFilter { tag_name, kind });
            }
        } else {
            keywords.push(word.to_owned());
        }
    }

    DecodedQuery {
        tag_filters,
        keywords,
    }
}

fn matches_tag_filters(entry_tags: &[String], filters: &[TagFilter]) -> bool {
    for filter in filters {
        match filter.kind {
            TagFilterKind::Included => {
                if !entry_tags.iter().any(|t| t == &filter.tag_name) {
                    return false;
                }
            }
            TagFilterKind::Excluded => {
                if entry_tags.iter().any(|t| t == &filter.tag_name) {
                    return false;
                }
            }
            TagFilterKind::PrefixIncluded => {
                if !entry_tags.iter().any(|t| t.starts_with(&filter.tag_name)) {
                    return false;
                }
            }
        }
    }
    true
}

/// Keyword matcher ported from 1Remote's `KeywordMatchService.cs`
/// (`DirectMatch`, `InitialsMatch`, and `DiscreteMatch`).
pub struct KeywordMatcher;

impl KeywordMatcher {
    /// Returns `true` if every keyword in `keywords` matches at least one string
    /// in `targets` via [`Self::direct_match`], [`Self::initials_match`], or
    /// [`Self::discrete_match`].
    #[must_use]
    pub fn match_keywords(targets: &[&str], keywords: &[String]) -> bool {
        for kw in keywords {
            let matched = targets.iter().any(|target| Self::match_single(target, kw));
            if !matched {
                return false;
            }
        }
        true
    }

    /// Returns `true` if `keyword` matches `target` via direct substring,
    /// word-initials, or ordered discrete character subsequence.
    #[must_use]
    pub fn match_single(target: &str, keyword: &str) -> bool {
        if keyword.is_empty() {
            return true;
        }
        if target.is_empty() {
            return false;
        }
        Self::direct_match(target, keyword)
            || Self::initials_match(target, keyword)
            || Self::discrete_match(target, keyword)
    }

    /// Case-insensitive substring match (`DirectMatch`).
    #[must_use]
    pub fn direct_match(target: &str, keyword: &str) -> bool {
        target
            .to_ascii_lowercase()
            .contains(&keyword.to_ascii_lowercase())
    }

    /// Word-initials match (`InitialsMatch`): extracts the first character of
    /// each word separated by spaces, hyphens, underscores, or dots (e.g.
    /// `"Prod Web Server"` -> `"pws"`) and checks case-insensitive substring match.
    #[must_use]
    pub fn initials_match(target: &str, keyword: &str) -> bool {
        let initials: String = target
            .split([' ', '-', '_', '.'])
            .filter_map(|word| word.chars().next())
            .map(|c| c.to_ascii_lowercase())
            .collect();
        initials.contains(&keyword.to_ascii_lowercase())
    }

    /// Ordered character subsequence match (`DiscreteMatch` in
    /// `1Remote/Ui/Service/KeywordMatchService.cs`).
    #[must_use]
    pub fn discrete_match(target: &str, keyword: &str) -> bool {
        let mut target_chars = target.chars().map(|c| c.to_ascii_lowercase());
        for kw_char in keyword.chars().map(|c| c.to_ascii_lowercase()) {
            if !target_chars.any(|tc| tc == kw_char) {
                return false;
            }
        }
        true
    }
}

/// Errors returned by `.rdp`, `RDCMan` `.rdg`, or `PuTTY` XML importers.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ImportError {
    /// Input file is empty or missing required connection fields.
    #[error("missing required field in imported connection file: {0}")]
    MissingField(&'static str),
    /// XML structure is malformed or has an unsupported schema version.
    #[error("malformed or unsupported XML connection file: {0}")]
    InvalidXml(String),
}

/// Parses a Microsoft `.rdp` file into a [`ConnectionEntry`], ported from
/// `Devolutions_IronRDP/crates/ironrdp-rdpfile/src/lib.rs` and mRemoteNG's
/// `RemoteDesktopConnectionDeserializer.cs`.
///
/// Supports:
/// - `full address:s:<host[:port]>` including bracketed IPv6 (`[::1]:3389`) and
///   bare IPv6 (`2001:db8::1` without misinterpreting the last hextet as a port).
/// - `server port:i:<port>`
/// - `username:s:<user>` and `domain:s:<domain>`
/// - `connect to console:i:1` and `administrative session:i:1`
/// - `redirectclipboard:i:0|1` and `audiomode:i:0|1|2`
/// - `gatewayusagemethod:i:1|2` and `gatewayhostname:s:<host>`
///
/// # Errors
///
/// Returns [`ImportError::MissingField`] if `full address:s:` is missing or empty.
pub fn import_rdp_file(
    id: &str,
    display_name: &str,
    content: &str,
) -> Result<ConnectionEntry, ImportError> {
    let mut int_props: HashMap<String, i64> = HashMap::new();
    let mut str_props: HashMap<String, String> = HashMap::new();

    for raw_line in content.lines() {
        let line = raw_line.trim().trim_start_matches('\u{feff}');
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        let parts: Vec<&str> = line.splitn(3, ':').collect();
        if parts.len() != 3 {
            continue;
        }
        let key = parts[0].trim().to_ascii_lowercase();
        let kind = parts[1].trim().to_ascii_lowercase();
        let val = parts[2].trim();

        match kind.as_str() {
            "i" => {
                if let Ok(parsed) = val.parse::<i64>() {
                    int_props.insert(key, parsed);
                }
            }
            "s" => {
                str_props.insert(key, val.to_owned());
            }
            _ => {}
        }
    }

    let full_address = str_props
        .get("full address")
        .filter(|s| !s.is_empty())
        .ok_or(ImportError::MissingField("full address"))?;

    let default_port = int_props
        .get("server port")
        .and_then(|&p| u16::try_from(p).ok())
        .unwrap_or(ConnectionProtocol::Rdp.default_port());

    let (hostname, port) = split_rdp_full_address(full_address, default_port);

    let username = str_props.get("username").cloned().unwrap_or_default();
    let domain = str_props.get("domain").cloned().unwrap_or_default();
    let use_console_session = int_props.get("connect to console").copied().unwrap_or(0) == 1
        || int_props
            .get("administrative session")
            .copied()
            .unwrap_or(0)
            == 1;
    let redirect_clipboard = int_props.get("redirectclipboard").copied().unwrap_or(1) != 0;
    // audiomode: 0 = bring to this computer, 1 = leave at remote, 2 = do not play
    let redirect_audio = int_props.get("audiomode").copied().unwrap_or(0) == 0;

    let gateway_method = int_props.get("gatewayusagemethod").copied().unwrap_or(0);
    let gateway_hostname = if gateway_method == 1 || gateway_method == 2 {
        str_props
            .get("gatewayhostname")
            .filter(|h| !h.is_empty())
            .cloned()
    } else {
        None
    };

    Ok(ConnectionEntry {
        id: id.to_owned(),
        display_name: display_name.to_owned(),
        hostname,
        parent_folder_id: None,
        tags: vec!["rdp".to_owned()],
        properties: ConnectionProperties {
            username,
            domain,
            protocol: ConnectionProtocol::Rdp,
            port,
            gateway_hostname,
            use_console_session,
            redirect_clipboard,
            redirect_audio,
        },
        inheritance: InheritanceFlags::none(),
    })
}

/// Splits an RDP `full address` string into `(hostname, port)`, handling IPv4,
/// DNS names, bracketed IPv6 (`[2001:db8::1]:3389`), and bare IPv6
/// (`2001:db8::1`), matching `RemoteDesktopConnectionDeserializer.cs`.
#[must_use]
pub fn split_rdp_full_address(full_address: &str, default_port: u16) -> (String, u16) {
    let trimmed = full_address.trim();
    if let Some(rest) = trimmed.strip_prefix('[')
        && let Some((ipv6_host, after_bracket)) = rest.split_once(']')
    {
        if let Some(port_str) = after_bracket.strip_prefix(':')
            && let Ok(p) = port_str.parse::<u16>()
        {
            return (ipv6_host.to_owned(), p);
        }
        return (ipv6_host.to_owned(), default_port);
    }

    // Bare IPv6 address has 2 or more colons; do not split the final hextet as a port.
    let colon_count = trimmed.bytes().filter(|&b| b == b':').count();
    if colon_count >= 2 {
        return (trimmed.to_owned(), default_port);
    }

    if let Some((host, port_str)) = trimmed.rsplit_once(':')
        && let Ok(p) = port_str.parse::<u16>()
    {
        return (host.to_owned(), p);
    }

    (trimmed.to_owned(), default_port)
}

/// Imports a Microsoft Remote Desktop Connection Manager (`.rdg`) XML document
/// into a [`ConnectionTree`], ported from mRemoteNG's
/// `RemoteDesktopConnectionManagerDeserializer.cs`.
///
/// # Errors
///
/// Returns [`ImportError::InvalidXml`] if `<RDCMan>` root is missing.
pub fn import_rdcman_rdg(xml: &str) -> Result<ConnectionTree, ImportError> {
    if !xml.contains("<RDCMan") {
        return Err(ImportError::InvalidXml(
            "missing <RDCMan> root element".to_owned(),
        ));
    }

    let mut tree = ConnectionTree::new();
    let mut group_counter = 0usize;
    let mut server_counter = 0usize;

    // Extract top-level or nested <group> blocks and <server> blocks.
    let mut current_folder_id: Option<String> = None;
    let mut cursor = xml;

    while let Some(tag_start) = cursor.find('<') {
        cursor = &cursor[tag_start..];
        if cursor.starts_with("<group>") || cursor.starts_with("<group ") {
            group_counter += 1;
            let folder_id = format!("rdg-group-{group_counter}");
            let group_header = cursor.find("<server").map_or(cursor, |idx| &cursor[..idx]);
            let folder_name = extract_xml_tag(group_header, "name")
                .unwrap_or_else(|| format!("Group {group_counter}"));
            let username = extract_xml_tag(group_header, "userName").unwrap_or_default();
            let domain = extract_xml_tag(group_header, "domain").unwrap_or_default();
            let port = extract_xml_tag(group_header, "port")
                .and_then(|p| p.parse::<u16>().ok())
                .unwrap_or(ConnectionProtocol::Rdp.default_port());

            tree.upsert_folder(ConnectionFolder {
                id: folder_id.clone(),
                name: folder_name,
                parent_id: None,
                properties: ConnectionProperties {
                    username,
                    domain,
                    protocol: ConnectionProtocol::Rdp,
                    port,
                    ..ConnectionProperties::default()
                },
                inheritance: InheritanceFlags::none(),
            });
            current_folder_id = Some(folder_id);
            cursor = &cursor[6..];
        } else if cursor.starts_with("</group>") {
            current_folder_id = None;
            cursor = &cursor[8..];
        } else if cursor.starts_with("<server>") || cursor.starts_with("<server ") {
            let end_idx = cursor
                .find("</server>")
                .ok_or_else(|| ImportError::InvalidXml("unclosed <server> element".to_owned()))?;
            let server_block = &cursor[..end_idx];
            server_counter += 1;

            let hostname = extract_xml_tag(server_block, "name")
                .ok_or(ImportError::MissingField("server/name"))?;
            let display_name =
                extract_xml_tag(server_block, "displayName").unwrap_or_else(|| hostname.clone());
            let username = extract_xml_tag(server_block, "userName");
            let domain = extract_xml_tag(server_block, "domain");
            let port = extract_xml_tag(server_block, "port").and_then(|p| p.parse::<u16>().ok());
            let use_console = extract_xml_tag(server_block, "connectToConsole")
                .is_some_and(|v| v.eq_ignore_ascii_case("true"));

            let mut inheritance = InheritanceFlags::all();
            inheritance.use_console_session = false;
            if username.is_some() {
                inheritance.username = false;
            }
            if domain.is_some() {
                inheritance.domain = false;
            }
            if port.is_some() {
                inheritance.port = false;
            }

            tree.add_entry(ConnectionEntry {
                id: format!("rdg-srv-{server_counter}"),
                display_name,
                hostname,
                parent_folder_id: current_folder_id.clone(),
                tags: vec!["rdg".to_owned(), "rdp".to_owned()],
                properties: ConnectionProperties {
                    username: username.unwrap_or_default(),
                    domain: domain.unwrap_or_default(),
                    protocol: ConnectionProtocol::Rdp,
                    port: port.unwrap_or(ConnectionProtocol::Rdp.default_port()),
                    use_console_session: use_console,
                    ..ConnectionProperties::default()
                },
                inheritance,
            });
            cursor = &cursor[end_idx + 9..];
        } else {
            cursor = &cursor[1..];
        }
    }

    Ok(tree)
}

/// Imports a `PuTTY` Connection Manager XML configuration into a [`ConnectionTree`],
/// ported from mRemoteNG's `PuttyConnectionManagerDeserializer.cs`.
///
/// # Errors
///
/// Returns [`ImportError::InvalidXml`] if `<configuration` root is missing.
pub fn import_putty_xml(xml: &str) -> Result<ConnectionTree, ImportError> {
    if !xml.contains("<configuration") {
        return Err(ImportError::InvalidXml(
            "missing <configuration> root element".to_owned(),
        ));
    }

    let mut tree = ConnectionTree::new();
    let mut conn_counter = 0usize;
    let mut cursor = xml;

    while let Some(idx) = cursor.find("<connection") {
        cursor = &cursor[idx..];
        let end_idx = cursor
            .find("</connection>")
            .ok_or_else(|| ImportError::InvalidXml("unclosed <connection> element".to_owned()))?;
        let block = &cursor[..end_idx];
        conn_counter += 1;

        let display_name =
            extract_xml_tag(block, "name").unwrap_or_else(|| format!("PuTTY {conn_counter}"));
        let hostname =
            extract_xml_tag(block, "host").ok_or(ImportError::MissingField("connection/host"))?;
        let proto_str = extract_xml_tag(block, "protocol").unwrap_or_else(|| "SSH".to_owned());
        let protocol = if proto_str.eq_ignore_ascii_case("telnet") {
            ConnectionProtocol::Telnet
        } else {
            ConnectionProtocol::Ssh
        };
        let port = extract_xml_tag(block, "port")
            .and_then(|p| p.parse::<u16>().ok())
            .unwrap_or_else(|| protocol.default_port());
        let username = extract_xml_tag(block, "login").unwrap_or_default();

        tree.add_entry(ConnectionEntry {
            id: format!("putty-{conn_counter}"),
            display_name,
            hostname,
            parent_folder_id: None,
            tags: vec!["putty".to_owned(), proto_str.to_ascii_lowercase()],
            properties: ConnectionProperties {
                username,
                protocol,
                port,
                ..ConnectionProperties::default()
            },
            inheritance: InheritanceFlags::none(),
        });

        cursor = &cursor[end_idx + 13..];
    }

    Ok(tree)
}

fn extract_xml_tag(block: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let close_idx = block.find(&close)?;
    let start = block[..close_idx].rfind(&open)? + open.len();
    Some(block[start..close_idx].trim().to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tag_and_keyword_launcher_matches_direct_initials_discrete_and_excluded_tags() {
        let mut tree = ConnectionTree::new();
        tree.add_entry(ConnectionEntry {
            id: "1".to_owned(),
            display_name: "Prod Web Server".to_owned(),
            hostname: "10.0.1.10".to_owned(),
            parent_folder_id: None,
            tags: vec!["#Prod".to_owned(), "linux web".to_owned()],
            properties: ConnectionProperties::default(),
            inheritance: InheritanceFlags::none(),
        });
        tree.add_entry(ConnectionEntry {
            id: "2".to_owned(),
            display_name: "Staging Database".to_owned(),
            hostname: "10.0.2.20".to_owned(),
            parent_folder_id: None,
            tags: vec!["staging".to_owned(), "postgres".to_owned()],
            properties: ConnectionProperties::default(),
            inheritance: InheritanceFlags::none(),
        });

        // 1. Tag rectification ("linux web" -> "linux-web", "#Prod" -> "prod")
        assert_eq!(tree.entries()[0].tags, vec!["prod", "linux-web"]);

        // 2. Initials match: "pws" matches "Prod Web Server"
        let res = tree.search("pws");
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].id, "1");

        // 3. Discrete subsequence match: "stgdb" matches "Staging Database"
        let res_discrete = tree.search("stgdb");
        assert_eq!(res_discrete.len(), 1);
        assert_eq!(res_discrete[0].id, "2");

        // 4. Tag inclusion & exclusion: "#prod " includes 1, "-#prod" excludes 1
        assert_eq!(tree.search("#prod ").len(), 1);
        let res_excl = tree.search("-#prod");
        assert_eq!(res_excl.len(), 1);
        assert_eq!(res_excl[0].id, "2");

        // 5. Partial prefix tag match (no trailing space): "#lin" matches "linux-web"
        assert_eq!(tree.search("#lin").len(), 1);
    }

    #[test]
    fn folder_property_inheritance_propagates_and_respects_overrides() {
        let mut tree = ConnectionTree::new();
        tree.upsert_folder(ConnectionFolder {
            id: "root".to_owned(),
            name: "Datacenter".to_owned(),
            parent_id: None,
            properties: ConnectionProperties {
                username: "corp_admin".to_owned(),
                domain: "CORP".to_owned(),
                protocol: ConnectionProtocol::Rdp,
                port: 3389,
                gateway_hostname: Some("rdgw.corp.example".to_owned()),
                use_console_session: true,
                redirect_clipboard: true,
                redirect_audio: false,
            },
            inheritance: InheritanceFlags::none(),
        });

        let mut subfolder_inheritance = InheritanceFlags::all();
        subfolder_inheritance.username = false; // Subfolder overrides username
        tree.upsert_folder(ConnectionFolder {
            id: "eu-west".to_owned(),
            name: "EU West".to_owned(),
            parent_id: Some("root".to_owned()),
            properties: ConnectionProperties {
                username: "eu_operator".to_owned(),
                ..ConnectionProperties::default()
            },
            inheritance: subfolder_inheritance,
        });

        let mut entry_inheritance = InheritanceFlags::all();
        entry_inheritance.port = false; // Entry overrides port
        let entry = ConnectionEntry {
            id: "srv-1".to_owned(),
            display_name: "EU App 01".to_owned(),
            hostname: "10.20.0.15".to_owned(),
            parent_folder_id: Some("eu-west".to_owned()),
            tags: vec![],
            properties: ConnectionProperties {
                port: 13389,
                ..ConnectionProperties::default()
            },
            inheritance: entry_inheritance,
        };

        let effective = tree.effective_entry_properties(&entry);
        assert_eq!(effective.username, "eu_operator");
        assert_eq!(effective.domain, "CORP");
        assert_eq!(effective.protocol, ConnectionProtocol::Rdp);
        assert_eq!(effective.port, 13389);
        assert_eq!(
            effective.gateway_hostname.as_deref(),
            Some("rdgw.corp.example")
        );
        assert!(effective.use_console_session);
        assert!(!effective.redirect_audio);
    }

    #[test]
    fn importers_parse_rdp_ipv6_rdcman_rdg_and_putty_xml() {
        // 1. .rdp file with bare IPv6 address + console session + RD Gateway
        let rdp_content = "\
full address:s:2001:db8:85a3::8a2e:370:7334
server port:i:3390
username:s:alice
domain:s:OMEGA
administrative session:i:1
gatewayusagemethod:i:1
gatewayhostname:s:gw.omega.example
redirectclipboard:i:0
audiomode:i:2
";
        let rdp_entry = import_rdp_file("rdp-1", "IPv6 Host", rdp_content).unwrap();
        assert_eq!(rdp_entry.hostname, "2001:db8:85a3::8a2e:370:7334");
        assert_eq!(rdp_entry.properties.port, 3390);
        assert_eq!(rdp_entry.properties.username, "alice");
        assert_eq!(rdp_entry.properties.domain, "OMEGA");
        assert!(rdp_entry.properties.use_console_session);
        assert!(!rdp_entry.properties.redirect_clipboard);
        assert!(!rdp_entry.properties.redirect_audio);
        assert_eq!(
            rdp_entry.properties.gateway_hostname.as_deref(),
            Some("gw.omega.example")
        );

        // 2. RDCMan .rdg XML with group inheritance
        let rdg_xml = r#"
<RDCMan schemaVersion="3">
  <file>
    <group>
      <properties>
        <name>Core Infra</name>
      </properties>
      <logonCredentials inherit="FromParent">
        <userName>infra_admin</userName>
        <domain>INFRA</domain>
      </logonCredentials>
      <server>
        <properties>
          <name>dc01.infra.omega</name>
          <displayName>Domain Controller 01</displayName>
        </properties>
        <connectionSettings inherit="FromParent">
          <connectToConsole>True</connectToConsole>
        </connectionSettings>
      </server>
    </group>
  </file>
</RDCMan>
"#;
        let rdg_tree = import_rdcman_rdg(rdg_xml).unwrap();
        assert_eq!(rdg_tree.entries().len(), 1);
        let srv = &rdg_tree.entries()[0];
        let eff = rdg_tree.effective_entry_properties(srv);
        assert_eq!(srv.hostname, "dc01.infra.omega");
        assert_eq!(srv.display_name, "Domain Controller 01");
        assert_eq!(eff.username, "infra_admin");
        assert_eq!(eff.domain, "INFRA");
        assert!(eff.use_console_session);

        // 3. PuTTY Connection Manager XML
        let putty_xml = r#"
<configuration version="0.7" save="True">
  <root type="database" name="ProdSSH">
    <container type="folder" name="Routers">
      <connection type="PuTTY" name="Core-Edge-01">
        <connection_info>
          <name>Core-Edge-01</name>
          <protocol>SSH</protocol>
          <host>192.0.2.1</host>
          <port>2222</port>
        </connection_info>
        <login>
          <login>netops</login>
        </login>
      </connection>
    </container>
  </root>
</configuration>
"#;
        let putty_tree = import_putty_xml(putty_xml).unwrap();
        assert_eq!(putty_tree.entries().len(), 1);
        let ssh_entry = &putty_tree.entries()[0];
        assert_eq!(ssh_entry.display_name, "Core-Edge-01");
        assert_eq!(ssh_entry.hostname, "192.0.2.1");
        assert_eq!(ssh_entry.properties.protocol, ConnectionProtocol::Ssh);
        assert_eq!(ssh_entry.properties.port, 2222);
        assert_eq!(ssh_entry.properties.username, "netops");
    }
}
