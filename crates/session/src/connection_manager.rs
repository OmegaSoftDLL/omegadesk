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

/// Minimal XML element tree used by the `.rdg` and `PuTTY` importers.
///
/// mRemoteNG walks both formats with `XmlDocument.SelectNodes("./group|./server")`
/// (`RemoteDesktopConnectionManagerDeserializer.cs`) and `SelectNodes("./*")`
/// (`PuttyConnectionManagerDeserializer.cs`), i.e. strictly over *direct children*,
/// and reads `InnerText` with entity references already decoded. This tree gives the
/// importers the same two guarantees without an XML dependency.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct XmlElement {
    name: String,
    attributes: Vec<(String, String)>,
    children: Vec<XmlElement>,
    text: String,
}

impl XmlElement {
    fn attr(&self, name: &str) -> Option<&str> {
        self.attributes
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }

    /// First direct child named `name` (`SelectSingleNode("./name")`).
    fn child(&self, name: &str) -> Option<&Self> {
        self.children.iter().find(|child| child.name == name)
    }

    /// Direct children named `name` (`SelectNodes("./name")`).
    fn children_named<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Self> + 'a {
        self.children.iter().filter(move |child| child.name == name)
    }

    /// Decoded, trimmed `InnerText` of the first direct child named `name`.
    fn child_text(&self, name: &str) -> Option<String> {
        self.child(name).map(|child| child.text.trim().to_owned())
    }

    fn child_bool(&self, name: &str) -> Option<bool> {
        let value = self.child_text(name)?;
        if value.eq_ignore_ascii_case("true") {
            Some(true)
        } else if value.eq_ignore_ascii_case("false") {
            Some(false)
        } else {
            None
        }
    }
}

/// Decodes the five predefined XML entities plus decimal (`&#NN;`) and hexadecimal
/// (`&#xHH;`) character references; unknown or malformed references are kept literally.
fn decode_xml_entities(raw: &str) -> String {
    if !raw.contains('&') {
        return raw.to_owned();
    }
    let mut out = String::with_capacity(raw.len());
    let mut rest = raw;
    while let Some(amp) = rest.find('&') {
        out.push_str(&rest[..amp]);
        let after_amp = &rest[amp + 1..];
        let Some(semi) = after_amp.find(';').filter(|&idx| idx > 0 && idx <= 10) else {
            out.push('&');
            rest = after_amp;
            continue;
        };
        let entity = &after_amp[..semi];
        let decoded = match entity {
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            _ => entity
                .strip_prefix('#')
                .and_then(|number| {
                    number.strip_prefix(['x', 'X']).map_or_else(
                        || number.parse::<u32>().ok(),
                        |hex| u32::from_str_radix(hex, 16).ok(),
                    )
                })
                .and_then(char::from_u32),
        };
        if let Some(ch) = decoded {
            out.push(ch);
            rest = &after_amp[semi + 1..];
        } else {
            out.push('&');
            rest = after_amp;
        }
    }
    out.push_str(rest);
    out
}

/// Parses an XML document into its root [`XmlElement`]. Processing instructions,
/// comments, and `DOCTYPE` declarations are skipped; `CDATA` sections are kept verbatim.
fn parse_xml_document(xml: &str) -> Result<XmlElement, ImportError> {
    let mut stack: Vec<XmlElement> = Vec::new();
    let mut root: Option<XmlElement> = None;
    let mut rest = xml.trim_start_matches('\u{feff}');

    while let Some(lt) = rest.find('<') {
        if let Some(current) = stack.last_mut() {
            current.text.push_str(&decode_xml_entities(&rest[..lt]));
        }
        rest = &rest[lt..];

        if let Some(after) = rest.strip_prefix("<![CDATA[") {
            let end = after
                .find("]]>")
                .ok_or_else(|| ImportError::InvalidXml("unterminated CDATA section".to_owned()))?;
            if let Some(current) = stack.last_mut() {
                current.text.push_str(&after[..end]);
            }
            rest = &after[end + 3..];
            continue;
        }
        if let Some(after) = rest.strip_prefix("<!--") {
            let end = after
                .find("-->")
                .ok_or_else(|| ImportError::InvalidXml("unterminated comment".to_owned()))?;
            rest = &after[end + 3..];
            continue;
        }
        if rest.starts_with("<?") || rest.starts_with("<!") {
            let end = rest
                .find('>')
                .ok_or_else(|| ImportError::InvalidXml("unterminated declaration".to_owned()))?;
            rest = &rest[end + 1..];
            continue;
        }

        let end = find_tag_end(rest)
            .ok_or_else(|| ImportError::InvalidXml("unterminated tag".to_owned()))?;
        let tag = &rest[1..end];
        rest = &rest[end + 1..];

        if let Some(closing) = tag.strip_prefix('/') {
            let closing = closing.trim();
            let Some(element) = stack.pop() else {
                return Err(ImportError::InvalidXml(format!(
                    "closing tag </{closing}> without an open element"
                )));
            };
            if element.name != closing {
                return Err(ImportError::InvalidXml(format!(
                    "expected </{}> but found </{closing}>",
                    element.name
                )));
            }
            attach_element(&mut stack, &mut root, element)?;
            continue;
        }

        let (self_closing, tag_body) = tag
            .strip_suffix('/')
            .map_or((false, tag), |body| (true, body));
        let element = parse_start_tag(tag_body)?;
        if self_closing {
            attach_element(&mut stack, &mut root, element)?;
        } else {
            stack.push(element);
        }
    }

    if let Some(open) = stack.last() {
        return Err(ImportError::InvalidXml(format!(
            "unclosed <{}> element",
            open.name
        )));
    }
    root.ok_or_else(|| ImportError::InvalidXml("document has no root element".to_owned()))
}

/// Byte index of the `>` that closes the tag starting at `tag[0] == '<'`, skipping any
/// `>` inside single- or double-quoted attribute values (`name="Ops > Lab"`).
fn find_tag_end(tag: &str) -> Option<usize> {
    let mut quote: Option<char> = None;
    for (idx, ch) in tag.char_indices().skip(1) {
        match (quote, ch) {
            (Some(open), c) if c == open => quote = None,
            (None, '"' | '\'') => quote = Some(ch),
            (None, '>') => return Some(idx),
            _ => {}
        }
    }
    None
}

fn attach_element(
    stack: &mut [XmlElement],
    root: &mut Option<XmlElement>,
    element: XmlElement,
) -> Result<(), ImportError> {
    if let Some(parent) = stack.last_mut() {
        parent.children.push(element);
        return Ok(());
    }
    if root.is_some() {
        return Err(ImportError::InvalidXml("multiple root elements".to_owned()));
    }
    *root = Some(element);
    Ok(())
}

/// Parses `name attr="value" attr2='value'` (the inside of a start tag).
fn parse_start_tag(tag_body: &str) -> Result<XmlElement, ImportError> {
    let body = tag_body.trim();
    let name_end = body
        .find(|c: char| c.is_whitespace() || c == '/')
        .unwrap_or(body.len());
    let name = &body[..name_end];
    if name.is_empty() {
        return Err(ImportError::InvalidXml("empty element name".to_owned()));
    }
    let mut element = XmlElement {
        name: name.to_owned(),
        ..XmlElement::default()
    };

    let mut attrs = body[name_end..].trim_start();
    while !attrs.is_empty() {
        let eq = attrs
            .find('=')
            .ok_or_else(|| ImportError::InvalidXml(format!("malformed attribute in <{name}>")))?;
        let key = attrs[..eq].trim();
        let value_part = attrs[eq + 1..].trim_start();
        let quote = value_part
            .chars()
            .next()
            .filter(|c| matches!(c, '"' | '\''));
        let Some(quote) = quote else {
            return Err(ImportError::InvalidXml(format!(
                "unquoted attribute value in <{name}>"
            )));
        };
        let value_body = &value_part[quote.len_utf8()..];
        let close = value_body.find(quote).ok_or_else(|| {
            ImportError::InvalidXml(format!("unterminated attribute value in <{name}>"))
        })?;
        element
            .attributes
            .push((key.to_owned(), decode_xml_entities(&value_body[..close])));
        attrs = value_body[close + quote.len_utf8()..].trim_start();
    }
    Ok(element)
}

/// `RDCMan` `inherit="None"` marks a settings section as explicit; `FromParent` (or a
/// missing attribute / missing section) means the section is resolved from the parent
/// and any saved local values inside it are ignored
/// (`RemoteDesktopConnectionManagerDeserializer.ConnectionInfoFromXml`).
fn rdg_section_is_explicit(section: Option<&XmlElement>) -> bool {
    section.is_some_and(|node| node.attr("inherit").is_some_and(|v| v == "None"))
}

/// Connection properties, inheritance flags, hostname, and display name read from an
/// `RDCMan` `<group>`, `<file>`, or `<server>` element, mirroring
/// `ConnectionInfoFromXml` in mRemoteNG's `RemoteDesktopConnectionManagerDeserializer.cs`.
struct RdgConnectionInfo {
    properties: ConnectionProperties,
    inheritance: InheritanceFlags,
    hostname: Option<String>,
    display_name: Option<String>,
}

/// `is_container` is true for `<file>` / `<group>` elements. In schema 1 (`RDCMan` 2.2) a
/// container wraps *all* of its settings (name, `logonCredentials`, ...) in `<properties>`
/// (`ImportContainer`: `containerPropertiesNode = node.SelectSingleNode("./properties")`),
/// while a schema-1 server keeps them at its own root; in schema 3 (`RDCMan` 2.7) only
/// `name` / `displayName` live in `<properties>` and the settings sections are direct children.
fn rdg_connection_info(
    node: &XmlElement,
    schema_v1: bool,
    is_container: bool,
) -> RdgConnectionInfo {
    let settings_node = if schema_v1 && is_container {
        node.child("properties").unwrap_or(node)
    } else {
        node
    };
    let props_node = if schema_v1 {
        settings_node
    } else {
        node.child("properties").unwrap_or(node)
    };
    let node = settings_node;
    let hostname = props_node.child_text("name");
    let display_name = props_node
        .child_text("displayName")
        .filter(|name| !name.trim().is_empty());

    let mut properties = ConnectionProperties {
        protocol: ConnectionProtocol::Rdp,
        port: ConnectionProtocol::Rdp.default_port(),
        ..ConnectionProperties::default()
    };
    let mut inheritance = InheritanceFlags::none();

    let logon = node.child("logonCredentials");
    if rdg_section_is_explicit(logon) {
        if let Some(section) = logon {
            properties.username = section.child_text("userName").unwrap_or_default();
            properties.domain = section.child_text("domain").unwrap_or_default();
        }
    } else {
        inheritance.username = true;
        inheritance.domain = true;
    }

    let connection = node.child("connectionSettings");
    if rdg_section_is_explicit(connection) {
        if let Some(section) = connection {
            if let Some(console) = section.child_bool("connectToConsole") {
                properties.use_console_session = console;
            }
            if let Some(port) = section
                .child_text("port")
                .and_then(|p| p.parse::<u16>().ok())
            {
                properties.port = port;
            }
        }
    } else {
        inheritance.use_console_session = true;
        inheritance.port = true;
    }

    let gateway = node.child("gatewaySettings");
    if rdg_section_is_explicit(gateway) {
        if let Some(section) = gateway {
            let enabled = section.child_bool("enabled").unwrap_or(false);
            properties.gateway_hostname = if enabled {
                section.child_text("hostName").filter(|h| !h.is_empty())
            } else {
                None
            };
        }
    } else {
        inheritance.gateway_hostname = true;
    }

    let local = node.child("localResources");
    if rdg_section_is_explicit(local) {
        if let Some(section) = local {
            if let Some(clipboard) = section.child_bool("redirectClipboard") {
                properties.redirect_clipboard = clipboard;
            }
            if let Some(audio) = section.child_text("audioRedirection") {
                // 0 / Client = bring to this computer; 1 / Remote and 2 / NoSound do not play locally.
                properties.redirect_audio = audio == "0" || audio.eq_ignore_ascii_case("Client");
            }
        }
    } else {
        inheritance.redirect_clipboard = true;
        inheritance.redirect_audio = true;
    }

    RdgConnectionInfo {
        properties,
        inheritance,
        hostname,
        display_name,
    }
}

struct RdgImporter {
    tree: ConnectionTree,
    schema_v1: bool,
    group_counter: usize,
    server_counter: usize,
}

impl RdgImporter {
    /// `ImportFileOrGroup`: creates the folder for `node`, then recurses into its
    /// *direct* `<group>` and `<server>` children with this folder as their parent.
    fn import_group(
        &mut self,
        node: &XmlElement,
        parent_id: Option<&str>,
    ) -> Result<(), ImportError> {
        self.group_counter += 1;
        let folder_id = format!("rdg-group-{}", self.group_counter);
        let info = rdg_connection_info(node, self.schema_v1, true);
        let name = info
            .display_name
            .or(info.hostname)
            .filter(|n| !n.is_empty())
            .unwrap_or_else(|| format!("Group {}", self.group_counter));
        self.tree.upsert_folder(ConnectionFolder {
            id: folder_id.clone(),
            name,
            parent_id: parent_id.map(str::to_owned),
            properties: info.properties,
            inheritance: info.inheritance,
        });

        for child in &node.children {
            match child.name.as_str() {
                "group" => self.import_group(child, Some(&folder_id))?,
                "server" => self.import_server(child, Some(&folder_id))?,
                _ => {}
            }
        }
        Ok(())
    }

    fn import_server(
        &mut self,
        node: &XmlElement,
        parent_id: Option<&str>,
    ) -> Result<(), ImportError> {
        self.server_counter += 1;
        let info = rdg_connection_info(node, self.schema_v1, false);
        let hostname = info
            .hostname
            .filter(|h| !h.is_empty())
            .ok_or(ImportError::MissingField("server/name"))?;
        let display_name = info.display_name.unwrap_or_else(|| hostname.clone());
        self.tree.add_entry(ConnectionEntry {
            id: format!("rdg-srv-{}", self.server_counter),
            display_name,
            hostname,
            parent_folder_id: parent_id.map(str::to_owned),
            tags: vec!["rdg".to_owned(), "rdp".to_owned()],
            properties: info.properties,
            inheritance: info.inheritance,
        });
        Ok(())
    }
}

/// Imports a Microsoft Remote Desktop Connection Manager (`.rdg`) XML document
/// into a [`ConnectionTree`], ported from mRemoteNG's
/// `RemoteDesktopConnectionManagerDeserializer.cs`:
///
/// - `<file>` and every nested `<group>` become folders whose `parent_id` is the
///   enclosing group (a stack of open groups, like the recursive `ImportFileOrGroup`),
///   and servers following a closed inner group return to the outer group.
/// - Properties are read only from the element's **direct** children, so an inner
///   group's credentials never leak into the outer folder.
/// - Each settings section's `inherit` attribute drives [`InheritanceFlags`]:
///   `None` means explicit values, anything else resolves from the parent and ignores
///   saved local values (including `connectToConsole`).
/// - Entity references (`&amp;`, `&#NN;`, `&#xHH;`, ...) are decoded.
///
/// # Errors
///
/// Returns [`ImportError::InvalidXml`] if the document is malformed or `<RDCMan>` is not
/// the root, and [`ImportError::MissingField`] for a `<server>` without a name.
pub fn import_rdcman_rdg(xml: &str) -> Result<ConnectionTree, ImportError> {
    let doc = parse_xml_document(xml)?;
    if doc.name != "RDCMan" {
        return Err(ImportError::InvalidXml(
            "missing <RDCMan> root element".to_owned(),
        ));
    }
    let schema_v1 = doc
        .attr("schemaVersion")
        .and_then(|v| v.trim().parse::<u32>().ok())
        == Some(1);

    let mut importer = RdgImporter {
        tree: ConnectionTree::new(),
        schema_v1,
        group_counter: 0,
        server_counter: 0,
    };
    for child in &doc.children {
        match child.name.as_str() {
            // mRemoteNG treats <file> itself as the top container (`ImportFileOrGroup(fileNode, root)`).
            "file" | "group" => importer.import_group(child, None)?,
            "server" => importer.import_server(child, None)?,
            _ => {}
        }
    }
    Ok(importer.tree)
}

struct PuttyImporter {
    tree: ConnectionTree,
    folder_counter: usize,
    conn_counter: usize,
}

impl PuttyImporter {
    /// `ImportRootOrContainer`: a `<root type="database">` or `<container type="folder">`
    /// becomes a folder, and its direct `<container>` / `<connection>` children are
    /// imported with that folder as their parent.
    fn import_container(
        &mut self,
        node: &XmlElement,
        parent_id: Option<&str>,
    ) -> Result<(), ImportError> {
        let node_type = node.attr("type").unwrap_or_default();
        let expected = if node.name == "root" {
            "database"
        } else {
            "folder"
        };
        if !node_type.eq_ignore_ascii_case(expected) {
            return Err(ImportError::InvalidXml(format!(
                "unrecognized <{}> node type ({node_type})",
                node.name
            )));
        }

        self.folder_counter += 1;
        let folder_id = format!("putty-folder-{}", self.folder_counter);
        let name = node
            .attr("name")
            .filter(|n| !n.trim().is_empty())
            .map_or_else(|| format!("Folder {}", self.folder_counter), str::to_owned);
        self.tree.upsert_folder(ConnectionFolder {
            id: folder_id.clone(),
            name,
            parent_id: parent_id.map(str::to_owned),
            properties: ConnectionProperties {
                protocol: ConnectionProtocol::Ssh,
                port: ConnectionProtocol::Ssh.default_port(),
                ..ConnectionProperties::default()
            },
            inheritance: InheritanceFlags::none(),
        });

        for child in &node.children {
            match child.name.as_str() {
                "container" => self.import_container(child, Some(&folder_id))?,
                "connection" => self.import_connection(child, Some(&folder_id))?,
                _ => {}
            }
        }
        Ok(())
    }

    fn import_connection(
        &mut self,
        node: &XmlElement,
        parent_id: Option<&str>,
    ) -> Result<(), ImportError> {
        self.conn_counter += 1;
        let info = node.child("connection_info").unwrap_or(node);
        let display_name = info
            .child_text("name")
            .filter(|n| !n.is_empty())
            .unwrap_or_else(|| format!("PuTTY {}", self.conn_counter));
        let hostname = info
            .child_text("host")
            .filter(|h| !h.is_empty())
            .ok_or(ImportError::MissingField("connection/host"))?;
        let proto_str = info
            .child_text("protocol")
            .filter(|p| !p.is_empty())
            .unwrap_or_else(|| "SSH".to_owned());
        let protocol = if proto_str.eq_ignore_ascii_case("telnet") {
            ConnectionProtocol::Telnet
        } else {
            ConnectionProtocol::Ssh
        };
        let port = info
            .child_text("port")
            .and_then(|p| p.parse::<u16>().ok())
            .unwrap_or_else(|| protocol.default_port());
        let username = node
            .child("login")
            .and_then(|login| login.child_text("login"))
            .unwrap_or_default();

        self.tree.add_entry(ConnectionEntry {
            id: format!("putty-{}", self.conn_counter),
            display_name,
            hostname,
            parent_folder_id: parent_id.map(str::to_owned),
            tags: vec!["putty".to_owned(), proto_str.to_ascii_lowercase()],
            properties: ConnectionProperties {
                username,
                protocol,
                port,
                ..ConnectionProperties::default()
            },
            inheritance: InheritanceFlags::none(),
        });
        Ok(())
    }
}

/// Imports a `PuTTY` Connection Manager XML configuration into a [`ConnectionTree`],
/// ported from mRemoteNG's `PuttyConnectionManagerDeserializer.cs`: every
/// `<root type="database">` and nested `<container type="folder">` becomes a folder,
/// and each `<connection>` is attached to its enclosing folder. Entity references in
/// names, hosts, and logins are decoded.
///
/// # Errors
///
/// Returns [`ImportError::InvalidXml`] if the document is malformed, `<configuration>`
/// is not the root, or a `root`/`container` has an unexpected `type`, and
/// [`ImportError::MissingField`] for a connection without a host.
pub fn import_putty_xml(xml: &str) -> Result<ConnectionTree, ImportError> {
    let doc = parse_xml_document(xml)?;
    if doc.name != "configuration" {
        return Err(ImportError::InvalidXml(
            "missing <configuration> root element".to_owned(),
        ));
    }
    let mut importer = PuttyImporter {
        tree: ConnectionTree::new(),
        folder_counter: 0,
        conn_counter: 0,
    };
    for root in doc.children_named("root") {
        importer.import_container(root, None)?;
    }
    Ok(importer.tree)
}

/// Imports Active Directory computer and organizational-unit (`OU=`) entries from an
/// LDIF export into a [`ConnectionTree`], ported from mRemoteNG's
/// `ActiveDirectoryDeserializer.cs` (`mRemoteNG/Config/Serializers/MiscSerializers/ActiveDirectoryDeserializer.cs`
/// lines 19–140, `docs/plan.md` §2.11 line 159).
///
/// Computer records receive `ConnectionProtocol::Rdp` and `InheritanceFlags::all()`
/// (`newConnectionInfo.Inheritance.TurnOnInheritanceCompletely()` in
/// `ActiveDirectoryDeserializer.cs` line 136).
///
/// # Errors
///
/// Returns [`ImportError::MissingField`] if the LDIF input contains no valid `dn:` records.
pub fn import_active_directory_ldif(
    ldif: &str,
    import_sub_ou: bool,
) -> Result<ConnectionTree, ImportError> {
    let mut tree = ConnectionTree::new();
    let mut any_dn = false;
    let mut computer_counter = 0usize;

    for stanza in ldif.split("\n\n") {
        let mut dn: Option<String> = None;
        let mut cn: Option<String> = None;
        let mut dns_host_name: Option<String> = None;
        let mut object_classes: Vec<String> = Vec::new();

        for raw_line in stanza.lines() {
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((attr, val)) = line.split_once(':') {
                let attr_lower = attr.trim().to_ascii_lowercase();
                let val_trimmed = val.trim().to_owned();
                match attr_lower.as_str() {
                    "dn" => dn = Some(val_trimmed),
                    "cn" | "ou" => cn = Some(val_trimmed),
                    "dnshostname" => dns_host_name = Some(val_trimmed),
                    "objectclass" => object_classes.push(val_trimmed.to_ascii_lowercase()),
                    _ => {}
                }
            }
        }

        let Some(dn_str) = dn else {
            continue;
        };
        any_dn = true;

        let ous: Vec<String> = dn_str
            .split(',')
            .filter_map(|rdn| {
                let (k, v) = rdn.trim().split_once('=')?;
                if k.trim().eq_ignore_ascii_case("ou") {
                    Some(v.trim().to_owned())
                } else {
                    None
                }
            })
            .collect();

        if !import_sub_ou && ous.len() > 1 {
            continue;
        }

        if object_classes.iter().any(|c| c == "organizationalunit") {
            if let Some(ou_name) = ous.first().or(cn.as_ref()) {
                let folder_id = format!("ad-ou-{}", ou_name.to_ascii_lowercase());
                let parent_id = ous
                    .get(1)
                    .map(|p| format!("ad-ou-{}", p.to_ascii_lowercase()));
                tree.upsert_folder(ConnectionFolder {
                    id: folder_id,
                    name: ou_name.clone(),
                    parent_id,
                    properties: ConnectionProperties {
                        protocol: ConnectionProtocol::Rdp,
                        port: ConnectionProtocol::Rdp.default_port(),
                        ..ConnectionProperties::default()
                    },
                    inheritance: if ous.len() > 1 {
                        InheritanceFlags::all()
                    } else {
                        InheritanceFlags::none()
                    },
                });
            }
        } else if object_classes.iter().any(|c| c == "computer") {
            computer_counter += 1;
            let display_name = cn.unwrap_or_else(|| format!("Computer-{computer_counter}"));
            let hostname = dns_host_name.unwrap_or_else(|| display_name.clone());
            let parent_folder_id = ous
                .first()
                .map(|ou| format!("ad-ou-{}", ou.to_ascii_lowercase()));

            tree.add_entry(ConnectionEntry {
                id: format!("ad-comp-{computer_counter}"),
                display_name,
                hostname,
                parent_folder_id,
                tags: vec!["active-directory".to_owned(), "rdp".to_owned()],
                properties: ConnectionProperties {
                    protocol: ConnectionProtocol::Rdp,
                    port: ConnectionProtocol::Rdp.default_port(),
                    ..ConnectionProperties::default()
                },
                inheritance: InheritanceFlags::all(),
            });
        }
    }

    if !any_dn {
        return Err(ImportError::MissingField("dn"));
    }

    Ok(tree)
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
      <logonCredentials inherit="None">
        <userName>infra_admin</userName>
        <domain>INFRA</domain>
      </logonCredentials>
      <server>
        <properties>
          <name>dc01.infra.omega</name>
          <displayName>Domain Controller 01</displayName>
        </properties>
        <connectionSettings inherit="None">
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
        // The server sits in "Core Infra", which itself sits in the <file> folder.
        let group = rdg_tree
            .folder(srv.parent_folder_id.as_deref().unwrap())
            .unwrap();
        assert_eq!(group.name, "Core Infra");
        assert!(group.parent_id.is_some());

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
        let routers = putty_tree
            .folder(ssh_entry.parent_folder_id.as_deref().unwrap())
            .unwrap();
        assert_eq!(routers.name, "Routers");
        let database = putty_tree
            .folder(routers.parent_id.as_deref().unwrap())
            .unwrap();
        assert_eq!(database.name, "ProdSSH");
        assert!(database.parent_id.is_none());
    }

    #[test]
    fn importer_parses_active_directory_ldif() {
        // Active Directory LDIF import (`ActiveDirectoryDeserializer.cs`)
        let ad_ldif = "\
dn: OU=Servers,DC=omega,DC=local
objectClass: organizationalUnit
ou: Servers

dn: CN=SQL01,OU=Servers,DC=omega,DC=local
objectClass: computer
cn: SQL01
dNSHostName: sql01.omega.local
";
        let ad_tree = import_active_directory_ldif(ad_ldif, true).unwrap();
        assert_eq!(ad_tree.entries().len(), 1);
        assert_eq!(ad_tree.entries()[0].hostname, "sql01.omega.local");
        assert_eq!(
            ad_tree.entries()[0].parent_folder_id.as_deref(),
            Some("ad-ou-servers")
        );
        assert_eq!(ad_tree.entries()[0].inheritance, InheritanceFlags::all());
    }

    /// Regression for #28 `connection_manager.rs:741` and `:749`: nested groups keep
    /// their real parent, a server after a closed inner group returns to the outer
    /// group, and an inner group's credentials never become the outer folder's own.
    #[test]
    fn rdcman_nested_groups_keep_parents_and_do_not_leak_child_credentials() {
        let rdg_xml = r#"<?xml version="1.0" encoding="utf-8"?>
<RDCMan programVersion="2.83" schemaVersion="3">
  <file>
    <properties><name>Lab</name></properties>
    <group>
      <properties><name>Outer</name></properties>
      <logonCredentials inherit="None">
        <userName></userName>
        <domain>OUTER</domain>
      </logonCredentials>
      <group>
        <properties><name>Inner</name></properties>
        <logonCredentials inherit="None">
          <userName>alice</userName>
          <domain>INNER</domain>
        </logonCredentials>
        <server>
          <properties><name>inner-01</name></properties>
        </server>
      </group>
      <server>
        <properties><name>outer-01</name></properties>
      </server>
    </group>
  </file>
</RDCMan>
"#;
        let tree = import_rdcman_rdg(rdg_xml).unwrap();
        assert_eq!(tree.entries().len(), 2);
        let inner_srv = tree
            .entries()
            .iter()
            .find(|e| e.hostname == "inner-01")
            .unwrap();
        let outer_srv = tree
            .entries()
            .iter()
            .find(|e| e.hostname == "outer-01")
            .unwrap();

        let inner = tree
            .folder(inner_srv.parent_folder_id.as_deref().unwrap())
            .unwrap();
        let outer = tree
            .folder(outer_srv.parent_folder_id.as_deref().unwrap())
            .unwrap();
        assert_eq!(inner.name, "Inner");
        assert_eq!(outer.name, "Outer");
        // Inner's parent is Outer, Outer's parent is the <file> folder "Lab".
        assert_eq!(inner.parent_id.as_deref(), Some(outer.id.as_str()));
        let lab = tree.folder(outer.parent_id.as_deref().unwrap()).unwrap();
        assert_eq!(lab.name, "Lab");
        assert!(lab.parent_id.is_none());

        // Outer keeps its own (empty) username: `alice` belongs to Inner only.
        assert_eq!(outer.properties.username, "");
        assert_eq!(outer.properties.domain, "OUTER");
        assert_eq!(inner.properties.username, "alice");

        let outer_eff = tree.effective_entry_properties(outer_srv);
        assert_eq!(outer_eff.username, "");
        assert_eq!(outer_eff.domain, "OUTER");
        let inner_eff = tree.effective_entry_properties(inner_srv);
        assert_eq!(inner_eff.username, "alice");
        assert_eq!(inner_eff.domain, "INNER");
    }

    /// Regression for #28 `connection_manager.rs:785`: `inherit="FromParent"` resolves
    /// the section from the parent even when it carries saved local values, and console
    /// session inheritance follows the same attribute instead of being always disabled.
    #[test]
    fn rdcman_inherit_attribute_controls_section_resolution() {
        let rdg_xml = r#"
<RDCMan schemaVersion="3">
  <file>
    <properties><name>Ops</name></properties>
    <group>
      <properties><name>Consoles</name></properties>
      <logonCredentials inherit="None">
        <userName>group_admin</userName>
        <domain>GROUP</domain>
      </logonCredentials>
      <connectionSettings inherit="None">
        <connectToConsole>True</connectToConsole>
        <port>3390</port>
      </connectionSettings>
      <server>
        <properties><name>inherits</name></properties>
        <logonCredentials inherit="FromParent">
          <userName>stale_local_user</userName>
          <domain>STALE</domain>
        </logonCredentials>
        <connectionSettings inherit="FromParent">
          <connectToConsole>False</connectToConsole>
          <port>13389</port>
        </connectionSettings>
      </server>
      <server>
        <properties><name>explicit</name></properties>
        <logonCredentials inherit="None">
          <userName>own_user</userName>
          <domain>OWN</domain>
        </logonCredentials>
        <connectionSettings inherit="None">
          <connectToConsole>False</connectToConsole>
        </connectionSettings>
      </server>
    </group>
  </file>
</RDCMan>
"#;
        let tree = import_rdcman_rdg(rdg_xml).unwrap();
        let inherits = tree
            .entries()
            .iter()
            .find(|e| e.hostname == "inherits")
            .unwrap();
        assert!(inherits.inheritance.username);
        assert!(inherits.inheritance.domain);
        assert!(inherits.inheritance.use_console_session);
        assert!(inherits.inheritance.port);
        let eff = tree.effective_entry_properties(inherits);
        assert_eq!(eff.username, "group_admin");
        assert_eq!(eff.domain, "GROUP");
        assert!(
            eff.use_console_session,
            "console inheritance must follow the parent"
        );
        assert_eq!(eff.port, 3390);

        let explicit = tree
            .entries()
            .iter()
            .find(|e| e.hostname == "explicit")
            .unwrap();
        assert!(!explicit.inheritance.username);
        assert!(!explicit.inheritance.use_console_session);
        let eff = tree.effective_entry_properties(explicit);
        assert_eq!(eff.username, "own_user");
        assert_eq!(eff.domain, "OWN");
        assert!(!eff.use_console_session);
        // Port section is explicit but has no <port>: RDP default, not the group's 3390.
        assert_eq!(eff.port, 3389);
    }

    /// Regression for #28 `connection_manager.rs:862`: the `PuTTY` importer must recreate
    /// the database/folder hierarchy instead of flattening every connection to the root.
    #[test]
    fn putty_importer_creates_nested_folders_and_assigns_connections_to_them() {
        let putty_xml = r#"
<configuration version="0.7" save="True">
  <root type="database" name="Prod" expanded="True">
    <connection type="PuTTY" name="bastion">
      <connection_info><name>bastion</name><protocol>SSH</protocol><host>bastion.example</host><port>22</port></connection_info>
    </connection>
    <container type="folder" name="Routers">
      <container type="folder" name="Core">
        <connection type="PuTTY" name="core-01">
          <connection_info><name>core-01</name><protocol>Telnet</protocol><host>10.0.0.1</host><port>23</port></connection_info>
          <login><login>netops</login></login>
        </connection>
      </container>
      <connection type="PuTTY" name="edge-01">
        <connection_info><name>edge-01</name><protocol>SSH</protocol><host>10.0.1.1</host><port>2222</port></connection_info>
      </connection>
    </container>
  </root>
</configuration>
"#;
        let tree = import_putty_xml(putty_xml).unwrap();
        assert_eq!(tree.entries().len(), 3);
        let by_host = |host: &str| tree.entries().iter().find(|e| e.hostname == host).unwrap();

        let prod = tree
            .folder(
                by_host("bastion.example")
                    .parent_folder_id
                    .as_deref()
                    .unwrap(),
            )
            .unwrap();
        assert_eq!(prod.name, "Prod");
        assert!(prod.parent_id.is_none());

        let routers = tree
            .folder(by_host("10.0.1.1").parent_folder_id.as_deref().unwrap())
            .unwrap();
        assert_eq!(routers.name, "Routers");
        assert_eq!(routers.parent_id.as_deref(), Some(prod.id.as_str()));

        let core_entry = by_host("10.0.0.1");
        let core = tree
            .folder(core_entry.parent_folder_id.as_deref().unwrap())
            .unwrap();
        assert_eq!(core.name, "Core");
        assert_eq!(core.parent_id.as_deref(), Some(routers.id.as_str()));
        assert_eq!(core_entry.properties.protocol, ConnectionProtocol::Telnet);
        assert_eq!(core_entry.properties.username, "netops");

        // A folder with the wrong type is rejected like mRemoteNG's FileFormatException.
        assert!(matches!(
            import_putty_xml(r#"<configuration><root type="folder" name="x"/></configuration>"#),
            Err(ImportError::InvalidXml(_))
        ));
    }

    /// Regression for #28 `connection_manager.rs:884`: XML character references must be
    /// decoded so `ops&amp;support` imports as the login `ops&support`.
    #[test]
    fn xml_importers_decode_named_and_numeric_character_references() {
        assert_eq!(decode_xml_entities("ops&amp;support"), "ops&support");
        assert_eq!(
            decode_xml_entities("&lt;a href=&quot;x&quot;&gt;&apos;q&apos;"),
            "<a href=\"x\">'q'"
        );
        assert_eq!(decode_xml_entities("&#65;&#x42;&#X43;"), "ABC");
        assert_eq!(decode_xml_entities("&#231;&#xE7;"), "çç");
        // Malformed or unknown references are kept literally and never panic.
        assert_eq!(
            decode_xml_entities("a & b &unknown; &#; &#xZZ; &"),
            "a & b &unknown; &#; &#xZZ; &"
        );

        let rdg_xml = r#"
<RDCMan schemaVersion="3">
  <file>
    <properties><name>Ops &amp; Support</name></properties>
    <server>
      <properties>
        <name>srv&#x2d;01.example</name>
        <displayName>&quot;Quoted&quot; &lt;Server&gt;</displayName>
      </properties>
      <logonCredentials inherit="None">
        <userName>ops&amp;support</userName>
        <domain>R&amp;D</domain>
      </logonCredentials>
    </server>
  </file>
</RDCMan>
"#;
        let tree = import_rdcman_rdg(rdg_xml).unwrap();
        let srv = &tree.entries()[0];
        assert_eq!(srv.hostname, "srv-01.example");
        assert_eq!(srv.display_name, "\"Quoted\" <Server>");
        assert_eq!(srv.properties.username, "ops&support");
        assert_eq!(srv.properties.domain, "R&D");
        assert_eq!(
            tree.folder(srv.parent_folder_id.as_deref().unwrap())
                .unwrap()
                .name,
            "Ops & Support"
        );

        let putty_xml = r#"
<configuration>
  <root type="database" name="R&amp;D &#x4C;ab">
    <connection type="PuTTY" name="x">
      <connection_info><name>Edge &lt;1&gt;</name><protocol>SSH</protocol><host>edge.example</host><port>22</port></connection_info>
      <login><login>ops&amp;support</login></login>
    </connection>
  </root>
</configuration>
"#;
        let tree = import_putty_xml(putty_xml).unwrap();
        let conn = &tree.entries()[0];
        assert_eq!(conn.display_name, "Edge <1>");
        assert_eq!(conn.properties.username, "ops&support");
        assert_eq!(
            tree.folder(conn.parent_folder_id.as_deref().unwrap())
                .unwrap()
                .name,
            "R&D Lab"
        );
    }

    /// Regression for the PR #38 review: `>` inside a quoted attribute value is not the
    /// end of the tag.
    #[test]
    fn xml_parser_allows_greater_than_inside_quoted_attributes() {
        let putty_xml = r#"
<configuration>
  <root type="database" name="Ops > Lab">
    <container type="folder" name='a > "b" > c'>
      <connection type="PuTTY" name="x">
        <connection_info><name>x</name><protocol>SSH</protocol><host>x.example</host><port>22</port></connection_info>
      </connection>
    </container>
  </root>
</configuration>
"#;
        let tree = import_putty_xml(putty_xml).unwrap();
        let conn = &tree.entries()[0];
        let folder = tree
            .folder(conn.parent_folder_id.as_deref().unwrap())
            .unwrap();
        assert_eq!(folder.name, "a > \"b\" > c");
        let root = tree.folder(folder.parent_id.as_deref().unwrap()).unwrap();
        assert_eq!(root.name, "Ops > Lab");
        // An unterminated quote is still an error, not a panic.
        assert!(matches!(
            import_putty_xml(
                r#"<configuration><root type="database" name="x></root></configuration>"#
            ),
            Err(ImportError::InvalidXml(_))
        ));
    }

    /// Regression for the PR #38 review: `RDCMan` schema 1 (v2.2) containers wrap their
    /// name and settings sections in `<properties>`; servers keep them at the root.
    #[test]
    fn rdcman_schema_1_containers_read_settings_from_properties() {
        let rdg_xml = r#"
<RDCMan schemaVersion="1">
  <version>2.2</version>
  <file>
    <properties>
      <name>Legacy File</name>
      <logonCredentials inherit="None">
        <userName>file_admin</userName>
        <domain>LEGACY</domain>
      </logonCredentials>
    </properties>
    <group>
      <properties>
        <name>Legacy Group</name>
        <connectionSettings inherit="None">
          <connectToConsole>True</connectToConsole>
          <port>3391</port>
        </connectionSettings>
      </properties>
      <server>
        <name>legacy-01</name>
        <displayName>Legacy 01</displayName>
        <logonCredentials inherit="None">
          <userName>server_user</userName>
        </logonCredentials>
      </server>
      <server>
        <name>legacy-02</name>
      </server>
    </group>
  </file>
</RDCMan>
"#;
        let tree = import_rdcman_rdg(rdg_xml).unwrap();
        assert_eq!(tree.entries().len(), 2);
        let srv1 = tree
            .entries()
            .iter()
            .find(|e| e.hostname == "legacy-01")
            .unwrap();
        let srv2 = tree
            .entries()
            .iter()
            .find(|e| e.hostname == "legacy-02")
            .unwrap();
        assert_eq!(srv1.display_name, "Legacy 01");

        let group = tree
            .folder(srv1.parent_folder_id.as_deref().unwrap())
            .unwrap();
        assert_eq!(group.name, "Legacy Group");
        assert!(group.properties.use_console_session);
        assert_eq!(group.properties.port, 3391);
        let file = tree.folder(group.parent_id.as_deref().unwrap()).unwrap();
        assert_eq!(file.name, "Legacy File");
        assert_eq!(file.properties.username, "file_admin");

        // Server 1 overrides the user; server 2 inherits the file's credentials and the
        // group's console/port settings through the hierarchy.
        assert_eq!(
            tree.effective_entry_properties(srv1).username,
            "server_user"
        );
        let eff2 = tree.effective_entry_properties(srv2);
        assert_eq!(eff2.username, "file_admin");
        assert_eq!(eff2.domain, "LEGACY");
        assert!(eff2.use_console_session);
        assert_eq!(eff2.port, 3391);
    }

    #[test]
    fn xml_parser_rejects_malformed_documents_without_panicking() {
        assert!(matches!(
            import_rdcman_rdg("<RDCMan><file><group></file></RDCMan>"),
            Err(ImportError::InvalidXml(_))
        ));
        assert!(matches!(
            import_rdcman_rdg("<RDCMan><file>"),
            Err(ImportError::InvalidXml(_))
        ));
        assert!(matches!(
            import_rdcman_rdg("<notrdcman/>"),
            Err(ImportError::InvalidXml(_))
        ));
        assert!(matches!(
            import_putty_xml("<configuration><root type=database></root></configuration>"),
            Err(ImportError::InvalidXml(_))
        ));
        assert!(matches!(
            import_putty_xml(""),
            Err(ImportError::InvalidXml(_))
        ));
        // Comments, processing instructions, CDATA and self-closing tags are tolerated.
        let tree = import_rdcman_rdg(
            "<?xml version=\"1.0\"?><!-- c --><RDCMan schemaVersion=\"3\"><file><properties><name><![CDATA[A & B]]></name><expanded/></properties></file></RDCMan>",
        )
        .unwrap();
        assert_eq!(tree.folder("rdg-group-1").unwrap().name, "A & B");
    }
}
