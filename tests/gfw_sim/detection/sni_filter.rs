//! TLS ClientHello parser + SNI keyword filter.
//!
//! Implements the simulator-side view of the GFW's "SNI middlebox" stage. The
//! parser is a minimal RFC 8446 TLS 1.2/1.3 ClientHello reader that extracts the
//! fields necessary for SNI extraction *and* JA3 / JA4 hashing - so the same
//! struct is reused by [`super::tls_fingerprint`].
//!
//! References:
//! - RFC 8446 §4.1.2 (ClientHello structure)
//! - RFC 6066 §3 (server_name extension)
//! - <https://gfw.report/blog/gfw_v3/> on TLS 1.3 SNI blocking behavior

use std::ops::Range;

use super::super::data::sni_blocklist::SniBlocklist;

// ---------------------- TLS constants ----------------------

pub const TLS_CONTENT_HANDSHAKE: u8 = 0x16;
pub const HANDSHAKE_CLIENT_HELLO: u8 = 0x01;

pub const EXT_SERVER_NAME: u16 = 0x0000;
pub const EXT_SUPPORTED_GROUPS: u16 = 0x000a;
pub const EXT_EC_POINT_FORMATS: u16 = 0x000b;
pub const EXT_SIGNATURE_ALGORITHMS: u16 = 0x000d;
pub const EXT_ALPN: u16 = 0x0010;
pub const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
pub const EXT_KEY_SHARE: u16 = 0x0033;
pub const EXT_PSK_KEY_EXCHANGE_MODES: u16 = 0x002d;
pub const EXT_ENCRYPTED_CLIENT_HELLO: u16 = 0xfe0d;
pub const EXT_ENCRYPTED_SERVER_NAME: u16 = 0xffce;

pub const TLS13_VERSION: u16 = 0x0304;

/// Record-layer protocol families an inspector distinguishes by the record
/// header version field. TLS 1.3 still advertises a legacy 0x0303 record
/// version, so the family is read from the record header, not the negotiated
/// version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordProtocol {
    Ssl3,
    Tls10,
    Tls11,
    Tls12,
    /// GM/T national-standard transport layer security (TLCP 1.1, 0x0101).
    Tlcp,
    /// DTLS 1.0 (0xfeff) / DTLS 1.2 (0xfefd).
    Dtls,
    Unknown,
}

/// Classify a record-header version field into a [`RecordProtocol`] family.
pub fn record_protocol(record_version: u16) -> RecordProtocol {
    match record_version {
        0x0300 => RecordProtocol::Ssl3,
        0x0301 => RecordProtocol::Tls10,
        0x0302 => RecordProtocol::Tls11,
        0x0303 => RecordProtocol::Tls12,
        0x0101 => RecordProtocol::Tlcp,
        0xfeff | 0xfefd => RecordProtocol::Dtls,
        _ => RecordProtocol::Unknown,
    }
}

// ---------------------- Parser ----------------------

/// All fields recovered from a TLS ClientHello, retaining wire order so that
/// JA3 / JA4 hashing in [`super::tls_fingerprint`] can stay byte-faithful.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedClientHello {
    pub record_len: usize,
    pub legacy_version: u16,
    pub client_random: [u8; 32],
    pub session_id_range: Range<usize>,
    pub session_id: Vec<u8>,
    pub cipher_suites: Vec<u16>,
    pub compression_methods: Vec<u8>,
    pub extensions_order: Vec<u16>,
    pub sni: Option<String>,
    pub encrypted_client_hello: Option<EncryptedClientHelloKind>,
    pub supported_versions: Vec<u16>,
    pub supported_groups: Vec<u16>,
    pub ec_point_formats: Vec<u8>,
    pub signature_algorithms: Vec<u16>,
    pub alpn: Vec<String>,
    pub key_shares: Vec<KeyShare>,
    pub psk_modes: Vec<u8>,
    /// True if `extensions_order` advertises TLS 1.3 (0x0304) in `supported_versions`.
    pub tls13_supported: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyShare {
    pub group: u16,
    pub key: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptedClientHelloKind {
    Ech,
    Esni,
}

impl EncryptedClientHelloKind {
    pub fn label(self) -> &'static str {
        match self {
            EncryptedClientHelloKind::Ech => "ECH",
            EncryptedClientHelloKind::Esni => "ESNI",
        }
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ClientHelloParseError {
    #[error("ClientHello buffer is shorter than a single TLS record header")]
    Truncated,
    #[error("not a TLS handshake record (content_type {0:#x})")]
    NotHandshake(u8),
    #[error("not a ClientHello (handshake type {0:#x})")]
    NotClientHello(u8),
    #[error("malformed length encoding")]
    MalformedLength,
    #[error("inner handshake length does not fit inside the TLS record")]
    LengthMismatch,
    #[error("ran out of bytes while parsing field {0}")]
    UnexpectedEof(&'static str),
    #[error("malformed extension {0:#x}")]
    MalformedExtension(u16),
}

/// Tries to parse `bytes` as the first TLS record of a ClientHello. Returns the
/// parsed fields including the absolute byte ranges of `session_id`, so the
/// caller can correlate them back to ParallaX's authentication tag.
pub fn parse_client_hello(bytes: &[u8]) -> Result<ParsedClientHello, ClientHelloParseError> {
    if bytes.len() < 5 {
        return Err(ClientHelloParseError::Truncated);
    }
    if bytes[0] != TLS_CONTENT_HANDSHAKE {
        return Err(ClientHelloParseError::NotHandshake(bytes[0]));
    }
    let record_len = u16::from_be_bytes([bytes[3], bytes[4]]) as usize;
    let total = 5 + record_len;
    if bytes.len() < total {
        return Err(ClientHelloParseError::LengthMismatch);
    }
    // The record must hold at least the 4-byte handshake header (type + 24-bit
    // length); without this guard a record_len of 0..4 indexes bytes[5..9] out of
    // bounds below.
    if record_len < 4 {
        return Err(ClientHelloParseError::LengthMismatch);
    }
    if bytes[5] != HANDSHAKE_CLIENT_HELLO {
        return Err(ClientHelloParseError::NotClientHello(bytes[5]));
    }
    let hs_len = (u32::from(bytes[6]) << 16) | (u32::from(bytes[7]) << 8) | u32::from(bytes[8]);
    let hs_end = 9 + hs_len as usize;
    if hs_end > total {
        return Err(ClientHelloParseError::LengthMismatch);
    }

    let mut cur = Cursor::new(&bytes[9..hs_end], 9);
    let legacy_version = cur.u16("legacy_version")?;
    let mut client_random = [0_u8; 32];
    cur.read_into(&mut client_random, "client_random")?;
    let session_id_start = cur.absolute();
    let session_id_len = cur.u8("session_id_len")? as usize;
    let session_id = cur.read_vec(session_id_len, "session_id")?;
    let session_id_end = cur.absolute();
    let cipher_suites = cur.u16_vec_u16len("cipher_suites")?;
    let compression_methods = cur.u8_vec_u8len("compression_methods")?;
    let exts_len = cur.u16("extensions_len")? as usize;
    let exts_end = cur.absolute() + exts_len;
    if exts_end > hs_end {
        return Err(ClientHelloParseError::LengthMismatch);
    }

    let mut extensions_order = Vec::new();
    let mut sni: Option<String> = None;
    let mut encrypted_client_hello = None;
    let mut supported_versions = Vec::new();
    let mut supported_groups = Vec::new();
    let mut ec_point_formats = Vec::new();
    let mut signature_algorithms = Vec::new();
    let mut alpn = Vec::new();
    let mut key_shares = Vec::new();
    let mut psk_modes = Vec::new();

    while cur.absolute() < exts_end {
        let ext_type = cur.u16("extension_type")?;
        let ext_len = cur.u16("extension_length")? as usize;
        let ext_data_start = cur.absolute();
        let ext_data = cur.read_vec(ext_len, "extension_data")?;
        extensions_order.push(ext_type);

        match ext_type {
            EXT_SERVER_NAME => {
                sni = parse_sni(&ext_data)?;
            }
            EXT_SUPPORTED_VERSIONS => {
                supported_versions = parse_supported_versions(&ext_data)?;
            }
            EXT_SUPPORTED_GROUPS => {
                supported_groups = parse_u16_list_u16len(&ext_data, ext_type)?;
            }
            EXT_EC_POINT_FORMATS => {
                ec_point_formats = parse_u8_list_u8len(&ext_data, ext_type)?;
            }
            EXT_SIGNATURE_ALGORITHMS => {
                signature_algorithms = parse_u16_list_u16len(&ext_data, ext_type)?;
            }
            EXT_ALPN => {
                alpn = parse_alpn(&ext_data)?;
            }
            EXT_KEY_SHARE => {
                key_shares = parse_key_shares(&ext_data)?;
            }
            EXT_PSK_KEY_EXCHANGE_MODES => {
                psk_modes = parse_u8_list_u8len(&ext_data, ext_type)?;
            }
            EXT_ENCRYPTED_CLIENT_HELLO => {
                encrypted_client_hello = Some(EncryptedClientHelloKind::Ech);
            }
            EXT_ENCRYPTED_SERVER_NAME => {
                encrypted_client_hello = Some(EncryptedClientHelloKind::Esni);
            }
            _ => {}
        }

        // Silence unused-warning for ext_data_start in non-debug builds.
        let _ = ext_data_start;
    }

    let tls13_supported = supported_versions.contains(&TLS13_VERSION);

    Ok(ParsedClientHello {
        record_len: total,
        legacy_version,
        client_random,
        session_id_range: session_id_start..session_id_end,
        session_id,
        cipher_suites,
        compression_methods,
        extensions_order,
        sni,
        encrypted_client_hello,
        supported_versions,
        supported_groups,
        ec_point_formats,
        signature_algorithms,
        alpn,
        key_shares,
        psk_modes,
        tls13_supported,
    })
}

fn parse_sni(data: &[u8]) -> Result<Option<String>, ClientHelloParseError> {
    if data.len() < 2 {
        return Err(ClientHelloParseError::MalformedExtension(EXT_SERVER_NAME));
    }
    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    if 2 + list_len > data.len() {
        return Err(ClientHelloParseError::MalformedExtension(EXT_SERVER_NAME));
    }
    let mut cur = 2;
    while cur < 2 + list_len {
        if data.len() < cur + 3 {
            return Err(ClientHelloParseError::MalformedExtension(EXT_SERVER_NAME));
        }
        let name_type = data[cur];
        cur += 1;
        let name_len = u16::from_be_bytes([data[cur], data[cur + 1]]) as usize;
        cur += 2;
        if cur + name_len > data.len() {
            return Err(ClientHelloParseError::MalformedExtension(EXT_SERVER_NAME));
        }
        let name = &data[cur..cur + name_len];
        cur += name_len;
        if name_type == 0 {
            let sni = std::str::from_utf8(name)
                .map_err(|_| ClientHelloParseError::MalformedExtension(EXT_SERVER_NAME))?;
            return Ok(Some(sni.to_owned()));
        }
    }
    Ok(None)
}

fn parse_supported_versions(data: &[u8]) -> Result<Vec<u16>, ClientHelloParseError> {
    if data.is_empty() {
        return Err(ClientHelloParseError::MalformedExtension(
            EXT_SUPPORTED_VERSIONS,
        ));
    }
    let list_len = data[0] as usize;
    if 1 + list_len > data.len() || list_len % 2 != 0 {
        return Err(ClientHelloParseError::MalformedExtension(
            EXT_SUPPORTED_VERSIONS,
        ));
    }
    let mut out = Vec::with_capacity(list_len / 2);
    let mut idx = 1;
    while idx < 1 + list_len {
        out.push(u16::from_be_bytes([data[idx], data[idx + 1]]));
        idx += 2;
    }
    Ok(out)
}

fn parse_u16_list_u16len(data: &[u8], ext: u16) -> Result<Vec<u16>, ClientHelloParseError> {
    if data.len() < 2 {
        return Err(ClientHelloParseError::MalformedExtension(ext));
    }
    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    if 2 + list_len > data.len() || list_len % 2 != 0 {
        return Err(ClientHelloParseError::MalformedExtension(ext));
    }
    let mut out = Vec::with_capacity(list_len / 2);
    let mut idx = 2;
    while idx < 2 + list_len {
        out.push(u16::from_be_bytes([data[idx], data[idx + 1]]));
        idx += 2;
    }
    Ok(out)
}

fn parse_u8_list_u8len(data: &[u8], ext: u16) -> Result<Vec<u8>, ClientHelloParseError> {
    if data.is_empty() {
        return Err(ClientHelloParseError::MalformedExtension(ext));
    }
    let list_len = data[0] as usize;
    if 1 + list_len > data.len() {
        return Err(ClientHelloParseError::MalformedExtension(ext));
    }
    Ok(data[1..1 + list_len].to_vec())
}

fn parse_alpn(data: &[u8]) -> Result<Vec<String>, ClientHelloParseError> {
    if data.len() < 2 {
        return Err(ClientHelloParseError::MalformedExtension(EXT_ALPN));
    }
    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    if 2 + list_len > data.len() {
        return Err(ClientHelloParseError::MalformedExtension(EXT_ALPN));
    }
    let mut out = Vec::new();
    let mut cur = 2;
    while cur < 2 + list_len {
        let proto_len = data[cur] as usize;
        cur += 1;
        if cur + proto_len > data.len() {
            return Err(ClientHelloParseError::MalformedExtension(EXT_ALPN));
        }
        let proto = std::str::from_utf8(&data[cur..cur + proto_len])
            .map_err(|_| ClientHelloParseError::MalformedExtension(EXT_ALPN))?;
        out.push(proto.to_owned());
        cur += proto_len;
    }
    Ok(out)
}

fn parse_key_shares(data: &[u8]) -> Result<Vec<KeyShare>, ClientHelloParseError> {
    if data.len() < 2 {
        return Err(ClientHelloParseError::MalformedExtension(EXT_KEY_SHARE));
    }
    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    if 2 + list_len > data.len() {
        return Err(ClientHelloParseError::MalformedExtension(EXT_KEY_SHARE));
    }
    let mut out = Vec::new();
    let mut cur = 2;
    while cur < 2 + list_len {
        if cur + 4 > data.len() {
            return Err(ClientHelloParseError::MalformedExtension(EXT_KEY_SHARE));
        }
        let group = u16::from_be_bytes([data[cur], data[cur + 1]]);
        let key_len = u16::from_be_bytes([data[cur + 2], data[cur + 3]]) as usize;
        cur += 4;
        if cur + key_len > data.len() {
            return Err(ClientHelloParseError::MalformedExtension(EXT_KEY_SHARE));
        }
        out.push(KeyShare {
            group,
            key: data[cur..cur + key_len].to_vec(),
        });
        cur += key_len;
    }
    Ok(out)
}

// ---------------------- Cursor helper ----------------------

struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
    base: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8], base: usize) -> Self {
        Self { data, pos: 0, base }
    }

    fn absolute(&self) -> usize {
        self.base + self.pos
    }

    fn need(&self, n: usize, field: &'static str) -> Result<(), ClientHelloParseError> {
        if self.pos + n > self.data.len() {
            Err(ClientHelloParseError::UnexpectedEof(field))
        } else {
            Ok(())
        }
    }

    fn u8(&mut self, field: &'static str) -> Result<u8, ClientHelloParseError> {
        self.need(1, field)?;
        let v = self.data[self.pos];
        self.pos += 1;
        Ok(v)
    }

    fn u16(&mut self, field: &'static str) -> Result<u16, ClientHelloParseError> {
        self.need(2, field)?;
        let v = u16::from_be_bytes([self.data[self.pos], self.data[self.pos + 1]]);
        self.pos += 2;
        Ok(v)
    }

    fn read_into(
        &mut self,
        buf: &mut [u8],
        field: &'static str,
    ) -> Result<(), ClientHelloParseError> {
        self.need(buf.len(), field)?;
        buf.copy_from_slice(&self.data[self.pos..self.pos + buf.len()]);
        self.pos += buf.len();
        Ok(())
    }

    fn read_vec(
        &mut self,
        n: usize,
        field: &'static str,
    ) -> Result<Vec<u8>, ClientHelloParseError> {
        self.need(n, field)?;
        let out = self.data[self.pos..self.pos + n].to_vec();
        self.pos += n;
        Ok(out)
    }

    fn u16_vec_u16len(&mut self, field: &'static str) -> Result<Vec<u16>, ClientHelloParseError> {
        let len = self.u16(field)? as usize;
        self.need(len, field)?;
        if len % 2 != 0 {
            return Err(ClientHelloParseError::MalformedLength);
        }
        let mut out = Vec::with_capacity(len / 2);
        for chunk in self.data[self.pos..self.pos + len].chunks_exact(2) {
            out.push(u16::from_be_bytes([chunk[0], chunk[1]]));
        }
        self.pos += len;
        Ok(out)
    }

    fn u8_vec_u8len(&mut self, field: &'static str) -> Result<Vec<u8>, ClientHelloParseError> {
        let len = self.u8(field)? as usize;
        self.need(len, field)?;
        let out = self.data[self.pos..self.pos + len].to_vec();
        self.pos += len;
        Ok(out)
    }
}

// ---------------------- Cross-segment reassembly ----------------------

/// Upper bound on bytes buffered while waiting for a ClientHello that is split
/// across several TCP segments. A handshake larger than this is abandoned.
pub const MAX_RECORD_CACHE_LEN: usize = 10240;

/// Status of a segment fed to [`ClientHelloReassembler`].
#[derive(Debug, Clone, PartialEq)]
pub enum ReassemblyStatus {
    /// A complete first TLS record is buffered and parsed.
    Complete(Box<ParsedClientHello>),
    /// The record header or body is still incomplete; more segments are needed.
    NeedMore,
    /// The buffered prefix is not a TLS handshake record at all.
    NotTls,
    /// The buffer grew past [`MAX_RECORD_CACHE_LEN`] without completing.
    Overflow,
}

/// Stateful reassembler that reconstructs a ClientHello delivered across
/// multiple TCP segments. A border inspector that holds segments until the
/// first record is whole defeats the "fragment the ClientHello" evasion: only a
/// handshake larger than the cache, or never completed, slips past.
#[derive(Debug, Default)]
pub struct ClientHelloReassembler {
    buffer: Vec<u8>,
    /// Number of original segments held while waiting for completion. Mirrors
    /// the "detained fragment" count a real middlebox tracks.
    pub detained_segments: usize,
}

impl ClientHelloReassembler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Append one TCP segment and attempt to parse a complete ClientHello.
    pub fn push_segment(&mut self, segment: &[u8]) -> ReassemblyStatus {
        if self.buffer.len() + segment.len() > MAX_RECORD_CACHE_LEN {
            return ReassemblyStatus::Overflow;
        }
        self.buffer.extend_from_slice(segment);
        self.detained_segments += 1;

        // Need the 5-byte record header before we can know the record length.
        if self.buffer.len() < 5 {
            return ReassemblyStatus::NeedMore;
        }
        if self.buffer[0] != TLS_CONTENT_HANDSHAKE {
            return ReassemblyStatus::NotTls;
        }
        let record_len = u16::from_be_bytes([self.buffer[3], self.buffer[4]]) as usize;
        let total = 5 + record_len;
        if self.buffer.len() < total {
            return ReassemblyStatus::NeedMore;
        }
        match parse_client_hello(&self.buffer[..total]) {
            Ok(parsed) => ReassemblyStatus::Complete(Box::new(parsed)),
            Err(ClientHelloParseError::NotHandshake(_)) => ReassemblyStatus::NotTls,
            // A length/EOF error on an otherwise-complete record means the
            // handshake message itself spans further bytes we have not seen.
            Err(_) => ReassemblyStatus::NeedMore,
        }
    }

    /// Bytes currently buffered (for tests / introspection).
    pub fn buffered_len(&self) -> usize {
        self.buffer.len()
    }
}

// ---------------------- Filter logic ----------------------

/// Output of a single SNI-filter pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SniVerdict {
    /// SNI was extracted and is *not* in the blocklist.
    Allow { sni: String },
    /// SNI was extracted and matches a blocklist rule. `matched_rule` is the
    /// pattern that fired (for logging).
    Block { sni: String, matched_rule: String },
    /// ECH / ESNI extension was advertised; public measurements show ESNI and
    /// ECH-style encrypted SNI paths are treated as censorable TLS metadata.
    BlockEncryptedClientHello {
        kind: EncryptedClientHelloKind,
        ext_type: u16,
    },
    /// Record was malformed, or no SNI extension was present. Real GFW behavior:
    /// the connection is allowed past MB-RA but flagged for MB-R inspection.
    NoSni,
    /// Record was not a valid ClientHello. Real GFW behavior: not a candidate
    /// for the TLS middlebox; falls through to other inspection layers.
    NotTls,
}

/// MB-RA / MB-R staging. The GFW's TLS middleboxes are deployed in two stages:
/// MB-RA acts on the ClientHello alone; MB-R retains state and reinforces the
/// decision at the ClientKeyExchange / Finished boundary (TLS 1.2) or at the
/// ChangeCipherSpec / first ApplicationData boundary (TLS 1.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MiddleboxStage {
    Mbra,
    Mbr,
}

/// Composable SNI filter. The default constructor uses the published
/// circumvention blocklist plus typical Maat regex rules; consumers can build a
/// filter from any [`SniBlocklist`] to drive negative scenarios.
pub struct SniFilter {
    blocklist: SniBlocklist,
}

impl Default for SniFilter {
    fn default() -> Self {
        Self {
            blocklist: SniBlocklist::default_circumvention(),
        }
    }
}

impl SniFilter {
    pub fn new(blocklist: SniBlocklist) -> Self {
        Self { blocklist }
    }

    pub fn blocklist(&self) -> &SniBlocklist {
        &self.blocklist
    }

    /// Run the filter on a parsed ClientHello.
    pub fn evaluate_parsed(&self, parsed: &ParsedClientHello) -> SniVerdict {
        if let Some(kind) = parsed.encrypted_client_hello {
            let ext_type = match kind {
                EncryptedClientHelloKind::Ech => EXT_ENCRYPTED_CLIENT_HELLO,
                EncryptedClientHelloKind::Esni => EXT_ENCRYPTED_SERVER_NAME,
            };
            return SniVerdict::BlockEncryptedClientHello { kind, ext_type };
        }
        match &parsed.sni {
            Some(sni) => {
                if let Some(rule) = self.blocklist.matched_rule(sni) {
                    SniVerdict::Block {
                        sni: sni.clone(),
                        matched_rule: rule,
                    }
                } else {
                    SniVerdict::Allow { sni: sni.clone() }
                }
            }
            None => SniVerdict::NoSni,
        }
    }

    /// Run the filter on a raw ClientHello record. Equivalent to MB-RA's
    /// single-pass decision.
    pub fn evaluate(&self, bytes: &[u8]) -> SniVerdict {
        match parse_client_hello(bytes) {
            Ok(parsed) => self.evaluate_parsed(&parsed),
            Err(_) => SniVerdict::NotTls,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gfw_sim::fixtures::synthetic_tls13_client_hello;

    fn parallax_client_hello(sni: &str) -> Vec<u8> {
        synthetic_tls13_client_hello(sni, 0xC0FFEE)
    }

    #[test]
    fn parses_parallax_client_hello() {
        let record = parallax_client_hello("cloudflare.com");
        let parsed = parse_client_hello(&record).unwrap();
        assert_eq!(parsed.sni.as_deref(), Some("cloudflare.com"));
        assert!(parsed.tls13_supported);
        assert!(parsed.extensions_order.contains(&EXT_SERVER_NAME));
        assert!(parsed.extensions_order.contains(&EXT_KEY_SHARE));
    }

    #[test]
    fn default_filter_allows_unlisted_sni() {
        let record = parallax_client_hello("cloudflare.com");
        let filter = SniFilter::default();
        assert!(matches!(filter.evaluate(&record), SniVerdict::Allow { .. }));
    }

    fn client_hello_with_extension(ext_type: u16) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0x11; 32]);
        body.push(0);
        body.extend_from_slice(&2_u16.to_be_bytes());
        body.extend_from_slice(&0x1301_u16.to_be_bytes());
        body.extend_from_slice(&[1, 0]);
        let mut exts = Vec::new();
        exts.extend_from_slice(&ext_type.to_be_bytes());
        exts.extend_from_slice(&0_u16.to_be_bytes());
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);

        let hs_len = body.len() as u32;
        let mut handshake = vec![
            HANDSHAKE_CLIENT_HELLO,
            ((hs_len >> 16) & 0xff) as u8,
            ((hs_len >> 8) & 0xff) as u8,
            (hs_len & 0xff) as u8,
        ];
        handshake.extend_from_slice(&body);

        let mut record = Vec::new();
        record.push(TLS_CONTENT_HANDSHAKE);
        record.extend_from_slice(&[0x03, 0x03]);
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    #[test]
    fn default_filter_blocks_known_circumvention_sni() {
        let record = parallax_client_hello("relay7.shadowsocks.io");
        let filter = SniFilter::default();
        match filter.evaluate(&record) {
            SniVerdict::Block { sni, matched_rule } => {
                assert_eq!(sni, "relay7.shadowsocks.io");
                assert_eq!(matched_rule, "*.shadowsocks.io");
            }
            other => panic!("expected Block, got {other:?}"),
        }
    }

    #[test]
    fn encrypted_client_hello_extension_is_blocked() {
        let filter = SniFilter::default();
        let record = client_hello_with_extension(EXT_ENCRYPTED_SERVER_NAME);
        match filter.evaluate(&record) {
            SniVerdict::BlockEncryptedClientHello { kind, ext_type } => {
                assert_eq!(kind, EncryptedClientHelloKind::Esni);
                assert_eq!(ext_type, EXT_ENCRYPTED_SERVER_NAME);
            }
            other => panic!("expected encrypted ClientHello block, got {other:?}"),
        }
    }

    #[test]
    fn malformed_input_is_not_tls() {
        let filter = SniFilter::default();
        assert_eq!(filter.evaluate(b""), SniVerdict::NotTls);
        assert_eq!(filter.evaluate(b"\x16\x03"), SniVerdict::NotTls);
    }

    #[test]
    fn mbra_and_mbr_can_be_distinguished() {
        // Stage labels carry no behaviour on their own but make verdicts more
        // useful in logs; ensure the enum is wired up.
        assert_ne!(MiddleboxStage::Mbra, MiddleboxStage::Mbr);
    }

    #[test]
    fn reassembler_joins_clienthello_split_across_segments() {
        let record = parallax_client_hello("relay7.shadowsocks.io");
        let mid = record.len() / 2;
        let mut reasm = ClientHelloReassembler::new();
        // First half: header is present but body incomplete.
        match reasm.push_segment(&record[..mid]) {
            ReassemblyStatus::NeedMore => {}
            other => panic!("expected NeedMore on first segment, got {other:?}"),
        }
        // Second half completes the record.
        match reasm.push_segment(&record[mid..]) {
            ReassemblyStatus::Complete(parsed) => {
                assert_eq!(parsed.sni.as_deref(), Some("relay7.shadowsocks.io"));
            }
            other => panic!("expected Complete on second segment, got {other:?}"),
        }
        assert_eq!(reasm.detained_segments, 2);
    }

    #[test]
    fn reassembler_handles_byte_at_a_time_delivery() {
        let record = parallax_client_hello("cloudflare.com");
        let mut reasm = ClientHelloReassembler::new();
        let mut completed = None;
        for b in &record {
            if let ReassemblyStatus::Complete(parsed) = reasm.push_segment(&[*b]) {
                completed = Some(parsed);
                break;
            }
        }
        assert_eq!(
            completed.expect("reassembled").sni.as_deref(),
            Some("cloudflare.com")
        );
    }

    #[test]
    fn reassembler_overflows_on_oversized_buffer() {
        let mut reasm = ClientHelloReassembler::new();
        // A handshake record header announcing a body far larger than the cache.
        let mut seg = vec![TLS_CONTENT_HANDSHAKE, 0x03, 0x03, 0xff, 0xff];
        seg.resize(64, 0);
        // Keep feeding until the cache overflows.
        let mut overflowed = false;
        for _ in 0..400 {
            if reasm.push_segment(&seg) == ReassemblyStatus::Overflow {
                overflowed = true;
                break;
            }
        }
        assert!(overflowed, "buffer should overflow past the cache limit");
    }

    #[test]
    fn reassembler_rejects_non_tls_prefix() {
        let mut reasm = ClientHelloReassembler::new();
        assert_eq!(
            reasm.push_segment(b"GET / HTTP/1.1\r\n"),
            ReassemblyStatus::NotTls
        );
    }

    #[test]
    fn record_protocol_classifies_families() {
        assert_eq!(record_protocol(0x0303), RecordProtocol::Tls12);
        assert_eq!(record_protocol(0x0101), RecordProtocol::Tlcp);
        assert_eq!(record_protocol(0xfeff), RecordProtocol::Dtls);
        assert_eq!(record_protocol(0xfefd), RecordProtocol::Dtls);
        assert_eq!(record_protocol(0x9999), RecordProtocol::Unknown);
    }
}
