//! Minimal, tolerant TLS ClientHello inspection for the passive analyzer.
//!
//! We only need enough parsing to answer: "does the first client->server flight
//! look like a genuine TLS 1.3 ClientHello to a CDN (SNI + h2/h3 ALPN), the way
//! a real browser's would?" A censor's cheapest, most reliable signal is that
//! the very first bytes are NOT a well-formed TLS record at all.

/// Parsed highlights of a ClientHello, plus a coarse JA3-style fingerprint.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct ClientHelloInfo {
    pub is_tls_record: bool,
    pub is_client_hello: bool,
    pub legacy_version: u16,
    pub sni: Option<String>,
    pub alpn: Vec<String>,
    pub cipher_suite_count: usize,
    pub extension_types: Vec<u16>,
    /// JA3-style unhashed string: version,ciphers,exts,groups,ecpf.
    pub ja3_string: Option<String>,
}

struct Cursor<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(b: &'a [u8]) -> Self {
        Cursor { b, pos: 0 }
    }
    fn remaining(&self) -> usize {
        self.b.len().saturating_sub(self.pos)
    }
    fn u8(&mut self) -> Option<u8> {
        let v = *self.b.get(self.pos)?;
        self.pos += 1;
        Some(v)
    }
    fn u16(&mut self) -> Option<u16> {
        if self.remaining() < 2 {
            return None;
        }
        let v = u16::from_be_bytes([self.b[self.pos], self.b[self.pos + 1]]);
        self.pos += 2;
        Some(v)
    }
    fn u24(&mut self) -> Option<usize> {
        if self.remaining() < 3 {
            return None;
        }
        let v = (self.b[self.pos] as usize) << 16
            | (self.b[self.pos + 1] as usize) << 8
            | (self.b[self.pos + 2] as usize);
        self.pos += 3;
        Some(v)
    }
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.remaining() < n {
            return None;
        }
        let s = &self.b[self.pos..self.pos + n];
        self.pos += n;
        Some(s)
    }
}

/// GREASE values (RFC 8701) are excluded from JA3 to match browser behaviour.
fn is_grease(v: u16) -> bool {
    (v & 0x0f0f) == 0x0a0a && (v >> 8) == (v & 0xff)
}

/// Inspect a client->server first flight. Never panics; returns best-effort.
pub fn inspect_client_hello(buf: &[u8]) -> ClientHelloInfo {
    let mut info = ClientHelloInfo::default();
    let mut c = Cursor::new(buf);

    // TLS record header: type(0x16 handshake) version(0x03xx) length(u16).
    let Some(rec_type) = c.u8() else {
        return info;
    };
    let Some(_rec_ver) = c.u16() else {
        return info;
    };
    let Some(_rec_len) = c.u16() else {
        return info;
    };
    if rec_type != 0x16 {
        return info;
    }
    info.is_tls_record = true;

    // Handshake header: msg_type(1 = ClientHello) length(u24).
    let Some(hs_type) = c.u8() else {
        return info;
    };
    let Some(_hs_len) = c.u24() else {
        return info;
    };
    if hs_type != 0x01 {
        return info;
    }
    // NOTE: `is_client_hello` is set only after the mandatory ClientHello body
    // (version, random, session_id, cipher_suites, compression) parses in full,
    // at the end of this function. Setting it here — before the body parse — would
    // misclassify a truncated/malformed TLS handshake as a valid ClientHello,
    // suppressing the `tls_record_but_not_client_hello` structural proxy flag.

    let Some(legacy_version) = c.u16() else {
        return info;
    };
    info.legacy_version = legacy_version;

    // random[32]
    if c.take(32).is_none() {
        return info;
    }
    // session_id
    let Some(sid_len) = c.u8() else {
        return info;
    };
    if c.take(sid_len as usize).is_none() {
        return info;
    }
    // cipher_suites
    let Some(cs_len) = c.u16() else {
        return info;
    };
    let Some(cs) = c.take(cs_len as usize) else {
        return info;
    };
    let mut ja3_ciphers = Vec::new();
    for pair in cs.chunks_exact(2) {
        let v = u16::from_be_bytes([pair[0], pair[1]]);
        if !is_grease(v) {
            ja3_ciphers.push(v.to_string());
        }
    }
    info.cipher_suite_count = cs.len() / 2;
    // compression methods
    let Some(comp_len) = c.u8() else {
        return info;
    };
    if c.take(comp_len as usize).is_none() {
        return info;
    }

    // Every mandatory ClientHello field (version, random, session_id,
    // cipher_suites, compression) parsed in full: this is a structurally valid
    // ClientHello. Extensions below are optional and parsed best-effort.
    info.is_client_hello = true;

    // extensions
    let mut ja3_exts = Vec::new();
    let mut ja3_groups = Vec::new();
    let mut ja3_ecpf = Vec::new();
    if let Some(ext_total) = c.u16() {
        let end = c.pos + ext_total as usize;
        while c.pos + 4 <= end.min(c.b.len()) {
            let Some(etype) = c.u16() else { break };
            let Some(elen) = c.u16() else { break };
            let Some(edata) = c.take(elen as usize) else {
                break;
            };
            if !is_grease(etype) {
                info.extension_types.push(etype);
                ja3_exts.push(etype.to_string());
            }
            match etype {
                0x0000 => {
                    if let Some(name) = parse_sni(edata) {
                        info.sni = Some(name);
                    }
                }
                0x0010 => {
                    info.alpn = parse_alpn(edata);
                }
                0x000a => {
                    // supported_groups
                    let mut gc = Cursor::new(edata);
                    if let Some(list_len) = gc.u16() {
                        if let Some(list) = gc.take(list_len as usize) {
                            for pair in list.chunks_exact(2) {
                                let v = u16::from_be_bytes([pair[0], pair[1]]);
                                if !is_grease(v) {
                                    ja3_groups.push(v.to_string());
                                }
                            }
                        }
                    }
                }
                0x000b => {
                    // ec_point_formats
                    if let Some((&len, rest)) = edata.split_first() {
                        for &b in rest.iter().take(len as usize) {
                            ja3_ecpf.push(b.to_string());
                        }
                    }
                }
                _ => {}
            }
        }
    }

    info.ja3_string = Some(format!(
        "{},{},{},{},{}",
        legacy_version,
        ja3_ciphers.join("-"),
        ja3_exts.join("-"),
        ja3_groups.join("-"),
        ja3_ecpf.join("-"),
    ));
    info
}

fn parse_sni(ext: &[u8]) -> Option<String> {
    let mut c = Cursor::new(ext);
    let _list_len = c.u16()?;
    let name_type = c.u8()?;
    if name_type != 0 {
        return None;
    }
    let name_len = c.u16()?;
    let name = c.take(name_len as usize)?;
    Some(String::from_utf8_lossy(name).into_owned())
}

fn parse_alpn(ext: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut c = Cursor::new(ext);
    let Some(_list_len) = c.u16() else {
        return out;
    };
    while c.remaining() > 0 {
        let Some(l) = c.u8() else { break };
        let Some(p) = c.take(l as usize) else { break };
        out.push(String::from_utf8_lossy(p).into_owned());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A TLS handshake record whose msg_type is ClientHello (0x01) but whose body
    /// is truncated before the mandatory fields end must NOT be classified as a
    /// valid ClientHello — otherwise the passive analyzer suppresses the
    /// `tls_record_but_not_client_hello` structural proxy flag on malformed input.
    #[test]
    fn truncated_client_hello_body_is_not_classified_as_client_hello() {
        // record header (0x16, 0x0301, len=4) + handshake header (0x01, u24 len)
        // and then nothing: the mandatory version/random/... never parse.
        let truncated = [0x16, 0x03, 0x01, 0x00, 0x04, 0x01, 0x00, 0x01, 0x00];
        let info = inspect_client_hello(&truncated);
        assert!(info.is_tls_record, "0x16 record type is a TLS record");
        assert!(
            !info.is_client_hello,
            "a ClientHello truncated inside its mandatory fields must not count as one"
        );
    }

    /// A well-formed minimal ClientHello (all mandatory fields present, no
    /// extensions) is still a valid ClientHello.
    #[test]
    fn minimal_well_formed_client_hello_is_classified() {
        let mut hs = Vec::new();
        hs.push(0x01); // msg_type = ClientHello
        let body_start = hs.len();
        hs.extend_from_slice(&[0, 0, 0]); // u24 length placeholder
        hs.extend_from_slice(&[0x03, 0x03]); // legacy_version TLS1.2
        hs.extend_from_slice(&[0u8; 32]); // random
        hs.push(0x00); // session_id len = 0
        hs.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // cipher_suites: len=2, TLS_AES_128_GCM
        hs.extend_from_slice(&[0x01, 0x00]); // compression: len=1, null
        let body_len = (hs.len() - body_start - 3) as u32;
        hs[body_start..body_start + 3]
            .copy_from_slice(&body_len.to_be_bytes()[1..]); // u24
        let mut rec = vec![0x16, 0x03, 0x01];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);

        let info = inspect_client_hello(&rec);
        assert!(info.is_tls_record);
        assert!(
            info.is_client_hello,
            "a structurally complete ClientHello must be classified as one"
        );
        assert_eq!(info.cipher_suite_count, 1);
    }
}
