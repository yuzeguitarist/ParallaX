use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Http2PeerProfile {
    Safari17,
    Chrome124,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Http2Setting {
    pub id: u16,
    pub value: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Http2Fingerprint {
    pub settings: Vec<Http2Setting>,
    pub initial_window_update: Option<u32>,
    pub priority_frames: u8,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum Http2FingerprintError {
    #[error("HTTP/2 frame payload is too large")]
    FrameTooLarge,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Http2FrameHeader {
    pub len: usize,
    pub frame_type: u8,
    pub flags: u8,
    pub stream_id: u32,
}

impl Http2Fingerprint {
    pub fn for_profile(profile: Http2PeerProfile) -> Self {
        match profile {
            Http2PeerProfile::Safari17 => Self {
                settings: vec![
                    Http2Setting {
                        id: 0x1,
                        value: 4096,
                    },
                    Http2Setting {
                        id: 0x3,
                        value: 100,
                    },
                    Http2Setting {
                        id: 0x4,
                        value: 2_097_152,
                    },
                    Http2Setting {
                        id: 0x6,
                        value: 262_144,
                    },
                ],
                initial_window_update: Some(15_663_105),
                priority_frames: 0,
            },
            Http2PeerProfile::Chrome124 => Self {
                settings: vec![
                    Http2Setting {
                        id: 0x1,
                        value: 65_536,
                    },
                    Http2Setting { id: 0x2, value: 0 },
                    Http2Setting {
                        id: 0x3,
                        value: 1000,
                    },
                    Http2Setting {
                        id: 0x4,
                        value: 6_291_456,
                    },
                    Http2Setting {
                        id: 0x6,
                        value: 262_144,
                    },
                ],
                initial_window_update: Some(15_663_105),
                priority_frames: 0,
            },
        }
    }

    pub fn settings_frame(&self) -> Result<Vec<u8>, Http2FingerprintError> {
        let mut payload = Vec::with_capacity(self.settings.len() * 6);
        for setting in &self.settings {
            payload.extend_from_slice(&setting.id.to_be_bytes());
            payload.extend_from_slice(&setting.value.to_be_bytes());
        }
        frame(0x4, 0, 0, &payload)
    }

    pub fn initial_window_update_frame(&self) -> Result<Option<Vec<u8>>, Http2FingerprintError> {
        let Some(increment) = self.initial_window_update else {
            return Ok(None);
        };
        let value = increment & 0x7fff_ffff;
        Ok(Some(frame(0x8, 0, 0, &value.to_be_bytes())?))
    }

    pub fn connection_preface(&self) -> Result<Vec<u8>, Http2FingerprintError> {
        let mut out = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
        out.extend_from_slice(&self.settings_frame()?);
        if let Some(window_update) = self.initial_window_update_frame()? {
            out.extend_from_slice(&window_update);
        }
        Ok(out)
    }

    pub fn settings_ack_frame() -> Result<Vec<u8>, Http2FingerprintError> {
        frame(0x4, 0x1, 0, &[])
    }

    pub fn headers_frame(&self, authority: &str) -> Result<Vec<u8>, Http2FingerprintError> {
        let mut payload = Vec::with_capacity(5 + authority.len());
        payload.push(0x82); // :method: GET
        payload.push(0x87); // :scheme: https
        payload.push(0x84); // :path: /
        payload.push(0x41); // literal with indexed name: :authority
        push_hpack_string(&mut payload, authority.as_bytes());
        frame(0x1, 0x4, 1, &payload)
    }
}

impl Http2FrameHeader {
    pub const SIZE: usize = 9;

    pub fn parse_complete(input: &[u8]) -> Option<(Self, usize)> {
        if input.len() < Self::SIZE {
            return None;
        }

        let len = ((input[0] as usize) << 16) | ((input[1] as usize) << 8) | input[2] as usize;
        let total = Self::SIZE + len;
        if input.len() < total {
            return None;
        }

        let stream_id = u32::from_be_bytes([input[5], input[6], input[7], input[8]]) & 0x7fff_ffff;
        Some((
            Self {
                len,
                frame_type: input[3],
                flags: input[4],
                stream_id,
            },
            total,
        ))
    }

    pub fn is_settings(&self) -> bool {
        self.frame_type == 0x4 && self.stream_id == 0
    }

    pub fn is_settings_ack(&self) -> bool {
        self.is_settings() && self.len == 0 && (self.flags & 0x1) != 0
    }
}

fn frame(
    frame_type: u8,
    flags: u8,
    stream_id: u32,
    payload: &[u8],
) -> Result<Vec<u8>, Http2FingerprintError> {
    if payload.len() > 0x00ff_ffff {
        return Err(Http2FingerprintError::FrameTooLarge);
    }

    let mut out = Vec::with_capacity(9 + payload.len());
    let len = payload.len() as u32;
    out.push(((len >> 16) & 0xff) as u8);
    out.push(((len >> 8) & 0xff) as u8);
    out.push((len & 0xff) as u8);
    out.push(frame_type);
    out.push(flags);
    out.extend_from_slice(&(stream_id & 0x7fff_ffff).to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

fn push_hpack_string(out: &mut Vec<u8>, value: &[u8]) {
    push_hpack_integer(out, value.len(), 7, 0);
    out.extend_from_slice(value);
}

fn push_hpack_integer(out: &mut Vec<u8>, value: usize, prefix_bits: u8, first_byte_mask: u8) {
    let max_prefix_value = (1_usize << prefix_bits) - 1;
    if value < max_prefix_value {
        out.push(first_byte_mask | value as u8);
        return;
    }

    out.push(first_byte_mask | max_prefix_value as u8);
    let mut remaining = value - max_prefix_value;
    while remaining >= 128 {
        out.push((remaining as u8 & 0x7f) | 0x80);
        remaining >>= 7;
    }
    out.push(remaining as u8);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_http2_preface() {
        let fp = Http2Fingerprint::for_profile(Http2PeerProfile::Chrome124);
        let preface = fp.connection_preface().unwrap();
        assert!(preface.starts_with(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"));
        assert!(preface.len() > 24);
    }

    #[test]
    fn settings_frame_has_expected_length() {
        let fp = Http2Fingerprint::for_profile(Http2PeerProfile::Safari17);
        let frame = fp.settings_frame().unwrap();
        assert_eq!(&frame[0..3], &[0, 0, 24]);
        assert_eq!(frame[3], 0x4);
    }

    #[test]
    fn builds_settings_ack_frame() {
        let frame = Http2Fingerprint::settings_ack_frame().unwrap();
        assert_eq!(&frame, &[0, 0, 0, 0x4, 0x1, 0, 0, 0, 0]);
    }

    #[test]
    fn builds_opening_headers_frame() {
        let fp = Http2Fingerprint::for_profile(Http2PeerProfile::Chrome124);
        let frame = fp.headers_frame("example.com").unwrap();
        let (header, total) = Http2FrameHeader::parse_complete(&frame).unwrap();

        assert_eq!(total, frame.len());
        assert_eq!(header.frame_type, 0x1);
        assert_eq!(header.flags, 0x4);
        assert_eq!(header.stream_id, 1);
        assert_eq!(&frame[9..14], &[0x82, 0x87, 0x84, 0x41, 11]);
    }

    #[test]
    fn parses_complete_settings_ack_frame() {
        let frame = Http2Fingerprint::settings_ack_frame().unwrap();
        let (header, total) = Http2FrameHeader::parse_complete(&frame).unwrap();

        assert_eq!(total, frame.len());
        assert!(header.is_settings_ack());
    }
}
