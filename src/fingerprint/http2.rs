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
}
