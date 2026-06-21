//! QUIC frame codec (RFC 9000 §19), clean-room, pruned to the frames the relay
//! actually sends or receives.
//!
//! Decoded frames borrow their variable-length payloads (CRYPTO/STREAM data,
//! tokens, reason phrases, connection ids) from the input buffer — the caller
//! copies into reassembly/flow state only what it keeps. [`Iter`] walks a packet
//! payload lazily; each [`Frame`] also encodes itself.
//!
//! Out of scope (never on ParallaX's wire): DATAGRAM (0x30/0x31, datagrams are
//! disabled), ACK_FREQUENCY / IMMEDIATE_ACK. An unknown frame type is a decode
//! error rather than being skipped.

use super::varint;

// Frame type codepoints (RFC 9000 §19). STREAM occupies the 0x08..=0x0f block,
// the low 3 bits being OFF/LEN/FIN flags.
const FT_PADDING: u64 = 0x00;
const FT_PING: u64 = 0x01;
const FT_ACK: u64 = 0x02;
const FT_ACK_ECN: u64 = 0x03;
const FT_RESET_STREAM: u64 = 0x04;
const FT_STOP_SENDING: u64 = 0x05;
const FT_CRYPTO: u64 = 0x06;
const FT_NEW_TOKEN: u64 = 0x07;
const FT_STREAM_BASE: u64 = 0x08;
const FT_STREAM_MAX: u64 = 0x0f;
const STREAM_FIN: u64 = 0x01;
const STREAM_LEN: u64 = 0x02;
const STREAM_OFF: u64 = 0x04;
const FT_MAX_DATA: u64 = 0x10;
const FT_MAX_STREAM_DATA: u64 = 0x11;
const FT_MAX_STREAMS_BIDI: u64 = 0x12;
const FT_MAX_STREAMS_UNI: u64 = 0x13;
const FT_DATA_BLOCKED: u64 = 0x14;
const FT_STREAM_DATA_BLOCKED: u64 = 0x15;
const FT_STREAMS_BLOCKED_BIDI: u64 = 0x16;
const FT_STREAMS_BLOCKED_UNI: u64 = 0x17;
const FT_NEW_CONNECTION_ID: u64 = 0x18;
const FT_RETIRE_CONNECTION_ID: u64 = 0x19;
const FT_PATH_CHALLENGE: u64 = 0x1a;
const FT_PATH_RESPONSE: u64 = 0x1b;
const FT_CONNECTION_CLOSE: u64 = 0x1c;
const FT_APPLICATION_CLOSE: u64 = 0x1d;
const FT_HANDSHAKE_DONE: u64 = 0x1e;

const RESET_TOKEN_LEN: usize = 16;

/// Error decoding a frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    /// Ran off the end of the payload.
    Truncated,
    /// A frame type the relay does not implement (anything outside the pruned set).
    UnknownFrame(u64),
    /// A field violated the frame's structure (e.g. an ACK range underflowed).
    Malformed,
}

/// Stream direction selector for MAX_STREAMS / STREAMS_BLOCKED (RFC 9000 §19).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dir {
    Bidi,
    Uni,
}

/// ECN counts on an ACK_ECN frame (RFC 9000 §19.3.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EcnCounts {
    pub ect0: u64,
    pub ect1: u64,
    pub ce: u64,
}

/// A decoded ACK frame (RFC 9000 §19.3). `ranges` are inclusive `[low, high]`
/// acknowledged packet-number ranges in DESCENDING order — `ranges[0]` covers
/// `largest`, each later range strictly below the previous with ≥1 unacked PN
/// between them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ack {
    pub largest: u64,
    pub delay: u64,
    pub ranges: Vec<(u64, u64)>,
    pub ecn: Option<EcnCounts>,
}

/// CONNECTION_CLOSE (transport, 0x1c) or APPLICATION_CLOSE (application, 0x1d).
///
/// The relay's idle-teardown sentinel matches an APPLICATION_CLOSE with
/// `error_code == 1`, so the `error_code` varint MUST round-trip byte-exactly.
/// `frame_type` is meaningful only for the transport variant (0 otherwise).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Close<'a> {
    pub application: bool,
    pub error_code: u64,
    pub frame_type: u64,
    pub reason: &'a [u8],
}

/// A single decoded (or to-be-encoded) QUIC frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame<'a> {
    /// A run of `n` consecutive PADDING (0x00) bytes, coalesced.
    Padding(usize),
    Ping,
    Ack(Ack),
    ResetStream {
        id: u64,
        error_code: u64,
        final_size: u64,
    },
    StopSending {
        id: u64,
        error_code: u64,
    },
    Crypto {
        offset: u64,
        data: &'a [u8],
    },
    NewToken {
        token: &'a [u8],
    },
    Stream {
        id: u64,
        offset: u64,
        fin: bool,
        data: &'a [u8],
    },
    MaxData(u64),
    MaxStreamData {
        id: u64,
        max: u64,
    },
    MaxStreams {
        dir: Dir,
        max: u64,
    },
    DataBlocked(u64),
    StreamDataBlocked {
        id: u64,
        limit: u64,
    },
    StreamsBlocked {
        dir: Dir,
        limit: u64,
    },
    NewConnectionId {
        seq: u64,
        retire_prior_to: u64,
        cid: &'a [u8],
        reset_token: &'a [u8],
    },
    RetireConnectionId(u64),
    PathChallenge(u64),
    PathResponse(u64),
    Close(Close<'a>),
    HandshakeDone,
}

impl Frame<'_> {
    /// Append this frame's wire encoding to `out`.
    pub fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Frame::Padding(n) => out.resize(out.len() + *n, 0),
            Frame::Ping => varint::encode(FT_PING, out),
            Frame::Ack(ack) => encode_ack(ack, out),
            Frame::ResetStream {
                id,
                error_code,
                final_size,
            } => {
                varint::encode(FT_RESET_STREAM, out);
                varint::encode(*id, out);
                varint::encode(*error_code, out);
                varint::encode(*final_size, out);
            }
            Frame::StopSending { id, error_code } => {
                varint::encode(FT_STOP_SENDING, out);
                varint::encode(*id, out);
                varint::encode(*error_code, out);
            }
            Frame::Crypto { offset, data } => {
                varint::encode(FT_CRYPTO, out);
                varint::encode(*offset, out);
                varint::encode(data.len() as u64, out);
                out.extend_from_slice(data);
            }
            Frame::NewToken { token } => {
                varint::encode(FT_NEW_TOKEN, out);
                varint::encode(token.len() as u64, out);
                out.extend_from_slice(token);
            }
            Frame::Stream {
                id,
                offset,
                fin,
                data,
            } => {
                // Always emit the explicit LEN form (self-delimiting); include OFF
                // only for a non-zero offset, matching the minimal Safari shape.
                let mut ty = FT_STREAM_BASE | STREAM_LEN;
                if *offset != 0 {
                    ty |= STREAM_OFF;
                }
                if *fin {
                    ty |= STREAM_FIN;
                }
                varint::encode(ty, out);
                varint::encode(*id, out);
                if *offset != 0 {
                    varint::encode(*offset, out);
                }
                varint::encode(data.len() as u64, out);
                out.extend_from_slice(data);
            }
            Frame::MaxData(v) => {
                varint::encode(FT_MAX_DATA, out);
                varint::encode(*v, out);
            }
            Frame::MaxStreamData { id, max } => {
                varint::encode(FT_MAX_STREAM_DATA, out);
                varint::encode(*id, out);
                varint::encode(*max, out);
            }
            Frame::MaxStreams { dir, max } => {
                varint::encode(
                    match dir {
                        Dir::Bidi => FT_MAX_STREAMS_BIDI,
                        Dir::Uni => FT_MAX_STREAMS_UNI,
                    },
                    out,
                );
                varint::encode(*max, out);
            }
            Frame::DataBlocked(v) => {
                varint::encode(FT_DATA_BLOCKED, out);
                varint::encode(*v, out);
            }
            Frame::StreamDataBlocked { id, limit } => {
                varint::encode(FT_STREAM_DATA_BLOCKED, out);
                varint::encode(*id, out);
                varint::encode(*limit, out);
            }
            Frame::StreamsBlocked { dir, limit } => {
                varint::encode(
                    match dir {
                        Dir::Bidi => FT_STREAMS_BLOCKED_BIDI,
                        Dir::Uni => FT_STREAMS_BLOCKED_UNI,
                    },
                    out,
                );
                varint::encode(*limit, out);
            }
            Frame::NewConnectionId {
                seq,
                retire_prior_to,
                cid,
                reset_token,
            } => {
                varint::encode(FT_NEW_CONNECTION_ID, out);
                varint::encode(*seq, out);
                varint::encode(*retire_prior_to, out);
                out.push(cid.len() as u8);
                out.extend_from_slice(cid);
                out.extend_from_slice(reset_token);
            }
            Frame::RetireConnectionId(seq) => {
                varint::encode(FT_RETIRE_CONNECTION_ID, out);
                varint::encode(*seq, out);
            }
            Frame::PathChallenge(d) => {
                varint::encode(FT_PATH_CHALLENGE, out);
                out.extend_from_slice(&d.to_be_bytes());
            }
            Frame::PathResponse(d) => {
                varint::encode(FT_PATH_RESPONSE, out);
                out.extend_from_slice(&d.to_be_bytes());
            }
            Frame::Close(c) => {
                varint::encode(
                    if c.application {
                        FT_APPLICATION_CLOSE
                    } else {
                        FT_CONNECTION_CLOSE
                    },
                    out,
                );
                varint::encode(c.error_code, out);
                if !c.application {
                    varint::encode(c.frame_type, out);
                }
                varint::encode(c.reason.len() as u64, out);
                out.extend_from_slice(c.reason);
            }
            Frame::HandshakeDone => varint::encode(FT_HANDSHAKE_DONE, out),
        }
    }
}

fn encode_ack(ack: &Ack, out: &mut Vec<u8>) {
    varint::encode(
        if ack.ecn.is_some() {
            FT_ACK_ECN
        } else {
            FT_ACK
        },
        out,
    );
    let (first_low, first_high) = ack.ranges[0];
    varint::encode(first_high, out); // largest
    varint::encode(ack.delay, out);
    varint::encode((ack.ranges.len() - 1) as u64, out); // ack range count
    varint::encode(first_high - first_low, out); // first ack range
    let mut prev_smallest = first_low;
    for &(low, high) in &ack.ranges[1..] {
        varint::encode(prev_smallest - high - 2, out); // gap
        varint::encode(high - low, out); // ack range length
        prev_smallest = low;
    }
    if let Some(e) = ack.ecn {
        varint::encode(e.ect0, out);
        varint::encode(e.ect1, out);
        varint::encode(e.ce, out);
    }
}

/// Lazy decoder over a packet payload's frame sequence.
pub struct Iter<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Iter<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn varint(&mut self) -> Result<u64, FrameError> {
        let (v, n) = varint::decode(&self.buf[self.pos..]).ok_or(FrameError::Truncated)?;
        self.pos += n;
        Ok(v)
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], FrameError> {
        let s = self
            .buf
            .get(self.pos..self.pos + n)
            .ok_or(FrameError::Truncated)?;
        self.pos += n;
        Ok(s)
    }

    fn u64_be(&mut self) -> Result<u64, FrameError> {
        let s = self.take(8)?;
        Ok(u64::from_be_bytes(s.try_into().unwrap()))
    }

    fn parse_one(&mut self) -> Result<Frame<'a>, FrameError> {
        let ty = self.varint()?;
        match ty {
            FT_PADDING => {
                // Coalesce the whole run of zero bytes.
                let mut n = 1;
                while self.buf.get(self.pos) == Some(&0) {
                    self.pos += 1;
                    n += 1;
                }
                Ok(Frame::Padding(n))
            }
            FT_PING => Ok(Frame::Ping),
            FT_ACK | FT_ACK_ECN => self.parse_ack(ty == FT_ACK_ECN),
            FT_RESET_STREAM => Ok(Frame::ResetStream {
                id: self.varint()?,
                error_code: self.varint()?,
                final_size: self.varint()?,
            }),
            FT_STOP_SENDING => Ok(Frame::StopSending {
                id: self.varint()?,
                error_code: self.varint()?,
            }),
            FT_CRYPTO => {
                let offset = self.varint()?;
                let len = self.varint()? as usize;
                Ok(Frame::Crypto {
                    offset,
                    data: self.take(len)?,
                })
            }
            FT_NEW_TOKEN => {
                let len = self.varint()? as usize;
                Ok(Frame::NewToken {
                    token: self.take(len)?,
                })
            }
            FT_STREAM_BASE..=FT_STREAM_MAX => {
                let id = self.varint()?;
                let offset = if ty & STREAM_OFF != 0 {
                    self.varint()?
                } else {
                    0
                };
                let data = if ty & STREAM_LEN != 0 {
                    let len = self.varint()? as usize;
                    self.take(len)?
                } else {
                    // No length: the stream data runs to the end of the packet.
                    let rest = &self.buf[self.pos..];
                    self.pos = self.buf.len();
                    rest
                };
                Ok(Frame::Stream {
                    id,
                    offset,
                    fin: ty & STREAM_FIN != 0,
                    data,
                })
            }
            FT_MAX_DATA => Ok(Frame::MaxData(self.varint()?)),
            FT_MAX_STREAM_DATA => Ok(Frame::MaxStreamData {
                id: self.varint()?,
                max: self.varint()?,
            }),
            FT_MAX_STREAMS_BIDI => Ok(Frame::MaxStreams {
                dir: Dir::Bidi,
                max: self.varint()?,
            }),
            FT_MAX_STREAMS_UNI => Ok(Frame::MaxStreams {
                dir: Dir::Uni,
                max: self.varint()?,
            }),
            FT_DATA_BLOCKED => Ok(Frame::DataBlocked(self.varint()?)),
            FT_STREAM_DATA_BLOCKED => Ok(Frame::StreamDataBlocked {
                id: self.varint()?,
                limit: self.varint()?,
            }),
            FT_STREAMS_BLOCKED_BIDI => Ok(Frame::StreamsBlocked {
                dir: Dir::Bidi,
                limit: self.varint()?,
            }),
            FT_STREAMS_BLOCKED_UNI => Ok(Frame::StreamsBlocked {
                dir: Dir::Uni,
                limit: self.varint()?,
            }),
            FT_NEW_CONNECTION_ID => {
                let seq = self.varint()?;
                let retire_prior_to = self.varint()?;
                let cid_len = *self.buf.get(self.pos).ok_or(FrameError::Truncated)? as usize;
                self.pos += 1;
                let cid = self.take(cid_len)?;
                let reset_token = self.take(RESET_TOKEN_LEN)?;
                Ok(Frame::NewConnectionId {
                    seq,
                    retire_prior_to,
                    cid,
                    reset_token,
                })
            }
            FT_RETIRE_CONNECTION_ID => Ok(Frame::RetireConnectionId(self.varint()?)),
            FT_PATH_CHALLENGE => Ok(Frame::PathChallenge(self.u64_be()?)),
            FT_PATH_RESPONSE => Ok(Frame::PathResponse(self.u64_be()?)),
            FT_CONNECTION_CLOSE | FT_APPLICATION_CLOSE => {
                let application = ty == FT_APPLICATION_CLOSE;
                let error_code = self.varint()?;
                let frame_type = if application { 0 } else { self.varint()? };
                let len = self.varint()? as usize;
                Ok(Frame::Close(Close {
                    application,
                    error_code,
                    frame_type,
                    reason: self.take(len)?,
                }))
            }
            FT_HANDSHAKE_DONE => Ok(Frame::HandshakeDone),
            other => Err(FrameError::UnknownFrame(other)),
        }
    }

    fn parse_ack(&mut self, ecn: bool) -> Result<Frame<'a>, FrameError> {
        let largest = self.varint()?;
        let delay = self.varint()?;
        let range_count = self.varint()?;
        let first_range = self.varint()?;
        let mut ranges = Vec::with_capacity(range_count as usize + 1);
        let first_low = largest
            .checked_sub(first_range)
            .ok_or(FrameError::Malformed)?;
        ranges.push((first_low, largest));
        let mut smallest = first_low;
        for _ in 0..range_count {
            let gap = self.varint()?;
            let len = self.varint()?;
            // next high = smallest - gap - 2 (RFC 9000 §19.3.1).
            let high = smallest.checked_sub(gap + 2).ok_or(FrameError::Malformed)?;
            let low = high.checked_sub(len).ok_or(FrameError::Malformed)?;
            ranges.push((low, high));
            smallest = low;
        }
        let ecn = if ecn {
            Some(EcnCounts {
                ect0: self.varint()?,
                ect1: self.varint()?,
                ce: self.varint()?,
            })
        } else {
            None
        };
        Ok(Frame::Ack(Ack {
            largest,
            delay,
            ranges,
            ecn,
        }))
    }
}

impl<'a> Iterator for Iter<'a> {
    type Item = Result<Frame<'a>, FrameError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos >= self.buf.len() {
            return None;
        }
        let result = self.parse_one();
        if result.is_err() {
            // Stop iterating after the first error.
            self.pos = self.buf.len();
        }
        Some(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encode a frame, decode it back, and assert it round-trips identically.
    fn round_trip(frame: Frame) {
        let mut out = Vec::new();
        frame.encode(&mut out);
        let mut iter = Iter::new(&out);
        let decoded = iter.next().expect("a frame").expect("decodes");
        assert_eq!(decoded, frame);
        assert!(iter.next().is_none(), "exactly one frame");
    }

    #[test]
    fn simple_frames_round_trip() {
        round_trip(Frame::Ping);
        round_trip(Frame::HandshakeDone);
        round_trip(Frame::MaxData(1 << 24));
        round_trip(Frame::MaxStreamData {
            id: 4,
            max: 1 << 21,
        });
        round_trip(Frame::MaxStreams {
            dir: Dir::Uni,
            max: 8,
        });
        round_trip(Frame::DataBlocked(99));
        round_trip(Frame::StreamDataBlocked { id: 0, limit: 5 });
        round_trip(Frame::StreamsBlocked {
            dir: Dir::Bidi,
            limit: 1,
        });
        round_trip(Frame::ResetStream {
            id: 4,
            error_code: 7,
            final_size: 1234,
        });
        round_trip(Frame::StopSending {
            id: 8,
            error_code: 2,
        });
        round_trip(Frame::RetireConnectionId(3));
        round_trip(Frame::PathChallenge(0x0123_4567_89ab_cdef));
        round_trip(Frame::PathResponse(0xfedc_ba98_7654_3210));
    }

    #[test]
    fn crypto_and_stream_carry_borrowed_data() {
        round_trip(Frame::Crypto {
            offset: 16,
            data: b"clienthello-bytes",
        });
        round_trip(Frame::Stream {
            id: 0,
            offset: 0,
            fin: false,
            data: b"relay-payload",
        });
        round_trip(Frame::Stream {
            id: 4,
            offset: 4096,
            fin: true,
            data: b"tail",
        });
    }

    #[test]
    fn new_connection_id_round_trips() {
        round_trip(Frame::NewConnectionId {
            seq: 1,
            retire_prior_to: 0,
            cid: &[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11],
            reset_token: &[0x42; RESET_TOKEN_LEN],
        });
    }

    #[test]
    fn ack_with_multiple_ranges_round_trips() {
        let ack = Ack {
            largest: 1000,
            delay: 25,
            ranges: vec![(1000, 1000), (990, 995), (980, 985)],
            ecn: None,
        };
        round_trip(Frame::Ack(ack));
    }

    #[test]
    fn ack_ecn_round_trips() {
        let ack = Ack {
            largest: 42,
            delay: 3,
            ranges: vec![(40, 42)],
            ecn: Some(EcnCounts {
                ect0: 10,
                ect1: 0,
                ce: 1,
            }),
        };
        round_trip(Frame::Ack(ack));
    }

    #[test]
    fn ack_range_reconstruction_is_exact() {
        // Hand-built wire: largest 100, delay 0, 1 range, first_range 0 ⇒ (100,100);
        // gap 3, len 5 ⇒ high = 100 - 3 - 2 = 95, low = 90 ⇒ (90,95).
        let mut out = Vec::new();
        for v in [FT_ACK, 100, 0, 1, 0, 3, 5] {
            varint::encode(v, &mut out);
        }
        let frame = Iter::new(&out).next().unwrap().unwrap();
        assert_eq!(
            frame,
            Frame::Ack(Ack {
                largest: 100,
                delay: 0,
                ranges: vec![(100, 100), (90, 95)],
                ecn: None,
            })
        );
    }

    #[test]
    fn application_close_error_code_round_trips_exactly() {
        // The idle-teardown sentinel matches APPLICATION_CLOSE error_code == 1.
        round_trip(Frame::Close(Close {
            application: true,
            error_code: 1,
            frame_type: 0,
            reason: b"relay idle",
        }));
    }

    #[test]
    fn connection_close_carries_frame_type() {
        round_trip(Frame::Close(Close {
            application: false,
            error_code: 0x0a, // PROTOCOL_VIOLATION
            frame_type: FT_STREAM_BASE,
            reason: b"bad stream",
        }));
    }

    #[test]
    fn padding_run_is_coalesced() {
        let buf = [0u8; 5];
        let mut iter = Iter::new(&buf);
        assert_eq!(iter.next(), Some(Ok(Frame::Padding(5))));
        assert!(iter.next().is_none());
    }

    #[test]
    fn multi_frame_packet_decodes_in_order() {
        let mut out = Vec::new();
        Frame::Padding(2).encode(&mut out);
        Frame::Ping.encode(&mut out);
        Frame::Crypto {
            offset: 0,
            data: b"hi",
        }
        .encode(&mut out);
        Frame::Ack(Ack {
            largest: 5,
            delay: 0,
            ranges: vec![(0, 5)],
            ecn: None,
        })
        .encode(&mut out);

        let frames: Result<Vec<_>, _> = Iter::new(&out).collect();
        let frames = frames.unwrap();
        assert_eq!(frames.len(), 4);
        assert_eq!(frames[0], Frame::Padding(2));
        assert_eq!(frames[1], Frame::Ping);
        assert!(matches!(frames[2], Frame::Crypto { offset: 0, data } if data == b"hi"));
        assert!(matches!(&frames[3], Frame::Ack(a) if a.largest == 5));
    }

    #[test]
    fn unknown_frame_type_errors() {
        // 0x30 = DATAGRAM, which the relay never accepts.
        let buf = [0x30u8];
        assert_eq!(
            Iter::new(&buf).next(),
            Some(Err(FrameError::UnknownFrame(0x30)))
        );
    }

    #[test]
    fn truncated_crypto_errors() {
        // CRYPTO, offset 0, len 8, but only 2 data bytes present.
        let mut out = Vec::new();
        for v in [FT_CRYPTO, 0, 8] {
            varint::encode(v, &mut out);
        }
        out.extend_from_slice(&[0xaa, 0xbb]);
        assert_eq!(Iter::new(&out).next(), Some(Err(FrameError::Truncated)));
    }
}
