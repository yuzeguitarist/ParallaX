// Reviewed complete AST scopes. Syntactic regression pin, not a CFG proof.
fn frame_permitted(space: PacketSpace, side: Side, frame_type: u64) -> bool {
    if side == Side::Server && matches!(frame_type, 0x07 | 0x1e) {
        return false;
    }
    match space {
        PacketSpace::Initial | PacketSpace::Handshake => {
            matches!(frame_type, 0x00 | 0x01 | 0x02 | 0x03 | 0x06 | 0x1c)
        }
        PacketSpace::ZeroRtt => {
            !matches!(frame_type, 0x02 | 0x03 | 0x06 | 0x07 | 0x19 | 0x1b | 0x1e)
        }
        PacketSpace::OneRtt => true,
    }
}

fn reviewed_frame_iteration() {
        while let Some(frame) = frames.next() {
            let frame_type = frames.last_frame_type();
            let frame = frame.map_err(|e| {
                transport_error(0x07, frame_type, format!("frame decode failed: {e:?}"))
            })?;
            // A driver may ignore a handshake processing error. Make rejection
            // terminal before returning; neither this frame nor later frames
            // (including in another datagram) may then mutate the connection.
            // Earlier legal frames and authenticated packet metadata stay committed.
            if !frame_permitted(pspace, self.side, frame_type) {
                self.close_transport(0x0a, frame_type, b"frame not permitted");
                return Err(transport_error(0x0a, frame_type, "frame not permitted"));
            }
            match frame {
                Frame::Crypto { offset, data } => {
                    ack_eliciting = true;
                    self.recv_crypto(space, offset, data)
                        .map_err(|error| with_frame_type(error, frame_type))?;
                }
                Frame::Stream {
                    id,
                    offset,
                    fin,
                    data,
                } => {
                    ack_eliciting = true;
                    self.recv_stream(id, offset, fin, data)
                        .map_err(|error| with_frame_type(error, frame_type))?;
                }
                Frame::ResetStream {
                    id,
                    error_code,
                    final_size,
                } => {
                    ack_eliciting = true;
                    self.recv_reset_stream(id, error_code, final_size)?;
                }
                Frame::StopSending { id, error_code } => {
                    ack_eliciting = true;
                    if is_uni(id) && self.is_peer_initiated(id) {
                        return Err(QuicTlsError::Transport {
                            error_code: 0x05,
                            frame_type: 0x05,
                            reason: "STOP_SENDING on a receive-only stream".into(),
                        });
                    }
                    if !self.stream_retired(id) {
                        if !self.is_peer_initiated(id) && !self.streams.contains_key(&id) {
                            return Err(QuicTlsError::Transport {
                                error_code: 0x05,
                                frame_type: 0x05,
                                reason: "STOP_SENDING on an unopened locally-initiated stream"
                                    .into(),
                            });
                        }
                        self.ensure_stream(id, frame_type)?;
                        self.reset_stream(id, error_code);
                    }
                }
                Frame::MaxData(max) => {
                    // Raise the connection-level send limit (RFC 9000 §19.9).
                    // MAX_DATA is ack-eliciting (RFC 9002 §2), so a lone MAX_DATA
                    // must still schedule an ACK or the peer would PTO-retransmit it.
                    ack_eliciting = true;
                    self.send_max_data = self.send_max_data.max(max);
                }
                Frame::MaxStreamData { id, max } => {
                    // Raise a stream's send limit (RFC 9000 §19.10).
                    ack_eliciting = true;
                    if let Some(s) = self.streams.get_mut(&id) {
                        s.send_max = s.send_max.max(max);
                    }
                }
                Frame::MaxStreams { dir, max } => {
                    ack_eliciting = true;
                    if max > (1 << 60) {
                        return Err(QuicTlsError::Transport {
                            error_code: 0x07, // FRAME_ENCODING_ERROR, RFC 9000 §19.11.
                            frame_type: if dir == Dir::Uni { 0x13 } else { 0x12 },
                            reason: "MAX_STREAMS exceeds 2^60".into(),
                        });
                    }
                    let kind = usize::from(dir == Dir::Uni);
                    self.send_max_streams[kind] = self.send_max_streams[kind].max(max);
                }
                Frame::Ack(ack) => self
                    .recv_ack(space, &ack, receive_generation, now)
                    .map_err(|error| with_frame_type(error, frame_type))?,
                Frame::HandshakeDone => {
                    ack_eliciting = true;
                    // RFC 9001 §4.1.2: the client treats HANDSHAKE_DONE as handshake
                    // confirmation. (Only a client should receive it.) On confirmation
                    // discard Handshake keys + state (RFC 9001 §4.9.2 / RFC 9002 §6.4).
                    if self.side == Side::Client {
                        self.handshake_confirmed = true;
                        self.discard_space(SPACE_HANDSHAKE);
                    }
                }
                Frame::Padding(_) => {}
                Frame::Close(c) => {
                    // The peer is tearing the connection down (RFC 9000 §19.19):
                    // enter the draining state and start the drain countdown.
                    if self.closed.is_none() {
                        let reason = c.reason.to_vec();
                        self.closed = Some(if c.application {
                            CloseReason::PeerApp(c.error_code, reason)
                        } else {
                            CloseReason::PeerTransport(c.error_code, c.frame_type, reason)
                        });
                        self.close_time = Some(now);
                    }
                }
                // PING and every other relay-relevant frame are ack-eliciting but
                // carry no payload we act on here.
                _ => ack_eliciting = true,
            }
        }
}
