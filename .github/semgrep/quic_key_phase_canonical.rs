// Reviewed complete AST scopes. Syntactic regression pin, not a CFG proof.
    fn build_close_packet(&mut self, now: Instant) -> Option<Vec<u8>> {
        self.enforce_aead_confidentiality_limit();
        self.enforce_aead_integrity_limit();
        let (code, frame_type, reason) = self.close_pending.clone()?;
        let available =
            |space: usize| !self.spaces[space].discarded && self.spaces[space].keys.is_some();
        let mut spaces = if !self.handshake_confirmed {
            let mut spaces = Vec::new();
            if self.side == Side::Server && available(SPACE_INITIAL) {
                spaces.push(SPACE_INITIAL);
            }
            if available(SPACE_HANDSHAKE) {
                spaces.push(SPACE_HANDSHAKE);
            }
            spaces
        } else {
            Vec::new()
        };
        let mandatory = spaces.len().max(1);
        if available(SPACE_DATA) {
            spaces.push(SPACE_DATA);
        } else if spaces.is_empty() && !self.handshake_confirmed && available(SPACE_INITIAL) {
            spaces.push(SPACE_INITIAL);
        }
        if spaces.is_empty() {
            return None;
        }
        // Preflight the entire batch before any PN advances or AEAD seals. A
        // lower-level close must not bypass an exhausted Application key.
        if spaces
            .iter()
            .any(|&space| !self.spaces[space].send.can_allocate())
        {
            self.close_pending = None;
            return None;
        }
        let mtu = self.pmtud.current_mtu();
        let batch_size = |spaces: &[usize], reason: &[u8]| {
            spaces.iter().try_fold(0usize, |total, &space| {
                total.checked_add(self.close_packet_size(space, code, frame_type, reason))
            })
        };
        let mut size = batch_size(&spaces, &reason)?;
        if size > mtu && spaces.len() > mandatory {
            spaces.truncate(mandatory);
            size = batch_size(&spaces, &reason)?;
        }
        // Optional Data is already removed. Shorten only the wire reason when
        // necessary to retain BOTH mandatory server levels; keep the local
        // CloseReason unchanged. The final sealer reads this same pending tuple.
        let shorten_reason = size > mtu
            && frame_type.is_some()
            && spaces.as_slice() == [SPACE_INITIAL, SPACE_HANDSHAKE];
        if shorten_reason {
            size = batch_size(&spaces, &[])?;
        }
        if size > mtu {
            self.close_pending = None;
            return None;
        }
        if !self.peer_addr_validated
            && self.anti_amp_sent.saturating_add(size as u64) > self.anti_amp_recv.saturating_mul(3)
        {
            return None;
        }
        if shorten_reason {
            self.close_pending.as_mut()?.2.clear();
        }
        let mut datagram = Vec::new();
        for space in spaces {
            datagram.extend(self.build_close_packet_in_space(space, now)?);
        }
        self.close_sent = true;
        Some(datagram)
    }

    fn close_packet_size(
        &self,
        space: usize,
        code: u64,
        frame_type: Option<u64>,
        reason: &[u8],
    ) -> usize {
        let pn = self.spaces[space].send.peek();
        let (_, pn_len) = packet::encode_packet_number(pn, None);
        let header = self.make_header(space, pn, pn_len);
        let close = Self::close_frame(space, code, frame_type, reason);
        if close.reason.len() > self.pmtud.current_mtu() {
            return self.pmtud.current_mtu().saturating_add(1);
        }
        let mut encoded = Vec::new();
        header.encode(&mut encoded);
        Frame::Close(close).encode(&mut encoded);
        encoded
            .len()
            .checked_add(3)
            .and_then(|size| {
                size.checked_add(
                    self.spaces[space]
                        .keys
                        .as_ref()
                        .unwrap()
                        .local
                        .packet
                        .tag_len(),
                )
            })
            .unwrap_or(usize::MAX)
    }

    fn build_close_packet_in_space(&mut self, space: usize, now: Instant) -> Option<Vec<u8>> {
        self.enforce_aead_confidentiality_limit();
        self.enforce_aead_integrity_limit();
        let (code, frame_type, reason) = self.close_pending.clone()?;
        if self.spaces[space].discarded
            || self.spaces[space].keys.is_none()
            || (self.handshake_confirmed && space != SPACE_DATA)
            || !self.spaces[space].send.can_allocate()
            || self.close_packet_size(space, code, frame_type, &reason) > self.pmtud.current_mtu()
        {
            self.close_pending = None;
            return None;
        }
        let pn = self.allocate_packet_number(space);
        let (_, pn_len) = packet::encode_packet_number(pn, None);
        let header = self.make_header(space, pn, pn_len);
        let close = Self::close_frame(space, code, frame_type, &reason);
        let datagram = {
            let keys = self.spaces[space].keys.as_ref().unwrap();
            seal_packet(
                &keys.local,
                header,
                &[Frame::Close(close), Frame::Padding(3)],
            )
        };
        // CONNECTION_CLOSE is not ack-eliciting (RFC 9002 §2).
        self.record_sent(
            space,
            pn,
            datagram.len(),
            false,
            SentContent::default(),
            now,
        );
        Some(datagram)
    }
