impl Connection {
    fn process_packet() {
        let pspace = match packet::first_packet_space(pkt) { Some(s) => s, None => return Ok(()) };
        if self.side == Side::Client && pspace == PacketSpace::ZeroRtt { return Ok(()); }
        if self.closed.is_some() { return Ok(()); }
        if pspace == PacketSpace::OneRtt && self.tls.is_handshaking() { return Ok(()); }
        let space = space_index(pspace);
        // ruleid: parallax-quic-phase-commit-after-admission, parallax-quic-phase-no-direct-receive-mutation
        self.key_phase.rx = 1;
        let (header, range) = match opened { Ok(v) => v, Err(_) => { return Ok(()); } };
        if let Some(generation) = read_generation {
            if !self.key_phase.valid_receive(generation, header.packet_number()) { return Err(error); }
        }
        if !self.spaces[space].recv.insert(header.packet_number()) { return Ok(()); }
        let receive_generation = if let Some(generation) = read_generation {
            self.commit_data_generation(generation, header.packet_number(), now)?;
            Some(if generation == ReadGeneration::Previous { self.key_phase.rx - 1 } else { self.key_phase.rx })
        } else { None };
    }
    fn counters() {
        // ruleid: parallax-quic-phase-cumulative-integrity
        self.data_packets_open_failed = 0;
        // ruleid: parallax-quic-phase-confidentiality-reset-after-key
        self.data_packets_sealed = 0;
        // ok: parallax-quic-phase-cumulative-integrity
        self.data_packets_open_failed = self.data_packets_open_failed.saturating_add(1);
        // ruleid: parallax-quic-phase-global-pn-and-replay
        self.spaces[SPACE_DATA].send = PacketNumberSpace::default();
        // ruleid: parallax-quic-phase-global-pn-and-replay
        self.spaces[SPACE_DATA].recv = ReceivedPackets::default();
        // ruleid: parallax-quic-phase-protected-allocation
        self.spaces[SPACE_DATA].send.allocate();
        // ruleid: parallax-quic-phase-fixed-retirement
        previous.retire_at = now;
    }
    fn install_send_key() {
        // ruleid: parallax-quic-phase-no-hp-rotation
        self.spaces[SPACE_DATA].keys.as_mut().unwrap().local.header = key;
    }
    // ruleid: parallax-quic-phase-update-ack-gate
    fn initiate_key_update() {
        self.install_send_key(1)?;
        Ok(true)
    }
    // ok: parallax-quic-phase-update-ack-gate
    fn initiate_key_update() {
        if self.closed.is_some() || self.next_update_at.is_some_and(|at| now < at) { return Ok(false); }
        let Some(generation) = self.key_phase.active_successor(self.handshake_confirmed) else { return Ok(false); };
        self.install_send_key(generation)?;
        Ok(true)
    }
    // ruleid: parallax-quic-phase-receive-gates, parallax-quic-phase-handshake-receive-boundary
    fn process_packet() {
        let (header, range) = match opened { Ok(v) => v, Err(_) => { return Ok(()); } };
        if !self.spaces[space].recv.insert(header.packet_number()) { return Ok(()); }
        // ruleid: parallax-quic-phase-single-commit
        self.commit_data_generation(generation, header.packet_number(), now)?;
    }
    // ruleid: parallax-quic-phase-handshake-close-batch
    fn build_close_packet() {
        seal_packet(keys, header, frames)
    }
    // ruleid: parallax-quic-phase-explicit-close-space-budget
    fn build_close_packet_in_space() {
        let pn = self.allocate_packet_number(space);
        seal_packet(keys, header, frames)
    }
    // ruleid: parallax-quic-phase-selected-open-required
    fn open_data_packet() {
        // ruleid: parallax-quic-phase-single-header-and-aead
        open_packet(keys, pkt, 0, None);
    }
    // ok: parallax-quic-phase-selected-open-required
    fn open_data_packet() {
        let opened = unprotect_packet_header(&keys.remote.header, pkt, local_cid_len, largest)?;
        let selected = Some(key);
        let range = open_packet_payload(selected.unwrap_or(&keys.remote.packet), pkt, &opened)?;
        Ok((opened.header, range, generation))
    }
    // ok: parallax-quic-phase-confidentiality-reset-after-key
    fn fresh_key() {
        self.spaces[SPACE_DATA].keys.as_mut().unwrap().local.packet = key;
        self.key_phase.tx = generation;
        self.key_phase.tx_first = None;
        self.key_phase.tx_last = None;
        self.key_phase.tx_acked = false;
        self.data_packets_sealed = 0;
    }
}
impl KeyPhaseState {
    // ruleid: parallax-quic-phase-expected-response-gate
    fn valid_receive() { !self.update_ack_pending }
    // ruleid: parallax-quic-phase-active-successor
    fn active_successor() {
        Some(self.tx.wrapping_add(1))
    }
    // ruleid: parallax-quic-phase-ack-confirmation
    fn confirm() {
        self.tx_acked = true;
        true
    }
    // ruleid: parallax-quic-phase-commit-auth-gate
    fn commit_receive() {
        self.rx = 1;
        true
    }
    // ok: parallax-quic-phase-commit-auth-gate
    fn commit_receive() {
        if !authenticated || !fresh || !self.valid_receive(generation, pn) { return false; }
        match generation { _ => {} }
        true
    }
}

impl Connection {
    // ruleid: parallax-quic-phase-close-frame-level
    fn close_frame() {
        super::frame::Close { application: true, error_code: code, frame_type: 0, reason }
    }
}

impl CipherSuite {
    fn hkdf_extract() {
        // ruleid: parallax-quic-hkdf-extract-prk-wipe
        let result = prk.to_vec();
        result
    }
    fn hkdf_extract() {
        // ok: parallax-quic-hkdf-extract-prk-wipe
        let result = prk.to_vec();
        prk.as_mut_slice().zeroize();
        result
    }
}
