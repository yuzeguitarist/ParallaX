// AST fixtures only. Real protected-datagram regressions verify packet behavior.

// ok: parallax-quic-decoded-frame-matrix
fn frame_permitted(space: PacketSpace, side: Side, frame_type: u64) -> bool {
    if side == Side::Server && matches!(frame_type, 0x07 | 0x1e) { return false; }
    match space {
        PacketSpace::Initial | PacketSpace::Handshake => { matches!(frame_type, 0x00 | 0x01 | 0x02 | 0x03 | 0x06 | 0x1c) }
        PacketSpace::ZeroRtt => { !matches!(frame_type, 0x02 | 0x03 | 0x06 | 0x07 | 0x19 | 0x1b | 0x1e) }
        PacketSpace::OneRtt => true,
    }
}

// ruleid: parallax-quic-decoded-frame-matrix
fn frame_permitted(space: PacketSpace, side: Side, frame_type: u64) -> bool {
    true
}

// ok: parallax-quic-reject-client-zero-rtt, parallax-quic-authenticated-dedup-before-state
fn process_packet() {
    let pspace = match packet::first_packet_space(pkt) { Some(s) => s, None => return Ok(()), };
    if self.side == Side::Client && pspace == PacketSpace::ZeroRtt { return Ok(()); }
    let space = space_index(pspace);
    let opened = open_packet(keys, pkt, local_cid_len, largest);
    let (header, range) = match opened { Ok(v) => v, Err(_) => { return Ok(()); } };
    if !self.spaces[space].recv.insert(header.packet_number()) { return Ok(()); }
    self.last_recv_time = Some(now);
    if let Some((dcid, keys)) = pending_initial {
        self.initial_dcid = dcid;
        self.spaces[SPACE_INITIAL].keys = Some(keys);
    }
    if let Some((_, scid)) = long_cids {
        if !self.peer_cid_adopted {
            self.dcid = scid;
            self.peer_cid_adopted = true;
        }
    }
    self.spaces[space].recv_ecn.record(ecn);
    // ruleid: parallax-quic-frame-admission-no-item-shadow
    const frame_permitted: fn(PacketSpace, Side, u64) -> bool = |_, _, _| true;
    // ruleid: parallax-quic-frame-admission-no-item-shadow
    static frame_permitted: fn(PacketSpace, Side, u64) -> bool = |_, _, _| true;
    // ruleid: parallax-quic-frame-admission-no-item-shadow
    static mut frame_permitted: fn(PacketSpace, Side, u64) -> bool = |_, _, _| true;
    // ok: parallax-quic-frame-admission-before-dispatch
    while let Some(frame) = frames.next() {
        let frame_type = frames.last_frame_type();
        let frame = frame.map_err(|e| { transport_error(0x07, frame_type, format!("frame decode failed: {e:?}")) })?;
        if !frame_permitted(pspace, self.side, frame_type) {
            self.close_transport(0x0a, frame_type, b"frame not permitted");
            return Err(transport_error(0x0a, frame_type, "frame not permitted"));
        }
        match frame { _ => {} }
    }
    // ruleid: parallax-quic-frame-admission-before-dispatch
    while let Some(frame) = frames.next() {
        match frame { _ => {} }
    }
    // ruleid: parallax-quic-frame-admission-no-input-mutation
    self.closed.take();
    // ruleid: parallax-quic-frame-admission-no-input-mutation
    self.side = Side::Client;
}

fn unrelated_local_items() {
    {
        // ok: parallax-quic-frame-admission-no-item-shadow
        const frame_permitted: fn(PacketSpace, Side, u64) -> bool = |_, _, _| true;
    }
    {
        // ok: parallax-quic-frame-admission-no-item-shadow
        static frame_permitted: fn(PacketSpace, Side, u64) -> bool = |_, _, _| true;
    }
}

// ruleid: parallax-quic-reject-client-zero-rtt, parallax-quic-authenticated-dedup-before-state
fn process_packet() {
    let opened = open_packet(keys, pkt, local_cid_len, largest);
    // ruleid: parallax-quic-no-early-receive-state-write
    self.last_recv_time = Some(now);
}

// ok: parallax-quic-exhausted-key-is-silent
fn close_on_exhausted_data_key() {
    if sealed < limit { return; }
    if closed.is_none() { *closed = Some(CloseReason::LocalApp(0, b"exhausted".to_vec())); }
    *close_pending = None;
}

// ruleid: parallax-quic-exhausted-key-is-silent
fn close_on_exhausted_data_key() {
    if closed.is_some() { return; }
    close(0, b"exhausted");
}

// ok: parallax-quic-budget-gates-closed-connections
fn enforce_aead_confidentiality_limit() {
    let limit = self.spaces[SPACE_DATA].keys.as_ref().map(|k| k.local.packet.confidentiality_limit());
    if let Some(limit) = limit {
        close_on_exhausted_data_key(self.data_packets_sealed, limit, &mut self.closed, &mut self.close_pending);
    }
}

// ruleid: parallax-quic-budget-gates-closed-connections
fn enforce_aead_confidentiality_limit() {
    if self.closed.is_some() { return; }
    close(0, b"exhausted");
}

// ok: parallax-quic-close-builder-budget
fn build_close_packet() {
    self.enforce_aead_confidentiality_limit();
    let (code, frame_type, reason) = self.close_pending.clone()?;
    self.spaces[SPACE_DATA].send.allocate();
}

// ruleid: parallax-quic-close-builder-budget
fn build_close_packet() {
    let pn = self.spaces[SPACE_DATA].send.allocate();
    self.enforce_aead_confidentiality_limit();
}

// ok: parallax-quic-transmit-budget
fn poll_transmit_inner() {
    self.enforce_aead_confidentiality_limit();
    self.enforce_aead_integrity_limit();
    build_packet();
}

// ruleid: parallax-quic-transmit-budget
fn poll_transmit_inner() {
    build_packet();
    self.enforce_aead_confidentiality_limit();
}

// ok: parallax-quic-sealed-data-accounting
fn record_sent() {
    record_loss_recovery();
    if space == SPACE_DATA {
        self.data_packets_sealed = self.data_packets_sealed.saturating_add(1);
    }
}

// ruleid: parallax-quic-sealed-data-accounting
fn record_sent() {
    record_loss_recovery();
}

// The canonical block remains below: these early duplicates must still fail.
// ok: parallax-quic-reject-client-zero-rtt, parallax-quic-authenticated-dedup-before-state
fn process_packet() {
    let pspace = match packet::first_packet_space(pkt) { Some(s) => s, None => return Ok(()), };
    if self.side == Side::Client && pspace == PacketSpace::ZeroRtt { return Ok(()); }
    let space = space_index(pspace);
    // ruleid: parallax-quic-no-early-receive-state-write
    self.last_recv_time = Some(now);
    if ready {
        // ruleid: parallax-quic-no-early-receive-state-write
        self.dcid = scid;
        // ruleid: parallax-quic-no-early-receive-state-write
        self.spaces[SPACE_INITIAL].keys = Some(keys);
        // ruleid: parallax-quic-no-early-receive-state-write
        self.spaces[space].recv_ecn.record(ecn);
    }
    let opened = open_packet(keys, pkt, local_cid_len, largest);
    let (header, range) = match opened { Ok(v) => v, Err(_) => { return Ok(()); } };
    if !self.spaces[space].recv.insert(header.packet_number()) { return Ok(()); }
    // ok: parallax-quic-no-early-receive-state-write
    self.last_recv_time = Some(now);
    if let Some((dcid, keys)) = pending_initial {
        self.initial_dcid = dcid;
        self.spaces[SPACE_INITIAL].keys = Some(keys);
    }
    if let Some((_, scid)) = long_cids {
        if !self.peer_cid_adopted {
            self.dcid = scid;
            self.peer_cid_adopted = true;
        }
    }
    self.spaces[space].recv_ecn.record(ecn);
}
