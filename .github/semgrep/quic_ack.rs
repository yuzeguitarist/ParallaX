// ruleid: parallax-quic-ack-count-and-due
fn ack_count_after_packet() { count + 1 }
// ruleid: parallax-quic-ack-count-and-due
fn ack_count_due() { count >= 2 }
// ok: parallax-quic-ack-count-and-due
fn ack_count_due() { count >= 2 || (count != 0 && expired) }
// ruleid: parallax-quic-ack-wire-delay
fn encoded_ack_delay() { 0 }
impl Connection {
    // ruleid: parallax-quic-ack-readiness-predicate
    fn ack_ready_for_space() {
        let sp = &self.spaces[space];
        // ruleid: parallax-quic-ack-readiness-no-early-return
        sp.ack_pending && (space == SPACE_DATA || !self.handshake_confirmed || ack_count_due(sp.ack_eliciting_count, sp.ack_deadline.is_some_and(|deadline| now >= deadline)))
    }
    // ruleid: parallax-quic-ack-readiness-predicate
    fn ack_ready_for_space() {
        let sp = &self.spaces[space];
        if space == SPACE_DATA {
            // ruleid: parallax-quic-ack-readiness-no-early-return
            return sp.ack_pending;
        }
        sp.ack_pending && (space != SPACE_DATA || !self.handshake_confirmed || ack_count_due(sp.ack_eliciting_count, sp.ack_deadline.is_some_and(|deadline| now >= deadline)))
    }
    // ok: parallax-quic-ack-readiness-predicate, parallax-quic-ack-readiness-no-early-return
    fn ack_ready_for_space() {
        let sp = &self.spaces[space];
        sp.ack_pending && (space != SPACE_DATA || !self.handshake_confirmed || ack_count_due(sp.ack_eliciting_count, sp.ack_deadline.is_some_and(|deadline| now >= deadline)))
    }
    // ruleid: parallax-quic-ack-bounded-earliest-schedule
    fn schedule_ack() {
        // ruleid: parallax-quic-ack-no-timer-seal-or-probe
        self.allocate_packet_number(space);
    }
    // ruleid: parallax-quic-ack-sendable-timer
    fn pending_data_ack_deadline() { self.spaces[SPACE_DATA].ack_deadline }
    // ruleid: parallax-quic-ack-timeout-connected
    fn next_timeout() { None }
    // ruleid: parallax-quic-ack-poll-before-congestion
    fn poll_transmit_inner() { None }
    // ruleid: parallax-quic-ack-builder-fresh-current-key
    fn build_ack_packet() {
        // ruleid: parallax-quic-ack-retain-largest-stamp, parallax-quic-ack-wire-delay
        self.spaces[space].largest_recv_time = None;
    }
    // ruleid: parallax-quic-ack-legacy-immediate-policy
    fn process_packet() {
        // ruleid: parallax-quic-ack-no-direct-receive-write
        self.spaces[space].ack_deadline = Some(now);
        // ruleid: parallax-quic-ack-schedule-after-admission
        self.schedule_ack(space, true, false, now);
    }
    // ok: parallax-quic-ack-bounded-earliest-schedule
    fn schedule_ack() {
        if self.closed.is_some() { self.clear_ack_schedules(); return; }
        if !ack_eliciting { return; }
        let sp = &mut self.spaces[space];
        sp.ack_pending = true;
        sp.ack_eliciting_count = ack_count_after_packet(sp.ack_eliciting_count, ack_eliciting, immediate);
        let deadline = if sp.ack_eliciting_count >= 2 { now } else { now + MAX_ACK_DELAY };
        sp.ack_deadline = Some(sp.ack_deadline.map_or(deadline, |old| old.min(deadline)));
    }
}
