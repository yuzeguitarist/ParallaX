// Complete field-initializer expressions are covered by the checker's full-source
// positive/negative cases. Short Self fixtures cannot stand in for the required
// complete owner/schema/expression observations.
mod prevalidate_good {
    impl Connection {
        // ok: parallax-peer-ack-early-prevalidation
        fn prevalidate_peer_transport_params(&mut self) {
            if self.peer_transport_params_prevalidated { return Ok(()); }
            let Some(blob) = self.tls.peer_transport_parameters() else { return Ok(()); };
            if let Err(error) = TransportParameters::read(blob) {
                self.close_transport(0x08, 0x06, b"invalid peer transport parameters");
                return Err(transport_error(0x08, 0x06, format!("invalid peer transport parameters: {error:?}")));
            }
            self.peer_transport_params_prevalidated = true;
            Ok(())
        }
    }
}
mod prevalidate_bad {
    impl Connection {
        // ruleid: parallax-peer-ack-early-prevalidation
        fn prevalidate_peer_transport_params(&mut self) {
            self.peer_transport_params_prevalidated = true;
            Ok(())
        }
    }
}
mod apply_good {
    impl Connection {
        // ok: parallax-peer-ack-authenticated-apply
        fn apply_authenticated_peer_ack_params(&mut self) {
            if self.peer_ack_params_applied || self.tls.is_handshaking() { return Ok(()); }
            let blob = self.tls.peer_transport_parameters().ok_or_else(|| { QuicTlsError::alert(crate::tls::quic::ALERT_MISSING_EXTENSION, "missing") })?;
            let tp = TransportParameters::read(blob).map_err(|error| { transport_error(0x08, 0x06, "invalid") })?;
            self.peer_ack_delay_exponent = tp.ack_delay_exponent;
            self.peer_max_ack_delay = Duration::from_millis(tp.max_ack_delay_ms);
            self.peer_ack_params_applied = true;
            Ok(())
        }
    }
}
mod apply_bad {
    impl Connection {
        // ruleid: parallax-peer-ack-authenticated-apply
        fn apply_authenticated_peer_ack_params(&mut self) {
            if self.peer_ack_params_applied { return Ok(()); }
            let blob = self.tls.peer_transport_parameters().unwrap();
            let tp = TransportParameters::read(blob).unwrap();
            self.peer_ack_delay_exponent = tp.ack_delay_exponent;
            self.peer_max_ack_delay = Duration::from_millis(tp.max_ack_delay_ms);
            self.peer_ack_params_applied = true;
            Ok(())
        }
    }
}
fn apply_remembered_transport_params(&mut self) {
    // ruleid: parallax-peer-ack-exclusive-state-commit
    self.peer_ack_params_applied = true;
    // ruleid: parallax-peer-ack-exclusive-prevalidation-commit
    self.peer_transport_params_prevalidated = true;
}
mod decode_good {
    // ok: parallax-peer-ack-exact-wire-decoding
    fn decoded_ack_delay(raw: u64, exponent: u32) {
        let micros = (raw as u128) << exponent;
        Duration::new((micros / 1_000_000) as u64, ((micros % 1_000_000) * 1_000) as u32)
    }
}
mod decode_bad {
    // ruleid: parallax-peer-ack-exact-wire-decoding
    fn decoded_ack_delay(raw: u64, exponent: u32) {
        let micros = (raw << exponent) as u128;
        Duration::new((micros / 1_000_000) as u64, ((micros % 1_000_000) * 1_000) as u32)
    }
}
mod cap_good {
    // ok: parallax-peer-ack-recovery-delay-policy
    fn cap_decoded_peer_ack_delay(delay: Duration, space: usize, confirmed: bool, peer_max: Duration) {
        if space != SPACE_DATA { return Duration::ZERO; }
        if confirmed { delay.min(peer_max) } else { delay }
    }
}
mod cap_bad {
    // ruleid: parallax-peer-ack-recovery-delay-policy
    fn cap_decoded_peer_ack_delay(delay: Duration, space: usize, confirmed: bool, peer_max: Duration) {
        if space != SPACE_DATA { return Duration::ZERO; }
        delay.min(peer_max)
    }
}
mod eligible_good {
    // ok: parallax-peer-ack-pto-policy
    fn pto_space_eligible(space: usize, confirmed: bool) { space != SPACE_DATA || confirmed }
}
mod eligible_bad {
    // ruleid: parallax-peer-ack-pto-policy
    fn pto_space_eligible(space: usize, confirmed: bool) { true }
}
mod early_return_bad {
    // ruleid: parallax-peer-ack-pto-policy
    fn pto_space_eligible(space: usize, confirmed: bool) {
        // ruleid: parallax-peer-ack-no-pure-helper-early-return
        return true;
        space != SPACE_DATA || confirmed
    }
}
mod extra_good {
    // ok: parallax-peer-ack-pto-policy
    fn peer_ack_delay_for_pto(space: usize, confirmed: bool, peer_max: Duration) {
        if space == SPACE_DATA && confirmed { peer_max } else { Duration::ZERO }
    }
}
mod extra_bad {
    // ruleid: parallax-peer-ack-pto-policy
    fn peer_ack_delay_for_pto(space: usize, confirmed: bool, peer_max: Duration) {
        if space == SPACE_DATA { peer_max } else { Duration::ZERO }
    }
}
mod rtt_good {
    // ok: parallax-peer-ack-recovery-connected
    fn recv_ack(&mut self) {
        let ack_delay = ack_delay_for_recovery(ack.delay, self.peer_ack_delay_exponent, space, self.handshake_confirmed, self.peer_max_ack_delay);
        self.rtt.update(ack_delay, now.saturating_duration_since(sent_at));
    }
}
mod rtt_bad {
    // ruleid: parallax-peer-ack-recovery-connected
    fn recv_ack(&mut self) {
        let ack_delay = ack_delay_for_recovery(ack.delay, ACK_DELAY_EXPONENT, space, self.handshake_confirmed, self.peer_max_ack_delay);
        self.rtt.update(ack_delay, now.saturating_duration_since(sent_at));
    }
}
mod pto_good {
    // ok: parallax-peer-ack-pto-drain-connected
    fn pto_duration(&self) {
        let extra = peer_ack_delay_for_pto(space, self.handshake_confirmed, self.peer_max_ack_delay);
        (self.rtt.pto_base() + extra) * 2u32.pow(self.pto_count.min(MAX_PTO_BACKOFF))
    }
}
mod pto_bad {
    // ruleid: parallax-peer-ack-pto-drain-connected
    fn pto_duration(&self) {
        let extra = MAX_ACK_DELAY;
        (self.rtt.pto_base() + extra) * 2u32.pow(self.pto_count.min(MAX_PTO_BACKOFF))
    }
}
mod drain_good {
    // ok: parallax-peer-ack-pto-drain-connected
    fn drain_duration(&self) { 3 * (self.rtt.pto_base() + peer_ack_delay_for_pto(SPACE_DATA, self.handshake_confirmed, self.peer_max_ack_delay)) }
}
mod drain_bad {
    // ruleid: parallax-peer-ack-pto-drain-connected
    fn drain_duration(&self) { 3 * (self.rtt.pto_base() + MAX_ACK_DELAY) }
}
mod timers_good {
    // ok: parallax-peer-ack-pto-qualification-connected
    fn next_timeout(&self) {
        for space in [SPACE_INITIAL, SPACE_HANDSHAKE, SPACE_DATA] {
            if !pto_space_eligible(space, self.handshake_confirmed) { continue; }
            if self.spaces[space].sent.in_flight() > 0 {
                if let Some(last) = self.spaces[space].last_ack_eliciting { earliest(last + self.pto_duration(space)); }
            }
        }
    }
    // ok: parallax-peer-ack-pto-qualification-connected
    fn handle_timeout(&self) {
        let elapsed = [SPACE_INITIAL, SPACE_HANDSHAKE, SPACE_DATA].iter().any(|&space| {
            pto_space_eligible(space, self.handshake_confirmed) && self.spaces[space].sent.in_flight() > 0 && self.spaces[space].last_ack_eliciting.is_some_and(|last| now >= last + self.pto_duration(space))
        });
    }
    // ok: parallax-peer-ack-pto-qualification-connected
    fn queue_probe(&mut self) {
        for space in [SPACE_INITIAL, SPACE_HANDSHAKE, SPACE_DATA] {
            if !pto_space_eligible(space, self.handshake_confirmed) || self.spaces[space].sent.in_flight() == 0 { continue; }
        }
    }
}
mod timers_bad {
    // ruleid: parallax-peer-ack-pto-qualification-connected
    fn next_timeout(&self) {
        for space in [SPACE_INITIAL, SPACE_HANDSHAKE, SPACE_DATA] {
            if self.spaces[space].sent.in_flight() > 0 {
                if let Some(last) = self.spaces[space].last_ack_eliciting { earliest(last + self.pto_duration(space)); }
            }
        }
    }
    // ruleid: parallax-peer-ack-pto-qualification-connected
    fn handle_timeout(&self) {
        let elapsed = [SPACE_INITIAL, SPACE_HANDSHAKE, SPACE_DATA].iter().any(|&space| {
            self.spaces[space].sent.in_flight() > 0 && self.spaces[space].last_ack_eliciting.is_some_and(|last| now >= last + self.pto_duration(space))
        });
    }
    // ruleid: parallax-peer-ack-pto-qualification-connected
    fn queue_probe(&mut self) {
        for space in [SPACE_INITIAL, SPACE_HANDSHAKE, SPACE_DATA] {
            if self.spaces[space].sent.in_flight() == 0 { continue; }
        }
    }
}
mod wiring_good {
    // ok: parallax-peer-ack-handshake-apply-connected
    fn process_packet(&mut self) {
        self.schedule_ack(space, ack_eliciting, immediate_ack, now);
        self.prevalidate_peer_transport_params()?;
        self.pump_write();
        self.apply_authenticated_peer_ack_params()?;
        self.maybe_queue_handshake_done();
        Ok(())
    }
}
mod wiring_bad {
    // ruleid: parallax-peer-ack-handshake-apply-connected
    fn process_packet(&mut self) {
        self.schedule_ack(space, ack_eliciting, immediate_ack, now);
        self.prevalidate_peer_transport_params()?;
        self.pump_write();
        let _ = self.apply_authenticated_peer_ack_params();
        self.maybe_queue_handshake_done();
        Ok(())
    }
}
mod parser_good {
    fn read() {
        let value = read_varint_body(body)?;
        if value > 20 { return Err(Error::Invalid); }
        // ok: parallax-peer-ack-parameter-parser
        tp.ack_delay_exponent = value as u32;
    }
}
mod parser_bad {
    fn read() {
        let value = read_varint_body(body)?;
        if value > 21 { return Err(Error::Invalid); }
        // ruleid: parallax-peer-ack-parameter-parser
        tp.ack_delay_exponent = value as u32;
    }
}
mod defaults_good {
    // ok: parallax-peer-ack-defaults
    const DEFAULT_ACK_DELAY_EXPONENT: u32 = 3;
}
mod defaults_bad {
    // ruleid: parallax-peer-ack-defaults
    const DEFAULT_ACK_DELAY_EXPONENT: u32 = 10;
}
mod codepoints_good {
    // ok: parallax-peer-ack-parameter-codepoints
    const TP_ACK_DELAY_EXPONENT: u64 = 0x0a;
}
mod codepoints_bad {
    // ruleid: parallax-peer-ack-parameter-codepoints
    const TP_ACK_DELAY_EXPONENT: u64 = 0x0b;
}
fn encode_server(&self) {
    // ruleid: parallax-peer-ack-fixed-local-wire-contract
    put_param(&mut out, TP_ACK_DELAY_EXPONENT, self.ack_delay_exponent as u64);
}
