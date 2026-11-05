// AST-only fragments. They deliberately mix valid canonical sequences and
// extra effects: a surrounding correct block must not excuse those effects.

fn block_on_current_or_fresh(fut: F) -> Result<T> {
    // ok: parallax-mux-benchmark-timer-driver
    tokio::runtime::Builder::new_current_thread().enable_time().build()?.block_on(fut)
}

fn block_on_current_or_fresh(fut: F) -> Result<T> {
    // ruleid: parallax-mux-benchmark-timer-driver
    tokio::runtime::Builder::new_current_thread().build()?.block_on(fut)
}

fn block_on_current_or_fresh(fut: F) -> Result<T> {
    if condition {
        // ruleid: parallax-mux-benchmark-timer-driver
        let _other = tokio::runtime::Builder::new_current_thread().build()?;
    }
    // ok: parallax-mux-benchmark-timer-driver
    tokio::runtime::Builder::new_current_thread().enable_time().build()?.block_on(fut)
}

// ok: parallax-mux-record-window-constants
const SERVER_MUX_FRAME_BATCH_LIMIT: usize = 64;
// ok: parallax-mux-record-window-constants
const SERVER_MUX_FAIR_BATCH_BYTES: usize = 64 * 1024;
// ruleid: parallax-mux-record-window-constants
const SERVER_MUX_FRAME_BATCH_LIMIT: usize = 128;
// ruleid: parallax-mux-record-window-constants
const SERVER_MUX_FAIR_BATCH_BYTES: usize = 1024 * 1024;

// ok: parallax-mux-profile-default-off
impl Default for TcpMuxRecordProfile { fn default() -> Self { Self::Off } }
// ruleid: parallax-mux-profile-default-off
impl Default for TcpMuxRecordProfile { fn default() -> Self { Self::CloudflareDynamic } }
// ok: parallax-mux-profile-default-off
impl Default for TrafficConfig {
    fn default() -> Self { Self { tcp_mux_record_profile: TcpMuxRecordProfile::Off } }
}
impl Default for TrafficConfig {
    // ruleid: parallax-mux-profile-default-off
    fn default() -> Self { Self { tcp_mux_record_profile: TcpMuxRecordProfile::CloudflareDynamic } }
}

impl Config {
    // ok: parallax-mux-profile-server-mode
    fn validate_structure(&self) -> Result<(), Error> {
        self.traffic.validate()?;
        self.udp.validate()?;
        if self.traffic.tcp_mux_record_profile != TcpMuxRecordProfile::Off && self.mode != Mode::Server {
            return Err(ConfigError::InvalidTcpMuxRecordProfile("server only"));
        }
        Ok(())
    }
    // ruleid: parallax-mux-profile-server-mode
    fn validate_structure(&self) -> Result<(), Error> { Ok(()) }
}
impl TrafficConfig {
    // ok: parallax-mux-profile-traffic-compatibility
    fn validate(&self) -> Result<(), Error> {
        if self.tcp_mux_record_profile != TcpMuxRecordProfile::Off {
            if self.max_concurrent_streams <= 1 { return Err(ConfigError::InvalidTcpMuxRecordProfile("mux required")); }
            if self.min_padding != 0 || self.max_padding != 0 || self.min_delay_ms != 0 || self.max_delay_ms != 0 || self.cover_min_interval_ms != 0 || self.cover_max_interval_ms != 0 {
                return Err(ConfigError::InvalidTcpMuxRecordProfile("zero shaping required"));
            }
        }
        Ok(())
    }
    // ruleid: parallax-mux-profile-traffic-compatibility
    fn validate(&self) -> Result<(), Error> { Ok(()) }
}

impl MuxRecordBudget {
    // ok: parallax-mux-record-profile-budgets
    fn plaintext_limit(self, codec_max: usize) -> usize {
        const CODEC_OVERHEAD: usize = 18;
        match self.profile {
            TcpMuxRecordProfile::Off => codec_max,
            TcpMuxRecordProfile::CloudflareDynamic if self.records_sent > 80 => codec_max,
            TcpMuxRecordProfile::CloudflareDynamic if self.records_sent > 40 => { codec_max.min(4246 - CODEC_OVERHEAD) }
            TcpMuxRecordProfile::CloudflareDynamic => codec_max.min(1386 - CODEC_OVERHEAD),
        }
    }
    // ruleid: parallax-mux-record-profile-budgets
    fn plaintext_limit(self, codec_max: usize) -> usize { usize::MAX }
    // ok: parallax-mux-record-idle-reset
    fn for_write(self, now: Instant) -> Self {
        let mut next = self;
        if next.profile == TcpMuxRecordProfile::CloudflareDynamic && next.last_write.is_some_and(|last| now.duration_since(last) > Duration::from_millis(1000)) {
            next.records_sent = 0;
        }
        next
    }
    // ruleid: parallax-mux-record-idle-reset
    fn for_write(self, now: Instant) -> Self { self }
}
// ok: parallax-mux-record-piece-capacity
fn mux_record_data_piece_len(remaining: usize, capacity: usize) -> usize {
    if remaining <= capacity { remaining }
    else if remaining - capacity <= capacity / 2 { remaining.div_ceil(2) }
    else { capacity }
}
// ruleid: parallax-mux-record-piece-capacity
fn mux_record_data_piece_len(remaining: usize, capacity: usize) -> usize { remaining }
impl MuxFrameCursor {
    // ok: parallax-mux-record-cursor-progress
    fn advance(&mut self, payload_len: usize, take: usize) {
        self.offset += take;
        if self.offset == payload_len { self.frame += 1; self.offset = 0; }
    }
    // ruleid: parallax-mux-record-cursor-progress
    fn advance(&mut self, payload_len: usize, take: usize) { self.frame += 2; }
}
// ok: parallax-mux-record-run-barriers
fn ready_mux_data_run(frames: &[MuxFrame], cursor: MuxFrameCursor) -> Result<(usize, usize), Error> {
    let stream_id = frames[cursor.frame].stream_id;
    let mut end = cursor.frame;
    let mut bytes = 0usize;
    while let Some(frame) = frames.get(end) {
        if frame.kind != MuxFrameKind::Data || frame.stream_id != stream_id { break; }
        let offset = if end == cursor.frame { cursor.offset } else { 0 };
        bytes = bytes.checked_add(frame.payload.len() - offset).ok_or(MuxFrameError::PayloadTooLong)?;
        end += 1;
    }
    Ok((end, bytes))
}
// ruleid: parallax-mux-record-run-barriers
fn ready_mux_data_run(frames: &[MuxFrame], cursor: MuxFrameCursor) -> Result<(usize, usize), Error> { Ok((frames.len(), 123)) }

// ok: parallax-mux-record-output-window, parallax-mux-record-padded-wire-window
fn plan_ready_mux_records() {
    scratch.plaintext_buf.clear();
    scratch.record_lens.clear();
    scratch.exact_pad_lens.clear();
    let mut window_wire_bytes = 0usize;
    let header_len = MuxFrame::encoded_len(0)?;
    while cursor.frame < frames.len() && scratch.record_lens.len() < SERVER_MUX_FRAME_BATCH_LIMIT {
        let limit = budget.plaintext_limit(codec_max);
        if budget.profile == TcpMuxRecordProfile::CloudflareDynamic {
            let (_, maximum_wire_len) = mux_record_padding_plan(budget.profile, true, 1, limit).ok_or_else(|| mux_record_capacity_error(limit))?;
            let next_wire_bound = window_wire_bytes.checked_add(maximum_wire_len).ok_or_else(|| mux_record_capacity_error(usize::MAX))?;
            if next_wire_bound > SERVER_MUX_FAIR_BATCH_BYTES { break; }
        }
        // ruleid: parallax-mux-record-planner-effects
        scratch.plaintext_buf.extend_from_slice(&frame.payload);
        let take = mux_record_data_piece_len(run_bytes, room - header_len);
        // ok: parallax-mux-record-planner-effects
        encode_mux_data_piece(&mut scratch.plaintext_buf, frames, cursor, take)?;
        if take < run_bytes { break; }
        if failed {
            // ruleid: parallax-mux-record-planner-effects
            encode_mux_data_piece(&mut scratch.plaintext_buf, frames, cursor, run_bytes)?;
        }
        let frame_len = MuxFrame::encoded_len(frame.payload.len())?;
        if frame_len > limit { return Err(mux_record_capacity_error(frame_len)); }
        if frame_len > room { break; }
        // ruleid: parallax-mux-record-one-control-encode
        frame.encode_into(&mut scratch.plaintext_buf)?;
        cursor.frame += 1;
        let frame_len = MuxFrame::encoded_len(frame.payload.len())?;
        if frame_len > limit { return Err(mux_record_capacity_error(frame_len)); }
        if frame_len > room { break; }
        // ok: parallax-mux-record-planner-effects
        frame.encode_into(&mut scratch.plaintext_buf)?;
        cursor.frame += 1;
        let len = scratch.plaintext_buf.len() - record_start;
        if len == 0 || len > limit { return Err(mux_record_capacity_error(len)); }
        let (pad, wire_len) = mux_record_padding_plan(budget.profile, has_positive_data, len, limit).ok_or_else(|| mux_record_capacity_error(len))?;
        if budget.profile == TcpMuxRecordProfile::CloudflareDynamic {
            // ok: parallax-mux-record-planner-effects
            window_wire_bytes = window_wire_bytes.checked_add(wire_len).filter(|&bytes| bytes <= SERVER_MUX_FAIR_BATCH_BYTES).ok_or_else(|| mux_record_capacity_error(usize::MAX))?;
            // ok: parallax-mux-record-planner-effects
            scratch.exact_pad_lens.push(pad);
        }
        // ok: parallax-mux-record-planner-effects
        scratch.record_lens.push(len);
        // ok: parallax-mux-record-planner-effects
        budget.records_sent = budget.records_sent.saturating_add(1);
        // ruleid: parallax-mux-record-planner-effects
        scratch.record_lens.push(len);
        if failed {
            // ruleid: parallax-mux-record-planner-effects
            budget.records_sent = budget.records_sent.saturating_add(1);
        }
        // ruleid: parallax-mux-record-planner-effects
        budget.records_sent += 1;
        // ruleid: parallax-mux-record-planner-effects, parallax-mux-record-no-piece-allocation
        scratch.record_lens.append(&mut Vec::from([len]));
    }
    Ok(())
}
// ruleid: parallax-mux-record-output-window, parallax-mux-record-padded-wire-window
fn plan_ready_mux_records() { while cursor.frame < frames.len() { do_something(); } }

fn encode_mux_data_piece() {
    // ruleid: parallax-mux-record-no-piece-allocation
    let copy = frame.payload.to_vec();
    // ruleid: parallax-mux-record-encoder-prefix, parallax-mux-record-one-header-per-piece
    MuxFrame::encode_borrowed_into(stream_id, MuxFrameKind::Data, &frames[cursor.frame].payload, out)?;
    let payload_len = u32::try_from(remaining).map_err(|_| MuxFrameError::PayloadTooLong)?;
    // ok: parallax-mux-record-encoder-prefix
    MuxFrame::encode_borrowed_into(stream_id, MuxFrameKind::Data, &[], out)?;
    let header_end = out.len();
    // ruleid: parallax-mux-record-encoder-prefix
    out.extend_from_slice(input);
    let available = frame.payload.len() - cursor.offset;
    let take = remaining.min(available);
    // ok: parallax-mux-record-encoder-prefix
    out.extend_from_slice(&frame.payload[cursor.offset..cursor.offset + take]);
    remaining -= take;
    // ok: parallax-mux-record-encoder-prefix
    cursor.advance(frame.payload.len(), take);
    if failed {
        // ruleid: parallax-mux-record-encoder-prefix
        out.extend_from_slice(input);
    }
    // ruleid: parallax-mux-record-encoder-prefix, parallax-mux-record-no-piece-allocation
    out.append(&mut Vec::from(input));
}

async fn write_server_mux_frames_planned() {
    // ruleid: parallax-mux-record-successful-write-commit
    *budget = planned_budget;
    let write_started = Instant::now();
    match timeout(idle, writer.write_records(scratch.records_buf.as_slice())).await {
        Ok(result) => result?,
        Err(_) => return Err(shed_mux_writer_on_stalled_client(log.cid)),
    }
    if let Some(activity) = activity { bump_relay_activity(activity); }
    waited = waited.saturating_add(write_started.elapsed());
    planned_budget.last_write = Some(Instant::now());
    // ok: parallax-mux-record-successful-write-commit
    *budget = planned_budget;
    scratch.records_buf.clear();
    if failed {
        // ruleid: parallax-mux-record-successful-write-commit
        budget.records_sent = planned_budget.records_sent;
    }
    // ruleid: parallax-mux-record-successful-write-commit
    budget.records_sent += 1;
}
async fn write_server_mux_frames_planned() {
    // ruleid: parallax-mux-record-one-write-per-plan, parallax-mux-record-successful-write-commit
    writer.write_records(scratch.records_buf.as_slice()).await?;
    // ruleid: parallax-mux-record-successful-write-commit
    writer.write_records(scratch.records_buf.as_slice()).await?;
    let write_started = Instant::now();
    match timeout(idle, writer.write_records(scratch.records_buf.as_slice())).await {
        Ok(result) => result?,
        Err(_) => return Err(shed_mux_writer_on_stalled_client(log.cid)),
    }
    if let Some(activity) = activity { bump_relay_activity(activity); }
    waited = waited.saturating_add(write_started.elapsed());
    planned_budget.last_write = Some(Instant::now());
    // ok: parallax-mux-record-successful-write-commit
    *budget = planned_budget;
    scratch.records_buf.clear();
}

// ok: parallax-mux-record-exact-padding-scope
fn mux_record_padding_plan(profile: TcpMuxRecordProfile, has_positive_data: bool, plaintext_len: usize, limit: usize) -> Option<(usize, usize)> {
    if plaintext_len == 0 || plaintext_len > limit { return None; }
    let pad = if profile == TcpMuxRecordProfile::CloudflareDynamic && has_positive_data { limit.checked_sub(plaintext_len)? } else { 0 };
    if pad > u16::MAX as usize { return None; }
    let tls_len = plaintext_len.checked_add(pad)?.checked_add(18)?;
    if tls_len > crate::protocol::data::OUTER_TLS_RECORD_LIMIT { return None; }
    Some((pad, tls_len.checked_add(TLS_HEADER_LEN)?))
}
// ruleid: parallax-mux-record-exact-padding-scope
fn mux_record_padding_plan(profile: TcpMuxRecordProfile, has_positive_data: bool, plaintext_len: usize, limit: usize) -> Option<(usize, usize)> { Some((limit - plaintext_len, limit + 23)) }

async fn write_server_mux_frames_planned() {
    // ok: parallax-mux-record-exact-sealer-branch
    if planned_budget.profile == TcpMuxRecordProfile::CloudflareDynamic {
        codec.seal_records_into_exact_padded(&scratch.plaintext_buf, &scratch.record_lens, &scratch.exact_pad_lens, rng, &mut scratch.records_buf)?;
    } else if should_parallelize_aead(scratch.record_lens.len(), scratch.plaintext_buf.len()) {
        codec.seal_records_into_parallel(parallel::global(), &scratch.plaintext_buf, &scratch.record_lens, rng, &mut scratch.records_buf)?;
    } else {
        codec.seal_records_into(&scratch.plaintext_buf, &scratch.record_lens, rng, &mut scratch.records_buf)?;
    }
    // ruleid: parallax-mux-record-exact-sealer-branch
    codec.seal_records_into_exact_padded(&scratch.plaintext_buf, &scratch.record_lens, &scratch.exact_pad_lens, rng, &mut scratch.records_buf)?;
}

async fn server_mux_writer_loop() {
    // ok: parallax-mux-record-no-whole-batch-timeout
    let waited = write_server_mux_frames_planned(&mut client_write, &mut server_seal, &mut batch, &mut rng, &mut seal_scratch, RelayWriteLog::new(cid, "server->client", "server-mux-writer"), &payload_pool, &mut record_budget, (idle, Some(&activity))).await?;
    // ruleid: parallax-mux-record-no-whole-batch-timeout, parallax-mux-record-writer-loop-timeout-boundary
    let waited = timeout(idle, write_server_mux_frames_planned(&mut client_write, &mut server_seal, &mut batch, &mut rng, &mut seal_scratch, RelayWriteLog::new(cid, "server->client", "server-mux-writer"), &payload_pool, &mut record_budget, (idle, Some(&activity)))).await??;
}
async fn write_server_mux_frames_planned() {
    // ok: parallax-mux-record-write-policy-binding
    let (idle, activity) = write_policy;
    // ruleid: parallax-mux-record-write-policy-binding
    let activity = None;
    // ruleid: parallax-mux-record-write-policy-binding
    let idle = Duration::MAX;
}
