// AST fixtures for the reviewed private TCP producer. Runtime behavior is
// covered separately by actual sockets and paused-time tests.

// ok: parallax-client-mux-tail-window, parallax-client-mux-tail-private-window
const CLIENT_TCP_MUX_TAIL_HOLD: Duration = Duration::from_millis(1);
// ruleid: parallax-client-mux-tail-window
const CLIENT_TCP_MUX_TAIL_HOLD: Duration = Duration::from_millis(50);
// ruleid: parallax-client-mux-tail-private-window
pub const CLIENT_TCP_MUX_TAIL_HOLD: Duration = Duration::from_millis(1);

// ok: parallax-client-mux-tail-capacity
fn client_mux_tail_append_len(buffered: usize, available: usize, capacity: usize) -> usize {
    available.min(capacity - buffered)
}

// ok: parallax-client-mux-tail-cancel-cleanup
impl Drop for ClientMuxUploadTail {
    fn drop(&mut self) {
        // Cancellation never sends asynchronously; recycle only uncommitted
        // local bytes, including a tail parked behind channel backpressure.
        self.pool.put(std::mem::take(&mut self.bytes));
    }
}

// ok: parallax-client-mux-tail-flush
async fn flush_client_mux_upload_tail(
    frame_tx: &mpsc::Sender<MuxFrame>,
    stream_id: u32,
    tail: &mut ClientMuxUploadTail,
    deadline: &mut Option<Instant>,
) -> Result<(), ClientRuntimeError> {
    *deadline = None;
    if !tail.bytes.is_empty() {
        // Reserve first so cancellation or receiver closure leaves the bytes
        // owned by the synchronous pool-return guard, never a pending send.
        let slot = frame_tx
            .reserve()
            .await
            .map_err(|err| io::Error::new(io::ErrorKind::BrokenPipe, err.to_string()))?;
        let payload = std::mem::replace(&mut tail.bytes, tail.pool.take());
        slot.send(MuxFrame {
            stream_id,
            kind: MuxFrameKind::Data,
            payload,
        });
    }
    Ok(())
}

// ok: parallax-client-mux-tail-producer
async fn client_mux_upload_loop(
    mut local_read: OwnedReadHalf,
    frame_tx: mpsc::Sender<MuxFrame>,
    stream_id: u32,
    chunk_size: usize,
    cid: u64,
    payload_pool: MuxPayloadPool,
    hold: Duration,
) -> Result<(), ClientRuntimeError> {
    let mut local_buf = vec![0_u8; relay_read_buffer_len(MuxFrame::max_payload_len(chunk_size))];
    let max_payload_len = MuxFrame::max_payload_len(chunk_size);
    if max_payload_len == 0 {
        return Err(ClientRuntimeError::TlsRecord(
            crate::tls::record::TlsRecordError::PayloadTooLarge(0),
        ));
    }
    let mut tail = ClientMuxUploadTail {
        bytes: if hold.is_zero() {
            Vec::new()
        } else {
            payload_pool.take()
        },
        pool: payload_pool.clone(),
    };
    let mut tail_deadline = None;

    loop {
        // Check before polling even an always-ready socket. New input must not
        // postpone the oldest byte, and timeout_at alone polls its I/O first.
        let read = if let Some(deadline) = tail_deadline {
            if Instant::now() >= deadline {
                flush_client_mux_upload_tail(&frame_tx, stream_id, &mut tail, &mut tail_deadline)
                    .await?;
                continue;
            }
            match timeout_at(deadline, local_read.read(&mut local_buf)).await {
                Ok(read) => read,
                Err(_) => {
                    flush_client_mux_upload_tail(
                        &frame_tx,
                        stream_id,
                        &mut tail,
                        &mut tail_deadline,
                    )
                    .await?;
                    continue;
                }
            }
        } else {
            local_read.read(&mut local_buf).await
        };
        let mut n = match read {
            Ok(n) => n,
            Err(err) => {
                flush_client_mux_upload_tail(&frame_tx, stream_id, &mut tail, &mut tail_deadline)
                    .await?;
                return Err(err.into());
            }
        };
        #[cfg(test)]
        CLIENT_MUX_UPLOAD_READ_BYTES.fetch_add(n as u64, Ordering::Relaxed);
        if n == 0 {
            flush_client_mux_upload_tail(&frame_tx, stream_id, &mut tail, &mut tail_deadline)
                .await?;
            send_mux_frame(&frame_tx, stream_id, MuxFrameKind::Fin, Vec::new()).await?;
            return Ok(());
        }
        let received_at = Instant::now();
        if !hold.is_zero() && tail.bytes.is_empty() {
            tail_deadline = Some(received_at + hold);
        }
        // Held reads are appended before polling again: the drain helper's Err
        // cannot report a successfully consumed partial prefix. The zero-hold
        // path keeps its original opportunistic-drain behavior.
        if hold.is_zero() {
            n = drain_ready_tcp_read(&local_read, &mut local_buf, n)?;
            for chunk in local_buf[..n].chunks(max_payload_len) {
                send_mux_frame(
                    &frame_tx,
                    stream_id,
                    MuxFrameKind::Data,
                    payload_pool.take_filled(chunk),
                )
                .await?;
            }
        } else {
            let mut input = &local_buf[..n];
            while !input.is_empty() {
                if tail.bytes.is_empty() {
                    // Full-frame sends can block; a remaining short suffix
                    // keeps this read's original receipt time, never a new hold.
                    tail_deadline = Some(received_at + hold);
                }
                let take =
                    client_mux_tail_append_len(tail.bytes.len(), input.len(), max_payload_len);
                tail.bytes.extend_from_slice(&input[..take]);
                input = &input[take..];
                if tail.bytes.len() == max_payload_len {
                    flush_client_mux_upload_tail(
                        &frame_tx,
                        stream_id,
                        &mut tail,
                        &mut tail_deadline,
                    )
                    .await?;
                }
            }
        }
        tracing::trace!(
            cid,
            stream_id,
            bytes = n,
            "queued client mux upload payload"
        );
    }
}

// ok: parallax-client-mux-tail-tcp-boundary
async fn handle_local_mux_connection_with_cid(
    mut local: TcpStream,
    mux_pool: ClientMuxPool,
    cid: u64,
) -> Result<(), ClientRuntimeError> {
    tune_tcp_stream(&local)?;
    let request = accept_local_socks_connect(&mut local).await?;
    tracing::debug!(
        cid,
        task_name = "client-mux-connection",
        "accepted SOCKS connection for mux session"
    );

    // Reserve a substream slot on a session that has one free, opening a new
    // session if every existing session is saturated. The permit is held for the
    // whole connection: it bounds each session to `max_concurrent_streams`
    // substreams WITHOUT capping the client's total concurrent connections.
    let (mux, _stream_permit) = mux_pool.acquire().await?;
    let initial_payload_cap = MuxFrame::max_open_initial_payload_len(&request.host, mux.chunk_size);
    let initial_payload = initial_payload::read_initial_payload(&mut local, initial_payload_cap)
        .await
        .map_err(ClientRuntimeError::Io)?;
    let connect_request = ConnectRequest {
        host: request.host,
        port: request.port,
        initial_payload,
    };

    // QUIC fast plane: open a dedicated bidi for this substream and relay it
    // natively (its own per-substream codec), independent of every other substream.
    if let MuxCarrier::Quic {
        conn,
        session_keys,
        traffic,
        authority,
        accept_language,
        ..
    } = &mux.carrier
    {
        return client_mux_quic_substream(
            local,
            conn.clone(),
            session_keys,
            *traffic,
            connect_request,
            authority,
            accept_language.as_deref(),
            cid,
        )
        .await;
    }

    // TCP path: serialize this substream's frames onto the shared record stream.
    let MuxCarrier::Tcp {
        frame_tx,
        register_tx,
        payload_pool,
    } = &mux.carrier
    else {
        unreachable!("QUIC carrier handled above");
    };
    let stream_id = next_mux_stream_id(&mux.next_stream_id);
    let connect_payload = connect_request.encode()?;
    let open_frame = MuxFrame {
        stream_id,
        kind: MuxFrameKind::Open,
        payload: connect_payload,
    };

    // Wait for queue capacity before arming the Open watchdog. Once registered,
    // enqueue synchronously so an ACK cannot race ahead of the download half and
    // time spent outside a full writer queue is not mistaken for carrier silence.
    let open_slot = frame_tx
        .reserve()
        .await
        .map_err(|err| io::Error::new(io::ErrorKind::BrokenPipe, err.to_string()))?;

    let (local_read, local_write) = local.into_split();
    let (outcome_tx, outcome_rx) = oneshot::channel();
    // Register the download half with the reader before announcing the stream,
    // so an immediate server response can never race ahead of the write half.
    if register_tx
        .send(ClientStreamControl::Register(ClientStreamRegistration {
            stream_id,
            local_write,
            outcome_tx,
        }))
        .await
        .is_err()
    {
        return Err(io::Error::new(io::ErrorKind::BrokenPipe, "client mux reader is gone").into());
    }
    open_slot.send(open_frame);
    if frame_tx.is_closed() {
        let _ = register_tx
            .send(ClientStreamControl::Deregister(stream_id))
            .await;
        return Err(io::Error::new(io::ErrorKind::BrokenPipe, "client mux writer is gone").into());
    }

    // ruleid: parallax-client-mux-tail-gate-immutable
    let mut mux_pool = mux_pool;
    // ruleid: parallax-client-mux-tail-gate-immutable
    mux_pool.traffic.max_delay_ms = 0;
    {
        // ruleid: parallax-client-mux-tail-gate-immutable
        let mux_pool = mux_pool.clone();
    }
    // ruleid: parallax-client-mux-tail-gate-immutable
    let (mut mux_pool, _unused) = (mux_pool, ());
    // ruleid: parallax-client-mux-tail-gate-immutable
    let policy = &mut mux_pool.traffic;
    // ruleid: parallax-client-mux-tail-gate-immutable
    mux_pool.traffic.max_delay_ms &= 0;
    let upload = client_mux_upload_loop(
        local_read,
        frame_tx.clone(),
        stream_id,
        mux.chunk_size,
        cid,
        payload_pool.clone(),
        if mux_pool.traffic.max_delay_ms == 0 {
            CLIENT_TCP_MUX_TAIL_HOLD
        } else {
            Duration::ZERO
        },
    );
    let download = client_mux_await_download(outcome_rx, cid);
    // Wait for BOTH halves. A clean server Fin (DownloadOutcome::Fin -> Ok)
    // resolves the download future but must NOT cancel the upload: the local app
    // may still be sending (TCP half-close), and the server deliberately keeps
    // its client->target write half open on Fin. try_join! keeps draining the
    // upload until local EOF (which sends the upstream Fin), and short-circuits
    // only on a Reset/error (DownloadOutcome::Reset -> Err), which the teardown
    // below turns into an upstream Reset. Cancelling the upload here would
    // silently drop in-flight client->server bytes and break half-close.
    let result = tokio::try_join!(upload, download).map(|_| ());

    // Tear the stream down on both ends so it cannot leak when it ended without a
    // server Fin/Reset (e.g. the local upload half errored before a clean Fin).
    // On an abnormal end, reset the server side so its target socket is released;
    // always deregister so the reader drops the local write half. Both are
    // idempotent no-ops if the stream was already removed via a server Fin/Reset.
    if result.is_err() {
        let _ = frame_tx
            .send(MuxFrame {
                stream_id,
                kind: MuxFrameKind::Reset,
                payload: Vec::new(),
            })
            .await;
    }
    let _ = register_tx
        .send(ClientStreamControl::Deregister(stream_id))
        .await;
    result
}

// ruleid: parallax-client-mux-tail-capacity
fn client_mux_tail_append_len(buffered: usize, available: usize, capacity: usize) -> usize { available }
// ruleid: parallax-client-mux-tail-cancel-cleanup
impl Drop for ClientMuxUploadTail { fn drop(&mut self) {} }
// ruleid: parallax-client-mux-tail-flush
async fn flush_client_mux_upload_tail() { Ok(()) }
// ruleid: parallax-client-mux-tail-producer
async fn client_mux_upload_loop() { Ok(()) }
// ruleid: parallax-client-mux-tail-tcp-boundary
async fn handle_local_mux_connection_with_cid() { Ok(()) }
fn bad_caller() {
  // ruleid: parallax-client-mux-tail-callsite
  client_mux_upload_loop(local_read, frame_tx.clone(), stream_id, mux.chunk_size, cid, payload_pool.clone(), Duration::from_millis(mux_pool.traffic.max_delay_ms));
}
