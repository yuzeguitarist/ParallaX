// Reviewed AST source scopes; syntax regression policy, not a concurrency theorem.

use crate::protocol::command::MUX_CARRIER_SUSPECT_AFTER;

pub(crate) const MUX_CARRIER_SUSPECT_AFTER: std::time::Duration = std::time::Duration::from_secs(5);

const MUX_CARRIER_DEAD_AFTER: Duration = Duration::from_secs(25);

const MUX_CARRIER_WATCHDOG: MuxCarrierWatchdog = MuxCarrierWatchdog {
    suspect_after: MUX_CARRIER_SUSPECT_AFTER,
    dead_after: MUX_CARRIER_DEAD_AFTER,
};

#[derive(Clone)]
struct ServerMuxStreamTx {
    stream_id: u32,
    frames: mpsc::Sender<MuxFrame>,
    wake: Arc<Notify>,
    first_publication: Arc<AtomicBool>,
    receipt_deadline: Instant,
}

impl ServerMuxDownlink {
    async fn register(&self, stream_id: u32) -> Result<ServerMuxStreamTx, HandshakeServerError> {
        // Start before registration can wait on a full control queue. Neither
        // spawning nor target I/O may grant the receipt a fresh delay window.
        let receipt_deadline = Instant::now() + MUX_CARRIER_SUSPECT_AFTER / 2;
        let (frames, queue) = mpsc::channel(self.stream_queue_depth);
        self.send_control(DownlinkControl::Register(stream_id, queue))
            .await?;
        Ok(ServerMuxStreamTx {
            stream_id,
            frames,
            wake: Arc::clone(&self.wake),
            first_publication: Arc::new(AtomicBool::new(false)),
            receipt_deadline,
        })
    }
}

impl ServerMuxStreamTx {
    async fn send(&self, kind: MuxFrameKind, payload: Vec<u8>) -> Result<(), HandshakeServerError> {
        let permit = self
            .frames
            .reserve()
            .await
            .map_err(|err| io::Error::new(io::ErrorKind::BrokenPipe, err.to_string()))?;
        if matches!(
            kind,
            MuxFrameKind::Data | MuxFrameKind::Fin | MuxFrameKind::Reset
        ) {
            claim_mux_publication(&self.first_publication);
        }
        // Ordinary frames are NEVER suppressed by the receipt claim result.
        permit.send(MuxFrame {
            stream_id: self.stream_id,
            kind,
            payload,
        });
        self.wake.notify_one();
        Ok(())
    }

    async fn send_receipt_if_unanswered(&self) -> Result<(), HandshakeServerError> {
        if self.first_publication.load(Ordering::Acquire) {
            return Ok(());
        }
        let permit = self
            .frames
            .reserve()
            .await
            .map_err(|err| io::Error::new(io::ErrorKind::BrokenPipe, err.to_string()))?;
        if claim_mux_publication(&self.first_publication) {
            permit.send(MuxFrame {
                stream_id: self.stream_id,
                kind: MuxFrameKind::Data,
                payload: Vec::new(),
            });
            self.wake.notify_one();
        }
        Ok(())
    }

    /// Resets this substream (empty-payload Reset, queued after its data).
    async fn reset(&self) -> Result<(), HandshakeServerError> {
        self.send(MuxFrameKind::Reset, Vec::new()).await
    }
}

impl Drop for ServerMuxStreamTx {
    /// A finished substream gives no frame to wake the writer on, so wake it here:
    /// once every handle is gone the writer sees the queue disconnected, drops it,
    /// and — with the reader gone too — flushes and shuts the client write down.
    fn drop(&mut self) {
        self.wake.notify_one();
    }
}

fn claim_mux_publication(first_publication: &AtomicBool) -> bool {
    !first_publication.swap(true, Ordering::AcqRel)
}

async fn with_mux_open_receipt(downlink: &ServerMuxStreamTx, upstream: impl Future<Output = ()>) {
    let receipt = async {
        sleep_until(downlink.receipt_deadline).await;
        downlink.send_receipt_if_unanswered().await
    };
    tokio::pin!(upstream, receipt);
    tokio::select! {
        biased;
        _ = &mut upstream => {}
        result = &mut receipt => {
            if result.is_ok() {
                upstream.await;
            }
        }
    }
}

async fn server_mux_upstream_task(
    stream_id: u32,
    mut connect_payload: Zeroizing<Vec<u8>>,
    upload_rx: mpsc::Receiver<Zeroizing<Vec<u8>>>,
    downlink: ServerMuxStreamTx,
    ctx: ServerMuxStreamContext,
    payload_pool: MuxPayloadPool,
) {
    let upstream = async {
        // The decrypted request is already scrub-on-drop before this task is spawned;
        // copy out the target + initial payload (also scrub-on-drop) so the request
        // buffer is dropped (scrubbed) before the connect await.
        let (target_addr, target_source, initial) = match resolve_connect_target(
            connect_payload.as_mut_slice(),
            ctx.fixed_data_target.as_deref(),
        ) {
            Ok((addr, source, initial)) => (addr, source, Zeroizing::new(initial.to_vec())),
            Err(_) => {
                tracing::debug!(
                    cid = ctx.cid,
                    stream_id,
                    "mux connect target resolve failed; resetting stream"
                );
                let _ = downlink.reset().await;
                return;
            }
        };
        drop(connect_payload);
        crate::process_hardening::exclude_from_core_dump("mux.upstream.initial_payload", &initial);

        let mut target = match connect_outbound_target(&target_addr, target_source).await {
            Ok(target) => target,
            Err(_) => {
                tracing::debug!(
                    cid = ctx.cid,
                    stream_id,
                    "mux outbound connect failed; resetting stream"
                );
                let _ = downlink.reset().await;
                return;
            }
        };
        if tune_tcp_stream(&target).is_err() {
            tracing::debug!(
                cid = ctx.cid,
                stream_id,
                "mux target tune failed; resetting stream"
            );
            let _ = downlink.reset().await;
            return;
        }
        if !initial.is_empty() {
            match timeout(ctx.target_write_timeout, target.write_all(&initial)).await {
                Ok(Ok(())) => {}
                _ => {
                    tracing::debug!(
                        cid = ctx.cid,
                        stream_id,
                        "mux target initial-payload write failed/stalled; resetting stream"
                    );
                    let _ = downlink.reset().await;
                    return;
                }
            }
        }
        drop(initial);

        let activity: RelayActivity = Arc::new(AtomicU64::new(relay_now_millis()));
        let (target_read, target_write) = target.into_split();
        let reader = server_mux_target_reader_loop(
            target_read,
            downlink.clone(),
            stream_id,
            ctx.timing,
            ctx.chunk_size,
            ctx.cid,
            payload_pool,
            activity.clone(),
        );
        let writer = server_mux_upload_drain(
            upload_rx,
            target_write,
            stream_id,
            ctx.cid,
            ctx.target_write_timeout,
            &downlink,
            activity.clone(),
        );
        // Run both directions; an error in either drops the other's half of the target
        // socket. Half-close (client Fin) resolves `writer` Ok while `reader` keeps
        // streaming the target back until its EOF.
        tokio::select! {
            _ = async { tokio::try_join!(reader, writer) } => {}
            _ = relay_idle_watchdog(activity, ctx.idle_timeout) => {
                tracing::debug!(cid = ctx.cid, stream_id, "mux target idle backstop reached");
                let _ = downlink.send(MuxFrameKind::Fin, Vec::new()).await;
            }
        }
    };
    with_mux_open_receipt(&downlink, upstream).await;
}

async fn client_mux_reader_loop() {
            while !frames.is_empty() {
                let (frame, used) = MuxFrame::decode_ref_prefix(frames)?;
                if frame.kind != MuxFrameKind::Cover {
                    bump_client_relay_activity(&health.relay_activity);
                }
                unanswered_opens.remove(&frame.stream_id);
                dispatch_client_mux_frame(&mut local_writes, frame, cid).await;
                frames = &frames[used..];
            }
}

#[cfg(test)]
mod tests {
    async fn mux_tail_test_reader(
        capacity: usize,
        timing: TimingProfile,
    ) -> (
        TcpStream,
        mpsc::Receiver<MuxFrame>,
        tokio::task::JoinHandle<Result<(), HandshakeServerError>>,
        RelayActivity,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (peer, target) = tokio::join!(
            TcpStream::connect(listener.local_addr().unwrap()),
            listener.accept(),
        );
        let peer = peer.unwrap();
        peer.set_nodelay(true).unwrap();
        let (target, _) = target.unwrap();
        target.set_nodelay(true).unwrap();
        let (read, _) = target.into_split();
        let (frames, receiver) = mpsc::channel(16);
        let downlink = ServerMuxStreamTx {
            stream_id: 1,
            frames,
            wake: Arc::new(Notify::new()),
            first_publication: Arc::new(AtomicBool::new(false)),
            receipt_deadline: Instant::now() + MUX_CARRIER_SUSPECT_AFTER / 2,
        };
        let activity = Arc::new(AtomicU64::new(u64::MAX));
        let task = tokio::spawn(server_mux_target_reader_loop(
            read,
            downlink,
            1,
            timing,
            MuxFrame::encoded_len(capacity).unwrap(),
            1,
            MuxPayloadPool::with_capacity(capacity),
            activity.clone(),
        ));
        (peer, receiver, task, activity)
    }
}
