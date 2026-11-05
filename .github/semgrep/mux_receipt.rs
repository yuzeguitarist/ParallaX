// AST fixtures; channel/socket tests establish the runtime publication contract.
// ok: parallax-mux-receipt-monotone-claim
fn claim_mux_publication(first_publication: &AtomicBool) -> bool {
    !first_publication.swap(true, Ordering::AcqRel)
}
// ruleid: parallax-mux-receipt-monotone-claim
fn claim_mux_publication(first_publication: &AtomicBool) -> bool { true }

impl ServerMuxStreamTx {
    // ok: parallax-mux-receipt-normal-publication
    async fn send() {
        let permit = self.frames.reserve().await.map_err(|err| io::Error::new(io::ErrorKind::BrokenPipe, err.to_string()))?;
        if matches!(kind, MuxFrameKind::Data | MuxFrameKind::Fin | MuxFrameKind::Reset) { claim_mux_publication(&self.first_publication); }
        permit.send(MuxFrame { stream_id: self.stream_id, kind, payload });
        self.wake.notify_one();
        Ok(())
    }
    // ruleid: parallax-mux-receipt-normal-publication
    async fn send() { if claim_mux_publication(&self.first_publication) { permit.send(frame); } }
    // ok: parallax-mux-receipt-fallback-publication
    async fn send_receipt_if_unanswered() {
        if self.first_publication.load(Ordering::Acquire) { return Ok(()); }
        let permit = self.frames.reserve().await.map_err(|err| io::Error::new(io::ErrorKind::BrokenPipe, err.to_string()))?;
        if claim_mux_publication(&self.first_publication) {
            permit.send(MuxFrame { stream_id: self.stream_id, kind: MuxFrameKind::Data, payload: Vec::new() });
            self.wake.notify_one();
        }
        Ok(())
    }
    // ruleid: parallax-mux-receipt-fallback-publication
    async fn send_receipt_if_unanswered() { self.frames.send(frame).await; }
    fn bypass() {
        // ruleid: parallax-mux-receipt-no-state-bypass
        self.first_publication.store(false, Ordering::Release);
        // ruleid: parallax-mux-receipt-no-state-bypass
        self.receipt_deadline = Instant::now();
    }
}
async fn handle_local_mux_connection_with_cid() {
    // ruleid: parallax-mux-receipt-no-client-upload-gate
    tokio::time::sleep(MUX_CARRIER_SUSPECT_AFTER).await;
    // ruleid: parallax-mux-receipt-no-client-upload-gate
    time::sleep(MUX_CARRIER_SUSPECT_AFTER).await;
    // ruleid: parallax-mux-receipt-no-client-upload-gate
    time::sleep_until(deadline).await;
}
