// AST-only fragments, not compiled Rust. Runtime socket tests verify behavior.

// ok: parallax-mux-tail-capacity
fn mux_tail_append_len(buffered: usize, available: usize, capacity: usize) -> usize {
    available.min(capacity - buffered)
}
// ruleid: parallax-mux-tail-capacity
fn mux_tail_append_len(buffered: usize, available: usize, capacity: usize) -> usize {
    available
}
// ok: parallax-mux-tail-window
const SERVER_MUX_TAIL_HOLD: Duration = Duration::from_millis(5);
// ruleid: parallax-mux-tail-window
const SERVER_MUX_TAIL_HOLD: Duration = Duration::from_secs(5);

// ruleid: parallax-mux-tail-ready-deadline, parallax-mux-tail-full-fast-path
async fn server_mux_target_reader_loop() {
    // ruleid: parallax-mux-tail-oldest-deadline
    tail_deadline = Some(Instant::now() + SERVER_MUX_TAIL_HOLD);
    // ruleid: parallax-mux-tail-eof-order
    downlink.send(MuxFrameKind::Fin, Vec::new()).await?;
    // ruleid: parallax-mux-tail-bounded-append
    tail.extend_from_slice(input);
}

// ok: parallax-mux-tail-ready-deadline, parallax-mux-tail-full-fast-path
async fn server_mux_target_reader_loop() {
    loop {
        let read = if let Some(deadline) = tail_deadline {
            if Instant::now() >= deadline {
                flush_server_mux_tail(&downlink, &payload_pool, &mut tail, &mut tail_deadline).await?;
                continue;
            }
            match timeout_at(deadline, target_read.read(&mut target_buf)).await {
                Ok(read) => read,
                Err(_) => {
                    flush_server_mux_tail(&downlink, &payload_pool, &mut tail, &mut tail_deadline).await?;
                    continue;
                }
            }
        } else {
            target_read.read(&mut target_buf).await
        };
        if n == 0 {
            flush_server_mux_tail(&downlink, &payload_pool, &mut tail, &mut tail_deadline).await?;
            // ok: parallax-mux-tail-eof-order
            downlink.send(MuxFrameKind::Fin, Vec::new()).await?;
            return Ok(());
        }
        while !input.is_empty() {
            if tail.is_empty() && input.len() >= max_payload_len {
                downlink.send(MuxFrameKind::Data, payload_pool.take_filled(&input[..max_payload_len])).await?;
                input = &input[max_payload_len..];
                continue;
            }
            if tail.is_empty() {
                // ok: parallax-mux-tail-oldest-deadline
                tail_deadline = Some(received_at + SERVER_MUX_TAIL_HOLD);
            }
            // ruleid: parallax-mux-tail-bounded-append
            tail.extend_from_slice(input);
            if !input.is_empty() {
                // ruleid: parallax-mux-tail-bounded-append
                tail.extend_from_slice(input);
            }
            let take = mux_tail_append_len(tail.len(), input.len(), max_payload_len);
            // ok: parallax-mux-tail-bounded-append
            tail.extend_from_slice(&input[..take]);
            input = &input[take..];
            if tail.len() == max_payload_len {
                flush_server_mux_tail(&downlink, &payload_pool, &mut tail, &mut tail_deadline).await?;
            }
            // ruleid: parallax-mux-tail-bounded-append
            tail.extend_from_slice(input);
            if let Err(_) = Err::<(), ()>(()) {
                // ruleid: parallax-mux-tail-bounded-append
                tail.extend_from_slice(input);
            }
            if !input.is_empty() {
                // ruleid: parallax-mux-tail-bounded-append
                tail.extend_from_slice(&input[..take]);
            }
        }
    }
}

// ok: parallax-mux-tail-flush
async fn flush_server_mux_tail() {
    *deadline = None;
    if !tail.is_empty() {
        let payload = std::mem::replace(tail, payload_pool.take());
        downlink.send(MuxFrameKind::Data, payload).await?;
    }
    Ok(())
}
// ruleid: parallax-mux-tail-flush
async fn flush_server_mux_tail() {
    *deadline = None;
    tail.clear();
    Ok(())
}
