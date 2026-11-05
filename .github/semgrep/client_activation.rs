// AST-only fixtures, not compiled Rust. Findings enforce syntactic boundaries;
// actual socket regressions cover the observed startup behavior.

async fn run() {
    // ruleid: parallax-no-startup-carrier
    pool.ensure_started().await;
    // ruleid: parallax-no-startup-carrier
    establish_authenticated_data_session_with_resolver().await;
    // ok: parallax-no-startup-carrier
    pool.start_keeper();
}

async fn handle_local_connection_with_cid(mut local: TcpStream) {
    tune_tcp_stream(&local)?;
    let request = accept_local_socks_connect(&mut local).await?;
    // ok: parallax-validate-socks-before-carrier
    // ruleid: parallax-single-demand-carrier
    pool.take_or_start().await;
}

async fn handle_local_connection_with_cid(mut local: TcpStream) {
    // ruleid: parallax-validate-socks-before-carrier, parallax-single-demand-carrier
    pool.take_or_start().await;
    tune_tcp_stream(&local)?;
    let request = accept_local_socks_connect(&mut local).await?;
}

async fn handle_local_connection_with_cid(mut local: TcpStream) {
    tune_tcp_stream(&local)?;
    let request = accept_local_socks_connect(&mut local).await?;
    // ruleid: parallax-single-demand-carrier
    pool.fill_locked(&mut warm);
    // ruleid: parallax-single-demand-carrier-once
    let server_session_task = first;
    do_something();
    let server_session_task = second;
}

async fn handle_local_connection_with_cid(mut local: TcpStream) {
    tune_tcp_stream(&local)?;
    let request = accept_local_socks_connect(&mut local).await?;
    // ruleid: parallax-single-demand-carrier-once
    for item in items {
        let server_session_task = task;
    }
}

async fn handle_local_mux_connection_with_cid(mut local: TcpStream) {
    tune_tcp_stream(&local)?;
    let request = accept_local_socks_connect(&mut local).await?;
    // ok: parallax-validate-socks-before-carrier
    pool.acquire().await;
}

async fn handle_local_mux_connection_with_cid(mut local: TcpStream) {
    tune_tcp_stream(&local)?;
    let _ignored = accept_local_socks_connect(&mut local).await;
    // ruleid: parallax-validate-socks-before-carrier
    pool.acquire().await;
}

// ok: parallax-validated-socks-boundary
async fn accept_local_socks_connect(local: &mut TcpStream) -> Result<Request, Error> {
    match timeout(SOCKS_ACCEPT_TIMEOUT, socks::accept_connect(local)).await {
        Ok(result) => result.map_err(Into::into),
        Err(elapsed) => { Err(Error) }
    }
}

// ruleid: parallax-validated-socks-boundary
async fn accept_local_socks_connect(local: &mut TcpStream) -> Result<Request, Error> {
    Ok(Request)
}

impl ClientMuxPool {
    fn new() -> Self {
        // ok: parallax-mux-starts-inactive
        Self { last_activity: Arc::new(AtomicU64::new(0)), inner: state }
    }

    fn new() -> Self {
        // ruleid: parallax-mux-starts-inactive
        Self { last_activity: Arc::new(AtomicU64::new(1)), inner: state }
    }

    async fn ensure_warm(&self) -> Result<(), Error> {
        loop {
            if !mux_activity_is_recent(self.last_activity.load(Ordering::Relaxed), relay_now_millis()) {
                return Ok(());
            }
            // ok: parallax-mux-warm-activation-guard
            self.spawn_build().await;
        }
    }

    async fn ensure_warm(&self) -> Result<(), Error> {
        // ruleid: parallax-mux-warm-activation-guard
        self.spawn_build().await;
    }

    fn start_keeper(&self) {
        // ruleid: parallax-no-eager-keeper-build
        pool.ensure_warm().await;
        loop {
            // ok: parallax-no-eager-keeper-build
            pool.ensure_warm().await;
        }
    }

    fn acquire(&self) {
        // ok: parallax-mux-activity-stamp
        self.last_activity.store(relay_now_millis().saturating_add(1), Ordering::Relaxed);
        // ruleid: parallax-mux-activity-stamp
        self.last_activity.store(relay_now_millis(), Ordering::Relaxed);
    }
}

// ok: parallax-mux-activity-sentinel
fn mux_activity_is_recent(last_activity: u64, now: u64) -> bool {
    last_activity != 0 && now.saturating_sub(last_activity - 1) <= MUX_WARM_KEEPER_ACTIVE_WINDOW.as_millis() as u64
}

// ruleid: parallax-mux-activity-sentinel
fn mux_activity_is_recent(last_activity: u64, now: u64) -> bool {
    now.saturating_sub(last_activity) <= MUX_WARM_KEEPER_ACTIVE_WINDOW.as_millis() as u64
}

// ok: parallax-socks-reserved-byte
async fn read_connect_request(stream: &mut S) -> Result<Request, Error> {
    read_socks5_version(stream).await?;
    let command = stream.read_u8().await?;
    if command != 1 { return Err(SocksError::UnsupportedCommand(command)); }
    let reserved = stream.read_u8().await?;
    if reserved != 0 { return Err(SocksError::InvalidReserved); }
    Ok(request)
}

// ruleid: parallax-socks-reserved-byte
async fn read_connect_request(stream: &mut S) -> Result<Request, Error> {
    read_socks5_version(stream).await?;
    let command = stream.read_u8().await?;
    if command != 1 { return Err(SocksError::UnsupportedCommand(command)); }
    let reserved = stream.read_u8().await?;
    Ok(request)
}
