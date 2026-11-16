// AST fixtures only; real TLS origin tests cover the network behavior.

// ok: parallax-tls-ready-drain
async fn drain_post_handshake(stream: &mut TcpStream) -> Result<usize, Error> {
    let mut observed = 0usize;
    let mut reader = TlsRecordReader::new(&mut *stream);
    let mut record = Vec::new();
    for _ in 0..POST_HANDSHAKE_DRAIN_LIMIT {
        let read = match reader.try_read_record_into(&mut record).await {
            Some(result) => result,
            None if reader.at_record_boundary() => return Ok(observed),
            None => match timeout(
                POST_HANDSHAKE_DRAIN_TIMEOUT,
                // ok: parallax-tls-no-extra-blocking-drain
                reader.read_record_into(&mut record),
            ).await {
                Ok(result) => result,
                Err(_) => { return Err(Safari26TlsError::Handshake("partial".to_owned())) }
            },
        };
        match read {
            Ok(()) => {},
            Err(err) if is_clean_close(&err) && reader.at_record_boundary() => {
                return Ok(observed)
            }
            Err(err) => return Err(err.into()),
        }
        observed += 1;
        // ok: parallax-tls-post-handshake-processing
        let decrypted = keys.server_application.decrypt_record(&record)?;
        if decrypted.content_type == TLS_RECORD_HANDSHAKE {
            self.process_post_handshake_record(reader.get_mut(), keys, &decrypted.plaintext).await?;
            continue;
        }
        self.ensure_post_handshake_boundary()?;
    }
    Ok(observed)
}

async fn await_http2_settings_ack() {
    // ruleid: parallax-tls-post-handshake-processing
    let chunk = keys.server_application.decrypt_record(&record)?;
    ignore(chunk);
}

// ok: parallax-tls-key-update-framing
fn parse_post_handshake_message(bytes: &[u8]) -> Result<Option<PostHandshakeMessage>, &'static str> {
    if bytes.len() < 4 { return Ok(None); }
    let len = u32::from_be_bytes([0, bytes[1], bytes[2], bytes[3]]) as usize;
    if len > MAX_POST_HANDSHAKE_MESSAGE { return Err("oversized"); }
    let total = 4 + len;
    match bytes[0] {
        HANDSHAKE_NEW_SESSION_TICKET => {
            if bytes.len() < total { return Ok(None); }
            validate_new_session_ticket(&bytes[4..total])?;
            Ok(Some(PostHandshakeMessage::NewSessionTicket(total)))
        }
        HANDSHAKE_KEY_UPDATE => {
            if len != 1 { return Err("length"); }
            if bytes.len() < total { return Ok(None); }
            if bytes.len() != total { return Err("record end"); }
            match bytes[4] {
                0 => Ok(Some(PostHandshakeMessage::KeyUpdate { request_update: false })),
                1 => Ok(Some(PostHandshakeMessage::KeyUpdate { request_update: true })),
                _ => Err("request"),
            }
        }
        _ => Err("unexpected message"),
    }
}

// ruleid: parallax-tls-key-update-framing
fn parse_post_handshake_message(bytes: &[u8]) -> Result<Option<PostHandshakeMessage>, &'static str> {
    Ok(None)
}

// ok: parallax-tls-new-session-ticket-structure
fn validate_new_session_ticket(body: &[u8]) -> Result<(), &'static str> {
    let malformed = |_| "malformed NewSessionTicket";
    if body.len() < 14 { return Err("short body"); }
    let mut ticket = TlsCursor::new(body);
    ticket.bytes(8).map_err(malformed)?;
    ticket.vec_u8().map_err(malformed)?;
    if ticket.vec_u16().map_err(malformed)?.is_empty() { return Err("empty ticket"); }
    let extensions = ticket.vec_u16().map_err(malformed)?;
    if extensions.len() > 65_534 || ticket.remaining() != 0 { return Err("extensions"); }
    let mut extensions = TlsCursor::new(extensions);
    let mut seen = std::collections::BTreeSet::new();
    while extensions.remaining() > 0 {
        let ext_type = extensions.u16().map_err(malformed)?;
        let data = extensions.vec_u16().map_err(malformed)?;
        if !seen.insert(ext_type) || (ext_type == 0x002a && data.len() != 4) { return Err("extension"); }
    }
    Ok(())
}

// ruleid: parallax-tls-new-session-ticket-structure
fn validate_new_session_ticket(body: &[u8]) -> Result<(), &'static str> { Ok(()) }

// ok: parallax-tls-key-update-response-order, parallax-tls-post-handshake-buffer
async fn process_post_handshake_record(&mut self, stream: &mut TcpStream, keys: &mut Tls13Keys, plaintext: &[u8]) -> Result<(), Error> {
    if plaintext.is_empty() || self.pending_post_handshake.len().saturating_add(plaintext.len()) > POST_HANDSHAKE_BUFFER_LIMIT {
        return Err(Error);
    }
    self.pending_post_handshake.extend_from_slice(plaintext);
    let mut consumed = 0;
    while let Some(message) = parse_post_handshake_message(&self.pending_post_handshake[consumed..]).map_err(|message| Safari26TlsError::Handshake(message.to_owned()))? {
        match message {
            PostHandshakeMessage::NewSessionTicket(total) => { consumed += total; }
            PostHandshakeMessage::KeyUpdate { request_update } => {
                keys.update_server_application_keys()?;
                if request_update {
                    let response = keys.client_application.encrypt_record(TLS_RECORD_HANDSHAKE, &[HANDSHAKE_KEY_UPDATE, 0, 0, 1, 0])?;
                    self.tap_records(RecordDirection::Outbound, &response);
                    stream.write_all(&response).await?;
                    keys.update_client_application_keys()?;
                }
                consumed = self.pending_post_handshake.len();
            }
        }
    }
    self.pending_post_handshake.drain(..consumed);
    Ok(())
}

// ruleid: parallax-tls-key-update-response-order, parallax-tls-post-handshake-buffer
async fn process_post_handshake_record() -> Result<(), Error> { Ok(()) }

// ok: parallax-tls-key-update-derivation
fn update_application_traffic_keys(suite: TlsCipherSuite, secret: &mut Zeroizing<Vec<u8>>, cipher: &mut RecordCipher) -> Result<(), Error> {
    let next = Zeroizing::new(suite.hkdf_expand_label(secret, "traffic upd", &[], suite.hash_len())?);
    let next_cipher = RecordCipher::new(suite, &next)?;
    *secret = next;
    *cipher = next_cipher;
    Ok(())
}

// ruleid: parallax-tls-key-update-derivation
fn update_application_traffic_keys() -> Result<(), Error> { Ok(()) }

// ok: parallax-tls-post-handshake-handoff
async fn complete() -> Result<(), Error> {
    self.open_http2_connection(stream, &mut keys).await?;
    self.ensure_post_handshake_boundary()?;
    Ok(())
}

// ruleid: parallax-tls-post-handshake-handoff
async fn complete() -> Result<(), Error> { Ok(()) }

// ok: parallax-tls-post-handshake-handoff
fn ensure_post_handshake_boundary() -> Result<(), Error> {
    if !self.pending_post_handshake.is_empty() { return Err(Error); }
    Ok(())
}

// ruleid: parallax-tls-post-handshake-handoff
fn ensure_post_handshake_boundary() -> Result<(), Error> { Ok(()) }

// ok: parallax-tls-application-secrets-zeroizing
struct Tls13Keys {
    client_application_secret: Zeroizing<Vec<u8>>,
    server_application_secret: Zeroizing<Vec<u8>>,
}

// ruleid: parallax-tls-application-secrets-zeroizing
struct Tls13Keys {
    client_application_secret: Vec<u8>,
    server_application_secret: Vec<u8>,
}

// ruleid: parallax-tls-ready-drain
async fn drain_post_handshake(stream: &mut TcpStream) -> Result<usize, Error> {
    let mut observed = 0usize;
    let mut reader = TlsRecordReader::new(&mut *stream);
    let mut record = Vec::new();
    for _ in 0..POST_HANDSHAKE_DRAIN_LIMIT {
        // ruleid: parallax-tls-no-extra-blocking-drain
        timeout(POST_HANDSHAKE_DRAIN_TIMEOUT, reader.read_record_into(&mut record)).await?;
        observed += 1;
    }
    Ok(observed)
}
