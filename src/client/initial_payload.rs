use std::{io, time::Duration};

use tokio::{
    io::{AsyncRead, AsyncReadExt},
    time::timeout,
};

const INITIAL_PAYLOAD_CAPTURE_TIMEOUT: Duration = Duration::from_millis(2);
const MAX_INITIAL_PAYLOAD_CAPTURE: usize = 4096;

pub async fn read_initial_payload<R>(
    local: &mut R,
    protocol_payload_cap: usize,
) -> Result<Vec<u8>, io::Error>
where
    R: AsyncRead + Unpin,
{
    let cap = protocol_payload_cap.min(MAX_INITIAL_PAYLOAD_CAPTURE);
    if cap == 0 {
        return Ok(Vec::new());
    }

    let mut buf = vec![0_u8; cap];
    match timeout(INITIAL_PAYLOAD_CAPTURE_TIMEOUT, local.read(&mut buf)).await {
        Ok(Ok(n)) => {
            buf.truncate(n);
            Ok(buf)
        }
        Ok(Err(err)) => Err(err),
        Err(_) => Ok(Vec::new()),
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{duplex, AsyncWriteExt};

    use super::*;

    #[tokio::test]
    async fn captures_waiting_initial_payload() {
        let (mut app, mut runtime) = duplex(64);
        app.write_all(b"hello").await.unwrap();

        let captured = read_initial_payload(&mut runtime, 64).await.unwrap();

        assert_eq!(captured, b"hello");
    }

    #[tokio::test]
    async fn respects_protocol_payload_cap() {
        let (mut app, mut runtime) = duplex(64);
        app.write_all(b"abcdef").await.unwrap();

        let captured = read_initial_payload(&mut runtime, 3).await.unwrap();

        assert_eq!(captured, b"abc");
    }

    #[tokio::test]
    async fn returns_empty_when_no_payload_arrives_before_timeout() {
        let (_app, mut runtime) = duplex(64);

        let captured = read_initial_payload(&mut runtime, 64).await.unwrap();

        assert!(captured.is_empty());
    }
}
