use sha2::{Digest, Sha256};

pub fn session_context(client_hello_record: &[u8], server_random: &[u8; 32]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(b"ParallaX v1 handshake transcript");
    hasher.update(client_hello_record);
    let client_hello_hash = hasher.finalize();

    let mut context = Vec::with_capacity(client_hello_hash.len() + server_random.len());
    context.extend_from_slice(&client_hello_hash);
    context.extend_from_slice(server_random);
    context
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn context_binds_client_hello_and_server_random() {
        let a = session_context(b"client-hello-a", &[1; 32]);
        let b = session_context(b"client-hello-b", &[1; 32]);
        let c = session_context(b"client-hello-a", &[2; 32]);

        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_eq!(a.len(), 64);
    }
}
