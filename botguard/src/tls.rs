use crate::fingerprinting::ja3_index;
use async_trait::async_trait;
use pingora::listeners::TlsAccept;
use pingora::tls::ext;
use pingora::tls::pkey::{PKey, Private};
use pingora::tls::ssl::SslRef;
use pingora::tls::x509::X509;
use std::sync::Arc;

pub struct BotGuardTls {
    cert: X509,
    key: PKey<Private>,
}

impl BotGuardTls {
    pub fn new() -> Self {
        let cert_bytes = std::fs::read("certs/cert.pem").unwrap();
        let key_bytes = std::fs::read("certs/key.pem").unwrap();
        BotGuardTls {
            cert: X509::from_pem(&cert_bytes).unwrap(),
            key: PKey::private_key_from_pem(&key_bytes).unwrap(),
        }
    }
}

#[async_trait]
impl TlsAccept for BotGuardTls {
    async fn certificate_callback(&self, ssl: &mut SslRef) {
        ext::ssl_use_certificate(ssl, &self.cert).unwrap();
        ext::ssl_use_private_key(ssl, &self.key).unwrap();
    }

    async fn handshake_complete_callback(
        &self,
        ssl: &SslRef,
    ) -> Option<Arc<dyn std::any::Any + Send + Sync>> {
        let fingerprint = ssl.ex_data::<String>(*ja3_index())?.clone();
        println!("Handshake fertig, JA3: {}", fingerprint);
        Some(Arc::new(fingerprint))
    }
}
