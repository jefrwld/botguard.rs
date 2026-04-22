use async_trait::async_trait;
use pingora::listeners::TlsAccept;
use pingora::listeners::tls::TlsSettings;
use pingora::prelude::*;
use pingora::proxy::{ProxyHttp, Session};
use pingora::tls::ext;
use pingora::tls::pkey::{PKey, Private};
use pingora::tls::ssl::{ClientHelloResponse, Ssl, SslAlert, SslRef, SslVersion};
use pingora::tls::x509::X509;
use openssl::ex_data::Index;
use std::sync::{Arc, OnceLock};

/// Globaler Index für unser ex_data Slot — einmal registriert, für alle Verbindungen gültig
static JA3_INDEX: OnceLock<Index<Ssl, String>> = OnceLock::new();

fn ja3_index() -> &'static Index<Ssl, String> {
    JA3_INDEX.get_or_init(|| Ssl::new_ex_index().unwrap())
}

fn main() {
    // Index einmal beim Start registrieren
    ja3_index();

    let mut server = Server::new(None).unwrap();
    server.bootstrap();

    let proxy = BotGuardProxy;
    let mut proxy_service = http_proxy_service(&server.configuration, proxy);

    proxy_service.add_tcp("0.0.0.0:8080");

    let mut tls_settings =
        TlsSettings::with_callbacks(Box::new(BotGuardTls::new())).unwrap();

    tls_settings.set_client_hello_callback(|ssl: &mut SslRef, _alert: &mut SslAlert| {
        // Variablen außerhalb der if-let Blöcke mit `mut` damit wir sie danach neu zuweisen können
        let mut ciphers: Vec<u16> = Vec::new();
        let mut tls_version: Option<SslVersion> = None;

        if let Some(raw) = ssl.client_hello_ciphers() {
            ciphers = raw
                .chunks(2)
                .map(|c| u16::from_be_bytes([c[0], c[1]]))
                .collect();
        }

        if let Some(version) = ssl.client_hello_legacy_version() {
            tls_version = Some(version);
        }

        // Beide Felder in EINEM Fingerprint zusammen — nur EIN set_ex_data
        let fingerprint = format!("{:?}|{:?}", tls_version, ciphers);
        println!("Fingerprint: {}", fingerprint);
        ssl.set_ex_data(*ja3_index(), fingerprint);

        Ok(ClientHelloResponse::SUCCESS)
    });

    proxy_service.add_tls_with_settings("0.0.0.0:8443", None, tls_settings);

    server.add_service(proxy_service);
    server.run_forever();
}

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
    /// Setzt Zertifikat und Key — wird nach dem ClientHello Callback aufgerufen
    async fn certificate_callback(&self, ssl: &mut SslRef) {
        ext::ssl_use_certificate(ssl, &self.cert).unwrap();
        ext::ssl_use_private_key(ssl, &self.key).unwrap();
    }

    /// Nach dem Handshake — liest Fingerprint aus ex_data und gibt ihn an die Session weiter
    async fn handshake_complete_callback(
        &self,
        ssl: &SslRef,
    ) -> Option<Arc<dyn std::any::Any + Send + Sync>> {
        let fingerprint = ssl.ex_data::<String>(*ja3_index())?.clone();
        println!("Handshake fertig, JA3: {}", fingerprint);
        Some(Arc::new(fingerprint))
    }
}

pub struct RequestContext;

pub struct BotGuardProxy;

#[async_trait]
impl ProxyHttp for BotGuardProxy {
    type CTX = RequestContext;

    fn new_ctx(&self) -> Self::CTX {
        RequestContext
    }

    async fn upstream_peer(
        &self,
        session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        if let Some(digest) = session.digest() {
            if let Some(ssl_digest) = &digest.ssl_digest {
                if let Some(fingerprint) = ssl_digest.extension.get::<String>() {
                    println!("JA3 in upstream_peer: {}", fingerprint);
                }
            }
        }

        let peer = Box::new(HttpPeer::new(
            "httpbin.org:80",
            false,
            "httpbin.org".to_string(),
        ));
        Ok(peer)
    }
}
