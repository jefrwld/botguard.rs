use async_trait::async_trait;
use openssl::ex_data::Index;
use pingora::listeners::tls::TlsSettings;
use pingora::listeners::TlsAccept;
use pingora::prelude::*;
use pingora::proxy::{ProxyHttp, Session};
use pingora::tls::ext;
use pingora::tls::pkey::{PKey, Private};
use pingora::tls::ssl::{ClientHelloResponse, Ssl, SslAlert, SslRef};
use pingora::tls::x509::X509;
use std::sync::{Arc, OnceLock};

mod config;
mod fingerprinting;

use config::Config;
use fingerprinting::compute_ja3_from_client_hello;

static JA3_INDEX: OnceLock<Index<Ssl, String>> = OnceLock::new();

fn ja3_index() -> &'static Index<Ssl, String> {
    JA3_INDEX.get_or_init(|| Ssl::new_ex_index().unwrap())
}

fn main() {
    ja3_index();

    let config = Config::load("config.yaml").expect("config.yaml konnte nicht geladen werden");
    println!("Geladene Config: {:?}", config);

    let mut server = Server::new(None).unwrap();
    server.bootstrap();

    let proxy = BotGuardProxy {
        config: Arc::new(config),
    };
    let mut proxy_service = http_proxy_service(&server.configuration, proxy);

    proxy_service.add_tcp("0.0.0.0:8080");

    let mut tls_settings = TlsSettings::with_callbacks(Box::new(BotGuardTls::new())).unwrap();

    tls_settings.set_client_hello_callback(|ssl: &mut SslRef, _alert: &mut SslAlert| {
        let ja3 = compute_ja3_from_client_hello(ssl);

        println!("JA3 String: {}", ja3.raw);
        println!("JA3 Hash:   {}", ja3.hash);

        ssl.set_ex_data(*ja3_index(), ja3.hash);

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

pub struct RequestContext;

pub struct BotGuardProxy {
    pub config: Arc<Config>,
}

#[async_trait]
impl ProxyHttp for BotGuardProxy {
    type CTX = RequestContext;

    fn new_ctx(&self) -> Self::CTX {
        RequestContext
    }

    async fn request_filter(&self, session: &mut Session, _ctx: &mut Self::CTX) -> Result<bool> {
        let fingerprint = session
            .digest()
            .and_then(|d| d.ssl_digest.as_ref())
            .and_then(|s| s.extension.get::<String>())
            .cloned();

        let Some(fp) = fingerprint else {
            return Ok(false);
        };

        if self.config.blocked_fingerprints.contains(&fp) {
            println!("BLOCKED — JA3 {} ist auf der Blocklist", fp);
            session
                .respond_error(403)
                .await
                .or_err(ErrorType::HTTPStatus(403), "blocked by botguard")?;
            return Ok(true);
        }

        println!("ALLOWED — JA3 {} passt durch", fp);
        Ok(false)
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        let peer = Box::new(HttpPeer::new(
            "httpbin.org:80",
            false,
            "httpbin.org".to_string(),
        ));
        Ok(peer)
    }
}
