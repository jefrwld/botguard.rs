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
use foreign_types_shared::ForeignTypeRef;
use std::ffi::c_void;
use std::os::raw::{c_char, c_int};
use std::sync::{Arc, OnceLock};

extern "C" {
    fn SSL_client_hello_get1_extensions_present(
        s: *mut c_void,
        out: *mut *mut c_int,
        outlen: *mut usize,
    ) -> c_int;

    fn SSL_client_hello_get0_ext(
        s: *mut c_void,
        ext_type: std::os::raw::c_uint,
        out: *mut *const u8,
        outlen: *mut usize,
    ) -> c_int;

    fn SSL_client_hello_get0_legacy_version(s: *mut c_void) -> c_int;

    fn CRYPTO_free(ptr: *mut c_void, file: *const c_char, line: c_int);
}

fn client_hello_extension_data(ssl: &mut SslRef, ext_type: u32) -> Option<Vec<u8>> {
    let mut out: *const u8 = std::ptr::null();
    let mut outlen: usize = 0;

    let ret = unsafe {
        SSL_client_hello_get0_ext(
            ssl.as_ptr() as *mut c_void,
            ext_type,
            &mut out,
            &mut outlen,
        )
    };

    if ret != 1 {
        return None;
    }

    let slice = unsafe { std::slice::from_raw_parts(out, outlen) };
    Some(slice.to_vec())
}

fn parse_supported_groups(data: &[u8]) -> Vec<u16> {
    if data.len() < 2 { return Vec::new(); }
    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    let list = &data[2..];
    if list.len() < list_len { return Vec::new(); }
    list[..list_len]
        .chunks(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .collect()
}

fn parse_ec_point_formats(data: &[u8]) -> Vec<u8> {
    if data.is_empty() { return Vec::new(); }
    let list_len = data[0] as usize;
    let list = &data[1..];
    if list.len() < list_len { return Vec::new(); }
    list[..list_len].to_vec()
}

fn join_u16(items: &[u16]) -> String {
    items.iter().map(|x| x.to_string()).collect::<Vec<_>>().join("-")
}

fn join_u8(items: &[u8]) -> String {
    items.iter().map(|x| x.to_string()).collect::<Vec<_>>().join("-")
}

fn client_hello_extensions(ssl: &mut SslRef) -> Vec<u16> {
    let mut out: *mut c_int = std::ptr::null_mut();
    let mut outlen: usize = 0;

    let ret = unsafe {
        SSL_client_hello_get1_extensions_present(
            ssl.as_ptr() as *mut c_void,
            &mut out,
            &mut outlen,
        )
    };

    if ret != 1 {
        return Vec::new();
    }

    let slice: &[c_int] = unsafe { std::slice::from_raw_parts(out, outlen) };
    let result: Vec<u16> = slice.iter().map(|&id| id as u16).collect();
    unsafe { CRYPTO_free(out as *mut c_void, std::ptr::null(), 0) };

    result
}

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
        let version =
            unsafe { SSL_client_hello_get0_legacy_version(ssl.as_ptr() as *mut c_void) } as u16;

        let ciphers: Vec<u16> = ssl
            .client_hello_ciphers()
            .map(|raw| {
                raw.chunks(2)
                    .map(|c| u16::from_be_bytes([c[0], c[1]]))
                    .collect()
            })
            .unwrap_or_default();

        let extensions = client_hello_extensions(ssl);

        let curves = client_hello_extension_data(ssl, 10)
            .map(|d| parse_supported_groups(&d))
            .unwrap_or_default();

        let point_formats = client_hello_extension_data(ssl, 11)
            .map(|d| parse_ec_point_formats(&d))
            .unwrap_or_default();

        let ja3_string = format!(
            "{},{},{},{},{}",
            version,
            join_u16(&ciphers),
            join_u16(&extensions),
            join_u16(&curves),
            join_u8(&point_formats),
        );

        let ja3_hash = format!("{:x}", md5::compute(&ja3_string));

        println!("JA3 String: {}", ja3_string);
        println!("JA3 Hash:   {}", ja3_hash);

        ssl.set_ex_data(*ja3_index(), ja3_hash);

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
