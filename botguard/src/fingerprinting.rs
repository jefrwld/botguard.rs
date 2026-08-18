use foreign_types_shared::ForeignTypeRef;
use openssl::ex_data::Index;
use pingora::tls::ssl::{Ssl, SslRef};
use std::ffi::c_void;
use std::os::raw::{c_char, c_int};
use std::sync::OnceLock;

struct ClientHelloFingerprintData {
    version: u16,
    ciphers: Vec<u16>,
    extensions: Vec<u16>,
    curves: Vec<u16>,
    point_formats: Vec<u8>,
    signature_algorithms: Vec<u16>,
    alpn: Option<String>,
    sni_present: bool,
}

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

fn extract_client_hello_fingerprint_data(ssl: &mut SslRef) -> ClientHelloFingerprintData {
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

    let signature_algorithms = client_hello_extension_data(ssl, 13)
        .map(|d| parse_signature_algorithms(&d))
        .unwrap_or_default();

    let alpn = client_hello_extension_data(ssl, 16).and_then(|d| parse_alpn(&d));
    let sni_present = extensions.contains(&0);

    ClientHelloFingerprintData {
        version,
        ciphers,
        extensions,
        curves,
        point_formats,
        signature_algorithms,
        alpn,
        sni_present,
    }
}

static JA3_INDEX: OnceLock<Index<Ssl, String>> = OnceLock::new();

pub struct Ja3Fingerprint {
    pub raw: String,
    pub hash: String,
}

pub fn ja3_index() -> &'static Index<Ssl, String> {
    JA3_INDEX.get_or_init(|| Ssl::new_ex_index().unwrap())
}

pub fn compute_ja3_from_client_hello(ssl: &mut SslRef) -> Ja3Fingerprint {
    let fingerprint_data = extract_client_hello_fingerprint_data(ssl);

    let raw = format!(
        "{},{},{},{},{}",
        fingerprint_data.version,
        join_u16(&fingerprint_data.ciphers),
        join_u16(&fingerprint_data.extensions),
        join_u16(&fingerprint_data.curves),
        join_u8(&fingerprint_data.point_formats),
    );

    let hash = format!("{:x}", md5::compute(&raw));

    Ja3Fingerprint { raw, hash }
}

fn client_hello_extension_data(ssl: &mut SslRef, ext_type: u32) -> Option<Vec<u8>> {
    let mut out: *const u8 = std::ptr::null();
    let mut outlen: usize = 0;

    let ret = unsafe {
        SSL_client_hello_get0_ext(ssl.as_ptr() as *mut c_void, ext_type, &mut out, &mut outlen)
    };

    if ret != 1 {
        return None;
    }

    let slice = unsafe { std::slice::from_raw_parts(out, outlen) };
    Some(slice.to_vec())
}

fn client_hello_extensions(ssl: &mut SslRef) -> Vec<u16> {
    let mut out: *mut c_int = std::ptr::null_mut();
    let mut outlen: usize = 0;

    let ret = unsafe {
        SSL_client_hello_get1_extensions_present(ssl.as_ptr() as *mut c_void, &mut out, &mut outlen)
    };

    if ret != 1 {
        return Vec::new();
    }

    let slice: &[c_int] = unsafe { std::slice::from_raw_parts(out, outlen) };
    let result: Vec<u16> = slice.iter().map(|&id| id as u16).collect();
    unsafe { CRYPTO_free(out as *mut c_void, std::ptr::null(), 0) };

    result
}

pub fn parse_supported_groups(data: &[u8]) -> Vec<u16> {
    if data.len() < 2 {
        return Vec::new();
    }
    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    let list = &data[2..];
    if list.len() < list_len {
        return Vec::new();
    }
    list[..list_len]
        .chunks(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .collect()
}

pub fn parse_alpn(data: &[u8]) -> Option<String> {
    if data.len() < 2 {
        return None;
    }

    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    let list = &data[2..];
    if list.len() < list_len {
        return None;
    }

    let protocols = &list[..list_len];
    if protocols.is_empty() {
        return None;
    }

    let first_len = protocols[0] as usize;
    let first_start = 1;
    let first_end = first_start + first_len;

    if protocols.len() < first_end {
        return None;
    }

    std::str::from_utf8(&protocols[first_start..first_end])
        .ok()
        .map(|protocol| protocol.to_string())
}

pub fn parse_signature_algorithms(data: &[u8]) -> Vec<u16> {
    if data.len() < 2 {
        return Vec::new();
    }
    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    let list = &data[2..];

    if list.len() < list_len {
        return Vec::new();
    }
    list[..list_len]
        .chunks(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .collect()
}

pub fn parse_ec_point_formats(data: &[u8]) -> Vec<u8> {
    if data.is_empty() {
        return Vec::new();
    }
    let list_len = data[0] as usize;
    let list = &data[1..];
    if list.len() < list_len {
        return Vec::new();
    }
    list[..list_len].to_vec()
}

pub fn join_u16(items: &[u16]) -> String {
    items
        .iter()
        .map(|x| x.to_string())
        .collect::<Vec<_>>()
        .join("-")
}

pub fn join_u8(items: &[u8]) -> String {
    items
        .iter()
        .map(|x| x.to_string())
        .collect::<Vec<_>>()
        .join("-")
}

pub fn is_grease(items: u16) -> bool {
    let parts = items.to_be_bytes();
    let high_byte = parts[0];
    let low_byte = parts[1];
    let low_nibble = low_byte & 0x0f;

    // GREASE values repeat the same byte and end in the A nibble.
    high_byte == low_byte && low_nibble == 0x0a
}















