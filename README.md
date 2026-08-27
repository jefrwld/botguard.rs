# botguard.rs

A Rust-based reverse proxy that extracts TLS JA3 fingerprints from ClientHello messages and uses them for configurable traffic decisions.

The project is built with Pingora and OpenSSL. Its main goal is to demonstrate TLS ClientHello parsing, Rust FFI usage, fingerprint-based request filtering, and clean Rust project structure.

## Features

- Reverse proxy built with Pingora
- TLS listener with OpenSSL ClientHello callback
- JA3 fingerprint extraction and MD5 hashing
- Configurable blocklist-based decision engine
- OpenSSL `ex_data` usage to pass fingerprint data from the TLS layer into request filtering
- Parser helpers for TLS extension byte data
- Experimental JA4-style fingerprinting support

## Architecture

```text
TLS Client
   |
   v
Pingora TLS Listener
   |
   v
ClientHello Callback
   |
   v
JA3 Fingerprint Extraction
   |
   v
Store JA3 Hash in OpenSSL ex_data
   |
   v
Request Filter
   |
   v
Config Decision Engine
   |
   v
Allow / Block / Forward
```

## How It Works

During the TLS handshake, the proxy reads the ClientHello message through OpenSSL callback APIs. It extracts the fields needed for JA3, builds the JA3 string, hashes it with MD5, and stores the hash on the SSL object with OpenSSL `ex_data`.

Later, when Pingora processes the HTTP request, the proxy reads the stored fingerprint and checks it against the configured blocklist. Matching fingerprints are blocked with HTTP `403`; all other requests are forwarded upstream.

## Configuration

Create a `config.yaml` file:

```yaml
blocked_fingerprints:
  - "e7d705a3286e19ea42f587b344ee6865"
```

An example file is available at `botguard/config.example.yaml`.

## Running Locally

From the project root:

```bash
cd botguard
cargo run
```

The proxy listens on:

- TCP: `0.0.0.0:8080`
- TLS: `0.0.0.0:8443`

## Example Output

```text
JA3 String: 771,4865-4866-4867,0-10-11-13-16-43,29-23-24,0
JA3 Hash:   e7d705a3286e19ea42f587b344ee6865
JA4 String: t13d0305h2_8daaf6152771_02713d6af862
```

## Project Structure

```text
botguard/src/main.rs            Proxy startup and Pingora service wiring
botguard/src/config.rs          YAML configuration loading
botguard/src/tls.rs             TLS certificate and key loading
botguard/src/fingerprinting.rs  JA3, experimental JA4, TLS extension parsing
```

## Tests

The parser and fingerprint helper functions have focused unit tests:

```bash
cd botguard
cargo test
```

## Current Limitations

- JA3 is the primary implemented fingerprinting feature.
- JA4 support is experimental and should be validated against official test vectors before being described as a complete JA4 implementation.
- The decision engine currently uses a static fingerprint blocklist.
- The upstream target is currently hardcoded for demonstration purposes.
- This is a learning and portfolio project, not production WAF software.

## What I Learned

- Parsing binary TLS extension data in Rust
- Working with `Vec<u8>`, slices, `u8`, `u16`, and big-endian byte order
- Using `Option` and `Result` for fallible parsing and control flow
- Calling OpenSSL APIs through Rust FFI
- Keeping `unsafe` blocks small and converting raw C data into owned Rust values
- Passing TLS-layer data into request filtering with OpenSSL `ex_data`
- Structuring a Rust proxy project into focused modules

## AI Assistance

This project was developed with AI assistance. I used it as a learning partner while independently reviewing, refactoring, documenting, and validating the Rust, TLS, and proxy concepts.
