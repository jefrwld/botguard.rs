use async_trait::async_trait;
use pingora::prelude::*;
use pingora::proxy::{ProxyHttp, Session};

fn main() {
    let mut server = Server::new(None).unwrap();
    server.bootstrap();

    let proxy = BotGuardProxy;
    let mut proxy_service = http_proxy_service(&server.configuration, proxy);
    proxy_service.add_tcp("0.0.0.0:8080");

    server.add_service(proxy_service);
    server.run_forever();
}

pub struct BotGuardProxy;

#[async_trait]
impl ProxyHttp for BotGuardProxy {
    type CTX = ();

    fn new_ctx(&self) -> Self::CTX {
        ()
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
