//! The listener closes clients that stall, and stops within its grace period.

use super::*;
use axum::routing::get;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// A listener on a free local port, serving `router` until the returned sender is
/// set, and the port's address.
async fn serving(router: Router) -> (SocketAddr, watch::Sender<bool>, JoinSet<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("address");
    let (stop, _) = watch::channel(false);
    let mut server = JoinSet::new();
    let listening = stop.clone();
    server.spawn(async move { Command::listen(listener, router, &listening).await });
    (address, stop, server)
}

/// A client that starts its headers and never finishes them is disconnected once
/// the header-read timeout passes.
#[tokio::test(start_paused = true)]
async fn a_connection_that_never_finishes_its_headers_is_closed() {
    let (address, _stop, _server) = serving(Router::new()).await;
    let mut client = TcpStream::connect(address).await.expect("connect");
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: auth\r\n")
        .await
        .expect("partial headers");
    let started = Instant::now();
    let mut answer = Vec::new();
    client.read_to_end(&mut answer).await.expect("closed");
    assert_eq!(started.elapsed(), HEADER_READ_TIMEOUT);
    assert!(answer.is_empty(), "{}", String::from_utf8_lossy(&answer));
}

/// Once stopped, a listener waits for open requests only for the grace period,
/// then cuts off a request that never ends.
#[tokio::test(start_paused = true)]
async fn a_stop_cuts_off_requests_after_the_grace_period() {
    let router = Router::new().route("/", get(std::future::pending::<()>));
    let (address, stop, mut server) = serving(router).await;
    let mut client = TcpStream::connect(address).await.expect("connect");
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: auth\r\n\r\n")
        .await
        .expect("request");
    // Let the request reach its handler before stopping.
    tokio::task::yield_now().await;
    let started = Instant::now();
    stop.send_replace(true);
    server
        .join_next()
        .await
        .expect("listener")
        .expect("no panic");
    assert_eq!(started.elapsed(), Jobs::SHUTDOWN_GRACE);
    let mut answer = Vec::new();
    client.read_to_end(&mut answer).await.expect("closed");
    assert!(answer.is_empty(), "{}", String::from_utf8_lossy(&answer));
}
