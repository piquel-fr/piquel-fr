//! Serving the public listener and, when configured, the admin dashboard's listener.
//!
//! A stop is bounded: on SIGTERM both listeners stop accepting and jobs are told
//! to stop, at once. Open requests and running jobs then get
//! [`Jobs::SHUTDOWN_GRACE`], concurrently, before they are cut off, and telemetry
//! gets what `Cli::run` allows to flush.

use super::{CliError, Command};
use crate::{AuthConfig, Jobs, KeyStore};
use axum::{
    Router,
    extract::{ConnectInfo, Request},
    serve::Listener,
};
use hyper::{body::Incoming, server::conn::http1};
use hyper_util::{
    rt::{TokioIo, TokioTimer},
    server::graceful::GracefulShutdown,
    service::TowerToHyperService,
};
use sourceorigin_repository::Database;
use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, ready},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{TcpListener, TcpStream},
    sync::watch,
    task::JoinSet,
    time::{Instant, Sleep},
};
use tower::ServiceExt;

/// How long a client may take to send a request's headers, or to start its next
/// request on a kept-alive connection, before the connection is closed.
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a response write may make no progress, as to a client that stopped
/// reading, before the connection is closed.
const WRITE_STALL_TIMEOUT: Duration = Duration::from_secs(10);

impl Command {
    /// Builds the configured service, loads its signing keys, starts background
    /// jobs and serves the public listener, and the admin dashboard's listener when
    /// one is configured, until a shutdown signal. Requests and jobs then get
    /// [`Jobs::SHUTDOWN_GRACE`] to finish.
    pub(super) async fn serve(database: Database) -> Result<(), CliError> {
        let config = AuthConfig::from_environment()?;
        let public = TcpListener::bind(config.public_listener).await?;
        let admin = match &config.dashboard {
            Some(dashboard) => Some((TcpListener::bind(dashboard.listener).await?, dashboard)),
            None => None,
        };
        let store = KeyStore::new(database.clone(), Arc::clone(&config.key_encryption_key));
        let keys = store.start().await?;
        let router = config.router(database.clone(), &keys)?;
        let admin = match admin {
            Some((listener, dashboard)) => Some((
                listener,
                dashboard.listener,
                config.admin_router(database.clone(), &keys, dashboard)?,
            )),
            None => None,
        };
        database.observe_connections();
        let jobs = Jobs::start(&database, &config, &store, &keys)?;
        tracing::info!(address=%config.public_listener,"authentication service listening");
        let (stop, _) = watch::channel(false);
        let admin = async {
            if let Some((listener, address, admin_router)) = admin {
                tracing::info!(%address, "admin dashboard listening");
                Self::listen(listener, admin_router, &stop).await;
            }
        };
        let jobs = async {
            // Fails only once `stop` is dropped, which also means stopping.
            let _ = stop.subscribe().wait_for(|stopped| *stopped).await;
            jobs.shutdown().await
        };
        let signal = async {
            Self::shutdown_signal().await;
            stop.send_replace(true);
        };
        let ((), (), jobs, ()) =
            tokio::join!(Self::listen(public, router, &stop), admin, jobs, signal);
        Ok(jobs?)
    }

    /// Resolves on Ctrl+C or SIGTERM, the signal container runtimes send on stop.
    async fn shutdown_signal() {
        use tokio::signal::unix::{SignalKind, signal};
        let ctrl_c = async {
            if let Err(error) = tokio::signal::ctrl_c().await {
                tracing::error!(?error, "Ctrl+C handler unavailable");
                std::future::pending::<()>().await;
            }
        };
        let terminate = async {
            match signal(SignalKind::terminate()) {
                Ok(mut terminate) => {
                    terminate.recv().await;
                }
                Err(error) => {
                    tracing::error!(?error, "SIGTERM handler unavailable");
                    std::future::pending::<()>().await;
                }
            }
        };
        tokio::select! {
            () = ctrl_c => {}
            () = terminate => {}
        }
        tracing::info!("shutting down");
    }

    /// Serves `router` on `listener` over HTTP/1.1 until `stop` is set, closing
    /// connections that exceed [`HEADER_READ_TIMEOUT`] or [`WRITE_STALL_TIMEOUT`].
    /// Then it stops accepting, lets open requests finish for up to
    /// [`Jobs::SHUTDOWN_GRACE`], and closes whatever is left. Behind piqueld's
    /// ingress, which terminates TLS and HTTP/2, HTTP/1.1 is all auth needs.
    pub(super) async fn listen(
        mut listener: TcpListener,
        router: Router,
        stop: &watch::Sender<bool>,
    ) {
        let mut http = http1::Builder::new();
        http.timer(TokioTimer::new())
            .header_read_timeout(HEADER_READ_TIMEOUT);
        let graceful = GracefulShutdown::new();
        let mut connections = JoinSet::new();
        let mut stopped = stop.subscribe();
        loop {
            // Accepting retries by itself after failures, such as too many open files.
            let (stream, peer) = tokio::select! {
                accepted = Listener::accept(&mut listener) => accepted,
                // Fails only once `stop` is dropped, which also means stopping.
                _ = stopped.wait_for(|stopped| *stopped) => break,
            };
            let service = router
                .clone()
                .map_request(move |mut request: Request<Incoming>| {
                    request.extensions_mut().insert(ConnectInfo(peer));
                    request
                });
            let connection = http.serve_connection(
                TokioIo::new(WriteBounded::new(stream)),
                TowerToHyperService::new(service),
            );
            let connection = graceful.watch(connection);
            connections.spawn(async move {
                if let Err(error) = connection.await {
                    tracing::debug!(%error, %peer, "connection closed on an error");
                }
            });
            // Forget the connections that ended.
            while connections.try_join_next().is_some() {}
        }
        drop(listener);
        if tokio::time::timeout(Jobs::SHUTDOWN_GRACE, graceful.shutdown())
            .await
            .is_err()
        {
            tracing::warn!(
                open = connections.len(),
                "closing connections still open after the grace period"
            );
        }
        // Dropping `connections` cancels the requests still running.
    }
}

/// A connection whose writes fail once they make no progress for
/// [`WRITE_STALL_TIMEOUT`], so a client that stops reading its response cannot
/// keep the connection, and its request's task, forever. Reads need no bound:
/// hyper's header-read timeout and the request deadline cover them.
struct WriteBounded {
    /// The client's connection.
    stream: TcpStream,
    /// Fires [`WRITE_STALL_TIMEOUT`] after the current write stalled.
    deadline: Pin<Box<Sleep>>,
    /// Whether the last write, flush or shutdown is still pending, so `deadline`
    /// is running.
    stalled: bool,
}

impl WriteBounded {
    /// Bounds the writes of `stream`.
    fn new(stream: TcpStream) -> Self {
        Self {
            stream,
            deadline: Box::pin(tokio::time::sleep(WRITE_STALL_TIMEOUT)),
            stalled: false,
        }
    }

    /// Passes on the outcome of a write, flush or shutdown, `poll`, unless it has
    /// been pending since [`WRITE_STALL_TIMEOUT`] ago, which fails it.
    fn bound<T>(&mut self, cx: &mut Context<'_>, poll: Poll<io::Result<T>>) -> Poll<io::Result<T>> {
        if poll.is_ready() {
            self.stalled = false;
            return poll;
        }
        if !self.stalled {
            self.stalled = true;
            self.deadline
                .as_mut()
                .reset(Instant::now() + WRITE_STALL_TIMEOUT);
        }
        ready!(self.deadline.as_mut().poll(cx));
        Poll::Ready(Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "the client stopped reading the response",
        )))
    }
}

impl AsyncRead for WriteBounded {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for WriteBounded {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let poll = Pin::new(&mut this.stream).poll_write(cx, buf);
        this.bound(cx, poll)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let poll = Pin::new(&mut this.stream).poll_write_vectored(cx, bufs);
        this.bound(cx, poll)
    }

    fn is_write_vectored(&self) -> bool {
        self.stream.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let poll = Pin::new(&mut this.stream).poll_flush(cx);
        this.bound(cx, poll)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let poll = Pin::new(&mut this.stream).poll_shutdown(cx);
        this.bound(cx, poll)
    }
}

/// The listener's timeouts and its bounded drain.
#[cfg(test)]
mod tests;
