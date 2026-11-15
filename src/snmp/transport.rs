//! A device's UDP socket, behind one async client: a blocking socket on
//! a thread of the device's own, or with feature `tokio` a task on one
//! runtime thread for every device.

use std::io;
use std::time::Duration;

/// A device on the LAN answers in milliseconds: a dead one is given up
/// on soon.
pub const TIMEOUT: Duration = Duration::from_secs(1);

pub trait Transport: Sized {
    /// `address` with its port, or 161.
    async fn connect(address: &str) -> io::Result<Self>;
    async fn send(&mut self, bytes: &[u8]) -> io::Result<()>;
    /// A datagram, or TimedOut after TIMEOUT.
    async fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize>;
}

fn with_port(address: &str) -> String {
    if address.contains(':') {
        address.to_owned()
    } else {
        format!("{address}:161")
    }
}

/// Blocks in each call: its futures are ready when first polled.
#[cfg(not(feature = "tokio"))]
pub struct Blocking(std::net::UdpSocket);

#[cfg(not(feature = "tokio"))]
impl Transport for Blocking {
    async fn connect(address: &str) -> io::Result<Self> {
        let socket = std::net::UdpSocket::bind("0.0.0.0:0")?;
        socket.connect(with_port(address))?;
        socket.set_read_timeout(Some(TIMEOUT))?;
        Ok(Blocking(socket))
    }

    async fn send(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.0.send(bytes).map(drop)
    }

    async fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.recv(buf).map_err(|error| match error.kind() {
            io::ErrorKind::WouldBlock => io::ErrorKind::TimedOut.into(),
            _ => error,
        })
    }
}

/// Runs a future of a `Blocking` transport, which never waits.
#[cfg(not(feature = "tokio"))]
pub fn block_on<F: Future>(future: F) -> F::Output {
    use std::task::{Context, Poll, Waker};
    let mut context = Context::from_waker(Waker::noop());
    match std::pin::pin!(future).poll(&mut context) {
        Poll::Ready(output) => output,
        Poll::Pending => unreachable!("a blocking socket never waits"),
    }
}

#[cfg(feature = "tokio")]
pub struct Tokio(tokio::net::UdpSocket);

#[cfg(feature = "tokio")]
impl Transport for Tokio {
    async fn connect(address: &str) -> io::Result<Self> {
        let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
        socket.connect(with_port(address)).await?;
        Ok(Tokio(socket))
    }

    async fn send(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.0.send(bytes).await.map(drop)
    }

    async fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        tokio::time::timeout(TIMEOUT, self.0.recv(buf))
            .await
            .unwrap_or_else(|_| Err(io::ErrorKind::TimedOut.into()))
    }
}
