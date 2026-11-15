//! HTTP/2 over TLS, as Go's client speaks it with enable_http2: h2 and
//! http/1.1 offered by ALPN, and HTTP/1.1 on the same connection when
//! the server picks it. One connection per request, as for HTTP/1.1
//! here; driven by a tokio runtime of the calling thread's own.

use super::{Client, MAX_RESPONSE, Response, Url, broken, tls};
use bytes::Bytes;
use std::future::{Future, poll_fn};
use std::io;
use std::net::TcpStream;
use std::pin::pin;
use std::task::Poll;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::runtime::{Builder, Runtime};
use tokio_rustls::TlsConnector;

/// Headers HTTP/2 forbids or carries as pseudo-headers.
const HOP: [&str; 6] = [
    "connection",
    "host",
    "keep-alive",
    "proxy-connection",
    "transfer-encoding",
    "upgrade",
];

thread_local! {
    static RUNTIME: io::Result<Runtime> =
        Builder::new_current_thread().enable_all().build();
}

pub struct Request<'a> {
    pub method: &'a str,
    pub url: &'a Url,
    /// Header lines, each ending in CR LF.
    pub lines: &'a str,
    /// The same request for HTTP/1.1, head whole.
    pub head: &'a [u8],
    pub body: &'a [u8],
}

/// The request on `stream`, within the client's timeout.
pub fn exchange(
    stream: TcpStream,
    client: &Client,
    request: &Request,
) -> io::Result<(Response, Option<String>)> {
    RUNTIME.with(|runtime| {
        let runtime = runtime
            .as_ref()
            .map_err(|e| io::Error::new(e.kind(), e.to_string()))?;
        runtime.block_on(async {
            let exchange = over_tls(stream, client, request);
            tokio::time::timeout(client.timeout, exchange)
                .await
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::TimedOut, "timed out")
                })?
        })
    })
}

async fn over_tls(
    stream: TcpStream,
    client: &Client,
    request: &Request<'_>,
) -> io::Result<(Response, Option<String>)> {
    stream.set_nonblocking(true)?;
    let stream = tokio::net::TcpStream::from_std(stream)?;
    let (config, name) = tls::alpn(request.url, client.tls.as_ref())?;
    let stream = TlsConnector::from(config).connect(name, stream).await?;
    match stream.get_ref().1.alpn_protocol() {
        Some(b"h2") => http2(stream, request).await,
        _ => http1(stream, request).await,
    }
}

async fn http1(
    mut stream: impl AsyncRead + AsyncWrite + Unpin,
    request: &Request<'_>,
) -> io::Result<(Response, Option<String>)> {
    stream.write_all(request.head).await?;
    stream.write_all(request.body).await?;
    stream.flush().await?;
    let mut raw = Vec::new();
    super::ended(stream.take(MAX_RESPONSE).read_to_end(&mut raw).await)?;
    super::parse_response(raw)
}

async fn http2(
    stream: impl AsyncRead + AsyncWrite + Unpin,
    request: &Request<'_>,
) -> io::Result<(Response, Option<String>)> {
    let (send, connection) =
        h2::client::handshake(stream).await.map_err(other)?;
    let mut exchange = pin!(send_request(send, request));
    let mut connection = pin!(connection);
    // The connection is driven alongside, never spawned: it ends with
    // the request.
    poll_fn(|cx| {
        if let Poll::Ready(done) = exchange.as_mut().poll(cx) {
            return Poll::Ready(done);
        }
        match connection.as_mut().poll(cx) {
            Poll::Ready(Err(e)) => Poll::Ready(Err(other(e))),
            Poll::Ready(Ok(())) => {
                Poll::Ready(Err(broken("connection closed")))
            }
            Poll::Pending => Poll::Pending,
        }
    })
    .await
}

async fn send_request(
    send: h2::client::SendRequest<Bytes>,
    request: &Request<'_>,
) -> io::Result<(Response, Option<String>)> {
    let mut send = send.ready().await.map_err(other)?;
    let url = request.url;
    let mut builder = http::Request::builder()
        .method(request.method)
        .uri(format!("https://{}{}", url.host, url.path));
    for line in request.lines.split("\r\n") {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if !HOP.iter().any(|hop| name.trim().eq_ignore_ascii_case(hop)) {
            builder = builder.header(name.trim(), value.trim());
        }
    }
    let head = builder.body(()).map_err(other)?;
    let empty = request.body.is_empty();
    let (response, mut body) = send.send_request(head, empty).map_err(other)?;
    if !empty {
        let data = Bytes::copy_from_slice(request.body);
        body.send_data(data, true).map_err(other)?;
    }
    let response = response.await.map_err(other)?;
    let status = response.status().as_u16();
    let location = response.headers().get("location");
    let location = location.and_then(|l| l.to_str().ok()).map(str::to_owned);
    let mut body = response.into_body();
    let mut data = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk.map_err(other)?;
        let _ = body.flow_control().release_capacity(chunk.len());
        data.extend_from_slice(&chunk);
        if data.len() as u64 >= MAX_RESPONSE {
            data.truncate(MAX_RESPONSE as usize);
            break;
        }
    }
    Ok((Response { status, body: data }, location))
}

fn other(error: impl std::error::Error + Send + Sync + 'static) -> io::Error {
    io::Error::other(error)
}
