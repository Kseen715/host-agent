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

#[cfg(test)]
mod tests {
    use super::super::request;
    use super::super::tls::{Settings, Tls};
    use super::*;
    use crate::testing::{self, CA, response};
    use std::sync::{Arc, Mutex};

    type Seen = Arc<Mutex<Vec<String>>>;

    /// An HTTPS server that speaks h2 only, agreed on by ALPN: it
    /// answers what it was sent, and `/moved` with a 303 to `/echo`.
    fn serve_h2() -> (u16, Seen) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen = Seen::default();
        let kept = Arc::clone(&seen);
        std::thread::spawn(move || {
            let runtime = Builder::new_current_thread().enable_all().build();
            runtime.unwrap().block_on(accept(listener, kept));
        });
        (port, seen)
    }

    async fn accept(listener: std::net::TcpListener, seen: Seen) {
        let mut config = testing::server_config();
        config.alpn_protocols = vec![b"h2".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        listener.set_nonblocking(true).unwrap();
        let listener = tokio::net::TcpListener::from_std(listener).unwrap();
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let stream = acceptor.accept(stream).await.unwrap();
            let mut connection = h2::server::handshake(stream).await.unwrap();
            // Each stream answered alongside: the connection, polled
            // here, is what moves their frames.
            while let Some(Ok((request, respond))) = connection.accept().await {
                tokio::spawn(answer(request, respond, Arc::clone(&seen)));
            }
        }
    }

    async fn answer(
        request: http::Request<h2::RecvStream>,
        mut respond: h2::server::SendResponse<Bytes>,
        seen: Seen,
    ) {
        let (head, mut body) = request.into_parts();
        let mut data = Vec::new();
        while let Some(Ok(chunk)) = body.data().await {
            data.extend_from_slice(&chunk);
        }
        let header = head.headers.get("x-a").map(|v| v.to_str().unwrap());
        let text = format!(
            "{} {} x-a={} {}",
            head.method,
            head.uri.path(),
            header.unwrap_or_default(),
            String::from_utf8_lossy(&data)
        );
        seen.lock().unwrap().push(text.clone());
        let status = if head.uri.path() == "/moved" {
            303
        } else {
            200
        };
        let answer = http::Response::builder()
            .status(status)
            .header("location", "/echo")
            .body(())
            .unwrap();
        let mut send = respond.send_response(answer, false).unwrap();
        send.send_data(Bytes::from(text), true).unwrap();
    }

    fn client() -> Client {
        let settings = Settings {
            ca: Some(CA.into()),
            ..Settings::default()
        };
        Client {
            tls: Some(Tls::new(&settings).unwrap()),
            http2: true,
            ..Client::default()
        }
    }

    #[test]
    fn speaks_h2_when_the_server_picks_it() {
        let (port, seen) = serve_h2();
        let url = |path: &str| {
            Url::parse(&format!("https://localhost:{port}{path}")).unwrap()
        };
        // Connection is HTTP/1.1's alone: h2 refuses a request with it.
        let headers = "X-A: 1\r\nConnection: close\r\n";
        let echo = request(&url("/echo"), &client(), "POST", headers, b"hi");
        let echo = echo.unwrap();
        assert_eq!(
            (echo.status, &echo.body[..]),
            (200, &b"POST /echo x-a=1 hi"[..])
        );
        let moved = request(&url("/moved"), &client(), "POST", "", b"x");
        assert_eq!(&moved.unwrap().body[..], b"GET /echo x-a= ");
        assert_eq!(
            *seen.lock().unwrap(),
            [
                "POST /echo x-a=1 hi",
                "POST /moved x-a= x",
                "GET /echo x-a= "
            ]
        );
    }

    #[test]
    fn falls_back_to_http1_when_the_server_picks_it() {
        let server = testing::serve_tls(|r| {
            response(
                "200 OK",
                "text/plain",
                &format!("{} {}", r.method, r.path),
            )
        });
        let port = server.address.port();
        let url = Url::parse(&format!("https://localhost:{port}/a")).unwrap();
        let answer = request(&url, &client(), "GET", "", &[]).unwrap();
        assert_eq!(&answer.body[..], b"GET /a");
    }
}
