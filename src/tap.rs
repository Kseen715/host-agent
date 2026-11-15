//! A live view of what flows to one sink, for one HTTP client at a time
//! (crate::server): each line is written through as it passes, never
//! kept, and a client that cannot take it at once is let go.

use std::io::Write;
use std::net::TcpStream;

#[derive(Default)]
pub struct Tap(Option<TcpStream>);

impl Tap {
    /// The client a response's body now streams to, in place of any
    /// before it.
    pub fn open(&mut self, stream: TcpStream) {
        let started = stream.set_nonblocking(true).is_ok();
        self.0 = started.then_some(stream);
    }

    pub fn is_open(&self) -> bool {
        self.0.is_some()
    }

    pub fn line(&mut self, text: &str) {
        let Some(stream) = self.0.as_mut() else {
            return;
        };
        let sent = stream.write_all(text.as_bytes());
        if sent.and_then(|()| stream.write_all(b"\n")).is_err() {
            self.0 = None;
        }
    }
}
