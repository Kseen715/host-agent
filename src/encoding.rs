//! Base64 and URL percent-encoding, as Go's encoding/base64 and
//! net/url spell them.

const BASE64: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const BASE64_URL: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Standard base64 with padding.
pub fn base64(data: &[u8]) -> String {
    base64_in(data, BASE64)
}

/// The URL-safe alphabet, with padding (Go's URLEncoding).
pub fn base64_url(data: &[u8]) -> String {
    base64_in(data, BASE64_URL)
}

pub fn from_base64(text: &str) -> Option<Vec<u8>> {
    from_base64_in(text, BASE64)
}

pub fn from_base64_url(text: &str) -> Option<Vec<u8>> {
    from_base64_in(text, BASE64_URL)
}

fn base64_in(data: &[u8], alphabet: &[u8; 64]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let bytes = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = u32::from_be_bytes([0, bytes[0], bytes[1], bytes[2]]);
        for i in 0..4 {
            if i <= chunk.len() {
                let at = (n >> (18 - 6 * i)) & 63;
                out.push(char::from(alphabet[at as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// Base64, padded or not; None if not base64.
fn from_base64_in(text: &str, alphabet: &[u8; 64]) -> Option<Vec<u8>> {
    let text = text.trim_end_matches('=');
    if text.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    let (mut bits, mut count) = (0u32, 0);
    for byte in text.bytes() {
        let value = alphabet.iter().position(|&b| b == byte)?;
        bits = bits << 6 | value as u32;
        count += 6;
        if count >= 8 {
            count -= 8;
            out.push((bits >> count) as u8);
        }
    }
    Some(out)
}

/// Go's url.QueryEscape: a form value, spaces as `+`.
pub fn query_escape(text: &str) -> String {
    escape(text, true)
}

fn escape(text: &str, query: bool) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        match byte {
            b'A'..=b'Z'
            | b'a'..=b'z'
            | b'0'..=b'9'
            | b'-'
            | b'_'
            | b'.'
            | b'~' => out.push(char::from(byte)),
            b' ' if query => out.push('+'),
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// RFC 3986's percent-encoding: all but the unreserved characters, as
/// AWS's canonical requests take it.
pub fn uri_escape(text: &str) -> String {
    escape(text, false)
}

/// Go's url.QueryUnescape (`+` is a space) or PathUnescape.
pub fn unescape(text: &str, query: bool) -> Option<String> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        match bytes[at] {
            b'%' => {
                let hex = text.get(at + 1..at + 3)?;
                out.push(u8::from_str_radix(hex, 16).ok()?);
                at += 3;
                continue;
            }
            b'+' if query => out.push(b' '),
            byte => out.push(byte),
        }
        at += 1;
    }
    String::from_utf8(out).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        for text in ["", "f", "fo", "foo", "foob", "fooba", "foobar"] {
            let encoded = base64(text.as_bytes());
            assert_eq!(from_base64(&encoded).unwrap(), text.as_bytes());
        }
        assert_eq!(base64(b"user:pass"), "dXNlcjpwYXNz");
        assert!(from_base64("a").is_none());
        assert_eq!(query_escape("a b&c/é"), "a+b%26c%2F%C3%A9");
        assert_eq!(base64_url(&[0xfb, 0xff]), "-_8=");
        assert_eq!(unescape("a+b%26", true).unwrap(), "a b&");
        assert_eq!(unescape("a+b%26", false).unwrap(), "a+b&");
    }
}
