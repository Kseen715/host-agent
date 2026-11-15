//! Credentials sent with each request, as Prometheus's HTTP client
//! sends them: basic_auth, authorization (bearer tokens among them),
//! OAuth2's client credentials grant, and remote_write's cloud
//! sign-ins (sigv4.rs, azure.rs, google.rs).

use super::{Client, Response, Url};
use crate::encoding::{base64, query_escape};
use crate::json::Json;
use std::fs;
use std::io;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// A credential given inline, or a file read on every request so a
/// rotated one is picked up.
#[derive(Clone)]
pub enum Secret {
    Text(String),
    File(PathBuf),
}

impl Secret {
    pub fn read(&self) -> io::Result<String> {
        match self {
            Secret::Text(text) => Ok(text.clone()),
            Secret::File(path) => {
                let text = fs::read_to_string(path).map_err(|e| {
                    io::Error::new(e.kind(), format!("{}: {e}", path.display()))
                })?;
                Ok(text.trim().to_owned())
            }
        }
    }
}

/// The request credentials go with: SigV4 signs all of it.
pub struct Request<'a> {
    pub method: &'a str,
    pub url: &'a Url,
    /// Header lines, each ending in CR LF.
    pub headers: &'a str,
    pub body: &'a [u8],
}

#[derive(Clone, Default)]
pub enum Auth {
    #[default]
    None,
    Basic {
        user: String,
        password: Option<Secret>,
    },
    /// `Authorization: <kind> <credentials>`, sent when not empty.
    Header {
        kind: String,
        credentials: Option<Secret>,
    },
    /// An Authorization value asked for and kept: OAuth2, Azure AD,
    /// Google.
    Token(Arc<Tokens>),
    SigV4(Arc<super::sigv4::SigV4>),
}

impl Auth {
    /// The header lines `request` is sent with, if any.
    pub fn header(&self, request: &Request) -> io::Result<String> {
        let value = match self {
            Auth::None => return Ok(String::new()),
            Auth::Basic { user, password } => {
                let password = read(password.as_ref())?;
                format!(
                    "Basic {}",
                    base64(format!("{user}:{password}").as_bytes())
                )
            }
            Auth::Header { kind, credentials } => {
                let credentials = read(credentials.as_ref())?;
                if credentials.is_empty() {
                    return Ok(String::new());
                }
                format!("{kind} {credentials}")
            }
            Auth::Token(tokens) => tokens.get()?,
            Auth::SigV4(sigv4) => return sigv4.sign(request),
        };
        Ok(format!("Authorization: {value}\r\n"))
    }
}

fn read(secret: Option<&Secret>) -> io::Result<String> {
    secret.map_or(Ok(String::new()), Secret::read)
}

/// A value and when it stops being good, if it does.
pub type Expiring<T> = (T, Option<Instant>);

/// Asks for a token.
pub type Fetch = Box<dyn Fn() -> io::Result<Expiring<String>> + Send + Sync>;

/// A token kept until `early` before it expires, then asked for again.
pub struct Tokens {
    fetch: Fetch,
    early: Duration,
    kept: Mutex<Option<Expiring<String>>>,
}

impl Tokens {
    pub fn new(early: Duration, fetch: Fetch) -> Tokens {
        Tokens {
            fetch,
            early,
            kept: Mutex::new(None),
        }
    }

    fn get(&self) -> io::Result<String> {
        let mut kept = self.kept.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((value, expiry)) = kept.as_ref() {
            if expiry.is_none_or(|at| Instant::now() + self.early < at) {
                return Ok(value.clone());
            }
        }
        let fresh = (self.fetch)()?;
        *kept = Some(fresh.clone());
        Ok(fresh.0)
    }
}

/// x/oauth2's client credentials: a token asked for at `token_url`.
pub struct OAuth2 {
    pub client_id: String,
    pub secret: Secret,
    pub scopes: Vec<String>,
    pub token_url: Url,
    pub params: Vec<(String, String)>,
    /// How the token endpoint is reached: its proxy and TLS.
    pub client: Client,
}

/// x/oauth2's expiryDelta.
pub const EARLY: Duration = Duration::from_secs(10);

impl OAuth2 {
    pub fn tokens(self) -> Tokens {
        Tokens::new(EARLY, Box::new(move || self.ask()))
    }

    /// The credentials in an Authorization header first, then in the
    /// form, as x/oauth2 probes a server's style.
    fn ask(&self) -> io::Result<Expiring<String>> {
        let secret = self.secret.read()?;
        let mut form =
            vec![("grant_type".to_owned(), "client_credentials".into())];
        if !self.scopes.is_empty() {
            form.push(("scope".into(), self.scopes.join(" ")));
        }
        for (key, value) in &self.params {
            form.retain(|(k, _)| k != key);
            form.push((key.clone(), value.clone()));
        }
        let basic = format!(
            "{}:{}",
            query_escape(&self.client_id),
            query_escape(&secret)
        );
        let header =
            format!("Authorization: Basic {}\r\n", base64(basic.as_bytes()));
        let url = &self.token_url;
        match form_token(url, &self.client, &form, &header) {
            Ok(token) => Ok(token),
            Err(_) => {
                form.push(("client_id".into(), self.client_id.clone()));
                if !secret.is_empty() {
                    form.push(("client_secret".into(), secret));
                }
                form_token(url, &self.client, &form, "")
            }
        }
    }
}

/// A token from an OAuth2 token endpoint: `form` posted, sorted as Go's
/// url.Values encodes it.
pub fn form_token(
    url: &Url,
    client: &Client,
    form: &[(String, String)],
    header: &str,
) -> io::Result<Expiring<String>> {
    let mut form = form.to_vec();
    form.sort();
    let body: Vec<String> = form
        .iter()
        .map(|(k, v)| format!("{}={}", query_escape(k), query_escape(v)))
        .collect();
    let headers =
        format!("Content-Type: application/x-www-form-urlencoded\r\n{header}");
    let response =
        super::post(url, client, &headers, body.join("&").as_bytes())?;
    json_token(&response)
}

/// A token from a JSON answer: OAuth2's, or a metadata server's.
pub fn json_token(response: &Response) -> io::Result<Expiring<String>> {
    let text = String::from_utf8_lossy(&response.body);
    if !response.ok() {
        let message = format!("token: {} {}", response.status, text.trim());
        return Err(io::Error::other(message));
    }
    parse_token(&text)
}

/// `access_token`, `token_type`, and `expires_in` in seconds from now or
/// `expires_on` in seconds since the epoch (Azure's), numbers or text.
fn parse_token(text: &str) -> io::Result<Expiring<String>> {
    let json =
        Json::parse(text).ok_or_else(|| io::Error::other("token: not JSON"))?;
    let access = json.get("access_token").and_then(Json::str).unwrap_or("");
    if access.is_empty() {
        return Err(io::Error::other("token: no access_token"));
    }
    let kind = json.get("token_type").and_then(Json::str).unwrap_or("");
    let kind = match kind.to_ascii_lowercase().as_str() {
        "" | "bearer" => "Bearer",
        "mac" => "MAC",
        "basic" => "Basic",
        _ => kind,
    };
    let number = |key| {
        let value = json.get(key)?;
        value.num().or_else(|| value.str()?.parse().ok())
    };
    let now_s = crate::time::now_ms() as f64 / 1e3;
    let left = number("expires_in")
        .or_else(|| number("expires_on").map(|at| at - now_s));
    let expiry = left
        .filter(|s| *s > 0.0)
        .map(|s| Instant::now() + Duration::from_secs_f64(s));
    Ok((format!("{kind} {access}"), expiry))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sends_credentials() {
        let basic = Auth::Basic {
            user: "u".into(),
            password: Some(Secret::Text("p".into())),
        };
        let url = Url::parse("http://h/").unwrap();
        let request = Request {
            method: "GET",
            url: &url,
            headers: "",
            body: &[],
        };
        let header = basic.header(&request).unwrap();
        assert_eq!(header, "Authorization: Basic dTpw\r\n");
        let empty = Auth::Header {
            kind: "Bearer".into(),
            credentials: None,
        };
        assert_eq!(empty.header(&request).unwrap(), "");
        let (token, expiry) =
            parse_token(r#"{"access_token":"t","expires_in":"60"}"#).unwrap();
        assert_eq!(token, "Bearer t");
        assert!(expiry.is_some());
    }
}
