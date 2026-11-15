//! Credentials sent with each request, as Prometheus's HTTP client
//! sends them: basic_auth, authorization (bearer tokens among them),
//! and OAuth2's client credentials grant.

use super::{Client, Url};
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
    OAuth2(Arc<OAuth2>),
}

impl Auth {
    /// The Authorization header line, if any.
    pub fn header(&self) -> io::Result<String> {
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
            Auth::OAuth2(oauth) => oauth.token()?,
        };
        Ok(format!("Authorization: {value}\r\n"))
    }
}

fn read(secret: Option<&Secret>) -> io::Result<String> {
    secret.map_or(Ok(String::new()), Secret::read)
}

/// x/oauth2's client credentials: a token asked for at `token_url`,
/// kept until 10 s before it expires.
pub struct OAuth2 {
    pub client_id: String,
    pub secret: Secret,
    pub scopes: Vec<String>,
    pub token_url: Url,
    pub params: Vec<(String, String)>,
    /// How the token endpoint is reached: its proxy and TLS.
    pub client: Client,
    pub token: Mutex<Option<(String, Option<Instant>)>>,
}

/// x/oauth2's expiryDelta.
const EARLY: Duration = Duration::from_secs(10);

impl OAuth2 {
    /// `<type> <access token>`, asked for when there is none still good.
    fn token(&self) -> io::Result<String> {
        let mut token = self.token.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((value, expiry)) = token.as_ref() {
            if expiry.is_none_or(|at| Instant::now() + EARLY < at) {
                return Ok(value.clone());
            }
        }
        let fresh = self.ask()?;
        *token = Some(fresh.clone());
        Ok(fresh.0)
    }

    /// The credentials in an Authorization header first, then in the
    /// form, as x/oauth2 probes a server's style.
    fn ask(&self) -> io::Result<(String, Option<Instant>)> {
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
        match self.post(&form, &header) {
            Ok(token) => Ok(token),
            Err(_) => {
                form.push(("client_id".into(), self.client_id.clone()));
                if !secret.is_empty() {
                    form.push(("client_secret".into(), secret));
                }
                self.post(&form, "")
            }
        }
    }

    fn post(
        &self,
        form: &[(String, String)],
        header: &str,
    ) -> io::Result<(String, Option<Instant>)> {
        let mut form = form.to_vec();
        form.sort();
        let body: Vec<String> = form
            .iter()
            .map(|(k, v)| format!("{}={}", query_escape(k), query_escape(v)))
            .collect();
        let headers = format!(
            "Content-Type: application/x-www-form-urlencoded\r\n{header}"
        );
        let url = &self.token_url;
        let response = super::post(
            url,
            &self.client,
            &headers,
            body.join("&").as_bytes(),
        )?;
        let text = String::from_utf8_lossy(&response.body);
        if !response.ok() {
            let message =
                format!("oauth2: token: {} {}", response.status, text.trim());
            return Err(io::Error::other(message));
        }
        parse_token(&text)
    }
}

fn parse_token(text: &str) -> io::Result<(String, Option<Instant>)> {
    let json = Json::parse(text)
        .ok_or_else(|| io::Error::other("oauth2: token: not JSON"))?;
    let access = json.get("access_token").and_then(Json::str).unwrap_or("");
    if access.is_empty() {
        return Err(io::Error::other("oauth2: no access_token"));
    }
    let kind = json.get("token_type").and_then(Json::str).unwrap_or("");
    let kind = match kind.to_ascii_lowercase().as_str() {
        "" | "bearer" => "Bearer",
        "mac" => "MAC",
        "basic" => "Basic",
        _ => kind,
    };
    let expires = json
        .get("expires_in")
        .and_then(|v| v.num().or_else(|| v.str().and_then(|s| s.parse().ok())));
    let expiry = expires
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
        assert_eq!(basic.header().unwrap(), "Authorization: Basic dTpw\r\n");
        let empty = Auth::Header {
            kind: "Bearer".into(),
            credentials: None,
        };
        assert_eq!(empty.header().unwrap(), "");
        let (token, expiry) =
            parse_token(r#"{"access_token":"t","expires_in":"60"}"#).unwrap();
        assert_eq!(token, "Bearer t");
        assert!(expiry.is_some());
    }
}
