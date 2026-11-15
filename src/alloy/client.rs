//! Alloy's HTTP client settings (`HTTPClientConfig`), squashed into
//! prometheus.scrape and the endpoints of prometheus.remote_write and
//! loki.write: auth, headers, proxy, redirects, TLS.

use super::compile::Body;
use crate::http::Client;
use crate::http::auth::{Auth, OAuth2, Secret};
use crate::http::proxy::{Proxy, Route};
use std::sync::Arc;
use std::time::Duration;

const PROXY_ATTRS: [&str; 4] = [
    "proxy_url",
    "no_proxy",
    "proxy_from_environment",
    "proxy_connect_header",
];

pub const ATTRS: [&str; 9] = [
    "bearer_token",
    "bearer_token_file",
    "follow_redirects",
    "enable_http2",
    "http_headers",
    PROXY_ATTRS[0],
    PROXY_ATTRS[1],
    PROXY_ATTRS[2],
    PROXY_ATTRS[3],
];

pub const BLOCKS: [&str; 4] =
    ["basic_auth", "authorization", "oauth2", "tls_config"];

/// Headers Prometheus will not let a configuration set.
const RESERVED: [&str; 17] = [
    "authorization",
    "host",
    "content-encoding",
    "content-length",
    "content-type",
    "user-agent",
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "www-authenticate",
    "accept-encoding",
    "x-prometheus-remote-write-version",
    "x-prometheus-scrape-timeout-seconds",
    "x-amz-date",
    "x-amz-security-token",
    "x-amz-content-sha256",
];

/// `own` and the client's attributes or blocks, for Body::check.
pub fn with<'a>(own: &[&'a str], client: &[&'a str]) -> Vec<&'a str> {
    [own, client].concat()
}

/// The client `body` configures, with requests timed out at `timeout`.
pub fn http(body: &Body, timeout: Duration) -> Result<Client, String> {
    // HTTP/1.1 only: HTTP/2 changes how, not what, is sent.
    body.bool_or("enable_http2", true)?;
    let mut client = Client {
        timeout,
        headers: header_lines(body, "http_headers")?,
        auth: auth(body, timeout)?,
        follow_redirects: body.bool_or("follow_redirects", true)?,
        proxy: proxy(body)?,
        #[cfg(feature = "tls")]
        tls: None,
    };
    tls(body, &mut client)?;
    Ok(client)
}

/// `{ name = ["value", ...] }` as header lines.
fn header_lines(body: &Body, attr: &str) -> Result<String, String> {
    let lists = body.object_lists(attr)?;
    let pairs = lists.into_iter().flat_map(|(name, values)| {
        values.into_iter().map(move |v| (name.clone(), v))
    });
    headers(body, attr, pairs)
}

/// Header lines, names Prometheus reserves refused.
pub fn headers(
    body: &Body,
    attr: &str,
    pairs: impl IntoIterator<Item = (String, String)>,
) -> Result<String, String> {
    let mut lines = String::new();
    for (name, value) in pairs {
        if RESERVED.contains(&name.to_ascii_lowercase().as_str()) {
            let message = format!("setting header `{name}` is not allowed");
            return Err(body.error(body.attr_pos(attr), &message));
        }
        lines.push_str(&line(body, attr, &name, &value)?);
    }
    Ok(lines)
}

/// One `name: value` line; CR, LF and a bad name refused.
fn line(
    body: &Body,
    attr: &str,
    name: &str,
    value: &str,
) -> Result<String, String> {
    let token =
        |c: char| c.is_ascii_alphanumeric() || "!#$%&'*+-.^_`|~".contains(c);
    if name.is_empty()
        || !name.chars().all(token)
        || value.contains(['\r', '\n'])
    {
        let message = format!("`{attr}`: header `{name}` is not valid");
        return Err(body.error(body.attr_pos(attr), &message));
    }
    Ok(format!("{name}: {value}\r\n"))
}

fn auth(body: &Body, timeout: Duration) -> Result<Auth, String> {
    let given = [
        body.block("basic_auth").is_some(),
        body.block("authorization").is_some(),
        body.block("oauth2").is_some(),
        body.value("bearer_token")?.is_some(),
        body.value("bearer_token_file")?.is_some(),
    ];
    if given.iter().filter(|g| **g).count() > 1 {
        let message = "at most one of basic_auth, authorization, oauth2, \
            bearer_token & bearer_token_file must be configured";
        return Err(body.error(body.block.pos, message));
    }
    if let Some(basic) = body.block("basic_auth") {
        basic.check(&["username", "password", "password_file"], &[])?;
        return Ok(Auth::Basic {
            user: basic.string_or("username", "")?,
            password: secret(&basic, "password", "password_file")?,
        });
    }
    if let Some(oauth) = body.block("oauth2") {
        return oauth2(&oauth, timeout);
    }
    let bearer = |credentials| Auth::Header {
        kind: "Bearer".into(),
        credentials,
    };
    if body.value("bearer_token")?.is_some()
        || body.value("bearer_token_file")?.is_some()
    {
        return Ok(bearer(secret(body, "bearer_token", "bearer_token_file")?));
    }
    match body.block("authorization") {
        Some(block) => authorization(&block),
        None => Ok(Auth::None),
    }
}

fn authorization(body: &Body) -> Result<Auth, String> {
    body.check(&["type", "credentials", "credentials_file"], &[])?;
    let kind = match body.string_or("type", "")?.trim() {
        "" => "Bearer".to_owned(),
        kind => kind.to_owned(),
    };
    if kind.eq_ignore_ascii_case("basic") {
        let message = "authorization type cannot be set to \"basic\", use \
            \"basic_auth\" block instead";
        return Err(body.error(body.block.pos, message));
    }
    let credentials = secret(body, "credentials", "credentials_file")?;
    Ok(Auth::Header { kind, credentials })
}

/// A secret given as `text` or in the file `file`, not both.
pub fn secret(
    body: &Body,
    text: &str,
    file: &str,
) -> Result<Option<Secret>, String> {
    let (inline, path) = (body.string(text)?, body.string(file)?);
    match (inline, path) {
        (Some(_), Some(_)) => {
            let message =
                format!("at most one of {text} & {file} must be configured");
            Err(body.error(body.block.pos, &message))
        }
        (Some(text), None) if !text.is_empty() => Ok(Some(Secret::Text(text))),
        (_, Some(path)) if !path.is_empty() => {
            Ok(Some(Secret::File(path.into())))
        }
        _ => Ok(None),
    }
}

fn oauth2(body: &Body, timeout: Duration) -> Result<Auth, String> {
    let attrs = [
        "client_id",
        "client_secret",
        "client_secret_file",
        "scopes",
        "token_url",
        "endpoint_params",
    ];
    body.check(&with(&attrs, &PROXY_ATTRS), &["tls_config"])?;
    let client_id = configured(body, "client_id")?;
    let Some(secret) = secret(body, "client_secret", "client_secret_file")?
    else {
        let message = "either oauth2 client_secret or client_secret_file \
            must be configured";
        return Err(body.error(body.block.pos, message));
    };
    let url = configured(body, "token_url")?;
    let token_url = crate::http::Url::parse(&url).ok_or_else(|| {
        body.error(body.attr_pos("token_url"), &unusable_url())
    })?;
    let mut client = Client {
        timeout,
        proxy: proxy(body)?,
        ..Client::default()
    };
    tls(body, &mut client)?;
    let oauth = OAuth2 {
        client_id,
        secret,
        scopes: body.strings("scopes")?,
        token_url,
        params: body.labels("endpoint_params")?,
        client,
    };
    Ok(Auth::Token(Arc::new(oauth.tokens())))
}

/// An oauth2 attribute that may not be empty.
fn configured(body: &Body, name: &str) -> Result<String, String> {
    let value = body.string_or(name, "")?;
    if value.is_empty() {
        let message = format!("oauth2 {name} must be configured");
        return Err(body.error(body.block.pos, &message));
    }
    Ok(value)
}

/// Why a URL is refused.
pub fn unusable_url() -> String {
    match cfg!(feature = "tls") {
        true => "url: only http:// or https://".into(),
        false => "url: only http:// (https://: feature tls)".into(),
    }
}

fn proxy(body: &Body) -> Result<Proxy, String> {
    let url = body.string_or("proxy_url", "")?;
    let no_proxy = body.string_or("no_proxy", "")?;
    let environment = body.bool_or("proxy_from_environment", false)?;
    let connect = connect_headers(body)?;
    let unset = [connect.is_empty(), url.is_empty(), no_proxy.is_empty()];
    if let Some(message) = conflict(unset, environment) {
        return Err(body.error(body.block.pos, message));
    }
    if environment {
        return Ok(Proxy::Environment {
            connect_headers: connect,
        });
    }
    if url.is_empty() {
        return Ok(Proxy::Direct);
    }
    let route = Route::parse(&url, &connect).ok_or_else(|| {
        body.error(body.attr_pos("proxy_url"), "proxy_url: only http://")
    })?;
    Ok(Proxy::Fixed { route, no_proxy })
}

/// Proxy settings that do not go together, as Prometheus refuses them:
/// `unset` says whether the connect headers, URL and no_proxy are.
fn conflict(unset: [bool; 3], environment: bool) -> Option<&'static str> {
    let [no_connect, no_url, no_no_proxy] = unset;
    let conflicts = [
        (
            !no_connect && !environment && no_url,
            "if proxy_connect_header is configured, proxy_url or \
            proxy_from_environment must also be configured",
        ),
        (
            environment && !no_url,
            "if proxy_from_environment is configured, proxy_url \
            must not be configured",
        ),
        (
            environment && !no_no_proxy,
            "if proxy_from_environment is configured, no_proxy \
            must not be configured",
        ),
        (
            no_url && !no_no_proxy,
            "if no_proxy is configured, proxy_url must also be configured",
        ),
    ];
    conflicts
        .into_iter()
        .find(|(found, _)| *found)
        .map(|(_, m)| m)
}

fn connect_headers(body: &Body) -> Result<String, String> {
    let attr = "proxy_connect_header";
    let mut connect = String::new();
    for (name, values) in body.object_lists(attr)? {
        for value in values {
            connect.push_str(&line(body, attr, &name, &value)?);
        }
    }
    Ok(connect)
}

#[cfg(not(feature = "tls"))]
fn tls(body: &Body, _: &mut Client) -> Result<(), String> {
    match body.block("tls_config") {
        Some(tls) => super::components::built(&tls, "tls", false),
        None => Ok(()),
    }
}

#[cfg(feature = "tls")]
const TLS_ATTRS: [&str; 9] = [
    "ca_pem",
    "ca_file",
    "cert_pem",
    "cert_file",
    "key_pem",
    "key_file",
    "server_name",
    "insecure_skip_verify",
    "min_version",
];

#[cfg(feature = "tls")]
fn tls(body: &Body, client: &mut Client) -> Result<(), String> {
    use crate::http::tls::{Settings, Tls};
    let Some(tls) = body.block("tls_config") else {
        return Ok(());
    };
    tls.check(&TLS_ATTRS, &[])?;
    let pos = tls.block.pos;
    let tls13_only = match tls.string_or("min_version", "TLS12")?.as_str() {
        "TLS12" => false,
        "TLS13" => true,
        other => {
            let message = format!("min_version `{other}`: TLS12 or TLS13");
            return Err(tls.error(pos, &message));
        }
    };
    let settings = Settings {
        ca: super::components::pem(&tls, "ca")?,
        cert: super::components::pem(&tls, "cert")?,
        key: super::components::pem(&tls, "key")?,
        server_name: tls.string("server_name")?.filter(|n| !n.is_empty()),
        insecure_skip_verify: tls.bool_or("insecure_skip_verify", false)?,
        tls13_only,
    };
    if settings.cert.is_some() != settings.key.is_some() {
        let message = "a client certificate needs its key, and a key its \
            certificate";
        return Err(tls.error(pos, message));
    }
    client.tls = Some(Tls::new(&settings).map_err(|e| tls.error(pos, &e))?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::compile::{Plan, compile};
    use super::super::syntax::parse;

    fn remote(endpoint: &str) -> Result<Plan, String> {
        let text = format!(
            r#"prometheus.remote_write "w" {{
                endpoint {{ url = "http://p/api" {endpoint} }}
            }}"#
        );
        compile(&parse(&text).unwrap(), false)
    }

    #[test]
    fn reads_client_settings() {
        let fine = r#"
            basic_auth { username = "u" password = "p" }
            http_headers = { "X-A" = ["1", "2"] }
            headers = { "X-B" = "3" }
            proxy_url = "http://proxy:3128"
            no_proxy = "10.0.0.0/8"
            queue_config { max_backoff = "1m" retry_on_http_429 = false }
            write_relabel_config { action = "drop" regex = "x" }
        "#;
        let plan = remote(fine).unwrap();
        // The fan-out, the write and the relabel before it.
        assert_eq!(plan.metrics.nodes.len(), 3);
        let refused = [
            (r#"basic_auth { } bearer_token = "t""#, "at most one"),
            (r#"http_headers = { "Host" = ["h"] }"#, "not allowed"),
            (r#"headers = { "authorization" = "a" }"#, "basic_auth"),
            (r#"headers = { "X-A" = "a\nb" }"#, "not valid"),
            (r#"no_proxy = "x""#, "proxy_url must also"),
            (r#"proxy_url = "socks5://p""#, "only http://"),
            (r#"authorization { type = "Basic" }"#, "basic_auth"),
        ];
        for (endpoint, error) in refused {
            let found = remote(endpoint).err().unwrap_or_default();
            assert!(found.contains(error), "{endpoint}: {found}");
        }
    }

    #[test]
    fn checks_cloud_sign_ins() {
        let refused = [
            (r#"sigv4 { access_key = "a" }"#, "access key and secret"),
            (r#"sigv4 { external_id = "x" }"#, "only be used with role"),
            (r#"sigv4 { } basic_auth { }"#, "at most one of sigv4"),
            (r#"azuread { }"#, "must provide an Azure Managed"),
            (
                r#"azuread { managed_identity { client_id = "x" } }"#,
                "client_id is invalid",
            ),
            (r#"azuread { cloud = "Mars" }"#, "must provide a cloud"),
        ];
        for (endpoint, error) in refused {
            let found = remote(endpoint).err().unwrap_or_default();
            assert!(found.contains(error), "{endpoint}: {found}");
        }
        let keys =
            r#"sigv4 { region = "r" access_key = "a" secret_key = "s" }"#;
        assert!(remote(keys).is_ok());
        let id = "00000000-1111-2222-3333-444444444444";
        let azure = format!(
            "azuread {{ managed_identity {{ client_id = \"{id}\" }} }}"
        );
        assert!(remote(&azure).is_ok());
    }
}
