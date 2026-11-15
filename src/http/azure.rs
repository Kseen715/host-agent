//! Azure AD tokens for remote_write, as Prometheus's azuread asks for
//! them: a managed identity, a workload identity's federated token, an
//! app's client secret, or the SDK's default chain (environment's
//! secret, certificate or password, workload identity, managed
//! identity, the Azure CLI, Azure Developer CLI and PowerShell).

use super::auth::{Expiring, Secret, Tokens, form_token, json_token};
use super::{Client, Url};
use crate::encoding::query_escape;
use crate::json::Json;
use std::env;
use std::fs;
use std::io;
use std::process::Command;
use std::time::{Duration, Instant};

/// Workload identity's projected token, unless configured.
pub const TOKEN_FILE: &str =
    "/var/run/secrets/azure/tokens/azure-identity-token";
/// DefaultAzureCredential's sources in order; the first three are
/// AZURE_TOKEN_CREDENTIALS's "prod", the rest its "dev".
const SOURCES: [&str; 6] = [
    "EnvironmentCredential",
    "WorkloadIdentityCredential",
    "ManagedIdentityCredential",
    "AzureCLICredential",
    "AzureDeveloperCLICredential",
    "AzurePowerShellCredential",
];
const ASSERTION_TYPE: &str =
    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
/// Metadata servers answer at once or are not there.
const METADATA_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Clone, Copy)]
pub enum Cloud {
    Public,
    China,
    Government,
}

impl Cloud {
    pub fn named(name: &str) -> Option<Cloud> {
        match name {
            "AzurePublic" => Some(Cloud::Public),
            "AzureChina" => Some(Cloud::China),
            "AzureGovernment" => Some(Cloud::Government),
            _ => None,
        }
    }

    /// Azure Monitor's ingestion scope.
    fn audience(self) -> &'static str {
        match self {
            Cloud::Public => "https://monitor.azure.com//.default",
            Cloud::China => "https://monitor.azure.cn//.default",
            Cloud::Government => "https://monitor.azure.us//.default",
        }
    }

    fn authority(self) -> &'static str {
        match self {
            Cloud::Public => "https://login.microsoftonline.com",
            Cloud::China => "https://login.chinacloudapi.cn",
            Cloud::Government => "https://login.microsoftonline.us",
        }
    }
}

pub enum Method {
    ManagedIdentity {
        client_id: String,
    },
    Workload {
        client_id: String,
        tenant_id: String,
        token_file: String,
    },
    OAuth {
        client_id: String,
        secret: Secret,
        tenant_id: String,
    },
    Sdk {
        tenant_id: String,
    },
}

struct Azure {
    method: Method,
    cloud: Cloud,
    scope: String,
    client: Client,
}

/// Tokens for `scope`, else the cloud's ingestion audience.
pub fn tokens(
    method: Method,
    cloud: Cloud,
    scope: &str,
    client: Client,
) -> Tokens {
    let scope = match scope {
        "" => cloud.audience().to_owned(),
        scope => scope.to_owned(),
    };
    let azure = Azure {
        method,
        cloud,
        scope,
        client,
    };
    // Expiries are halved: azuread renews at half a token's life.
    Tokens::new(Duration::ZERO, Box::new(move || azure.ask().map(halved)))
}

fn halved((token, expiry): Expiring<String>) -> Expiring<String> {
    let now = Instant::now();
    (
        token,
        expiry.map(|at| now + at.saturating_duration_since(now) / 2),
    )
}

impl Azure {
    fn ask(&self) -> io::Result<Expiring<String>> {
        match &self.method {
            Method::ManagedIdentity { client_id } => self.managed(client_id),
            Method::Workload {
                client_id,
                tenant_id,
                token_file,
            } => self.federated(client_id, tenant_id, token_file),
            Method::OAuth {
                client_id,
                secret,
                tenant_id,
            } => self.secret(client_id, &secret.read()?, tenant_id),
            Method::Sdk { tenant_id } => self.chain(tenant_id),
        }
    }

    /// The scope as a v1 resource: without `/.default`.
    fn resource(&self) -> &str {
        self.scope.strip_suffix("/.default").unwrap_or(&self.scope)
    }

    fn token_url(&self, tenant: &str) -> io::Result<Url> {
        let url =
            format!("{}/{tenant}/oauth2/v2.0/token", self.cloud.authority());
        Url::parse(&url).ok_or_else(|| io::Error::other(format!("url `{url}`")))
    }

    fn form(
        &self,
        client_id: &str,
        pairs: &[(&str, &str)],
    ) -> Vec<(String, String)> {
        let mut form = vec![
            ("grant_type".to_owned(), "client_credentials".to_owned()),
            ("client_id".into(), client_id.into()),
            ("scope".into(), self.scope.clone()),
        ];
        form.extend(pairs.iter().map(|(k, v)| ((*k).into(), (*v).into())));
        form
    }

    fn secret(
        &self,
        id: &str,
        secret: &str,
        tenant: &str,
    ) -> io::Result<Expiring<String>> {
        let form = self.form(id, &[("client_secret", secret)]);
        form_token(&self.token_url(tenant)?, &self.client, &form, "")
    }

    fn federated(
        &self,
        id: &str,
        tenant: &str,
        file: &str,
    ) -> io::Result<Expiring<String>> {
        let assertion = fs::read_to_string(file)?;
        let form = self.form(
            id,
            &[
                ("client_assertion_type", ASSERTION_TYPE),
                ("client_assertion", assertion.trim()),
            ],
        );
        form_token(&self.token_url(tenant)?, &self.client, &form, "")
    }

    /// App Service's identity endpoint if the environment names one,
    /// else the instance metadata service.
    fn managed(&self, client_id: &str) -> io::Result<Expiring<String>> {
        let resource = query_escape(self.resource());
        let id = match client_id {
            "" => String::new(),
            id => format!("&client_id={}", query_escape(id)),
        };
        let service = ["IDENTITY_ENDPOINT", "IDENTITY_HEADER"].map(env::var);
        let (url, header) = match service {
            [Ok(endpoint), Ok(secret)] => (
                format!(
                    "{endpoint}?api-version=2019-08-01&resource={resource}{id}"
                ),
                format!("X-IDENTITY-HEADER: {secret}\r\n"),
            ),
            _ => (
                format!(
                    "http://169.254.169.254/metadata/identity/oauth2/token\
                     ?api-version=2018-02-01&resource={resource}{id}"
                ),
                "Metadata: true\r\n".to_owned(),
            ),
        };
        let url =
            Url::parse(&url).ok_or_else(|| io::Error::other(url.clone()))?;
        let client = Client {
            timeout: METADATA_TIMEOUT,
            ..Client::default()
        };
        json_token(&super::request(&url, &client, "GET", &header, &[])?)
    }

    /// DefaultAzureCredential: the first of the sources
    /// AZURE_TOKEN_CREDENTIALS selects (all unset) that gives a token.
    fn chain(&self, tenant: &str) -> io::Result<Expiring<String>> {
        let chosen = selected(&var("AZURE_TOKEN_CREDENTIALS"))
            .map_err(io::Error::other)?;
        let tenant = match tenant {
            "" => var("AZURE_TENANT_ID"),
            tenant => tenant.to_owned(),
        };
        let mut errors = Vec::new();
        for source in chosen {
            let found = match source {
                "EnvironmentCredential" => self.environment(),
                "WorkloadIdentityCredential" => self.workload(&tenant),
                "ManagedIdentityCredential" => {
                    self.managed(&var("AZURE_CLIENT_ID"))
                }
                "AzureCLICredential" => self.cli(&tenant),
                "AzureDeveloperCLICredential" => self.azd(&tenant),
                _ => self.powershell(&tenant),
            };
            match found {
                Ok(token) => return Ok(token),
                Err(error) => errors.push(format!("{source}: {error}")),
            }
        }
        Err(io::Error::other(format!("azure: {}", errors.join("; "))))
    }

    /// EnvironmentCredential: a client secret, a certificate, or a
    /// user's password, by AZURE_* variables.
    fn environment(&self) -> io::Result<Expiring<String>> {
        let (tenant, id) = (var("AZURE_TENANT_ID"), var("AZURE_CLIENT_ID"));
        for (name, value) in
            [("AZURE_TENANT_ID", &tenant), ("AZURE_CLIENT_ID", &id)]
        {
            if value.is_empty() {
                let message = format!("missing environment variable {name}");
                return Err(io::Error::other(message));
            }
        }
        let secret = var("AZURE_CLIENT_SECRET");
        if !secret.is_empty() {
            return self.secret(&id, &secret, &tenant);
        }
        let path = var("AZURE_CLIENT_CERTIFICATE_PATH");
        if !path.is_empty() {
            return self.certificate(&id, &tenant, &path);
        }
        let user = var("AZURE_USERNAME");
        if !user.is_empty() {
            return self.password(&id, &tenant, &user);
        }
        Err(io::Error::other(
            "incomplete environment variable configuration. Only \
             AZURE_TENANT_ID and AZURE_CLIENT_ID are set",
        ))
    }

    #[cfg(feature = "tls")]
    fn certificate(
        &self,
        id: &str,
        tenant: &str,
        path: &str,
    ) -> io::Result<Expiring<String>> {
        let password = var("AZURE_CLIENT_CERTIFICATE_PASSWORD");
        let cert = super::azure_cert::load(path, &password)?;
        let send = var("AZURE_CLIENT_SEND_CERTIFICATE_CHAIN");
        let send = send == "1" || send.eq_ignore_ascii_case("true");
        let url = self.token_url(tenant)?;
        let audience = format!("https://{}{}", url.host, url.path);
        let assertion = cert.assertion(&audience, id, send)?;
        let form = self.form(
            id,
            &[
                ("client_assertion_type", ASSERTION_TYPE),
                ("client_assertion", &assertion),
            ],
        );
        form_token(&url, &self.client, &form, "")
    }

    #[cfg(not(feature = "tls"))]
    fn certificate(
        &self,
        _: &str,
        _: &str,
        _: &str,
    ) -> io::Result<Expiring<String>> {
        Err(io::Error::other("certificate credentials need feature tls"))
    }

    /// The resource owner password grant, as a public client.
    fn password(
        &self,
        id: &str,
        tenant: &str,
        user: &str,
    ) -> io::Result<Expiring<String>> {
        let password = var("AZURE_PASSWORD");
        if password.is_empty() {
            return Err(io::Error::other("no value for AZURE_PASSWORD"));
        }
        let scope = format!("{} openid offline_access profile", self.scope);
        let form = [
            ("grant_type", "password"),
            ("client_id", id),
            ("username", user),
            ("password", &password),
            ("scope", &scope),
            ("client_info", "1"),
        ];
        let form: Vec<(String, String)> = form
            .iter()
            .map(|(k, v)| ((*k).into(), (*v).into()))
            .collect();
        form_token(&self.token_url(tenant)?, &self.client, &form, "")
    }

    fn workload(&self, tenant: &str) -> io::Result<Expiring<String>> {
        let (id, file) =
            (var("AZURE_CLIENT_ID"), var("AZURE_FEDERATED_TOKEN_FILE"));
        if tenant.is_empty() || id.is_empty() || file.is_empty() {
            let message = "no client ID, tenant ID or token file specified";
            return Err(io::Error::other(message));
        }
        self.federated(&id, tenant, &file)
    }

    /// `az account get-access-token`, as the SDK's AzureCLICredential.
    fn cli(&self, tenant: &str) -> io::Result<Expiring<String>> {
        let mut args = vec!["account", "get-access-token", "-o", "json"];
        args.extend(["--resource", self.resource()]);
        if !tenant.is_empty() {
            args.extend(["--tenant", tenant]);
        }
        let json = run("az", &args)?;
        let token = json.get("accessToken").and_then(Json::str).unwrap_or("");
        let at = json.get("expires_on").and_then(Json::num);
        let now_s = crate::time::now_ms() as f64 / 1e3;
        let left = at.map_or(300.0, |at| (at - now_s).max(0.0));
        let expiry = Instant::now() + Duration::from_secs_f64(left);
        Ok((format!("Bearer {token}"), Some(expiry)))
    }

    /// `azd auth token`, as AzureDeveloperCLICredential.
    fn azd(&self, tenant: &str) -> io::Result<Expiring<String>> {
        let mut args = vec!["auth", "token", "-o", "json", "--no-prompt"];
        args.extend(["--scope", &self.scope]);
        if !tenant.is_empty() {
            args.extend(["--tenant-id", tenant]);
        }
        let json = run("azd", &args)?;
        let token = json.get("token").and_then(Json::str).unwrap_or("");
        let at = json.get("expiresOn").and_then(Json::str).unwrap_or("");
        Ok((format!("Bearer {token}"), Some(expires_at(at)?)))
    }

    /// Az.Accounts' Get-AzAccessToken through pwsh, as
    /// AzurePowerShellCredential runs it.
    fn powershell(&self, tenant: &str) -> io::Result<Expiring<String>> {
        let script = include_str!("azure_token.ps1")
            .replace("{resource}", self.resource())
            .replace("{tenant}", tenant);
        let utf16: Vec<u8> =
            script.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let encoded = crate::encoding::base64(&utf16);
        let args = [
            "-NoProfile",
            "-NonInteractive",
            "-OutputFormat",
            "Text",
            "-EncodedCommand",
            &encoded,
        ];
        let json = run("pwsh", &args)?;
        let token = json.get("Token").and_then(Json::str).unwrap_or("");
        let at = json.get("ExpiresOn").and_then(Json::num).unwrap_or(0.0);
        let left = (at - crate::time::now_ms() as f64 / 1e3).max(0.0);
        let expiry = Instant::now() + Duration::from_secs_f64(left);
        Ok((format!("Bearer {token}"), Some(expiry)))
    }
}

/// The sources AZURE_TOKEN_CREDENTIALS names, in the chain's order;
/// refused when it names none, as NewDefaultAzureCredential refuses it.
pub fn selected(value: &str) -> Result<Vec<&'static str>, String> {
    let (prod, dev) = SOURCES.split_at(3);
    match value {
        "" => Ok(SOURCES.to_vec()),
        "dev" => Ok(dev.to_vec()),
        "prod" => Ok(prod.to_vec()),
        name => SOURCES
            .iter()
            .find(|s| s.eq_ignore_ascii_case(name))
            .map(|s| vec![*s])
            .ok_or_else(|| {
                format!(
                    "invalid AZURE_TOKEN_CREDENTIALS value {name:?}. Valid \
                     values are \"dev\", \"prod\", or the name of any \
                     credential type in the default chain"
                )
            }),
    }
}

fn var(name: &str) -> String {
    env::var(name).unwrap_or_default()
}

/// A developer tool's JSON answer.
fn run(program: &str, args: &[&str]) -> io::Result<Json> {
    let output = Command::new(program).args(args).output()?;
    let text = String::from_utf8_lossy(&output.stdout);
    Json::parse(&text)
        .filter(|_| output.status.success())
        .ok_or_else(|| {
            let error = String::from_utf8_lossy(&output.stderr);
            io::Error::other(format!("{program}: {}", error.trim()))
        })
}

/// azd's `2006-01-02T15:04:05Z` expiry.
fn expires_at(text: &str) -> io::Result<Instant> {
    let at_ns = crate::time::parse_rfc3339(text).ok_or_else(|| {
        let message = format!("error parsing token expiration time {text:?}");
        io::Error::other(message)
    })?;
    let left = (at_ns - crate::time::now_ns()).max(0) as u64;
    Ok(Instant::now() + Duration::from_nanos(left))
}

/// Go's uuid.Parse: 36 characters with dashes, or 32 hex digits,
/// maybe as a URN or in braces.
pub fn uuid(text: &str) -> bool {
    let text = text.strip_prefix("urn:uuid:").unwrap_or(text);
    let text = text
        .strip_prefix('{')
        .and_then(|t| t.strip_suffix('}'))
        .unwrap_or(text);
    let hex = |s: &str| s.chars().all(|c| c.is_ascii_hexdigit());
    match text.len() {
        32 => hex(text),
        36 => {
            let dashes = [8, 13, 18, 23];
            text.char_indices().all(|(i, c)| match dashes.contains(&i) {
                true => c == '-',
                false => c.is_ascii_hexdigit(),
            })
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checks_ids() {
        assert!(uuid("00000000-1111-2222-3333-444444444444"));
        assert!(uuid("{00000000111122223333444444444444}"));
        assert!(!uuid("00000000-1111-2222-3333-44444444444g"));
        let (_, expiry) = halved((String::new(), Some(Instant::now())));
        assert!(expiry.is_some());
    }
}
