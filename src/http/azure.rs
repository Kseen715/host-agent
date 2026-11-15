//! Azure AD tokens for remote_write, as Prometheus's azuread asks for
//! them: a managed identity, a workload identity's federated token, an
//! app's client secret, or the SDK's default chain (environment,
//! workload identity, managed identity, Azure CLI).

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
                (
                    "client_assertion_type",
                    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                ),
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

    /// DefaultAzureCredential: the first source that gives a token.
    fn chain(&self, tenant: &str) -> io::Result<Expiring<String>> {
        let var = |name: &str| env::var(name).unwrap_or_default();
        let tenant = match tenant {
            "" => var("AZURE_TENANT_ID"),
            tenant => tenant.to_owned(),
        };
        let (id, secret) = (var("AZURE_CLIENT_ID"), var("AZURE_CLIENT_SECRET"));
        let file = var("AZURE_FEDERATED_TOKEN_FILE");
        let mut errors = Vec::new();
        let mut attempt = |found: io::Result<Expiring<String>>| match found {
            Ok(token) => Some(token),
            Err(error) => {
                errors.push(error.to_string());
                None
            }
        };
        let complete = !tenant.is_empty() && !id.is_empty();
        if complete && !secret.is_empty() {
            if let Some(token) = attempt(self.secret(&id, &secret, &tenant)) {
                return Ok(token);
            }
        }
        if complete && !file.is_empty() {
            if let Some(token) = attempt(self.federated(&id, &tenant, &file)) {
                return Ok(token);
            }
        }
        if let Some(token) = attempt(self.managed(&id)) {
            return Ok(token);
        }
        if let Some(token) = attempt(self.cli(&tenant)) {
            return Ok(token);
        }
        Err(io::Error::other(format!("azure: {}", errors.join("; "))))
    }

    /// `az account get-access-token`, as the SDK's AzureCLICredential.
    fn cli(&self, tenant: &str) -> io::Result<Expiring<String>> {
        let mut az = Command::new("az");
        az.args(["account", "get-access-token", "--output", "json"]);
        az.args(["--resource", self.resource()]);
        if !tenant.is_empty() {
            az.args(["--tenant", tenant]);
        }
        let output = az.output()?;
        let text = String::from_utf8_lossy(&output.stdout);
        let json = Json::parse(&text)
            .filter(|_| output.status.success())
            .ok_or_else(|| io::Error::other("az: no token"))?;
        let token = json.get("accessToken").and_then(Json::str).unwrap_or("");
        let at = json.get("expires_on").and_then(Json::num);
        let now_s = crate::time::now_ms() as f64 / 1e3;
        let left = at.map_or(300.0, |at| (at - now_s).max(0.0));
        let expiry = Instant::now() + Duration::from_secs_f64(left);
        Ok((format!("Bearer {token}"), Some(expiry)))
    }
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
