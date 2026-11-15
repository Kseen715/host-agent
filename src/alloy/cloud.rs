//! remote_write's cloud sign-ins in place of the client's own auth:
//! `sigv4`, `azuread`, `google_iam`, checked as Alloy checks them.

use super::compile::Body;
use crate::http::auth::{Auth, Secret};
use crate::http::{Client, azure, sigv4};
use std::sync::Arc;

pub const BLOCKS: [&str; 3] = ["sigv4", "azuread", "google_iam"];

/// The client's auth set from the endpoint's cloud block, if any. The
/// sign-in's own requests go through the endpoint's proxy and TLS.
pub fn auth(endpoint: &Body, client: &mut Client) -> Result<(), String> {
    let own = ["basic_auth", "authorization", "oauth2"];
    let attrs = ["bearer_token", "bearer_token_file"];
    let mut count = own.iter().filter(|n| endpoint.block(n).is_some()).count();
    for attr in attrs {
        count += usize::from(endpoint.value(attr)?.is_some());
    }
    let clouds: Vec<(&str, Body)> = BLOCKS
        .iter()
        .filter_map(|name| Some((*name, endpoint.block(name)?)))
        .collect();
    if clouds.len() + count > 1 && !clouds.is_empty() {
        let message = "at most one of sigv4, azuread, google_iam, \
            basic_auth, oauth2, bearer_token & bearer_token_file must be \
            configured";
        return Err(endpoint.error(endpoint.block.pos, message));
    }
    let Some((name, block)) = clouds.into_iter().next() else {
        return Ok(());
    };
    let transport = Client {
        timeout: client.timeout,
        proxy: client.proxy.clone(),
        #[cfg(feature = "tls")]
        tls: client.tls.clone(),
        ..Client::default()
    };
    client.auth = match name {
        "sigv4" => sigv4(&block, transport)?,
        "azuread" => azuread(&block, transport)?,
        _ => google(&block, transport)?,
    };
    Ok(())
}

fn sigv4(body: &Body, client: Client) -> Result<Auth, String> {
    let attrs = [
        "region",
        "access_key",
        "secret_key",
        "profile",
        "role_arn",
        "external_id",
        "session_name",
        "tags",
        "use_fips_sts_endpoint",
        "service_name",
    ];
    body.check(&attrs, &[])?;
    let text = |name| body.string_or(name, "");
    let (id, secret) = (text("access_key")?, text("secret_key")?);
    let pos = body.block.pos;
    if id.is_empty() != secret.is_empty() {
        let message = "must provide an AWS SigV4 access key and secret key \
            if credentials are specified in the SigV4 config";
        return Err(body.error(pos, message));
    }
    let (arn, external_id) = (text("role_arn")?, text("external_id")?);
    if !external_id.is_empty() && arn.is_empty() {
        return Err(
            body.error(pos, "external_id can only be used with role_arn")
        );
    }
    let role = (!arn.is_empty()).then(|| -> Result<_, String> {
        Ok(sigv4::Role {
            arn,
            external_id,
            session_name: text("session_name")?,
            tags: body.labels("tags")?,
        })
    });
    let settings = sigv4::Settings {
        region: text("region")?,
        service: text("service_name")?,
        keys: (!id.is_empty()).then(|| sigv4::Keys {
            id,
            secret,
            token: String::new(),
        }),
        profile: text("profile")?,
        role: role.transpose()?,
        fips: body.bool_or("use_fips_sts_endpoint", false)?,
        client,
    };
    let signer =
        sigv4::SigV4::new(settings).map_err(|e| body.error(pos, &e))?;
    Ok(Auth::SigV4(Arc::new(signer)))
}

fn azuread(body: &Body, client: Client) -> Result<Auth, String> {
    let blocks = ["managed_identity", "workload_identity", "oauth", "sdk"];
    body.check(&["cloud", "scope"], &blocks)?;
    let pos = body.block.pos;
    let cloud = azure::Cloud::named(&body.string_or("cloud", "AzurePublic")?)
        .ok_or_else(|| {
        body.error(pos, "must provide a cloud in the Azure AD config")
    })?;
    let given: Vec<Body> =
        blocks.iter().filter_map(|n| body.block(n)).collect();
    if given.is_empty() {
        let message = "must provide an Azure Managed Identity, Azure \
            Workload Identity, Azure OAuth or Azure SDK in the Azure AD config";
        return Err(body.error(pos, message));
    }
    if given.len() > 1 {
        let message = "cannot provide multiple authentication methods in the Azure AD config";
        return Err(body.error(pos, message));
    }
    let scope = body.string_or("scope", "")?;
    let allowed = |c: char| {
        c.is_alphanumeric()
            || c == '_'
            || c.is_whitespace()
            || ":/.-".contains(c)
    };
    if !scope.is_empty() && !scope.chars().all(allowed) {
        let message = "the provided scope contains invalid characters";
        return Err(body.error(pos, message));
    }
    let method = azure_method(body)?;
    Ok(Auth::Token(Arc::new(azure::tokens(
        method, cloud, &scope, client,
    ))))
}

/// The one method block, its ids checked as Alloy checks them.
fn azure_method(body: &Body) -> Result<azure::Method, String> {
    let id = |block: &Body, what: &str, name: &str| -> Result<String, String> {
        let value = block.string_or(name, "")?;
        let pos = block.block.pos;
        if value.is_empty() {
            let message = format!(
                "must provide an Azure {what} {name} in the Azure AD config"
            );
            return Err(block.error(pos, &message));
        }
        let checked = name == "client_id" || what == "Workload Identity";
        if checked && !azure::uuid(&value) {
            let message =
                format!("the provided Azure {what} {name} is invalid");
            return Err(block.error(pos, &message));
        }
        Ok(value)
    };
    if let Some(block) = body.block("managed_identity") {
        block.check(&["client_id"], &[])?;
        let client_id = id(&block, "Managed Identity", "client_id")?;
        return Ok(azure::Method::ManagedIdentity { client_id });
    }
    if let Some(block) = body.block("workload_identity") {
        block.check(&["client_id", "tenant_id", "token_file_path"], &[])?;
        let what = "Workload Identity";
        let token_file =
            block.string_or("token_file_path", azure::TOKEN_FILE)?;
        return Ok(azure::Method::Workload {
            client_id: id(&block, what, "client_id")?,
            tenant_id: id(&block, what, "tenant_id")?,
            token_file,
        });
    }
    if let Some(block) = body.block("oauth") {
        block.check(&["client_id", "client_secret", "tenant_id"], &[])?;
        let what = "OAuth";
        let client_id = id(&block, what, "client_id")?;
        let secret = Secret::Text(id(&block, what, "client_secret")?);
        // Alloy's tenant pattern check never fails: any tenant is taken.
        let tenant_id = id(&block, what, "tenant_id")?;
        return Ok(azure::Method::OAuth {
            client_id,
            secret,
            tenant_id,
        });
    }
    let sdk = body.block("sdk").expect("one block was given");
    sdk.check(&["tenant_id"], &[])?;
    let tenant_id = sdk.string_or("tenant_id", "")?;
    Ok(azure::Method::Sdk { tenant_id })
}

#[cfg(feature = "tls")]
fn google(body: &Body, client: Client) -> Result<Auth, String> {
    body.check(&["credentials_file"], &[])?;
    let file = body.string_or("credentials_file", "")?;
    let tokens = crate::http::google::tokens(&file, client)
        .map_err(|e| body.error(body.block.pos, &e))?;
    Ok(Auth::Token(Arc::new(tokens)))
}

#[cfg(not(feature = "tls"))]
fn google(body: &Body, _: Client) -> Result<Auth, String> {
    super::components::built(body, "tls", false)?;
    unreachable!("refused without feature tls")
}
