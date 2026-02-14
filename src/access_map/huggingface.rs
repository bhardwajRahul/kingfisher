use anyhow::{anyhow, Context, Result};
use reqwest::{header, Client};
use serde::Deserialize;
use tracing::warn;

use crate::{cli::commands::access_map::AccessMapArgs, validation::GLOBAL_USER_AGENT};

use super::{
    build_recommendations, AccessMapResult, AccessSummary, AccessTokenDetails, PermissionSummary,
    ResourceExposure, RoleBinding, Severity,
};

const HUGGINGFACE_API: &str = "https://huggingface.co/api";

#[derive(Deserialize)]
struct HfWhoAmI {
    #[serde(default)]
    name: Option<String>,
    #[serde(default, rename = "fullname")]
    full_name: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    r#type: Option<String>,
    #[serde(default)]
    orgs: Vec<HfOrg>,
    #[serde(default)]
    auth: Option<HfAuth>,
}

#[derive(Deserialize)]
struct HfOrg {
    #[serde(default)]
    name: Option<String>,
    #[serde(default, rename = "roleInOrg")]
    role_in_org: Option<String>,
}

#[derive(Deserialize)]
struct HfAuth {
    #[serde(default, rename = "type")]
    token_type: Option<String>,
    #[serde(default, rename = "accessToken")]
    access_token: Option<HfAccessTokenInfo>,
}

#[derive(Deserialize)]
struct HfAccessTokenInfo {
    #[serde(default, rename = "displayName")]
    display_name: Option<String>,
    #[serde(default)]
    role: Option<String>,
    #[serde(default, rename = "createdAt")]
    created_at: Option<String>,
}

#[derive(Deserialize)]
struct HfModel {
    #[serde(default, rename = "modelId")]
    model_id: Option<String>,
    #[serde(default, rename = "id")]
    id: Option<String>,
    #[serde(default)]
    private: bool,
}

pub async fn map_access(args: &AccessMapArgs) -> Result<AccessMapResult> {
    let token = if let Some(path) = args.credential_path.as_deref() {
        let raw = std::fs::read_to_string(path).with_context(|| {
            format!("Failed to read Hugging Face token from {}", path.display())
        })?;
        raw.trim().to_string()
    } else {
        return Err(anyhow!(
            "Hugging Face access-map requires a validated token from scan results"
        ));
    };

    map_access_from_token(&token).await
}

pub async fn map_access_from_token(token: &str) -> Result<AccessMapResult> {
    let client = Client::builder()
        .user_agent(GLOBAL_USER_AGENT.as_str())
        .build()
        .context("Failed to build Hugging Face HTTP client")?;

    let whoami_resp = client
        .get(format!("{HUGGINGFACE_API}/whoami-v2"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .send()
        .await
        .context("Hugging Face access-map: failed to fetch whoami")?;

    if !whoami_resp.status().is_success() {
        return Err(anyhow!(
            "Hugging Face access-map: whoami failed with HTTP {}",
            whoami_resp.status()
        ));
    }

    let whoami: HfWhoAmI =
        whoami_resp.json().await.context("Hugging Face access-map: invalid whoami JSON")?;

    let username = whoami.name.clone().unwrap_or_else(|| "huggingface_user".to_string());

    let identity = AccessSummary {
        id: username.clone(),
        access_type: whoami.r#type.clone().unwrap_or_else(|| "user".into()).to_lowercase(),
        project: None,
        tenant: None,
        account_id: None,
    };

    let mut risk_notes = Vec::new();
    let mut resources = Vec::new();
    let mut permissions = PermissionSummary::default();
    let mut roles = Vec::new();

    // Extract token role/type from auth info.
    let token_role =
        whoami.auth.as_ref().and_then(|a| a.access_token.as_ref()).and_then(|t| t.role.clone());
    let token_type = whoami.auth.as_ref().and_then(|a| a.token_type.clone());
    let token_name = whoami
        .auth
        .as_ref()
        .and_then(|a| a.access_token.as_ref())
        .and_then(|t| t.display_name.clone());
    let token_created = whoami
        .auth
        .as_ref()
        .and_then(|a| a.access_token.as_ref())
        .and_then(|t| t.created_at.clone());

    if let Some(ref role) = token_role {
        roles.push(RoleBinding {
            name: "token_role".into(),
            source: "huggingface".into(),
            permissions: vec![format!("role:{role}")],
        });

        match role.as_str() {
            "write" => permissions.risky.push("token:write".to_string()),
            "read" => permissions.read_only.push("token:read".to_string()),
            "admin" | "fineGrained" => permissions.admin.push(format!("token:{role}")),
            _ => permissions.read_only.push(format!("token:{role}")),
        }
    }

    // Enumerate organizations.
    for org in &whoami.orgs {
        let org_name = org.name.clone().unwrap_or_else(|| "unknown_org".to_string());
        let org_role = org.role_in_org.clone().unwrap_or_else(|| "member".to_string());

        let risk = if org_role == "admin" { Severity::High } else { Severity::Low };

        resources.push(ResourceExposure {
            resource_type: "organization".into(),
            name: org_name,
            permissions: vec![format!("org_role:{org_role}")],
            risk: severity_to_str(risk).to_string(),
            reason: "Organization membership available to the token".into(),
        });
    }

    // Enumerate models accessible to the user.
    let models = list_user_models(&client, token, &username).await.unwrap_or_else(|err| {
        warn!("Hugging Face access-map: model enumeration failed: {err}");
        Vec::new()
    });

    for model in &models {
        let model_name = model
            .model_id
            .clone()
            .or_else(|| model.id.clone())
            .unwrap_or_else(|| "unknown".to_string());

        let (risk, perm_label) = if model.private {
            (Severity::Medium, "model:private")
        } else {
            (Severity::Low, "model:public")
        };

        resources.push(ResourceExposure {
            resource_type: "model".into(),
            name: model_name,
            permissions: vec![perm_label.to_string()],
            risk: severity_to_str(risk).to_string(),
            reason: if model.private {
                "Accessible private model".to_string()
            } else {
                "Accessible public model".to_string()
            },
        });

        if model.private {
            permissions.risky.push(perm_label.to_string());
        } else {
            permissions.read_only.push(perm_label.to_string());
        }
    }

    permissions.admin.sort();
    permissions.admin.dedup();
    permissions.risky.sort();
    permissions.risky.dedup();
    permissions.read_only.sort();
    permissions.read_only.dedup();

    let severity = derive_severity(&token_role, &models);

    if models.is_empty() && whoami.orgs.is_empty() {
        resources.push(ResourceExposure {
            resource_type: "account".into(),
            name: username.clone(),
            permissions: Vec::new(),
            risk: severity_to_str(Severity::Low).to_string(),
            reason: "Hugging Face account associated with the token".into(),
        });
        risk_notes.push("Token did not enumerate any models or organizations".into());
    }

    if roles.is_empty() {
        risk_notes.push("Hugging Face did not report token role information".into());
    }

    Ok(AccessMapResult {
        cloud: "huggingface".into(),
        identity,
        roles,
        permissions,
        resources,
        severity,
        recommendations: build_recommendations(severity),
        risk_notes,
        token_details: Some(AccessTokenDetails {
            name: token_name.or_else(|| whoami.full_name.clone()),
            username: whoami.name.clone(),
            account_type: whoami.r#type.clone(),
            company: None,
            location: None,
            email: whoami.email.clone(),
            url: Some(format!("https://huggingface.co/{username}")),
            token_type,
            created_at: token_created,
            last_used_at: None,
            expires_at: None,
            user_id: Some(username),
            scopes: token_role.into_iter().collect(),
        }),
        provider_metadata: None,
        fingerprint: None,
    })
}

async fn list_user_models(client: &Client, token: &str, username: &str) -> Result<Vec<HfModel>> {
    let mut models = Vec::new();
    let limit = 100;

    let resp = client
        .get(format!("{HUGGINGFACE_API}/models"))
        .query(&[("author", username), ("limit", &limit.to_string())])
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .send()
        .await
        .context("Hugging Face access-map: failed to list models")?;

    if !resp.status().is_success() {
        warn!("Hugging Face access-map: model enumeration failed with HTTP {}", resp.status());
        return Ok(models);
    }

    let page_models: Vec<HfModel> =
        resp.json().await.context("Hugging Face access-map: invalid model JSON")?;
    models.extend(page_models);

    Ok(models)
}

fn derive_severity(token_role: &Option<String>, models: &[HfModel]) -> Severity {
    if let Some(role) = token_role {
        match role.as_str() {
            "admin" | "fineGrained" => return Severity::High,
            "write" => {
                if models.iter().any(|m| m.private) {
                    return Severity::High;
                }
                return Severity::Medium;
            }
            _ => {}
        }
    }

    if models.iter().any(|m| m.private) {
        Severity::Medium
    } else {
        Severity::Low
    }
}

fn severity_to_str(severity: Severity) -> &'static str {
    match severity {
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}
