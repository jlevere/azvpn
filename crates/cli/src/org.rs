//! `azvpn org` — GET /v1.0/organization. Returns metadata about the tenant
//! the current identity belongs to: display name, country, verified domains,
//! and the technical / security / privacy contact addresses.

use azvpn_auth::cloud;
use serde::Deserialize;

use crate::Result;

#[derive(Deserialize)]
struct ListResponse {
    value: Vec<Organization>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct Organization {
    id: Option<String>,
    display_name: Option<String>,
    country: Option<String>,
    country_letter_code: Option<String>,
    tenant_type: Option<String>,
    created_date_time: Option<String>,
    on_premises_sync_enabled: Option<bool>,
    #[serde(default)]
    verified_domains: Vec<VerifiedDomain>,
    #[serde(default)]
    technical_notification_mails: Vec<String>,
    #[serde(default)]
    security_compliance_notification_mails: Vec<String>,
    privacy_profile: Option<PrivacyProfile>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct VerifiedDomain {
    name: Option<String>,
    is_default: Option<bool>,
    is_initial: Option<bool>,
    capabilities: Option<String>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct PrivacyProfile {
    contact_email: Option<String>,
    statement_url: Option<String>,
}

pub async fn run() -> Result<()> {
    let list: ListResponse = cloud::graph_get("/organization").await?;
    println!("graph: GET /v1.0/organization");
    for org in &list.value {
        println!();
        print_org(org);
    }
    Ok(())
}

fn print_org(o: &Organization) {
    if let Some(v) = &o.display_name {
        println!("name:           {v}");
    }
    if let Some(v) = &o.id {
        println!("tenant id:      {v}");
    }
    if let Some(v) = &o.tenant_type {
        println!("type:           {v}");
    }
    if let Some(c) = &o.country {
        let code = o.country_letter_code.as_deref().unwrap_or("");
        if code.is_empty() {
            println!("country:        {c}");
        } else {
            println!("country:        {c} ({code})");
        }
    }
    if let Some(t) = &o.created_date_time {
        println!("created:        {t}");
    }
    if let Some(sync) = o.on_premises_sync_enabled {
        println!("on-prem sync:   {sync}");
    }
    if !o.technical_notification_mails.is_empty() {
        println!(
            "technical:      {}",
            o.technical_notification_mails.join(", ")
        );
    }
    if !o.security_compliance_notification_mails.is_empty() {
        println!(
            "security:       {}",
            o.security_compliance_notification_mails.join(", ")
        );
    }
    if let Some(p) = &o.privacy_profile {
        if let Some(e) = &p.contact_email {
            println!("privacy email:  {e}");
        }
        if let Some(u) = &p.statement_url {
            println!("privacy url:    {u}");
        }
    }
    if !o.verified_domains.is_empty() {
        println!("verified domains ({}):", o.verified_domains.len());
        for d in &o.verified_domains {
            let name = d.name.as_deref().unwrap_or("(unknown)");
            let mut tags = Vec::new();
            if d.is_default == Some(true) {
                tags.push("default");
            }
            if d.is_initial == Some(true) {
                tags.push("initial");
            }
            if let Some(caps) = &d.capabilities {
                tags.push(caps);
            }
            if tags.is_empty() {
                println!("  {name}");
            } else {
                println!("  {name}  [{}]", tags.join(", "));
            }
        }
    }
}
