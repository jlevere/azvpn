//! `azvpn groups` — GET /v1.0/me/memberOf. Lists the AAD groups and
//! directory roles the current user is a direct member of.
//!
//! Scope note: the Azure VPN client app registration only consented to
//! `User.Read` + `User.ReadBasic.All`, neither of which grants
//! `Group.Read.All` or `GroupMember.Read.All`. The /memberOf endpoint
//! still works — Graph returns the membership IDs (so you know which
//! groups you're in) — but every group's `displayName`, `description`,
//! etc. come back as `null` because we don't have permission to read
//! group properties. We surface IDs and the @odata.type so the
//! information is still useful.

use serde::Deserialize;

use crate::{Result, aad};

#[derive(Deserialize)]
struct ListResponse {
    value: Vec<DirectoryObject>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct DirectoryObject {
    #[serde(rename = "@odata.type", default)]
    odata_type: Option<String>,
    id: Option<String>,
    display_name: Option<String>,
    description: Option<String>,
    mail: Option<String>,
    security_enabled: Option<bool>,
    mail_enabled: Option<bool>,
}

pub async fn run() -> Result<()> {
    let list: ListResponse = aad::graph_get("/me/memberOf?$top=999").await?;

    println!("graph: GET /v1.0/me/memberOf");
    println!("count: {}", list.value.len());

    let mut groups: Vec<DirectoryObject> = Vec::with_capacity(list.value.len());
    let mut roles: Vec<DirectoryObject> = Vec::new();
    for obj in list.value {
        if obj.odata_type.as_deref() == Some("#microsoft.graph.directoryRole") {
            roles.push(obj);
        } else {
            groups.push(obj);
        }
    }
    groups.sort_by(|a, b| a.display_name.cmp(&b.display_name).then(a.id.cmp(&b.id)));
    roles.sort_by(|a, b| a.display_name.cmp(&b.display_name).then(a.id.cmp(&b.id)));

    let all_names_hidden = groups
        .iter()
        .chain(roles.iter())
        .all(|o| o.display_name.is_none());
    if all_names_hidden && !(groups.is_empty() && roles.is_empty()) {
        println!();
        println!("note: every property returned null — the Azure VPN client token is");
        println!("      scoped to User.Read; group names need Group.Read.All. The IDs");
        println!("      below are valid memberships, just unlabeled.");
    }

    if !roles.is_empty() {
        println!();
        println!("directory roles ({})", roles.len());
        for r in &roles {
            print_object(r);
        }
    }
    if !groups.is_empty() {
        println!();
        println!("groups ({})", groups.len());
        for g in &groups {
            print_object(g);
        }
    }
    Ok(())
}

fn print_object(obj: &DirectoryObject) {
    let id = obj.id.as_deref().unwrap_or("(no id)");
    match &obj.display_name {
        Some(name) => println!("  {name}  ({id})"),
        None => println!("  {id}"),
    }
    if let Some(desc) = obj.description.as_deref().filter(|s| !s.is_empty()) {
        println!("    {desc}");
    }
    if let Some(mail) = &obj.mail {
        println!("    mail: {mail}");
    }
    let mut tags = Vec::new();
    if obj.mail_enabled == Some(true) {
        tags.push("mail-enabled");
    }
    if obj.security_enabled == Some(true) {
        tags.push("security");
    }
    if let Some(ty) = obj.odata_type.as_deref() {
        if let Some(short) = ty.strip_prefix("#microsoft.graph.") {
            tags.push(short);
        }
    }
    if !tags.is_empty() {
        println!("    [{}]", tags.join(", "));
    }
}
