//! `azvpn me` — GET /v1.0/me via the refreshed Graph token. Same canonical
//! call the official Microsoft Azure VPN Client makes post-auth (verified
//! against the Ghidra decomp of
//! `MacTunnelExtension::AadController::getContentWithToken`).

use serde::Deserialize;

use crate::{Result, aad};

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct GraphUser {
    display_name: Option<String>,
    given_name: Option<String>,
    surname: Option<String>,
    mail: Option<String>,
    user_principal_name: Option<String>,
    job_title: Option<String>,
    department: Option<String>,
    office_location: Option<String>,
    mobile_phone: Option<String>,
    id: Option<String>,
}

pub async fn run() -> Result<()> {
    let user: GraphUser = aad::graph_get("/me").await?;
    println!("graph: GET /v1.0/me");
    println!();
    if let Some(v) = &user.display_name {
        println!("name:     {v}");
    }
    if let (Some(g), Some(s)) = (&user.given_name, &user.surname) {
        println!("given:    {g} {s}");
    }
    if let Some(v) = &user.user_principal_name {
        println!("upn:      {v}");
    }
    if let Some(v) = &user.mail {
        println!("mail:     {v}");
    }
    if let Some(v) = &user.job_title {
        println!("title:    {v}");
    }
    if let Some(v) = &user.department {
        println!("dept:     {v}");
    }
    if let Some(v) = &user.office_location {
        println!("office:   {v}");
    }
    if let Some(v) = &user.mobile_phone {
        println!("phone:    {v}");
    }
    if let Some(v) = &user.id {
        println!("oid:      {v}");
    }
    Ok(())
}
