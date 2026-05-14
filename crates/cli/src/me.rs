//! `azvpn me` — GET /v1.0/me via the refreshed Graph token. Same canonical
//! call the official Microsoft Azure VPN Client makes post-auth (verified
//! against the Ghidra decomp of
//! `MacTunnelExtension::AadController::getContentWithToken`).

use serde::Deserialize;

use crate::aad;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Aad(#[from] aad::Error),
    #[error("graph: {0}")]
    Graph(String),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}

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

pub async fn run() -> Result<(), Error> {
    let client = aad::graph_client().await?;
    let response = client
        .me()
        .get_user()
        .send()
        .await
        .map_err(|e| Error::Graph(e.to_string()))?;
    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(|e| Error::Graph(e.to_string()))?;
    if !status.is_success() {
        return Err(Error::Graph(format!("GET /v1.0/me → {status}: {body}")));
    }
    let user: GraphUser = serde_json::from_str(&body)?;
    print_user(&user);
    Ok(())
}

fn print_user(u: &GraphUser) {
    println!("graph: GET /v1.0/me");
    println!();
    if let Some(v) = &u.display_name {
        println!("name:     {v}");
    }
    if let (Some(g), Some(s)) = (&u.given_name, &u.surname) {
        println!("given:    {g} {s}");
    }
    if let Some(v) = &u.user_principal_name {
        println!("upn:      {v}");
    }
    if let Some(v) = &u.mail {
        println!("mail:     {v}");
    }
    if let Some(v) = &u.job_title {
        println!("title:    {v}");
    }
    if let Some(v) = &u.department {
        println!("dept:     {v}");
    }
    if let Some(v) = &u.office_location {
        println!("office:   {v}");
    }
    if let Some(v) = &u.mobile_phone {
        println!("phone:    {v}");
    }
    if let Some(v) = &u.id {
        println!("oid:      {v}");
    }
}
