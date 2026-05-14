//! `azvpn manager` — GET /v1.0/me/manager. Returns who you report to,
//! per the org chart configured in Microsoft Entra ID.

use serde::Deserialize;

use crate::{Error, Result, aad};

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct GraphUser {
    display_name: Option<String>,
    user_principal_name: Option<String>,
    mail: Option<String>,
    job_title: Option<String>,
    department: Option<String>,
    id: Option<String>,
}

pub async fn run() -> Result<()> {
    match aad::graph_get::<GraphUser>("/me/manager").await {
        Ok(mgr) => {
            println!("graph: GET /v1.0/me/manager");
            println!();
            print_manager(&mgr);
            Ok(())
        }
        Err(Error::HttpStatus { status, .. }) if status == reqwest::StatusCode::NOT_FOUND => {
            println!("(no manager configured in Entra ID for this user)");
            Ok(())
        }
        Err(e) => Err(e),
    }
}

fn print_manager(mgr: &GraphUser) {
    if let Some(v) = &mgr.display_name {
        println!("name:     {v}");
    }
    if let Some(v) = &mgr.user_principal_name {
        println!("upn:      {v}");
    }
    if let Some(v) = &mgr.mail {
        println!("mail:     {v}");
    }
    if let Some(v) = &mgr.job_title {
        println!("title:    {v}");
    }
    if let Some(v) = &mgr.department {
        println!("dept:     {v}");
    }
    if let Some(v) = &mgr.id {
        println!("oid:      {v}");
    }
}
