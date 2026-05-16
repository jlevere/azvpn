//! `azvpn profile <import|list|remove>` dispatch. Thin shell over
//! [`crate::profile_store`].

use std::path::Path;

use crate::Result;
use crate::profile_store;

pub fn import(src: &Path, name: Option<&str>, force: bool) -> Result<()> {
    let dest = profile_store::import(src, name, force)?;
    eprintln!("imported -> {}", dest.display());
    Ok(())
}

pub fn list() {
    let entries = profile_store::list();
    if entries.is_empty() {
        eprintln!("no profiles registered. Import with: `azvpn profile import <path>`");
        return;
    }
    for entry in &entries {
        println!("{:<24} {}", entry.name, entry.path.display());
    }
}

pub fn remove(name: &str) -> Result<()> {
    profile_store::remove(name)?;
    eprintln!("removed `{name}`");
    Ok(())
}
