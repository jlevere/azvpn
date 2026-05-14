use azvpn_core::session::RunningSession;
use azvpn_openvpn::ManagementClient;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("session: {0}")]
    Session(#[from] azvpn_core::session::Error),
    #[error("management: {0}")]
    Management(#[from] azvpn_openvpn::Error),
}

pub async fn run() -> Result<(), Error> {
    let Some(session) = RunningSession::load()? else {
        eprintln!("not connected");
        return Ok(());
    };

    match ManagementClient::connect(session.mgmt_addr).await {
        Ok(mut mgmt) => {
            mgmt.send("signal SIGTERM").await?;
            eprintln!("disconnect signal sent to pid {}", session.pid);
        }
        Err(e) => {
            eprintln!(
                "session file present but management socket unreachable ({e}); \
                 clearing stale session"
            );
            RunningSession::clear()?;
        }
    }
    Ok(())
}
