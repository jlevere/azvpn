use std::net::SocketAddr;
use std::path::Path;

use tokio::process::{Child, Command};
use tracing::{debug, info, instrument};

use crate::{Error, ManagementClient, OpenVpnConfig};

pub struct OpenVpnProcess {
    child: Child,
    management_addr: SocketAddr,
}

impl OpenVpnProcess {
    #[instrument(skip_all)]
    pub fn start(ovpn_config: &OpenVpnConfig, config_path: &Path) -> Result<Self, Error> {
        info!(
            binary = %ovpn_config.openvpn_binary.display(),
            config = %config_path.display(),
            "starting openvpn"
        );

        let child = Command::new(&ovpn_config.openvpn_binary)
            .arg("--config")
            .arg(config_path)
            .arg("--suppress-timestamps")
            .kill_on_drop(true)
            .spawn()
            .map_err(Error::ProcessStart)?;

        debug!(pid = child.id(), "openvpn process started");

        Ok(Self {
            child,
            management_addr: ovpn_config.management_addr,
        })
    }

    #[instrument(skip_all, fields(addr = %self.management_addr))]
    pub async fn connect_management(&self) -> Result<ManagementClient, Error> {
        let mut attempts = 0;
        loop {
            match ManagementClient::connect(self.management_addr).await {
                Ok(client) => return Ok(client),
                Err(_) if attempts < 20 => {
                    attempts += 1;
                    debug!(attempt = attempts, "management not ready yet, retrying");
                    tokio::time::sleep(std::time::Duration::from_millis(250)).await;
                }
                Err(e) => return Err(e),
            }
        }
    }

    pub fn kill(&mut self) {
        let _ = self.child.start_kill();
    }

    pub async fn wait(&mut self) -> Result<Option<i32>, Error> {
        let status = self.child.wait().await.map_err(Error::ProcessStart)?;
        Ok(status.code())
    }
}

impl Drop for OpenVpnProcess {
    fn drop(&mut self) {
        self.kill();
    }
}
