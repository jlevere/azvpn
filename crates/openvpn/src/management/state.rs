//! VPN connection-state enum reported by openvpn's `>STATE:` messages.
//! The wire form is a comma-separated tuple `timestamp,STATE,desc,...`;
//! we parse the second column into [`VpnState`] and discard the rest at
//! the boundary so consumers work with a typed enum.

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum VpnState {
    Connecting,
    Resolve,
    TcpConnect,
    Wait,
    Auth,
    GetConfig,
    AssignIp,
    AddRoutes,
    Connected,
    Reconnecting,
    Exiting,
    Unknown(String),
}

impl VpnState {
    pub(crate) fn parse(s: &str) -> Self {
        match s {
            "CONNECTING" => Self::Connecting,
            "RESOLVE" => Self::Resolve,
            "TCP_CONNECT" => Self::TcpConnect,
            "WAIT" => Self::Wait,
            "AUTH" => Self::Auth,
            "GET_CONFIG" => Self::GetConfig,
            "ASSIGN_IP" => Self::AssignIp,
            "ADD_ROUTES" => Self::AddRoutes,
            "CONNECTED" => Self::Connected,
            "RECONNECTING" => Self::Reconnecting,
            "EXITING" => Self::Exiting,
            other => Self::Unknown(other.to_owned()),
        }
    }

    /// Whether an operator skimming `azvpnd`'s log would want to see
    /// this state transition by default. Stops the noisy intermediate
    /// states that openvpn fires through on every connect/reneg
    /// (Resolve, TcpConnect, Wait, GetConfig, AssignIp, AddRoutes)
    /// from dominating an `info`-level log, while keeping the
    /// operationally meaningful transitions visible:
    /// Connecting / Auth / Connected / Reconnecting / Exiting and any
    /// Unknown openvpn doesn't have a typed variant for.
    #[must_use]
    pub fn is_operationally_significant(&self) -> bool {
        matches!(
            self,
            Self::Connecting
                | Self::Auth
                | Self::Connected
                | Self::Reconnecting
                | Self::Exiting
                | Self::Unknown(_)
        )
    }
}
