azvpn — first-run guide
=======================

The MSI installed the `azvpnd` Windows service and added this directory
to the system PATH. The service is running now and will auto-start on
boot.

Next:

  1. Download your Azure profile XML from the Azure portal:
       Virtual Network Gateway -> Point-to-site -> "Download VPN client"
     Unzip the bundle and locate AzureVpnProfile.xml.

  2. Register the profile:
       azvpn profile import <path-to-AzureVpnProfile.xml>

  3. Authenticate against Entra ID:
       azvpn login

  4. Bring the tunnel up:
       azvpn up

  5. Verify:
       azvpn status

To tear it all down:

  azvpn uninstall-daemon                # stops + removes the service
  azvpn uninstall-daemon --purge        # also wipes profiles + cached tokens
  (then uninstall via "Apps & features" or msiexec /x)

Logs live at C:\ProgramData\azvpn\logs\daemon.log.<date> with daily
rotation and 7-day retention.

Project: https://github.com/jlevere/azvpn
