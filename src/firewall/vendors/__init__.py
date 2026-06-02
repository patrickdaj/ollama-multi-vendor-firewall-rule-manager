from src.config import DeviceConfig
from src.firewall.base import FirewallConnector


def get_connector(device: DeviceConfig) -> FirewallConnector:
    """Factory — return the right connector for the device's vendor."""
    match device.vendor:
        case "paloalto":
            from src.firewall.vendors.paloalto import PaloAltoConnector
            return PaloAltoConnector(device)
        case "cisco_asa":
            from src.firewall.vendors.cisco_asa import CiscoASAConnector
            return CiscoASAConnector(device)
        case "cisco_asa_ssh":
            # Legacy fallback for ASA firmware < 9.3 without REST API
            from src.firewall.vendors.cisco_asa_ssh import CiscoASASSHConnector
            return CiscoASASSHConnector(device)
        case "cisco_ftd":
            from src.firewall.vendors.cisco_ftd import CiscoFTDConnector
            return CiscoFTDConnector(device)
        case "fortinet":
            from src.firewall.vendors.fortinet import FortinetConnector
            return FortinetConnector(device)
        case _:
            raise ValueError(f"Unsupported vendor: {device.vendor}")
