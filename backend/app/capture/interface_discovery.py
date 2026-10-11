import os
from typing import Dict, List, Optional
from scapy.all import conf, get_if_list
from scapy.arch.windows import get_windows_if_list

from app.core.logging import logger
from app.schemas.capture import InterfaceInfo


def is_npcap_installed() -> bool:
    """
    Checks if Npcap is installed on the Windows system.
    """
    npcap_paths = [
        os.path.join(os.environ.get("SystemRoot", "C:\\Windows"), "System32", "Npcap"),
        os.path.join(os.environ.get("ProgramFiles", "C:\\Program Files"), "Npcap"),
    ]
    for p in npcap_paths:
        if os.path.exists(p):
            return True
    return False


class InterfaceDiscoveryService:
    """
    Service for discovering and validating network interfaces on the local host.
    """

    @staticmethod
    def list_interfaces() -> List[InterfaceInfo]:
        """
        Discovers all available network interfaces using Scapy Windows interface registry.
        """
        interfaces: List[InterfaceInfo] = []

        try:
            win_if_list = get_windows_if_list()
        except Exception as exc:
            logger.error(f"Failed to query Windows interfaces via Scapy: {exc}")
            win_if_list = []

        for iface in win_if_list:
            iface_id = iface.get("name") or iface.get("guid") or ""
            name = iface.get("name") or iface.get("description") or "Unknown Interface"
            desc = iface.get("description")
            mac = iface.get("mac")

            ips: List[str] = []
            if iface.get("ips"):
                for ip in iface["ips"]:
                    if ip and ip not in ips:
                        ips.append(str(ip))

            is_loopback = False
            if "loopback" in name.lower() or "loopback" in (desc or "").lower():
                is_loopback = True

            # Determine status based on presence of IPs or link status
            status = "Up" if (ips and mac) else "Down"

            interfaces.append(
                InterfaceInfo(
                    id=iface_id,
                    name=name,
                    description=desc,
                    mac_address=mac,
                    ip_addresses=ips,
                    status=status,
                    is_loopback=is_loopback,
                )
            )

        # Fallback to get_if_list if no Windows interfaces were found
        if not interfaces:
            try:
                raw_list = get_if_list()
                for item in raw_list:
                    interfaces.append(
                        InterfaceInfo(
                            id=str(item),
                            name=str(item),
                            description=None,
                            mac_address=None,
                            ip_addresses=[],
                            status="Unknown",
                            is_loopback=("lo" in str(item).lower()),
                        )
                    )
            except Exception as exc:
                logger.error(f"Fallback get_if_list failed: {exc}")

        return interfaces

    @staticmethod
    def get_interface_by_id(interface_id: str) -> Optional[InterfaceInfo]:
        """
        Retrieves a specific interface by ID or name.
        """
        for iface in InterfaceDiscoveryService.list_interfaces():
            if iface.id == interface_id or iface.name == interface_id:
                return iface
        return None

    @staticmethod
    def validate_interface_id(interface_id: str) -> bool:
        """
        Checks whether the specified interface ID exists on the machine.
        """
        return InterfaceDiscoveryService.get_interface_by_id(interface_id) is not None
