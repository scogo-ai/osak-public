"""Vendor-aware version schemes used by OSAK's deterministic matcher."""

from osak.versions.arista_eos import AristaEOSScheme
from osak.versions.base import VersionScheme
from osak.versions.cisco_asa import CiscoASAScheme
from osak.versions.cisco_ios import CiscoIOSScheme
from osak.versions.cisco_iosxe import CiscoIOSXEScheme
from osak.versions.cisco_literal import CiscoLiteralScheme
from osak.versions.cisco_nxos import CiscoNXOSScheme
from osak.versions.fortios import FortiOSScheme

_SCHEMES: dict[str, VersionScheme] = {
    "arista_eos": AristaEOSScheme(),
    "cisco_asa": CiscoASAScheme(),
    "cisco_ios": CiscoIOSScheme(),
    "cisco_iosxe": CiscoIOSXEScheme(),
    "cisco_nxos": CiscoNXOSScheme(),
    "cisco_literal": CiscoLiteralScheme(),
    "fortios": FortiOSScheme(),
}


def get_scheme(name: str) -> VersionScheme | None:
    """Return the registered scheme for ``name`` or ``None`` if unsupported."""

    return _SCHEMES.get(name.strip().lower())


__all__ = [
    "AristaEOSScheme",
    "CiscoASAScheme",
    "CiscoIOSScheme",
    "CiscoIOSXEScheme",
    "CiscoLiteralScheme",
    "CiscoNXOSScheme",
    "FortiOSScheme",
    "VersionScheme",
    "get_scheme",
]
