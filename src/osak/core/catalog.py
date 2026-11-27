"""Shared product identities for the network OS feeds.

Publishers spell the same product differently. Resolve only explicit product
names here. Hardware PIDs and release strings belong to their own data sources.
"""

import re

from osak.core.models import Product, Vendor


def _key(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.casefold())


_VENDORS = (
    Vendor(id="cisco", name="Cisco", aliases=["Cisco Systems", "Cisco Systems, Inc."]),
    Vendor(id="fortinet", name="Fortinet", aliases=["Fortinet, Inc."]),
    Vendor(id="arista", name="Arista Networks", aliases=["Arista", "Arista Networks, Inc."]),
)


def _product(
    vendor: str, short_id: str, os_name: str, scheme: str, family: str, *aliases: str
) -> Product:
    return Product(
        id=f"{vendor}-{short_id}",
        vendor_id=vendor,
        family=family,
        os=os_name,
        scheme=scheme,
        aliases=list(aliases),
    )


_PRODUCTS = (
    _product("fortinet", "fortios", "FortiOS", "fortios", "FortiGate", "Fortinet FortiOS"),
    _product("arista", "eos", "EOS", "arista_eos", "Arista EOS", "Extensible Operating System"),
    _product("cisco", "ios", "IOS", "cisco_ios", "Cisco IOS", "Cisco IOS Software"),
    _product("cisco", "iosxe", "IOS XE", "cisco_iosxe", "Cisco IOS XE", "Cisco IOS XE Software"),
    _product("cisco", "nxos", "NX-OS", "cisco_nxos", "Cisco NX-OS", "Cisco NX-OS Software"),
    _product(
        "cisco",
        "asa",
        "ASA",
        "cisco_asa",
        "Cisco ASA",
        "Cisco Adaptive Security Appliance Software",
        "Cisco Adaptive Security Appliance (ASA) Software",
        "Cisco Secure Firewall Adaptive Security Appliance (ASA) Software",
        "Adaptive Security Appliance Software",
    ),
    _product(
        "cisco",
        "fmc",
        "FMC",
        "cisco_literal",
        "Firewall Management Center",
        "Cisco Secure Firewall Management Center",
        "Cisco Firepower Management Center",
    ),
    _product(
        "cisco",
        "ftd",
        "FTD",
        "cisco_literal",
        "Firepower Threat Defense",
        "Cisco Firepower Threat Defense Software",
        "Cisco Secure Firewall Threat Defense",
        "Cisco Secure Firewall Threat Defense (FTD) Software",
    ),
    _product(
        "cisco",
        "fxos",
        "FXOS",
        "cisco_literal",
        "Cisco FXOS",
        "Cisco Firepower Extensible Operating System",
    ),
)

_VENDOR_INDEX = {
    _key(alias): vendor
    for vendor in _VENDORS
    for alias in (vendor.id, vendor.name, *vendor.aliases)
}
_PRODUCT_INDEX = {
    (product.vendor_id, _key(alias)): product
    for product in _PRODUCTS
    for alias in (product.id, product.os, product.family, *product.aliases)
}


def resolve_vendor(name: str) -> Vendor | None:
    vendor = _VENDOR_INDEX.get(_key(name))
    return vendor.model_copy(deep=True) if vendor else None


def resolve_product(vendor: str, name: str) -> Product | None:
    owner = _VENDOR_INDEX.get(_key(vendor))
    if owner is None:
        return None
    product = _PRODUCT_INDEX.get((owner.id, _key(name)))
    return product.model_copy(deep=True) if product else None
