from osak.core.catalog import resolve_product, resolve_vendor


def test_publisher_spellings_join_on_vendor_scoped_ids() -> None:
    product = resolve_product("Arista Networks, Inc.", "Arista EOS")
    assert product is not None and product.id == "arista-eos"
    assert resolve_product("Cisco", "EOS") is None
    assert resolve_product("Cisco", "IOS XR") is None
    assert resolve_product("Cisco", "Cisco IOS XE Software").id == "cisco-iosxe"


def test_connector_annotations_do_not_mutate_shared_catalog() -> None:
    vendor = resolve_vendor("Fortinet, Inc.")
    assert vendor is not None
    vendor.aliases.clear()
    assert resolve_vendor("Fortinet").aliases
