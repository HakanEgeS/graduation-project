from defusedxml import ElementTree


def parse_order(xml_bytes: bytes):
    return ElementTree.fromstring(xml_bytes)
