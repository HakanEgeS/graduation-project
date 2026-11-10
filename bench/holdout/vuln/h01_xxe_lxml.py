from lxml import etree


def parse_order(xml_bytes: bytes):
    parser = etree.XMLParser(resolve_entities=True)
    return etree.fromstring(xml_bytes, parser)
