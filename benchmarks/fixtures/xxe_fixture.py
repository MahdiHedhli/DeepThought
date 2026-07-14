# XXE (CWE-611) fixture (Python/lxml), modeled on python-docx CVE-2016-5851.
from lxml import etree


def vulnerable_parser():
    # external entities resolved by default -> XXE on untrusted XML
    return etree.XMLParser(remove_blank_text=True)


def safe_parser():
    # resolve_entities=False disables external entity expansion
    return etree.XMLParser(remove_blank_text=True, resolve_entities=False)
