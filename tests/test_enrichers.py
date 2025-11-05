import os

from src.enrichers.virustotal import vt_lookup
from src.enrichers.abuseipdb import abuse_lookup
from src.enrichers.shodan_api import shodan_lookup


def test_virustotal_mock():
    # Ensure no API key is set for a predictable mock response
    os.environ.pop("VT_API_KEY", None)
    res = vt_lookup("example.com")
    assert isinstance(res, dict)
    assert "note" in res or "error" in res or "reputation" in res


def test_abuseipdb_mock():
    os.environ.pop("ABUSEIPDB_KEY", None)
    res = abuse_lookup("1.2.3.4")
    assert isinstance(res, dict)
    assert "note" in res or "score" in res or "error" in res


def test_shodan_mock():
    os.environ.pop("SHODAN_KEY", None)
    res = shodan_lookup("1.2.3.4")
    assert isinstance(res, dict)
    assert "note" in res or "open_ports" in res or "error" in res
