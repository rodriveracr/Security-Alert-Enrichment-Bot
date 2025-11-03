import os
from typing import Any, Dict
import requests
import certifi


def shodan_lookup(target: str) -> Dict[str, Any]:
    """Query Shodan for IP/domain. Returns mock if no key is set.

    The real Shodan API requires registration. This function keeps behavior simple.
    """
    key = os.getenv("SHODAN_KEY")
    print(f"[Shodan] API Key loaded: {'YES' if key else 'NO'}")
    if not target:
        print("[Shodan] No target provided.")
        return {"error": "no target provided"}

    if not key:
        print("[Shodan] SHODAN_KEY not set; returning mock result.")
        return {"note": "SHODAN_KEY not set; returning mock result", "target": target, "ports": []}

    if any(c.isalpha() for c in target):
        print(f"[Shodan] Domain lookup not implemented for Shodan. Target: {target}")
        return {"note": "domain lookup not implemented for Shodan in this minimal enricher", "target": target}

    url = f"https://api.shodan.io/shodan/host/{target}"
    params = {"key": key}
    print(f"[Shodan] Querying URL: {url}")
    try:
        r = requests.get(url, params=params, timeout=15, verify=certifi.where())
        print(f"[Shodan] Response status: {r.status_code}")
        r.raise_for_status()
        print(f"[Shodan] Response JSON: {r.text[:200]}")
        shodan_data = r.json()
        open_ports = shodan_data.get('ports')
        org = shodan_data.get('org')
        return {
            'open_ports': open_ports,
            'org': org
        }
    except Exception as e:
        print(f"[Shodan] Error: {e}")
        return {"error": str(e)}


def enrich_shodan(target: str) -> dict:
    return shodan_lookup(target)
