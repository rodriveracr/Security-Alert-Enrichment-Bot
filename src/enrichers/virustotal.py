import os
import requests
import certifi

from typing import Any, Dict


def vt_lookup(indicator: str) -> Dict[str, Any]:
    """Lookup an IP or domain in VirusTotal v3.

    If VT_API_KEY is not set, returns a small mocked response so the pipeline can run.
    """
    key = os.getenv("VT_API_KEY")
    print(f"[VT] API Key loaded: {'YES' if key else 'NO'}")
    if not indicator:
        print("[VT] No indicator provided.")
        return {"error": "no indicator provided"}

    if not key:
        print("[VT] VT_API_KEY not set; returning mock result.")
        return {
            "note": "VT_API_KEY not set; returning mock result",
            "indicator": indicator,
            "malicious": False,
            "detected_engines": 0,
        }

    headers = {"x-apikey": key}
    if any(c.isalpha() for c in indicator):
        url = f"https://www.virustotal.com/api/v3/domains/{indicator}"
    else:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{indicator}"

    print(f"[VT] Querying URL: {url}")
    try:
        r = requests.get(url, headers=headers, timeout=15, verify=certifi.where())
        print(f"[VT] Response status: {r.status_code}")
        r.raise_for_status()
        print(f"[VT] Response JSON: {r.text[:200]}")
        vt_data = r.json()
        # Extract reputation and detected URLs
        attributes = vt_data.get('data', {}).get('attributes', {})
        reputation = attributes.get('reputation')
        detected_urls = attributes.get('last_analysis_stats', {}).get('malicious')
        return {
            'reputation': reputation,
            'detected_urls': detected_urls
        }
    except Exception as e:
        print(f"[VT] Error: {e}")
        return {"error": str(e)}


def enrich_virustotal(indicator: str) -> dict:
    return vt_lookup(indicator)
