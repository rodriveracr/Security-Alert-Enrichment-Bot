import os
import requests
import certifi
from typing import Any, Dict


def abuse_lookup(ip: str) -> Dict[str, Any]:
    """Lookup IP in AbuseIPDB.

    If ABUSEIPDB_KEY not set, returns mock data.
    """
    key = os.getenv("ABUSEIPDB_KEY")
    print(f"[AbuseIPDB] API Key loaded: {'YES' if key else 'NO'}")
    if not ip:
        print("[AbuseIPDB] No IP provided.")
        return {"error": "no ip provided"}

    if not key:
        print("[AbuseIPDB] ABUSEIPDB_KEY not set; returning mock result.")
        return {
            "note": "ABUSEIPDB_KEY not set; returning mock result",
            "ip": ip,
            "abuseConfidenceScore": 0,
            "countryCode": "US",
        }

    url = "https://api.abuseipdb.com/api/v2/check"
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    headers = {"Key": key, "Accept": "application/json"}

    print(f"[AbuseIPDB] Querying URL: {url} with IP: {ip}")
    try:
        r = requests.get(url, headers=headers, params=params, timeout=15, verify=certifi.where())
        print(f"[AbuseIPDB] Response status: {r.status_code}")
        r.raise_for_status()
        print(f"[AbuseIPDB] Response JSON: {r.text[:200]}")
        abuse_data = r.json()
        data = abuse_data.get('data', {})
        score = data.get('abuseConfidenceScore')
        reports = data.get('totalReports')
        return {
            'score': score,
            'reports': reports
        }
    except Exception as e:
        print(f"[AbuseIPDB] Error: {e}")
        return {"error": str(e)}


def enrich_abuseipdb(ip: str) -> dict:
    return abuse_lookup(ip)
