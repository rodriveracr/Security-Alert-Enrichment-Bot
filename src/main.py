import json
import os
from pathlib import Path

from dotenv import load_dotenv

from src.enrichers.virustotal import vt_lookup
from src.enrichers.abuseipdb import abuse_lookup
from src.enrichers.shodan_api import shodan_lookup
from src.utils.report import write_json_report, write_markdown_report


def main():
    # load .env if present
    load_dotenv()

    base = Path(__file__).resolve().parents[1]
    data_file = base / "data" / "alert.json"

    if not data_file.exists():
        print(f"Missing input file: {data_file}")
        return

    with data_file.open() as f:
        alert = json.load(f)

    ip = alert.get("source_ip")
    domain = alert.get("source_domain")

    vt = vt_lookup(ip) if ip else None
    abuse = abuse_lookup(ip) if ip else None
    shodan = shodan_lookup(ip or domain)

    enriched = {
        "alert": alert,
        "enrichment": {
            "ip": ip,
            "domain": domain,
            "virustotal": vt,
            "abuseipdb": abuse,
            "shodan": shodan,
        },
    }

    reports_dir = base / "reports"
    reports_dir.mkdir(exist_ok=True)

    json_path = reports_dir / "result.json"
    md_path = reports_dir / "result.md"

    write_json_report(enriched, json_path)
    write_markdown_report(enriched, md_path)

    print(f"✅ Enrichment completed. See {json_path}")


if __name__ == "__main__":
    main()
