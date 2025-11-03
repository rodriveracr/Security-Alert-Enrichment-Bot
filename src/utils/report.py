import json
from pathlib import Path
from typing import Any, Dict


def write_json_report(obj: Dict[str, Any], path: Path) -> None:
    with path.open("w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)


def write_markdown_report(obj: Dict[str, Any], path: Path) -> None:
    lines = []
    alert = obj.get("alert", {})
    enrichment = obj.get("enrichment", {})

    lines.append(f"# Enrichment Report\n")
    lines.append("## Alert")
    for k, v in alert.items():
        lines.append(f"- **{k}**: {v}")

    lines.append("\n## Enrichment Summary")
    lines.append(f"- IP: {enrichment.get('ip')}")
    lines.append(f"- Domain: {enrichment.get('domain')}")

    lines.append("\n## VirusTotal")
    vt = enrichment.get("virustotal")
    lines.append("```")
    lines.append(json.dumps(vt, indent=2, ensure_ascii=False))
    lines.append("```")

    lines.append("\n## AbuseIPDB")
    abuse = enrichment.get("abuseipdb")
    lines.append("```")
    lines.append(json.dumps(abuse, indent=2, ensure_ascii=False))
    lines.append("```")

    lines.append("\n## Shodan")
    sh = enrichment.get("shodan")
    lines.append("```")
    lines.append(json.dumps(sh, indent=2, ensure_ascii=False))
    lines.append("```")

    with path.open("w", encoding="utf-8") as f:
        f.write("\n".join(lines))
