import json
from pathlib import Path
from typing import Any, Dict
import os
import logging


logger = logging.getLogger(__name__)


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


def write_and_maybe_upload(obj: Dict[str, Any], json_path: Path, md_path: Path) -> None:
    """Write both JSON and MD reports and, if `S3_BUCKET` is configured, upload them to S3.

    Environment variables:
    - S3_BUCKET: bucket name to upload reports
    - S3_PREFIX: optional key prefix
    - AWS_REGION: optional AWS region
    - AWS_SECRET_NAME: optional secret name to fetch via Secrets Manager (read-only)
    """
    write_json_report(obj, json_path)
    write_markdown_report(obj, md_path)

    bucket = os.getenv("S3_BUCKET")
    if not bucket:
        logger.debug("S3_BUCKET not set; skipping upload")
        return

    s3_prefix = os.getenv("S3_PREFIX", "")
    region = os.getenv("AWS_REGION") or None

    # Lazy import to keep boto3 optional
    try:
        from .aws import upload_file_to_s3, get_secret
    except Exception:
        logger.exception("AWS helpers unavailable; ensure boto3 is installed")
        return

    # Optionally fetch secrets (useful to validate access)
    secret_name = os.getenv("AWS_SECRET_NAME")
    if secret_name:
        secret = get_secret(secret_name, region)
        logger.debug("Fetched secret %s: %s", secret_name, bool(secret))

    # Upload files
    json_key = f"{s3_prefix.rstrip('/')}/{json_path.name}" if s3_prefix else json_path.name
    md_key = f"{s3_prefix.rstrip('/')}/{md_path.name}" if s3_prefix else md_path.name

    upload_file_to_s3(json_path, bucket, json_key, region)
    upload_file_to_s3(md_path, bucket, md_key, region)
