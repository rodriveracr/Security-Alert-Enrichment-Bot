import json
import logging
from pathlib import Path
from typing import Any, Dict, Optional


logger = logging.getLogger(__name__)


def _get_boto3_client(service: str, region_name: Optional[str] = None):
    try:
        import boto3
    except Exception:
        return None
    return boto3.client(service, region_name=region_name) if region_name else boto3.client(service)


def get_secret(secret_name: str, region_name: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Retrieve a secret from AWS Secrets Manager. Returns dict if secret is JSON, otherwise raw string under key 'value'."""
    client = _get_boto3_client("secretsmanager", region_name)
    if client is None:
        logger.debug("boto3 not installed or unavailable; skipping Secrets Manager access")
        return None

    try:
        resp = client.get_secret_value(SecretId=secret_name)
        secret = resp.get("SecretString")
        if not secret:
            return None
        try:
            return json.loads(secret)
        except Exception:
            return {"value": secret}
    except Exception as e:
        logger.exception("Failed to get secret %s: %s", secret_name, e)
        return None


def upload_file_to_s3(file_path: Path, bucket: str, key: str, region_name: Optional[str] = None) -> bool:
    """Upload a local file to S3. Returns True if success."""
    client = _get_boto3_client("s3", region_name)
    if client is None:
        logger.debug("boto3 not installed or unavailable; skipping S3 upload")
        return False

    try:
        client.upload_file(str(file_path), bucket, key)
        logger.info("Uploaded %s to s3://%s/%s", file_path, bucket, key)
        return True
    except Exception as e:
        logger.exception("S3 upload failed for %s: %s", file_path, e)
        return False
