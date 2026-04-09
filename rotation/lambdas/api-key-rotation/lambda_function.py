"""
Generic API Key Rotation Lambda
For third-party services that support key rotation (e.g., internal APIs).
Generates a new key, validates it, then promotes it.
"""
import boto3
import json
import logging
import secrets
import httpx

logger = logging.getLogger()
logger.setLevel(logging.INFO)

SM_CLIENT = boto3.client("secretsmanager")


def lambda_handler(event: dict, context) -> None:
    arn   = event["SecretId"]
    token = event["ClientRequestToken"]
    step  = event["Step"]

    steps = {
        "createSecret": _create_secret,
        "setSecret":    _set_secret,
        "testSecret":   _test_secret,
        "finishSecret": _finish_secret,
    }
    steps[step](arn, token)


def _create_secret(arn: str, token: str) -> None:
    """Generate a new API key placeholder (actual key issued by _set_secret)."""
    try:
        SM_CLIENT.get_secret_value(SecretId=arn, VersionId=token, VersionStage="AWSPENDING")
        return
    except SM_CLIENT.exceptions.ResourceNotFoundException:
        pass

    current = json.loads(SM_CLIENT.get_secret_value(SecretId=arn, VersionStage="AWSCURRENT")["SecretString"])
    pending = {**current, "api_key": f"PENDING-{secrets.token_hex(16)}", "status": "pending"}

    SM_CLIENT.put_secret_value(
        SecretId=arn,
        ClientRequestToken=token,
        SecretString=json.dumps(pending),
        VersionStages=["AWSPENDING"],
    )
    logger.info("Created pending version for %s", arn)


def _set_secret(arn: str, token: str) -> None:
    """Call the external API to provision a new key."""
    current = json.loads(SM_CLIENT.get_secret_value(SecretId=arn, VersionStage="AWSCURRENT")["SecretString"])
    api_url   = current["api_management_url"]
    admin_key = current["admin_api_key"]

    resp = httpx.post(
        f"{api_url}/keys",
        headers={"Authorization": f"Bearer {admin_key}"},
        json={"description": "Rotated by Secrets Manager", "ttl_days": 365},
        timeout=10,
    )
    resp.raise_for_status()
    new_key = resp.json()["api_key"]

    pending = {**current, "api_key": new_key, "status": "active"}
    SM_CLIENT.put_secret_value(
        SecretId=arn,
        ClientRequestToken=token,
        SecretString=json.dumps(pending),
        VersionStages=["AWSPENDING"],
    )
    logger.info("New API key provisioned for %s", arn)


def _test_secret(arn: str, token: str) -> None:
    """Verify the new key works."""
    pending = json.loads(SM_CLIENT.get_secret_value(SecretId=arn, VersionId=token, VersionStage="AWSPENDING")["SecretString"])
    resp = httpx.get(
        f"{pending['api_url']}/me",
        headers={"Authorization": f"Bearer {pending['api_key']}"},
        timeout=10,
    )
    resp.raise_for_status()
    logger.info("New API key validated for %s", arn)


def _finish_secret(arn: str, token: str) -> None:
    """Promote AWSPENDING to AWSCURRENT."""
    metadata = SM_CLIENT.describe_secret(SecretId=arn)
    current_ver = next(v for v, s in metadata["VersionIdsToStages"].items() if "AWSCURRENT" in s)
    if current_ver == token:
        return
    SM_CLIENT.update_secret_version_stage(
        SecretId=arn, VersionStage="AWSCURRENT",
        MoveToVersionId=token, RemoveFromVersionId=current_ver,
    )
    logger.info("Promoted new API key to AWSCURRENT for %s", arn)
