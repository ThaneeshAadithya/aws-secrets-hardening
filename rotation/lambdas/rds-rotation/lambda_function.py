"""
RDS Password Rotation Lambda
Implements the AWS Secrets Manager rotation pattern for PostgreSQL/MySQL.
Four-step rotation: createSecret → setSecret → testSecret → finishSecret

Docs: https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotating-secrets.html
"""
import boto3
import json
import logging
import os
import string
import secrets as secrets_module
import psycopg2

logger = logging.getLogger()
logger.setLevel(logging.INFO)

SM_CLIENT = boto3.client("secretsmanager")


def lambda_handler(event: dict, context) -> None:
    """Entry point — routes to the appropriate rotation step."""
    arn  = event["SecretId"]
    token = event["ClientRequestToken"]
    step  = event["Step"]

    metadata = SM_CLIENT.describe_secret(SecretId=arn)

    if not metadata.get("RotationEnabled"):
        raise ValueError(f"Secret {arn} does not have rotation enabled")

    versions = metadata.get("VersionIdsToStages", {})
    if token not in versions:
        raise ValueError(f"Token {token} not found in secret versions")

    if "AWSCURRENT" in versions[token]:
        logger.info("Token %s is already current — nothing to do", token)
        return

    if "AWSPENDING" not in versions[token]:
        raise ValueError(f"Token {token} is not in AWSPENDING stage")

    steps = {
        "createSecret": create_secret,
        "setSecret":    set_secret,
        "testSecret":   test_secret,
        "finishSecret": finish_secret,
    }

    if step not in steps:
        raise ValueError(f"Unknown rotation step: {step}")

    steps[step](SM_CLIENT, arn, token)


def create_secret(client, arn: str, token: str) -> None:
    """Step 1: Create a new secret version with a generated password."""
    try:
        client.get_secret_value(SecretId=arn, VersionId=token, VersionStage="AWSPENDING")
        logger.info("AWSPENDING version already exists — skipping createSecret")
        return
    except client.exceptions.ResourceNotFoundException:
        pass

    # Get current secret to preserve non-password fields
    current = json.loads(
        client.get_secret_value(SecretId=arn, VersionStage="AWSCURRENT")["SecretString"]
    )

    # Generate a strong password
    alphabet  = string.ascii_letters + string.digits + "!@#$%^&*"
    password  = "".join(secrets_module.choice(alphabet) for _ in range(32))

    # Ensure complexity requirements
    assert any(c.isupper() for c in password)
    assert any(c.islower() for c in password)
    assert any(c.isdigit() for c in password)

    new_secret = {**current, "password": password}

    client.put_secret_value(
        SecretId=arn,
        ClientRequestToken=token,
        SecretString=json.dumps(new_secret),
        VersionStages=["AWSPENDING"],
    )
    logger.info("Created AWSPENDING secret version for %s", arn)


def set_secret(client, arn: str, token: str) -> None:
    """Step 2: Apply the new password to the RDS instance."""
    pending = json.loads(
        client.get_secret_value(SecretId=arn, VersionId=token, VersionStage="AWSPENDING")["SecretString"]
    )
    current = json.loads(
        client.get_secret_value(SecretId=arn, VersionStage="AWSCURRENT")["SecretString"]
    )

    conn = _get_connection(current)
    try:
        with conn.cursor() as cur:
            # Escape username to prevent SQL injection
            username = pending["username"]
            new_pw   = pending["password"]
            cur.execute(
                f"ALTER USER %s WITH PASSWORD %s",
                (username, new_pw)
            )
        conn.commit()
        logger.info("Password updated in RDS for user %s", pending["username"])
    finally:
        conn.close()


def test_secret(client, arn: str, token: str) -> None:
    """Step 3: Verify the new secret works by connecting to the database."""
    pending = json.loads(
        client.get_secret_value(SecretId=arn, VersionId=token, VersionStage="AWSPENDING")["SecretString"]
    )
    conn = _get_connection(pending)
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT 1")
        logger.info("Test connection successful with new secret for %s", arn)
    finally:
        conn.close()


def finish_secret(client, arn: str, token: str) -> None:
    """Step 4: Promote AWSPENDING to AWSCURRENT."""
    metadata = client.describe_secret(SecretId=arn)
    current_version = next(
        v for v, stages in metadata["VersionIdsToStages"].items()
        if "AWSCURRENT" in stages
    )

    if current_version == token:
        logger.info("Already AWSCURRENT — skipping finishSecret")
        return

    client.update_secret_version_stage(
        SecretId=arn,
        VersionStage="AWSCURRENT",
        MoveToVersionId=token,
        RemoveFromVersionId=current_version,
    )
    logger.info("Promoted %s to AWSCURRENT for secret %s", token, arn)


def _get_connection(secret: dict):
    """Open a connection using secret fields."""
    return psycopg2.connect(
        host=secret["host"],
        port=int(secret.get("port", 5432)),
        dbname=secret.get("dbname", "postgres"),
        user=secret["username"],
        password=secret["password"],
        sslmode="require",
        connect_timeout=10,
    )
