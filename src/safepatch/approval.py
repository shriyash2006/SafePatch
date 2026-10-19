from __future__ import annotations

from datetime import datetime, timezone

from .hashing import sha256_json


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def approval_token(plan_hash: str, command_hash: str, repository_hash: str) -> str:
    return sha256_json(
        {"plan_hash": plan_hash, "command_hash": command_hash, "repository_hash": repository_hash}
    )


def create_approval(plan_hash: str, command_hash: str, repository_hash: str, command_id: str) -> dict:
    return {
        "event": "approval",
        "command_id": command_id,
        "status": "approved",
        "created_at": now(),
        "plan_hash": plan_hash,
        "command_hash": command_hash,
        "repository_hash": repository_hash,
        "approval_token": approval_token(plan_hash, command_hash, repository_hash),
    }


def valid_approval(event: dict, plan_hash: str, command_hash: str, repository_hash: str) -> bool:
    if event.get("status") != "approved":
        return False
    expected = approval_token(plan_hash, command_hash, repository_hash)
    return (
        event.get("plan_hash") == plan_hash
        and event.get("command_hash") == command_hash
        and event.get("repository_hash") == repository_hash
        and event.get("approval_token") == expected
    )
