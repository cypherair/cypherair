#!/usr/bin/env python3
"""Start an Xcode Cloud workflow build for a specific git tag.

Used by the "PgpMobile XCFramework" workflow (WF1) to start the "CypherAir
Release" workflow (WF2) for the same stable tag once the draft GitHub Release
exists, via the App Store Connect API ``ciBuildRuns`` endpoint.

Credentials (App Store Connect API key) are read from the environment so they
never appear on the command line or in logs:

    ASC_ISSUER_ID                Issuer ID (UUID)
    ASC_KEY_ID                   Key ID
    ASC_PRIVATE_KEY              Contents of the .p8 private key, or
    ASC_PRIVATE_KEY_PATH         Path to the .p8 private key file
    XCODE_CLOUD_RELEASE_WORKFLOW_ID
                                 The target workflow's id (from its App Store
                                 Connect URL). Required unless --workflow-id is
                                 passed.

The pure helpers (reference selection and request payload construction) are unit
tested; the JWT/HTTP layer requires live credentials.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request


ASC_API_BASE = "https://api.appstoreconnect.apple.com/v1"
ASC_AUDIENCE = "appstoreconnect-v1"


class AscError(RuntimeError):
    pass


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Start an Xcode Cloud build for a git tag.")
    parser.add_argument("--git-tag", required=True, help="Git tag to build (scmGitReferences name).")
    parser.add_argument(
        "--workflow-id",
        default=os.environ.get("XCODE_CLOUD_RELEASE_WORKFLOW_ID", ""),
        help="Target Xcode Cloud workflow id. Defaults to $XCODE_CLOUD_RELEASE_WORKFLOW_ID.",
    )
    parser.add_argument(
        "--workflow-name",
        default="",
        help="Target workflow name (informational/logging only).",
    )
    return parser.parse_args()


def select_tag_reference(references: list[dict], tag: str) -> str:
    """Return the scmGitReferences id whose kind is TAG and name matches ``tag``."""
    for reference in references:
        attributes = reference.get("attributes") or {}
        if attributes.get("kind") == "TAG" and attributes.get("name") == tag:
            reference_id = reference.get("id")
            if reference_id:
                return str(reference_id)
    raise AscError(f"git tag reference {tag!r} not found for the workflow's repository")


def build_ci_build_run_payload(workflow_id: str, git_reference_id: str) -> dict:
    """Build the CiBuildRunCreateRequest body for the ciBuildRuns endpoint."""
    return {
        "data": {
            "type": "ciBuildRuns",
            "relationships": {
                "workflow": {"data": {"type": "ciWorkflows", "id": workflow_id}},
                "sourceBranchOrTag": {"data": {"type": "scmGitReferences", "id": git_reference_id}},
            },
        }
    }


def _load_private_key() -> str:
    key = os.environ.get("ASC_PRIVATE_KEY", "").strip()
    if key:
        return key
    key_path = os.environ.get("ASC_PRIVATE_KEY_PATH", "").strip()
    if key_path:
        with open(key_path, encoding="utf-8") as handle:
            return handle.read()
    raise AscError("ASC_PRIVATE_KEY or ASC_PRIVATE_KEY_PATH must be set")


def make_jwt() -> str:
    try:
        import jwt  # PyJWT, requires the cryptography backend for ES256
    except ImportError as error:  # pragma: no cover - exercised only on CI
        raise AscError(
            "PyJWT with the cryptography backend is required (pip install 'pyjwt[crypto]')"
        ) from error

    issuer_id = os.environ.get("ASC_ISSUER_ID", "").strip()
    key_id = os.environ.get("ASC_KEY_ID", "").strip()
    if not issuer_id or not key_id:
        raise AscError("ASC_ISSUER_ID and ASC_KEY_ID must be set")

    issued_at = int(time.time())
    payload = {
        "iss": issuer_id,
        "iat": issued_at,
        "exp": issued_at + 19 * 60,  # App Store Connect requires <= 20 minutes.
        "aud": ASC_AUDIENCE,
    }
    return jwt.encode(payload, _load_private_key(), algorithm="ES256", headers={"kid": key_id})


def _request(method: str, url: str, token: str, body: dict | None = None) -> dict:
    data = json.dumps(body).encode("utf-8") if body is not None else None
    request = urllib.request.Request(url, data=data, method=method)
    request.add_header("Authorization", f"Bearer {token}")
    request.add_header("Accept", "application/json")
    if data is not None:
        request.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(request) as response:
            raw = response.read().decode("utf-8")
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as error:
        detail = error.read().decode("utf-8", "replace")
        raise AscError(f"{method} {url} failed: HTTP {error.code} {detail}") from error
    except urllib.error.URLError as error:
        raise AscError(f"{method} {url} failed: {error.reason}") from error


def resolve_repository_id(token: str, workflow_id: str) -> str:
    payload = _request("GET", f"{ASC_API_BASE}/ciWorkflows/{workflow_id}?include=repository", token)
    relationships = (payload.get("data") or {}).get("relationships") or {}
    repository = (relationships.get("repository") or {}).get("data") or {}
    repository_id = repository.get("id")
    if not repository_id:
        raise AscError(f"workflow {workflow_id} has no associated repository")
    return str(repository_id)


def resolve_git_reference_id(token: str, repository_id: str, tag: str) -> str:
    references: list[dict] = []
    url = f"{ASC_API_BASE}/scmRepositories/{repository_id}/gitReferences?limit=200"
    while url:
        payload = _request("GET", url, token)
        references.extend(payload.get("data") or [])
        url = ((payload.get("links") or {}).get("next")) or ""
    return select_tag_reference(references, tag)


def main() -> None:
    args = parse_args()
    if not args.workflow_id:
        raise AscError("--workflow-id or XCODE_CLOUD_RELEASE_WORKFLOW_ID is required")

    token = make_jwt()
    repository_id = resolve_repository_id(token, args.workflow_id)
    git_reference_id = resolve_git_reference_id(token, repository_id, args.git_tag)
    payload = build_ci_build_run_payload(args.workflow_id, git_reference_id)
    result = _request("POST", f"{ASC_API_BASE}/ciBuildRuns", token, payload)

    build_run_id = (result.get("data") or {}).get("id", "<unknown>")
    label = args.workflow_name or args.workflow_id
    print(f"Started Xcode Cloud build run {build_run_id} for workflow {label!r} tag {args.git_tag!r}")


if __name__ == "__main__":
    try:
        main()
    except AscError as error:
        print(f"error: {error}", file=sys.stderr)
        sys.exit(1)
