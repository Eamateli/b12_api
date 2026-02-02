"""
B12 Full Stack Engineer — Application Submission Script
========================================================

This script is designed to run inside a GitHub Actions workflow.
It constructs a signed JSON payload and POSTs it to B12's application endpoint.

Key concepts used:
- JSON canonicalization (deterministic serialization)
- HMAC-SHA256 (message authentication)
- Environment variables (for secrets and CI metadata)
"""

import json
import hmac
import hashlib
import os
import sys
from datetime import datetime, timezone
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError


def build_payload() -> dict:
    """
    Build the application payload from environment variables.

    WHY environment variables?
    - SIGNING_SECRET: Should never be hardcoded in source code. GitHub Actions
      injects it at runtime from the repository's encrypted secrets store.
    - GITHUB_REPOSITORY and GITHUB_RUN_ID: These are automatically set by
      GitHub Actions in every CI run, so we don't need to hardcode them.
    - NAME, EMAIL, RESUME_LINK: Personal info that you might not want in
      the public repo, so we read these from env vars too (set in the workflow
      or as secrets).
    """
    return {
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") 
                      + f"{datetime.now(timezone.utc).microsecond // 1000:03d}Z",
        "name": os.environ["NAME"],
        "email": os.environ["EMAIL"],
        "resume_link": os.environ["RESUME_LINK"],
        "repository_link": f"https://github.com/{os.environ['GITHUB_REPOSITORY']}",
        "action_run_link": f"https://github.com/{os.environ['GITHUB_REPOSITORY']}/actions/runs/{os.environ['GITHUB_RUN_ID']}",
    }


def canonicalize(payload: dict) -> bytes:
    """
    Serialize the payload into a canonical (deterministic) byte string.

    WHY canonicalize?
    HMAC signs raw bytes. If we serialize the same dict differently on our
    side vs B12's side (e.g., different key order or whitespace), the
    signatures won't match, and the request will be rejected.

    Canonicalization rules (from the job listing):
    - sort_keys=True    → alphabetical key order
    - separators=(',',':')  → no spaces after commas or colons (compact)
    - encode('utf-8')   → consistent byte encoding
    """
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def sign(body: bytes, secret: str) -> str:
    """
    Compute the HMAC-SHA256 hex digest of the body using the signing secret.

    HOW HMAC-SHA256 WORKS (simplified):
    1. The secret key is padded/hashed to a fixed block size.
    2. Two passes of SHA256 are computed:
       - Inner: SHA256(key XOR inner_pad || message)
       - Outer: SHA256(key XOR outer_pad || inner_hash)
    3. The result is a 256-bit (32-byte) digest, represented as 64 hex chars.

    WHY HMAC instead of plain SHA256?
    Plain SHA256(secret + message) is vulnerable to "length extension attacks."
    HMAC's nested structure prevents this.
    """
    return hmac.new(
        secret.encode("utf-8"),
        body,
        hashlib.sha256,
    ).hexdigest()


def submit(body: bytes, signature: str) -> None:
    """
    POST the signed payload to B12's submission endpoint.

    The X-Signature-256 header follows the format: sha256={hex_digest}
    This convention is borrowed from GitHub's webhook signature verification,
    which is a nice touch since we're submitting from GitHub Actions.
    """
    url = "https://b12.io/apply/submission"

    request = Request(
        url,
        data=body,
        headers={
            "Content-Type": "application/json; charset=utf-8",
            "X-Signature-256": f"sha256={signature}",
        },
        method="POST",
    )

    try:
        with urlopen(request) as response:
            result = response.read().decode("utf-8")
            print(f"Status: {response.status}")
            print(f"Response: {result}")

            # Parse and display the receipt
            data = json.loads(result)
            if data.get("success"):
                print(f"\n=== RECEIPT: {data['receipt']} ===\n")
            else:
                print("\nSubmission was not successful.")
                sys.exit(1)

    except HTTPError as e:
        print(f"HTTP Error {e.code}: {e.reason}")
        print(f"Response body: {e.read().decode('utf-8')}")
        sys.exit(1)
    except URLError as e:
        print(f"Connection error: {e.reason}")
        sys.exit(1)


def main():
    # Step 1: Build the payload
    payload = build_payload()
    print(f"Payload: {json.dumps(payload, indent=2)}")

    # Step 2: Canonicalize to deterministic bytes
    body = canonicalize(payload)
    print(f"\nCanonicalized body:\n{body.decode('utf-8')}")

    # Step 3: Sign the canonical body
    secret = os.environ["SIGNING_SECRET"]
    signature = sign(body, secret)
    print(f"\nSignature: sha256={signature}")

    # Step 4: Submit
    print(f"\nSubmitting to B12...")
    submit(body, signature)


if __name__ == "__main__":
    main()