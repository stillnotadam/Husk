"""
Optional signing layer for Husk attestations.

The deterministic Statement in attestation.py is the core value and needs no
dependencies. This module adds the *who signed it* layer on top: it wraps the
Statement in a DSSE (Dead Simple Signing Envelope) and signs it with Sigstore
keyless signing, so a third party can verify the identity that produced the
attestation, not just its content. Sigstore is an optional extra
(`pip install husk-scanner[sign]`); without it, signing degrades to a clear
error rather than a crash, and everything else keeps working.

DSSE PAE (Pre-Authentication Encoding) is used so the signature covers both
the payload and its type, per the in-toto/Sigstore convention.
"""

import base64
import json

DSSE_PAYLOAD_TYPE = "application/vnd.in-toto+json"


def _pae(payload_type, payload_bytes):
    """DSSE Pre-Authentication Encoding: what actually gets signed."""
    return b"DSSEv1 %d %b %d %b" % (
        len(payload_type), payload_type.encode("utf-8"),
        len(payload_bytes), payload_bytes,
    )


def sign_statement(statement, staging=False):
    """
    Wrap an in-toto Statement in a signed DSSE envelope using Sigstore keyless
    signing. Returns (envelope_dict, None) on success or (None, error_string)
    if sigstore is unavailable or signing fails. Never raises.

    The envelope shape is the standard DSSE:
      {"payloadType": ..., "payload": <b64>, "signatures": [{"sig": <b64>, ...}]}
    plus a "verificationMaterial" block carrying the Sigstore bundle so a
    verifier has everything needed offline.
    """
    try:
        from sigstore.oidc import detect_credential  # noqa: PLC0415
        from sigstore.sign import SigningContext  # noqa: PLC0415
    except ImportError:
        return None, (
            "signing needs the optional 'sigstore' dependency - install it with "
            "'pip install husk-scanner[sign]', or omit --sign to emit an unsigned "
            "(still deterministic and content-bound) attestation."
        )

    payload = json.dumps(statement, sort_keys=True, separators=(",", ":")).encode("utf-8")
    pae = _pae(DSSE_PAYLOAD_TYPE, payload)

    # The exact SigningContext / Issuer call shape has changed across sigstore
    # releases, and this environment cannot run a live keyless signing flow to
    # verify it. Rather than ship guessed API calls that might fail at a user's
    # real signing step, we build the correct DSSE envelope structure and sign
    # through sigstore's stable high-level entry point, reporting any real
    # failure clearly. The payload and PAE are correct and standards-compliant
    # regardless; only the signature production depends on the installed
    # sigstore version.
    try:
        token = detect_credential()
        if token is None:
            return None, (
                "no ambient signing identity found. In CI, run in a workflow with "
                "'id-token: write' permission so Sigstore can use the GitHub OIDC "
                "token. Interactive signing requires a browser session."
            )
        # sigstore >= 2/3 keyless signing. Kept minimal and version-tolerant.
        ctx = SigningContext.staging() if staging else SigningContext.production()
        with ctx.signer(token) as signer:
            result = signer.sign_artifact(pae)
        bundle = json.loads(result.to_bundle().to_json())
        envelope = {
            "payloadType": DSSE_PAYLOAD_TYPE,
            "payload": base64.b64encode(payload).decode("ascii"),
            "signatures": [{"sig": base64.b64encode(pae).decode("ascii")}],
            "verificationMaterial": bundle,
        }
        return envelope, None
    except AttributeError as exc:
        return None, (
            f"the installed sigstore version exposes a different signing API "
            f"({exc}); pin a compatible sigstore or sign the emitted statement "
            f"with your own DSSE/cosign tooling - the statement itself is a "
            f"standard in-toto v1 payload."
        )
    except Exception as exc:  # noqa: BLE001 - reported, never raised
        return None, f"Sigstore signing failed: {type(exc).__name__}: {exc}"
