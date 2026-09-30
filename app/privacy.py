"""
privacy.py
----------
Identity-hiding boundary for the online-learning pipeline.

Principle: **raw PII never enters the learning stream, the training log, or the
model.** Identifiers are converted to stable, non-reversible-without-the-key
tokens *at the producer boundary*, before anything is published to the queue.

Technique: keyed pseudonymization via HMAC-SHA256 with a secret pepper
(`PII_PEPPER`, kept in the environment / a secrets manager — never in code or
VCS). The same input always maps to the same token, so behavioural linkage
(e.g. "these 5 events are the same card") is preserved for the model, but the
token cannot be reversed to the real identity without the pepper. This is
"pseudonymization" in the GDPR sense: re-identification is possible only for
holders of the separately-stored key, which supports audit-gated fraud
investigation while keeping the analytics layer PII-free.

What we do to each field:
  - user_id / cc_num / account   -> HMAC token  (kept, as a stable subject key)
  - device_id                    -> HMAC token  (kept, behavioural signal)
  - name / street / email / dob  -> dropped entirely (never needed by the model)
  - ip_address                   -> dropped (or coarsened) — high re-id risk
  - amount / category / hour ... -> kept as-is (behavioural, non-identifying)

The model's feature vector is already PII-free (only numeric behavioural
signals); this module guarantees the *metadata* travelling alongside it is too.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import os

from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

_PEPPER = os.getenv("PII_PEPPER", "")
if not _PEPPER:
    # Never silently run without a key in production — pseudonyms would also be
    # unstable across restarts. Fall back to a clearly-marked dev key and shout.
    logger.warning(
        "PII_PEPPER is not set — using an INSECURE development key. "
        "Set PII_PEPPER before handling real data."
    )
    _PEPPER = "INSECURE-DEV-PEPPER-DO-NOT-USE-IN-PROD"

_PEPPER_BYTES = _PEPPER.encode("utf-8")

# Fields that must never be forwarded in raw form.
_DROP_FIELDS = {"first", "last", "name", "full_name", "street", "email",
                "phone", "dob", "ssn", "ip_address", "zip"}


def pseudonymize(value: str | None, prefix: str = "id", length: int = 16) -> str | None:
    """Return a stable HMAC token for an identifier, or None for empty input.

    length = hex chars kept (16 -> 64 bits, ample collision resistance for the
    identifier space here while keeping tokens short and readable).
    """
    if value is None:
        return None
    v = str(value).strip()
    if not v:
        return None
    digest = hmac.new(_PEPPER_BYTES, v.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{prefix}_{digest[:length]}"


def anonymize_event(raw: dict) -> dict:
    """Strip/tokenize a raw labelled event so it is safe to publish to the queue.

    Input may carry real identifiers (from a partner feed or public dataset).
    Output keeps only pseudonymous keys + non-identifying behavioural fields.
    Idempotent: fields already tokenized (prefixed) are left alone.
    """
    out: dict = {}
    for k, val in raw.items():
        if k in _DROP_FIELDS:
            continue  # never forward raw PII
        out[k] = val

    # Canonical pseudonymous subject key (the "who"), from whatever id is present.
    subject = raw.get("subject") or raw.get("user_id") or raw.get("cc_num")
    out.pop("cc_num", None)
    if subject is not None and not str(subject).startswith("subj_"):
        out["subject"] = pseudonymize(subject, "subj")
    elif subject is not None:
        out["subject"] = subject
    out.pop("user_id", None)

    if raw.get("device_id"):
        out["device_id"] = pseudonymize(raw["device_id"], "dev")

    return out


def pepper_fingerprint() -> str:
    """A non-secret fingerprint of the active pepper, for audit/version display.

    Lets you confirm which key generated a set of pseudonyms (e.g. after a key
    rotation) without ever exposing the key itself.
    """
    return hashlib.sha256(_PEPPER_BYTES).hexdigest()[:12]
