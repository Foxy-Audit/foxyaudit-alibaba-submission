"""The tamper-evident hash chain — the single source of truth.

Hn = SHA256( data_blob_n || H_{n-1} )

Both the ingest route (which writes new rows) and the verifier (which recomputes
the whole chain) import THIS function. The field order in `data_blob` is frozen
here; any divergence between writer and verifier is the classic hash-chain bug,
so there is exactly one implementation.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

GENESIS_HASH = "0" * 64
CHAIN_VERSION_LEGACY = 1
CHAIN_VERSION_CAPTURE_V2 = 2
CHAIN_VERSION_POLICY_V3 = 3
CHAIN_VERSION_VERDICT_V4 = 4
CHAIN_VERSION_UTC_V5 = 5


def normalize_occurred_at(value):
    """One canonical UTC text for one instant — from a datetime OR from its ISO string.

    ⚠ THE TWO IMPLEMENTATIONS OF THIS RECIPE START FROM DIFFERENT THINGS.
    This one folds the `datetime` SQLAlchemy hands back; `verifier/foxy_verify.py`
    folds the STRING that datetime was exported as. They must arrive at the same
    bytes, so the string is parsed back into an instant rather than patched
    textually — a text-level fix would agree with itself and with nothing else.

    A naive datetime names no instant, so it is read as UTC. That is the same
    reading `schemas.LogIngest` applies before the value is stored, which is what
    keeps the moment hashed and the moment written identical.

    Anything that parses as neither is folded unchanged. Refusing it here would
    turn an unreadable field into a hash mismatch, and a hash mismatch is
    reported to a customer as TAMPERING.
    """
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, str):
        try:
            # `Z` is accepted natively only from 3.11; the swap is what makes the
            # verifier's stated 3.9 floor real. An unparseable string keeps its
            # ORIGINAL text, never the swapped one, so both sides fold the same.
            dt = datetime.fromisoformat(value.strip().replace("Z", "+00:00").replace("z", "+00:00"))
        except ValueError:
            return value
    elif hasattr(value, "isoformat"):
        return value.isoformat()          # a date — no instant to normalise
    else:
        return value
    if dt.utcoffset() is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat()


def _occurred_at_blob(occurred_at, chain_version: int):
    """The text `occurred_at` contributes to the hashed event, BY VERSION.

    ⚠ THIS IS THE ONE FIELD WHOSE FOLDING DIFFERS BETWEEN VERSIONS, AND IT IS
    WHY V5 IS NOT LIKE V2, V3 OR V4. Each of those ADDED a key under a
    `chain_version >=` guard, so every earlier payload stayed byte-identical for
    free. V5 changes how an EXISTING key is rendered, so the version test has to
    sit on this line. Move it and you silently rewrite history.

    Below V5 the pre-V5 text is reproduced exactly: `isoformat()` for anything
    datetime-like, the value untouched otherwise. That text carries whatever UTC
    offset the value happened to have — and for a row read back from Postgres
    that is the READER's session `TimeZone`, not the writer's. So the same row
    hashed in two sessions produced two hashes and an honest ledger read as
    tampered (register #272). Those rows are frozen and keep that behaviour.

    From V5 the same INSTANT is folded, normalised to UTC, so a recompute no
    longer depends on where the reader sits.
    """
    if chain_version >= CHAIN_VERSION_UTC_V5:
        return normalize_occurred_at(occurred_at)
    return occurred_at.isoformat() if hasattr(occurred_at, "isoformat") else occurred_at


def verdict_hash_hex(verdict: dict | None) -> str | None:
    """The digest V4 binds: SHA-256 over the canonical JSON of a LOCAL verdict.

    The same canonical form the chain itself uses, so key order can never move a
    hash. Returns None for None, which is what an un-evaluated row carries.

    Only the DIGEST goes into the chain, so the chain alone cannot notice an
    edited verdict body — a verifier has to re-derive this from the exported
    `local_verdict` and compare. verifier/foxy_verify.py does exactly that.
    """
    if verdict is None:
        return None
    canonical = json.dumps(verdict, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def compute_chain_hash(
    *,
    org_id,
    prompt_hash: str,
    response_hash: str,
    token_count: int,
    policy_tag: str,
    seq: int,
    prev_hash: str,
    agent: str | None = None,
    chain_version: int = CHAIN_VERSION_LEGACY,
    event_id=None,
    client_id: str | None = None,
    client_seq: int | None = None,
    event_type: str | None = None,
    commitment_alg: str | None = None,
    event_metadata: dict | None = None,
    pii_signals: list[str] | None = None,
    occurred_at=None,
    verdict_hash: str | None = None,
) -> str:
    if chain_version >= CHAIN_VERSION_CAPTURE_V2:
        event = {
            "org_id": str(org_id), "event_id": str(event_id) if event_id else None,
            "client_id": client_id, "client_seq": client_seq,
            "event_type": event_type or "interaction",
            "commitment_alg": commitment_alg or "sha256-legacy",
            "prompt_hash": prompt_hash, "response_hash": response_hash,
            "token_count": token_count, "policy_tag": policy_tag, "agent": agent,
            "pii_signals": pii_signals, "event_metadata": event_metadata,
            "occurred_at": _occurred_at_blob(occurred_at, chain_version),
            "seq": seq,
        }
        # V3 binds the declared chain format too. Earlier V2 rows remain exactly
        # byte-compatible so their historic hashes continue to verify.
        if chain_version >= CHAIN_VERSION_POLICY_V3:
            event["chain_version"] = chain_version
        # V4 binds the LOCAL, deterministic verdict — the one policy_engine
        # decided at ingest, so a verdict can no longer be edited in the database
        # without breaking the chain. NOT the AI judge's grade: that does not
        # exist yet when this runs (the worker adds it asynchronously), so
        # chaining it would mean re-hashing the row afterwards and invalidating
        # every block after it. See schemas.Verdict for the full line.
        # V1/V2/V3 stay byte-identical, exactly as V3 did for V2.
        if chain_version >= CHAIN_VERSION_VERDICT_V4:
            event["verdict_hash"] = verdict_hash
        # V5 adds NO key. It changes how `occurred_at` is rendered — see
        # _occurred_at_blob, which is where the version actually bites.
        data_blob = json.dumps(event, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256((data_blob + prev_hash).encode("utf-8")).hexdigest()
    data_blob = f"{org_id}|{prompt_hash}|{response_hash}|{token_count}|{policy_tag}|{seq}"
    # `agent` (which model produced the interaction) is appended ONLY when present,
    # so rows written before 6B hash byte-for-byte identically — the whole pre-6B
    # chain keeps verifying, while agent-bearing rows are tamper-evident. (6B)
    if agent:
        data_blob += f"|agent={agent}"
    return hashlib.sha256((data_blob + prev_hash).encode("utf-8")).hexdigest()
