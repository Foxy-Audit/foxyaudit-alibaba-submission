"""Test helper for per-tenant judge routing (migration 0053).

Since the AI Judge became per-tenant, an org with no provider key and no premium
plan gets NO judge at all — that is the tier matrix, not a bug. Any test that
wants grading to actually reach a (stubbed) judge must first give its org a key.

Exposed both as this plain function — importable from module-level test helpers —
and as the `configure_judge` fixture in conftest.py.
"""

from __future__ import annotations

import uuid

from app.crypto_secrets import encrypt_secret
from app.db import SessionLocal
from app.models import OrgPolicy, Organization


def give_judge_key(org_id, *, provider: str = "gemini", key_mode: str = "own",
                   gemini_key: str | None = "test-byok-gemini",
                   openai_key: str | None = None,
                   qwen_key: str | None = None,
                   plan_tier: str | None = None) -> None:
    """Set an org's live judge routing (and optionally its plan tier).

    ⚠ `qwen_key` ARRIVED LATE AND IT IS WHY QWEN HAD NO INTEGRATION COVERAGE.
    Q1 added the third provider, Q3 folded it into `worker._judge_verdict` and Q4
    shipped it — but this helper took `gemini_key` and `openai_key` only, so no
    test could route an org to Qwen at all. `judge_routing.resolve_judge_routing`
    decrypts `qwen_key_enc` ONLY when "qwen" is in the selected set, so an org
    without one materialises no key and the worker calls `_fallback` instead of
    the judge. Everything Qwen was pinned by AST-parsing `worker.py` rather than
    by executing it until this parameter existed.
    """
    db = SessionLocal()
    try:
        oid = uuid.UUID(str(org_id))
        row = db.get(OrgPolicy, oid) or OrgPolicy(org_id=oid)
        row.judge_provider = provider
        row.judge_key_mode = key_mode
        row.gemini_key_enc = encrypt_secret(gemini_key, oid, "gemini") if gemini_key else None
        row.openai_key_enc = encrypt_secret(openai_key, oid, "openai") if openai_key else None
        row.qwen_key_enc = encrypt_secret(qwen_key, oid, "qwen") if qwen_key else None
        db.add(row)
        if plan_tier is not None:
            db.get(Organization, oid).plan_tier = plan_tier
        db.commit()
    finally:
        db.close()
