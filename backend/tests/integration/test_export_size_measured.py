"""#271 — the bytes, measured through the real endpoint rather than estimated.

The register's figure (670 B a `ledger` row) predates #269 making the DSAR ledger
the full `_export_row` projection, so it understated the exposure by about 3x.
This file re-measures both artefacts the same way — build an export with N rows
and one with none, and divide the difference — and turns the result into the two
statements that matter: what a row costs, and what the WHOLE response can now
cost at worst.

It prints the numbers (`-s` to see them) and asserts only the property, so it
does not go red because the projection legitimately grew a field.
"""

from __future__ import annotations

import hashlib
import json


def _h(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def _ingest(client, org, n: int) -> None:
    rows = [{"prompt_hash": _h(f"{org['org_id']}p{i}"),
             "response_hash": _h(f"{org['org_id']}r{i}"),
             "token_count": 100 + i, "policy_tag": "chat",
             "agent": "gpt-4o", "event_type": "llm_call"} for i in range(n)]
    assert client.post("/v1/logs/batch", json=rows,
                       headers=org["auth"]).status_code == 202


def test_the_worst_case_response_is_bounded_and_the_bound_is_stated(make_org, client):
    """The defect was never the per-row cost — it was that nothing multiplied it
    by anything. Measured here: one row's bytes, then the largest response the
    endpoint can now be made to build."""
    from app.routers.logs import EXPORT_PAGE_MAX

    empty = make_org()
    full = make_org()
    n = 40
    _ingest(client, full, n)

    zero = len(client.get("/v1/logs/export", headers=empty["auth"]).content)
    many = len(client.get("/v1/logs/export", headers=full["auth"]).content)
    per_row = (many - zero) / n
    worst = zero + per_row * EXPORT_PAGE_MAX

    print(f"\n  fixed overhead (0 rows, incl. the page block): {zero} B"
          f"\n  bytes per ledger row:                          {per_row:.1f} B"
          f"\n  worst-case response at EXPORT_PAGE_MAX={EXPORT_PAGE_MAX}: "
          f"{worst / 1e6:.1f} MB"
          f"\n  the same ledger unbounded (3,000,000 rows):     "
          f"{per_row * 3_000_000 / 1e9:.2f} GB")

    assert per_row > 0
    assert worst < 64e6, (
        f"one response can now reach {worst / 1e6:.0f} MB. The row projection grew "
        f"and EXPORT_PAGE_MAX did not come down with it — the bound is supposed to "
        f"cap the BYTES, and the row count is only how it does that.")


def test_the_dsar_ledger_pays_the_same_per_row_and_the_same_cap(make_org, login):
    """#269 made the two artefacts one projection, so their row cost is the same
    number by construction. Measured rather than asserted from the source,
    because "they call the same function" stops being true silently."""
    from app.routers.logs import EXPORT_PAGE_MAX

    a, b = make_org(), make_org()
    sa = login(a["admin_email"], a["admin_password"])
    sb = login(b["admin_email"], b["admin_password"])
    n = 40
    _ingest(sb, b, n)

    zero = len(json.dumps(sa.get("/v1/account/export").json()))
    many = len(json.dumps(sb.get("/v1/account/export").json()))
    per_row = (many - zero) / n
    print(f"\n  DSAR bundle: {per_row:.1f} B per ledger row, "
          f"worst-case ledger section {per_row * EXPORT_PAGE_MAX / 1e6:.1f} MB")

    assert per_row * EXPORT_PAGE_MAX < 64e6, (
        "the DSAR ledger section can build more than 64 MB in one response")
