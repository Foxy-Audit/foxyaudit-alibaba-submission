#!/usr/bin/env python3
"""Foxy Audit — independent, open-source ledger verifier (Phase 6 · 6D).

Re-verifies a Foxy Audit log export WITHOUT trusting Foxy. It re-implements the
hash-chain recipe here from scratch (stdlib only, zero Foxy imports), recomputes
every row from genesis, and reports the first tampered sequence — the whole point
being that you can run this yourself and don't have to take our word for it.

    python foxy_verify.py foxy-audit-logs.json
    python foxy_verify.py page1.json page2.json page3.json        # a paged export
    python foxy_verify.py foxy-audit-logs.json --anchor --rpc https://rpc.sepolia.org

Input: the JSON you download from the dashboard (GET /v1/logs/export?format=json):

    {
      "org_id": "…", "count": N,
      "anchor": { "root_hash": "…", "last_seq": K, "tx_hash": "0x…",
                  "chain": "sepolia", "contract": "0x…" },   # optional
      "logs": [ { "seq": 1, "prompt_hash": "…", "response_hash": "…",
                  "token_count": 10, "policy_tag": "chat", "agent": "gpt-4o"|null,
                  "prev_hash": "…", "chain_hash": "…",
                  # chain_version 4 and later:
                  "verdict_hash": "…", "local_verdict": {…} }, … ]
    }

From chain_version 5 `occurred_at` is hashed as the UTC INSTANT it names, so an
export verifies identically whatever timezone the exporting database session sat
in. Versions 1-4 hash that timestamp's text verbatim, offset included, and are
left exactly as they were written: a historical row must keep verifying forever.

The GDPR bundle from GET /v1/account/export carries the same rows under "ledger"
instead of "logs"; both keys are read. ANY OTHER FILE IS REFUSED — see
find_chain_section below for why the refusal is the point and the alias is not.

A ledger too large for one response is exported in PAGES, each carrying a `page`
block that names the seq range it holds, the chain hash it continues from, and
whether more rows remain. Pass every page file in one command, in any order, and
they are verified as a single chain: the pages must join at both the sequence and
the hash, so one dropped from the middle cannot pass. A file with no `page` block
is read as one page starting wherever its first row does, so an export downloaded
before paging existed verifies exactly as it did then.

Exit code 0 = the whole ledger is intact from genesis, 1 = tampering / anchor /
commitment mismatch, 2 = NOTHING WAS VERIFIED (unreadable file, or no chain in
it), 3 = every row given was intact but they are only a SEGMENT of the ledger —
pages are missing, or the export began somewhere other than seq 1. 3 is not a
pass: it means nothing was found wrong in what you supplied and the rest was
never seen. `--json` for machine output.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import sys
from datetime import datetime, timezone

# ─── the chain recipe — an INDEPENDENT copy of backend/app/chain.py ───────────
# Keep this byte-for-byte identical to the backend, INCLUDING the rule that
# `agent` is appended only when present (so pre-agent rows hash unchanged). If the
# backend recipe ever changes, this must change with it — verifier/test_verify.py
# cross-checks the two on every run.

GENESIS_HASH = "0" * 64


def normalize_occurred_at(value):
    """One canonical UTC text for one instant — the V5 rendering of `occurred_at`.

    ⚠ THE TWO SIDES OF THIS RECIPE START FROM DIFFERENT THINGS. The backend
    folds the `datetime` its database hands back; this file folds the STRING
    that datetime was exported as, which carries whatever UTC offset the
    exporting session's `TimeZone` rendered it in. So the string is PARSED back
    into an instant and re-rendered, never patched textually — the two must land
    on identical bytes from opposite starting points.

    A value with no offset names no instant, and is read as UTC — the same
    reading ingest applies before storing it.

    Anything that parses as neither is folded UNCHANGED, and unchanged means the
    original text rather than the `Z`-swapped one. Refusing it here would turn an
    unreadable field into a hash mismatch, and this tool reports a hash mismatch
    as TAMPERING.
    """
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, str):
        try:
            # `Z` is parsed natively only from Python 3.11; this file promises 3.9.
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


def compute_chain_hash(*, org_id, prompt_hash, response_hash, token_count,
                       policy_tag, seq, prev_hash, agent=None, chain_version=1,
                       event_id=None, client_id=None, client_seq=None,
                       event_type=None, commitment_alg=None, event_metadata=None,
                       pii_signals=None, occurred_at=None, verdict_hash=None):
    if chain_version >= 2:
        event = {
            "org_id": str(org_id), "event_id": str(event_id) if event_id else None,
            "client_id": client_id, "client_seq": client_seq,
            "event_type": event_type or "interaction",
            "commitment_alg": commitment_alg or "sha256-legacy",
            "prompt_hash": prompt_hash, "response_hash": response_hash,
            "token_count": token_count, "policy_tag": policy_tag, "agent": agent,
            "pii_signals": pii_signals, "event_metadata": event_metadata,
            # ⚠ V5 IS THE ONE VERSION THAT RE-RENDERS AN EXISTING FIELD RATHER
            # THAN ADDING ONE. V2/V3/V4 each appended a key, so every earlier
            # payload stayed byte-identical for free; V5 changes how this line
            # reads, so the version test lives ON the line. Below V5 the raw
            # exported text is folded — offset and all, which is exactly why a
            # pre-V5 row read back in a non-UTC session hashes differently from
            # the one that was written (register #272). Those rows are frozen
            # and keep that behaviour; from V5 the INSTANT is folded instead.
            "occurred_at": (normalize_occurred_at(occurred_at)
                            if chain_version >= 5 else occurred_at),
            "seq": seq,
        }
        if chain_version >= 3:
            event["chain_version"] = chain_version
        # V4 binds the digest of the row's LOCAL, deterministic verdict (the one
        # decided at ingest). The later, asynchronous grade is NOT bound — see
        # verdict_hash_hex below for what that means for a reader.
        if chain_version >= 4:
            event["verdict_hash"] = verdict_hash
        # V5 adds no key — see the `occurred_at` line above for where it bites.
        blob = json.dumps(event, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256((blob + prev_hash).encode("utf-8")).hexdigest()
    data_blob = f"{org_id}|{prompt_hash}|{response_hash}|{token_count}|{policy_tag}|{seq}"
    if agent:
        data_blob += f"|agent={agent}"
    return hashlib.sha256((data_blob + prev_hash).encode("utf-8")).hexdigest()


# ─── what counts as a chain, and what is refused ──────────────────────────────

#: The keys a Foxy export may carry its chain under, in the order they are tried.
#: `logs` is what GET /v1/logs/export?format=json writes and what this tool is
#: documented against; `ledger` is the same rows inside the GDPR bundle from
#: GET /v1/account/export, which a customer will reasonably point this at.
CHAIN_SECTION_KEYS = ("logs", "ledger")

#: The fields a recompute reads with no default. A row missing any of them cannot
#: be verified at all — and saying so is the only honest answer, because guessing
#: a value would produce a hash mismatch, which this tool reports as TAMPERING.
#: Accusing an export of tampering when the truth is "you gave me the wrong file"
#: is the same class of lie as #269 itself, pointed the other way.
REQUIRED_ROW_FIELDS = ("seq", "prompt_hash", "response_hash", "token_count",
                       "policy_tag", "chain_hash")


def find_chain_section(data):
    """Name the key holding this file's chain, or None if it holds no chain at all.

    ⚠ THIS FUNCTION EXISTS BECAUSE THE ABSENCE OF IT WAS A LIE. Until register
    #269 every call site read `data.get("logs", [])`, so a JSON file with no
    `logs` key verified clean, printed `[OK] chain intact - 0 rows verified from
    genesis`, and exited 0. The verifier reported SUCCESS over a file it had
    never read.

    On this tool that is the worst possible failure. Everything Foxy sells rests
    on "export your evidence and check it yourself, without trusting us" — so a
    false `[OK]` tells a customer, an auditor or a regulator that a chain is
    intact when nothing whatsoever was checked. A crash would have been safer.

    ⚠ AND THE ALIAS IS NOT THE FIX. Accepting `ledger` removes the specific
    collision that made it easy to hit (the DSAR bundle names its chain section
    `ledger`, so running this on the file you were just handed produced exactly
    that false pass). The FIX is that anything which is neither shape is REFUSED:
    a new key, a truncated download, a wrong file, a hand-edited export with the
    chain deleted. "0 rows verified" and "verified 0 rows because I could not
    find any" are different statements, and only one of them is honest.
    """
    if not isinstance(data, dict):
        return None
    for key in CHAIN_SECTION_KEYS:
        if isinstance(data.get(key), list):
            return key
    return None


def chain_rows(data):
    """The chain rows this file carries — empty when it carries no chain section."""
    key = find_chain_section(data)
    return data[key] if key else []


def _refusal(detail, section=None):
    """Nothing was verified, and the result says so instead of reporting a pass.

    `ok` is False so no caller can mistake it for a verified chain, and `refused`
    separates it from `ok=False` meaning TAMPERING FOUND — which is a finding
    about the evidence, not about the file being the wrong one.
    """
    return {"ok": False, "refused": True, "count": 0, "first_broken_seq": None,
            "detail": detail, "head": None, "head_seq": None, "section": section}


#: Named in every refusal, because "this is not a chain" is only half an answer:
#: the reader needs to know which artefact IS one.
VERIFIABLE_ARTEFACTS = (
    "Verifiable exports: GET /v1/logs/export?format=json (rows under \"logs\"), "
    "the identical file inside ?format=bundle, or the GDPR bundle from "
    "GET /v1/account/export (rows under \"ledger\")."
)


# ─── verification ─────────────────────────────────────────────────────────────

def _row_hash(org_id, row, prev_hash):
    return compute_chain_hash(
        org_id=org_id, prompt_hash=row["prompt_hash"], response_hash=row["response_hash"],
        token_count=row["token_count"], policy_tag=row["policy_tag"], seq=row["seq"],
        prev_hash=prev_hash, agent=row.get("agent"), chain_version=row.get("chain_version", 1),
        event_id=row.get("event_id"), client_id=row.get("client_id"),
        client_seq=row.get("client_seq"), event_type=row.get("event_type"),
        commitment_alg=row.get("commitment_alg"), event_metadata=row.get("event_metadata"),
        pii_signals=row.get("pii_signals"), occurred_at=row.get("occurred_at"),
        verdict_hash=row.get("verdict_hash"))


def verdict_hash_hex(verdict):
    """Re-derive the digest a V4 row binds, from the verdict body it exported.

    The chain binds `verdict_hash`, not the verdict itself, so the chain recompute
    alone would still pass if someone rewrote `local_verdict` and left the digest
    in place. Comparing this against the stored `verdict_hash` closes that: the
    verdict body is tamper-evident too.

    `local_verdict` is the LOCAL, deterministic verdict — decided by policy rules
    at ingest. `gemini_verdict` is the row's later, advisory grade; it is not
    hashed and this tool does not check it.

    ⚠ NEITHER COLUMN NAME IS EVIDENCE THAT A MODEL PRODUCED THE VERDICT IN IT.
    `gemini_verdict` is named for the first provider this product shipped with; a
    verdict stored there may have been produced with no model called at all. Read
    `graded_by` on the verdict body — "ai", "rules", "host_enforcement" or "none"
    — and treat its absence as "not recorded", never as "no AI". On
    `local_verdict` that field is inside the bytes this digest covers, so the
    authorship claim on a V4 row is tamper-evident like everything else here.
    """
    canonical = json.dumps(verdict, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def commitment_hex(value, key, salt=None):
    """Match the SDK's HMAC commitment for customer-held known content.

    `salt` mirrors the SDK's optional per-event salt, mixed in CANONICALLY —
    HMAC(key, {"s": salt, "v": <canonical value>}) — never by concatenation.
    Omitting it reproduces the pre-salt digest byte for byte, which is what keeps
    every row written before salting existed verifiable forever.

    The salt never reaches Foxy. It lives only in the customer's own sidecar, so
    this check is the ONLY thing that needs it: `verify_export` below recomputes
    the chain from stored field values and never re-derives a hash from plaintext.
    """
    canonical = json.dumps(value, ensure_ascii=True, sort_keys=True,
                           separators=(",", ":"), default=str)
    if salt:
        canonical = json.dumps({"s": str(salt), "v": canonical},
                               ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    return hmac.new(str(key).encode("utf-8"), canonical.encode("utf-8"), hashlib.sha256).hexdigest()


def _is_salted(row):
    return str(row.get("commitment_alg") or "").endswith("-salted")


def verify_known_events(data, known_events, key):
    """Check commitments using a customer-owned sidecar without sending content to Foxy.

    Sidecar entries are keyed by event_id and hold {"prompt", "response"} plus, for
    a salted row, the "salt" the SDK recorded locally when the event was created.

    A salted row whose sidecar entry has NO salt is reported as `unprovable`, not
    as a mismatch and not as a pass: without the salt this tool cannot recompute
    the commitment at all, and calling that "tampered" would be a false accusation
    while calling it "verified" would be a lie. Same convention as the on-chain
    check — could-not-run is its own answer.
    """
    checked = 0
    unprovable = []
    for row in chain_rows(data):
        event_id = row.get("event_id")
        known = known_events.get(str(event_id)) if event_id else None
        if not known:
            continue
        # An unsalted row hashes unsalted even if the sidecar carries a salt.
        salt = known.get("salt") if _is_salted(row) else None
        if _is_salted(row) and not salt:
            unprovable.append(str(event_id))
            continue
        if commitment_hex(known.get("prompt", ""), key, salt) != row.get("prompt_hash"):
            return {"ok": False, "event_id": str(event_id), "field": "prompt_hash",
                    "checked": checked, "unprovable": unprovable}
        if commitment_hex(known.get("response", ""), key, salt) != row.get("response_hash"):
            return {"ok": False, "event_id": str(event_id), "field": "response_hash",
                    "checked": checked, "unprovable": unprovable}
        checked += 1
    return {"ok": True, "checked": checked, "unprovable": unprovable}


#: The key an export carries its page/completeness statement under. Absent from
#: every export written before paging existed, and that is handled rather than
#: rejected: such a file is read as a single page starting wherever its first row
#: does, which is exactly how this tool read it then. An export downloaded years
#: ago still verifies, and verifies to the same verdict.
PAGE_KEY = "page"


def page_meta(data):
    """This file's declared bounds, normalised. Never None, never raises.

    ⚠ THE SEED IS THE WHOLE POINT. A recompute has to start from SOMETHING, and
    until paging this tool always started from genesis — which is correct for a
    file whose first row is seq 1 and WRONG for any other. A date-ranged export
    (`?date_from=`) has always been able to start at seq 501, and recomputing
    row 501 against genesis produced a hash mismatch, which this tool reports as
    TAMPERING. An honest export was called forged because of where it began.

    So the seed is: genesis when the file starts at seq 1; the `prev_chain_hash`
    the page block declares; and otherwise the first row's own `prev_hash`,
    which is used but NOT believed — a file seeded that way can never be
    reported complete, because nothing in it proves what came before it.
    """
    rows = [r for r in chain_rows(data) if isinstance(r, dict) and "seq" in r]
    ordered = sorted(rows, key=lambda r: r["seq"])
    first = ordered[0]["seq"] if ordered else None
    last = ordered[-1]["seq"] if ordered else None
    raw = data.get(PAGE_KEY) if isinstance(data, dict) else None
    if not isinstance(raw, dict):
        raw = {}
    from_seq = raw.get("from_seq", first)
    to_seq = raw.get("to_seq", last)
    if from_seq == 1:
        seed, seed_proven = GENESIS_HASH, True
    elif raw.get("prev_chain_hash"):
        seed, seed_proven = raw["prev_chain_hash"], False
    else:
        seed, seed_proven = (ordered[0].get("prev_hash") if ordered else None), False
    return {"from_seq": from_seq, "to_seq": to_seq, "seed": seed,
            "seed_proven": seed_proven, "first_row_seq": first,
            "last_row_seq": last, "declared": bool(raw),
            "complete": bool(raw.get("complete", True))}


def _page_refusals(data, label, section):
    """The per-file refusals, unchanged from when there was only ever one file —
    only the wording now names WHICH file, because "entry 4" on its own is
    useless once an export arrives as 300 of them."""
    where = f"{label}: " if label else ""
    if not data[section]:
        return _refusal(
            f'nothing was verified: {where}the "{section}" section is present but empty, '
            "so there is no chain to recompute. An export with no rows proves "
            "nothing about a ledger; it is not an intact chain. "
            + VERIFIABLE_ARTEFACTS, section=section)
    for n, row in enumerate(data[section], 1):
        if not isinstance(row, dict):
            return _refusal(
                f'nothing was verified: {where}"{section}" entry {n} is a '
                f"{type(row).__name__}, not a row object. " + VERIFIABLE_ARTEFACTS,
                section=section)
        missing = [f for f in REQUIRED_ROW_FIELDS if f not in row]
        if missing:
            return _refusal(
                f'nothing was verified: {where}"{section}" entry {n} is missing the '
                f"field(s) a recompute needs: {', '.join(missing)}. This file "
                "carries a chain section but not the columns the hash is taken "
                "over, so no row in it can be checked. " + VERIFIABLE_ARTEFACTS,
                section=section)
    return None


def _broken(detail, seq, count, section):
    """A finding about the evidence: something was recomputed and did not match.
    Never `refused` — that is the wrong-file answer — and never `complete`,
    because a chain that broke was not verified to its end."""
    return {"ok": False, "refused": False, "count": count, "first_broken_seq": seq,
            "detail": detail, "section": section, "head": None, "head_seq": None,
            "complete": False, "from_seq": None, "to_seq": None, "pages": 1,
            "seed": None, "incomplete_reason": None}


def verify_export(data):
    """Verify ONE export file — the single-file entry point every existing caller
    uses, kept exactly as it was. The work happens in verify_pages."""
    return verify_pages([data])


def verify_pages(pages, labels=None):
    """Recompute the chain across one or more export files and compare each row's
    stored hash.

    Returns {ok, refused, count, first_broken_seq, detail, section, head,
    head_seq, complete, from_seq, to_seq, pages, seed, incomplete_reason}.

    FOUR outcomes, not two, and `ok` alone no longer tells a reader what they
    have. `refused=True` means no chain was recomputed at all and must never
    print [OK]. `ok=False` means a row did not match — tampering. `ok=True` with
    `complete=True` is the whole ledger from genesis. `ok=True` with
    `complete=False` is a SEGMENT: every row in it is intact, and it proves
    nothing about the rows outside it.

    ⚠ THAT FOURTH OUTCOME IS THE POINT. A ledger too large for one response now
    arrives in pages, and reporting page 1 of 300 as "chain intact - 10000 rows
    verified from genesis" would be a completeness claim over 0.3% of the
    evidence — the exact shape of #252, re-made by the tool that exists to check
    it. A segment gets its own wording and its own exit code (3), so no reader
    and no CI job can mistake one for the whole ledger.
    """
    labels = list(labels or [None] * len(pages))
    if not pages:
        return _refusal("nothing was verified: no export file was given. "
                        + VERIFIABLE_ARTEFACTS)

    metas = []
    for data, label in zip(pages, labels):
        section = find_chain_section(data)
        if section is None:
            keys = sorted(data) if isinstance(data, dict) else []
            saw = (", ".join(keys[:12]) + ("..." if len(keys) > 12 else "")) if keys else (
                "a JSON " + type(data).__name__ + ", not an object")
            where = f"{label}: " if label else ""
            return _refusal(
                f"nothing was verified: {where}this file has no chain section. Looked for "
                + " and ".join(f'"{k}"' for k in CHAIN_SECTION_KEYS)
                + f"; the file carries {saw}. " + VERIFIABLE_ARTEFACTS)
        bad = _page_refusals(data, label, section)
        if bad is not None:
            return bad
        metas.append((data, label, section, page_meta(data)))

    metas.sort(key=lambda m: m[3]["first_row_seq"])
    section = metas[0][2]
    total = sum(len(m[0][m[2]]) for m in metas)

    # A page whose declared bounds disagree with the rows inside it has been
    # edited: one of the two was rewritten and they no longer describe the same
    # file. Trimming rows off the front of a page and leaving the block alone is
    # the cheapest possible forgery, and it is caught here rather than by luck.
    for data, label, sec, meta in metas:
        where = f"{label}" if label else "this file"
        if meta["declared"]:
            if meta["from_seq"] != meta["first_row_seq"]:
                return _broken(
                    f'{where} declares it starts at seq {meta["from_seq"]} but its '
                    f'first row is seq {meta["first_row_seq"]}',
                    meta["first_row_seq"], total, sec)
            if meta["to_seq"] != meta["last_row_seq"]:
                return _broken(
                    f'{where} declares it ends at seq {meta["to_seq"]} but its '
                    f'last row is seq {meta["last_row_seq"]}',
                    meta["last_row_seq"], total, sec)

    # Pages must belong to the same workspace. org_id is the FIRST field of the
    # hashed event, so two workspaces' pages concatenated would otherwise fail as
    # tampering with no hint of the real cause.
    org_ids = {str(m[0].get("org_id")) for m in metas}
    if len(org_ids) > 1:
        return _broken(
            "these files are not pages of one export: they carry "
            f"{len(org_ids)} different org_id values ({', '.join(sorted(org_ids))})",
            None, total, section)

    # ...and they must join. Page k+1 starts where page k stopped, and says so
    # itself: its declared prev_chain_hash is checked against the hash page k
    # actually ended on, so a page dropped from the middle of a 300-page export
    # cannot pass as a join.
    for (a_data, a_label, a_sec, a), (b_data, b_label, b_sec, b) in zip(metas, metas[1:]):
        if b["first_row_seq"] != a["last_row_seq"] + 1:
            return _broken(
                f'page files do not join: one ends at seq {a["last_row_seq"]} and the '
                f'next starts at seq {b["first_row_seq"]}'
                + (f" ({b_label})" if b_label else ""),
                b["first_row_seq"], total, section)
        a_last = max(a_data[a_sec], key=lambda r: r["seq"])["chain_hash"]
        if b["declared"] and b["seed"] != a_last:
            return _broken(
                f'page files do not join at seq {b["first_row_seq"]}: that page '
                f'declares it continues from {b["seed"]}, but the page before it '
                f"ends on {a_last}",
                b["first_row_seq"], total, section)

    org_id = metas[0][0].get("org_id")
    head_meta = metas[0][3]
    prev = head_meta["seed"]
    if prev is None:
        return _refusal(
            "nothing was verified: this export starts at seq "
            f'{head_meta["first_row_seq"]}, not at the start of the ledger, and '
            "carries neither a page block naming the chain hash it continues "
            "from nor a prev_hash on its first row. There is nothing to "
            "recompute the first row against. " + VERIFIABLE_ARTEFACTS,
            section=section)

    rows = sorted((r for m in metas for r in m[0][m[2]]), key=lambda r: r["seq"])
    expected_seq = head_meta["first_row_seq"]
    for row in rows:
        if row["seq"] != expected_seq:
            return _broken(f"sequence gap before seq {row['seq']}", row["seq"], len(rows), section)
        # ⚠ THE DEFAULT IS GENESIS, NOT `prev`, AND THAT IS LOAD-BEARING.
        # Defaulting to `prev` makes the comparison compare a value with
        # itself, so a ledger could drop prev_hash from every row and still
        # verify. Genesis is only ever the right answer for the first row of
        # the whole chain, so every other missing prev_hash fails here.
        if row.get("prev_hash", GENESIS_HASH) != prev:
            return _broken(f"previous hash mismatch at seq {row['seq']}", row["seq"], len(rows), section)
        expected = _row_hash(org_id, row, prev)
        if expected != row.get("chain_hash"):
            return _broken(f"chain hash mismatch at seq {row['seq']}", row["seq"], len(rows), section)
        # The chain binds the verdict's DIGEST; this binds the digest to the body.
        # Without it, `local_verdict` could be rewritten and the chain still pass.
        if row.get("local_verdict") is not None:
            if verdict_hash_hex(row["local_verdict"]) != row.get("verdict_hash"):
                return _broken(
                    f"local verdict does not match its bound hash at seq {row['seq']}",
                    row["seq"], len(rows), section)
        prev = row["chain_hash"]
        expected_seq += 1

    # ⚠ `first_row_seq`, NOT the DECLARED `from_seq`. The bounds check above
    # already refuses a page whose block and rows disagree, and this reads the
    # rows anyway: a completeness verdict must not rest on a number the file
    # asserts about itself when the rows are right there to be counted.
    from_genesis = (head_meta["first_row_seq"] == 1
                    and head_meta["seed"] == GENESIS_HASH)
    last_page_complete = metas[-1][3]["complete"]
    complete = from_genesis and last_page_complete
    reason = None
    if not from_genesis:
        reason = (
            f'this export starts at seq {head_meta["first_row_seq"]}, not at the '
            f'start of the ledger. Rows 1-{head_meta["first_row_seq"] - 1} are not '
            "in it and nothing here proves anything about them; the hash it "
            "continues from is read out of the file itself, not verified.")
    elif not last_page_complete:
        reason = (
            f'the ledger continues past seq {rows[-1]["seq"]}: the last file given '
            "says it is not the final page. Fetch the remaining pages (each "
            'page names the next one in page.next) and pass them all to this '
            "command at once.")

    # The first page that HAS a receipt, not `pages[0]` — the caller may hand
    # the files over in any order, and the receipt is per-workspace anyway.
    anchor = next((p.get("anchor") for p in pages if p.get("anchor")), None) or {}
    # Only an export that CLAIMS to be whole can "stop before" the checkpoint. On
    # an admittedly partial one, stopping short is what partial MEANS, and
    # reporting it as a failure would accuse an honest page of tampering.
    if complete and rows and anchor.get("last_seq", 0) > rows[-1]["seq"]:
        return _broken("export stops before the anchored checkpoint", None, len(rows), section)

    # `rows` cannot be empty here: an empty section was refused above, so the
    # head is always a real recomputed hash rather than GENESIS standing in for
    # one. That substitution was how "0 rows verified" acquired a head at all.
    return {"ok": True, "refused": False, "count": len(rows), "first_broken_seq": None,
            "detail": "chain intact" if complete else "segment intact",
            "section": section, "head": prev, "head_seq": rows[-1]["seq"],
            "complete": complete, "from_seq": rows[0]["seq"], "to_seq": rows[-1]["seq"],
            "pages": len(metas), "seed": head_meta["seed"],
            "incomplete_reason": reason}


def merge_pages(pages):
    """One dict shaped like a single export, holding every page's rows — what the
    anchor checks read. The anchor receipt and org_id come from the first page;
    they are per-workspace, not per-page, and verify_pages has already refused a
    set that mixes workspaces."""
    if len(pages) == 1:
        return pages[0]
    rows = sorted((r for p in pages for r in chain_rows(p)), key=lambda r: r["seq"])
    anchor = next((p.get("anchor") for p in pages if p.get("anchor")), None)
    return {"org_id": pages[0].get("org_id"), "anchor": anchor,
            "page": pages[0].get("page"), "logs": rows}


def recompute_head_upto(data, upto_seq):
    """Independently recompute the chain head at ``upto_seq`` from genesis."""
    org_id = data.get("org_id")
    prev, last = GENESIS_HASH, None
    for row in sorted(chain_rows(data), key=lambda r: r["seq"]):
        if row["seq"] > upto_seq:
            break
        prev = _row_hash(org_id, row, prev)
        last = prev
    return last


def check_anchor_offline(data, _verify_result=None):
    """Compare the export's embedded anchor receipt to an INDEPENDENT recompute of
    the chain head at the anchored seq. Returns None if there's no receipt.

    NOTE: the receipt is Foxy-provided, so this proves the export's chain matches
    what Foxy says it anchored — for proof against the PUBLIC chain, use --anchor.

    ⚠ THREE ANSWERS, BECAUSE OTHERWISE TWO DIFFERENT THINGS PRINT AS TAMPERING.
    Recomputing the head at the anchored seq needs every row from genesis up to
    it, and a paged or date-ranged export need not carry them. Run regardless,
    this check seeds at genesis, recomputes a head over rows that do not start
    there, finds it unequal to the receipt and prints "anchor receipt DOES NOT
    MATCH" — an accusation of forgery against an honest page. So `matches` is
    None and `checked` is False when the rows the check needs are simply not in
    the file. Not-checked is a third answer and it is the honest one.
    """
    a = data.get("anchor")
    if not a:
        return None
    meta = page_meta(data)
    common = {"root_hash": a.get("root_hash"), "last_seq": a.get("last_seq"),
              "chain": a.get("chain"), "tx_hash": a.get("tx_hash"),
              "block_number": a.get("block_number"), "contract": a.get("contract")}
    if not (meta["from_seq"] == 1 and meta["seed"] == GENESIS_HASH):
        return {**common, "matches": None, "checked": False, "recomputed": None,
                "detail": (f'not checked: this export starts at seq {meta["first_row_seq"]}, '
                           "so the head at the anchored seq cannot be recomputed from "
                           "genesis out of this file")}
    if a.get("last_seq", 0) > (meta["last_row_seq"] or 0):
        return {**common, "matches": None, "checked": False, "recomputed": None,
                "detail": (f'not checked: the anchored checkpoint is at seq {a.get("last_seq")}, '
                           f'past the last row given (seq {meta["last_row_seq"]}). Pass the '
                           "remaining pages of this export to check it")}
    recomputed = recompute_head_upto(data, a["last_seq"])
    return {**common, "matches": recomputed == a.get("root_hash"),
            "checked": True, "recomputed": recomputed, "detail": None}


# ─── optional live on-chain check (lazy web3) ─────────────────────────────────

def _norm_hex(s):
    return str(s).lower().removeprefix("0x")


def check_anchor_onchain(rpc, tx_hash, expected_root, contract=None):
    """Confirm the anchoring tx really emitted Anchored(root) on the public chain.
    Best-effort and network-dependent; `ok` is None when it couldn't run."""
    if not rpc or not tx_hash or not expected_root:
        return {"ok": None, "detail": "need --rpc and an anchor tx_hash + root in the export"}
    try:
        from web3 import Web3
    except ImportError:
        return {"ok": None, "detail": "web3 not installed — `pip install web3` to use --anchor"}
    try:
        w3 = Web3(Web3.HTTPProvider(rpc))
        receipt = w3.eth.get_transaction_receipt(tx_hash)
        sig = _norm_hex(w3.keccak(text="Anchored(address,bytes32,uint256)").hex())
    except Exception as exc:  # noqa: BLE001 — any RPC/tx error → couldn't verify
        return {"ok": None, "detail": f"could not query the chain: {exc}"}

    want = _norm_hex(expected_root)
    for lg in receipt["logs"]:
        topics = [_norm_hex(t.hex() if hasattr(t, "hex") else t) for t in lg["topics"]]
        if not topics or topics[0] != sig:
            continue
        if contract and _norm_hex(lg["address"]) != _norm_hex(contract):
            continue
        if len(topics) >= 3 and topics[2] == want:   # topic[2] = indexed bytes32 root
            return {"ok": True, "address": lg["address"],
                    "block_number": receipt.get("blockNumber"),
                    "detail": "Anchored(root) event confirmed on-chain"}
    return {"ok": False, "detail": "no matching Anchored(root) event in that transaction"}


# ─── CLI ──────────────────────────────────────────────────────────────────────

def _load_sidecar(path):
    """Read a known-event sidecar in either shape.

    * one JSON object keyed by event_id — what a customer hand-writes; or
    * JSON Lines, `{"event_id": …, "salt": …}` per line, which is what the SDK
      appends. It can only append: it knows the salt when the event happens and
      never rewrites the file.

    Lines merge per event_id, later wins, so a customer can append their own
    `{"event_id": …, "prompt": …, "response": …}` line beside the SDK's salt line
    instead of editing one big object.
    """
    with open(path, encoding="utf-8") as f:
        text = f.read()
    try:
        loaded = json.loads(text)
    except json.JSONDecodeError:
        loaded = None
    # A top-level "event_id" means this is a single JSONL line, not an id → entry map.
    if isinstance(loaded, dict) and "event_id" not in loaded:
        return loaded
    merged = {}
    for n, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        entry = json.loads(line)
        event_id = str(entry.get("event_id") or "")
        if not event_id:
            raise ValueError(f"sidecar line {n} has no event_id")
        merged.setdefault(event_id, {}).update(
            {k: v for k, v in entry.items() if k != "event_id"})
    return merged


def _wrap(text, width=72, indent=" " * 10):
    """Fold a refusal onto the console without pulling in `textwrap`-free tricks.

    stdlib only, like everything here; `textwrap` is stdlib, but this keeps the
    output's exact shape obvious to anyone reading the file to check it.
    """
    line, out = "", []
    for word in text.split():
        if line and len(line) + 1 + len(word) > width:
            out.append(line)
            line = word
        else:
            line = f"{line} {word}".strip()
    if line:
        out.append(line)
    return ("\n" + indent).join(out)


def _print_refusal(result):
    """The one thing this tool must never do quietly.

    A refusal is not a pass with a caveat and not an accusation of tampering, so
    it gets its own marker and its own exit code (2). `[OK]` appears nowhere in
    it — the string itself is what a reader skims for, and printing it beside
    "0 rows" is exactly the lie #269 was.
    """
    print("[REFUSED] " + _wrap(result["detail"]))


def _print_human(result, anchor_off, anchor_live, commitments=None):
    # ASCII-only markers so the tool never crashes on a non-UTF-8 console (Windows
    # cp1252, cp437, …) — it must run for anyone, anywhere.
    if result.get("refused"):
        _print_refusal(result)
        return
    if result["ok"] and result.get("complete", True):
        print(f"[OK]   chain intact - {result['count']} rows verified from genesis")
        if result["count"]:
            print(f"       head @ seq {result['head_seq']} = {result['head']}")
    elif result["ok"]:
        # ⚠ NOT "[OK] chain intact". Every row given was recomputed and matched,
        # and that is worth saying — but this file is a SEGMENT of a ledger, and
        # a reader who skims for [OK] must not carry away a completeness claim
        # the evidence does not support. The word, the rows it names and the
        # exit code (3) all say segment.
        pages = result.get("pages", 1)
        print(f"[OK]   segment intact - {result['count']} rows verified, "
              f"seq {result['from_seq']}-{result['to_seq']}"
              + (f" across {pages} page files" if pages > 1 else ""))
        print(f"       head @ seq {result['head_seq']} = {result['head']}")
        print("[--]   INCOMPLETE - this is NOT the whole ledger:")
        print("       " + _wrap(result.get("incomplete_reason") or
                                "this export does not cover the ledger end to end.",
                                indent="       "))
    else:
        print(f"[FAIL] CHAIN BROKEN at seq {result['first_broken_seq']} - {result['detail']}")

    if anchor_off is None:
        print("[--]   no anchor receipt in this export")
    elif anchor_off.get("matches") is None:
        print(f"[--]   anchor receipt {_wrap(anchor_off['detail'], indent='       ')}")
    elif anchor_off["matches"]:
        print(f"[OK]   anchor receipt matches the chain @ seq {anchor_off['last_seq']}")
        print(f"       root {anchor_off['root_hash']} (chain={anchor_off['chain']})")
    else:
        print(f"[FAIL] anchor receipt DOES NOT MATCH the chain @ seq {anchor_off['last_seq']}")
        print(f"       receipt {anchor_off['root_hash']} vs recomputed {anchor_off['recomputed']}")

    if anchor_live is not None:
        if anchor_live.get("ok") is True:
            print(f"[OK]   ON-CHAIN: {anchor_live['detail']} "
                  f"(block {anchor_live.get('block_number')})")
        elif anchor_live.get("ok") is False:
            print(f"[FAIL] ON-CHAIN: {anchor_live['detail']}")
        else:
            print(f"[--]   on-chain check skipped: {anchor_live['detail']}")

    # The known-content check used to set the exit code while printing NOTHING
    # here, so a mismatch looked like a clean run that mysteriously returned 1.
    if commitments is not None:
        if commitments.get("detail"):
            print(f"[FAIL] known-content check: {commitments['detail']}")
        elif commitments["ok"]:
            print(f"[OK]   {commitments['checked']} known event(s) match their commitments")
        else:
            print(f"[FAIL] {commitments['field']} does NOT match the known content "
                  f"for event {commitments['event_id']}")
        skipped = len(commitments.get("unprovable") or [])
        if skipped:
            print(f"[--]   {skipped} salted event(s) not checked - no salt in the sidecar, "
                  f"so the commitment cannot be recomputed (--json lists them)")


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(
        description="Independently verify a Foxy Audit log export (no Foxy trust required).")
    ap.add_argument("export", nargs="+",
                    help="path to the downloaded foxy-audit-logs.json. A ledger too "
                         "large for one response arrives in pages: pass every page "
                         "file, in any order, and they are verified as one chain")
    ap.add_argument("--anchor", action="store_true",
                    help="also confirm the anchor root live on the public chain (needs web3 + --rpc)")
    ap.add_argument("--rpc", help="EVM RPC URL for --anchor, e.g. https://rpc.sepolia.org")
    ap.add_argument("--contract", help="AnchorRegistry address to match (defaults to the export's)")
    ap.add_argument("--commitment-key", help="customer-owned HMAC key for a known-event sidecar")
    ap.add_argument("--events",
                    help="known-event sidecar: a JSON object keyed by event_id, or the "
                         "JSONL file the SDK appends salts to. Entries hold prompt/response "
                         "and, for a salted row, the salt (which never leaves your machine)")
    ap.add_argument("--json", action="store_true", help="machine-readable JSON output")
    args = ap.parse_args(argv)

    pages = []
    for path in args.export:
        try:
            with open(path, encoding="utf-8") as f:
                pages.append(json.load(f))
        except (OSError, json.JSONDecodeError) as exc:
            print(f"could not read export: {exc}", file=sys.stderr)
            return 2

    result = verify_pages(pages, labels=args.export)
    # ⚠ A REFUSAL STOPS HERE, AND STOPPING IS PART OF THE ANSWER. Running the
    # anchor and known-content checks over a file with no chain would print two
    # more lines of verdict about evidence nobody recomputed — and the offline
    # anchor check, handed no rows, compares a receipt against None and reports
    # a MISMATCH, which reads as tampering. Exit 2 = nothing was verified, kept
    # distinct from 1 = something was verified and was wrong.
    if result.get("refused"):
        if args.json:
            print(json.dumps({"chain": result, "anchor_offline": None,
                              "anchor_onchain": None, "commitments": None}, indent=2))
        else:
            _print_refusal(result)
        return 2
    data = merge_pages(pages)
    commitment_result = None
    if args.commitment_key and args.events:
        try:
            commitment_result = verify_known_events(
                data, _load_sidecar(args.events), args.commitment_key)
        except (OSError, ValueError) as exc:   # ValueError covers JSONDecodeError
            commitment_result = {"ok": False, "detail": f"could not read known-event sidecar: {exc}"}
    anchor_off = check_anchor_offline(data, result)
    anchor_live = None
    if args.anchor:
        a = data.get("anchor") or {}
        anchor_live = check_anchor_onchain(
            args.rpc, a.get("tx_hash"), a.get("root_hash"),
            args.contract or a.get("contract"))

    if args.json:
        print(json.dumps({"chain": result, "anchor_offline": anchor_off,
                          "anchor_onchain": anchor_live,
                          "commitments": commitment_result}, indent=2))
    else:
        _print_human(result, anchor_off, anchor_live, commitment_result)

    bad = ((not result["ok"])
           or (commitment_result is not None and not commitment_result["ok"])
           or (anchor_off is not None and anchor_off.get("matches") is False)
           or (anchor_live is not None and anchor_live.get("ok") is False))
    if bad:
        return 1
    # ⚠ 3, NOT 0. Nothing was found wrong, and that is not the same as the whole
    # ledger being intact. A CI job that treats a segment as a pass is asserting
    # completeness over rows it never saw, so a segment gets an exit code no
    # `if [ $? -eq 0 ]` can swallow by accident.
    return 0 if result.get("complete", True) else 3


if __name__ == "__main__":
    sys.exit(main())
