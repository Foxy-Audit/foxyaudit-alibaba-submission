#!/usr/bin/env python3
"""Foxy Audit — independent, open-source ledger verifier (Phase 6 · 6D).

Re-verifies a Foxy Audit log export WITHOUT trusting Foxy. It re-implements the
hash-chain recipe here from scratch (stdlib only, zero Foxy imports), recomputes
every row from genesis, and reports the first tampered sequence — the whole point
being that you can run this yourself and don't have to take our word for it.

    python foxy_verify.py foxy-audit-logs.json
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

The GDPR bundle from GET /v1/account/export carries the same rows under "ledger"
instead of "logs"; both keys are read. ANY OTHER FILE IS REFUSED — see
find_chain_section below for why the refusal is the point and the alias is not.

Exit code 0 = intact, 1 = tampering / anchor / commitment mismatch, 2 = NOTHING
WAS VERIFIED (unreadable file, or no chain in it). `--json` for machine output.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import sys

# ─── the chain recipe — an INDEPENDENT copy of backend/app/chain.py ───────────
# Keep this byte-for-byte identical to the backend, INCLUDING the rule that
# `agent` is appended only when present (so pre-agent rows hash unchanged). If the
# backend recipe ever changes, this must change with it — verifier/test_verify.py
# cross-checks the two on every run.

GENESIS_HASH = "0" * 64


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
            "occurred_at": occurred_at, "seq": seq,
        }
        if chain_version >= 3:
            event["chain_version"] = chain_version
        # V4 binds the digest of the row's LOCAL, deterministic verdict (the one
        # decided at ingest). The later, asynchronous grade is NOT bound — see
        # verdict_hash_hex below for what that means for a reader.
        if chain_version >= 4:
            event["verdict_hash"] = verdict_hash
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


def verify_export(data):
    """Recompute the whole chain from genesis and compare each row's stored hash.
    Returns {ok, refused, count, first_broken_seq, detail, section, head, head_seq}.

    Three outcomes, not two. `ok` means the chain was recomputed and matched;
    `ok=False` means a row did not match — tampering; `refused=True` means no
    chain was recomputed at all, which is neither and must never print [OK].
    """
    section = find_chain_section(data)
    if section is None:
        keys = sorted(data) if isinstance(data, dict) else []
        saw = (", ".join(keys[:12]) + ("…" if len(keys) > 12 else "")) if keys else (
            "a JSON " + type(data).__name__ + ", not an object")
        return _refusal(
            "nothing was verified: this file has no chain section. Looked for "
            + " and ".join(f'"{k}"' for k in CHAIN_SECTION_KEYS)
            + f"; the file carries {saw}. " + VERIFIABLE_ARTEFACTS)
    if not data[section]:
        return _refusal(
            f'nothing was verified: the "{section}" section is present but empty, '
            "so there is no chain to recompute. An export with no rows proves "
            "nothing about a ledger; it is not an intact chain. "
            + VERIFIABLE_ARTEFACTS, section=section)
    for n, row in enumerate(data[section], 1):
        if not isinstance(row, dict):
            return _refusal(
                f'nothing was verified: "{section}" entry {n} is a '
                f"{type(row).__name__}, not a row object. " + VERIFIABLE_ARTEFACTS,
                section=section)
        missing = [f for f in REQUIRED_ROW_FIELDS if f not in row]
        if missing:
            return _refusal(
                f'nothing was verified: "{section}" entry {n} is missing the '
                f"field(s) a recompute needs: {', '.join(missing)}. This file "
                "carries a chain section but not the columns the hash is taken "
                "over, so no row in it can be checked. " + VERIFIABLE_ARTEFACTS,
                section=section)

    org_id = data.get("org_id")
    rows = sorted(data[section], key=lambda r: r["seq"])
    prev = GENESIS_HASH
    expected_seq = 1
    for row in rows:
        if row["seq"] != expected_seq:
            return {"ok": False, "refused": False, "count": len(rows), "first_broken_seq": row["seq"],
                    "detail": f"sequence gap before seq {row['seq']}",
                    "section": section, "head": None, "head_seq": None}
        if row.get("prev_hash", GENESIS_HASH) != prev:
            return {"ok": False, "refused": False, "count": len(rows), "first_broken_seq": row["seq"],
                    "detail": f"previous hash mismatch at seq {row['seq']}",
                    "section": section, "head": None, "head_seq": None}
        expected = _row_hash(org_id, row, prev)
        if expected != row.get("chain_hash"):
            return {"ok": False, "refused": False, "count": len(rows), "first_broken_seq": row["seq"],
                    "detail": f"chain hash mismatch at seq {row['seq']}",
                    "section": section, "head": None, "head_seq": None}
        # The chain binds the verdict's DIGEST; this binds the digest to the body.
        # Without it, `local_verdict` could be rewritten and the chain still pass.
        if row.get("local_verdict") is not None:
            if verdict_hash_hex(row["local_verdict"]) != row.get("verdict_hash"):
                return {"ok": False, "refused": False, "count": len(rows), "first_broken_seq": row["seq"],
                        "detail": f"local verdict does not match its bound hash at seq {row['seq']}",
                        "section": section, "head": None, "head_seq": None}
        prev = row["chain_hash"]
        expected_seq += 1
    anchor = data.get("anchor") or {}
    if rows and anchor.get("last_seq", 0) > rows[-1]["seq"]:
        return {"ok": False, "refused": False, "count": len(rows), "first_broken_seq": None,
                "detail": "export stops before the anchored checkpoint",
                "section": section, "head": None, "head_seq": None}
    # `rows` cannot be empty here: an empty section was refused above, so the
    # head is always a real recomputed hash rather than GENESIS standing in for
    # one. That substitution was how "0 rows verified" acquired a head at all.
    return {"ok": True, "refused": False, "count": len(rows), "first_broken_seq": None,
            "detail": "chain intact", "section": section,
            "head": prev, "head_seq": rows[-1]["seq"]}


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
    what Foxy says it anchored — for proof against the PUBLIC chain, use --anchor."""
    a = data.get("anchor")
    if not a:
        return None
    recomputed = recompute_head_upto(data, a["last_seq"])
    return {
        "matches": recomputed == a.get("root_hash"),
        "root_hash": a.get("root_hash"), "recomputed": recomputed,
        "last_seq": a.get("last_seq"), "chain": a.get("chain"),
        "tx_hash": a.get("tx_hash"), "block_number": a.get("block_number"),
        "contract": a.get("contract"),
    }


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
    if result["ok"]:
        print(f"[OK]   chain intact - {result['count']} rows verified from genesis")
        if result["count"]:
            print(f"       head @ seq {result['head_seq']} = {result['head']}")
    else:
        print(f"[FAIL] CHAIN BROKEN at seq {result['first_broken_seq']} - {result['detail']}")

    if anchor_off is None:
        print("[--]   no anchor receipt in this export")
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
    ap.add_argument("export", help="path to the downloaded foxy-audit-logs.json")
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

    try:
        with open(args.export, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"could not read export: {exc}", file=sys.stderr)
        return 2

    result = verify_export(data)
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
           or (anchor_off is not None and not anchor_off["matches"])
           or (anchor_live is not None and anchor_live.get("ok") is False))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
