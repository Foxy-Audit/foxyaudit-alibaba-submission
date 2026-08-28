"""The verification bundle — the evidence and the tool that checks it, in one ZIP.

The Compliance Passport tells a third party to run the standalone verifier, and
until now there was no honest way for that third party to obtain it: no route
served it, the SDK wheel does not carry it, and there is no public repository
URL. `GET /v1/logs/export?format=bundle` closes that: whoever holds the evidence
holds the tool.

    foxy-audit-export.zip
    |- foxy-audit-logs.json   the format=json body, byte-for-byte
    |- foxy_verify.py         the standalone verifier (stdlib only, no network)
    `- VERIFY.txt             the two commands, lifted from verifier/README.md

Built in memory with `zipfile` + `io.BytesIO` — both standard library, no new
dependency and no file on disk, which is what ExportJob's docstring promises
("the server keeps NO file archive; a re-download re-runs the producer").

⚠ WHY THE VERIFIER IS VENDORED HERE. `backend/Dockerfile` does `COPY . .` from
the `backend/` build context, and the real verifier lives at the repo ROOT
(`verifier/foxy_verify.py`) — so it never reaches the image. The alternative was
a runtime mount (the pattern `deploy/docker-compose.prod.yml` uses for
`foxy-dashboard/`), but a missing mount only announces itself in production,
whereas a stale copy is caught deterministically by
`tests/integration/test_export_bundle.py::test_the_vendored_verifier_has_not_drifted`,
which asserts `app/bundled/foxy_verify.py` is byte-identical to
`verifier/foxy_verify.py`. If you edit one, edit both — that test is the guard.
"""

from __future__ import annotations

import io
import zipfile
from pathlib import Path

BUNDLE_FILENAME = "foxy-audit-export.zip"
LOGS_MEMBER = "foxy-audit-logs.json"
VERIFIER_MEMBER = "foxy_verify.py"
INSTRUCTIONS_MEMBER = "VERIFY.txt"

VERIFIER_PATH = Path(__file__).resolve().parent / "bundled" / VERIFIER_MEMBER


class VerifierUnavailable(RuntimeError):
    """The vendored verifier could not be read, so no bundle can be produced.

    Deliberately fatal. A bundle that silently omits the tool it exists to
    deliver is worse than a download that refuses: the auditor discovers the gap
    later, having already been told the archive is self-sufficient.
    """


# Lifted from verifier/README.md rather than written afresh — the same two
# commands described a third time is a third thing to keep in sync. ASCII only:
# this is a .txt an auditor may open in whatever editor their bank issued them.
VERIFY_TXT = """\
Foxy Audit - verify this export yourself
========================================

This archive contains the evidence AND the tool that checks it. Verification
does not require trusting Foxy Audit, and does not require our servers to be
reachable.

  foxy-audit-logs.json   the ledger export you requested
  foxy_verify.py         the standalone verifier
  VERIFY.txt             this file

Requirements: Python 3.9+ (standard library only). `web3` is optional - needed
only for the live --anchor on-chain check below.


Run it
------

  python foxy_verify.py foxy-audit-logs.json

  [OK] chain intact - 512 rows verified from genesis
       head @ seq 512 = a3f9c17e...
  [OK] anchor receipt matches the chain @ seq 512
       root a3f9c17e... (chain=sepolia)

Exit code is 0 when intact, 1 when tampering or an anchor mismatch is found, and
2 when NOTHING WAS VERIFIED - so it drops straight into CI. Add --json for
machine-readable output.

It will never report success over a file it did not read. A file with no chain
in it, an empty chain section, or rows missing the columns the hash is taken
over is a [REFUSED] and exit 2, naming what the file actually contained and
which export is verifiable. "0 rows verified" and "verified 0 rows because there
were none to find" are different statements, and only one of them is honest.


Live on-chain check (optional)
------------------------------

The offline check confirms the export's chain matches the anchor receipt Foxy
included. To confirm against the PUBLIC chain instead of Foxy's word, verify the
anchoring transaction really emitted the root:

  pip install web3
  python foxy_verify.py foxy-audit-logs.json --anchor --rpc https://rpc.sepolia.org

This fetches the anchor transaction named in the export and confirms it emitted
Anchored(root) on the AnchorRegistry contract. It only applies to EVM-anchored
organisations (a stub-anchored export has no on-chain transaction to check).


What this proves
----------------

The verifier re-implements the hash-chain recipe from scratch - it imports
nothing from Foxy - and recomputes your entire ledger from genesis, reporting
the first tampered row (if any).

Each row declares its own chain_version, and every version is frozen forever: a
new one may only ADD a field, never reorder or remove one, so an export you
downloaded years ago still verifies with this script. Version 1 hashes a
pipe-delimited string; version 2 onward hashes canonical JSON of the event:

  Hn = SHA256( "org_id|prompt_hash|response_hash|token_count|policy_tag|seq"
               [+ "|agent=<agent>"]  +  Hn-1 )              # version 1
  Hn = SHA256( canonical_json(event)  +  Hn-1 )             # version 2+
  H0 = "0" x 64   (genesis)

The |agent=<agent> segment is appended only when the row has an agent, so rows
logged before agent attribution hash identically. Version 2 added the capture
fields (event_id, client ids, event_type, metadata, pii_signals, occurred_at),
version 3 bound chain_version itself, and version 4 bound verdict_hash.

If Foxy - or anyone with database access - altered a historical interaction, the
recomputed chain hash for that row no longer matches the stored one, and every
row after it breaks too (avalanche effect). Only the SHA-256 hashes of your
prompts and responses are ever stored - never the raw text.

WHICH VERDICT VERSION 4 BINDS. local_verdict is the deterministic verdict decided
by policy rules on the row's metadata at the moment it was recorded; that is what
verdict_hash covers, and editing it afterwards breaks the chain. gemini_verdict
is the row's later, asynchronous grade - not bound, and it cannot be, because the
chain hash is fixed when the row is written and grading happens afterwards. The
chain covers what the system DECIDED; the later grade sits beside it, labelled,
and this script does not check it.

WHO GRADED EACH ROW - read graded_by, do not assume. gemini_verdict is named for
the first provider this product shipped with; it is NOT evidence that a model
produced it, and a row it holds may have been graded with no model involved at
all. Every verdict says which:

  graded_by = "ai"                a model answered, and judge_provider /
                                  judge_model name it
  graded_by = "rules"             the deterministic metadata engine graded this
                                  row and no model was called. When that is
                                  because a judge could not be reached,
                                  evaluator_unavailable_reason says why
  graded_by = "host_enforcement"  the row is a prompt your own host blocked or
                                  redacted before it left. Nothing was sent, so
                                  there was no model response to grade
  graded_by = "none"              nothing graded this row - either no evaluator
                                  ran, or one answered and its answer was refused
                                  as self-contradictory
  absent                          the row predates this field. It records no
                                  claim about who graded it, and nothing has been
                                  written in after the fact to invent one

On local_verdict this field is inside what verdict_hash binds, so an authorship
claim on a chain_version 4 row cannot be edited without this script noticing.

  Check                       When                        Proves
  --------------------------  --------------------------  ------------------------
  Chain integrity             always                      no historical row was
                                                          altered (pure recompute)
  Verdict binding             chain_version 4 or later    the row's local verdict
                                                          is the one recorded
  Anchor, offline             if a receipt is present     the export's chain
                                                          matches the anchored
                                                          root Foxy recorded
  Anchor, on-chain (--anchor) opt-in                      that root really exists
                                                          on a public chain,
                                                          independent of Foxy
"""


def build(logs_json: bytes) -> bytes:
    """Return the ZIP bytes for `logs_json` (the format=json body, verbatim).

    Raises VerifierUnavailable if the vendored verifier is missing or empty.
    """
    try:
        verifier = VERIFIER_PATH.read_bytes()
    except OSError as exc:
        raise VerifierUnavailable(str(exc)) from exc
    if not verifier.strip():
        raise VerifierUnavailable(f"{VERIFIER_PATH} is empty")

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr(LOGS_MEMBER, logs_json)
        z.writestr(VERIFIER_MEMBER, verifier)
        z.writestr(INSTRUCTIONS_MEMBER, VERIFY_TXT.encode("utf-8"))
    return buf.getvalue()
