"""#264 — the rotate dialog states the estate it burns, and counts it correctly.

`Rotate API key` on the Access page calls `regenerateKey()` →
`POST /v1/keys/regenerate/confirm` → `keys.py::_rotate_org_key`, whose own
docstring opens *"Revoke **every** active key in the org"*. The button's tooltip
said it *"revokes the current one"* and the dialog said *"the current one stops
working immediately"* — singular, both of them, and false since `298819e`.

**It matters more since #249, not less.** That phase narrowed the machine
endpoint (`POST /v1/keys/rotate`) so it replaces only the credential that
authenticated the call, precisely so that burning the whole estate stays a
deliberate human decision behind an admin session and an emailed code. The fix
therefore *leans on this dialog being where a human makes that choice informed*.
A dialog that understates what it destroys is the wrong thing to lean on.

Two things here a static diff review reads as correct:

* **The count must use the server's predicate, not the tile's.** `_rotate_org_key`
  selects `ApiKey.status == "active"` and nothing else. The KPI tile above the
  button counts `active && !expired`. Reusing the tile's number would understate
  the revocation by every expired-but-unrevoked row — the same class of error the
  sentence itself was — so the dialog counts `status === 'active'`.

* **A count that cannot be trusted must not be printed.** `_keysAll` is assigned
  only on a successful `GET /v1/keys`, so an empty list means *either* "no keys"
  *or* "the fetch failed" and the two are indistinguishable here. Printing `0`
  would read as "nothing will break", which is the understatement again wearing a
  number. The sentence drops the count and keeps the scope instead — the
  register's standing rule: say what the code does, or say you cannot tell.

The dialogs are DRIVEN, not grepped: `regenerateKey` is lifted out of the shipped
file and run under node against a `foxConfirm` stub that records what it was
asked to show. A static assertion proves a literal exists; it cannot prove which
branch produced it, and every interesting failure here is a branch.
"""

from __future__ import annotations

import json
import re
import subprocess
import tempfile
from functools import lru_cache
from pathlib import Path

import pytest

HTML = Path(__file__).resolve().parent / "foxy-audit-premium.html"


@lru_cache(maxsize=1)
def source() -> str:
    return HTML.read_text(encoding="utf-8")


@lru_cache(maxsize=1)
def markup() -> str:
    """Markup with HTML comments stripped — a comment explaining the old copy
    must not be able to satisfy a test looking for the new copy."""
    return re.sub(r"<!--.*?-->", " ", source(), flags=re.S)


# ══ the tooltip ═════════════════════════════════════════════════════════════
@lru_cache(maxsize=1)
def rotate_button() -> str:
    at = markup().index("onclick=\"regenerateKey()\"")
    return markup()[markup().rindex("<button", 0, at):markup().index("</button>", at)]


def test_the_button_tooltip_names_the_whole_workspace():
    tip = re.search(r'data-tip="([^"]*)"', rotate_button())
    assert tip, "the Rotate API key button lost its tooltip"
    text = tip.group(1)
    assert "revokes the current one" not in text.lower(), (
        f"the tooltip is singular again on the button that burns the estate: "
        f"{text!r}")
    assert "every active key" in text.lower(), (
        f"the tooltip does not say the rotation is workspace-wide: {text!r}")
    assert "workspace" in text.lower(), (
        f"the tooltip does not say whose keys: {text!r}")


# ══ the dialogs, driven ═════════════════════════════════════════════════════
_HARNESS = r"""
const shown = [];
global.window = {};
global._keysAll = KEYS_JSON;
global.foxConfirm = async function(o){
  shown.push({title:o.title||"", body:o.body||"", confirm:o.confirm||"", danger:!!o.danger});
  // first dialog -> proceed; second (the code entry) -> abort, we only want its copy
  return shown.length === 1 ? true : null;
};
global.api = async function(){ return {ok:true, json:async()=>({}), status:200}; };
global.errText = async function(){ return ""; };
global.toast = function(){};
global.revealSecret = function(){};
global.loadKeys = function(){};
REGENERATE_SOURCE
window.regenerateKey().then(function(){
  console.log(JSON.stringify(shown));
}).catch(function(e){
  console.log(JSON.stringify({error:String(e), shown:shown}));
});
"""


@lru_cache(maxsize=1)
def regenerate_source() -> str:
    """`window.regenerateKey` exactly as it ships, from `window.` to its `};`,
    with JS comments STRIPPED.

    The comments in it quote the copy they replaced, on purpose. Left in, they
    would both satisfy a test hunting the new wording and trip the test banning
    the old one — the same trap this file's own subject is an instance of."""
    src = source()
    start = src.index("window.regenerateKey=async function(){")
    end = src.index("\n  };", start) + len("\n  };")
    body = src[start:end]
    assert "regenerate/confirm" in body, "the extracted function is not the rotate flow"
    assert "foxConfirm(" in body, "the rotate flow no longer opens a dialog"
    body = re.sub(r"/\*.*?\*/", " ", body, flags=re.S)
    return re.sub(r"(?m)//.*$", "", body)


def _dialogs(keys: list[dict]) -> list[dict]:
    script = (_HARNESS
              .replace("KEYS_JSON", json.dumps(keys))
              .replace("REGENERATE_SOURCE", regenerate_source()))
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "run.js"
        path.write_text(script, encoding="utf-8")
        proc = subprocess.run(["node", str(path)], capture_output=True,
                              text=True, encoding="utf-8")
    assert proc.returncode == 0, proc.stderr
    out = json.loads(proc.stdout.strip().splitlines()[-1])
    assert isinstance(out, list), f"the flow threw: {out}"
    assert len(out) == 2, f"expected two dialogs, got {len(out)}: {out}"
    return out


def _active(n: int, **extra) -> list[dict]:
    return [dict(status="active", **extra) for _ in range(n)]


#: (label, _keysAll, the phrase the first dialog must contain)
_COUNT_CASES = [
    ("list never loaded / the fetch failed", [],
     "every active key in this workspace is revoked"),
    ("one active key", _active(1),
     "the 1 active key in this workspace is revoked"),
    ("four active keys", _active(4),
     "all 4 active keys in this workspace are revoked"),
    ("two active among revoked", _active(2) + [{"status": "revoked"}] * 3,
     "all 2 active keys in this workspace are revoked"),
    ("everything already revoked", [{"status": "revoked"}] * 2,
     "every active key in this workspace is revoked"),
    # ⚠ THE SERVER'S PREDICATE, NOT THE TILE'S. `_rotate_org_key` filters on
    # status alone, so an expired-but-unrevoked row IS revoked and must be
    # counted. The KPI tile drops it; borrowing that number would understate the
    # blast radius by exactly the rows nobody is thinking about.
    ("an expired key still counts", _active(1) + _active(1, expired=True),
     "all 2 active keys in this workspace are revoked"),
]


@pytest.mark.parametrize("label,keys,phrase",
                         _COUNT_CASES, ids=[c[0] for c in _COUNT_CASES])
def test_the_first_dialog_states_the_scope_it_can_back(label, keys, phrase):
    first = _dialogs(keys)[0]
    assert phrase in first["body"], (
        f"[{label}] the dialog does not state its real scope.\n"
        f"  body: {first['body']!r}\n  expected to contain: {phrase!r}")
    assert "all 0" not in first["body"], (
        f"[{label}] the dialog printed a zero count, which reads as 'nothing "
        f"will break': {first['body']!r}")
    assert "the current one" not in first["body"].lower(), (
        f"[{label}] the singular claim is back: {first['body']!r}")
    assert first["danger"], "the org-wide rotation lost its danger styling"


def test_the_first_dialog_title_asks_the_question_the_action_actually_poses():
    title = _dialogs(_active(3))[0]["title"]
    assert "rotate your api key?" != title.lower(), (
        "the title still asks about one key")
    assert "every" in title.lower() and "workspace" in title.lower(), (
        f"the title does not name the scope: {title!r}")


def test_the_second_dialog_is_where_the_estate_burns_and_says_so():
    """The code-entry step is the point of commitment — its button used to say
    'Rotate key', naming a single-key act on the control that performs the
    org-wide one."""
    second = _dialogs(_active(3))[1]
    assert second["confirm"].lower() != "rotate key", (
        "the confirming button still names a single-key rotation")
    assert "revoke" in second["confirm"].lower(), (
        f"the confirming button does not name what it destroys: "
        f"{second['confirm']!r}")
    assert "every active key" in second["body"].lower(), (
        f"the last screen before the estate burns does not say so: "
        f"{second['body']!r}")


def test_no_singular_rotation_claim_survives_anywhere_in_the_flow():
    """The half that makes a partial revert die loudly instead of quietly."""
    flow = regenerate_source() + " " + rotate_button()
    for retired in ("revokes the current one",
                    "the current one stops working",
                    "Anything still using the old key"):
        assert retired not in flow, (
            f"the retired singular copy is back: {retired!r}")
