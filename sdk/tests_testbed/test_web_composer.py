"""The composer's send lock, exercised by RUNNING the page's own script.

⚠ WHY THIS RUNS THE REAL SCRIPT INSTEAD OF GREPPING FOR THE FIX. The defect
these guards exist for was that ``send()`` was locked at one entrance and not the
other: the button was disabled, and Ctrl+Enter called ``send()`` directly without
ever looking at it. Three rapid presses ran three turns for one prompt, which on
a live provider is three billed calls.

A source guard for that reads ``assert "state.inFlight" in PAGE`` -- which is the
implementation restated, green the moment somebody writes the flag and forgets to
check it in the keydown path. The only assertion that means anything is the
count of requests, so the script is loaded into a minimal DOM under node and the
keys are actually pressed.

The DOM stub covers only what the script touches up to the moment it posts:
``/turn`` is answered with a promise that never settles, so ``renderTurn`` is
never reached and the record template does not have to be modelled. That is the
whole trick that keeps this harness small enough to trust.
"""

from __future__ import annotations

import json
import pathlib
import re
import shutil
import subprocess

import pytest

from foxy_testbed import web

PAGE_PATH = pathlib.Path(web.__file__).parent / web.PAGE_FILENAME
PAGE_SOURCE = PAGE_PATH.read_text(encoding="utf-8")

NODE = shutil.which("node")

# A DOM with exactly the surface the page script uses before its first POST.
HARNESS = r"""
'use strict';
var CALLS = [];

function makeClassList(node) {
  var set = {};
  return {
    toggle: function (name, force) {
      if (force === undefined) { force = !set[name]; }
      if (force) { set[name] = true; } else { delete set[name]; }
    },
    contains: function (name) { return Boolean(set[name]); }
  };
}

function makeNode(tag) {
  var node = {
    tagName: tag, children: [], listeners: {}, attributes: {},
    textContent: '', className: '', value: '', type: '', name: '',
    disabled: false, checked: false, selected: false
  };
  node.classList = makeClassList(node);
  node.appendChild = function (child) { node.children.push(child); return child; };
  node.removeChild = function (child) {
    var i = node.children.indexOf(child);
    if (i >= 0) { node.children.splice(i, 1); }
    return child;
  };
  node.insertBefore = function (child, ref) {
    var i = ref ? node.children.indexOf(ref) : -1;
    if (i < 0) { node.children.unshift(child); } else { node.children.splice(i, 0, child); }
    return child;
  };
  node.addEventListener = function (name, fn) {
    (node.listeners[name] = node.listeners[name] || []).push(fn);
  };
  node.setAttribute = function (k, v) { node.attributes[k] = v; };
  node.getAttribute = function (k) { return node.attributes[k]; };
  node.focus = function () {};
  node.fire = function (name, event) {
    (node.listeners[name] || []).forEach(function (fn) { fn(event); });
  };
  Object.defineProperty(node, 'firstChild', {
    get: function () { return node.children[0] || null; }
  });
  return node;
}

var BY_ID = {};
__IDS__.forEach(function (id) { BY_ID[id] = makeNode('div'); });

var document = {
  getElementById: function (id) {
    if (!BY_ID[id]) { throw new Error('the page asked for an unmodelled id: ' + id); }
    return BY_ID[id];
  },
  createElement: function (tag) { return makeNode(tag); },
  createTextNode: function (text) { var n = makeNode('#text'); n.textContent = text; return n; }
};
var window = { addEventListener: function () {} };

var SESSION = __SESSION__;
var SETTLE_SESSION = __SETTLE_SESSION__;

function fetch(url, options) {
  CALLS.push({ url: url, body: options && options.body });
  if (String(url).indexOf('/session') >= 0) {
    if (!SETTLE_SESSION) { return new Promise(function () {}); }
    return Promise.resolve({ ok: true, json: function () { return Promise.resolve(SESSION); } });
  }
  // Never settles: the request is what is being counted, and leaving it in
  // flight is also the state the lock is supposed to hold.
  return new Promise(function () {});
}

__PAGE_SCRIPT__

function pressCtrlEnter() {
  BY_ID.prompt.fire('keydown', {
    ctrlKey: true, metaKey: false, key: 'Enter', preventDefault: function () {}
  });
}

// One turn of the microtask queue lets the /session promise chain finish.
setTimeout(function () {
  BY_ID.prompt.value = 'Confirm coverage for member SSN 900-12-3456.';
  pressCtrlEnter();
  pressCtrlEnter();
  pressCtrlEnter();
  setTimeout(function () {
    var turns = CALLS.filter(function (c) { return String(c.url).indexOf('/turn') >= 0; });
    console.log(JSON.stringify({
      turnRequests: turns.length,
      sessionRequests: CALLS.length - turns.length,
      sendDisabled: BY_ID.send.disabled,
      promptDisabled: BY_ID.prompt.disabled,
      problemText: BY_ID.problem.children.map(function (c) { return c.textContent; }).join('')
    }));
  }, 0);
}, 0);
"""


def _page_script() -> str:
    scripts = re.findall(r"<script\b[^>]*>(.*?)</script>", PAGE_SOURCE, re.S)
    assert len(scripts) == 1, len(scripts)
    return scripts[0]


def _ids(page: str) -> list:
    """Every id the page declares, so the stub models exactly the real set.

    Derived from the markup rather than hand-listed: a stub whose element set
    drifts from production tests a page that does not exist, and this repo has
    shipped a shim whose host had no id so 45 guards exercised a fallback the
    real page never takes.
    """
    return sorted(set(re.findall(r'\bid="([a-z0-9-]+)"', page)))


def run_page(page: str, settle_session: bool = True) -> dict:
    """Load ``page``'s script into the stub DOM and press Ctrl+Enter three times."""
    session = {
        "bind": "127.0.0.1:8787",
        "modes": list(web.MODES),
        "mode": "block",
        "provider": {"name": "mock", "model": "mock-fixture-1",
                     "is_live": False, "note": "fixtures"},
        "sectors": [{"name": "healthcare", "title": "t", "policy_tag": "hipaa",
                     "policy_note": "n", "probes": []}],
    }
    scripts = re.findall(r"<script\b[^>]*>(.*?)</script>", page, re.S)
    harness = (HARNESS
               .replace("__IDS__", json.dumps(_ids(page)))
               .replace("__SESSION__", json.dumps(session))
               .replace("__SETTLE_SESSION__", "true" if settle_session else "false")
               .replace("__PAGE_SCRIPT__", scripts[0]))
    completed = subprocess.run(
        [NODE, "--input-type=commonjs", "-e", harness],
        capture_output=True, text=True, encoding="utf-8", timeout=60)
    assert completed.returncode == 0, completed.stderr[:2000]
    return json.loads(completed.stdout.strip().splitlines()[-1])


@pytest.fixture(autouse=True)
def _needs_node():
    if NODE is None:
        pytest.skip("node is not installed, so the send lock is UNVERIFIED here")


def test_three_rapid_ctrl_enters_send_one_turn():
    """⚠ THE DEFECT, RE-RUN. Three presses used to post three times.

    Only the button was disabled, and Ctrl+Enter does not go through the button.
    On the mock provider that is a confusing transcript; on a live one it is
    three billed calls for one prompt.
    """
    result = run_page(PAGE_SOURCE)
    assert result["turnRequests"] == 1, result
    assert result["sendDisabled"] is True, result


def test_the_harness_would_have_caught_the_old_behaviour():
    """⚠ THE HARNESS PROVES ITSELF, or it proves nothing.

    A test that presses three keys and sees one request is equally green against
    a page that ignores every press. So the flag check is removed from the
    keydown path and the SAME harness must report three -- which is the count the
    reported defect produced by hand.
    """
    without_lock = PAGE_SOURCE.replace("    if (state.inFlight) { return; }\n", "", 1)
    assert without_lock != PAGE_SOURCE, "the in-flight gate moved; re-aim this guard"
    result = run_page(without_lock)
    assert result["turnRequests"] == 3, result


def test_nothing_is_sent_before_the_session_answers():
    """The composer is dead until the rail is built.

    Sending during the bootstrap posted ``sector: ""`` and came back 400 "unknown
    sector" -- an error naming a control the user had never touched. Both halves
    are checked: no request goes out, and the controls are visibly disabled
    rather than merely inert.
    """
    result = run_page(PAGE_SOURCE, settle_session=False)
    assert result["turnRequests"] == 0, result
    assert result["sendDisabled"] is True
    assert result["promptDisabled"] is True


def test_the_composer_is_disabled_in_the_markup_too():
    """Before the script runs at all, not merely after it decides.

    A textarea that accepts typing it cannot send is worse than one that plainly
    waits, and the window between parse and first paint is exactly when someone
    clicks into it.
    """
    markup = PAGE_SOURCE.split("</script>", 1)[0]
    textarea = re.search(r"<textarea[^>]*>", markup).group(0)
    send = re.search(r'<button class="send"[^>]*>', markup).group(0)
    assert "disabled" in textarea, textarea
    assert "disabled" in send, send


def test_a_bootstrap_failure_does_not_claim_a_turn_failed():
    """``problem()`` was one sentence for two failures.

    A server that never answered ``/session`` reported "Could not run that turn."
    over an empty transcript, before anything had been sent.
    """
    script = _page_script()
    assert 'problem("Could not reach the testbed server."' in script
    assert 'problem("Could not run that turn."' in script
    # And the lead is a parameter rather than a constant inside the function.
    assert re.search(r"function problem\(\s*lead\s*,\s*text\s*\)", script)
