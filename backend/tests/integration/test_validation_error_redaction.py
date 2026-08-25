"""A 422 says WHICH field failed and WHY — never what the value was.

FastAPI's default RequestValidationError handler puts the rejected value in each
error as ``input``; for a list body that is the WHOLE item. It lands in the
response body, the proxy access log, and any dashboard toast that renders
``detail``.

THE ECHO IS OLD; THE EXPOSURE IS NEW. It was harmless for as long as every field
it could reflect was bounded — charset-locked tags, fixed-length hashes, an
allowlisted metadata dict. `policy_tag_raw` (S12) is the first field whose value
can carry content AT THE MOMENT IT IS REJECTED, which is the only moment that
matters: a validator runs precisely because something got that far.

So the fix is general rather than a special case for that one field. These tests
are about the handler, not about the tag — a field added to this API next year
inherits the property instead of having to remember it.
"""

from __future__ import annotations

import uuid

import pytest
from fastapi.exceptions import RequestValidationError

from app.main import admin_api, customer_api

SECRET = "MRN-4417829"


def _event(**overrides):
    event = {
        "event_id": str(uuid.uuid4()),
        "prompt_hash": "a" * 64,
        "response_hash": "c" * 64,
        "token_count": 0,
        "policy_tag": "hipaa",
        "event_type": "blocked",
        "pii_signals": ["phi"],
        "event_metadata": {"decision": "blocked",
                           "policy_rules": ["phi.ssn_pattern"]},
    }
    event.update(overrides)
    return event


@pytest.mark.parametrize("field,event", [
    # the field that made this urgent: a typed tag carrying an identifier
    ("policy_tag_raw",
     _event(event_metadata={"decision": "blocked", "policy_rules": [],
                            "policy_tag_raw": "hipaa-" + SECRET})),
    # a metadata VALUE over the size cap — rejected by the allowlist validator
    ("oversized value",
     _event(event_metadata={"decision": "blocked", "policy_rules": [],
                            "trace_id": SECRET + "-" + "v" * 300})),
    # a metadata KEY nobody allowlisted, whose value is the payload
    ("unknown key",
     _event(event_metadata={"decision": "blocked", "policy_rules": [],
                            "patient_note": SECRET})),
    # a top-level field failing its own pattern
    ("client_id", _event(client_id="patient " + SECRET)),
    # A FIELD-LEVEL constraint rather than a validator, because the two echo
    # different things and both had to be covered: a model or metadata validator
    # reflects the whole item or dict, while a Field(pattern=...) reflects just
    # that field's value. (Measured, not assumed — a first draft of this row
    # used a bad prompt_hash with the secret in a NEIGHBOURING field, and it
    # could never fail: that error's `input` is only the 64 bad characters.)
    ("commitment_alg", _event(commitment_alg="hmac-" + SECRET)),
])
def test_no_rejected_value_is_echoed_back(make_org, client, field, event):
    """One case per validator that can fire, because the handler is shared.

    Parametrised across DIFFERENT validators on purpose: the point is that the
    property belongs to the error handler, so it must hold no matter which
    check rejected the request.
    """
    org = make_org()
    response = client.post("/v1/logs/batch", headers=org["auth"], json=[event])
    assert response.status_code == 422, response.text
    assert SECRET not in response.text, f"{field}: the 422 echoed the value"


def test_the_422_still_says_which_field_and_why(make_org, client):
    """CONTROL. Redacting everything would satisfy the test above and leave a
    developer with an unactionable error.

    `loc` and `msg` are kept deliberately; only `input` and `ctx` are dropped.
    """
    org = make_org()
    bad = _event(event_metadata={"decision": "blocked", "policy_rules": [],
                                 "patient_note": SECRET})
    response = client.post("/v1/logs/batch", headers=org["auth"], json=[bad])

    detail = response.json()["detail"]
    assert detail, "the 422 carried no detail at all"
    assert "unsupported fields" in detail[0]["msg"]
    # The failing FIELD survives, not just the item index — this is what makes
    # the redacted error still actionable.
    assert detail[0]["loc"] == ["body", 0, "event_metadata"]


def test_ctx_is_dropped_too(make_org, client):
    """`ctx` is the second door: pydantic puts the offending value there for
    several error types, so keeping it would have left the leak half-open."""
    org = make_org()
    response = client.post("/v1/logs/batch", headers=org["auth"],
                           json=[_event(client_id="patient " + SECRET)])
    assert response.status_code == 422
    assert all(set(error) <= {"type", "loc", "msg"}
               for error in response.json()["detail"]), response.text


def test_both_apps_carry_the_handler():
    """The admin API takes bodies through the same mechanism.

    Staff input is not safer input — an operator pastes a customer identifier
    into a form. Asserted rather than assumed, because registering it on one app
    and not the other is a one-line omission that nothing else would catch.
    """
    for app in (customer_api, admin_api):
        assert RequestValidationError in app.exception_handlers, app.title
