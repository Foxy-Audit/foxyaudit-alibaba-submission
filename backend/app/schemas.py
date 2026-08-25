"""Pydantic request/response models.

Note: org_id is intentionally NOT in LogIngest — it is derived server-side from
the Bearer API key, so a client can never spoof another tenant's id.
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator, model_validator

# The typed spelling of a policy tag, and nothing else.
#
# DELIBERATELY NARROWER THAN `agent`, which admits dot, colon and slash: those
# are the punctuation of paths, URIs and namespaced identifiers — the shapes
# real-world content travels in — and none of them can survive the fold below
# anyway, so admitting them would only widen what a rejection message has to
# quote. What is left is what a human actually types as a TAG: any case, and
# the three separators they reach for.
#
# NO ANCHORS, AND MATCHED WITH fullmatch. In Python re, "$" also matches
# just before a TRAILING NEWLINE, so an anchored pattern accepted
# "hipaa" + newline — and the .strip() below then folded that to a clean
# "hipaa" which equalled policy_tag. A log-injection carrier would have
# chained. pydantic Field(pattern=...) does NOT share this: it compiles
# with the Rust engine, where "$" is end of input, so policy_tag itself
# was never exposed (checked). Caught by the charset test, not by review.
_RAW_TAG_PATTERN = re.compile(r"[A-Za-z0-9 _-]{1,64}")
# One separator in, one underscore out. NOT a run-collapsing `+`: policy_tag
# permits a doubled underscore, so collapsing runs would reject a raw tag that
# is character-for-character identical to the canonical one.
_RAW_TAG_SEPARATORS = re.compile(r"[ -]")


def canonical_policy_tag(raw: str) -> str:
    """Fold a typed tag into the spelling `policy_tag` is charset-locked to."""
    return _RAW_TAG_SEPARATORS.sub("_", raw.strip().lower())


class LogIngest(BaseModel):
    prompt_hash: str = Field(min_length=64, max_length=64)
    response_hash: str = Field(min_length=64, max_length=64)
    token_count: int = Field(ge=0, le=10_000_000)
    policy_tag: str = Field(pattern=r"^[a-z0-9_]{1,32}$")
    pii_signals: list[str] | None = None
    # which model produced it (6B); charset-locked (like policy_tag) so it's safe
    # to render raw and can't smuggle HTML/delimiters into the chain blob.
    agent: str | None = Field(default=None, max_length=128,
                              pattern=r"^[A-Za-z0-9_.\-: /]{1,128}$")
    event_id: uuid.UUID | None = None
    client_id: str | None = Field(default=None, max_length=128,
                                  pattern=r"^[A-Za-z0-9_.:-]{1,128}$")
    client_seq: int | None = Field(default=None, ge=1)
    event_type: str = Field(default="interaction", pattern=r"^[a-z0-9_]{1,32}$")
    commitment_alg: str = Field(default="sha256-legacy", pattern=r"^[a-z0-9-]{1,32}$")
    event_metadata: dict[str, Any] | None = None
    occurred_at: datetime | None = None

    @field_validator("event_metadata")
    @classmethod
    def _metadata_is_content_blind(cls, value):
        if value is None:
            return value
        allowed = {"request_id", "trace_id", "session_id", "provider", "model",
                   "id", "usage", "choice_count", "tool_names", "retrieval_refs",
                   "client_seq_gap",
                   # Host-side enforcement labels (blocked/redacted events). These
                   # are content-blind: an allowed|blocked|redacted decision, a short
                   # blocked_reason label, and the list of policy rule ids that fired.
                   "decision", "blocked_reason", "policy_rules",
                   # Ruleset provenance (SDK >= 1.7.0), sent only alongside
                   # policy_rules. Two short strings naming WHICH FROZEN RULE
                   # DEFINITIONS produced those ids, so an auditor can establish
                   # what `injection.ignore_previous` meant on the day it matched
                   # rather than taking our word for it. Content-blind by
                   # construction: the hash is over the SDK's own rule
                   # definitions and never over anything derived from a prompt.
                   #
                   # THIS LINE MUST BE DEPLOYED BEFORE ANY SDK SENDS IT. The
                   # validator rejects the whole REQUEST — `payload: List[LogIngest]`
                   # is validated as one unit — so an upgraded SDK talking to a
                   # backend without it loses the ENTIRE BATCH to a 422, on
                   # exactly the guarded events that matter most. The SDK
                   # degrades on its side as well (it retries once without these
                   # keys and records that it did), but that is a safety net for
                   # self-hosted and lagging deployments, not a licence to ship
                   # the two halves in the wrong order.
                   "ruleset_version", "ruleset_hash",
                   # The policy tag AS THE CALLER TYPED IT (SDK >= 1.13.0),
                   # sent only when normalisation changed it. `policy_tag`
                   # above is charset-locked to ^[a-z0-9_]{1,32}$, so
                   # `policy="HIPAA"` cannot travel as itself: the SDK folds
                   # it to the canonical tag and preserves the typed form
                   # here, so an auditor can see that the `hipaa` rules ran
                   # because a developer wrote `HIPAA`. Before this key the
                   # miscased call was chained as `default` and the typed
                   # form was lost.
                   #
                   # "Content-blind by construction" was doing too much work
                   # here on its own: it IS a decorator argument rather than
                   # anything derived from a prompt, but `policy=` takes any
                   # runtime string, and the 256-char cap this comment used to
                   # lean on bounds a LENGTH, not a vocabulary. What bounds it
                   # is _typed_tag_is_bounded_and_is_the_same_tag below: a tag
                   # charset, and the fold back to this row's own policy_tag.
                   #
                   # SAME DEPLOY ORDER AS THE TWO KEYS ABOVE, for the same
                   # reason: the whole REQUEST is rejected, so an SDK sending
                   # this to a backend without it loses the entire batch.
                   "policy_tag_raw"}
        unknown = set(value) - allowed
        if unknown:
            raise ValueError("event_metadata contains unsupported fields")
        for key, item in value.items():
            values = item if isinstance(item, list) else [item]
            if len(values) > 64 or any(len(str(v)) > 256 for v in values):
                raise ValueError(f"event_metadata.{key} is too large")
        return value

    @model_validator(mode="after")
    def _typed_tag_is_bounded_and_is_the_same_tag(self):
        """`policy_tag_raw` carries a SPELLING, never information of its own.

        Two rules, and the ledger needs both. `policy_tag` and `agent` — the
        only other caller-chosen fields — are pattern-locked; this key was 256
        characters of anything, persisted and CHAIN-BOUND, so
        `policy=f"hipaa-{mrn}"` wrote a patient identifier into a hash chain
        that by design cannot be edited afterwards. Rejecting at ingest is the
        only place it can be stopped: after the append there is no fix, only a
        disclosure.

        The equality is the part that actually bounds it. A charset alone still
        admits `hipaa-MRN-4417829`; requiring the fold to equal the canonical
        tag means the raw form can differ from `policy_tag` ONLY in case and in
        which separator was typed. It therefore carries no information the
        chain does not already hold — which is what "bounded metadata" has to
        mean if the phrase is doing any work.

        Second rule, second failure it closes: nothing checked that the typed
        tag was a spelling of THIS row's tag. `policy_tag="hipaa"` with
        `policy_tag_raw="PCI"` ingested and chained happily, and — because the
        duplicate-content comparison in logs.py pops this key — a resend
        carrying an entirely different typed tag was a 202 duplicate rather
        than a 409. That comparison's comment claims only two SPELLINGS of one
        canonical tag can compare equal. This validator is what makes the claim
        true; without it, it was merely a hope.

        A tag that cannot satisfy this is refused rather than trimmed: silently
        storing something other than what the caller typed would put a
        fabricated spelling in the evidence.

        BOTH MESSAGES BEGIN WITH THE PHRASE THE SDK PROBES FOR, and that is
        load-bearing rather than cosmetic. `payload: List[LogIngest]` validates
        as ONE unit, so one bad typed tag 422s the whole request;
        dispatch._rejects_unsupported_fields matches the substring "unsupported
        fields" to decide whether to strip and retry. A message without it makes
        the probe return False, no retry fires, raise_for_status raises, and
        spool.retry re-queues the entire batch — forever. That is the evidence
        outage the pop in logs.py and the warning at client.py:1169 exist to
        prevent, arriving through the rejection door instead of the duplicate
        one.

        Reusing the existing phrase rather than minting a second one: the remedy
        is identical (drop policy_tag_raw, resend), S13 already has to put the
        key in ruleset.PROVENANCE_KEYS for the duplicate half, and a phrase only
        the backend knows would be the worst of the three options. The specific
        reason follows the colon so a human is not left guessing.
        """
        raw = (self.event_metadata or {}).get("policy_tag_raw")
        if raw is None:
            return self
        # The value is never echoed back. An error body is a place caller text
        # can escape to — logs, proxies, a dashboard toast — and this key exists
        # precisely because callers put unexpected things in it.
        if not isinstance(raw, str) or not _RAW_TAG_PATTERN.fullmatch(raw):
            raise ValueError("event_metadata contains unsupported fields: "
                             "policy_tag_raw is not a tag spelling")
        if canonical_policy_tag(raw) != self.policy_tag:
            raise ValueError("event_metadata contains unsupported fields: "
                             "policy_tag_raw is not a spelling of policy_tag")
        return self

    @field_validator("prompt_hash", "response_hash")
    @classmethod
    def _must_be_hex(cls, v: str) -> str:
        v = v.lower()
        int(v, 16)  # raises ValueError on non-hex → 422 (never a corrupt row)
        return v


class Verdict(BaseModel):
    policy_breach: bool = False
    reason: str = ""
    risk_score: int = Field(default=0, ge=0, le=100)
    # clean|breach|unknown are AI-judge outcomes; blocked|redacted|response_blocked
    # are terminal host-side enforcement outcomes decided locally (nothing to grade).
    # response_blocked is a response the SDK withheld from the calling application
    # — see policy_engine.ENFORCEMENT_EVENT_TYPES for why it is not `blocked`.
    decision: str = Field(
        default="unknown",
        pattern=r"^(clean|breach|unknown|blocked|redacted|response_blocked)$")
    rules: list[str] = Field(default_factory=list)

    # P6f provenance: WHICH model produced this grade. A model id is not a secret;
    # a provider key is, and none is ever recorded here — see judge_routing.py:1-8.
    #
    # This is the right home for it because THIS verdict is not hashed chain
    # material. Since chain version 4 the line runs between two verdicts, not
    # around all of them:
    #
    #   audit_logs.local_verdict — the deterministic verdict policy_engine
    #     decides synchronously at ingest. Its digest IS bound: V4 puts
    #     `verdict_hash` in the hashed event (chain.py), so editing that verdict
    #     in the database now breaks the chain.
    #   audit_logs.gemini_verdict — this model's grade, the one carrying the
    #     provenance below. NOT bound, and cannot be: the chain hash is fixed at
    #     ingest (routers/logs.py) and this grade does not exist yet — the worker
    #     adds it asynchronously, with an UPDATE that never touches chain_hash.
    #     Binding it would mean re-hashing the row after grading, invalidating
    #     every block after it, or waiting on an LLM inside ingest.
    #
    # So the chain binds what the system DECIDED, deterministically; the AI grade
    # stays advisory metadata beside it. Note the contrast with event_metadata,
    # which has been hashed since V2 — putting the model there would have
    # invalidated every existing chain.
    #
    # Both stay None unless a model actually answered. An evaluator that never ran
    # (no key, timeout) records nothing rather than naming a model it did not call.
    # Set at the single point of truth: the judge module that made the call.
    # Multi-judge runs comma-join both fields in the same order, matching how
    # `reason` already merges (judge.combine).
    judge_provider: str | None = None
    judge_model: str | None = None


class LogResponse(BaseModel):
    log_id: uuid.UUID
    seq: int
    chain_hash: str
    status: str = "pending"          # "pending" | "graded"
    verdict: Verdict | None = None


class LastAnchor(BaseModel):
    """The org's most recent public-chain anchor (Phase 3 A1), if any."""
    chain: str
    status: str
    root_hash: str
    last_seq: int
    tx_hash: str | None = None
    block_number: int | None = None
    anchored_at: str | None = None
    # True when the anchored root still matches a fresh recompute of the chain up
    # to last_seq — i.e. nothing before the anchor point was tampered with.
    matches_current_chain: bool | None = None


class VerifyResponse(BaseModel):
    ok: bool
    count: int
    first_broken_seq: int | None = None
    detail: str | None = None
    last_anchor: LastAnchor | None = None


class CoverageGap(BaseModel):
    """A client-reported sequence range that was not observed by Foxy."""

    start: int
    end: int
    count: int


class CoverageClient(BaseModel):
    """Content-blind capture continuity for one SDK client identity."""

    client_id: str
    events: int
    first_client_seq: int
    last_client_seq: int
    server_seq_start: int
    server_seq_end: int
    last_seen_at: datetime | None = None
    missing_ranges: list[CoverageGap] = Field(default_factory=list)
    duplicate_client_sequences: list[int] = Field(default_factory=list)


class CoverageResponse(BaseModel):
    """Evidence coverage, not a claim that every model call was captured."""

    status: Literal["verified", "partial", "unknown"]
    scope: str
    message: str
    total_events: int
    identified_events: int
    events_without_client_identity: int
    instrumented_clients: int
    clients_with_anomalies: int
    missing_events: int
    duplicate_client_sequences: int
    chain_verified: bool | None
    chain_verification: Literal["verified", "failed", "not_checked"]
    chain_detail: str
    last_event_at: datetime | None = None
    clients: list[CoverageClient] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class LogListItem(BaseModel):
    """One row returned by GET /v1/logs."""
    id: uuid.UUID
    seq: int
    event_id: uuid.UUID | None = None
    client_id: str | None = None
    client_seq: int | None = None
    event_type: str | None = None
    commitment_alg: str | None = None
    event_metadata: dict[str, Any] | None = None
    occurred_at: datetime | None = None
    chain_version: int = 1
    prompt_hash: str
    response_hash: str
    token_count: int
    policy_tag: str
    agent: str | None = None
    pii_signals: list[str] | None = None
    chain_hash: str
    # Both carried for the same reason _EXPORT_COLS carries them: from
    # chain_version 4 `verdict_hash` is hashed material, so a row without it
    # cannot be recomputed by anything reading this route.
    verdict_hash: str | None = None
    local_verdict: dict[str, Any] | None = None
    gemini_verdict: dict[str, Any] | None = None
    grading_status: str = "pending"
    created_at: datetime

    class Config:
        from_attributes = True


class LogListResponse(BaseModel):
    items: list[LogListItem]
    total: int
    page: int
    limit: int


# ── dashboard stats (GET /v1/stats) ──
class GradingCounts(BaseModel):
    pending: int = 0
    in_progress: int = 0
    graded: int = 0
    failed: int = 0


class ActivityDay(BaseModel):
    date: str            # YYYY-MM-DD
    count: int
    breaches: int


class StatsResponse(BaseModel):
    total_logged: int
    breaches: int
    clean_rate: float | None     # percent, 0-100; None when no determinate grades exist
    avg_token_count: float
    judge_model: str             # the real configured Gemini judge model
    avg_seconds_to_verdict: float | None   # avg graded_at - created_at; None if none graded
    grading: GradingCounts
    activity_7d: list[ActivityDay]
    evaluator_unknown: int = 0
    # Host-side enforcement (prevented egress), counted separately from breaches.
    blocked: int = 0
    redacted: int = 0
    # A model response the SDK withheld from the calling application. Its own
    # count, not folded into `blocked`: that one means prompts stopped before
    # they reached a provider, and here the provider was called.
    response_blocked: int = 0

