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
                   "policy_tag_raw",
                   # WHICH of the customer's declared AI systems produced this
                   # event (R2) — the id of an `ai_systems` row an admin
                   # registered through POST /v1/systems. Optional at every
                   # layer: an event that omits it is byte-for-byte the event
                   # this backend accepted yesterday.
                   #
                   # Content-blind, and for a stronger reason than any key
                   # above: it is not derived from the interaction at all. It
                   # names a DECLARATION the customer already made to us about
                   # their own estate, so it puts nothing in the ledger that the
                   # ledger could not already join to.
                   #
                   # ⚠ SHAPE HERE, OWNERSHIP IN routers/logs.py. This validator
                   # has no database, so all it can say is "that is the spelling
                   # of an id". Whether the id names a LIVE system belonging to
                   # THIS org is decided at ingest, where the org is known —
                   # `_validate_system_attributions`. Both refusals answer with
                   # the phrase below, for the reason the phrase exists.
                   #
                   # SAME DEPLOY ORDER AS THE THREE KEYS ABOVE, for the same
                   # reason: the whole REQUEST is rejected, so an SDK sending
                   # this to a backend without it loses the entire batch. R2
                   # deploys before R3 ships, and that is not negotiable.
                   #
                   # ⚠ AND THIS LIST ONLY EVER GROWS. The SDK's degrade ladder
                   # (dispatch._DEGRADE_LADDER) escalates one rung at a time on
                   # the assumption that the key sets a backend can refuse are
                   # NESTED — true only because a key is never taken away, so a
                   # backend that knows `system_id` necessarily knows the three
                   # above it. Adding a key keeps that true; removing one breaks
                   # a live SDK's retry logic, not just this contract.
                   "system_id"}
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

    @model_validator(mode="after")
    def _system_id_is_a_system_identifier(self):
        """`system_id` names a declared AI system, and spells it exactly one way.

        SHAPE ONLY. This class has no database, so all it can decide is whether
        the value is the spelling of an id; whether that id names a system that
        EXISTS, belongs to THIS org and is not RETIRED is decided in
        routers/logs.py, which has both the session and the org. The split is
        deliberate — the cheap refusal stays cheap, and the org filter stays
        next to the org.

        THE CANONICAL SPELLING, NOT MERELY "PARSES AS A UUID". `uuid.UUID` also
        accepts `{...}`, `urn:uuid:...`, and undashed or upper-case hex, so five
        different strings name one system. This value is CHAIN-BOUND — it rides
        in event_metadata, hashed since V2 — and it is what per-system reporting
        will group by, so five spellings of one id would be five chain hashes
        for one attribution and five systems on that surface.

        Refused rather than normalised, and that is the same rule
        `policy_tag_raw` is held to one validator above: silently storing
        something other than what the caller sent would put a spelling in the
        evidence that nobody typed. The caller already has the canonical form —
        it is what GET /v1/systems returned them.

        ⚠ THE VALUE IS NEVER QUOTED BACK. A rejection here is by definition a
        rejection of something that is NOT a UUID, so it can be any string the
        caller put there — the same echo `main._validation_error_handler` strips
        out of `input`, arriving through the message instead. The ownership
        refusals in routers/logs.py DO name the id, and may: by then it has
        passed this check and is provably 36 characters of hex and hyphens.

        THE PHRASE IS REUSED, for the reason the docstring above spells out at
        length — `dispatch._rejects_unsupported_fields` matches "unsupported
        fields" to decide whether to strip and retry, and a message only the
        backend knows means no retry, then `raise_for_status`, then
        `spool.retry` re-queuing the whole batch forever. The remedy is
        identical to the other rungs' (drop system_id, resend), so a second
        phrase would buy nothing and cost the spool.
        """
        # ⚠ ABSENT AND `null` ARE NOT THE SAME THING, so this asks whether the
        # KEY is there rather than whether `.get` came back None. An explicit
        # JSON null is a present key carrying a value that is not an id, and
        # reading it as "no attribution" would chain `{"system_id": null}` into
        # event_metadata: a row claiming the field while holding nothing, which
        # `_validate_system_attributions` then never looks at and per-system
        # reporting has to invent a meaning for. R1's `update_system` refuses an
        # explicit null one layer up for the same reason — Optional means
        # "omitted", and a null that is read as a default is a value nobody
        # chose. Absent is absent; anything present is judged.
        metadata = self.event_metadata or {}
        if "system_id" not in metadata:
            return self
        raw = metadata["system_id"]
        parsed = None
        if isinstance(raw, str):
            try:
                parsed = uuid.UUID(raw)
            except ValueError:
                parsed = None
        if parsed is None or str(parsed) != raw:
            raise ValueError("event_metadata contains unsupported fields: "
                             "system_id is not an AI system id")
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

    # ── #228 · WHO produced this verdict, stated positively ───────────────────
    #
    # Before this field the record answered that question only by ABSENCE. When no
    # provider key was reachable the judges returned an `evaluator_unavailable`
    # verdict and the worker REPLACED it wholesale with the deterministic rules
    # engine, so the stored row read `decision: "clean"` under a confident reason
    # and nothing anywhere said a model had never run. The single tell was
    # `judge_provider` being null INSIDE a JSON blob — a null a reader has to know
    # to look for, and one that is equally null on a row a judge answered badly. On
    # a product whose pitch is evidence, "an AI reviewed this" has to be
    # falsifiable FROM THE RECORD, so the record now names its author, always.
    #
    # A CLOSED VOCABULARY, and every producer sets it explicitly:
    #
    #   "ai"                a model answered and its answer was taken as the grade
    #                       (the gemini/openai success paths, and judge.combine,
    #                       which merges only verdicts a model actually returned)
    #   "rules"             policy_engine.evaluate — the deterministic metadata
    #                       engine. What the worker substitutes when no judge could
    #                       be reached, and what ingest decides synchronously
    #   "host_enforcement"  policy_engine.evaluate_enforcement — the host's own
    #                       blocked/redacted labels. Not a grade of a model
    #                       response; there was no model response
    #   "none"              NOTHING graded this row. Either the evaluator never ran
    #                       (a _fallback verdict) or it answered incoherently and
    #                       judge.validate refused the answer (_quarantine). Those
    #                       two stay distinguishable from each other by `reason`
    #                       (evaluator_unavailable: vs evaluator_unknown:) and by
    #                       judge_provider, which _quarantine deliberately keeps
    #
    # ⚠ `None` MEANS "NOT RECORDED", AND IS NOT A CLAIM. Rows graded before this
    # field existed carry null, and nothing backfills them: whether a model graded
    # a historical row is not something the ledger recorded, and deriving it now
    # and writing it down would be manufacturing evidence. It would also be unsafe
    # — `local_verdict` is hashed (chain.verdict_hash_hex), so rewriting one breaks
    # its row's verdict_hash. A reader gets three states, not two: graded by X,
    # graded by nothing, and not recorded.
    graded_by: str | None = Field(
        default=None, pattern=r"^(ai|rules|host_enforcement|none)$")

    # WHY no AI grade is on this row, when that is the case — the structured
    # reason, not a prefix parsed back out of `reason`.
    #
    # judge_routing already distinguishes these (`JudgeRouting.problems`:
    # no_byok_key, byok_encryption_unavailable, byok_key_undecryptable) and the
    # provider modules add their own (no_api_key, plus the exception TYPE for a
    # timeout / quota / transport failure). All of it used to reach `_fallback`,
    # be formatted into "evaluator_unavailable:<reason>", and then be discarded
    # whole the moment the worker swapped in the rules verdict.
    #
    # It rides through that substitution now, because "graded by rules" and
    # "graded by rules BECAUSE THIS TENANT'S BYOK KEY WOULD NOT DECRYPT" are
    # different facts and only the second is actionable by the customer reading
    # their own export.
    #
    # Set ONLY on a verdict that is not an AI grade. Never contains key material:
    # every value is a fixed label or an exception class name.
    evaluator_unavailable_reason: str | None = None


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
    # ⚠ DEPLOYMENT CONFIGURATION, NOT A CLAIM ABOUT ANY EVENT (#228). Derived
    # from whether this deployment holds platform provider keys, so it cannot
    # answer "was this org's traffic graded by a model" — which judge grades is a
    # per-tenant choice and a BYOK org on a keyless deployment is graded by a
    # model this string knows nothing about. The two counters below answer that
    # question, from the ledger.
    judge_model: str
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
    # ── #228 · authorship, counted from the RECORD ───────────────────────────
    # Over graded rows, how many carry a verdict a model actually produced and
    # how many carry a deterministic one. They do not have to sum to the graded
    # count: rows graded before `graded_by` existed are in neither, because the
    # ledger does not record who graded them and a count that guessed would be
    # the defect these fields exist to end. Read them beside `grading.graded`.
    ai_graded: int = 0
    rules_graded: int = 0

