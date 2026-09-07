"""Per-tenant AI Judge routing: which judge grades an org's events, on whose key.

Two independent choices per org, held on the LIVE OrgPolicy row (never on the
chain snapshot — routing is an operational/billing decision, not evidence):

  judge_provider  gemini | openai | both
  judge_key_mode  own (BYOK, the tenant's encrypted key) | platform (Foxy's keys)

``platform`` is a paid privilege, decided in ONE place —
:func:`platform_keys_allowed`. Which TIERS qualify is still a one-line change
(:data:`PLATFORM_KEY_TIERS`); since M4a the tier is no longer the whole test,
because ``premium`` is also what an evaluation offer sets. That function takes
the organisation and answers for three populations rather than one — read it
before changing who pays for grading.

The decision is re-made HERE, at grading time, against the org's live row. A
premium org that selects platform keys and later downgrades — or an evaluator
whose window shuts — therefore stops spending Foxy's key immediately: it falls
back to its own key, and with no own key the provider is simply skipped (an
honest ``evaluator_unavailable``), never silently billed to the platform.

Decrypted keys exist only inside the returned :class:`JudgeRouting`, for the
duration of one grading call. They are never logged, persisted, or serialised.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field

from sqlalchemy.orm import Session

from . import billing_state
from .config import get_settings
from .crypto_secrets import SecretDecryptionError, SecretsNotConfigured, decrypt_secret
from .models import OrgPolicy, Organization

log = logging.getLogger("foxy.judge_routing")

# The ONLY place the privileged tier set is defined. Orgs on any other tier
# (pro, free, trial, max, NULL, anything unknown) are BYOK-only.
PLATFORM_KEY_TIERS = {"premium"}

PROVIDERS = ("gemini", "openai", "qwen",
             "gemini+openai", "gemini+qwen", "openai+qwen", "all")
KEY_MODES = ("own", "platform")

DEFAULT_PROVIDER = "gemini"
DEFAULT_KEY_MODE = "own"

# Before Qwen, "both" meant gemini+openai. Map it at resolve time so existing
# orgs with judge_provider="both" keep grading exactly as before, and no DB
# migration or data rewrite is needed.
_PROVIDER_COMPAT = {"both": "gemini+openai"}

# Human-readable names for the admin UI. Every value in PROVIDERS must appear
# here; values not in this dict will render as their raw string.
JUDGE_PROVIDER_DISPLAY = {
    "gemini": "Gemini",
    "openai": "OpenAI",
    "qwen": "Qwen",
    "gemini+openai": "Gemini + OpenAI",
    "gemini+qwen": "Gemini + Qwen",
    "openai+qwen": "OpenAI + Qwen",
    "all": "Gemini + OpenAI + Qwen",
}

# Which model versions an org may pin, per provider (P6f). One constant, in the
# same spirit as PLATFORM_KEY_TIERS above: adding a model is a one-line change.
#
# The DEPLOYMENT DEFAULT IS NOT LISTED HERE and is not required to be. It comes
# from settings.gemini_model / settings.openai_model and is always allowed, so a
# deployment can move to a model this list has not heard of without anyone having
# to edit it first. That ordering matters — the operator's setting outranks a
# constant in source.
JUDGE_MODELS = {
    "gemini": ("gemini-2.5-flash", "gemini-2.5-pro", "gemini-2.0-flash"),
    "openai": ("gpt-5.6", "gpt-5.6-mini", "chat-latest"),
    "qwen": ("qwen-plus", "qwen3.5-plus"),
}

# Map each single provider to its Settings field for the deployment default.
# allowed_models / resolve_model read through this so adding a provider is one
# line here + one line in JUDGE_MODELS, not a new branch in every function.
_PROVIDER_DEFAULT_ATTR = {
    "gemini": "gemini_model",
    "openai": "openai_model",
    "qwen": "qwen_model",
}


def _default_model(provider: str) -> str:
    """The deployment-default model id for a provider, from settings."""
    return getattr(get_settings(), _PROVIDER_DEFAULT_ATTR[provider])


def allowed_models(provider: str) -> tuple[str, ...]:
    """The models this deployment will accept for a provider, default first.

    The default is prepended rather than assumed present, and de-duplicated, so
    the list is correct whether or not the running default happens to appear in
    JUDGE_MODELS."""
    default = _default_model(provider)
    out = [default] if default else []
    for m in JUDGE_MODELS.get(provider, ()):
        if m not in out:
            out.append(m)
    return tuple(out)


def resolve_model(provider: str, stored: str | None) -> str:
    """The model id to grade with: the org's pin if we still honour it, else the
    deployment default.

    AN UNKNOWN STORED VALUE FALLS BACK; IT DOES NOT FAIL THE GRADE. A model that
    was valid when an admin chose it can be retired by the provider months later,
    and the org finds out through a grading outage it cannot diagnose. The same
    posture the BYOK path takes when a key will not decrypt: record the problem,
    carry on with something that works."""
    default = _default_model(provider)
    if stored and stored in allowed_models(provider):
        return stored
    if stored:
        log.warning("org pinned an unknown %s judge model %r; using the "
                    "deployment default %r", provider, stored, default)
    return default


def platform_keys_allowed(org) -> bool:
    """True when this ORG may grade on Foxy's platform provider keys.

    TAKES THE ORG, NOT THE TIER, SINCE M4a — and that is the whole point. The
    tier set below still decides which plans are privileged, but ``premium``
    stopped being a sufficient answer the day Premium became something customers
    buy: an evaluation offer sets exactly that string, deliberately and
    permanently (see ``billing_state.evaluation_lock``). A function handed only
    ``"premium"`` cannot tell a paying enterprise customer from an evaluator
    whose window shut months ago, and this is the decision that spends Foxy's own
    LLM key.

    Three populations, and they do not all get the same answer:

    * **Paid Premium** — yes. The owner chose this knowing the cost is unbounded.
    * **A LIVE evaluation** — yes, unchanged from before M4a. Not needing your own
      provider key is most of what a judge offer is for, and taking it away here
      would quietly gut the offer while claiming to fix a leak.
    * **An EXPIRED evaluation** — no. This is the one that changes. Such an org
      keeps reading ``premium`` forever, so before M4a it kept the privilege
      forever too.

    The live exposure that closes was bounded rather than dramatic, and it is
    worth stating accurately: an expired evaluator cannot capture
    (``capture_block`` answers ``evaluation_expired``), so no NEW events reach
    the worker. What could still be graded on Foxy's key was whatever sat
    un-graded in the outbox when the window shut, plus its retries. The real
    defect was never the size of that bill — it was that ``plan_tier`` could no
    longer answer "is this org a customer?", and four other entitlements were
    asking it the same way.

    Accepts anything with a ``plan_tier`` attribute, and ``None`` for "no org",
    which answers False — a routing decision with no organisation behind it must
    never resolve to spending the platform's key.
    """
    if org is None:
        return False
    if (getattr(org, "plan_tier", None) or "").strip().lower() not in PLATFORM_KEY_TIERS:
        return False
    # The tier qualifies. It only counts if something real put the org there:
    # money, or an offer still inside its window. Tier-agnostic on purpose —
    # PLATFORM_KEY_TIERS above stays the one place that decides WHICH tiers.
    return billing_state.entitlement_is_earned(org)


@dataclass(frozen=True)
class JudgeRouting:
    """One org's resolved judge configuration for a single grading call.

    ``gemini_key`` / ``openai_key`` are plaintext BYOK keys held in memory only.
    ``None`` means "no tenant key for this provider": in platform mode that is
    correct (the provider falls back to settings.*), and in own mode it means the
    provider must be SKIPPED rather than charged to the platform — which is what
    :meth:`can_call` encodes.
    """

    provider: str = DEFAULT_PROVIDER
    key_mode: str = DEFAULT_KEY_MODE
    gemini_key: str | None = None
    openai_key: str | None = None
    qwen_key: str | None = None
    # The RESOLVED model id per provider — an org pin if it survived validation,
    # otherwise the deployment default. Never None once resolve_judge_routing has
    # run. Unlike the keys above these are safe to record: a model id identifies
    # a public product, not a credential, and the verdict carries it so the ledger
    # can say which model graded each event.
    gemini_model: str | None = None
    openai_model: str | None = None
    qwen_model: str | None = None
    # Why a chosen provider had to be skipped (e.g. "no_byok_key"), for the
    # evaluator_unavailable reason string. Never contains key material.
    problems: dict[str, str] = field(default_factory=dict)

    # Which providers this routing calls. Named combinations replace the old
    # "both" — see _PROVIDER_COMPAT for the backwards-compat shim.
    _GEMINI_PROVIDERS = frozenset({"gemini", "gemini+openai", "gemini+qwen", "all"})
    _OPENAI_PROVIDERS = frozenset({"openai", "gemini+openai", "openai+qwen", "all"})
    _QWEN_PROVIDERS = frozenset({"qwen", "gemini+qwen", "openai+qwen", "all"})

    @property
    def uses_gemini(self) -> bool:
        return self.provider in self._GEMINI_PROVIDERS

    @property
    def uses_openai(self) -> bool:
        return self.provider in self._OPENAI_PROVIDERS

    @property
    def uses_qwen(self) -> bool:
        return self.provider in self._QWEN_PROVIDERS

    def key_for(self, provider: str) -> str | None:
        if provider == "qwen":
            return self.qwen_key
        if provider == "openai":
            return self.openai_key
        return self.gemini_key

    def model_for(self, provider: str) -> str | None:
        if provider == "qwen":
            return self.qwen_model
        if provider == "openai":
            return self.openai_model
        return self.gemini_model

    def can_call(self, provider: str) -> bool:
        """False when this provider is chosen but has no usable key in own mode."""
        if self.key_mode == "platform":
            return True
        return bool(self.key_for(provider))


def _decrypt_optional(ciphertext: str | None, org_id, provider: str,
                      problems: dict[str, str]) -> str | None:
    """Decrypt a stored BYOK key, or record why we could not. Never raises."""
    if not (ciphertext or "").strip():
        problems[provider] = "no_byok_key"
        return None
    try:
        plaintext = decrypt_secret(ciphertext, org_id, provider).strip()
    except SecretsNotConfigured:
        # Deployment has no PROVIDER_KEY_ENCRYPTION_KEY — fail closed.
        log.warning("BYOK key for org %s unusable: encryption not configured", org_id)
        problems[provider] = "byok_encryption_unavailable"
        return None
    except SecretDecryptionError:
        log.warning("BYOK key for org %s could not be decrypted", org_id)
        problems[provider] = "byok_key_undecryptable"
        return None
    if not plaintext:
        problems[provider] = "no_byok_key"
        return None
    return plaintext


def resolve_judge_routing(db: Session, org_id) -> JudgeRouting:
    """Read the org's LIVE routing choice and materialise the keys for one call.

    Reads the live OrgPolicy row deliberately: the policy snapshot bound to an
    event governs HOW the event is judged, but never WHO judges it or whose key
    pays — a key must never touch the chain.
    """
    oid = org_id if isinstance(org_id, uuid.UUID) else uuid.UUID(str(org_id))
    policy = db.get(OrgPolicy, oid)
    if policy is None:
        return JudgeRouting(gemini_model=resolve_model("gemini", None),
                            openai_model=resolve_model("openai", None),
                            qwen_model=resolve_model("qwen", None))

    # Backwards-compat: "both" predates Qwen and meant gemini+openai.
    raw_provider = policy.judge_provider
    provider = _PROVIDER_COMPAT.get(raw_provider, raw_provider)
    if provider not in PROVIDERS:
        provider = DEFAULT_PROVIDER
    key_mode = policy.judge_key_mode if policy.judge_key_mode in KEY_MODES else DEFAULT_KEY_MODE

    if key_mode == "platform":
        org = db.get(Organization, oid)
        if not platform_keys_allowed(org):
            # Server-side tier gate, re-checked at grading time (e.g. after a
            # downgrade): fall back to BYOK rather than spending Foxy's key.
            key_mode = "own"

    # Resolved for BOTH key modes: whose key pays and which version runs are
    # independent choices, and a platform-key org still gets to pick a model.
    gemini_model = resolve_model("gemini", policy.gemini_judge_model)
    openai_model = resolve_model("openai", policy.openai_judge_model)
    qwen_model = resolve_model("qwen", policy.qwen_judge_model)

    if key_mode == "platform":
        return JudgeRouting(provider=provider, key_mode=key_mode,
                            gemini_model=gemini_model,
                            openai_model=openai_model,
                            qwen_model=qwen_model)

    # Build the routing first so the uses_* properties decide which keys to
    # decrypt — only a chosen provider's key is worth attempting.
    routing = JudgeRouting(provider=provider, key_mode=key_mode,
                           gemini_model=gemini_model,
                           openai_model=openai_model,
                           qwen_model=qwen_model)
    problems: dict[str, str] = {}
    gemini_key = (_decrypt_optional(policy.gemini_key_enc, oid, "gemini", problems)
                  if routing.uses_gemini else None)
    openai_key = (_decrypt_optional(policy.openai_key_enc, oid, "openai", problems)
                  if routing.uses_openai else None)
    qwen_key = (_decrypt_optional(policy.qwen_key_enc, oid, "qwen", problems)
                if routing.uses_qwen else None)
    return JudgeRouting(provider=provider, key_mode=key_mode,
                        gemini_key=gemini_key, openai_key=openai_key,
                        qwen_key=qwen_key,
                        gemini_model=gemini_model,
                        openai_model=openai_model,
                        qwen_model=qwen_model,
                        problems=problems)
