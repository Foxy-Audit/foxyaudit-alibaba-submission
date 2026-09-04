"""Per-tenant AI Judge routing: which judge grades an org's events, on whose key.

Two independent choices per org, held on the LIVE OrgPolicy row (never on the
chain snapshot — routing is an operational/billing decision, not evidence):

  judge_provider  one of :data:`PROVIDERS` — a single provider, a named pair,
                  or ``all``. Plus ``both``, the pre-0071 spelling of
                  ``gemini+openai``, accepted forever as an alias
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

# Every judge this deployment can call. ONE name per provider, and the
# combinations spelled out — because "both" stopped being an answer the moment a
# third provider existed, and a word that used to mean one thing and now could
# mean three is worse than no word.
JUDGE_PROVIDERS = ("gemini", "openai", "qwen")

PROVIDERS = ("gemini", "openai", "qwen",
             "gemini+openai", "gemini+qwen", "openai+qwen", "all")
KEY_MODES = ("own", "platform")

# ⚠ `both` IS STILL STORED, AND IS NOT MIGRATED. It is what every two-judge org
# chose before 0071, it means gemini+openai, and it is mapped here rather than in
# the database for two reasons:
#
#   * a data migration would rewrite rows to say something the customer never
#     chose, on a table whose whole job is recording what they did choose;
#   * the alias has to survive anyway. Two shipped clients (the desktop and the
#     dashboard) still SEND "both", and will until Q4 updates them.
#
# So it stays an accepted input forever, and is resolved HERE — at grading time —
# and nowhere else. ⚠ Deliberately NOT on the policy API's read or write path:
# handing a client a word it does not recognise makes it post "gemini" back, so
# converting the spelling would destroy the very setting it tidied.
PROVIDER_ALIASES = {"both": "gemini+openai"}

# Which judges each vocabulary word actually selects. ONE mapping, so a
# combination added above cannot be forgotten in three `uses_*` properties —
# which is exactly how a chain of `provider in (...)` tests goes stale.
_PROVIDER_MEMBERS = {
    "gemini": frozenset({"gemini"}),
    "openai": frozenset({"openai"}),
    "qwen": frozenset({"qwen"}),
    "gemini+openai": frozenset({"gemini", "openai"}),
    "gemini+qwen": frozenset({"gemini", "qwen"}),
    "openai+qwen": frozenset({"openai", "qwen"}),
    "all": frozenset(JUDGE_PROVIDERS),
}

DEFAULT_PROVIDER = "gemini"
DEFAULT_KEY_MODE = "own"


def normalise_provider(value: str | None) -> str:
    """The stored routing word, as this version of the code understands it.

    Resolves the ``both`` alias and falls back to the default for anything
    unrecognised — the same posture :func:`resolve_model` takes for a withdrawn
    model pin. A row holding a word we no longer know must not take grading down
    for that tenant.

    ⚠ CALLED AT GRADING TIME ONLY — **not** on the policy API's read or write
    path, and that is deliberate. An earlier cut of Q1 did call it there; it was
    reverted in `32f2152`, because both shipped clients coerce a routing word
    they do not recognise back to "gemini" and then SAVE it, so converting a
    stored "both" into "gemini+openai" on the way out silently downgraded every
    pre-0071 two-judge org on its next policy save.

    What keeps `GET /v1/policies` working instead is that `"both"` stays in
    `PolicyConfig`'s Literal — one model serves both directions and is built
    straight from the stored column, so removing the value there is what would
    500 the policy page for exactly those orgs.
    """
    resolved = PROVIDER_ALIASES.get(value, value)
    return resolved if resolved in PROVIDERS else DEFAULT_PROVIDER


def providers_in(value: str | None) -> frozenset[str]:
    """The individual judges a routing word selects."""
    return _PROVIDER_MEMBERS[normalise_provider(value)]

# Which model versions an org may pin, per provider (P6f). One constant, in the
# same spirit as PLATFORM_KEY_TIERS above: adding a model is a one-line change.
#
# The DEPLOYMENT DEFAULT IS NOT LISTED HERE and is not required to be. It comes
# from settings (see _PROVIDER_DEFAULTS) and is always allowed, so a deployment
# can move to a model this list has not heard of without anyone having to edit it
# first. That ordering matters — the operator's setting outranks a constant in
# source.
JUDGE_MODELS = {
    "gemini": ("gemini-2.5-flash", "gemini-2.5-pro", "gemini-2.0-flash"),
    "openai": ("gpt-5.6", "gpt-5.6-mini", "chat-latest"),
    "qwen": ("qwen-plus", "qwen-max", "qwen-turbo"),
}

# Where each provider's deployment default comes from.
#
# ⚠ A MAPPING, AND IT RAISES ON AN UNKNOWN PROVIDER. This was a two-way ternary
# — `settings.gemini_model if provider == "gemini" else settings.openai_model` —
# in both functions below, which is correct for exactly as long as there are two
# providers. With a third, EVERY name that is not "gemini" takes the second
# branch: a qwen org with no pin would have resolved to the OpenAI default, sent
# `gpt-5.6` to dashscope, and written `judge_provider="qwen"` beside
# `judge_model="gpt-5.6"` onto the verdict — a false provenance line in the one
# artefact this product sells. `allowed_models("qwen")` would also have listed
# `gpt-5.6` as a valid qwen pin and accepted it.
#
# Refusing an unknown key is the point: a fourth provider must fail loudly here
# rather than inherit a third one's model.
_PROVIDER_DEFAULTS = {
    "gemini": lambda s: s.gemini_model,
    "openai": lambda s: s.openai_model,
    "qwen": lambda s: s.qwen_model,
}


def default_model(provider: str) -> str:
    """This deployment's default model id for one provider.

    Raises :class:`ValueError` for a provider it has no setting for, rather than
    silently answering with another provider's model.
    """
    try:
        return _PROVIDER_DEFAULTS[provider](get_settings())
    except KeyError:
        raise ValueError(
            f"no deployment default model for judge provider {provider!r}; "
            f"known providers are {', '.join(sorted(_PROVIDER_DEFAULTS))}"
        ) from None


def allowed_models(provider: str) -> tuple[str, ...]:
    """The models this deployment will accept for a provider, default first.

    The default is prepended rather than assumed present, and de-duplicated, so
    the list is correct whether or not the running default happens to appear in
    JUDGE_MODELS."""
    default = default_model(provider)
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
    default = default_model(provider)
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

    ``gemini_key`` / ``openai_key`` / ``qwen_key`` are plaintext BYOK keys held in
    memory only. ``None`` means "no tenant key for this provider": in platform
    mode that is correct (the provider falls back to settings.*), and in own mode
    it means the provider must be SKIPPED rather than charged to the platform —
    which is what :meth:`can_call` encodes.
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

    @property
    def selected(self) -> frozenset[str]:
        """The judges this routing selects — the ONE place the word is decoded."""
        return providers_in(self.provider)

    # Kept as named properties because the worker reads them one branch at a
    # time, but all three now answer from `selected`: a new combination added to
    # PROVIDERS cannot be right in two of these and stale in the third.
    @property
    def uses_gemini(self) -> bool:
        return "gemini" in self.selected

    @property
    def uses_openai(self) -> bool:
        return "openai" in self.selected

    @property
    def uses_qwen(self) -> bool:
        return "qwen" in self.selected

    def key_for(self, provider: str) -> str | None:
        """This org's BYOK key for one provider, or None.

        A LOOKUP, NOT A TERNARY — the two-branch form answered `openai_key` for
        every provider that was not "gemini", so an unrecognised name silently
        borrowed another provider's credential and `can_call` said yes.
        """
        return {"gemini": self.gemini_key, "openai": self.openai_key,
                "qwen": self.qwen_key}.get(provider)

    def model_for(self, provider: str) -> str | None:
        return {"gemini": self.gemini_model, "openai": self.openai_model,
                "qwen": self.qwen_model}.get(provider)

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

    # normalise_provider, not a membership test: it also resolves the "both"
    # alias, which no amount of `in PROVIDERS` would.
    provider = normalise_provider(policy.judge_provider)
    selected = providers_in(provider)
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
                            gemini_model=gemini_model, openai_model=openai_model,
                            qwen_model=qwen_model)

    # Decrypt ONLY the keys this routing will actually spend. `selected` is the
    # same set the worker branches on, so a provider can never be called with a
    # key that was not materialised for it, and a key is never decrypted for a
    # provider this org did not choose.
    problems: dict[str, str] = {}
    gemini_key = (_decrypt_optional(policy.gemini_key_enc, oid, "gemini", problems)
                  if "gemini" in selected else None)
    openai_key = (_decrypt_optional(policy.openai_key_enc, oid, "openai", problems)
                  if "openai" in selected else None)
    qwen_key = (_decrypt_optional(policy.qwen_key_enc, oid, "qwen", problems)
                if "qwen" in selected else None)
    return JudgeRouting(provider=provider, key_mode=key_mode,
                        gemini_key=gemini_key, openai_key=openai_key,
                        qwen_key=qwen_key,
                        gemini_model=gemini_model, openai_model=openai_model,
                        qwen_model=qwen_model,
                        problems=problems)
