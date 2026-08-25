"""The model providers the testbed can put behind the guard.

Three of them, and the default is the one that needs nothing:

* :class:`MockProvider` — offline, deterministic, no key, no socket. The default
  everywhere, and the only one CI ever runs.
* :class:`OpenAIProvider` — the Responses API, under the user's own key.
* :class:`GeminiProvider` — ``generateContent``, under the user's own key.

WHAT THE MOCK IS HONEST ABOUT
=============================
Its replies are FIXTURES written by us, not model output, and :data:`MOCK_NOTE`
is the sentence every surface has to render beside them. The distinction that
makes the demo worth anything is that ENFORCEMENT IS REAL either way: the
preflight guard is ``foxy_audit``'s own, it runs identically whichever provider
is behind it, and a blocked prompt never reaches any of the three.

DETERMINISM IS A REQUIREMENT, NOT A PREFERENCE
==============================================
The probe scoreboard is a CI gate, so the mock uses no ``random``, no clock, and
no iteration over an unordered container. A prompt in the sector's corpus gets
that probe's fixture; anything else gets a stable sha256-derived line that says
what it is. Same input, same bytes, forever.

CONTENT-BLINDNESS AT THE PROVIDER SEAM
======================================
The real providers send the prompt to the model the user chose, under the user's
own key, from the user's own machine — which is the same thing the SDK's own
customers do, and it is why the web surface in T2 must stay local-only. Nothing
in this module sends anything anywhere near Foxy. Their error paths raise
``ProviderError`` carrying a status code and an exception type, never a response
body, so a provider that echoes the prompt back in an error cannot turn a
traceback into an exfiltration route.
"""

from __future__ import annotations

import hashlib
import json

#: The sentence that must appear beside any mock reply, on every surface.
MOCK_NOTE = ("mock provider -- replies are fixtures, not model output. "
             "Enforcement is real: the same foxy_audit guard runs whichever "
             "provider is behind it.")

#: How the no-fixture filler opens. ⚠ A PLACEHOLDER IS NOT AN ANSWER, and the
#: fact that one was returned has to be CARRIED rather than recovered by a
#: consumer matching this string -- see :attr:`Provider.answered_with_filler`.
#: It is a module constant so the reply and the flag are built from one source
#: and a guard can assert the literal instead of comparing a name to itself.
NO_FIXTURE_PREFIX = "[no fixture for this prompt]"

OPENAI_RESPONSES_URL = "https://api.openai.com/v1/responses"
GEMINI_BASE_URL = "https://generativelanguage.googleapis.com/v1beta/models"

DEFAULT_OPENAI_MODEL = "gpt-5.6"
DEFAULT_GEMINI_MODEL = "gemini-2.5-flash"

#: Bound on a testbed reply. A demo turn that runs to a thousand tokens is a
#: worse demo and a larger bill.
MAX_OUTPUT_TOKENS = 400
REQUEST_TIMEOUT = 30


class ProviderError(RuntimeError):
    """A provider call failed. Carries a type and a status, never a body.

    The response body is deliberately dropped rather than attached. It is the
    one place in this module where content the user typed could come back to us,
    and an error message ends up in logs, in terminal scrollback, and in
    whatever a future surface decides to render.
    """


class Provider:
    """The seam every surface calls: ``complete(system, prompt) -> str``.

    ``name`` and ``model`` ride into the audit event through the SDK's
    ``_metadata`` allowlist, so an auditor reading a row can see which model
    produced it. Both are plain identifiers, never content.
    """

    name = "provider"

    def __init__(self, model: str) -> None:
        self.model = model

    def complete(self, system: str, prompt: str) -> str:
        raise NotImplementedError

    @property
    def is_live(self) -> bool:
        """Does this provider make a network call? Surfaces render the answer."""
        return True

    @property
    def answered_with_filler(self) -> bool:
        """Was the LAST reply this provider produced a placeholder, not an answer?

        ⚠ CARRIED, NOT RE-DERIVED, and for the same reason :attr:`is_live` is.
        ``Assistant`` accepts any ``Provider`` subclass, so a consumer sniffing
        for :data:`NO_FIXTURE_PREFIX` in the reply text would be guessing at
        another object's business -- and would misfire the day a real model
        quotes the phrase back.

        False here because every provider that answers for real answers for
        real: a live model returning something unhelpful has still answered, and
        nothing in this package reads a reply's content to judge it. Only the
        mock knows it had no fixture, and only the mock overrides this.
        """
        return False

    @property
    def note(self) -> str:
        """The disclaimer to render beside this provider's replies, if any."""
        return ""


class MockProvider(Provider):
    """Canned, deterministic, offline. The default.

    ``fixtures`` maps a prompt to the exact reply for it — an exact-match dict
    rather than keyword scoring, because "deterministic" has to survive somebody
    adding a probe whose wording happens to overlap another one's keywords.
    """

    name = "mock"

    def __init__(self, fixtures=None, model: str = "mock-fixture-1") -> None:
        super().__init__(model)
        self.fixtures = dict(fixtures or {})
        #: How many times the wrapped call actually reached a provider. A
        #: blocked prompt must never increment this, which is what makes
        #: "prevention" a measurement rather than a claim.
        self.calls = 0
        #: Whether the LAST completion fell through to the filler. Per-call
        #: state on the provider, alongside ``calls``, because ``Assistant``
        #: holds one provider and reads it immediately after the call returns.
        self._filler = False

    def complete(self, system: str, prompt: str) -> str:
        self.calls += 1
        canned = self.fixtures.get(prompt)
        # Set from the SAME lookup that decides the reply, so the flag and the
        # text cannot disagree. A second `prompt in self.fixtures` here would be
        # a second reading of the dict and a second thing to get wrong.
        self._filler = canned is None
        if canned is not None:
            return canned
        digest = hashlib.sha256(str(prompt).encode("utf-8")).hexdigest()[:12]
        return (NO_FIXTURE_PREFIX + " The mock provider has no written "
                "answer for it, so there is nothing to show you here -- and "
                "inventing one would make this demo dishonest. The enforcement "
                "result above is real and was produced by the same guard a live "
                "provider runs behind. Point --provider at openai or gemini with "
                "your own key for a real answer. (prompt digest {0})".format(digest))

    @property
    def is_live(self) -> bool:
        return False

    @property
    def answered_with_filler(self) -> bool:
        return self._filler

    @property
    def note(self) -> str:
        return MOCK_NOTE


def _requests():
    """Import ``requests`` at call time, not at module import.

    ``requests`` is the SDK's only dependency so it is always installed, but the
    offline path must not so much as import an HTTP library — that is a property
    the guard test asserts, and a module-level import would make it untrue for
    reasons that have nothing to do with the offline path being offline.
    """
    import requests
    return requests


class OpenAIProvider(Provider):
    """The OpenAI Responses API, under the user's own key.

    The request body mirrors ``demo/live_openai_client.py`` exactly rather than
    being written fresh — that shape is already exercised against the live API
    and against ``demo/test_live_openai_client.py``'s boundary tests.
    """

    name = "openai"

    def __init__(self, api_key: str, model: str = DEFAULT_OPENAI_MODEL) -> None:
        super().__init__(model)
        if not api_key:
            raise ProviderError("openai provider needs an API key "
                                "(--api-key or OPENAI_API_KEY)")
        self._api_key = api_key

    def complete(self, system: str, prompt: str) -> str:
        requests = _requests()
        body = {
            "model": self.model,
            "instructions": system,
            "input": [{"role": "user", "content": [
                {"type": "input_text", "text": prompt},
            ]}],
            "max_output_tokens": MAX_OUTPUT_TOKENS,
        }
        try:
            response = requests.post(
                OPENAI_RESPONSES_URL,
                headers={"Authorization": "Bearer {0}".format(self._api_key),
                         "Content-Type": "application/json"},
                data=json.dumps(body).encode("utf-8"),
                timeout=REQUEST_TIMEOUT,
            )
        except Exception as exc:                      # noqa: BLE001 — see ProviderError
            raise ProviderError(
                "openai request failed: {0}".format(type(exc).__name__)) from exc
        if response.status_code != 200:
            raise ProviderError(
                "openai request failed with HTTP {0}".format(response.status_code))
        return _openai_text(response.json())

    @property
    def note(self) -> str:
        return ("live provider -- this prompt is sent to OpenAI under YOUR key, "
                "from this machine. It never passes through Foxy.")


def _openai_text(payload) -> str:
    """Pull the text out of a Responses API payload, or say it had none."""
    direct = payload.get("output_text")
    if isinstance(direct, str) and direct:
        return direct
    for item in payload.get("output", []) or []:
        if not isinstance(item, dict):
            continue
        for content in item.get("content", []) or []:
            if (isinstance(content, dict)
                    and content.get("type") == "output_text"
                    and isinstance(content.get("text"), str)):
                return content["text"]
    raise ProviderError("openai returned no text output")


class GeminiProvider(Provider):
    """Gemini ``generateContent``, under the user's own key.

    Over REST with ``requests`` rather than through ``google.generativeai``,
    which the backend judge uses: that package is a backend dependency, and the
    testbed ships inside the ``foxy-audit`` wheel, whose dependency list is one
    entry long and stays that way.
    """

    name = "gemini"

    def __init__(self, api_key: str, model: str = DEFAULT_GEMINI_MODEL) -> None:
        super().__init__(model)
        if not api_key:
            raise ProviderError("gemini provider needs an API key "
                                "(--api-key or GEMINI_API_KEY)")
        self._api_key = api_key

    def complete(self, system: str, prompt: str) -> str:
        requests = _requests()
        url = "{0}/{1}:generateContent".format(GEMINI_BASE_URL, self.model)
        body = {
            "system_instruction": {"parts": [{"text": system}]},
            "contents": [{"role": "user", "parts": [{"text": prompt}]}],
            "generationConfig": {"maxOutputTokens": MAX_OUTPUT_TOKENS},
        }
        try:
            response = requests.post(
                url,
                headers={"x-goog-api-key": self._api_key,
                         "Content-Type": "application/json"},
                data=json.dumps(body).encode("utf-8"),
                timeout=REQUEST_TIMEOUT,
            )
        except Exception as exc:                      # noqa: BLE001 — see ProviderError
            raise ProviderError(
                "gemini request failed: {0}".format(type(exc).__name__)) from exc
        if response.status_code != 200:
            raise ProviderError(
                "gemini request failed with HTTP {0}".format(response.status_code))
        return _gemini_text(response.json())

    @property
    def note(self) -> str:
        return ("live provider -- this prompt is sent to Google under YOUR key, "
                "from this machine. It never passes through Foxy.")


def _gemini_text(payload) -> str:
    for candidate in payload.get("candidates", []) or []:
        if not isinstance(candidate, dict):
            continue
        for part in (candidate.get("content") or {}).get("parts", []) or []:
            if isinstance(part, dict) and isinstance(part.get("text"), str):
                return part["text"]
    raise ProviderError("gemini returned no text output")


#: The names ``--provider`` accepts, in the order a surface should list them.
PROVIDER_NAMES = ("mock", "openai", "gemini")


def build_provider(name: str, sector=None, api_key: str = "", model: str = ""):
    """The provider called ``name``, wired for ``sector``.

    ``mock`` is the default and takes its fixtures from the sector's own probe
    corpus, so a probe run answers with the reply written for that probe.
    """
    key = str(name or "mock").strip().lower()
    if key == "mock":
        fixtures = {}
        if sector is not None:
            fixtures = {p.prompt: p.reply for p in sector.probes if p.reply}
        return MockProvider(fixtures, model=model or "mock-fixture-1")
    if key == "openai":
        return OpenAIProvider(api_key, model or DEFAULT_OPENAI_MODEL)
    if key == "gemini":
        return GeminiProvider(api_key, model or DEFAULT_GEMINI_MODEL)
    raise ValueError("unknown provider {0!r}; available: {1}".format(
        name, ", ".join(PROVIDER_NAMES)))


__all__ = ["DEFAULT_GEMINI_MODEL", "DEFAULT_OPENAI_MODEL", "GeminiProvider",
           "MOCK_NOTE", "MockProvider", "NO_FIXTURE_PREFIX", "OpenAIProvider",
           "PROVIDER_NAMES", "Provider", "ProviderError", "build_provider"]
