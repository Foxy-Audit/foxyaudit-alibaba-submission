"""Vendor-neutral extraction for common LLM response shapes.

This intentionally avoids importing OpenAI, Anthropic, Gemini, or LiteLLM. The
SDK hashes the complete local object, while these helpers walk it.

TWO FUNCTIONS, TWO VERY DIFFERENT BOUNDARIES — do not confuse them:

* :func:`response_metadata` returns BOUNDED IDENTIFIERS that are emitted. Ids,
  model names, usage counts, tool names. Everything it returns leaves the host.
* :func:`response_text` returns RESPONSE CONTENT and must NEVER be emitted,
  logged, hashed into a message, or put in an exception. It exists for one
  caller — the in-process response scan in ``response_policy.py``, which reads
  it and returns rule ids. It is in this module rather than in a second
  traversal of its own because ``response_metadata`` already walks ``choices``
  and one walker is easier to keep correct than two.

They share ``_get`` and nothing else.
"""

from __future__ import annotations

from typing import Any

# How much of a response the scan could actually read. Ordered worst-last.
COVERAGE_FULL = "full"          # the shape was understood; this IS the content
COVERAGE_DEGRADED = "degraded"  # a serialised envelope was scanned instead
COVERAGE_NONE = "none"          # nothing scannable was reachable
_COVERAGE_ORDER = (COVERAGE_FULL, COVERAGE_DEGRADED, COVERAGE_NONE)


def worst_coverage(*values: str) -> str:
    return max(values, key=_COVERAGE_ORDER.index)


def _get(obj: Any, name: str) -> Any:
    """Attribute or mapping key, whichever this object uses.

    Mapping first: a dict has plenty of attributes (``items``, ``get``) and none
    of them is the field we mean."""
    if isinstance(obj, dict):
        return obj.get(name)
    try:
        return getattr(obj, name, None)
    except Exception:               # noqa: BLE001 — Gemini's .text raises when
        return None                 # there is no candidate; that is a None.


def _as_list(value: Any) -> list:
    return list(value) if isinstance(value, (list, tuple)) else [value]


def _block_text(block: Any) -> str:
    """One content block: a bare string, ``{"type": "text", "text": ...}``, or
    an object with ``.text``. Anything else contributes nothing."""
    if isinstance(block, str):
        return block
    value = _get(block, "text")
    return value if isinstance(value, str) else ""


def _content_text(content: Any) -> str:
    """A ``content`` field, which is a string on some providers and a list of
    blocks on others."""
    if isinstance(content, str):
        return content
    if isinstance(content, (list, tuple)):
        return "".join(_block_text(b) for b in content)
    return _block_text(content)


def _extract(value: Any) -> tuple[str, bool]:
    """(text, shape_was_understood) for one non-container response value.

    ``True`` means the SHAPE was recognised, not that text was found: an
    OpenAI chunk whose delta carries only a tool call is fully understood and
    contributes nothing, and calling that "unreadable" would be a false alarm
    on every tool-calling stream.

    Ordered most-specific first. Each entry is a real wire shape:
      choices[].delta.content     OpenAI chat streaming
      choices[].message.content   OpenAI chat, non-streaming
      candidates[].content.parts  Gemini
      output[].content[].text     OpenAI Responses API
      output_text                 OpenAI Responses API convenience field
      content                     Anthropic Messages (list of blocks, or a str)
      delta.text / delta.content  Anthropic streaming events
    """
    choices = _get(value, "choices")
    if isinstance(choices, (list, tuple)):
        parts = []
        for choice in choices:
            delta = _get(choice, "delta")
            if delta is not None:
                parts.append(_content_text(_get(delta, "content")))
                parts.append(_block_text(delta))
            message = _get(choice, "message")
            if message is not None:
                parts.append(_content_text(_get(message, "content")))
            if delta is None and message is None:
                parts.append(_content_text(_get(choice, "text")))
        return "".join(parts), True

    candidates = _get(value, "candidates")
    if isinstance(candidates, (list, tuple)):
        parts = []
        for candidate in candidates:
            content = _get(candidate, "content")
            parts.append("".join(_block_text(p)
                                 for p in _as_list(_get(content, "parts") or [])))
        return "".join(parts), True

    output = _get(value, "output")
    if isinstance(output, (list, tuple)):
        return "".join(_content_text(_get(item, "content")) for item in output), True

    output_text = _get(value, "output_text")
    if isinstance(output_text, str):
        return output_text, True

    content = _get(value, "content")
    if content is not None:
        return _content_text(content), True

    delta = _get(value, "delta")
    if delta is not None:
        return _block_text(delta) + _content_text(_get(delta, "content")), True

    text = _get(value, "text")
    if isinstance(text, str):
        return text, True

    return "", False


def _plain(value: Any):
    """The object's own serialisation, or ``None`` if it has none / it raised.

    Deliberately NO ``str(value)`` fallback. ``hashing.canonical_json`` has one,
    and on the response side it is a hazard rather than a convenience: an opaque
    object reprs to ``<Foo object at 0x1234567890>``, and a memory address is a
    random digit run that the phone detector matches whenever it comes out the
    right length. The prompt side keeps its fallback — changing it would move
    block decisions that already ship."""
    for name in ("model_dump", "dict", "to_dict"):
        method = getattr(value, name, None)
        if callable(method):
            try:
                plain = method()
            except Exception:       # noqa: BLE001 — a serialiser that raises is
                return None         # an object we cannot read, not a repr.
            if isinstance(plain, (dict, list, tuple)):
                return plain
    return None


def _leaf_text(value: Any) -> str:
    """Every string leaf of a plain structure, newline-joined.

    Newlines, not concatenation: these are unrelated FIELDS, and gluing them
    would manufacture matches that span two of them."""
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        return "\n".join(_leaf_text(v) for v in value.values())
    if isinstance(value, (list, tuple)):
        return "\n".join(_leaf_text(v) for v in value)
    return ""


def response_text(value: Any) -> tuple[str, str]:
    """(text, coverage) — the RESPONSE CONTENT, for the in-process scan only.

    ⚠ Never emit, log, hash into a message, or put the first element anywhere
    that leaves this process. See this module's docstring.

    A list or tuple is joined with NO separator: in the response position that
    is the accumulated chunks of ONE stream, and a separator between "123-45"
    and "-6789" is exactly what stops the whole-stream rescan from rejoining a
    split match.

    ``bytes`` decode as UTF-8 with ``errors="replace"``. Raw SSE and
    ``iter_bytes()`` are a real transport, and scanning them as "" was zero
    coverage reported as a clean scan. Replacement characters cannot break the
    ASCII patterns the rules use.

    Coverage is the honest half of the answer. ``degraded`` means a serialised
    envelope was scanned rather than content — matches spanning two fields are
    possible and, on a stream, the carry window cannot rejoin across the
    envelope. ``none`` means nothing was reachable at all.
    """
    if value is None:
        return "", COVERAGE_FULL
    if isinstance(value, str):
        return value, COVERAGE_FULL
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).decode("utf-8", errors="replace"), COVERAGE_FULL
    if isinstance(value, (int, float, bool)):
        return "", COVERAGE_FULL
    if isinstance(value, (list, tuple)):
        parts, coverage = [], COVERAGE_FULL
        for item in value:
            text, item_coverage = response_text(item)
            parts.append(text)
            coverage = worst_coverage(coverage, item_coverage)
        return "".join(parts), coverage

    text, understood = _extract(value)
    if understood:
        return text, COVERAGE_FULL

    plain = value if isinstance(value, dict) else _plain(value)
    if plain is None:
        return "", COVERAGE_NONE
    text, understood = _extract(plain)
    if understood:
        return text, COVERAGE_FULL
    return _leaf_text(plain), COVERAGE_DEGRADED


def response_metadata(response: Any) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name in ("id", "model", "provider"):
        value = getattr(response, name, None)
        if value is not None:
            result[name] = str(value)[:256]
    usage = getattr(response, "usage", None)
    if usage is not None:
        values = {}
        for name in ("prompt_tokens", "completion_tokens", "total_tokens", "input_tokens", "output_tokens"):
            value = getattr(usage, name, None)
            if value is None and isinstance(usage, dict):
                value = usage.get(name)
            if isinstance(value, int):
                values[name] = value
        if values:
            result["usage"] = values
    choices = getattr(response, "choices", None)
    if choices is not None and isinstance(choices, (list, tuple)):
        result["choice_count"] = len(choices)
        tool_names = []
        for choice in choices[:32]:
            message = getattr(choice, "message", None)
            calls = getattr(message, "tool_calls", None)
            if calls is None and isinstance(message, dict):
                calls = message.get("tool_calls")
            for call in calls or []:
                function = getattr(call, "function", None)
                name = getattr(function, "name", None)
                if name is None and isinstance(function, dict):
                    name = function.get("name")
                if name:
                    tool_names.append(str(name)[:128])
        if tool_names:
            result["tool_names"] = tool_names[:64]
    return result
