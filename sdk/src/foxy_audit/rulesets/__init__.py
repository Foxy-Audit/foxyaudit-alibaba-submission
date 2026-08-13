"""The published ruleset registry: version string -> frozen definition.

One module per version, each written once and never edited. They are plain
Python dict literals rather than JSON data files on purpose — a module is
guaranteed to be importable from a wheel or a zipapp with no packaging
declaration, no file IO and no ``importlib.resources`` dance, and this registry
has to be readable in every environment a customer's SDK runs in.

Adding a version is two lines here plus the new frozen module. Removing one is
never correct: rows in customers' chains name these strings.
"""

from __future__ import annotations

from . import v2026_08_1, v2026_08_2

_REGISTRY = {
    v2026_08_1.VERSION: v2026_08_1.DEFINITION,
    v2026_08_2.VERSION: v2026_08_2.DEFINITION,
}


def get(version: str) -> dict:
    """The frozen definition for ``version``.

    ``KeyError`` when this build does not carry it — the honest answer for a row
    minted by a newer SDK. Replaying the wrong rules would be worse than saying
    so.
    """
    try:
        return _REGISTRY[version]
    except KeyError:
        raise KeyError(
            f"unknown ruleset version {version!r}; this build carries "
            f"{', '.join(sorted(_REGISTRY))}"
        ) from None


def versions() -> tuple[str, ...]:
    return tuple(sorted(_REGISTRY))


__all__ = ["get", "versions"]
