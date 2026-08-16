"""
Foxy Audit desktop — the three surfaces that make the guard visible.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    GuardStrip    the policy and mode in force, and whether anything ships
    GuardReceipt  under every turn: the whole read-out, one line until opened
    BlockOverlay  when the guard refuses, a card that says so and why

All three render a `foxy_guard.run()` dict AS RETURNED. Nothing here re-derives
a verdict, re-hashes anything or decides what a rule means: a second opinion
computed in a renderer is how two surfaces start disagreeing about one event.

⚠ NO TOKENS AT IMPORT TIME. Every colour and font is read inside a constructor,
never at module level. `glass_tokens()` reaches QFontDatabase through
`pick_font()`, which SEGFAULTS when no QApplication exists yet — measured, exit
139, on the normal platform and not only offscreen. A module-level token dict
would move that crash to import time, where it is even harder to see.
"""

from __future__ import annotations

import json

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QFrame, QGridLayout, QHBoxLayout, QLabel, QPushButton, QVBoxLayout, QWidget,
)

from foxy_tokens import BAD_RED, OK_GREEN, WARN_AMBER, WEB, glass_tokens


#: A rule family, in words a person can read. The keys are the SDK's own
#: `blocked_reason` labels (policy._REASON_LABEL), not invented here.
REASON_PHRASE = {
    "phi":              "protected health information",
    "pii":              "personal data",
    "secret_key":       "a credential",
    "prompt_injection": "a prompt-injection attempt",
    "unsafe_markup":    "unsafe markup",
    "unsafe_sql":       "unsafe SQL",
    "unsafe_url":       "an unsafe URL",
    "scan_coverage":    "a response the scanner could not read",
}

#: decision → (edge colour token name, the word shown). The three status colours
#: are the app's own; nothing here invents a palette.
_EDGE = {
    "allowed":          ("ok",    "ALLOWED"),
    "flagged":          ("warn",  "FLAGGED"),
    "redacted":         ("fox",   "REDACTED"),
    "blocked":          ("bad",   "BLOCKED"),
    "response_blocked": ("bad",   "RESPONSE BLOCKED"),
    "unguarded":        ("muted", "UNGUARDED"),
    "error":            ("muted", "GUARD ERROR"),
}

CARD_FILL = "rgba(255,255,255,13)"
RIM = "1px solid rgba(255,255,255,38)"


def phrase(reason: str) -> str:
    return REASON_PHRASE.get(reason, str(reason).replace("_", " "))


def leaked_words(prompt: str, body: str) -> list:
    """Every word of six characters or more from the prompt, searched for in the
    shipped bytes. Short tokens are skipped because they collide by chance.
    Ported from `demo/mock_llm.py`'s `--show-wire` check so both surfaces make
    the same claim by the same measurement."""
    return sorted(w for w in set(prompt.split()) if len(w) >= 6 and w in body)


def wrap_mono(text: str, width: int = 34) -> str:
    """Hard-break over-long TOKENS so a hash cannot widen the window.

    ⚠ NOT COSMETIC. A QLabel's minimum width is its longest *word*, and a
    64-character commitment is one word — so a single receipt row set the
    message container's minimum width and pushed the rest of the chat past the
    right edge, with horizontal scrolling switched off. Measured: the reply
    bubble lost half its text.

    Ellipsis is not an option. A truncated commitment is not a commitment, and
    it is the one value here somebody might check by eye. Prose is left alone —
    the label's own word wrap handles it, and breaking every line at `width`
    chopped words in half ("…≥6 char/s").
    """
    out = []
    for line in str(text).splitlines() or [""]:
        words = []
        for word in line.split(" "):
            if len(word) > width:
                word = "\n".join(word[i:i + width] for i in range(0, len(word), width))
            words.append(word)
        out.append(" ".join(words))
    return "\n".join(out)


def _colours(tokens: dict) -> dict:
    return {"ok": OK_GREEN, "warn": WARN_AMBER, "bad": BAD_RED,
            "fox": tokens["accent"], "muted": WEB["muted"]}


def _label(text, tokens, size=11, colour=None, weight=500, mono=False,
           caps=False, wrap=True) -> QLabel:
    lbl = QLabel(text)
    lbl.setWordWrap(wrap)
    face = tokens.get("font_mono" if mono else "font", "Segoe UI")
    lbl.setStyleSheet(
        f"background: transparent; border: none;"
        f"color: {colour or WEB['ink2']};"
        f"font-family: '{face}'; font-size: {size}px; font-weight: {weight};"
        + ("letter-spacing: 1.4px;" if caps else ""))
    return lbl


class StatusDot(QFrame):
    """A painted 8px disc rather than a '●' character: the brand face
    (Unbounded) has no glyph for it, and a mark the font cannot draw is a mark
    that is not there."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedSize(8, 8)

    def set_colour(self, colour: str):
        self.setStyleSheet(f"background: {colour}; border-radius: 4px; border: none;")


class GuardStrip(QFrame):
    """One row: what the guard will do to the next message, and where it goes."""

    clicked = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        tokens = glass_tokens()
        self._tokens = tokens
        self.setObjectName("guardStrip")
        self.setFixedHeight(32)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setStyleSheet(
            "QFrame#guardStrip { background: rgba(255,255,255,18);"
            " border: 1px solid rgba(255,255,255,52); border-radius: 11px; }")
        row = QHBoxLayout(self)
        row.setContentsMargins(12, 0, 10, 0)
        row.setSpacing(8)
        # wrap=False on both: the strip is a fixed 32px, and a wrapped line
        # loses its second half behind the bottom edge.
        self.left = _label("", tokens, weight=700, wrap=False)
        self.dot = StatusDot()
        self.right = _label("", tokens, colour=WEB["muted"], weight=700, wrap=False)
        row.addWidget(self.left)
        row.addStretch()
        row.addWidget(self.dot)
        row.addWidget(self.right)
        row.addWidget(_label("›", tokens, size=13, colour=WEB["muted"], weight=800))
        self.setAccessibleName("Guard settings: policy, mode and API key")

    def update_state(self, policy_tag: str, mode: str, endpoint: str,
                     has_key: bool, available: bool = True):
        tokens = self._tokens
        if not available:
            # An honest empty state. A chat that cannot run the guard must not
            # look like a chat that is running it.
            self.left.setText("guard unavailable")
            self.right.setText("pip install foxy-audit")
            self.dot.set_colour(WEB["muted"])
            return
        # The tag it will actually judge under, never "auto": the strip is the
        # one place a person checks before typing something sensitive.
        self.left.setText(f"{policy_tag}  ·  {mode}")
        # Rebuilt whole, never patched by string-replace: a replace() works in
        # one direction only, so clearing the key would have left the dot green
        # while the words said local only.
        if has_key:
            host = endpoint.replace("https://", "").replace("http://", "")
            text, colour = f"shipping to {host}", OK_GREEN
        else:
            text, colour = "local only", WEB["muted"]
        self.right.setText(text)
        self.right.setStyleSheet(
            f"background: transparent; border: none; color: {colour};"
            f"font-family: '{tokens['font']}'; font-size: 11px; font-weight: 700;")
        self.dot.set_colour(colour)

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit()
        super().mousePressEvent(event)


class GuardReceipt(QFrame):
    """One turn's evidence: the terminal read-out, collapsed to a line."""

    def __init__(self, result: dict, prompt: str, parent=None):
        super().__init__(parent)
        tokens = glass_tokens()
        self.result = result
        cols = _colours(tokens)
        key, word = _EDGE.get(result["decision"], ("muted", result["decision"].upper()))
        colour = cols[key]

        self.setObjectName("receipt")
        self.setStyleSheet(
            f"QFrame#receipt {{ background: {CARD_FILL}; border: {RIM};"
            f" border-left: 2px solid {colour}; border-radius: 10px; }}")

        box = QVBoxLayout(self)
        box.setContentsMargins(11, 8, 9, 9)
        box.setSpacing(7)

        head = QHBoxLayout()
        head.setSpacing(8)
        summary = f"{word} · {result['policy'] or '—'} · {result['mode']}"
        if result["reason"] != "none":
            summary += f" · {result['reason']}"
        self.summary = _label(summary, tokens, colour=colour, weight=800)
        head.addWidget(self.summary)
        head.addStretch()
        self.toggle = QPushButton("Evidence  ⌄")
        self.toggle.setObjectName("evToggle")
        self.toggle.setCursor(Qt.CursorShape.PointingHandCursor)
        self.toggle.setMinimumHeight(24)
        self.toggle.setStyleSheet(
            f"QPushButton#evToggle {{ background: transparent; border: none;"
            f" color: {WEB['muted']}; font-family: '{tokens['font']}';"
            f" font-size: 10px; font-weight: 700; padding: 2px 4px; }}"
            f"QPushButton#evToggle:hover {{ color: {WEB['ink']}; }}")
        self.toggle.setAccessibleName("Show the evidence for this turn")
        self.toggle.clicked.connect(self.flip)
        head.addWidget(self.toggle)
        box.addLayout(head)

        self.detail = QWidget()
        self.detail.setStyleSheet("background: transparent;")
        grid = QGridLayout(self.detail)
        grid.setContentsMargins(0, 4, 0, 0)
        grid.setHorizontalSpacing(10)
        grid.setVerticalSpacing(5)
        grid.setColumnStretch(1, 1)
        self.rows = self.build_rows(result, prompt)
        for i, (name, value) in enumerate(self.rows):
            grid.addWidget(_label(name, tokens, size=10, colour=WEB["muted"],
                                  weight=700, caps=True),
                           i, 0, Qt.AlignmentFlag.AlignTop)
            val = _label(wrap_mono(value), tokens, size=10, mono=True)
            # Selectable: a commitment nobody can copy out is a picture of
            # evidence rather than evidence.
            val.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            val.setCursor(Qt.CursorShape.IBeamCursor)
            grid.addWidget(val, i, 1)
        self.detail.hide()
        box.addWidget(self.detail)

    @staticmethod
    def build_rows(r: dict, prompt: str) -> list:
        """The rows, as data — so a test can compare them against the guard's
        dict without going through the widget tree."""
        rows = [
            ("policy / mode", f"{r['policy'] or '—'} / {r['mode']}"),
            ("decision", f"{r['decision'].upper()}   (reason: {r['reason']})"),
            ("rules", " · ".join(r["rules"]) or "[]"),
            ("signals", " · ".join(r["signals"]) or "[]"),
            ("prompt_hash", r["prompt_hash"] or "—"),
            ("response_hash", r["response_hash"] or "—"),
            ("llm called?", "YES" if r["llm_called"]
                            else "NO  (blocked before the model ran)"),
        ]
        if r["decision"] == "redacted":
            rows.append(("model input", r["model_input"] + "   ← scrubbed locally"))
        if r.get("ruleset_version"):
            rows.append(("ruleset", f"{r['ruleset_version']}  ·  sdk {r['sdk_version']}"))
        payload = r.get("wire")
        if payload:
            body = json.dumps(payload, indent=2, sort_keys=True)
            leaked = leaked_words(prompt, body)
            rows.append(("what left this machine", body))
            rows.append(("prompt text in it",
                         f"⚠ {leaked}" if leaked
                         else "none — searched every word ≥6 chars"))
        else:
            rows.append(("what left this machine",
                         "nothing — no API key, so the guard ran locally only"))
        return rows

    def flip(self):
        shown = not self.detail.isVisible()
        self.detail.setVisible(shown)
        self.toggle.setText("Evidence  ⌃" if shown else "Evidence  ⌄")


class BlockOverlay(QWidget):
    """The card that appears when the guard refuses.

    It says two different things, and the difference is the whole point. A
    PROMPT block prevented the call. A RESPONSE block did not — the model
    already ran and the prompt already reached it; only the answer was stopped.
    Reporting the second as the first is a false statement about egress, which
    is the one kind of error this product may not make.
    """

    edit_requested = pyqtSignal()
    redact_requested = pyqtSignal()
    dismissed = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        tokens = glass_tokens()
        self._tokens = tokens
        self.setObjectName("blockOv")
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        # Takes focus itself, so Escape reaches keyPressEvent below.
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self.setStyleSheet(
            "QWidget#blockOv { background: rgba(6,6,8,214); border-radius: 20px; }")

        outer = QVBoxLayout(self)
        outer.setContentsMargins(16, 16, 16, 16)
        outer.addStretch()

        card = QFrame()
        card.setObjectName("blockCard")
        card.setStyleSheet(
            f"QFrame#blockCard {{ background: #161416; border: 1px solid {BAD_RED};"
            f" border-radius: 16px; }}")
        v = QVBoxLayout(card)
        v.setContentsMargins(18, 16, 18, 16)
        v.setSpacing(9)

        self.eyebrow = _label("", tokens, size=10, colour=BAD_RED, weight=800, caps=True)
        self.title = _label("", tokens, size=16, colour=WEB["ink"], weight=800)
        self.body = _label("", tokens, size=12, weight=500)
        v.addWidget(self.eyebrow)
        v.addWidget(self.title)
        v.addWidget(self.body)

        ev = QFrame()
        ev.setObjectName("blockEv")
        ev.setStyleSheet(
            f"QFrame#blockEv {{ background: rgba(255,255,255,10); border: {RIM};"
            f" border-radius: 10px; }}")
        evb = QVBoxLayout(ev)
        evb.setContentsMargins(12, 10, 12, 10)
        evb.setSpacing(4)
        evb.addWidget(_label("WHAT WAS RECORDED", tokens, size=10,
                             colour=WEB["muted"], weight=800, caps=True))
        self.ev_rules = _label("", tokens, size=10, mono=True)
        self.ev_hash = _label("", tokens, size=10, colour=WEB["muted"], mono=True)
        evb.addWidget(self.ev_rules)
        evb.addWidget(self.ev_hash)
        v.addWidget(ev)

        btns = QHBoxLayout()
        btns.setSpacing(8)
        self.edit_btn = self._button("Edit prompt", tokens, primary=True)
        self.redact_btn = self._button("Retry with redaction", tokens)
        self.close_btn = self._button("Close", tokens)
        self.edit_btn.clicked.connect(self._edit)
        self.redact_btn.clicked.connect(self._redact)
        self.close_btn.clicked.connect(self.dismiss)
        btns.addWidget(self.edit_btn)
        btns.addWidget(self.redact_btn)
        btns.addStretch()
        btns.addWidget(self.close_btn)
        v.addLayout(btns)

        outer.addWidget(card)
        outer.addStretch()
        self.hide()

    @staticmethod
    def _button(text: str, tokens: dict, primary: bool = False) -> QPushButton:
        b = QPushButton(text)
        b.setCursor(Qt.CursorShape.PointingHandCursor)
        b.setMinimumHeight(34)
        b.setAccessibleName(text)
        # #1a0900 on the accent, not white: white on this orange measures
        # 3.76:1, the AA miss the dashboard's own buttons used to carry.
        #
        # ⚠ HOVER BRIGHTENS, IT DOES NOT DARKEN. The obvious hover — the
        # accent_dark token, #a8551f — puts that same near-black ink at 3.68:1
        # and `test_d15_contrast` caught it. Darkening a fill under dark ink
        # takes contrast away; #ff9d52 (the fox2 token) gives back 9.4:1 and
        # still reads as a state change.
        return _styled(b, primary, tokens["accent"], WEB["fox2"], tokens)

    def show_for(self, result: dict, can_redact: bool):
        if result.get("stage") == "response":
            self.eyebrow.setText("RESPONSE SCAN")
            self.title.setText("Blocked on the way back.")
            self.body.setText(
                f"The model answered, and the scan stopped the answer before it "
                f"reached you — it matched {phrase(result['reason'])} under the "
                f"{result['policy']} policy. The prompt did reach the model.")
        else:
            self.eyebrow.setText("PREFLIGHT GUARD")
            self.title.setText("Blocked before the model saw it.")
            self.body.setText(
                f"This prompt matched {phrase(result['reason'])} under the "
                f"{result['policy']} policy. The model was never called, and the "
                f"text never left this machine.")
        self.ev_rules.setText(wrap_mono(" · ".join(result["rules"]) or "[]"))
        self.ev_hash.setText("prompt commitment\n"
                             + wrap_mono(result["prompt_hash"] or "—"))
        self.redact_btn.setVisible(can_redact and result.get("stage") != "response")
        if self.parent() is not None:
            self.setGeometry(self.parent().rect())
        self.show()
        self.raise_()
        # The overlay itself takes focus, not a button inside it: Escape has to
        # reach keyPressEvent, and nothing behind the scrim may keep the caret.
        self.setFocus(Qt.FocusReason.OtherFocusReason)

    def dismiss(self):
        self.hide()
        self.dismissed.emit()

    def _edit(self):
        self.hide()
        self.edit_requested.emit()

    def _redact(self):
        self.hide()
        self.redact_requested.emit()

    def keyPressEvent(self, event):
        if event.key() == Qt.Key.Key_Escape:
            self.dismiss()
        else:
            super().keyPressEvent(event)


def _styled(button: QPushButton, primary: bool, accent: str, accent_dark: str,
            tokens: dict) -> QPushButton:
    button.setStyleSheet(
        f"QPushButton {{ background: {accent if primary else 'transparent'};"
        f" color: {'#1a0900' if primary else WEB['ink2']};"
        f" border: {'none' if primary else RIM}; border-radius: 9px;"
        f" padding: 6px 14px; font-family: '{tokens['font']}'; font-size: 12px;"
        f" font-weight: 700; }}"
        f"QPushButton:hover {{"
        f" background: {accent_dark if primary else 'rgba(255,255,255,20)'};"
        f" color: {'#1a0900' if primary else WEB['ink']}; }}")
    return button
