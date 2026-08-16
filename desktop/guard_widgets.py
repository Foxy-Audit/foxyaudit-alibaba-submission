"""
Foxy Audit desktop — what the fox shows when something else gets blocked.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
The guard does not run here. It runs inside the customer's own application,
where the SDK wraps their model call — and when it refuses a prompt it fires a
loopback datagram at 127.0.0.1:9999. `sdk_bridge` receives it; these widgets are
what the person sees:

    BlockAlert    a card by the fox: what was refused, under which policy, and
                  whether the model ran at all
    GuardReceipt  the fuller read-out, when the sender had one to give

⚠ TWO PAYLOADS, ONE CARD. The SDK's ping carries policy, reason, rules and
decision — deliberately little, because it crosses a process boundary on a
customer's machine and content-blindness is the product. That is enough for the
card, and the card must be complete with nothing else. A sender that also has
the hashes (the demo does, from its own result dict) may follow up with a
richer payload, and the receipt appears then. Neither is allowed to require the
other.

⚠ NO TOKENS AT IMPORT TIME. Every colour and font is read inside a constructor.
`glass_tokens()` reaches QFontDatabase through `pick_font()`, which segfaults
when no QApplication exists yet — measured, exit 139, on the normal platform.
"""

from __future__ import annotations

import json

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QApplication, QFrame, QGridLayout, QHBoxLayout, QLabel, QPushButton,
    QVBoxLayout, QWidget,
)

from foxy_tokens import BAD_RED, OK_GREEN, WARN_AMBER, WEB, glass_tokens, make_shadow


#: A rule family in words a person can read. The keys are the SDK's own
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

#: The SDK's own spellings for a decision taken on the RESPONSE side
#: (`client.py`: `outcome = "response_truncated"` / `"blocked_response"`). They
#: are listed rather than pattern-matched because the difference between them is
#: the difference between two true sentences, and a prefix test would blur it.
TRUNCATED = "response_truncated"
RESPONSE_BLOCKED = ("blocked_response", "response_blocked")

CARD_FILL = "rgba(255,255,255,13)"
RIM = "1px solid rgba(255,255,255,38)"

#: Every key a receipt may read, so a thin payload cannot crash a renderer.
_RECEIPT_DEFAULTS = {
    "policy": "", "mode": "", "decision": "blocked", "rules": [], "signals": [],
    "reason": "none", "prompt_hash": "", "response_hash": "", "llm_called": False,
    "model_input": "", "ruleset_version": "", "sdk_version": "", "wire": None,
    "shipped": False,
}


def normalise(payload: dict) -> dict:
    """A ping, with every field the widgets read present.

    The SDK sends four keys. The demo sends fifteen. Both arrive here, and the
    renderer is the worst place to discover a missing one.
    """
    out = dict(_RECEIPT_DEFAULTS)
    out.update({k: v for k, v in (payload or {}).items() if v is not None})
    out["rules"] = list(out.get("rules") or [])
    out["signals"] = list(out.get("signals") or [])
    return out


def stage_of(payload: dict) -> str:
    """"prompt" | "response" | "truncated" — which side of the model stopped it."""
    decision = str(payload.get("decision", ""))
    if decision == TRUNCATED:
        return "truncated"
    if decision in RESPONSE_BLOCKED:
        return "response"
    return "prompt"


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
    container's minimum width and pushed everything else past the right edge.
    Ellipsis is not an option: a truncated commitment is not a commitment, and
    it is the one value here somebody might check by eye. Prose is left to the
    label's own word wrap, which handles it correctly.
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


def _button(text: str, tokens: dict, primary: bool = False) -> QPushButton:
    b = QPushButton(text)
    b.setCursor(Qt.CursorShape.PointingHandCursor)
    b.setMinimumHeight(34)
    b.setAccessibleName(text)
    accent = tokens["accent"]
    # #1a0900 on the accent, not white: white on this orange measures 3.76:1.
    # And hover BRIGHTENS — darkening to accent_dark puts that ink at 3.68:1,
    # which test_d15_contrast catches.
    b.setStyleSheet(
        f"QPushButton {{ background: {accent if primary else 'transparent'};"
        f" color: {'#1a0900' if primary else WEB['ink2']};"
        f" border: {'none' if primary else RIM}; border-radius: 9px;"
        f" padding: 6px 14px; font-family: '{tokens['font']}'; font-size: 12px;"
        f" font-weight: 700; }}"
        f"QPushButton:hover {{"
        f" background: {WEB['fox2'] if primary else 'rgba(255,255,255,20)'};"
        f" color: {'#1a0900' if primary else WEB['ink']}; }}")
    return b


class GuardReceipt(QFrame):
    """The fuller read-out for one refused interaction, collapsed to a line."""

    EDGE = {
        "allowed":            (OK_GREEN,   "ALLOWED"),
        "flagged":            (WARN_AMBER, "FLAGGED"),
        "redacted":           (None,       "REDACTED"),      # None -> accent
        "blocked":            (BAD_RED,    "BLOCKED"),
        "blocked_by_org_policy": (BAD_RED,  "BLOCKED BY ORG POLICY"),
        "blocked_response":   (BAD_RED,    "RESPONSE BLOCKED"),
        "response_blocked":   (BAD_RED,    "RESPONSE BLOCKED"),
        "response_truncated": (WARN_AMBER, "RESPONSE TRUNCATED"),
    }

    def __init__(self, payload: dict, parent=None):
        super().__init__(parent)
        tokens = glass_tokens()
        self.result = normalise(payload)
        colour, word = self.EDGE.get(self.result["decision"],
                                     (WEB["muted"], self.result["decision"].upper()))
        colour = colour or tokens["accent"]

        self.setObjectName("receipt")
        self.setStyleSheet(
            f"QFrame#receipt {{ background: {CARD_FILL}; border: {RIM};"
            f" border-left: 2px solid {colour}; border-radius: 10px; }}")

        box = QVBoxLayout(self)
        box.setContentsMargins(11, 8, 9, 9)
        box.setSpacing(7)

        head = QHBoxLayout()
        head.setSpacing(8)
        summary = f"{word} · {self.result['policy'] or '—'}"
        if self.result["reason"] != "none":
            summary += f" · {self.result['reason']}"
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
        self.toggle.setAccessibleName("Show the evidence for this event")
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
        self.rows = self.build_rows(self.result)
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
    def build_rows(payload: dict) -> list:
        """The rows, as data — so a test can compare them against the payload
        without going through the widget tree.

        A row is omitted when the sender did not supply it. A dash in the hash
        column would read as "the commitment is empty", which is a different
        and untrue statement from "this sender did not tell us".
        """
        r = normalise(payload)
        rows = [("policy", r["policy"] or "—")]
        if r["mode"]:
            rows.append(("mode", r["mode"]))
        rows.append(("decision", f"{r['decision'].upper()}   (reason: {r['reason']})"))
        rows.append(("rules", " · ".join(r["rules"]) or "[]"))
        if r["signals"]:
            rows.append(("signals", " · ".join(r["signals"])))
        if r["prompt_hash"]:
            rows.append(("prompt_hash", r["prompt_hash"]))
        if r["response_hash"]:
            rows.append(("response_hash", r["response_hash"]))
        if "llm_called" in payload:
            rows.append(("llm called?", "YES" if r["llm_called"]
                         else "NO  (blocked before the model ran)"))
        if r["ruleset_version"]:
            rows.append(("ruleset", f"{r['ruleset_version']}  ·  sdk {r['sdk_version']}"))
        if r["wire"]:
            rows.append(("what left this machine",
                         json.dumps(r["wire"], indent=2, sort_keys=True)))
        elif "shipped" in payload:
            # Both branches, because "nothing left this machine" is a claim and
            # printing it for a keyed sender would be the exact inverse of the
            # truth. `shipped` says which one this was.
            rows.append(("what left this machine",
                         "a commitment and its labels — the prompt text stayed put"
                         if r["shipped"] else
                         "nothing — no API key, so the guard ran locally only"))
        return rows

    def flip(self):
        shown = not self.detail.isVisible()
        self.detail.setVisible(shown)
        self.toggle.setText("Evidence  ⌃" if shown else "Evidence  ⌄")


class BlockAlert(QWidget):
    """The card the fox raises when another application's prompt was refused.

    It says three different things, and the differences are the point:

      PROMPT     the call was prevented — the model never ran
      RESPONSE   it was not — the model ran, the prompt reached it, only the
                 answer was stopped
      TRUNCATED  part of the answer had already reached the caller

    Reporting the second or third as the first is a false statement about
    egress, which is the one kind of error this product may not make. The SDK
    keeps the exception classes unrelated for the same reason.
    """

    dismissed = pyqtSignal()
    console_requested = pyqtSignal()

    def __init__(self, parent=None):
        # A frameless tool window: it belongs to the fox, not to the taskbar,
        # and it must be able to appear while the console is closed.
        super().__init__(parent, Qt.WindowType.Tool
                         | Qt.WindowType.FramelessWindowHint
                         | Qt.WindowType.WindowStaysOnTopHint)
        tokens = glass_tokens()
        self._tokens = tokens
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self.setWindowTitle("Foxy Audit — prompt blocked")
        self.setFixedWidth(430)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(12, 12, 12, 12)

        self.card = QFrame()
        self.card.setObjectName("blockCard")
        self.card.setStyleSheet(
            f"QFrame#blockCard {{ background: #161416; border: 1px solid {BAD_RED};"
            f" border-radius: 16px; }}")
        self.card.setGraphicsEffect(make_shadow(tokens))
        v = QVBoxLayout(self.card)
        v.setContentsMargins(18, 16, 18, 16)
        v.setSpacing(9)

        top = QHBoxLayout()
        self.eyebrow = _label("", tokens, size=10, colour=BAD_RED, weight=800, caps=True)
        top.addWidget(self.eyebrow)
        top.addStretch()
        self.source = _label("", tokens, size=10, colour=WEB["muted"], weight=700)
        top.addWidget(self.source)
        v.addLayout(top)

        self.title = _label("", tokens, size=16, colour=WEB["ink"], weight=800)
        self.body = _label("", tokens, size=12, weight=500)
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
        evb.addWidget(self.ev_rules)
        v.addWidget(ev)

        # Where the richer payload lands, if one follows.
        self.receipt_slot = QVBoxLayout()
        self.receipt_slot.setContentsMargins(0, 0, 0, 0)
        v.addLayout(self.receipt_slot)
        self._receipt: GuardReceipt | None = None

        btns = QHBoxLayout()
        btns.setSpacing(8)
        self.console_btn = _button("Open the console", tokens, primary=True)
        self.close_btn = _button("Dismiss", tokens)
        self.console_btn.clicked.connect(self._open_console)
        self.close_btn.clicked.connect(self.dismiss)
        btns.addWidget(self.console_btn)
        btns.addStretch()
        btns.addWidget(self.close_btn)
        v.addLayout(btns)

        outer.addWidget(self.card)
        self.hide()

    # -- content ------------------------------------------------------------
    def show_for(self, payload: dict, near: QWidget | None = None):
        """Render an incoming ping. Works from the SDK's four keys alone."""
        data = normalise(payload)
        stage = stage_of(data)
        what = phrase(data["reason"])
        tag = data["policy"] or "the active"

        if stage == "response":
            self.eyebrow.setText("RESPONSE SCAN")
            self.title.setText("Blocked on the way back.")
            self.body.setText(
                f"An answer matched {what} under the {tag} policy and was stopped "
                f"before it reached the application. The prompt did reach the model.")
        elif stage == "truncated":
            self.eyebrow.setText("RESPONSE SCAN")
            self.title.setText("Cut off on the way back.")
            self.body.setText(
                f"An answer matched {what} under the {tag} policy and was cut off "
                f"partway. What had already been streamed did reach the application.")
        else:
            self.eyebrow.setText("PREFLIGHT GUARD")
            self.title.setText("Blocked before the model saw it.")
            self.body.setText(
                f"An application on this machine sent a prompt matching {what} "
                f"under the {tag} policy. The model was never called, and the "
                f"prompt text never left that process.")

        self.source.setText(str(payload.get("app") or "").strip()[:40])
        self.ev_rules.setText(wrap_mono(" · ".join(data["rules"]) or "[]"))
        self._clear_receipt()
        self.adjustSize()
        if near is not None:
            self._place_beside(near)
        self.show()
        self.raise_()
        self.activateWindow()
        self.setFocus(Qt.FocusReason.OtherFocusReason)

    def attach_detail(self, payload: dict):
        """A richer payload for the event already on screen.

        Only ever ADDS. The card is complete without this — a customer's SDK
        sends nothing more than the ping — so a sender that has hashes to offer
        may enrich the card, and one that does not changes nothing.
        """
        if not self.isVisible():
            return False
        self._clear_receipt()
        self._receipt = GuardReceipt(payload)
        self.receipt_slot.addWidget(self._receipt)
        self.adjustSize()
        return True

    def _clear_receipt(self):
        if self._receipt is not None:
            self.receipt_slot.removeWidget(self._receipt)
            self._receipt.setParent(None)
            self._receipt.deleteLater()
            self._receipt = None

    def _place_beside(self, widget: QWidget):
        screen = QApplication.primaryScreen().availableGeometry()
        x = widget.x() - self.width() - 14
        if x < screen.x():
            x = min(widget.x() + widget.width() + 14,
                    screen.right() - self.width() - 8)
        y = max(screen.y() + 8,
                min(widget.y(), screen.bottom() - self.height() - 8))
        self.move(int(x), int(y))

    # -- actions ------------------------------------------------------------
    def dismiss(self):
        self.hide()
        self.dismissed.emit()

    def _open_console(self):
        self.hide()
        self.console_requested.emit()

    def keyPressEvent(self, event):
        if event.key() == Qt.Key.Key_Escape:
            self.dismiss()
        else:
            super().keyPressEvent(event)
