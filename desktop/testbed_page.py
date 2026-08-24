"""Foxy Audit desktop — the Compliance Testbed page (T3).

The third rendering of the same `foxy_testbed` Turn the REPL (T1) and the local
web page (T2) already render. Type a prompt; watch `foxy_audit`'s real preflight
guard decide what happens to it BEFORE any model is called.

THE THESIS, CARRIED OVER FROM THE WEB PAGE
==========================================
The most persuasive screen here is the one where nothing happened. This page
refuses the category default — a chat window with a red "blocked" banner —
because the product's claim is not that text turns red, it is that a call was
never made. So the blocked turn is the FULLEST state on the page, not the
degraded one: it is the only one that fills in "kept back", breaks the delivery
rail with a drawn cross, and says in words that the provider was never called.

WHAT THIS PAGE DECIDES: NOTHING
===============================
`core.py` holds the engine, `cli._headline` holds the verdict wording, and
`testbed_data` holds the shaping. This module builds widgets and paints. The one
thing it chooses is which of four colours a verdict wears, and `family_of` takes
that from the record's MEASURED properties rather than from its label — the same
rule, in the same order, the web page's `familyOf` uses.

⚠ NOT THE SANDBOX PAGE. `dashboard._page_sandbox` is the VERIFICATION sandbox:
paste a prompt and a response, hash them locally, compare to the ledger. This is
the assistant. They are one row apart in the sidebar and must not read alike.

THREADING
=========
`Assistant.ask` is a network call whenever a live provider is selected, so it
runs on a :class:`TurnWorker` and the composer is dead while it is in flight.
The lock is a FLAG, not the button's `disabled`: Ctrl+Enter reaches `_send`
without ever looking at the button, and on a live provider a double entrance
means a second billed call.
"""

from __future__ import annotations

from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QBrush, QColor, QPainter, QPen
from PyQt6.QtWidgets import (
    QApplication, QButtonGroup, QComboBox, QFrame, QHBoxLayout, QLabel,
    QPushButton, QScrollArea, QSizePolicy, QTextEdit, QVBoxLayout, QWidget,
)

import panel_state
import testbed_data as tbd
from foxy_tokens import (
    BAD_RED, DARK_TX, INFO_BLUE, OK_GREEN, RADIUS, WARN_AMBER, WEB, pick_font,
)
from home_page import _card, _label, scroll_qss, seg_button, seg_container
from verify_page import ResultPanel

#: The four verdict families, in `foxy_tokens`' own status palette. NO NEW
#: COLOUR: every one is a token the console already paints elsewhere.
#:
#: ⚠ `enforced` IS THE ONE DIVERGENCE FROM THE WEB PAGE, which uses a lavender
#: (#c9b7ff) that has no counterpart here. `INFO_BLUE` is the desktop status
#: palette's fourth member — the "neither good nor bad" one — which is exactly
#: what an enforced turn is: the guard worked, and that is not a success message
#: and not a failure. Borrowing a categorical CHART colour instead would put a
#: series hue into a status vocabulary, which is the worse of the two.
#:
#: Measured against WEB["surf"], the card behind them, and NOT only against
#: their own ink — the check a chip usually fails:
#:   allowed  9.74:1   enforced  5.49:1   flagged 11.24:1   fault  5.31:1
#: and DARK_TX on each fill: 10.75 / 6.06 / 12.40 / 5.86.
FAMILY_FILL = {
    tbd.FAMILY_ALLOWED:  OK_GREEN,
    tbd.FAMILY_ENFORCED: INFO_BLUE,
    tbd.FAMILY_FLAGGED:  WARN_AMBER,
    tbd.FAMILY_FAULT:    BAD_RED,
}

#: The rail is 480×46 in the web page's viewBox; these are its node centres as
#: fractions of the width, so the drawing scales with the card instead of
#: clipping.
_RAIL_STOPS = (0.125, 0.375, 0.625, 0.875)
_RAIL_HEIGHT = 46
_NODE_R = 6


# ── the composer ─────────────────────────────────────────────────────────────
class PromptBox(QTextEdit):
    """The prompt field. Ctrl/⌘+Enter sends; Enter is a newline.

    A prompt is often several lines — a system-prompt injection attempt usually
    is — so Enter must not submit. The shortcut is stated beside the button
    rather than left to be discovered.
    """

    submitted = pyqtSignal()

    def keyPressEvent(self, event):
        if (event.key() in (Qt.Key.Key_Return, Qt.Key.Key_Enter)
                and event.modifiers() & (Qt.KeyboardModifier.ControlModifier
                                         | Qt.KeyboardModifier.MetaModifier)):
            self.submitted.emit()
            event.accept()
            return
        super().keyPressEvent(event)


class TurnWorker(QThread):
    """One `Assistant.ask` off the GUI thread.

    ⚠ THE MOCK PROVIDER IS INSTANT AND THAT IS NOT THE CASE THIS EXISTS FOR. A
    live provider is an HTTPS round trip, and running it on the GUI thread
    freezes the whole console — every other page, the tray, the fox's own
    window — for as long as OpenAI takes.

    `ask` never raises: the engine catches a failed provider and returns a Turn
    stamped `error`, which is a better answer than an exception because it still
    reports what the guard did. `failed` is therefore for the unreachable case
    only, and it carries a string — see `foxy_client.ApiWorker` on why the
    payload across this boundary is kept simple.
    """

    finished_turn = pyqtSignal(object)
    failed = pyqtSignal(str)

    def __init__(self, assistant, prompt: str, parent=None):
        super().__init__(parent)
        self._assistant = assistant
        self._prompt = prompt

    def run(self):
        try:
            self.finished_turn.emit(self._assistant.ask(self._prompt))
        except Exception as exc:                      # noqa: BLE001
            self.failed.emit("{0}: {1}".format(type(exc).__name__, exc))


# ── the delivery rail ────────────────────────────────────────────────────────
class DeliveryRail(QWidget):
    """Where the prompt got to: four points, three segments, drawn.

    ⚠ IT IS NOT IN THE ACCESSIBILITY TREE, ON PURPOSE. Every fact it draws —
    `reached_provider`, `prompt_changed`, `answered` — is also printed in words
    in the field list directly beneath it, so a reader who cannot see it loses
    nothing, and announcing it twice would only be noise. It is a second
    ENCODING, not a second source.

    A break is a SHAPE — two crossed strokes where the line stops — because
    colour alone never carries a state on this surface.
    """

    def __init__(self, state: dict, family: str, parent=None):
        super().__init__(parent)
        self._state = state
        self._family = family
        self.setFixedHeight(_RAIL_HEIGHT)
        self.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.setSizePolicy(QSizePolicy.Policy.Expanding,
                           QSizePolicy.Policy.Fixed)

    def _stroke(self, name: str) -> QColor:
        return QColor({"on": OK_GREEN, "changed": INFO_BLUE}.get(
            name, WEB["muted"]))

    def paintEvent(self, _event):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        w = max(self.width(), 1)
        y = 17
        xs = [w * f for f in _RAIL_STOPS]

        for index, name in enumerate(self._state["segments"]):
            pen = QPen(self._stroke(name), 3)
            pen.setCapStyle(Qt.PenCapStyle.RoundCap)
            if name == "changed":
                pen.setDashPattern([3.0, 2.4])
            elif name == "off":
                pen.setDashPattern([0.7, 2.7])
            p.setPen(pen)
            p.drawLine(int(xs[index] + _NODE_R + 2), y,
                       int(xs[index + 1] - _NODE_R - 2), y)

        for index, name in enumerate(self._state["nodes"]):
            fill = {"on": OK_GREEN, "changed": INFO_BLUE,
                    "fault": BAD_RED}.get(name, WEB["surf2"])
            edge = WEB["muted"] if name == "idle" else fill
            p.setPen(QPen(QColor(edge), 2))
            p.setBrush(QBrush(QColor(fill)))
            p.drawEllipse(int(xs[index]) - _NODE_R, y - _NODE_R,
                          _NODE_R * 2, _NODE_R * 2)

        break_colour = QColor(BAD_RED if self._family == tbd.FAMILY_FAULT
                              else INFO_BLUE)
        pen = QPen(break_colour, 3)
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        p.setPen(pen)
        p.setBrush(Qt.BrushStyle.NoBrush)
        for index, broken in enumerate(self._state["breaks"]):
            if not broken:
                continue
            cx = int((xs[index + 1] + xs[index + 2]) / 2)
            p.drawLine(cx - 6, y - 7, cx + 6, y + 7)
            p.drawLine(cx + 6, y - 7, cx - 6, y + 7)
        p.end()


def _rail_labels() -> QWidget:
    row = QWidget()
    lay = QHBoxLayout(row)
    lay.setContentsMargins(0, 2, 0, 0)
    lay.setSpacing(0)
    for text in tbd.RAIL_LABELS:
        cell = _label(text, size=9.5, colour=WEB["muted"])
        cell.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lay.addWidget(cell, 1)
    return row


# ── one record ───────────────────────────────────────────────────────────────
def record_card(turn) -> QWidget:
    """One turn, rendered. Everything it says is read off the record.

    NEWEST FIRST in the stream above, which is not the chat convention and is
    deliberate: you type at the TOP of this column, so the verdict for what you
    just sent belongs where you are already looking rather than a scroll away.
    """
    family = tbd.family_of(turn)
    fill = FAMILY_FILL[family]
    card, lay = _card()
    card.setProperty("turnFamily", family)
    card.setProperty("turnDecision", turn.decision)

    label, note = _headline_of(turn)

    verdict = QHBoxLayout()
    verdict.setSpacing(10)
    # No wrap: a wrapped QLabel claims the full row and the pill stops hugging
    # its word. The longest headline the engine can produce is "RESPONSE
    # WITHHELD, BUT NOTHING WAS SENT", which fits a card at this size.
    mark = _label(label, size=13, bold=True, colour=DARK_TX)
    mark.setStyleSheet(mark.styleSheet()
                       + f"background: {fill}; border-radius: 7px;"
                       f" padding: 5px 11px;")
    verdict.addWidget(mark, 0, Qt.AlignmentFlag.AlignTop)
    # The SDK's own stamp, beside the measured word and visibly a different kind
    # of thing: the label says what the policy evaluation concluded, the word
    # beside it says what was observed. Where they can disagree this card shows
    # both rather than picking a winner.
    stamp = QWidget()
    stamp_lay = QHBoxLayout(stamp)
    stamp_lay.setContentsMargins(0, 0, 0, 0)
    stamp_lay.setSpacing(5)
    stamp_lay.addWidget(_label("the SDK stamped this turn", size=10.5,
                               colour=WEB["muted"]))
    stamp_lay.addWidget(_label(turn.decision, size=10.5, bold=True, mono=True))
    stamp_lay.addStretch()
    verdict.addWidget(stamp, 1, Qt.AlignmentFlag.AlignVCenter)
    lay.addLayout(verdict)
    lay.addWidget(_label(note, size=11, colour=WEB["muted"], wrap=True))

    lay.addWidget(DeliveryRail(tbd.rail_state(turn), family))
    lay.addWidget(_rail_labels())
    lay.addWidget(_divider())

    fields = QWidget()
    grid = QVBoxLayout(fields)
    grid.setContentsMargins(0, 0, 0, 0)
    grid.setSpacing(6)
    for name, value, opts in tbd.field_rows(turn):
        grid.addWidget(_field_row(name, value, opts))
    lay.addWidget(fields)

    if turn.answered:
        lay.addWidget(_reply_box(turn))
    else:
        # What did NOT happen, stated rather than left blank. A blocked turn is
        # where this surface earns its keep and the absence is the content.
        lay.addWidget(_inset(tbd.reply_status(turn)))
    return card


def _headline_of(turn) -> tuple:
    """The verdict word and its sentence, from the engine — never from here.

    Reaching for `cli`'s private `_headline` is deliberate and has precedent:
    `foxy_testbed.web` imports the same name for the same reason. A Qt copy of
    that function would be the third, and the one nobody runs the engine's own
    tests against.
    """
    engine, problem = tbd.load_engine()
    if engine is None:                                # unreachable from a Turn
        return (str(turn.decision).upper(), problem)
    return engine.cli._headline(turn)


def _field_row(name: str, value: str, opts: dict) -> QWidget:
    row = QWidget()
    lay = QHBoxLayout(row)
    lay.setContentsMargins(0, 0, 0, 0)
    lay.setSpacing(14)
    loud = bool(opts.get("loud"))
    key = _label(name, size=10.5, bold=loud,
                 colour=BAD_RED if loud else WEB["muted"])
    key.setFixedWidth(96)
    key.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop)
    lay.addWidget(key)
    lay.addWidget(_label(value, size=10.5, bold=loud,
                         colour=BAD_RED if loud else WEB["ink"],
                         mono=bool(opts.get("mono")), wrap=True), 1)
    return row


def _reply_box(turn) -> QWidget:
    frame = QFrame()
    frame.setObjectName("tbInset")
    frame.setStyleSheet(_inset_qss())
    lay = QVBoxLayout(frame)
    lay.setContentsMargins(14, 12, 14, 12)
    lay.setSpacing(7)
    # The provenance rides on every reply, not only on the rail panel: a session
    # is long, the panel scrolls away, and "is this thing making up answers?" is
    # the question asked on turn nine, not turn one.
    lay.addWidget(_label(tbd.reply_source(turn), size=10, colour=WEB["muted"]))
    for paragraph in str(turn.reply).split("\n\n"):
        if paragraph.strip():
            lay.addWidget(_label(paragraph.strip(), size=11, wrap=True))
    return frame


def _inset(text: str) -> QWidget:
    frame = QFrame()
    frame.setObjectName("tbInset")
    frame.setStyleSheet(_inset_qss())
    lay = QVBoxLayout(frame)
    lay.setContentsMargins(14, 12, 14, 12)
    lay.addWidget(_label(text, size=11, colour=WEB["muted"], wrap=True))
    return frame


def _inset_qss() -> str:
    return (f"QFrame#tbInset {{ background: {WEB['surf2']};"
            f" border: 2px solid {WEB['bc']};"
            f" border-radius: {RADIUS['sm']}px; }}")


def _divider() -> QFrame:
    line = QFrame()
    line.setObjectName("tbDivider")
    line.setFixedHeight(2)
    line.setStyleSheet(f"QFrame#tbDivider {{ background: {WEB['bc']};"
                       f" border: none; }}")
    return line


def _combo_qss() -> str:
    return (f"QComboBox {{ background: {WEB['surf2']}; color: {WEB['ink']};"
            f" border: 2.5px solid {WEB['bc']}; border-radius: {RADIUS['sm']}px;"
            f" padding: 6px 10px; font-family: '{pick_font('mono')}';"
            f" font-size: 11px; }}"
            f"QComboBox:focus {{ border-color: {WEB['fox']}; }}"
            f"QComboBox::drop-down {{ border: none; width: 18px; }}"
            f"QComboBox QAbstractItemView {{ background: {WEB['surf']};"
            f" color: {WEB['ink']}; border: 2px solid {WEB['bc']};"
            f" selection-background-color: {WEB['fox']};"
            f" selection-color: {DARK_TX}; outline: none; }}")


def _prompt_qss() -> str:
    return (f"QTextEdit {{ background: {WEB['surf2']}; color: {WEB['ink']};"
            f" border: 2.5px solid {WEB['bc']}; border-radius: {RADIUS['sm']}px;"
            f" padding: 10px 12px; font-family: '{pick_font('disp')}';"
            f" font-size: 12px; }}"
            f"QTextEdit:focus {{ border-color: {WEB['fox']}; }}"
            f"QTextEdit:disabled {{ color: {WEB['muted2']}; }}")


# ── the page ─────────────────────────────────────────────────────────────────
class TestbedSections:
    """Builds the Testbed page onto `owner` (the DashboardWindow)."""

    def __init__(self, owner):
        self.o = owner
        self.engine = None
        self.problem = ""
        #: (sector, mode, provider) → Assistant. One per combination, and a mode
        #: switch goes through `Assistant.with_mode` rather than a fresh build:
        #: rebuilding from sector/mode/provider alone is how T1's REPL silently
        #: swapped a keyed session's client for a keyless one.
        self._assistants: dict = {}
        #: provider name → fingerprint of the key its cached Assistants were
        #: built with. A digest, never the key — see `tbd.key_fingerprint`.
        self._key_fps: dict = {}
        self._worker = None
        self._turns = 0

    # ── build ──
    def build(self, t: dict) -> QWidget:
        o = self.o
        # ⚠ THE IMPORT LIVES HERE, INSIDE THE BUILD, INSIDE A TRY. At module
        # scope it takes the whole console down on any checkout that has not
        # installed the SDK — which, before T3, was every one of them.
        self.engine, self.problem = tbd.load_engine()

        page = QWidget()
        outer = QVBoxLayout(page)
        outer.setContentsMargins(0, 0, 0, 0)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setStyleSheet(scroll_qss())
        body = QWidget()
        body.setObjectName("pageBody")
        body.setStyleSheet("QWidget#pageBody { background: transparent; }")
        v = QVBoxLayout(body)
        v.setContentsMargins(22, 18, 22, 22)
        v.setSpacing(16)

        v.addWidget(self._head())
        if self.engine is None:
            v.addWidget(self._not_installed())
        else:
            v.addLayout(self._work_and_rail())
        v.addStretch()

        scroll.setWidget(body)
        outer.addWidget(scroll)
        o.tb_scroll = scroll
        # ⚠ HERE, AND NOT IN `_work`. Everything above is parented now — `body`
        # owns the layouts, `scroll` owns `body` — so setting the empty state
        # visible shows a card inside a page. Run one line earlier, when the
        # column was still detached, the same call mapped a top-level window.
        if self.engine is not None:
            self._after_stream_change()
        return page

    def _head(self) -> QWidget:
        row = QWidget()
        lay = QVBoxLayout(row)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(3)
        lay.addWidget(_label("● TRY THE GUARD", size=10, bold=True,
                             colour=WEB["fox2"], mono=True, spacing=1.5))
        lay.addWidget(_label("Send a prompt through the real guard.", size=26,
                             bold=True))
        lay.addWidget(_label(
            "The same foxy_audit preflight check your SDK runs, in front of a "
            "sector assistant. Nothing you type here leaves this machine unless "
            "you pick a live provider and supply your own key.",
            size=12, colour=WEB["muted"], wrap=True))
        return row

    # ── the honest state when the SDK is not there ──
    def _not_installed(self) -> QWidget:
        """⚠ NOT A DISABLED BUTTON AND NOT A SPINNER. Both of those imply the
        page is one click or one moment from working; it is one install away,
        and saying so is the only useful thing this state can do."""
        card, lay = _card()
        lay.addWidget(_label(tbd.MISSING_TITLE, size=15, bold=True))
        lay.addWidget(_label(tbd.MISSING_BODY, size=11.5, colour=WEB["muted"],
                             wrap=True))
        fix = _label(tbd.MISSING_FIX, size=11.5, mono=True)
        fix.setStyleSheet(fix.styleSheet()
                          + f"background: {WEB['surf2']};"
                          f" border: 2px solid {WEB['bc']};"
                          f" border-radius: {RADIUS['sm']}px; padding: 9px 11px;")
        lay.addWidget(fix)
        lay.addWidget(_label(tbd.MISSING_AFTER, size=11.5, colour=WEB["muted"],
                             wrap=True))
        # The real reason, verbatim and unglossed. A reader debugging a broken
        # install needs the exception, not our paraphrase of it.
        lay.addWidget(_label("Python said: " + self.problem, size=10,
                             colour=WEB["muted"], mono=True, wrap=True))
        self.o.tb_missing = card
        return card

    # ── the working page ──
    def _work_and_rail(self) -> QHBoxLayout:
        row = QHBoxLayout()
        row.setSpacing(16)
        # ⚠ THE WORK COLUMN IS BUILT FIRST AND ADDED FIRST, and both halves of
        # that matter. Tab order follows creation order and reading order
        # follows layout order, so building the settings rail first would give a
        # keyboard user four panels of configuration before the prompt box —
        # the task, buried under its own settings. `test_d15_a11y` pins the two
        # orders against each other on every page.
        row.addLayout(self._work(), 1)
        row.addWidget(self._rail(), 0)
        return row

    def _work(self) -> QVBoxLayout:
        o = self.o
        col = QVBoxLayout()
        col.setSpacing(16)

        card, lay = _card()
        prompt_label = _label("Prompt", size=11.5, bold=True)
        lay.addWidget(prompt_label)
        o.tb_prompt = PromptBox()
        # The visible label above is enough for a sighted user; a reader needs
        # the tie spelled out. Same shape as auth_windows._Field.
        o.tb_prompt.setAccessibleName("Prompt to send through the guard")
        o.tb_prompt.setPlaceholderText(
            "Type a prompt and send it through the guard.")
        # ⚠ A BAND, NOT A FLOOR. QTextEdit expands in both directions by
        # default, so on a tall window with one record below it the prompt box
        # grew to four hundred-odd pixels and the composer stopped looking like
        # a composer — the same control at two very different sizes depending on
        # how much transcript happened to be under it. The web's textarea is
        # `min-height:118px` and only grows when the user drags it; Qt has no
        # drag handle, so the ceiling stands in for one and a longer prompt
        # scrolls inside, exactly as it does on the web at rest.
        o.tb_prompt.setMinimumHeight(118)
        o.tb_prompt.setMaximumHeight(220)
        # ⚠ AND THE POLICY, WHICH IS THE HALF THAT ACTUALLY DID IT. QTextEdit
        # ships `Expanding` vertically; a widget that ADVERTISES expansion takes
        # a share of the surplus alongside a stretch spacer, so the column's
        # trailing stretch alone left the card at 660px against a 313px hint —
        # measured, after the stretch was already in place. `Preferred` still
        # grows to the ceiling above when there is room and stops asking for it.
        o.tb_prompt.setSizePolicy(QSizePolicy.Policy.Expanding,
                                  QSizePolicy.Policy.Preferred)
        o.tb_prompt.setStyleSheet(_prompt_qss())
        o.tb_prompt.submitted.connect(self.send)
        lay.addWidget(o.tb_prompt)

        foot = QHBoxLayout()
        foot.setSpacing(12)
        foot.addWidget(_label("Ctrl + Enter sends", size=10,
                              colour=WEB["muted"], mono=True))
        foot.addStretch()
        o.tb_send = QPushButton("Send prompt")
        o.tb_send.setObjectName("ctaBtn")
        o.tb_send.setMinimumHeight(44)
        o.tb_send.setCursor(Qt.CursorShape.PointingHandCursor)
        o.tb_send.clicked.connect(self.send)
        foot.addWidget(o.tb_send)
        lay.addLayout(foot)
        col.addWidget(card)

        # Errors name the problem and the recovery. A turn that failed here
        # proved nothing about the guard, and saying so beats a red box.
        o.tb_problem = ResultPanel()
        col.addWidget(o.tb_problem)

        stream = QWidget()
        o.tb_stream = QVBoxLayout(stream)
        o.tb_stream.setContentsMargins(0, 0, 0, 0)
        o.tb_stream.setSpacing(16)
        col.addWidget(stream)

        empty, empty_lay = _card()
        empty_lay.addWidget(_label("Nothing has been sent yet.", size=13,
                                   bold=True))
        empty_lay.addWidget(_label(
            "Type a prompt above, or start from one of this sector's labelled "
            "probes. Every turn is decided by the same foxy_audit preflight "
            "guard an installed SDK runs — there is no separate demo policy.",
            size=11, colour=WEB["muted"], wrap=True))
        o.tb_empty = empty
        col.addWidget(empty)

        stream_foot = QWidget()
        sf = QHBoxLayout(stream_foot)
        sf.setContentsMargins(0, 0, 0, 0)
        sf.setSpacing(12)
        o.tb_count = _label("", size=10, colour=WEB["muted"], mono=True)
        sf.addWidget(o.tb_count)
        sf.addStretch()
        o.tb_clear = QPushButton("Clear transcript")
        o.tb_clear.setObjectName("ghostBtn")
        o.tb_clear.setMinimumHeight(38)
        o.tb_clear.setCursor(Qt.CursorShape.PointingHandCursor)
        o.tb_clear.clicked.connect(self.clear_transcript)
        sf.addWidget(o.tb_clear)
        o.tb_stream_foot = stream_foot
        col.addWidget(stream_foot)
        # ⚠ THE COLUMN TAKES THE SLACK, NOT THE COMPOSER. The rail beside this
        # is four cards tall, so the row is as tall as the rail — and without
        # somewhere for the difference to go, the composer card swallowed it and
        # the prompt box rendered at four hundred-odd pixels with its own label
        # stranded halfway down. The rail already ends in one; so does this.
        col.addStretch()
        # ⚠ NO `_after_stream_change()` HERE, AND THAT IS THE WHOLE FIX. `col`
        # is not attached to anything yet, so `QLayout.addWidget` has not
        # reparented a single one of these widgets — `tb_empty.parentWidget()`
        # is None. Calling `setVisible(True)` on a parentless widget does not
        # "show a card in a column"; it MAPS A TOP-LEVEL WINDOW. Measured on a
        # real window, not offscreen, which cannot see it: at that call
        # `isWindow()` was True and `isVisible()` was True. `build` runs it once
        # the layout is attached instead.
        return col

    def _rail(self) -> QWidget:
        o = self.o
        rail = QWidget()
        rail.setFixedWidth(320)
        lay = QVBoxLayout(rail)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(16)

        card, box = _card()
        box.addWidget(_label("Sector", size=11.5, bold=True))
        seg, seg_lay, group = seg_container()
        o.tb_sector_group = group
        o.tb_sector_buttons = []
        for index, name in enumerate(self.engine.sectors.SECTOR_NAMES):
            btn = seg_button(name, accessible=f"Use the {name} preset")
            btn.setChecked(index == 0)
            btn.clicked.connect(lambda _c, n=name: self.choose_sector(n))
            group.addButton(btn, index)
            seg_lay.addWidget(btn)
            o.tb_sector_buttons.append(btn)
        box.addWidget(seg)
        o.tb_sector_title = _label("", size=10.5, colour=WEB["muted"],
                                   wrap=True)
        box.addWidget(o.tb_sector_title)

        box.addWidget(_label("Preflight mode", size=11.5, bold=True))
        o.tb_mode = QComboBox()
        o.tb_mode.setAccessibleName("Preflight mode")
        o.tb_mode.setMinimumHeight(44)
        o.tb_mode.setCursor(Qt.CursorShape.PointingHandCursor)
        o.tb_mode.setStyleSheet(_combo_qss())
        for name in self.engine.core.MODES:
            o.tb_mode.addItem(name, name)
        o.tb_mode.setCurrentText(self.engine.core.DEFAULT_MODE)
        o.tb_mode.currentIndexChanged.connect(lambda _i: self.choose_mode())
        box.addWidget(o.tb_mode)
        o.tb_mode_hint = _label("", size=10, colour=WEB["muted"], wrap=True)
        box.addWidget(o.tb_mode_hint)
        lay.addWidget(card)

        card2, box2 = _card()
        box2.addWidget(_label("Provider", size=11.5, bold=True))
        o.tb_provider = QComboBox()
        o.tb_provider.setAccessibleName("Model provider")
        o.tb_provider.setMinimumHeight(44)
        o.tb_provider.setCursor(Qt.CursorShape.PointingHandCursor)
        o.tb_provider.setStyleSheet(_combo_qss())
        for name in self.engine.providers.PROVIDER_NAMES:
            o.tb_provider.addItem(name, name)
        o.tb_provider.currentIndexChanged.connect(lambda _i: self.choose_provider())
        box2.addWidget(o.tb_provider)
        o.tb_provider_model = _label("", size=10, colour=WEB["muted"],
                                     mono=True, wrap=True)
        box2.addWidget(o.tb_provider_model)
        o.tb_provider_note = _label("", size=10.5, colour=WEB["muted"],
                                    wrap=True)
        box2.addWidget(o.tb_provider_note)
        lay.addWidget(card2)

        card3, box3 = _card()
        # wrap=True: at the rail's 320px this heading is clipped mid-word
        # without it, and a heading that ends in "and what" is worse than none.
        box3.addWidget(_label("What this preset enforces, and what it does not",
                              size=11.5, bold=True, wrap=True))
        o.tb_policy_note = _label("", size=10.5, colour=WEB["muted"], wrap=True)
        box3.addWidget(o.tb_policy_note)
        o.tb_policy_tag = _label("", size=10, colour=WEB["ink"], mono=True)
        box3.addWidget(o.tb_policy_tag)
        lay.addWidget(card3)

        card4, box4 = _card()
        box4.addWidget(_label("Start from a probe", size=11.5, bold=True))
        box4.addWidget(_label(
            "This sector's own labelled corpus — the same prompts the "
            "scoreboard scores. Each one says what it is for.",
            size=10.5, colour=WEB["muted"], wrap=True))
        probes = QWidget()
        o.tb_probes = QVBoxLayout(probes)
        o.tb_probes.setContentsMargins(0, 0, 0, 0)
        o.tb_probes.setSpacing(8)
        box4.addWidget(probes)
        lay.addWidget(card4)
        lay.addStretch()

        self._sector = self.engine.sectors.SECTOR_NAMES[0]
        self._mode = self.engine.core.DEFAULT_MODE
        self._provider = self.engine.providers.PROVIDER_NAMES[0]
        self._paint_sector()
        self._paint_mode()
        self._paint_provider()
        return rail

    # ── painting the rail's panels ──
    def _paint_sector(self):
        o = self.o
        sector = self.engine.sectors.get_sector(self._sector)
        o.tb_sector_title.setText(sector.title)
        o.tb_policy_note.setText(sector.policy_note)
        o.tb_policy_tag.setText("policy_tag = " + sector.policy_tag)

        panel_state.clear_rows(o.tb_probes)
        # Rebuilt every time the sector changes, so the list `_set_busy` reaches
        # for is rebuilt with them rather than left pointing at deleted buttons.
        o.tb_probe_buttons = []
        for probe in sector.probes:
            button = self._probe_button(probe)
            # A sector switch is itself disabled mid-flight, so this cannot
            # normally run while busy — it is set from the live state anyway,
            # because a control that decides its own enabledness from a
            # constant is one refactor away from being wrong.
            button.setEnabled(self._worker is None)
            o.tb_probe_buttons.append(button)
            panel_state.add_visible(o.tb_probes, button)
        o.tb_probes.activate()

    def _probe_button(self, probe) -> QWidget:
        button = QPushButton()
        button.setObjectName("tbProbe")
        button.setCursor(Qt.CursorShape.PointingHandCursor)
        button.setMinimumHeight(44)
        button.setAccessibleName("Load the probe " + probe.id)
        button.setStyleSheet(
            f"QPushButton#tbProbe {{ background: transparent;"
            f" border: 2px solid {WEB['bc']};"
            f" border-radius: {RADIUS['sm']}px; padding: 8px 10px;"
            f" text-align: left; }}"
            f"QPushButton#tbProbe:hover {{ background: {WEB['surf2']}; }}"
            f"QPushButton#tbProbe:focus {{ border-color: {WEB['fox']}; }}"
            f"QPushButton#tbProbe:disabled {{ border-color: {WEB['line']}; }}")
        lay = QVBoxLayout(button)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(2)
        for text, size, colour, mono in ((probe.id, 9.5, WEB["muted"], True),
                                         (probe.intent, 10.5, WEB["ink"], False)):
            # ⚠ THE LABELS NEED THE `:disabled` RULE THEMSELVES. `setEnabled`
            # propagates to children, but an explicit `color:` on a child does
            # not yield to it — so disabling a probe starter left it looking
            # exactly as clickable as before, which is worse than leaving it
            # live. `muted2` is the console's disabled colour (`#ctaBtn`,
            # `#segBtn`) and this is the one use WCAG 1.4.3 exempts.
            line = _label(text, size=size, colour=colour, mono=mono,
                          wrap=not mono)
            line.setStyleSheet(
                f"QLabel {{ {line.styleSheet()} }}"
                f"QLabel:disabled {{ color: {WEB['muted2']}; }}")
            lay.addWidget(line)
        button.clicked.connect(lambda _c, p=probe: self._load_probe(p))
        return button

    def _load_probe(self, probe):
        self.o.tb_prompt.setPlainText(probe.prompt)
        self.o.tb_prompt.setFocus()

    def _paint_mode(self):
        # The one place this page states something the engine did not, and it is
        # a restatement of what the engine already refuses to hide: under
        # observe the guard records and never prevents. `scoreboard.render`
        # prints the same caveat above a 0/N enforcement column.
        self.o.tb_mode_hint.setText(
            "observe records and never prevents. Prompts are delivered exactly "
            "as typed." if self._mode == "observe" else "")

    def _paint_provider(self):
        o = self.o
        try:
            assistant = self._assistant()
        except Exception as exc:                      # noqa: BLE001
            o.tb_provider_model.setText("")
            o.tb_provider_note.setText("")
            self._show_problem("This provider is not ready.", str(exc))
            return
        o.tb_provider_model.setText("model  " + assistant.provider.model)
        # The mock's note is the sentence every surface must render beside its
        # replies; a live provider's note says where the text goes. Both come
        # from providers.py, so this page writes neither.
        o.tb_provider_note.setText(assistant.provider.note)
        o.tb_problem.clear()

    # ── choices ──
    def choose_sector(self, name: str):
        self._sector = name
        self._paint_sector()
        self._paint_provider()

    def choose_mode(self):
        self._mode = self.o.tb_mode.currentData()
        self._paint_mode()
        self._paint_provider()

    def choose_provider(self):
        self._provider = self.o.tb_provider.currentData()
        self._paint_provider()

    # ── the assistant ──
    def _assistant(self):
        """The Assistant for the current (sector, mode, provider), built once.

        ⚠ A LIVE PROVIDER'S KEY IS CHECKED HERE, BEFORE THE PROMPT. `providers`
        raises a ProviderError naming `--api-key`, which is a CLI flag this
        surface does not have — so the missing key is caught first and the
        message names where a key actually goes on THIS surface.

        ⚠ AND IT IS RE-READ ON EVERY CALL, WHICH IS WHY THE CACHE IS CONSULTED
        SECOND. It used to be consulted first, so the key that happened to be in
        the keychain when the first Assistant for a combination was built stayed
        pinned for the life of the window: a user whose key had been revoked,
        who then pasted a working one into Settings, kept failing every turn
        until they restarted the console — and nothing on the page could have
        told them why.
        """
        api_key = ""
        if tbd.provider_needs_key(self._provider):
            api_key = tbd.provider_key(
                self._provider, getattr(self.o, "settings", None))
            if not api_key:
                raise RuntimeError(tbd.no_key_message(self._provider))

        # A CHANGED KEY EVICTS; it does not merely miss. Putting the fingerprint
        # in the cache key instead would leave the old Assistant — and the
        # revoked credential inside its provider — alive in this dict for the
        # rest of the session, which is the wrong way to hold a secret you have
        # just been told is dead.
        fingerprint = tbd.key_fingerprint(api_key)
        if self._key_fps.get(self._provider) != fingerprint:
            self._assistants = {k: v for k, v in self._assistants.items()
                                if k[2] != self._provider}
            self._key_fps[self._provider] = fingerprint

        key = (self._sector, self._mode, self._provider)
        found = self._assistants.get(key)
        if found is not None:
            return found

        sibling = self._assistants.get(
            (self._sector, self.engine.core.DEFAULT_MODE, self._provider))
        if sibling is not None:
            # `with_mode` hands over the already-built provider AND client, so
            # nothing a mode switch could drop is rebuilt from arguments.
            found = sibling.with_mode(self._mode)
        else:
            # ⚠ `desktop_ping` IS LEFT AT ITS DEFAULT, WHICH IS False. Turning
            # it on would make the fox react to a demo the user is driving — a
            # fox reaction is a claim about a real event — and would push
            # invented rows into the console's own live-capture table.
            found = self.engine.core.Assistant(
                self._sector, mode=self._mode, provider=self._provider,
                api_key=api_key)
        self._assistants[key] = found
        return found

    # ── sending ──
    def send(self):
        o = self.o
        # ⚠ GATED ON THE WORKER, NOT ON THE BUTTON'S `disabled`. Ctrl+Enter
        # reaches this method directly, so disabling the button locks one
        # entrance and leaves the other open — and on a live provider a second
        # entrance is a second billed call.
        if self._worker is not None:
            return
        text = o.tb_prompt.toPlainText()
        if not text.strip():
            return
        if len(text) > tbd.MAX_PROMPT_CHARS:
            self._show_problem(
                "That prompt is too long to send.",
                f"The testbed accepts {tbd.MAX_PROMPT_CHARS:,} characters and "
                f"this one is {len(text):,}. Nothing was sent.")
            return
        try:
            assistant = self._assistant()
        except Exception as exc:                      # noqa: BLE001
            self._show_problem("This provider is not ready.", str(exc))
            return

        o.tb_problem.clear()
        self._set_busy(True)
        worker = TurnWorker(assistant, text, parent=o)
        worker.finished_turn.connect(self._on_turn)
        worker.failed.connect(self._on_failed)
        # Released on `finished`, which fires on success AND on failure — a
        # hand-maintained flag cleared only in the success callback is how D3.1
        # froze its banner for the rest of the session.
        worker.finished.connect(self._release)
        self._worker = worker
        getattr(o, "_testbed_workers", set()).add(worker)
        worker.start()

    def _release(self):
        worker, self._worker = self._worker, None
        self._set_busy(False)
        if worker is not None:
            getattr(self.o, "_testbed_workers", set()).discard(worker)
            worker.deleteLater()

    def _set_busy(self, busy: bool):
        """The whole composer, not just the button.

        ⚠ THE PROBE BUTTONS ARE PART OF THE COMPOSER. They were left live while
        everything around them went dead, so a probe clicked mid-flight wrote
        its prompt into a DISABLED box — and `_on_turn` then cleared that box
        the moment the turn returned. The staged prompt vanished with no error
        and no way to tell it had ever been staged.

        ⚠ AND THE FOCUS IS RESTORED ONLY IF NOBODY ELSE MOVED IT. This docstring
        used to promise that and the code did not check: it remembered only
        whether the prompt box had focus BEFORE the send, so a user who tabbed
        to the sidebar mid-flight was yanked back to the composer when the turn
        landed. Qt hands focus onward when it disables the focused widget, so
        wherever it parks is the "nobody touched it" reading; anything else is
        the user, and the user wins.
        """
        o = self.o
        if busy:
            self._had_focus = o.tb_prompt.hasFocus()
        o.tb_send.setEnabled(not busy)
        o.tb_send.setText("Sending…" if busy else "Send prompt")
        o.tb_prompt.setEnabled(not busy)
        for button in o.tb_sector_buttons:
            button.setEnabled(not busy)
        for button in getattr(o, "tb_probe_buttons", ()):
            button.setEnabled(not busy)
        o.tb_mode.setEnabled(not busy)
        o.tb_provider.setEnabled(not busy)
        if busy:
            self._focus_parked = QApplication.focusWidget()
            return
        if tbd.should_restore_focus(getattr(self, "_had_focus", False),
                                    getattr(self, "_focus_parked", None),
                                    QApplication.focusWidget()):
            o.tb_prompt.setFocus()

    def _on_turn(self, turn):
        o = self.o
        panel_state.insert_visible(o.tb_stream, 0, record_card(turn))
        o.tb_prompt.setPlainText("")
        self._turns += 1
        self._after_stream_change()

    def _on_failed(self, message: str):
        self._show_problem(
            "Could not run that turn.",
            message + " Nothing was recorded for it, and it says nothing about "
            "what the guard would have done. Your prompt is still in the box.")

    def _show_problem(self, title: str, detail: str):
        self.o.tb_problem.show_result("bad", title, detail)

    def clear_transcript(self):
        o = self.o
        panel_state.clear_rows(o.tb_stream)
        self._turns = 0
        self._after_stream_change()
        o.tb_prompt.setFocus()

    def _after_stream_change(self):
        o = self.o
        o.tb_empty.setVisible(self._turns == 0)
        o.tb_stream_foot.setVisible(self._turns > 0)
        o.tb_count.setText(tbd.transcript_count(self._turns))


__all__ = ["DeliveryRail", "FAMILY_FILL", "PromptBox", "TestbedSections",
           "TurnWorker", "record_card"]
