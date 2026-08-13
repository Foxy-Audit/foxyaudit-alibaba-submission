"""Public-chain anchoring (Phase 3 A1).

Publishes each org's hash-chain head — ``root_hash`` = the latest
``audit_logs.chain_hash`` at ``last_seq`` — to a public chain and records the
receipt in ``chain_anchors``. Once the anchoring tx confirms, any third party
holding the receipt can read the on-chain value and prove the ledger existed in
exactly that state at that block. That makes tampering detectable EXTERNALLY
(after the next anchor), not merely recomputable by us — the whole trust upgrade
over ``/v1/verify`` alone.

Provider is pluggable (config ``anchor_provider``):
  * ``stub``          — deterministic, no external chain (dev / tests / CI).
  * ``evm``           — web3.py -> the AnchorRegistry contract on Sepolia (or any
                        EVM). Configure rpc/key/contract; see contracts/.

TWO CHAINS, ONE PROVIDER (A1)
-----------------------------
This module anchors BOTH hash chains:

  * the CUSTOMER ledger, per org — ``anchor_org`` over ``audit_logs``, receipts
    in ``chain_anchors``;
  * the STAFF audit trail, platform-wide — ``anchor_admin`` over
    ``admin_actions``, receipts in ``admin_chain_anchors``.

They share this file rather than living in a sibling module because the part
that costs money and can leak secrets is the PROVIDER layer — the funded wallet
floor check, the EIP-1559 pricing, and ``_redact``, which keeps an RPC URL's
embedded API key out of a persisted receipt. Two copies of that is two places to
get redaction wrong. The chain-specific halves are small and clearly separated
below; the expensive half is written once.

Framing caution: an anchor makes tampering *externally detectable after the next
anchor*, not impossible. We say "tamper-evident, independently verifiable".

⚠ THAT PHRASE IS THE CEILING, FOR BOTH CHAINS. Anchoring closes #143 (a
truncated tail leaves no trace) and #144 (a wholesale delete self-heals). It
does not make anything immutable, and the word appears nowhere in this codebase
— not about the staff chain and not about the fully-anchored customer ledger.
foxy-sale-page/test_site_wide_claims.py enforces that on every published page.
"""

from __future__ import annotations

import hashlib
import logging
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from . import email, email_templates as et
from .chain import GENESIS_HASH, compute_chain_hash
from .config import Settings, get_settings
from .models import AdminAction, AdminChainAnchor, AuditLog, ChainAnchor, Organization

log = logging.getLogger("foxy.anchor")

# Minimal ABI: anchor(bytes32 root) — the contract emits an event and stores it.
_ANCHOR_ABI = [{
    "inputs": [{"internalType": "bytes32", "name": "root", "type": "bytes32"}],
    "name": "anchor", "outputs": [], "stateMutability": "nonpayable", "type": "function",
}]


@dataclass
class AnchorReceipt:
    chain: str
    status: str                    # confirmed | pending | failed
    tx_hash: str | None = None
    block_number: int | None = None
    detail: str | None = None


# ─────────────────────────────── chain head ──────────────────────────────────

def _scope(db: Session, org_id) -> None:
    db.execute(text("SELECT set_config('app.current_org', :oid, true)"), {"oid": str(org_id)})


def _redact(msg: str, settings: Settings) -> str:
    """Strip known secrets before persisting/logging an error. An RPC URL often
    embeds an API key (e.g. Alchemy /v2/<key>) and can appear in web3 errors, so
    never let it reach chain_anchors.detail (exposed via GET /v1/anchors)."""
    for secret in (settings.anchor_evm_private_key, settings.anchor_evm_rpc_url):
        if secret and secret in msg:
            msg = msg.replace(secret, "<redacted>")
    return msg


def head_of(db: Session, org_id) -> tuple[str | None, int]:
    """Return (chain_head_hash, last_seq) for the org, or (None, 0) if empty.
    The head is simply the stored chain_hash of the highest-seq row."""
    row = db.execute(
        select(AuditLog.chain_hash, AuditLog.seq)
        .where(AuditLog.org_id == org_id)
        .order_by(AuditLog.seq.desc())
        .limit(1)
    ).first()
    if row is None:
        return None, 0
    return row[0], row[1]


def recompute_head(db: Session, org_id, upto_seq: int) -> str | None:
    """Independently recompute the chain hash at ``upto_seq`` from genesis.
    Used by verify_anchor to prove the anchored root matches the ledger — if a
    historical row was altered, this no longer equals the anchored root_hash."""
    rows = db.execute(
        select(AuditLog)
        .where(AuditLog.org_id == org_id, AuditLog.seq <= upto_seq)
        .order_by(AuditLog.seq.asc())
    ).scalars().all()
    prev = GENESIS_HASH
    last = None
    for row in rows:
        prev = compute_chain_hash(
            org_id=org_id, prompt_hash=row.prompt_hash, response_hash=row.response_hash,
            token_count=row.token_count, policy_tag=row.policy_tag, seq=row.seq, prev_hash=prev,
            agent=row.agent, chain_version=row.chain_version or 1,
            event_id=row.event_id, client_id=row.client_id, client_seq=row.client_seq,
            event_type=row.event_type, commitment_alg=row.commitment_alg,
            event_metadata=row.event_metadata, pii_signals=row.pii_signals,
            occurred_at=row.occurred_at, verdict_hash=row.verdict_hash,
        )
        last = prev
    return last


def validate_chain(db: Session, org_id, upto_seq: int) -> tuple[bool, str, str | None]:
    """Validate all stored rows before publishing a root externally."""
    rows = db.execute(
        select(AuditLog)
        .where(AuditLog.org_id == org_id, AuditLog.seq <= upto_seq)
        .order_by(AuditLog.seq.asc())
    ).scalars().yield_per(1000)
    prev = GENESIS_HASH
    expected_seq = 1
    last = None
    for row in rows:
        if row.seq != expected_seq:
            return False, f"sequence gap before seq {row.seq}", last
        if row.prev_hash != prev:
            return False, f"previous hash mismatch at seq {row.seq}", last
        expected = compute_chain_hash(
            org_id=org_id, prompt_hash=row.prompt_hash, response_hash=row.response_hash,
            token_count=row.token_count, policy_tag=row.policy_tag, seq=row.seq,
            prev_hash=prev, agent=row.agent, chain_version=row.chain_version or 1,
            event_id=row.event_id, client_id=row.client_id, client_seq=row.client_seq,
            event_type=row.event_type, commitment_alg=row.commitment_alg,
            event_metadata=row.event_metadata, pii_signals=row.pii_signals,
            occurred_at=row.occurred_at, verdict_hash=row.verdict_hash,
        )
        if expected != row.chain_hash:
            return False, f"chain hash mismatch at seq {row.seq}", last
        prev = row.chain_hash
        last = prev
        expected_seq += 1
    if expected_seq - 1 != upto_seq:
        return False, f"chain ends before seq {upto_seq}", last
    return True, "chain intact", last


# ─────────────────────────────── providers ───────────────────────────────────

def _anchor_stub(root_hash: str, settings: Settings) -> AnchorReceipt:
    """Deterministic fake anchor — no external chain. Verifiable because the
    'on-chain' value is exactly the submitted root, so verify_anchor's recompute
    still has something concrete to check against."""
    digest = hashlib.sha256(("stub-anchor:" + root_hash).encode("utf-8")).hexdigest()
    return AnchorReceipt(
        chain="stub", status="confirmed", tx_hash="0x" + digest,
        block_number=int(root_hash[:12], 16) % 10_000_000,
        detail="simulated anchor (no external chain) — set ANCHOR_PROVIDER=evm for Sepolia",
    )


def _ensure_wallet_funded(balance_wei: int, settings: Settings) -> None:
    """Refuse to anchor when the funded wallet is below the configured floor (7C).
    A doomed transaction still burns nothing on-chain (it never lands) but wastes a
    nonce/round-trip and, worse, hides the real problem — an empty key — behind a
    generic 'failed' receipt. Raising here surfaces it explicitly. floor 0 = off."""
    floor = settings.anchor_wallet_min_balance_wei
    if floor > 0 and balance_wei < floor:
        raise RuntimeError(
            f"anchor wallet balance {balance_wei} wei is below the configured floor "
            f"{floor} wei — top up the funded key; refusing to submit a doomed anchor")


def _anchor_evm(root_hash: str, settings: Settings) -> AnchorReceipt:
    """Submit root to the AnchorRegistry contract on an EVM chain via web3.py."""
    if not settings.anchor_evm_rpc_url:
        raise RuntimeError("ANCHOR_EVM_RPC_URL is not set")
    if not settings.anchor_evm_private_key:
        raise RuntimeError("ANCHOR_EVM_PRIVATE_KEY is not set")
    if not settings.anchor_evm_contract:
        raise RuntimeError("ANCHOR_EVM_CONTRACT is not set")
    try:
        from web3 import Web3
    except ImportError as e:                      # pragma: no cover
        raise RuntimeError("web3 is not installed (pip install web3) — required for anchor_provider=evm") from e

    w3 = Web3(Web3.HTTPProvider(settings.anchor_evm_rpc_url))
    acct = w3.eth.account.from_key(settings.anchor_evm_private_key)
    _ensure_wallet_funded(w3.eth.get_balance(acct.address), settings)
    contract = w3.eth.contract(
        address=Web3.to_checksum_address(settings.anchor_evm_contract), abi=_ANCHOR_ABI)
    root_bytes = bytes.fromhex(root_hash)         # 64 hex chars -> 32 bytes (bytes32)
    if len(root_bytes) != 32:
        raise RuntimeError(f"root_hash must be 32 bytes (64 hex chars), got {len(root_bytes)}")

    # EIP-1559 fees. A legacy gasPrice at/below the base fee is dropped by the
    # mempool (base fee can exceed a stale eth_gasPrice), so price with headroom.
    base = w3.eth.get_block("latest").get("baseFeePerGas")
    priority = w3.to_wei(2, "gwei")
    fees = ({"maxPriorityFeePerGas": priority, "maxFeePerGas": base * 2 + priority}
            if base is not None else {"gasPrice": w3.eth.gas_price})
    tx = contract.functions.anchor(root_bytes).build_transaction({
        "from": acct.address,
        "nonce": w3.eth.get_transaction_count(acct.address),
        "gas": 120_000,
        "chainId": w3.eth.chain_id,
        **fees,
    })
    signed = acct.sign_transaction(tx)
    raw = getattr(signed, "raw_transaction", None) or getattr(signed, "rawTransaction")  # web3 v7/v6
    tx_hash = w3.eth.send_raw_transaction(raw)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=180)
    txh = receipt["transactionHash"]
    tx_hex = txh.hex() if hasattr(txh, "hex") else str(txh)   # v6 HexBytes / v7 HexStr
    if not tx_hex.startswith("0x"):
        tx_hex = "0x" + tx_hex
    return AnchorReceipt(
        chain=settings.anchor_evm_chain,
        status="confirmed" if receipt.get("status") == 1 else "failed",
        tx_hash=tx_hex,
        block_number=receipt["blockNumber"],
    )


_PROVIDERS = {
    "stub": _anchor_stub,
    "evm": _anchor_evm,
}


def run_provider(root_hash: str, settings: Settings) -> AnchorReceipt:
    provider = _PROVIDERS.get(settings.anchor_provider)
    if provider is None:
        raise RuntimeError(f"unknown anchor_provider '{settings.anchor_provider}'")
    return provider(root_hash, settings)


def run_validated_provider(db: Session, org_id, root_hash: str, last_seq: int,
                           settings: Settings) -> AnchorReceipt:
    """Refuse external publication unless the stored chain recomputes cleanly."""
    valid, detail, recomputed_head = validate_chain(db, org_id, last_seq)
    if not valid or recomputed_head != root_hash:
        detail = detail if not valid else "stored head differs from recomputed head"
        log.warning("anchor for org %s refused: %s", org_id, detail)
        return AnchorReceipt(
            chain=settings.anchor_evm_chain if settings.anchor_provider == "evm"
            else settings.anchor_provider,
            status="failed", detail=f"chain integrity check failed: {detail}"[:500],
        )
    return run_provider(root_hash, settings)


# ─────────────────────────────── orchestration ───────────────────────────────

def latest_anchor(db: Session, org_id) -> ChainAnchor | None:
    """Most recent anchor for the org (any status). Caller scopes RLS if needed."""
    return db.execute(
        select(ChainAnchor)
        .where(ChainAnchor.org_id == org_id)
        .order_by(ChainAnchor.anchored_at.desc())
        .limit(1)
    ).scalars().first()


def anchor_org(db: Session, org_id, settings: Settings | None = None,
               force: bool = False, respect_cadence: bool = False) -> ChainAnchor | None:
    """Anchor one org's current chain head. Returns the ChainAnchor row, or None
    if the org has no logs, or (unless force) its head hasn't advanced since the
    last successful anchor. A provider failure is persisted as status='failed'
    (a visible receipt), never silently dropped.

    respect_cadence (set by the automatic worker sweep, NOT manual 'anchor now'):
    even with an advanced head, skip if the last anchor is younger than the org's
    per-tier cadence — the configurable anchor SLA (6E)."""
    settings = settings or get_settings()
    org_id = org_id if isinstance(org_id, uuid.UUID) else uuid.UUID(str(org_id))
    _scope(db, org_id)

    head_hash, last_seq = head_of(db, org_id)
    if head_hash is None:
        return None

    if not force:
        prev = latest_anchor(db, org_id)
        if prev is not None and prev.status != "failed":
            if prev.last_seq == last_seq:
                return None   # head hasn't advanced since a non-failed anchor
            # 6E: automatic sweeps also honor the org's per-tier anchor cadence —
            # even with an advanced head, don't re-anchor within the cadence window.
            if respect_cadence and prev.anchored_at is not None:
                plan_tier = db.execute(
                    select(Organization.plan_tier).where(Organization.id == org_id)
                ).scalar_one_or_none()
                cadence = settings.anchor_cadence_for(plan_tier)
                anchored_at = prev.anchored_at
                if anchored_at.tzinfo is None:
                    anchored_at = anchored_at.replace(tzinfo=timezone.utc)
                if (datetime.now(timezone.utc) - anchored_at).total_seconds() < cadence:
                    return None   # within the tier's cadence window — wait

    try:
        receipt = run_validated_provider(db, org_id, head_hash, last_seq, settings)
    except Exception as exc:                        # noqa: BLE001 — record the failure
        safe = _redact(str(exc), settings)          # never persist/log RPC URL or key
        log.warning("anchor for org %s failed: %s", org_id, safe)
        receipt = AnchorReceipt(chain=settings.anchor_evm_chain if settings.anchor_provider == "evm"
                                else settings.anchor_provider,
                                status="failed", detail=f"{type(exc).__name__}: {safe}"[:500])

    row = ChainAnchor(
        org_id=org_id, root_hash=head_hash, last_seq=last_seq, chain=receipt.chain,
        tx_hash=receipt.tx_hash, block_number=receipt.block_number, status=receipt.status,
        detail=receipt.detail,
        confirmed_at=datetime.now(timezone.utc) if receipt.status == "confirmed" else None,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    log.info("anchored org %s @ seq %s -> %s tx=%s status=%s",
             org_id, last_seq, receipt.chain, receipt.tx_hash, receipt.status)
    return row


# In-memory last-alert clock for the anchor-health check (per worker process).
_ANCHOR_ALERT_STATE: dict = {}


def alert_on_anchor_problems(db: Session, settings, state: dict, *,
                             now: float | None = None) -> bool:
    """If any org's LATEST anchor is 'failed', or its newest confirmed anchor is
    older than anchor_stale_alert_seconds, log a WARNING and — at most once per
    anchor_alert_cooldown — email settings.alert_email (7C). Mirrors the grading
    dead-letter alert (usage.alert_on_grading_failures). Returns True iff an email
    was sent. Runs unscoped in the worker (superuser bypasses RLS → sees all orgs).
    `state` carries the last-alert time across calls."""
    now = time.time() if now is None else now
    failed = db.execute(text(
        "SELECT count(*) FROM ("
        "  SELECT DISTINCT ON (org_id) status FROM chain_anchors"
        "  ORDER BY org_id, anchored_at DESC, id DESC"
        ") t WHERE status = 'failed'"
    )).scalar() or 0
    stale = 0
    if settings.anchor_stale_alert_seconds > 0:
        cutoff = datetime.fromtimestamp(
            now - settings.anchor_stale_alert_seconds, tz=timezone.utc)
        stale = db.execute(text(
            "SELECT count(*) FROM ("
            "  SELECT DISTINCT ON (org_id) confirmed_at FROM chain_anchors"
            "  WHERE status = 'confirmed'"
            "  ORDER BY org_id, anchored_at DESC, id DESC"
            ") t WHERE confirmed_at < :cutoff"
        ), {"cutoff": cutoff}).scalar() or 0

    if failed == 0 and stale == 0:
        return False
    log.warning("anchor health: %d org(s) with a failed latest anchor, "
                "%d with a stale confirmed anchor", failed, stale)
    last = state.get("last_alert")   # None = never alerted → don't apply cooldown
    if not settings.alert_email or (
            last is not None and (now - last) < settings.anchor_alert_cooldown):
        return False
    html, plain = et.layout(
        title="Anchoring needs attention",
        preheader=f"{failed} org(s) with a failed latest anchor; {stale} with a stale confirmed anchor.",
        blocks=[
            et.paragraph("Public-chain anchoring health check flagged issues:"),
            et.info_rows([("Failed latest anchor", f"{failed} org(s)"),
                          ("Stale confirmed anchor", f"{stale} org(s)")]),
            et.muted("Check the worker logs and the funded wallet balance."),
        ],
        surface="staff", variant="compact",
    )
    ok = email.send_email(
        to=settings.alert_email,
        subject="[Foxy Audit] anchoring needs attention",
        html=html, text=plain,
    )
    if ok:
        state["last_alert"] = now
    return ok


def anchor_all_due(db: Session, settings: Settings | None = None) -> int:
    """Anchor every org whose head advanced since its last anchor. Runs in the
    worker (a BYPASSRLS/superuser role, so it sees all orgs). Returns the count
    of orgs anchored this pass."""
    settings = settings or get_settings()
    org_ids = db.execute(select(Organization.id)).scalars().all()
    anchored = 0
    for oid in org_ids:
        try:
            if anchor_org(db, oid, settings, respect_cadence=True) is not None:
                anchored += 1
        except Exception as exc:                    # noqa: BLE001 — one org must not stop the sweep
            db.rollback()
            # Log the TYPE only: a malformed ANCHOR_EVM_PRIVATE_KEY can make web3
            # embed the raw key in str(exc) ("invalid private key: 0x…"), which must
            # never reach our logs.
            log.warning("anchor sweep skipped org %s (%s)", oid, type(exc).__name__)
    return anchored


# ═════════════════════════ the STAFF chain (A1) ══════════════════════════════
#
# Everything above is per-org and RLS-scoped. Everything below is platform-wide:
# admin_actions has no org_id, and neither does its receipt table. The provider
# layer in the middle is shared, which is the reason these live together.


def admin_head(db: Session) -> tuple[str | None, int, int, int]:
    """(head_hash, last_seq, covers_from_seq, unchained_before) for the staff chain.

    ``seq IS NOT NULL`` excludes the rows that predate migration 0066 — they are
    real audit rows that are simply older than the mechanism, and they are
    COUNTED rather than ignored so the receipt can state what it does not cover.
    """
    from sqlalchemy import func as _f
    row = db.execute(
        select(AdminAction.chain_hash, AdminAction.seq)
        .where(AdminAction.seq.isnot(None))
        .order_by(AdminAction.seq.desc())
        .limit(1)
    ).first()
    if row is None:
        return None, 0, 0, 0
    first_seq = db.execute(
        select(_f.min(AdminAction.seq)).where(AdminAction.seq.isnot(None))
    ).scalar() or 1
    unchained = db.execute(
        select(_f.count()).select_from(AdminAction).where(AdminAction.seq.is_(None))
    ).scalar() or 0
    return row[0], row[1], int(first_seq), int(unchained)


def latest_admin_anchor(db: Session) -> AdminChainAnchor | None:
    """The most recent staff-chain anchor of any status."""
    return db.execute(
        select(AdminChainAnchor)
        .order_by(AdminChainAnchor.anchored_at.desc(), AdminChainAnchor.id.desc())
        .limit(1)
    ).scalars().first()


def latest_confirmed_admin_anchor(db: Session) -> AdminChainAnchor | None:
    """The most recent CONFIRMED one — the only kind that is a witness.

    A 'failed' receipt is a record that we tried, not a record that anything was
    published. Verification must never treat one as evidence.
    """
    return db.execute(
        select(AdminChainAnchor)
        .where(AdminChainAnchor.status == "confirmed")
        .order_by(AdminChainAnchor.anchored_at.desc(), AdminChainAnchor.id.desc())
        .limit(1)
    ).scalars().first()


def anchor_admin(db: Session, settings: Settings | None = None,
                 force: bool = False) -> AdminChainAnchor | None:
    """Anchor the staff chain's current head. Mirrors ``anchor_org``.

    Returns None when there is nothing chained, or (unless force) when the head
    has not advanced since the last non-failed anchor. A provider failure is
    PERSISTED as status='failed' with a redacted detail — a visible receipt,
    never a silent drop — exactly as the customer path does.

    ⚠ NOT ON THE STAFF-ACTION WRITE PATH. admin_chain.py records that the hot
    path is already +3.99ms and platform-serialised on an advisory lock; adding
    an RPC round trip to it would be indefensible. This runs in the worker's
    anchor thread, off the grading loop, like anchor_all_due.
    """
    settings = settings or get_settings()
    head_hash, last_seq, covers_from, unchained = admin_head(db)
    if head_hash is None:
        return None

    if not force:
        prev = latest_admin_anchor(db)
        if prev is not None and prev.status != "failed" and prev.last_seq == last_seq:
            return None

    try:
        receipt = run_validated_admin_provider(db, head_hash, last_seq, settings)
    except Exception as exc:                        # noqa: BLE001 — record the failure
        safe = _redact(str(exc), settings)
        log.warning("staff-chain anchor failed: %s", safe)
        receipt = AnchorReceipt(
            chain=settings.anchor_evm_chain if settings.anchor_provider == "evm"
            else settings.anchor_provider,
            status="failed", detail=f"{type(exc).__name__}: {safe}"[:500])

    row = AdminChainAnchor(
        root_hash=head_hash, last_seq=last_seq, covers_from_seq=covers_from,
        unchained_before=unchained, chain=receipt.chain, tx_hash=receipt.tx_hash,
        block_number=receipt.block_number, status=receipt.status, detail=receipt.detail,
        confirmed_at=datetime.now(timezone.utc) if receipt.status == "confirmed" else None,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    log.info("anchored staff chain @ seq %s -> %s tx=%s status=%s",
             last_seq, receipt.chain, receipt.tx_hash, receipt.status)
    return row


def run_validated_admin_provider(db: Session, root_hash: str, last_seq: int,
                                 settings: Settings) -> AnchorReceipt:
    """Refuse to publish a staff-chain root that does not recompute.

    Publishing a root we cannot re-derive would put a number on a public chain
    that proves nothing — worse than not anchoring, because the receipt looks
    like evidence. Same posture as run_validated_provider.
    """
    from .admin_chain import verify_admin_chain
    result = verify_admin_chain(db)
    if result.get("ok") is not True or result.get("head_hash") != root_hash:
        detail = result.get("detail") or "chain not verified"
        if result.get("ok") is True:
            detail = "stored head differs from recomputed head"
        log.warning("staff-chain anchor refused: %s", detail)
        return AnchorReceipt(
            chain=settings.anchor_evm_chain if settings.anchor_provider == "evm"
            else settings.anchor_provider,
            status="failed", detail=f"chain integrity check failed: {detail}"[:500])
    return run_provider(root_hash, settings)
