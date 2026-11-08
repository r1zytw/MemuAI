"""Secure one-time pairing of a Telegram chat with MemuAI.

The Settings panel (MemuAI window process) creates a short code and shows it
together with a deep link ``t.me/<bot>?start=pair-<code>`` (and a QR code).
The bot (MemuAI Proxy process) accepts the code from ``/start pair-<code>``
or as a plain message and pairs that private chat. Both processes share
``telegram_state.json`` through atomic cross-process transactions.

* only a salted SHA-256 of the code is stored;
* the code expires after 10 minutes and works once;
* after 8 wrong attempts the code is burned (brute-force protection);
* the legacy manual ``telegram_chat_id`` keeps working unchanged.
"""
from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import time
from typing import Any, Dict, Optional, Tuple

from .pgdata import load_preferences, load_telegram_state, save_preferences, update_telegram_state

ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
CODE_LENGTH = 8
CODE_TTL = 10 * 60
MAX_ATTEMPTS = 8
HEARTBEAT_STALE = 100
# 5.0 multi-account: two Telegram accounts can be bound at once (each is one
# private chat with the bot). Both chat, both get notifications and schedules.
MAX_OWNERS = 2

def token_fingerprint(token: str) -> str:
    token = str(token or "").strip()
    return hashlib.sha256(token.encode("utf-8")).hexdigest()[:12] if token else ""

def normalize_code(value: str) -> str:
    return re.sub(r"[^A-Z0-9]", "", str(value or "").upper())

def format_code(code: str) -> str:
    code = normalize_code(code)
    return code[:4] + "-" + code[4:] if len(code) == 8 else code

def _hash(code: str, salt: str) -> str:
    return hashlib.sha256((salt + ":" + normalize_code(code)).encode("utf-8")).hexdigest()

def create_pairing_code(ttl: int = CODE_TTL) -> Tuple[str, float]:
    code = "".join(secrets.choice(ALPHABET) for _ in range(CODE_LENGTH))
    salt = secrets.token_hex(8)
    now = time.time()
    expires = now + max(60, int(ttl))

    def apply(data: Dict[str, Any]) -> Dict[str, Any]:
        data["pairing"] = {"code_hash": _hash(code, salt), "salt": salt,
                           "expires": expires, "attempts": 0, "created": now}
        return data

    update_telegram_state(apply)
    return code, expires

def cancel_pairing_code() -> None:
    def apply(data: Dict[str, Any]) -> Dict[str, Any]:
        data.pop("pairing", None)
        return data

    update_telegram_state(apply)

def pairing_active(state: Optional[Dict[str, Any]] = None) -> bool:
    state = state if state is not None else load_telegram_state()
    pairing = state.get("pairing") or {}
    return bool(pairing.get("code_hash")) and float(pairing.get("expires") or 0) > time.time()

def extract_code(text: str) -> str:
    """Code candidate from ``/start pair-XXXX``, ``/start XXXX`` or ``XXXX-XXXX``."""
    value = str(text or "").strip()
    match = re.match(r"^/start(?:@\w+)?\s+(?:pair[-_])?([A-Za-z0-9-]{6,20})\s*$", value)
    if match:
        return normalize_code(match.group(1))
    match = re.fullmatch(r"\s*([A-Za-z0-9]{4})[-\s]?([A-Za-z0-9]{4})\s*", value)
    if match:
        return normalize_code(match.group(1) + match.group(2))
    return ""

def check_pairing_code(candidate: str) -> bool:
    """Consume the code when it matches; count failures otherwise."""
    candidate = normalize_code(candidate)
    outcome = {"ok": False}

    def apply(data: Dict[str, Any]) -> Dict[str, Any]:
        pairing = data.get("pairing") or {}
        if not pairing.get("code_hash"):
            return data
        if float(pairing.get("expires") or 0) <= time.time():
            data.pop("pairing", None)
            return data
        if len(candidate) == CODE_LENGTH and hmac.compare_digest(
                _hash(candidate, str(pairing.get("salt") or "")), str(pairing.get("code_hash"))):
            outcome["ok"] = True
            data.pop("pairing", None)
            return data
        pairing["attempts"] = int(pairing.get("attempts") or 0) + 1
        if pairing["attempts"] >= MAX_ATTEMPTS:
            data.pop("pairing", None)
        else:
            data["pairing"] = pairing
        return data

    update_telegram_state(apply)
    return outcome["ok"]

def owners(state: Optional[Dict[str, Any]] = None) -> list:
    """All bound Telegram accounts from the state (legacy single owner included)."""
    state = state if state is not None else load_telegram_state()
    rows = [dict(row) for row in (state.get("owners") or [])
            if isinstance(row, dict) and row.get("chat_id")]
    if rows:
        return rows
    owner = state.get("owner") if isinstance(state.get("owner"), dict) else {}
    return [dict(owner)] if owner.get("chat_id") else []

def bound_chats(prefs: Optional[Dict[str, Any]] = None,
                state: Optional[Dict[str, Any]] = None) -> list:
    """Effective bound accounts: state owners first, then the manual Chat ID pref.

    The manual ``telegram_chat_id`` (filled by hand in Settings → Advanced) keeps
    working exactly as before — it counts as one bound chat, never a group."""
    from .pgdata import load_preferences
    prefs = prefs if prefs is not None else load_preferences()
    rows: list = []
    seen: set = set()

    def add(row: Dict[str, Any]) -> None:
        chat = str((row or {}).get("chat_id") or "").strip()
        if chat and chat not in seen and not chat.startswith("-"):
            seen.add(chat)
            rows.append(row)

    for row in owners(state):
        add(row)
    manual = str(prefs.get("telegram_chat_id") or "").strip()
    if manual:
        add({"chat_id": manual})
    return rows

def complete_pairing(chat: Dict[str, Any], user: Dict[str, Any]) -> Dict[str, Any]:
    """Bind this private chat as one of the MemuAI Telegram accounts.

    Re-binding an already bound chat refreshes its record, a new chat is added
    while there is a free slot (up to ``MAX_OWNERS``); otherwise the chat is
    refused (``full``). ``telegram_chat_id`` keeps pointing at the first bound
    chat so every legacy consumer stays correct."""
    chat_id = str(chat.get("id") or "")
    name = " ".join(str(user.get(key) or "") for key in ("first_name", "last_name")).strip()
    owner = {"chat_id": chat_id, "user_id": str(user.get("id") or chat_id), "name": name[:120],
             "username": str(user.get("username") or "")[:64], "paired_at": time.time()}
    outcome: Dict[str, Any] = {"owner": owner, "added": False, "full": False, "first_chat_id": ""}

    def apply(data: Dict[str, Any]) -> Dict[str, Any]:
        rows = [dict(row) for row in owners(data)]
        data.pop("owner", None)
        for index, row in enumerate(rows):
            if str(row.get("chat_id")) == chat_id:
                rows[index] = owner
                data["owners"] = rows
                outcome["owner"], outcome["first_chat_id"] = owner, str(rows[0].get("chat_id") or "")
                return data
        if len(rows) >= MAX_OWNERS:
            outcome["full"] = True
            data["owners"] = rows
            outcome["first_chat_id"] = str(rows[0].get("chat_id") or "")
            return data
        rows.append(owner)
        data["owners"] = rows
        outcome["added"], outcome["owner"] = True, owner
        outcome["first_chat_id"] = str(rows[0].get("chat_id") or "")
        return data

    update_telegram_state(apply)
    if not outcome["full"]:
        save_preferences({"telegram_chat_id": str(outcome["first_chat_id"] or chat_id),
                          "telegram_enabled": True})
    return outcome

def unpair(chat_id: str = "") -> None:
    """Unbind one Telegram account (by chat id) or every bound account."""
    chat_id = str(chat_id or "").strip()

    def apply(data: Dict[str, Any]) -> Dict[str, Any]:
        data.pop("owner", None)
        rows = [dict(row) for row in owners(data)]
        if chat_id:
            rows = [row for row in rows if str(row.get("chat_id")) != chat_id]
        else:
            rows = []
        if rows:
            data["owners"] = rows
        else:
            data.pop("owners", None)
        return data

    update_telegram_state(apply)
    remaining = owners(load_telegram_state())
    save_preferences({"telegram_chat_id": str((remaining[0] if remaining else {}).get("chat_id") or "")})

def request_restart() -> float:
    """«Restart bot» from Settings: the bot process watches ``control.restart``
    and restarts its polling session (fresh connection, lock, token check)."""
    stamp = time.time()

    def apply(data: Dict[str, Any]) -> Dict[str, Any]:
        data.setdefault("control", {})["restart"] = stamp
        return data

    update_telegram_state(apply)
    return stamp

def status(prefs: Optional[Dict[str, Any]] = None,
           state: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Everything the Settings panel shows; no secrets."""
    from .telegram_api import valid_token
    prefs = prefs if prefs is not None else load_preferences()
    state = state if state is not None else load_telegram_state()
    token = str(prefs.get("telegram_bot_token") or "").strip()
    bot = state.get("bot") or {}
    fingerprint = token_fingerprint(token)
    same_token = bool(fingerprint) and bot.get("token_fp") == fingerprint
    heartbeat = float(bot.get("heartbeat") or 0) if same_token else 0.0

    alive_stamp = float(bot.get("alive") or 0) or heartbeat
    now = time.time()
    alive = bool(alive_stamp) and now - alive_stamp < HEARTBEAT_STALE
    bot_status = str(bot.get("status") or "") if same_token else ""
    online = alive and bool(heartbeat) and bot_status in ("ok", "conflict", "")
    rows = bound_chats(prefs, state)
    chat_id = str(prefs.get("telegram_chat_id") or "")
    owner = dict(rows[0]) if rows else ({"chat_id": chat_id} if chat_id else {})
    pairing = state.get("pairing") or {}
    if not prefs.get("telegram_enabled"):
        phase = "disabled"
    elif not token:
        phase = "no_token"
    elif not valid_token(token):
        phase = "bad_token"
    elif same_token and bot_status == "unauthorized":
        phase = "bad_token"
    elif not (same_token and alive):
        phase = "offline"
    elif bot_status in ("conflict", "conflict_local"):
        phase = "conflict"
    elif bot_status in ("reconnecting", "starting", "disabled"):
        phase = "reconnecting"
    elif not rows:
        phase = "unpaired"
    else:
        phase = "ready"
    retry_at = float(bot.get("retry_at") or 0) if same_token else 0.0
    return {
        "phase": phase,
        "enabled": bool(prefs.get("telegram_enabled")),
        "has_token": bool(token),
        "token_valid": valid_token(token),
        "online": online,
        "alive": alive,
        "heartbeat_age": round(now - alive_stamp, 1) if alive_stamp else None,
        "retry_in": max(0, round(retry_at - now)) if retry_at and phase == "reconnecting" else None,
        "last_ok_age": round(now - float(bot.get("last_ok") or 0)) if same_token and bot.get("last_ok") else None,
        "restarts": int(bot.get("restarts") or 0) if same_token else 0,
        "local_conflict": bot_status == "conflict_local",
        "bot": {"username": bot.get("username", ""), "name": bot.get("name", ""),
                "id": bot.get("id", "")} if same_token else {},
        "bot_status": bot.get("status", "") if same_token else "",
        "bot_error": bot.get("error", "") if same_token else "",
        "webapp_url": bot.get("webapp_url", "") if same_token else "",
        "paired": bool(rows),
        "owner": owner,
        "owners": rows,
        "pairing": {"active": pairing_active(state), "expires": pairing.get("expires", 0)},
        "allowed_users": list(prefs.get("telegram_allowed_users") or []),
        "test": state.get("test") or {},
    }
