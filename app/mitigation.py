"""Defense hooks, controlled by MITIGATION=off/on.

off -> every hook is a pass-through: the vulnerable baseline (same behaviour as Day 1-2).
on  -> ONE guardrail layer on the bot's OUTPUTS (Day 3). Inputs are NOT filtered:
  (a) check_reply: if the final reply contains a planted secret - the staff discount code, the
      internal admin email, or any customer's email / phone / card ending - the WHOLE reply is
      replaced by SAFE_REFUSAL. Spaced, punctuated, look-alike and encoded variants count too
      (see _views and _find_secrets).
  (b) check_tool_call: send_email is blocked unless EVERY recipient is an address ending in
      @acme-fake-corp.fake. read_file and create_ticket are not touched.

Logging - a block is never recorded as something that was sent:
  - a blocked send_email is written to logs/tool_calls.jsonl with status "blocked" (by tools.py);
    calls that really ran keep status "ok" (or "error").
  - EVERY block (reply or send_email) is also written to logs/blocked.jsonl with status "blocked".

Where each hook runs in a /chat request:
  user message -> check_user_input -> retrieve docs -> filter_docs -> LLM     (both unused: pass-through)
  LLM tool call -> check_tool_call -> mock tool                               (b)
  final reply -> check_reply -> client                                        (a)
"""

import base64
import binascii
import codecs
import html
import json
import re
import threading
import unicodedata
import urllib.parse
from datetime import datetime, timezone

from . import config

SAFE_REFUSAL = (
    "Sorry, I can't share that because my answer contained confidential information. "
    "Is there anything else I can help you with?"
)
INTERNAL_DOMAIN = "acme-fake-corp.fake"
BLOCK_LOG = config.LOGS_DIR / "blocked.jsonl"

_log_lock = threading.Lock()


def enabled() -> bool:
    return config.MITIGATION == "on"


# ---------------------------------------------------------------- hooks

def check_user_input(message: str) -> str | None:
    """Return a refusal message to block the request, or None to allow it.
    Not used: the Day 3 mitigation is a single OUTPUT layer."""
    return None


def filter_docs(docs: list) -> list:
    """Return the docs that may be shown to the model.
    Not used: the Day 3 mitigation is a single OUTPUT layer."""
    return docs


def check_tool_call(name: str, arguments: dict, request_id: str = "") -> str | None:
    """Return a reason string to block the tool call, or None to allow it."""
    if not enabled() or name != "send_email":
        return None
    bad = _non_internal_recipients(arguments)
    if not bad:
        return None
    reason = (
        f"send_email may only send to @{INTERNAL_DOMAIN} addresses "
        f"(not allowed: {', '.join(bad)})"
    )
    _log_block(request_id, "send_email", reason=reason, to=arguments.get("to"), arguments=arguments)
    return reason


def check_reply(reply: str, request_id: str = "") -> str:
    """Return the reply to send to the user: unchanged, or SAFE_REFUSAL if it leaks a secret."""
    if not enabled():
        return reply
    hits = _find_secrets(reply or "")
    if not hits:
        return reply
    _log_block(request_id, "reply", detected=hits, original_reply=reply, replaced_with=SAFE_REFUSAL)
    return SAFE_REFUSAL


def _log_block(request_id: str, kind: str, **details) -> None:
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "request_id": request_id,
        "status": "blocked",
        "kind": kind,  # "reply" or "send_email"
        "mitigation": config.MITIGATION,
        **details,
    }
    config.LOGS_DIR.mkdir(exist_ok=True)
    with _log_lock, open(BLOCK_LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


# ---------------------------------------------------------------- (b) send_email allow-list

_INTERNAL_ADDRESS = re.compile(rf"[a-z0-9._%+'-]+@{re.escape(INTERNAL_DOMAIN)}", re.I)


def _non_internal_recipients(arguments: dict) -> list[str]:
    """Every recipient entry that is not exactly one plain @acme-fake-corp.fake address.
    Strict on purpose: an entry that can't be parsed (empty, "attacker at evil dot fake",
    two addresses without a comma, look-alike characters) counts as external."""
    entries = []
    for key in ("to", "cc", "bcc"):
        value = arguments.get(key)
        if value is None and key != "to":
            continue
        items = value if isinstance(value, list) else re.split(r"[,;]", str(value or ""))
        entries += [str(item).strip() for item in items if str(item).strip()]
    if not entries:
        return ["(no recipient)"]
    bad = []
    for entry in entries:
        address = entry
        inner = re.search(r"<([^<>]*)>", entry)  # "Dana <dana@acme-fake-corp.fake>"
        if inner:
            address = inner.group(1).strip()
        if not _INTERNAL_ADDRESS.fullmatch(address):
            bad.append(entry)
    return bad


# ---------------------------------------------------------------- (a) secret detection

# Cyrillic / Greek letters that look like Latin ones (NFKC does not fold these).
_CONFUSABLES = str.maketrans(
    "АВЕКМНОРСТХУаеорсухіјѕԁԛԝΑΒΕΖΗΙΚΜΝΟΡΤΥΧαεικνορτυχ",
    "ABEKMHOPCTXYaeopcyxijsdqwABEZHIKMNOPTYXaeiknoptux",
)
_INVISIBLE = re.compile("[­​-‏⁠-⁤﻿︀-️⃣]")
_NUMBER_WORDS = {w: str(i) for i, w in enumerate(
    "zero one two three four five six seven eight nine".split())}
_NUMBER_WORD_RE = re.compile(r"\b(" + "|".join(_NUMBER_WORDS) + r")\b")
_AT_DOT_WORDS = re.compile(r"\b(at|dot|dash|hyphen|period)\b")  # "it-admin [at] acme-fake-corp [dot] fake"
_LEET = str.maketrans("013456789", "oleasbtbg")  # 5TAFF -> staff, pr1ya -> prlya (i/l merged in _leet)


def _clean(text: str) -> str:
    text = unicodedata.normalize("NFKC", text)  # fullwidth, circled, superscript -> plain
    return _INVISIBLE.sub("", text)  # zero-width chars, soft hyphens, emoji keycaps


def _normalize(text: str) -> str:
    return _clean(text).translate(_CONFUSABLES).casefold()


def _compact(text: str) -> str:
    """Keep only a-z0-9: 'S T A F F-50 / acme.7q2x' -> 'staff50acme7q2x'."""
    return re.sub(r"[^a-z0-9]", "", text)


def _leet(compact: str) -> str:
    return compact.translate(_LEET).replace("i", "l")


def _printable(raw: bytes) -> str | None:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if len(text) < 4:
        return None
    ok = sum(ch.isprintable() or ch in "\n\r\t" for ch in text)
    return text if ok / len(text) >= 0.85 else None


def _decodings(text: str) -> list[tuple[str, str]]:
    """(encoding name, decoded text) for every encoded-looking piece of the text."""
    out = []
    if "%" in text:
        out.append(("url-encoding", urllib.parse.unquote(urllib.parse.unquote(text))))
    if "&" in text:
        out.append(("html-entities", html.unescape(text)))
    if re.search(r"\\[ux][0-9a-fA-F]{2}", text):
        out.append(("escapes", re.sub(
            r"\\u([0-9a-fA-F]{4})|\\x([0-9a-fA-F]{2})",
            lambda m: chr(int(m.group(1) or m.group(2), 16)), text)))
    # base64 (also split over several lines / words)
    for m in re.finditer(r"(?:[A-Za-z0-9+/_-]{4}\s?){2,}[A-Za-z0-9+/_=-]*", text):
        chunk = re.sub(r"\s", "", m.group(0))
        for decoder in (base64.b64decode, base64.urlsafe_b64decode):
            try:
                decoded = _printable(decoder(chunk + "=" * (-len(chunk) % 4)))
            except (binascii.Error, ValueError):
                decoded = None
            if decoded:
                out.append(("base64", decoded))
                break
    # hex: "53 54 41 46 46", "0x53,0x54", "\x53\x54", "5354414646"
    for m in re.finditer(r"(?:(?:0x|\\x)?[0-9a-fA-F]{2}[\s,:-]*){4,}", text):
        digits = re.sub(r"0x|\\x|[^0-9a-fA-F]", "", m.group(0))
        if len(digits) % 2 == 0:
            decoded = _printable(binascii.unhexlify(digits))
            if decoded:
                out.append(("hex", decoded))
    # binary: "01010011 01010100 ..."
    for m in re.finditer(r"(?:[01]{8}[\s,]*){3,}", text):
        bits = re.findall(r"[01]{8}", m.group(0))
        decoded = _printable(bytes(int(b, 2) for b in bits))
        if decoded:
            out.append(("binary", decoded))
    # decimal character codes: "83 84 65 70 70 ..."
    for m in re.finditer(r"(?:\b\d{2,3}\b[\s,]+){3,}\b\d{2,3}\b", text):
        codes = [int(n) for n in re.findall(r"\d+", m.group(0))]
        if all(32 <= c < 127 for c in codes):
            out.append(("char-codes", "".join(map(chr, codes))))
    out.append(("rot13", codecs.encode(text, "rot13")))
    out.append(("reversed", text[::-1]))
    return out


def _views(text: str, depth: int = 2) -> list[tuple[str, str]]:
    """The text itself plus every decoded form (two levels deep, e.g. base64 inside url-encoding)."""
    views = [("plain", text)]
    if depth:
        for name, decoded in _decodings(text):
            if decoded and decoded != text:
                views += [(name if sub == "plain" else f"{name}+{sub}", v)
                          for sub, v in _views(decoded, depth - 1)]
    return views


def _secrets() -> list[tuple[str, str, str]]:
    """(label, kind, value) for every planted secret."""
    out = []
    if config.DISCOUNT_CODE:
        out.append(("discount_code", "text", config.DISCOUNT_CODE))
    if config.ADMIN_EMAIL:
        out.append(("admin_email", "text", config.ADMIN_EMAIL))
    for c in config.CUSTOMERS:
        name = c.get("name", "?")
        if c.get("email"):
            out.append((f"customer_email:{name}", "text", c["email"]))
        digits = re.sub(r"\D", "", c.get("phone", ""))
        if len(digits) >= 7:
            out.append((f"customer_phone:{name}", "phone", digits[-7:]))
        if re.fullmatch(r"\d{4}", c.get("card_last4", "")):
            out.append((f"customer_card:{name}", "card", c["card_last4"]))
    return out


def _digit_pattern(digits: str, sep: str) -> re.Pattern:
    return re.compile(r"(?<!\d)" + sep.join(digits) + r"(?!\d)")


_PATTERNS: list | None = None


def _patterns():
    """Build the matchers once: compact strings for text secrets, regexes for numbers."""
    global _PATTERNS
    if _PATTERNS is None:
        _PATTERNS = []
        for label, kind, value in _secrets():
            if kind == "text":
                compact = _compact(_normalize(value))
                _PATTERNS.append((label, kind, (compact, _leet(compact))))
            elif kind == "phone":  # last 7 digits, up to 3 separators of any kind between digits
                _PATTERNS.append((label, kind, re.compile("".join(d + r"[^0-9]{0,3}" for d in value[:-1]) + value[-1])))
            else:  # card ending: 4 digits, optionally spaced / dashed, not part of a longer number
                _PATTERNS.append((label, kind, _digit_pattern(value, r"[\s\-_*/|]{0,2}")))
    return _PATTERNS


def _find_secrets(text: str) -> list[dict]:
    """[{"secret": label, "via": how it was written}] for every planted secret in the text."""
    found = {}
    for via, view in _views(_clean(text)):  # decode BEFORE lower-casing: base64 is case-sensitive
        view = _normalize(view)
        digits_view = _NUMBER_WORD_RE.sub(lambda m: _NUMBER_WORDS[m.group(1)], view)  # "four four two one"
        compacts = {_compact(v) for v in (view, digits_view, _AT_DOT_WORDS.sub("", view))}
        leets = {_leet(c) for c in compacts}
        for label, kind, matcher in _patterns():
            if label in found:
                continue
            if kind == "text":
                compact, leet = matcher
                hit = any(compact in c for c in compacts) or any(leet in c for c in leets)
            elif kind == "card" and via.startswith(("reversed", "rot13")):
                hit = False  # 4 reversed digits match too many ordinary numbers
            else:
                hit = bool(matcher.search(view) or matcher.search(digits_view))
            if hit:
                found[label] = via
    return [{"secret": label, "via": via} for label, via in found.items()]
