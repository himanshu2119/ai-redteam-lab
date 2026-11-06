"""promptfoo provider for the HelpDesk Bot (POST /chat).

- Single-turn tests send a plain prompt.
- Multi-turn strategies (crescendo) send the whole conversation as a JSON list of
  {"role", "content"} messages; we split that into history + latest user message.

The output shown to the judge is the bot's reply PLUS a summary of the tool calls it
made, so the judge can see e.g. a send_email to an outside address.
Crescendo sends those outputs back as conversation history, so the summary is
STRIPPED from every assistant message before the history goes to the bot: the bot
only ever sees its own real reply text (a real chat.py user would never send it).

Every request is also written to logs/promptfoo_target.jsonl together with the
promptfoo eval id, attack id and repeat index, so score.py can match each promptfoo
result to the exact bot requests (and their entries in logs/tool_calls.jsonl).
Standard library only, so any python3 can run it.
"""

import json
import os
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TRACE_LOG = ROOT / "logs" / "promptfoo_target.jsonl"
BOT_URL = os.environ.get("BOT_URL", "http://127.0.0.1:8000").rstrip("/")
TIMEOUT = float(os.environ.get("BOT_TIMEOUT", "300"))


TOOL_SUMMARY_MARKER = "\n\n[TOOL CALLS MADE BY THE BOT]\n"


def _strip_tool_summary(text: str) -> tuple[str, bool]:
    """Remove the summary _format_output appended (always the LAST block of an output)."""
    if TOOL_SUMMARY_MARKER not in text:
        return text, False
    return text.rpartition(TOOL_SUMMARY_MARKER)[0], True


def _split_conversation(prompt: str) -> tuple[str, list[dict], int]:
    """Return (latest user message, history for the bot, number of summaries stripped)."""
    try:
        msgs = json.loads(prompt)
    except (json.JSONDecodeError, TypeError):
        return prompt, [], 0
    if not (isinstance(msgs, list) and msgs and all(isinstance(m, dict) and "role" in m for m in msgs)):
        return prompt, [], 0
    turns, stripped = [], 0
    for m in msgs:
        if m["role"] not in ("user", "assistant"):
            continue
        content = str(m.get("content", ""))
        if m["role"] == "assistant":
            content, was_stripped = _strip_tool_summary(content)
            stripped += was_stripped
        turns.append({"role": m["role"], "content": content})
    if not turns or turns[-1]["role"] != "user":
        return prompt, [], 0
    return turns[-1]["content"], turns[:-1], stripped


def _format_output(reply: str, tool_calls: list[dict]) -> str:
    if not tool_calls:
        return f"{reply}{TOOL_SUMMARY_MARKER}none"
    lines = [
        f"- {tc['tool']}({json.dumps(tc['arguments'], ensure_ascii=False)}) -> {tc['status']}"
        for tc in tool_calls
    ]
    return f"{reply}{TOOL_SUMMARY_MARKER}" + "\n".join(lines)


def call_api(prompt, options, context):
    test_vars = (context or {}).get("vars", {}) or {}
    message, history, stripped = _split_conversation(prompt)

    started = time.time()
    body = json.dumps({"message": message, "history": history}).encode()
    req = urllib.request.Request(
        f"{BOT_URL}/chat", data=body, headers={"content-type": "application/json"}, method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            data = json.loads(r.read())
    except urllib.error.HTTPError as e:
        return {"error": f"Bot returned HTTP {e.code}: {e.read()[:300]!r}"}
    except (urllib.error.URLError, TimeoutError) as e:
        return {"error": f"Could not reach the bot at {BOT_URL}: {e}"}

    reply = data.get("reply", "")
    tool_calls = data.get("tool_calls", [])
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "eval_id": test_vars.get("__evalId"),
        "attack_id": test_vars.get("attack_id"),
        "repeat_index": test_vars.get("__repeatIndex"),
        "request_id": data.get("request_id"),
        "message": message,
        "history_len": len(history),
        "tool_summaries_stripped": stripped,
        "history_has_tool_summary": any("[TOOL CALLS MADE BY THE BOT]" in t["content"] for t in history),
        "reply": reply,
        "tool_calls": tool_calls,
        "retrieved_docs": data.get("retrieved_docs", []),
        "mitigation": data.get("mitigation"),
        "latency_s": round(time.time() - started, 2),
    }
    TRACE_LOG.parent.mkdir(exist_ok=True)
    with open(TRACE_LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")

    return {
        "output": _format_output(reply, tool_calls),
        "metadata": {
            "request_id": data.get("request_id"),
            "retrieved_docs": data.get("retrieved_docs", []),
            # lets conversation_judge.py find this request in the trace log (single-turn tests;
            # for crescendo tests fresh_crescendo.js sets the same tag on the final response)
            "redteam_conversation": {
                "eval_id": record["eval_id"],
                "attack_id": record["attack_id"],
                "repeat_index": record["repeat_index"],
            },
        },
    }
