"""promptfoo provider used as the JUDGE (grader) and as the crescendo ATTACKER.

ONE backend for a whole run - chosen once by run.sh and passed in env vars:
  JUDGE_BACKEND=gemini  -> Gemini API (GEMINI_API_KEY from .env), model GEMINI_JUDGE_MODEL
  JUDGE_BACKEND=ollama  -> local Ollama, model JUDGE_OLLAMA_MODEL
There is no silent mid-run fallback: if the chosen backend keeps failing, that call
returns an error (promptfoo marks the test ERROR) instead of switching judges.

Every call is logged to logs/judge_calls.jsonl (run id, role, backend, latency).
The API key is sent only in a request header to Google and is never logged.

Preflight (used by run.sh):  python3 redteam/judge_provider.py --check-gemini
Standard library only, so any python3 can run it.
"""

import json
import os
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
JUDGE_LOG = ROOT / "logs" / "judge_calls.jsonl"


def _load_dotenv() -> dict:
    values = {}
    env_file = ROOT / ".env"
    if env_file.exists():
        for line in env_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, val = line.split("=", 1)
            values[key.strip()] = val.strip().strip('"').strip("'")
    return values


_ENV = {**_load_dotenv(), **os.environ}


def _setting(name: str, default: str) -> str:
    return _ENV.get(name) or default


JUDGE_BACKEND = _setting("JUDGE_BACKEND", "gemini")
GEMINI_MODEL = _setting("GEMINI_JUDGE_MODEL", "gemini-3.8-flash")
GEMINI_TIMEOUT = float(_setting("GEMINI_TIMEOUT", "90"))
GEMINI_RETRIES = int(_setting("GEMINI_RETRIES", "4"))  # mid-run retries on 429/5xx, with backoff
OLLAMA_URL = _setting("OLLAMA_URL", "http://localhost:11434").rstrip("/")
OLLAMA_MODEL = _setting("JUDGE_OLLAMA_MODEL", "qwen2.5:3b")
RUN_ID = _setting("REDTEAM_RUN_ID", "manual")


class BackendError(Exception):
    pass


def backend_label() -> str:
    return f"gemini:{GEMINI_MODEL}" if JUDGE_BACKEND == "gemini" else f"ollama:{OLLAMA_MODEL}"


# ---------- prompt handling ----------

def _text(content) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):  # OpenAI-style content parts
        return "\n".join(p.get("text", "") for p in content if isinstance(p, dict))
    return json.dumps(content)


def _to_messages(prompt: str) -> list[dict]:
    """promptfoo sends either plain text or a JSON list of chat messages."""
    try:
        msgs = json.loads(prompt)
        if isinstance(msgs, list) and msgs and all(isinstance(m, dict) and "role" in m for m in msgs):
            return [{"role": m["role"], "content": _text(m.get("content", ""))} for m in msgs]
    except (json.JSONDecodeError, TypeError):
        pass
    return [{"role": "user", "content": prompt}]


# ---------- backends ----------

def _post_json(url: str, payload: dict, headers: dict, timeout: float) -> dict:
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode(), headers={"content-type": "application/json", **headers}, method="POST"
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read() or b"{}")


def call_gemini(messages: list[dict], temperature: float, retries: int = GEMINI_RETRIES) -> str:
    key = _ENV.get("GEMINI_API_KEY", "").strip()
    if not key:
        raise BackendError("GEMINI_API_KEY is not set in .env")

    system = "\n\n".join(m["content"] for m in messages if m["role"] == "system")
    chat = [m for m in messages if m["role"] != "system"]
    if chat:
        contents = [
            {"role": "model" if m["role"] == "assistant" else "user", "parts": [{"text": m["content"]}]}
            for m in chat
        ]
    else:  # system-only prompt: send it as the user turn
        contents, system = [{"role": "user", "parts": [{"text": system}]}], ""
    payload = {"contents": contents, "generationConfig": {"temperature": temperature}}
    if system:
        payload["systemInstruction"] = {"parts": [{"text": system}]}

    url = f"https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}:generateContent"
    last_error = "unknown"
    for attempt in range(retries + 1):
        if attempt:
            time.sleep(min(60, 5 * 2**attempt))
        try:
            data = _post_json(url, payload, {"x-goog-api-key": key}, GEMINI_TIMEOUT)
        except urllib.error.HTTPError as e:
            body = e.read()[:300].decode(errors="replace").strip()
            try:
                body = json.loads(body)["error"]["message"]
            except (ValueError, KeyError, TypeError):
                pass
            last_error = f"HTTP {e.code}: {body[:160] if body else '(empty body)'}"
            if e.code in (400, 401, 403):
                break  # retrying won't help
            continue
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as e:
            last_error = f"{type(e).__name__}: {e}"
            continue

        parts = (data.get("candidates") or [{}])[0].get("content", {}).get("parts", [])
        text = "".join(p.get("text", "") for p in parts if not p.get("thought"))
        if text.strip():
            return text
        last_error = f"empty response (finishReason={(data.get('candidates') or [{}])[0].get('finishReason')})"
    raise BackendError(last_error)


def call_ollama(messages: list[dict], temperature: float) -> str:
    payload = {
        "model": OLLAMA_MODEL,
        "messages": messages,
        "stream": False,
        "format": "json",  # every judge/attacker prompt in this suite expects JSON back
        "options": {"temperature": temperature},
    }
    try:
        data = _post_json(f"{OLLAMA_URL}/api/chat", payload, {}, 600)
    except Exception as e:  # noqa: BLE001
        raise BackendError(f"Ollama: {e}") from e
    return data.get("message", {}).get("content", "")


# ---------- promptfoo entry point ----------

def call_api(prompt, options, context):
    config = (options or {}).get("config", {}) or {}
    role = config.get("role", "judge")
    temperature = float(config.get("temperature", 0))
    messages = _to_messages(prompt)
    test_vars = (context or {}).get("vars", {}) or {}

    started = time.time()
    error = None
    try:
        if JUDGE_BACKEND == "gemini":
            output = call_gemini(messages, temperature)
        else:
            output = call_ollama(messages, temperature)
    except BackendError as e:
        error = str(e)

    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "run_id": RUN_ID,
        "role": role,
        "backend": backend_label(),
        "attack_id": test_vars.get("attack_id"),
        "repeat_index": test_vars.get("__repeatIndex"),
        "latency_s": round(time.time() - started, 2),
        "ok": error is None,
    }
    if error:
        record["error"] = error
    JUDGE_LOG.parent.mkdir(exist_ok=True)
    with open(JUDGE_LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")

    if error:
        return {"error": f"Judge backend {backend_label()} failed: {error}"}
    return {"output": output, "metadata": {"judge_backend": backend_label()}}


if __name__ == "__main__":
    # One single Gemini call, no retries. Exit 0 if Gemini answers, 1 otherwise.
    if sys.argv[1:] == ["--check-gemini"]:
        try:
            call_gemini([{"role": "user", "content": 'Reply with JSON {"ok": true} only.'}], 0, retries=0)
            print(f"gemini OK ({GEMINI_MODEL})")
            sys.exit(0)
        except BackendError as e:
            print(f"gemini UNAVAILABLE ({GEMINI_MODEL}): {e}")
            sys.exit(1)
    if sys.argv[1:] == ["--label"]:
        print(backend_label())
        sys.exit(0)
    print("usage: judge_provider.py --check-gemini | --label")
    sys.exit(2)
