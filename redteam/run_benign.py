#!/usr/bin/env python3
"""Over-blocking check: run 20 normal helpdesk questions (redteam/benign.csv) once each.

  python3 redteam/run_benign.py off   # bot running with MITIGATION=off -> fills reply_before
  python3 redteam/run_benign.py on    # bot running with MITIGATION=on  -> fills reply_after

Writes results/benign.csv with columns prompt_id, prompt, reply_before, reply_after
(the column of the other mode is kept). Nothing is judged here - refusals are marked by hand.
Every request is also logged to logs/benign_runs.jsonl (with tool calls). Standard library only.
"""

import csv
import json
import os
import sys
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PROMPTS = ROOT / "redteam" / "benign.csv"
OUT = ROOT / "results" / "benign.csv"
RUN_LOG = ROOT / "logs" / "benign_runs.jsonl"
BLOCK_LOG = ROOT / "logs" / "blocked.jsonl"
BOT_URL = os.environ.get("BOT_URL", "http://127.0.0.1:8000").rstrip("/")
COLUMNS = ["prompt_id", "prompt", "reply_before", "reply_after"]


def post(path: str, payload: dict | None = None) -> dict:
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(f"{BOT_URL}{path}", data=data, headers={"content-type": "application/json"})
    with urllib.request.urlopen(req, timeout=300) as r:
        return json.loads(r.read())


def main() -> int:
    mode = sys.argv[1] if len(sys.argv) > 1 else ""
    if mode not in ("off", "on"):
        print(__doc__)
        return 2
    bot_mode = post("/health")["mitigation"]
    if bot_mode != mode:
        print(f"ERROR: asked for MITIGATION={mode} but the bot reports {bot_mode}. Restart the bot first.")
        return 1
    column = "reply_before" if mode == "off" else "reply_after"

    prompts = list(csv.DictReader(open(PROMPTS, encoding="utf-8")))
    rows = {p["prompt_id"]: {"prompt_id": p["prompt_id"], "prompt": p["prompt"], "reply_before": "", "reply_after": ""}
            for p in prompts}
    if OUT.exists():  # keep the other mode's replies
        for old in csv.DictReader(open(OUT, encoding="utf-8")):
            if old["prompt_id"] in rows and old["prompt"] == rows[old["prompt_id"]]["prompt"]:
                rows[old["prompt_id"]].update({k: old.get(k, "") for k in ("reply_before", "reply_after")})

    request_ids, tool_status = [], {}
    RUN_LOG.parent.mkdir(exist_ok=True)
    for p in prompts:
        started = time.time()
        try:
            data = post("/chat", {"message": p["prompt"], "history": []})
            reply = data["reply"]
        except Exception as e:  # keep going; the error is visible in the CSV
            data, reply = {}, f"[ERROR] {e}"
        rows[p["prompt_id"]][column] = reply
        request_ids.append(data.get("request_id"))
        for tc in data.get("tool_calls", []):
            key = f"{tc['tool']} {tc['status']}"
            tool_status[key] = tool_status.get(key, 0) + 1
        with open(RUN_LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps({
                "timestamp": datetime.now(timezone.utc).isoformat(), "mitigation": mode,
                "prompt_id": p["prompt_id"], "request_id": data.get("request_id"), "prompt": p["prompt"],
                "reply": reply, "tool_calls": data.get("tool_calls", []), "latency_s": round(time.time() - started, 1),
            }, ensure_ascii=False) + "\n")
        print(f"{p['prompt_id']} ({time.time() - started:4.1f}s) {reply[:90]!r}", flush=True)

    OUT.parent.mkdir(exist_ok=True)
    with open(OUT, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=COLUMNS)
        w.writeheader()
        w.writerows(rows[p["prompt_id"]] for p in prompts)

    wanted = set(filter(None, request_ids))
    blocks = [json.loads(line) for line in open(BLOCK_LOG, encoding="utf-8")] if BLOCK_LOG.exists() else []
    blocks = [b for b in blocks if b.get("request_id") in wanted]
    print(f"\nWrote {column} for {len(prompts)} prompts to {OUT.relative_to(ROOT)}")
    print("Tool calls: " + (", ".join(f"{k} x{v}" for k, v in sorted(tool_status.items())) or "none"))
    print(f"Guardrail blocks logged: {sum(b['kind'] == 'reply' for b in blocks)} replies replaced, "
          f"{sum(b['kind'] == 'send_email' for b in blocks)} send_email blocked")
    return 0


if __name__ == "__main__":
    sys.exit(main())
