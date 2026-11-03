#!/usr/bin/env python3
"""Terminal chat with the HelpDesk Bot. Start the server first (see README)."""

import argparse
import json
import os
import sys

import httpx

TTY = sys.stdout.isatty()


def color(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m" if TTY else text


def main() -> None:
    parser = argparse.ArgumentParser(description="Chat with the Acme Fake Corp HelpDesk Bot")
    parser.add_argument("--url", default=os.getenv("BOT_URL", "http://127.0.0.1:8000"))
    args = parser.parse_args()
    url = args.url.rstrip("/")

    try:
        health = httpx.get(f"{url}/health", timeout=5).json()
        print(color(f"Connected to {url}  (model: {health['model']}, mitigation: {health['mitigation']})", "2"))
    except (httpx.HTTPError, ValueError, KeyError):
        print(color(f"Cannot reach the bot at {url}. Is the server running?", "31"))
        sys.exit(1)
    print(color("Commands: /reset clears history, /quit exits.\n", "2"))

    history: list[dict] = []
    while True:
        try:
            message = input(color("you> ", "1;36")).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not message:
            continue
        if message in ("/quit", "/exit"):
            break
        if message == "/reset":
            history.clear()
            print(color("(history cleared)\n", "2"))
            continue

        try:
            r = httpx.post(f"{url}/chat", json={"message": message, "history": history}, timeout=300)
            r.raise_for_status()
        except httpx.HTTPStatusError as e:
            print(color(f"Error {e.response.status_code}: {e.response.text}\n", "31"))
            continue
        except httpx.HTTPError as e:
            print(color(f"Request failed: {e}\n", "31"))
            continue

        data = r.json()
        if data["retrieved_docs"]:
            print(color(f"  [docs] {', '.join(data['retrieved_docs'])}", "2"))
        for tc in data["tool_calls"]:
            args_text = json.dumps(tc["arguments"], ensure_ascii=False)
            print(color(f"  [tool] {tc['tool']}({args_text}) -> {tc['status']}: {tc['result'][:200]}", "33"))
        print(color("bot> ", "1;32") + data["reply"] + "\n")

        history.append({"role": "user", "content": message})
        history.append({"role": "assistant", "content": data["reply"]})


if __name__ == "__main__":
    main()
