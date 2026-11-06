#!/usr/bin/env bash
# Run the red-team suite (each test x 3 repeats) and score it.
#
#   caffeinate -ims ./redteam/run.sh before                       # full suite, 45 results
#   JUDGE_BACKEND=groq FILTER_PATTERN='^M[1-5] ' \
#     caffeinate -ims ./redteam/run.sh before before_mt_v2        # only M1-M5, own file names
#
# Args: PHASE (before|after, checked against the bot's MITIGATION), RUN_NAME (file names; default PHASE)
# 1. Checks the bot is up (and MITIGATION matches the phase).
# 2. Picks ONE judge for the final single-turn verdicts: JUDGE_BACKEND=groq if set, else one Gemini
#    call and, if that fails, the local Ollama judge (larger model when RAM >= 16 GB, else qwen2.5:3b).
#    Multi-turn (M) verdicts always come from conversation_judge.py (Groq, whole conversation).
#    The crescendo attacker always runs on local qwen2.5:3b.
# 3. Runs promptfoo, then score.py -> results/<RUN_NAME>.csv + summary.
set -uo pipefail
cd "$(dirname "$0")/.."

PHASE="${1:-before}"
RUN_NAME="${2:-$PHASE}"
BOT_URL="${BOT_URL:-http://127.0.0.1:8000}"
LARGE_JUDGE="${LARGE_JUDGE:-qwen2.5:7b}"
SMALL_JUDGE="qwen2.5:3b"
RUN_ID="${RUN_NAME}-$(date +%Y%m%d-%H%M%S)"
mkdir -p results logs
log() { echo "[$(date '+%H:%M:%S')] $*"; }

# --- 1. bot check ---
health=$(curl -sf "$BOT_URL/health") || { log "ERROR: bot not reachable at $BOT_URL - start it first."; exit 1; }
mitigation=$(echo "$health" | python3 -c 'import sys, json; print(json.load(sys.stdin)["mitigation"])')
expected=$([ "$PHASE" = "before" ] && echo off || echo on)
if [ "$mitigation" != "$expected" ]; then
  log "ERROR: phase '$PHASE' expects MITIGATION=$expected but the bot reports $mitigation."; exit 1
fi
log "Bot OK at $BOT_URL (mitigation=$mitigation). Run id: $RUN_ID"

# --- 2. choose ONE judge for the whole run ---
note=""
gemini_status="not checked"
if [ "${JUDGE_BACKEND:-}" = "groq" ]; then
  groq_status=$(python3 redteam/judge_provider.py --check-groq) || { log "ERROR: $groq_status"; exit 1; }
  log "Judge check: $groq_status -> using Groq for the whole run (attacker stays local qwen2.5:3b)."
elif gemini_status=$(python3 redteam/judge_provider.py --check-gemini); then
  export JUDGE_BACKEND=gemini
  log "Judge check: $gemini_status -> using Gemini for the whole run."
else
  log "Judge check: $gemini_status"
  ram_gb=$(( $(sysctl -n hw.memsize) / 1073741824 ))
  if [ "$ram_gb" -ge 16 ]; then
    export JUDGE_OLLAMA_MODEL="$LARGE_JUDGE"
    if ! ollama list | awk '{print $1}' | grep -qx "$LARGE_JUDGE"; then
      log "Pulling $LARGE_JUDGE for the judge..."; ollama pull "$LARGE_JUDGE" || exit 1
    fi
  else
    export JUDGE_OLLAMA_MODEL="$SMALL_JUDGE"
    note="Judge is qwen2.5:3b, the SAME model as the bot: only ${ram_gb} GB RAM, too little for a larger judge alongside it. Treat judge verdicts with extra caution."
  fi
  export JUDGE_BACKEND=ollama
  log "Gemini unavailable -> using the local Ollama judge ($JUDGE_OLLAMA_MODEL) for the whole run."
  [ -n "$note" ] && log "FLAG: $note"
fi
export REDTEAM_RUN_ID="$RUN_ID"
judge_label=$(python3 redteam/judge_provider.py --label)
started=$(date -u +%Y-%m-%dT%H:%M:%S+00:00)

write_meta() {  # $1 = finished_at (empty while running)
  RUN_ID="$RUN_ID" PHASE="$PHASE" RUN_NAME="$RUN_NAME" JUDGE="$judge_label" NOTE="$note" \
  GEMINI_CHECK="$gemini_status" FILTER="${FILTER_PATTERN:-}" STARTED="$started" FINISHED="${1:-}" python3 -c '
import json, os
e = os.environ
json.dump({"run_id": e["RUN_ID"], "phase": e["PHASE"], "run_name": e["RUN_NAME"],
           "judge_backend": e["JUDGE"], "judge_note": e["NOTE"], "gemini_check": e["GEMINI_CHECK"],
           "filter_pattern": e["FILTER"], "started_at": e["STARTED"], "finished_at": e["FINISHED"]},
          open("results/run_" + e["RUN_NAME"] + ".json", "w"), indent=2)'
}
write_meta ""

# --- 3. run promptfoo, then score ---
export PROMPTFOO_DISABLE_TELEMETRY=1 PROMPTFOO_DISABLE_UPDATE=1 PROMPTFOO_DISABLE_REDTEAM_REMOTE_GENERATION=true
filter_args=()
[ -n "${FILTER_PATTERN:-}" ] && filter_args=(--filter-pattern "$FILTER_PATTERN")
log "Starting promptfoo: 3 repeats, concurrency 1, judge $judge_label, filter '${FILTER_PATTERN:-none}' ..."
npx promptfoo eval -c redteam/promptfooconfig.yaml --repeat 3 -j 1 --no-cache --no-table \
  -o "results/promptfoo_${RUN_NAME}.json" ${filter_args[@]+"${filter_args[@]}"}
log "promptfoo exited with code $? (100 = some tests failed, which is expected)"

write_meta "$(date -u +%Y-%m-%dT%H:%M:%S+00:00)"
python3 score.py --phase "$PHASE" --run-name "$RUN_NAME"
log "Done."
