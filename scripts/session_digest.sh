#!/bin/bash
# Condense Claude Code session transcripts (.jsonl) into readable digests —
# used for periodic work-methods reviews of this project's agent sessions.
#
# Usage: scripts/session_digest.sh [project-or-transcript-dir] [output-dir]
#   arg 1  a project directory (default: cwd) whose Claude Code transcript
#          store is derived as ~/.claude/projects/<sanitized-path>; if the
#          given directory itself contains .jsonl transcripts it is used as-is
#   arg 2  output directory (default: ${TMPDIR:-/tmp}/session-digests)
#
# Produces, per session:
#   <out>/user/<id>.txt  — user messages only (asks, corrections, approvals)
#   <out>/full/<id>.txt  — user + assistant text + one-line tool calls
# and cross-session stats under <out>/stats/ (bash command frequency, tool/
# skill/agent usage, per-session interrupt/denial/error counters).
#
# Notes: archived sessions keep their .jsonl on disk (archiving only hides
# them from the app's list). Each assistant line carries message.model, so
# sessions can be filtered by model, e.g.:
#   jq -r 'select(.type=="assistant") | .message.model' <id>.jsonl | sort -u
set -uo pipefail

# Digests replay session content; keep them unreadable to other local users
# and default to the per-user temp dir instead of world-writable /tmp.
umask 077

ARG="${1:-$PWD}"
if ls "$ARG"/*.jsonl >/dev/null 2>&1; then
  SRC="$ARG"
else
  SRC="$HOME/.claude/projects/$(cd "$ARG" && pwd | sed 's|[^A-Za-z0-9]|-|g')"
fi
OUT="${2:-${TMPDIR:-/tmp}/session-digests}"
if ! ls "$SRC"/*.jsonl >/dev/null 2>&1; then
  echo "no transcripts found under $SRC" >&2
  exit 2
fi
echo "transcripts: $SRC"
mkdir -p "$OUT/user" "$OUT/full" "$OUT/stats"

FULL_JQ='
def ts: (.timestamp // "")[5:16];
if .type=="user" and (.isSidechain!=true) then
  (.message.content) as $c
  | (if ($c|type)=="string" then $c else ([$c[]? | select(.type=="text") | .text] | join("\n")) end) as $t
  | if ($t|length)>0 then "\n[U " + ts + "] " + ($t[0:2000]) else empty end
elif .type=="assistant" and (.isSidechain!=true) then
  ([ .message.content[]?
    | if .type=="text" and ((.text|length)>0) then "[A " + ts + "] " + (.text[0:400])
      elif .type=="tool_use" then
        ("  T:" + .name + " " +
        ( if .name=="Bash" then (((.input.command // "") | gsub("\\s+";" "))[0:150])
          elif .name=="Skill" then ((.input.skill // "") + " " + (((.input.args // "")|tostring)[0:60]))
          elif .name=="Agent" then ((.input.subagent_type // "gp") + " | " + (((.input.model // "")|tostring)) + " | " + ((.input.description // "")[0:80]))
          elif .name=="Workflow" then ("wf:" + (((.input.name // .input.scriptPath // "inline")|tostring)[0:80]))
          else (((.input.file_path // .input.query // .input.pattern // .input.skill // "")|tostring)[0:100])
          end ))
      else empty end ] | join("\n")) | select(length>0)
else empty end'

USER_JQ='
def ts: (.timestamp // "")[5:16];
if .type=="user" and (.isSidechain!=true) then
  (.message.content) as $c
  | (if ($c|type)=="string" then $c else ([$c[]? | select(.type=="text") | .text] | join("\n")) end) as $t
  | if ($t|length)>0 then "\n[" + ts + "] " + ($t[0:2500]) else empty end
else empty end'

ALL_FILES=""
for f in "$SRC"/*.jsonl; do
  [ -f "$f" ] || continue
  id=$(basename "$f" .jsonl)
  jq -r "$USER_JQ" "$f" > "$OUT/user/${id:0:8}.txt" 2>/dev/null
  jq -r "$FULL_JQ" "$f" > "$OUT/full/${id:0:8}.txt" 2>/dev/null
  ALL_FILES="$ALL_FILES $f"
done

jq -r 'select(.type=="assistant") | .message.content[]? | select(.type=="tool_use" and .name=="Bash") | .input.command | gsub("\\s+";" ") | .[0:100]' $ALL_FILES 2>/dev/null | sort | uniq -c | sort -rn | head -100 > "$OUT/stats/bash_freq.txt"
jq -r 'select(.type=="assistant") | .message.content[]? | select(.type=="tool_use") | .name' $ALL_FILES 2>/dev/null | sort | uniq -c | sort -rn > "$OUT/stats/tool_freq.txt"
jq -r 'select(.type=="assistant") | .message.content[]? | select(.type=="tool_use" and .name=="Skill") | .input.skill' $ALL_FILES 2>/dev/null | sort | uniq -c | sort -rn > "$OUT/stats/skill_freq.txt"
jq -r 'select(.type=="assistant") | .message.content[]? | select(.type=="tool_use" and .name=="Agent") | ((.input.subagent_type // "gp") + " | " + ((.input.model // "inherit")|tostring))' $ALL_FILES 2>/dev/null | sort | uniq -c | sort -rn > "$OUT/stats/agent_freq.txt"

{
for f in $ALL_FILES; do
  id=$(basename "$f" .jsonl)
  ints=$(grep -c 'Request interrupted' "$f" 2>/dev/null)
  den=$(grep -c "doesn.t want to proceed" "$f" 2>/dev/null)
  err=$(grep -c '"is_error":true' "$f" 2>/dev/null)
  echo "$ints interrupts | $den denials | $err tool-errors | ${id:0:8}"
done
} | sort -rn > "$OUT/stats/friction.txt"

echo "digests written to $OUT"
du -sh "$OUT/user" "$OUT/full" 2>/dev/null
