#!/bin/bash
# Does macOS still ENFORCE the screen-capture exclusion? (issue #920)
#
# The unit lane guards that the app sets `NSWindowSharingNone` on every window
# (Tests/ServiceTests/ScreenCaptureExclusionTests.swift). It cannot guard that
# the system still honours it: it reads the window server's own bookkeeping, so
# a macOS that kept recording `sharingType` while ignoring it would leave the
# lane green and the plaintext on screen readable. This script closes that gap
# by attempting a real cross-process capture.
#
# Run it once per macOS major, and whenever docs/SECURITY.md's screen-capture
# note is being re-checked. Apple's documentation discourages the constant
# while the shipped SDK header does not deprecate it, so the behaviour is the
# thing to keep measuring rather than the API's paperwork.
#
# Usage:
#   scripts/probe_macos_window_capture.sh [/path/to/CypherAir.app]
#
# Without an argument it builds a Debug macOS app into a scratch derived-data
# directory. Requires a GUI session, and Screen Recording permission for the
# terminal running it — the probe verifies that itself and refuses to report a
# pass it did not earn.
#
# Exit codes: 0 enforced, 1 NOT enforced (windows were captured), 2 the probe
# could not run.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d /tmp/cypherair-capture-probe.XXXXXX)"
APP_BINARY=""
APP_PID=""

cleanup() {
  [ -n "$APP_PID" ] && kill -9 "$APP_PID" 2>/dev/null
  rm -rf "$WORK"
}
trap cleanup EXIT

fail_setup() { echo "cannot run: $1" >&2; exit 2; }

case "$(uname -s)" in
  Darwin) ;;
  *) fail_setup "macOS only" ;;
esac
command -v screencapture >/dev/null || fail_setup "screencapture not found"

command -v xcrun >/dev/null || fail_setup "xcrun not found"

echo "macOS $(sw_vers -productVersion) ($(sw_vers -buildVersion)), $(uname -sr)"

# The window server is only reachable from a real API, so the two queries this
# probe needs live in a scratch Swift script rather than in the shell.
cat > "$WORK/windows.swift" <<'SWIFT'
// Probe helper (issue #920). `control` prints one on-screen window belonging to
// another process that is still shareable, to prove capture works at all here;
// `windows <pid>` prints "windowNumber sharingState" for that process.
import CoreGraphics
import Foundation

let arguments = Array(CommandLine.arguments.dropFirst())
let list = CGWindowListCopyWindowInfo([.optionOnScreenOnly], kCGNullWindowID) as? [[String: Any]] ?? []

func integer(_ info: [String: Any], _ key: CFString) -> Int? { info[key as String] as? Int }

switch arguments.first {
case "control":
    let ownPID = Int(ProcessInfo.processInfo.processIdentifier)
    for info in list {
        guard integer(info, kCGWindowOwnerPID) != ownPID,
              integer(info, kCGWindowSharingState) != 0,
              integer(info, kCGWindowLayer) == 0,
              let bounds = info[kCGWindowBounds as String] as? [String: Any],
              (bounds["Width"] as? Double ?? 0) > 100,
              (bounds["Height"] as? Double ?? 0) > 100,
              let number = integer(info, kCGWindowNumber) else { continue }
        print(number)
        break
    }
case "windows":
    let pid = Int(arguments.dropFirst().first ?? "") ?? -1
    for info in list where integer(info, kCGWindowOwnerPID) == pid {
        guard let number = integer(info, kCGWindowNumber) else { continue }
        print(number, integer(info, kCGWindowSharingState) ?? -1)
    }
default:
    FileHandle.standardError.write(Data("usage: windows.swift control | windows <pid>\n".utf8))
    exit(2)
}
SWIFT

# --- 1. Can this terminal capture at all? -----------------------------------
# Without this control a blocked capture is indistinguishable from a missing
# permission, and the probe would report "enforced" for the wrong reason.
CONTROL_ID="$(xcrun swift "$WORK/windows.swift" control 2>"$WORK/control_query.err")"
[ -n "$CONTROL_ID" ] || fail_setup "could not query the window server ($(tr -d '\n' < "$WORK/control_query.err"))"
[ -n "$CONTROL_ID" ] || fail_setup "no shareable window from another app to use as a control — open a normal window and retry"

if ! screencapture -x -l"$CONTROL_ID" -t png "$WORK/control.png" 2>"$WORK/control.err"; then
  fail_setup "the control capture failed ($(tr -d '\n' < "$WORK/control.err")) — grant this terminal Screen Recording permission and retry"
fi
[ -s "$WORK/control.png" ] || fail_setup "the control capture wrote no image — grant this terminal Screen Recording permission and retry"
echo "control: captured another app's window, so capture works here"

# --- 2. Build or take the app ------------------------------------------------
if [ $# -ge 1 ]; then
  APP_BINARY="$1/Contents/MacOS/CypherAir"
  [ -x "$APP_BINARY" ] || fail_setup "no CypherAir binary inside $1"
else
  echo "building (pass a built .app to skip)…"
  DEVELOPER_DIR="${DEVELOPER_DIR:-/Applications/Xcode-beta.app/Contents/Developer}" \
    xcodebuild build -project "$REPO_ROOT/CypherAir.xcodeproj" -scheme CypherAir \
      -destination 'platform=macOS' -derivedDataPath "$WORK/dd" >"$WORK/build.log" 2>&1 \
    || fail_setup "build failed — see $WORK/build.log (kept for this run only)"
  APP_BINARY="$WORK/dd/Build/Products/Debug/CypherAir.app/Contents/MacOS/CypherAir"
fi

# --- 3. Launch with a sheet up, so a presented window is probed too ----------
UITEST_ROOT=main UITEST_SKIP_ONBOARDING=1 UITEST_OPEN_AUTHMODE_CONFIRMATION=1 \
  "$APP_BINARY" >"$WORK/app.log" 2>&1 &
APP_PID=$!
disown "$APP_PID" 2>/dev/null   # so killing it at exit does not print job-control noise
sleep 12
kill -0 "$APP_PID" 2>/dev/null || fail_setup "the app exited during launch — see $WORK/app.log"

WINDOWS="$(xcrun swift "$WORK/windows.swift" windows "$APP_PID")"
[ -n "$WINDOWS" ] || fail_setup "the app put no window on screen — see $WORK/app.log"

# --- 4. Recorded state, then actual enforcement ------------------------------
STATUS=0
while read -r WINDOW_ID SHARING_STATE; do
  [ -n "$WINDOW_ID" ] || continue
  if [ "$SHARING_STATE" != "0" ]; then
    echo "FAIL window $WINDOW_ID: kCGWindowSharingState=$SHARING_STATE, expected 0 (the app is not excluding it)"
    STATUS=1
    continue
  fi
  if screencapture -x -l"$WINDOW_ID" -t png "$WORK/window_$WINDOW_ID.png" 2>/dev/null \
     && [ -s "$WORK/window_$WINDOW_ID.png" ]; then
    echo "FAIL window $WINDOW_ID: marked non-shareable, yet another process captured it — macOS no longer enforces NSWindowSharingNone"
    STATUS=1
  else
    echo "ok   window $WINDOW_ID: non-shareable, and capture by another process failed"
  fi
done <<< "$WINDOWS"

if [ "$STATUS" -eq 0 ]; then
  echo "ENFORCED: every on-screen window of the app refused cross-process capture"
else
  echo "NOT ENFORCED: see the failures above; docs/SECURITY.md's screen-capture note is now wrong" >&2
fi
exit "$STATUS"
