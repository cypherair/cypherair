# CypherAir

Offline OpenPGP encryption tool for iOS, iPadOS, macOS, and visionOS. `GPL-3.0-or-later OR MPL-2.0` for first-party code. Zero network access.

Everything below is either a project fact you cannot infer from the code or a place where this project wants something other than your default.

Before you start, say in a line what you're about to do; brief updates while you work help the user follow along. Close with a short recap that stands on its own (what you found, what you did, and what's next), so a reader who only sees the last message has the full picture.

## 2.0

**[Temporary — until 2.0 is released]** The app is being rebuilt as version 2.0, and 2.0 reads no data that 1.x wrote. Stored formats, identifiers and schemas may change freely; write no migration or compatibility code.

## Code

This codebase is yours: what it's for and how it's built are your call, and you'll keep building on it.

- Much of this codebase is older-generation model output. Do not match it: write what is correct by your own judgment, and match local naming and formatting only where it costs nothing.
- In code you touch, delete outdated comments rather than leaving them; most inline notes never needed recording.
- Most changes need no new tests. Write one only where it guards behaviour a later change could quietly break; a test that restates the code is not worth committing.
- Prefer the architecturally correct solution over the smallest patch.
- Docs state the current contracts a reader cannot recover from the code or the machinery: no history, no restating what the code shows.
