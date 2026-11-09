# CypherAir

Offline OpenPGP encryption tool for iOS, iPadOS, macOS, and visionOS. `GPL-3.0-or-later OR MPL-2.0` for first-party code. Zero network access.

Everything below is either a project fact you cannot infer from the code or a place where this project wants something other than your default.

## Code

This codebase is yours: what it's for and how it's built are your call, and you'll keep building on it.

- Much of this codebase is older-generation model output. Do not match it: write what is correct by your own judgment, and match local naming and formatting only where it costs nothing.
- In code you touch, delete outdated comments rather than leaving them; most inline notes never needed recording.
- Most changes need no new tests. Write one only where it guards behaviour a later change could quietly break; a test that restates the code is not worth committing.
- Prefer the architecturally correct solution over the smallest patch.
- Docs state the current contracts a reader cannot recover from the code or the machinery: no history, no restating what the code shows.

# Communicating clearly
Write for an intelligent but low-context reader. The person reading has not seen your tool calls, your reasoning or the files you opened, and may be switching in from other work. Messages should generally be self-contained: the reader should understand what you mean without having to dig for other context. Put the key points in the first few sentences. Practice progressive disclosure in your sentence order, and do not use undefined references and ideas in line 1 that won't make sense until the reader reaches line 12.

Use plain words, and write in clear, understandable full sentences. Do not use a term or abbreviation that you made up during the work. Say what the thing is in a way any reader would understand. Write mostly in the style of ASD-STE100 Simplified Technical English: short sentences, one idea per sentence, active voice, and consistently using the same word for the same thing. Use a paragraph of flowing prose where ideas connect, and keep bullets for lists of separate items. Leave out unnecessary details unless the reader asks and practice concision, but do ensure that your messages have the key context. Aim to make your user-facing text as human-readable and clear as possible.

Before you start, say in a line what you're about to do; brief updates while you work help the user follow along. Close with a short recap that stands on its own (what you found, what you did, and what's next), so a reader who only sees the last message has the full picture.
