# CypherAir

Offline OpenPGP encryption tool for iOS, iPadOS, macOS, and visionOS. `GPL-3.0-or-later OR MPL-2.0` for first-party code. Zero network access.

Everything below is either a project fact you cannot infer from the code or a place where this project wants something other than your default.

## Zero-Compatibility Premise — Foundation Over Blast Radius

**[Temporary — in force until the first public App Store release; internal TestFlight builds do not end it]** The app has never shipped: no users, no user data, no old on-disk state anywhere. Every persisted format, identifier, name, and schema may change freely — redesign from zero and update every reference together; never write migration or compatibility code for a past that does not exist, and never keep a version marker "for future migration". When another document conflicts with this premise, that document changes.

## Code

- Much of this codebase is older-generation model output. Do not match it: write what is correct by your own judgment, and match local naming and formatting only where it costs nothing.
- In code you touch, delete outdated comments rather than leaving them; most inline notes never needed recording.
- Most changes need no new tests. Write one only where it guards behaviour a later change could quietly break; a test that restates the code is not worth committing.
- Prefer the architecturally correct solution over the smallest patch. This sets the depth of a change, not its scope.
- Docs state the current contracts a reader cannot recover from the code or the machinery: no history, no restating what the code shows.
