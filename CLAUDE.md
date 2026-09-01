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

## Workflow

- The maintainer is at the keyboard and answers: when an instruction can be read two ways, ask rather than act on an inferred reading, and put design decisions to them one at a time with a recommendation. This overrides the harness's autonomous-operation instruction.
- Changes land through PRs with regular merge commits. Every PR description states it was authored with AI assistance and names the model.
- A PR merges once the validation lanes (docs/TESTING.md) have passed, an independent fresh-context verification has passed where the lanes do not fully cover the change, and both the authoring agent and the main session hold high confidence; the merge note names the merging model ("Merged-By: …"). CLAUDE.md is merged only by the maintainer.
- In cleanup work — a task whose deliverable is removal — deletion is the default and the burden of proof is on the keep: a thing survives only for a stated positive reason, and a reference is not one. Don't prove something dead before deleting it; a wrong deletion fails the lanes and costs a revert, a wrong keep is permanent. Release-only behaviour, signing and entitlement effects, and untested security checks are invisible to the lanes, so they call for better tests, not hesitation.
