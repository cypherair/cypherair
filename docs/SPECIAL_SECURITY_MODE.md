# Special Security Mode

> Purpose: Product-facing feature specification for the proposed Special Security Mode and its supporting Settings flow.
> Audience: Product, design, engineering, QA, and AI coding tools.
> Status: Draft intermediate spec. This document does not yet modify the canonical PRD, TDD, SECURITY, or TESTING documents.

## 1. Overview

CypherAir currently exposes two authentication modes in Settings:

- **Standard** — biometrics with device passcode fallback
- **High Security** — biometrics only, no passcode fallback

This document defines a proposed third mode:

- **Special Security Mode**

Special Security Mode is intended for users with unusually high privacy and coercion resistance requirements. It raises protection beyond the current High Security mode by binding private-key access to the device's current biometric enrollment set. In product terms, this means that if Face ID or Touch ID enrollment is reset, the app can no longer access the existing on-device private keys protected by this mode.

The tradeoff is significant: this mode materially increases the chance of permanent local key loss unless the user has already created current backups of all private keys.

This document is intentionally product-facing and interaction-detailed. It defines the intended user experience, feature behavior, risks, and recovery expectations without prescribing code-level implementation.

## 2. User Value and Risk

### User Value

Special Security Mode exists for users who need stronger assurance that possession of the device and knowledge of the device passcode are still not enough to regain access to encrypted private-key operations after biometric state changes.

Example users include:

- journalists operating in seizure or coercion risk environments
- activists or dissidents with high concern about forced device access
- users who explicitly prefer stronger anti-re-enrollment protections over convenience and recoverability

### Core Risk

The same property that makes this mode stronger also makes it more dangerous:

- if the biometric enrollment set changes, the app's protected private keys may become inaccessible on that device
- recovery is expected to come from previously exported private key backups
- users who have not backed up their keys are at elevated risk of irreversible data loss

Because of that risk, this feature must be hidden behind an explicit reveal step and strict backup gating rules.

## 3. Settings Structure

### Current Settings Model

The app continues to present an **Authentication Mode** control in Settings as the place where the user selects how private-key operations are protected.

By default, the Authentication Mode control shows only:

- **Standard**
- **High Security**

### New Advanced Settings Page

Settings gains a new **Advanced Settings** page.

This page contains a new toggle:

- **Show "Special Security Mode" option**

Default behavior:

- the toggle is **off** by default
- Special Security Mode is therefore hidden by default
- turning the toggle on only reveals the extra mode in the Authentication Mode selector
- turning the toggle on does **not** switch the user's authentication mode by itself

### Reveal Model

After the user successfully enables **Show "Special Security Mode" option**:

- the Authentication Mode selector now shows three options:
  - **Standard**
  - **High Security**
  - **Special Security Mode**

If the toggle is off, the selector returns to showing only the default two modes unless the user is currently in Special Security Mode. That special case is defined in Section 6.

## 4. Authentication Mode Behavior

### Standard

- remains the default mode
- allows biometric authentication with device passcode fallback
- remains suitable for most users

### High Security

- remains the currently available stronger mode
- allows biometric authentication only
- does not allow passcode fallback

### Special Security Mode

- is revealed only after the user enables **Show "Special Security Mode" option**
- uses the same Authentication Mode selector as the existing modes
- is intended as an opt-in mode for high-risk users who accept substantially higher data-loss risk

User-facing behavior:

- if biometric enrollment remains unchanged, private-key operations continue to behave like a biometric-only mode
- if biometric enrollment is reset or replaced, private-key operations protected by this mode are expected to become inaccessible on that device
- the expected recovery path is restoring from an exported private key backup

## 5. User Flows

### Flow A: Reveal the Mode

1. User opens `Settings`.
2. User navigates to `Advanced Settings`.
3. User sees **Show "Special Security Mode" option**, defaulted to off.
4. User attempts to turn the toggle on.
5. The app checks whether all current private keys have already been backed up.

If all current private keys are backed up:

6. The toggle turns on.
7. Returning to Authentication Mode now shows **Special Security Mode** as a third selectable option.

If any current private key is not backed up:

6. The toggle does not turn on.
7. The app blocks the action and tells the user that all private keys must be backed up first.

This is a hard requirement, not a warning-only path.

### Flow B: Switch into Special Security Mode

1. User opens `Settings`.
2. User opens the Authentication Mode selector.
3. User chooses **Special Security Mode**.
4. The app checks again whether all current private keys are already backed up.

If all current private keys are backed up:

5. The app presents the same style of confirmation flow already used for enabling High Security Mode.
6. The confirmation explains that resetting Face ID or Touch ID may make on-device private keys inaccessible and that recovery depends on backups.
7. The user confirms the change.
8. The app requires the same biometric confirmation pattern used for the current High Security mode switch flow.
9. The mode changes only after the user successfully confirms.

If any current private key is not backed up:

5. The mode switch is blocked.
6. The app explains that all private keys must be backed up before this mode can be enabled.

This second check is required even if the reveal toggle had already been enabled earlier.

### Flow C: Generate or Import a New Key While Already in Special Security Mode

1. User is already operating in Special Security Mode.
2. User generates a new private key or imports an existing private key.
3. The app allows the operation to complete.
4. After completion, the app strongly reminds the user to back up that new key immediately.

Expected product behavior:

- the app does **not** auto-downgrade the authentication mode
- the app does **not** forbid key generation or import in this mode
- the app does make the elevated backup risk explicit at the end of the flow

## 6. Rules and Guardrails

### Backup Gating

Special Security Mode uses an all-keys-backed-up rule rather than an any-key-backed-up rule.

The app must require that **all current private keys** are already backed up before either of the following actions can succeed:

- enabling **Show "Special Security Mode" option**
- switching the Authentication Mode to **Special Security Mode**

This gating is intentionally strict because the consequence of biometric enrollment reset is loss of local access to any affected private key that lacks a backup.

### Hidden by Default

Special Security Mode must not be visible in the default Settings experience.

This keeps the default experience safer for mainstream users and ensures the feature is only encountered by users who intentionally opt in to advanced settings.

### Reveal Toggle Does Not Change Security State

**Show "Special Security Mode" option** is a visibility control only.

Turning it on:

- reveals the option in the Authentication Mode selector
- does not itself change how keys are protected
- does not itself switch the app into Special Security Mode

### UI State Lock While Active

If the current authentication mode is **Special Security Mode**:

- the visibility toggle must remain enabled
- the user must not be allowed to turn it off while this mode is still active

Rationale:

- the Settings UI must never hide the currently active authentication mode from the selector
- the user should first switch to `Standard` or `High Security`, then optionally hide the Special Security Mode option

### Confirmation Requirement

Switching into Special Security Mode must use the same style of confirmation flow currently used for High Security Mode.

The confirmation flow should make three product facts clear:

- this mode is intentionally stronger and riskier
- biometric enrollment reset can make on-device private keys inaccessible
- recovery depends on previously exported backups

## 7. Failure and Recovery Expectations

### Expected Failure Scenario

The defining failure scenario for this mode is biometric enrollment reset.

Examples include:

- Face ID being reset and re-enrolled
- Touch ID fingerprints being removed and re-enrolled
- equivalent biometric enrollment changes that replace the prior biometric set

After that kind of change, the user should expect:

- private-key operations such as decrypt, sign, or backup export may no longer succeed for keys protected by Special Security Mode
- the app should communicate that the protected on-device keys are no longer available under the prior protection state

### Expected Recovery Path

The expected recovery path is:

1. obtain the previously exported private key backup
2. import or restore that backup into the app
3. re-establish secure on-device protection for future use

This document assumes backup-based recovery as the intended user story. It does not define the detailed implementation or UI for the restore flow itself.

### User Messaging Expectations

When this failure scenario occurs, the user-facing message should be recovery-oriented rather than generic.

The product expectation is that the app should explain, in plain language, that:

- access to the existing on-device private key is no longer available
- this can happen after biometric enrollment changes
- the next step is to restore from backup

## 8. Product Acceptance Expectations

This document does not define test implementation details, but the product behavior should be considered acceptable only if all of the following are true:

- Special Security Mode is hidden by default
- the reveal toggle exists only in Advanced Settings
- enabling the reveal toggle requires all current private keys to already be backed up
- switching into Special Security Mode requires the same all-keys-backed-up check again
- switching into Special Security Mode uses the existing High Security-style confirmation pattern
- the reveal toggle alone does not change the current authentication mode
- if the user is actively in Special Security Mode, the reveal toggle cannot be turned off
- generating or importing a new key while in this mode remains allowed, but produces a strong reminder to back it up immediately
- the recovery expectation after biometric enrollment reset is clearly explained

## 9. Out of Scope for This Document

This document does not define:

- code architecture
- Security.framework API details
- `SecAccessControl` flag mapping
- migration mechanics or crash-recovery implementation
- error-type design
- test-case implementation details
- direct edits to `PRD.md`
- direct edits to `TDD.md`
- direct edits to `SECURITY.md`
- direct edits to `TESTING.md`

Those topics should be handled later, after this product-facing behavior has been reviewed and accepted.

## 10. Open Questions / Follow-up for Implementation

- Finalize the permanent product naming for `Special Security Mode`. The current name is a working label.
- Finalize the permanent user-facing wording for the Advanced Settings toggle label.
- Decide whether the app should show backup-specific inline guidance, a blocking alert, or a dedicated screen when the all-keys-backed-up requirement is not met.
- Define the exact post-generation and post-import reminder language for users already operating in Special Security Mode.
- Define how the restore path should be surfaced immediately after the biometric-reset failure is detected.
- After this document is accepted, update the canonical PRD, TDD, SECURITY, and TESTING documents to reflect the final approved behavior.
