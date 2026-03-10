# Task Templates

> Purpose: Standardized description templates for issuing clear instructions to Claude Code.
> Audience: Human developers writing prompts for AI coding tools.

Copy and fill in the appropriate template when assigning a task to Claude Code. The structured format ensures Claude has all the context needed to produce correct, safe, well-tested code.

---

## Template 1: New Feature

```markdown
## Task: [Feature name]

### Context
[What this feature does and why. Reference PRD section if applicable.]

### Acceptance Criteria
- [ ] [Specific, testable criterion]
- [ ] [Another criterion]
- [ ] User-facing strings are in String Catalog (en + zh-Hans)
- [ ] VoiceOver labels on all interactive elements
- [ ] Tests written per docs/TESTING.md

### Files Likely Affected
- [List expected files, or "Determine by reading existing code"]

### Security Implications
- [ ] Does this touch private key material? [yes/no]
- [ ] Does this modify Keychain access? [yes/no]
- [ ] Does this involve authentication? [yes/no]
- [ ] Does this involve user data persistence? [yes/no]
- [ ] If any YES: read docs/SECURITY.md and stop to describe the data flow before implementing.

### Profile Implications
- [ ] Does this feature behave differently per profile? [yes/no]
- [ ] If yes: describe behavior for Profile A and Profile B.
- [ ] Tests cover both profiles? [yes/no — if no, justify]

### UI Notes
- [Describe the UI if applicable. Reference Liquid Glass guide: docs/LIQUID_GLASS.md]
- [Glass or no glass? Which variant?]

### Test Requirements
- [ ] Positive test: [describe happy path]
- [ ] Negative test: [describe failure case]
- [ ] Both profiles tested? [yes/no]
- [ ] [Any additional tests]
```

**Example (filled):**

```markdown
## Task: Add encrypt-to-self toggle to EncryptView

### Context
PRD 4.3: Users can toggle "encrypt-to-self" per message. Default ON. When ON, the sender's
own public key is added to the recipient list so they can decrypt their own ciphertext.

### Acceptance Criteria
- [ ] Toggle visible on EncryptView, default ON
- [ ] Toggle state persisted as default in UserDefaults (configurable in Settings)
- [ ] When ON: sender's public key added to recipient list before encryption
- [ ] When OFF: sender's public key not in recipient list
- [ ] Localized label: "Encrypt to self" (en), "加密给自己" (zh-Hans)
- [ ] VoiceOver: toggle has descriptive label

### Files Likely Affected
- Sources/App/Encrypt/EncryptView.swift
- Sources/Services/EncryptionService.swift
- Sources/Models/AppConfiguration.swift
- Localizable.xcstrings

### Security Implications
- [ ] Does this touch private key material? No — only adds a public key to recipient list.
- [ ] Does this modify Keychain access? No.
- [ ] Does this involve authentication? No.
- [ ] Does this involve user data persistence? Yes — UserDefaults preference.
- [ ] Data flow: UserDefaults stores a boolean (com.cypherair.preference.encryptToSelf).
       No sensitive data. No security review needed.

### Profile Implications
- [ ] Does this feature behave differently per profile? No — encrypt-to-self adds the
       sender's own public key regardless of profile. Format auto-selection handles the rest.
- [ ] Tests cover both profiles? Yes — round-trip test with self-decryption for both profiles.

### UI Notes
- Toggle uses standard SwiftUI Toggle (auto Liquid Glass). No custom glass needed.
- Place below recipient picker, above Encrypt button.

### Test Requirements
- [ ] Positive: encrypt with toggle ON → sender can decrypt own ciphertext (both profiles)
- [ ] Negative: encrypt with toggle OFF → sender cannot decrypt
- [ ] Default state: verify toggle defaults to ON on fresh install
```

---

## Template 2: Bug Fix

```markdown
## Task: Fix [bug description]

### Reproduction Steps
1. [Step 1]
2. [Step 2]
3. [Observed behavior]

### Expected Behavior
[What should happen instead]

### Suspected Root Cause
[Module or file if known. Otherwise: "Investigate"]

### Files Likely Affected
- [List if known]

### Security Impact
- [ ] Could this bug cause data leakage? [yes/no/unknown]
- [ ] Could the fix weaken any security invariant? [yes/no]
- [ ] If any YES: stop and describe the fix before implementing.

### Profile Impact
- [ ] Affects one profile or both? [A/B/both]

### Regression Test
- [ ] Write a test that reproduces the bug (fails before fix, passes after)
- [ ] [Additional tests if needed]
```

**Example (filled):**

```markdown
## Task: Fix AEAD error not shown when ciphertext is truncated

### Reproduction Steps
1. Encrypt a text message (Profile B)
2. Truncate the ciphertext (remove last 20 characters of ASCII armor)
3. Attempt to decrypt the truncated ciphertext
4. App shows generic "Decrypt failed" instead of AEAD-specific error

### Expected Behavior
Error message: "❌ Message may have been tampered with." (PRD 4.7 AEAD failure)

### Suspected Root Cause
DecryptionService catches the error but maps it to a generic case instead of
.aeadAuthenticationFailed.

### Files Likely Affected
- Sources/Services/DecryptionService.swift
- Sources/Models/PGPError.swift (verify mapping)

### Security Impact
- [ ] Data leakage: No — decryption correctly fails, just wrong message.
- [ ] Weaken security: No — AEAD hard-fail still works, only the user message is wrong.

### Profile Impact
- [ ] Affects Profile B (AEAD). Profile A uses MDC — verify analogous tamper error is correct too.

### Regression Test
- [ ] test_decrypt_withTruncatedCiphertext_showsAEADError
```

---

## Template 3: Refactor

```markdown
## Task: Refactor [what]

### Motivation
[Why this refactor is needed. What problem it solves.]

### Scope
- [ ] Files in scope: [list]
- [ ] Files explicitly OUT of scope: [list — do not touch these]

### What Must NOT Change
- [ ] Public API signatures [if applicable]
- [ ] Test behavior — all existing tests must still pass
- [ ] Security invariants — no weakening of access control, zeroing, or error handling
- [ ] Profile behavior — both profiles must produce identical results as before
- [ ] [Other contracts]

### Before / After Contract
[Describe the behavioral contract that must be preserved. E.g., "EncryptionService.encrypt()
accepts the same parameters and returns the same result type."]

### Test Requirements
- [ ] All existing tests pass without modification
- [ ] [New tests if the refactor introduces new internal boundaries]
```

---

## Template 4: Security Change

Use this template for ANY change that touches files listed in docs/SECURITY.md Section 7.

```markdown
## Task: [Security change description]

### Threat Model Context
[What threat does this address? What is the attack scenario?]

### Exact Change Proposed
[Describe precisely what will change. Include the specific access control flags,
Keychain attributes, CryptoKit calls, or Rust code that will be modified.]

### What Could Go Wrong
- [Risk 1: e.g., "Wrong flags → passcode fallback in High Security mode"]
- [Risk 2: e.g., "Zeroize removed → key material lingers in memory"]

### Human Review Checkpoint
⚠️ Claude Code: STOP HERE. Describe the proposed implementation and wait for approval
before writing any code. Do not proceed autonomously.

### Required Tests
- [ ] Positive test: [correct behavior under new logic]
- [ ] Negative test: [failure case handled correctly]
- [ ] Round-trip test: [if crypto-related]
- [ ] Memory test: [if sensitive data handling changed]

### Rollback Plan
[How to revert if the change causes issues. E.g., "Restore previous access control flags
and re-wrap keys using the old configuration."]
```

**Example (filled):**

```markdown
## Task: Implement High Security → Standard mode switch

### Threat Model Context
User wants to downgrade from biometric-only to biometric+passcode. This requires
re-wrapping all SE-protected keys with new access control flags.

### Exact Change Proposed
In AuthenticationManager.switchMode(to:):
1. Authenticate under current mode (.deviceOwnerAuthenticationWithBiometrics)
2. Set rewrapInProgress flag in UserDefaults
3. For each identity:
   a. Unwrap with current SE key
   b. Generate new SE key with [.privateKeyUsage, .biometryAny, .or, .devicePasscode]
   c. Re-wrap with new SE key
   d. Store new items under TEMPORARY key names (com.cypherair.v1.pending-*)
   e. Zeroize raw key bytes
4. Verify all new items stored successfully
5. Delete old Keychain items (com.cypherair.v1.se-key.* etc.)
6. Rename temporary items to permanent key names
7. Update UserDefaults auth mode preference
8. Clear rewrapInProgress flag

### What Could Go Wrong
- Crash mid-re-wrap → keys in inconsistent state. Mitigation: rewrapInProgress flag
  enables crash recovery on next launch (see SECURITY.md Section 4).
- Wrong flags on new SE key → High Security mode still active despite UI showing Standard.
  Mitigation: test both positive (passcode now works) and negative (biometry still works).
- Zeroize missed after unwrap → raw key lingers in memory.

### Human Review Checkpoint
⚠️ STOP. Describe implementation approach and wait for approval.

### Required Tests
- [ ] test_modeSwitch_highToStandard_passcodeNowWorks
- [ ] test_modeSwitch_failsMidway_originalKeysIntact
- [ ] test_modeSwitch_crashMidway_recoversOnLaunch
- [ ] test_modeSwitch_rawKeyZeroizedAfterRewrap
- [ ] test_modeSwitch_allIdentitiesRewrapped

### Rollback Plan
If re-wrap fails for any identity: delete all temporary (pending-*) Keychain items,
clear the rewrapInProgress flag. Original keys remain intact under their permanent names.
Do not delete originals until all new items are confirmed stored.
```

---

## Template 5: Rust API Change

Use this template when modifying the public API of the `pgp-mobile` crate.

```markdown
## Task: [API change description]

### Context
[Why this API change is needed. What feature or fix requires it.]

### API Change
```rust
// Before (if modifying existing)
pub fn existing_function(arg: Type) -> Result<ReturnType, PgpError>

// After
pub fn existing_function(arg: Type, new_arg: NewType) -> Result<ReturnType, PgpError>

// Or: new function
pub fn new_function(args...) -> Result<ReturnType, PgpError>
```

### Cascading Updates Required
- [ ] `pgp-mobile/src/` — implement the Rust change
- [ ] Rebuild host dylib: `cargo build --release`
- [ ] Regenerate Swift bindings: `cargo run --bin uniffi-bindgen generate ...`
- [ ] Rebuild XCFramework for both targets
- [ ] Update Swift call sites in `Sources/Services/` to use new API
- [ ] Add/update Rust tests in `pgp-mobile/tests/` (positive + negative, both profiles)
- [ ] Add/update FFI round-trip tests in Swift test target (both profiles)
- [ ] If new error variant: add to `PgpError` enum + update `PGPError.swift` mapping

### Profile Impact
- [ ] Affects Profile A, B, or both?

### Backward Compatibility
- [ ] Does this break existing Swift call sites? [yes/no — if yes, list them]
- [ ] Does this require XCFramework consumers to update? [yes — always for API changes]

### Test Requirements
- [ ] Rust unit test for the new/changed function (positive + negative, both profiles)
- [ ] FFI round-trip test: call from Swift, verify correct behavior
- [ ] If new error type: test error propagation across FFI boundary
```

---

## Usage Tips

- **Be specific.** "Add encryption" is too vague. "Add file encryption for files ≤ 100 MB with progress indicator and cancellation support" is actionable.
- **Reference docs.** Point Claude to the relevant section: "See docs/SECURITY.md Section 3 for the SE wrapping flow."
- **State what NOT to do.** "Do not refactor the Keychain layer as part of this task" prevents scope creep.
- **Include test criteria.** Claude will write better code when it knows what tests to write alongside. **Specify both profiles unless explicitly scoped to one.**
- **Use the Security template** for anything touching `Sources/Security/`, `Sources/Services/DecryptionService.swift`, `Sources/Services/QRService.swift`, `pgp-mobile/src/`, or entitlements. The human review checkpoint is not optional.
- **Use the Rust API Change template** for any modification to `pgp-mobile`'s public API. The cascading update checklist prevents forgetting a step.
