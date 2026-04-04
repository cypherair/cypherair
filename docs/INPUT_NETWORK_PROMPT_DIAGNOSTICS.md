# Input Network Prompt Diagnostics

Purpose: guide follow-up investigation of the network-related prompt reported on mainland China iPhones when focusing text input.

## Security Baseline

- Do not use a custom UIKit text field for passphrase entry.
- Keep import and backup passphrases on system `SecureField`.
- Limit `CypherMultilineTextInput` to non-sensitive multiline text only.

## First Capture

Before changing behavior further on iPhone:

1. Record the exact prompt text in Simplified Chinese and English if possible.
2. Take a screenshot of the alert.
3. Check whether Settings > Privacy & Security > Local Network contains a CypherAir entry after reproduction.

If the prompt text matches Apple's Local Network wording, follow the Local Network path below.
If the prompt is generic network wording and no Local Network entry appears, treat it as an undocumented system or regional behavior and collect evidence for Feedback.

Reference wording:

- Apple Support: "If an app would like to connect to devices on your local network"
- TN3179: local network alerts appear when an app performs a local network operation

## Reproduction Matrix

Run the same focus sequence on a mainland China iPhone in these two configurations:

1. Apple system keyboard only, with all third-party keyboards disabled.
2. Third-party keyboard support enabled again.

For each configuration, focus these inputs in order:

1. Import passphrase `SecureField`
2. Backup passphrase `SecureField`
3. Name `TextField`
4. Email `TextField`
5. Multiline text areas backed by `CypherMultilineTextInput`

Record for each case:

- Whether the prompt appears
- Exact alert text
- Whether a Local Network settings entry appears
- Which keyboard was active

## Decision Rules

- If the prompt appears only when a third-party keyboard is allowed:
  The next mitigation candidate is to reject custom keyboards app-wide using `application(_:shouldAllowExtensionPointIdentifier:)`.
- If the prompt appears with the Apple system keyboard and a Local Network entry appears:
  Investigate hidden local-network triggers and file Feedback with collected evidence.
- If the prompt appears with the Apple system keyboard and no Local Network entry appears:
  Treat it as undocumented system behavior. Do not add more aggressive input-control workarounds without new evidence. File Feedback with screenshots, iOS build number, device region, and reproduction steps.

## Relevant Apple References

- SwiftUI `SecureField`
- UIApplicationDelegate `application(_:shouldAllowExtensionPointIdentifier:)`
- App Extension Programming Guide: Custom Keyboard
- TN3179: Understanding local network privacy
- WWDC23: Keep up with the keyboard
- DevForums FAQ-15: Unexpected Local Network alert
