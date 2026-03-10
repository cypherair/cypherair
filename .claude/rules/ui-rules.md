---
paths:
  - "Sources/App/**"
---

# UI Rules

Views in Sources/App/ are presentation-only. They must not contain business logic,
cryptographic operations, Keychain access, or direct Sequoia calls.

## Liquid Glass

- Standard components (TabView, NavigationStack, toolbars, sheets) receive Liquid Glass
  automatically. Do NOT add `.background()` modifiers to these — it masks the glass effect.
- Apply `.glassEffect()` only to floating controls (action buttons, status banners, custom
  toolbars). Never apply glass to content views (lists, key details, message display,
  fingerprint display, error banners).
- Use `.tint()` on glass elements only for semantic meaning (blue = primary, red = destructive,
  green = success). Never for decoration.
- See docs/LIQUID_GLASS.md for the full guide, including known bugs and workarounds.

## Localization

- All user-visible strings must be in the String Catalog (Localizable.xcstrings).
- Use `String(localized:)` or `Text("key", tableName:)`. Never hardcode strings in Swift files.

## Accessibility

- Every button, toggle, and interactive element must have a meaningful `.accessibilityLabel`.
- Status indicators (valid/invalid/expired) must have text equivalents, not rely on color or icon alone.
- Minimum 44×44pt touch targets for all interactive elements.
- Support Dynamic Type — use system text styles, not fixed font sizes.

## View Architecture

- Views observe `@Observable` services via `@Environment` or `@State`. No direct instantiation
  of services in views.
- No `async` work in `body`. Trigger async operations via button actions or `.task {}`.
- Extract subviews into separate files when `body` exceeds ~50 lines.
