# Liquid Glass Adoption Guide

> Purpose: iOS 26 Liquid Glass design language reference and CypherAir-specific cross-platform guidance.
> Audience: Human developers and AI coding tools.

## 1. Overview

Liquid Glass is Apple's iOS 26 design language. It is a translucent, refracting material that replaces the blur-based materials used since iOS 7. Glass belongs exclusively on the **navigation and controls layer** — floating above content, never applied to content itself.

**CypherAir targets iOS 26.4+ / iPadOS 26.4+ / macOS 26.4+ / visionOS 26.4+.** There is no need for backward compatibility with older design languages. Do not use `UIDesignRequiresCompatibility`.

This guide is still primarily about the iOS and iPadOS Liquid Glass material model. On macOS and visionOS, prefer the platform's native SwiftUI chrome and use explicit glass APIs only when the API is available and the result matches platform conventions.

## 2. Automatic Adoption

On iOS and iPadOS, standard SwiftUI components receive Liquid Glass automatically when compiled with Xcode 26. On macOS and visionOS, prefer the platform's native SwiftUI chrome instead of forcing iOS-styled glass. No code changes are required for the following iOS/iPadOS examples:

- **TabView:** Becomes a floating glass capsule. Content scrolls behind it.
- **NavigationStack:** Navigation bar becomes transparent. Toolbar items appear as individual glass buttons.
- **Sheets and popovers:** Integrate with glass automatically.
- **System controls:** Buttons, toggles, pickers adopt glass styling.

**Critical:** Remove any custom `.background()` modifiers on these components. Custom backgrounds mask the glass effect. If a NavigationStack or sheet has a `.background(Color.white)` or `.background(.ultraThinMaterial)`, remove it.

## 3. The `.glassEffect()` API

For custom views that should appear as glass controls (floating action buttons, status indicators, custom toolbars):

```swift
// Basic usage
Text("Encrypt")
    .padding()
    .glassEffect()

// With explicit shape
Image(systemName: "lock.fill")
    .frame(width: 56, height: 56)
    .glassEffect(.regular, in: .circle)

// Conditional glass
.glassEffect(showGlass ? .regular : .identity)
```

### Glass Variants

| Variant | Usage |
|---------|-------|
| `.regular` | Default. Medium transparency. Works on any background. Use for most controls. |
| `.clear` | High transparency. For media-rich backgrounds. Use with a dimming layer beneath. |
| `.identity` | No effect. For conditional toggling (e.g., animation states). |

### Modifiers on Glass

```swift
// Semantic tint — ONLY for meaning, never decoration
.glassEffect()
    .tint(.blue)   // Primary action
    .tint(.red)    // Destructive action
    .tint(.green)  // Success / verified

// Interactive feedback (touch scaling, bounce, shimmer)
.glassEffect()
    .interactive()
```

### Applying `.glassEffect()` — Order Matters

Apply `.glassEffect()` as the **last visual modifier**. It must be after padding, frame, and clip shape, but can be before position/offset modifiers.

```swift
// Correct order
Text("Sign")
    .font(.headline)
    .padding(.horizontal, 16)
    .padding(.vertical, 10)
    .glassEffect(.regular, in: .capsule)

// Wrong — background masks glass
Text("Sign")
    .padding()
    .background(Color.blue)  // ← Remove this
    .glassEffect()
```

## 4. Grouping and Morphing

### GlassEffectContainer

Groups multiple glass elements so they share a sampling region and can merge or morph.

```swift
GlassEffectContainer(spacing: 8) {
    Button("Copy") { copyAction() }
        .glassEffect()
    Button("Share") { shareAction() }
        .glassEffect()
    // When elements are closer than `spacing`, they merge into one glass shape
}
```

**Glass cannot sample other glass.** Always use `GlassEffectContainer` when placing multiple glass elements near each other.

### Morphing Between States

Use `.glassEffectID(_:in:)` to animate glass transitions:

```swift
@Namespace private var glassNamespace
@State private var isExpanded = false

GlassEffectContainer {
    if isExpanded {
        ExpandedToolbar()
            .glassEffectID("toolbar", in: glassNamespace)
    } else {
        CompactToolbar()
            .glassEffectID("toolbar", in: glassNamespace)
    }
}
// Wrap state change in withAnimation(.bouncy) for fluid morphing
```

## 5. Component-Specific Changes

### TabView

CypherAir uses four primary tabs. No search tab at root level — search is an in-page feature within Contacts.

```swift
TabView {
    Tab("Home", systemImage: "house") { HomeView() }
    Tab("Keys", systemImage: "key") { MyKeysView() }
    Tab("Contacts", systemImage: "person.2") { ContactsView() }
    Tab("Settings", systemImage: "gear") { SettingsView() }
}
.tabBarMinimizeBehavior(.onScrollDown)  // Collapse on scroll
```

### NavigationStack Toolbars

```swift
.toolbar {
    // Individual glass buttons
    ToolbarItem(placement: .primaryAction) {
        Button("Encrypt", systemImage: "lock.fill") { ... }
    }
    
    // Grouped under shared glass background
    ToolbarItemGroup(placement: .secondaryAction) {
        Button("Copy") { ... }
        Button("Share") { ... }
    }
    
    // Split into separate glass groups
    ToolbarItem(placement: .primaryAction) {
        Button("Action A") { ... }
    }
    ToolbarSpacer(.fixed)  // Creates visual separation
    ToolbarItem(placement: .primaryAction) {
        Button("Action B") { ... }
    }
}
```

### Button Styles

These button-style examples are iOS/iPadOS-first. On visionOS and macOS, use the shared APIs only when they are actually available and visually match platform conventions.

```swift
// Translucent glass button (secondary actions)
Button("Cancel") { ... }
    .buttonStyle(.glass)

// Opaque glass button (primary actions)
Button("Encrypt") { ... }
    .buttonStyle(.glassProminent)
```

## 6. CypherAir-Specific Guidance

### Where to Apply Glass

| UI Element | Glass Treatment |
|-----------|----------------|
| Tab bar | Automatic (standard TabView) |
| Navigation bars + toolbars | Automatic (standard NavigationStack) |
| Encrypt/Decrypt action buttons | `.buttonStyle(.glassProminent)` for primary, `.glass` for secondary |
| Floating QR code display overlay | `.glassEffect(.regular, in: .rect(cornerRadius: 20))` |
| Copy/Share action bar | `GlassEffectContainer` with grouped buttons |
| Self-test result banner | `.glassEffect()` with `.tint(.green)` for pass, `.tint(.red)` for fail |
| Settings toggles (auth mode) | Standard controls — automatic glass |
| Onboarding pages | Standard sheets — automatic glass |

### Where NOT to Apply Glass

| UI Element | Reason |
|-----------|--------|
| Key detail page content | Content, not controls. Use standard list/form styles. |
| Encrypted message text display | Reading area. Glass would impair readability. |
| File preview area | Content. No glass overlay. |
| Contact list rows | Content. Standard list row styling. |
| Fingerprint display | Must be readable for verification. No glass. |
| Error message banners | Use semantic colors on solid background for maximum readability. |
| Passphrase input fields | TextField — standard control, automatic styling. No extra glass. |

### Privacy Screen Overlay

The blur overlay shown when the app enters the background should NOT use Liquid Glass. Use `.ultraThinMaterial` or `UIVisualEffectView` for the privacy screen. The purpose is to obscure content, not to be a beautiful control.

```swift
// Privacy screen — NOT glass
if showPrivacyScreen {
    Rectangle()
        .fill(.ultraThinMaterial)
        .ignoresSafeArea()
}
```

**Note:** Verify the visual appearance of `.ultraThinMaterial` on iOS 26. Material rendering may differ from iOS 18 due to Liquid Glass engine changes. If the privacy screen does not adequately obscure content, consider using a fully opaque overlay with the app logo instead.

## 7. Known Bugs and Workarounds (as of iOS 26.4)

| Bug | Workaround |
|-----|-----------|
| `.rotationEffect()` + `.glassEffect()` produces distorted shapes | Use UIKit's `UIGlassEffect` via `UIViewRepresentable` for rotated elements |
| `Menu` label with `.glassEffect()` breaks morphing animation | Apply `.glassEffect()` to the outer `Menu` container, not the label |
| `Menu` inside `GlassEffectContainer` breaks morphing | Move the `Menu` outside the container or use a custom popover instead |
| Glass on very small views (< 20pt) can look muddy | Ensure minimum 24pt dimension for glass elements |

## 8. Color and Theming Under Glass

Liquid Glass adapts to the content beneath it. Avoid hardcoded colors that fight the glass:

- Use **semantic colors** from the asset catalog: `.primary`, `.secondary`, `.accent`.
- For text on glass, use `.primary` (auto-adapts to dark/light and glass tinting).
- For icons, use SF Symbols with `.renderingMode(.hierarchical)` for best integration.
- Do not use opaque background colors behind glass elements — they defeat the purpose.

Dark Mode works automatically. Glass adapts its opacity and refraction to the current color scheme.
