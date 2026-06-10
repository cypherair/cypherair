# Coding Conventions

> Status: Canonical current-state.
> Purpose: Swift coding standards, SwiftUI patterns, and project-wide conventions for CypherAir.
> Audience: Human developers and AI coding tools.
> Update triggers: Swift style, SwiftUI patterns, concurrency model, file organization, localization, accessibility, or git conventions change.
> Last reviewed: 2026-06-10.

## 0. Engineering Principle

When building a feature or fixing an issue, prefer the solution that is architecturally correct
for long-term software governance over the smallest patch against the current code. If the
existing structure pushes toward awkward or fragile fixes, a larger refactor — or a substantial
rewrite of the affected area — is acceptable and encouraged when it produces a cleaner, more
maintainable design.

This governs the *depth* of a change, not its *scope*. It is not license to expand into unrelated
cleanup: keep the work focused on delivering the requested task (see the scoping rules in
`CLAUDE.md`), and let the intended architecture — not a smaller diff — determine the shape of the
change.

Keep source layout, ownership boundaries, and project wiring aligned with that intended
architecture: do not hide new behavior in unrelated places to make a diff look smaller or to avoid
configuration work. Shared components live in dedicated files in the right feature or shared area,
with Xcode file-system sync, target membership, and test-target exclusions reflecting that
structure.

## 1. Swift Style

### Naming

Follow the [Swift API Design Guidelines](https://www.swift.org/documentation/api-design-guidelines/). Clarity at the point of use is the overriding goal.

- Types and protocols: `UpperCamelCase` — `EncryptionService`, `KeychainManageable`.
- Functions, properties, variables: `lowerCamelCase` — `encryptMessage(for:)`, `publicKeyData`.
- Boolean properties read as assertions: `isEmpty`, `isBackedUp`, `canDecrypt`. Not `backed`, `empty`.
- Verb phrases for mutating methods: `sort()`, `zeroize()`. Past participle or `-ing` for non-mutating: `sorted()`, `removing(_:)`.
- Acronyms follow Apple convention: all-caps when standalone (`QR`, `SE`, `FFI`), all-lowercase when prefix of a longer word (`url`, `pgp`). In camelCase: `qrCodeImage`, `seKeyHandle`, `pgpEncrypt`.

### General Rules

- `guard let` / `guard else` for early exits. Never force-unwrap (`!`) in production code. `fatalError()` only in genuinely impossible paths (e.g., a `switch` default that is logically unreachable).
- `async/await` for all asynchronous work. No Combine in new code. No completion handler callbacks.
- Prefer value types (`struct`, `enum`) over `class` unless identity semantics or reference sharing is needed. Services that hold state use `@Observable class`.
- `let` over `var` wherever possible. Mutable state requires explicit justification.
- Access control: mark everything as restrictive as possible. `private` by default, `internal` if needed within the module, `public` only for the module's external API.
- No `// MARK: -` comments for sections shorter than 50 lines. Use them for clear logical sections in larger files.

### Error Handling

- Use typed errors that conform to `Error`. The primary app-level error type is `CypherAirError`, an app-owned vocabulary for security-layer, OpenPGP, and app-layer errors. Generated `PgpError` values are normalized at the FFI adapter / mapper boundary before reaching Models, ScreenModels, or Views.
- Each `CypherAirError` case has an associated user-facing message defined in the String Catalog, per PRD Section 4.7.
- Never `try!` in production. Never `catch` an error and silently ignore it. Always propagate or handle meaningfully.
- Use `do { } catch { }` at the call site that can present the error to the user. Services throw; views catch and display.

### Imports

- Group imports: Foundation/Swift standard library first, then Apple frameworks (CryptoKit, Security, Vision, CoreImage), then project modules, then third-party. Alphabetical within each group.
- Import only what is needed. Prefer `import CryptoKit` over `@_exported import CryptoKit`.

## 2. SwiftUI Patterns

### State Management

Use the Xcode 26.5 / Apple Swift 6.3.2 state management model:

| Old Pattern | New Pattern | Usage |
|------------|------------|-------|
| `ObservableObject` + `@Published` | `@Observable class` | All view models and services |
| `@StateObject` | `@State` | Owning reference to an `@Observable` in a view |
| `@ObservedObject` | Direct property (no wrapper) | Non-owning reference to an `@Observable` |
| `@EnvironmentObject` | `@Environment` | Injecting shared dependencies |
| `@Binding` | `@Bindable` | Creating bindings to `@Observable` properties |

### Navigation

Use `NavigationStack` with a typed path. Never use the deprecated `NavigationView`.

```swift
enum AppRoute: Hashable {
    case keyDetail(fingerprint: String)
    case encrypt
    case decrypt
    case contacts
    case settings
    // ...
}

struct ContentView: View {
    @State private var path = NavigationPath()

    var body: some View {
        NavigationStack(path: $path) {
            HomeView()
                .navigationDestination(for: AppRoute.self) { route in
                    switch route {
                    case .keyDetail(let fp): KeyDetailView(fingerprint: fp)
                    case .encrypt: EncryptView()
                    // ...
                    }
                }
        }
    }
}
```

### View Structure

- Views are thin. No business logic in `body`. No network calls, no Keychain access, no crypto operations in views.
- Views observe `@Observable` services injected via `@Environment` or `@State`.
- Workflow-heavy screens may use an owning `@Observable` screen model. The route view reads `@Environment`, passes explicit dependencies into a private owning host view, and that host owns the model via `@State`. The model should not read `@Environment` directly. `SignView` + `SignScreenModel` is the first in-repo baseline for this pattern.
- When a screen model is used, move async orchestration, importer/exporter state, invalidation, cleanup, and transient confirmation/error state into the model. The view keeps layout, bindings, and lifecycle wiring only. Prefer explicit lifecycle methods such as `prepareIfNeeded()`, `handleDisappear()`, and `invalidateFor...(...)` rather than keeping workflow logic inline in SwiftUI modifiers.
- Extract complex subviews into separate files when `body` exceeds ~50 lines.
- Use `ViewModifier` for reusable styling (e.g., the privacy screen blur overlay).

### Liquid Glass

CypherAir targets iOS 26.5+, iPadOS 26.5+, macOS 26.5+, and visionOS 26.5+. Fully embrace modern SwiftUI chrome across those platforms. General Liquid Glass implementation guidance lives in agent/tooling guidance; the archived background guide is in `docs/archive/LIQUID_GLASS.md`. Current project rules:

- On iOS and iPadOS, standard components (TabView, NavigationStack, toolbars, sheets) get Liquid Glass automatically. Do not override their backgrounds.
- On macOS and visionOS, prefer platform-native SwiftUI chrome instead of forcing iOS-styled glass.
- Custom floating controls: apply `.glassEffect()` as the last modifier only when the API is available and the result matches platform conventions. Remove any `.background()` modifiers first.
- Never apply glass to content views (lists, key details, message display).
- Use `.tint()` on glass only for semantic meaning (blue = primary action, red = destructive). Never decorative tinting.

## 3. Concurrency

The project uses Apple Swift 6.3.2 with `SWIFT_VERSION = 6.0` and `SWIFT_DEFAULT_ACTOR_ISOLATION = nonisolated`. `SWIFT_VERSION` selects the Swift 6 language mode; it is not the compiler release number.

- Do not rely on implicit main-actor isolation for view models, screen models, or services. Annotate UI-bound `@Observable` models with `@MainActor` when their state is read or mutated by SwiftUI.
- Plain SwiftUI `View` types still execute their `body` on the main actor through SwiftUI, but their owned reference state should make actor isolation explicit at the type boundary.
- Use `@concurrent` to opt into the cooperative thread pool for CPU-intensive work (Argon2id key import/export, file encryption progress).
- All types that cross actor boundaries must conform to `Sendable`. Use `nonisolated` only for properties/methods that are safe to access outside the owning actor.
- Use `actor` for shared mutable state that is not UI-bound (e.g., a cache or in-progress operation tracker).
- Perform PGP operations (encrypt, decrypt, sign, verify) on a background actor or `@concurrent` function to avoid blocking the UI. Return results to an explicitly main-actor-isolated model for display.

```swift
@concurrent
func encryptFile(inputURL: URL, outputURL: URL, recipients: [PublicKey]) async throws {
    // Runs off main actor and keeps file payloads on the streaming path.
    try pgpBridge.encryptFile(inputURL: inputURL, outputURL: outputURL, recipients: recipients)
}
```

### UniFFI Generated Code and Swift 6.3.2 Concurrency

UniFFI-generated Swift bindings may not fully conform to Swift 6.3.2's strict concurrency model. If the generated `pgp_mobile.swift` file produces `Sendable` or actor-isolation warnings:

1. Add `@preconcurrency import PgpMobile` at call sites that import the generated module.
2. If warnings persist, set `SWIFT_STRICT_CONCURRENCY = targeted` (not `complete`) for the generated bindings file only via per-file build settings, or wrap the generated types in `@unchecked Sendable` conformances in an extension file (not in the generated file itself — it will be overwritten on regeneration).
3. Do NOT modify the generated `pgp_mobile.swift` directly. It is overwritten by `uniffi-bindgen`.

## 4. File Organization

### One Type Per File

Each Swift file contains exactly one primary type (struct, class, enum, protocol). Small, tightly-related helper types may live in the same file if they are used exclusively by the primary type.

File name matches the type name: `EncryptionService.swift`, `CypherAirError.swift`, `KeyDetailView.swift`.

### Group by Feature, Not by Layer

Top-level structure and grouping rules — illustrative, not exhaustive; the authoritative module breakdown and component ownership live in [ARCHITECTURE.md](ARCHITECTURE.md):

```
Sources/
├── App/              # One subdirectory per feature surface:
│   ├── Common/       #   shared presentation infrastructure (OperationController, FileExportController, …)
│   ├── Onboarding/   #   onboarding + guided tutorial host
│   ├── Encrypt/ … Decrypt/ … Sign/ … Keys/ … Contacts/ … Settings/
│   │                 #   feature areas: route views + their ScreenModels (e.g. SignView + SignScreenModel)
│   └── (top level)   #   app entry, routing, shell composition
├── PgpMobile/        # Generated UniFFI bindings (pgp_mobile.swift — do not edit)
├── Services/         # One service per workflow (EncryptionService, QRService, …) + FFI/ adapter boundary
├── Security/         # SE wrapping, Keychain, auth modes, ProtectedData/; mocks only under Mocks/
├── Models/           # App-owned data types and error vocabulary
├── Extensions/       # Small Foundation/Swift helpers (e.g. Data+Zeroing.swift)
└── Resources/        # Assets.xcassets, Localizable.xcstrings

CypherAir-Info.plist  # Root-level app Info.plist source
```

Placement rules:

- New feature views and their ScreenModels go in the matching `App/<Feature>/` directory; shared presentation infrastructure goes in `App/Common/`.
- Workflow logic belongs in `Services/`; generated-API access stays behind the `Services/FFI/` adapters.
- Security primitives stay under `Security/`; test/tutorial mocks are confined to `Security/Mocks/` with visible `Mock*` names.

When multiple screens share the same lifecycle/platform behavior, prefer extracting common infrastructure (`OperationController`, `SecurityScopedFileAccess`, `FileExportController`) instead of re-implementing per-view task/progress/export state machines.

## 5. Localization

- All user-facing strings go in the String Catalog (`Localizable.xcstrings`). Use `String(localized:)` in code.
- Never hardcode user-visible strings in Swift files.
- If `Localizable.xcstrings` marks a key with `extractionState: stale`, verify whether the key is still referenced by Swift source: remove the entry if it is unused, or fix the extraction path if it is still used. Never make tests pass by merely deleting the `stale` marker.
- Supported languages: English (`en`) and Simplified Chinese (`zh-Hans`).
- Error messages per PRD Section 4.7 are defined as localized strings mapped from `CypherAirError` cases.
- VoiceOver labels: always localized. Fingerprints use segment-by-segment readout (4-character groups).

```swift
// Correct
Text(String(localized: "encrypt.button.title"))

// Wrong
Text("Encrypt")
```

## 6. Accessibility

All interactive elements must meet these requirements:

- **VoiceOver:** Every button, toggle, and interactive element has a meaningful `.accessibilityLabel`. Status indicators have text equivalents (not color/icon only).
- **Dynamic Type:** All text respects the user's preferred text size. Use system text styles (`.body`, `.headline`, `.caption`) rather than fixed font sizes.
- **Touch targets:** Minimum 44×44pt for all interactive elements.
- **Fingerprint display:** Support segment-by-segment VoiceOver readout. Group fingerprint characters into 4-character segments, each with its own accessibility element.

```swift
// Fingerprint accessibility example
ForEach(fingerprintSegments, id: \.self) { segment in
    Text(segment)
        .accessibilityLabel(segment.map { String($0) }.joined(separator: " "))
}
```

## 7. Git Conventions

- **Branch names:** `feature/<description>`, `fix/<description>`, `refactor/<description>`. Automated-contributor branches may instead use an authoring prefix (`claude-<topic>` / `codex-<topic>`) or the staged `<topic>-pr<NN>-<description>` series shape used by long-running integration work; the prefix should reflect the actual author rather than being copied from a prior series.
- **Commit messages:** Conventional format — `feat: add encrypt-to-self toggle`, `fix: AEAD hard-fail not triggered on empty ciphertext`, `test: add tamper detection round-trip`, `docs: update SE wrapping diagram`.
- **PR scope:** One logical change per PR. Do not bundle unrelated changes.
- **Do not commit directly to `main` unless the user explicitly asks for it.** Default to topic branches and PRs. Merge PRs with a regular merge commit; do not squash-merge or rebase-merge unless explicitly requested.
