# 修复计划：UI/UX 与合规审查发现

## 修复 1: [ARCH-1] CypherAirApp 直接调用 engine — 改为通过 QRService

**文件:** `Sources/App/CypherAirApp.swift` (第 241-242 行)

**现状:**
```swift
let keyInfo = try engine.parseKeyInfo(keyData: publicKeyData)
let profile = try engine.detectProfile(certData: publicKeyData)
```

**改为:**
```swift
let keyInfo = try qrService.inspectKeyInfo(keyData: publicKeyData)
let profile = try qrService.detectKeyProfile(keyData: publicKeyData)
```

**理由:** `QRService` 的 `inspectKeyInfo()` 和 `detectKeyProfile()` 是对 `engine` 方法的包装，但额外提供了统一的错误映射（将引擎错误转换为 `CypherAirError.invalidKeyData`）。`QRPhotoImportView` 已正确使用此模式。当前 `CypherAirApp` 中的直接调用虽然功能正确，但绕过了 QRService 的错误映射，且与项目的服务层架构不一致。

**影响范围:** 仅 `CypherAirApp.swift` 第 241-242 行，2 行变更。

---

## 修复 2: [A11Y-1] HomeView 指纹缺少分段朗读

**文件:** `Sources/App/HomeView.swift` (第 111-113 行)

**现状:**
```swift
Text(defaultKey.formattedFingerprint)
    .font(.caption.monospaced())
    .foregroundStyle(.secondary)
```

**改为:**
```swift
Text(defaultKey.formattedFingerprint)
    .font(.caption.monospaced())
    .foregroundStyle(.secondary)
    .accessibilityLabel(
        defaultKey.formattedFingerprint
            .split(separator: " ")
            .map { $0.map(String.init).joined(separator: " ") }
            .joined(separator: ", ")
    )
```

**理由:** 复用 `KeyDetailView.swift:104-109` 和 `ContactDetailView.swift:46-51` 已有的分段朗读模式。`formattedFingerprint` 以空格分隔 4 字符一组（如 "A1B2 C3D4 E5F6..."），此模式将每组字符拆为单字符（"A 1 B 2"）、组间用逗号（","）分隔，使 VoiceOver 能逐段清晰朗读。符合 CONVENTIONS.md Section 6 和 PRD Section 1.7 的 "segment-by-segment readout" 要求。

**影响范围:** 仅 `HomeView.swift`，添加约 5 行。

---

## 修复 3: [A11Y-2] DecryptView 指纹缺少分段朗读

**文件:** `Sources/App/Decrypt/DecryptView.swift` (第 91-93 行)

**现状:**
```swift
Text(matchedKey.formattedFingerprint)
    .font(.system(.caption, design: .monospaced))
    .foregroundStyle(.secondary)
```

**改为:**
```swift
Text(matchedKey.formattedFingerprint)
    .font(.system(.caption, design: .monospaced))
    .foregroundStyle(.secondary)
    .accessibilityLabel(
        matchedKey.formattedFingerprint
            .split(separator: " ")
            .map { $0.map(String.init).joined(separator: " ") }
            .joined(separator: ", ")
    )
```

**理由:** 同修复 2，复用已有的分段朗读模式。

**影响范围:** 仅 `DecryptView.swift`，添加约 5 行。

---

## 修复 4: [A11Y-5] 3 处装饰图标缺少 accessibilityHidden

报告中 13 处固定字号装饰图标中有 3 处缺少 `.accessibilityHidden(true)`，需要补齐。

### 4a: PostGenerationPromptView.swift (第 15-17 行)

**现状:**
```swift
Image(systemName: "checkmark.circle.fill")
    .font(.system(size: 48))
    .foregroundStyle(.green)
```

**改为:**
```swift
Image(systemName: "checkmark.circle.fill")
    .font(.system(size: 48))
    .foregroundStyle(.green)
    .accessibilityHidden(true)
```

### 4b: QRPhotoImportView.swift (第 26-28 行)

**现状:**
```swift
Image(systemName: "qrcode.viewfinder")
    .font(.system(size: 64))
    .foregroundStyle(.secondary)
```

**改为:**
```swift
Image(systemName: "qrcode.viewfinder")
    .font(.system(size: 64))
    .foregroundStyle(.secondary)
    .accessibilityHidden(true)
```

### 4c: AppIconPickerView.swift (第 115-117 行)

**现状:**
```swift
Image(systemName: "checkmark.circle.fill")
    .font(.system(size: 20))
    .foregroundStyle(.white, .blue)
```

**改为:**
```swift
Image(systemName: "checkmark.circle.fill")
    .font(.system(size: 20))
    .foregroundStyle(.white, .blue)
    .accessibilityHidden(true)
```

**理由:** 这些图标均为纯装饰性质（成功对勾、QR 视觉提示、选中指示器），不携带 VoiceOver 用户需要的独立语义信息。旁边的文本已提供等效信息。Apple 的 SwiftUI Accessibility Fundamentals 文档建议对装饰性图像使用 `accessibilityHidden(true)` 隐藏，避免 VoiceOver 朗读无意义的默认 label（如 "checkmark.circle.fill"）。其他 10 处同类图标已正确标记。

**关于固定字号：** 13 处使用 `.font(.system(size: N))` 的装饰图标不做字号修改。原因：
1. 这些都是 `Image(systemName:)` 图标而非文本内容，Apple HIG 的 Dynamic Type 要求主要针对文本。
2. 装饰性图标的尺寸通常需要与布局固定匹配（如 onboarding 页面的 72pt 图标需要保持视觉比例）。
3. 所有 13 处均已标记（或即将标记）`accessibilityHidden(true)`，不影响 VoiceOver 用户体验。

**影响范围:** 3 个文件各添加 1 行。

---

## 修复 5: [A11Y-6] 清除文件按钮触摸区域不足 44pt

**文件:** `Sources/App/Keys/ImportKeyView.swift` (第 29-37 行) 和 `Sources/App/Contacts/AddContactView.swift` (第 192-200 行)

**现状（两处相同模式）:**
```swift
Button {
    importedKeyData = nil
    importedFileName = nil
} label: {
    Image(systemName: "xmark.circle.fill")
        .foregroundStyle(.secondary)
}
.buttonStyle(.plain)
.accessibilityLabel(...)
```

**改为:**
```swift
Button {
    importedKeyData = nil
    importedFileName = nil
} label: {
    Image(systemName: "xmark.circle.fill")
        .foregroundStyle(.secondary)
        .frame(minWidth: 44, minHeight: 44)
        .contentShape(Rectangle())
}
.buttonStyle(.plain)
.accessibilityLabel(...)
```

**理由:** `.buttonStyle(.plain)` 移除了系统默认的按钮 padding，导致触摸区域仅为 SF Symbol 自身大小（约 24pt）。Apple HIG 要求所有可交互元素的最小触摸目标为 44×44pt，CONVENTIONS.md Section 6 明确要求 "Minimum 44×44pt for all interactive elements"。

添加 `.frame(minWidth: 44, minHeight: 44)` 扩展命中区域，`.contentShape(Rectangle())` 确保整个 frame 区域（包括透明区域）都响应点击。`.frame()` 加在 Image 上而非 Button 上，是因为 `.buttonStyle(.plain)` 下 SwiftUI 基于 label 内容计算命中区域。

**影响范围:** 2 个文件各添加 2 行。

---

## 修复 6: [DOC-1] ARCHITECTURE.md UserDefaults 键文档补全

**文件:** `docs/ARCHITECTURE.md` Section 5 (第 282-287 行附近)

**现状（仅 5 个键）:**
```
├── Library/Preferences/
│   └── (UserDefaults)
│       ├── com.cypherair.preference.authMode           → "standard" | "highSecurity"
│       ├── com.cypherair.preference.gracePeriod         → Int (seconds): 0 / 60 / 180 / 300
│       ├── com.cypherair.preference.encryptToSelf       → Bool (default true)
│       ├── com.cypherair.preference.clipboardNotice     → Bool (default true)
│       └── com.cypherair.internal.rewrapInProgress      → Bool (crash recovery flag)
```

**改为（10 个键）:**
```
├── Library/Preferences/
│   └── (UserDefaults)
│       ├── com.cypherair.preference.authMode              → "standard" | "highSecurity"
│       ├── com.cypherair.preference.gracePeriod            → Int (seconds): 0 / 60 / 180 / 300
│       ├── com.cypherair.preference.encryptToSelf          → Bool (default true)
│       ├── com.cypherair.preference.clipboardNotice        → Bool (default true)
│       ├── com.cypherair.preference.requireAuthOnLaunch    → Bool (default true)
│       ├── com.cypherair.preference.onboardingComplete     → Bool (default false)
│       ├── com.cypherair.internal.rewrapInProgress         → Bool (crash recovery flag)
│       ├── com.cypherair.internal.rewrapTargetMode         → String (target auth mode during re-wrap)
│       ├── com.cypherair.internal.modifyExpiryInProgress   → Bool (crash recovery flag)
│       └── com.cypherair.internal.modifyExpiryFingerprint  → String (key fingerprint during expiry modification)
```

**理由:** 5 个键在代码中使用但未文档化。`requireAuthOnLaunch` 和 `onboardingComplete` 定义在 `AppConfiguration.swift:66-69`；`rewrapTargetMode`、`modifyExpiryInProgress`、`modifyExpiryFingerprint` 定义在 `AuthenticationEvaluable.swift:96-105`。文档 Section 5 注释中声称 "UserDefaults" 列出了完整的存储布局，但实际缺少 50% 的键。

**影响范围:** 仅文档变更，`docs/ARCHITECTURE.md` 一处。

---

## 变更汇总

| 修复 | 文件 | 类型 | 变更量 |
|------|------|------|--------|
| 1 (ARCH-1) | `CypherAirApp.swift` | 代码 | 2 行替换 |
| 2 (A11Y-1) | `HomeView.swift` | 代码 | 添加 5 行 |
| 3 (A11Y-2) | `DecryptView.swift` | 代码 | 添加 5 行 |
| 4a (A11Y-5) | `PostGenerationPromptView.swift` | 代码 | 添加 1 行 |
| 4b (A11Y-5) | `QRPhotoImportView.swift` | 代码 | 添加 1 行 |
| 4c (A11Y-5) | `AppIconPickerView.swift` | 代码 | 添加 1 行 |
| 5 (A11Y-6) | `ImportKeyView.swift` + `AddContactView.swift` | 代码 | 各添加 2 行 |
| 6 (DOC-1) | `docs/ARCHITECTURE.md` | 文档 | 替换 5 行为 10 行 |

**总计:** 8 个文件，约 25 行变更。无安全边界文件变更。无架构变更。全部为低风险修正。

## 验证计划

1. **构建验证:** `BuildProject` 确认编译通过。
2. **测试验证:** 运行 `CypherAir-UnitTests` 测试计划，确认无回归。修复 1 涉及 QRService 调用路径变更，QRServiceTests 应覆盖。
3. **手动验证（可选）:**
   - VoiceOver 验证修复 2/3：在 HomeView 和 DecryptView 中指纹应分段朗读。
   - VoiceOver 验证修复 4：三个装饰图标不应被朗读。
   - 触摸目标验证修复 5：清除按钮可在图标周围区域点击。
