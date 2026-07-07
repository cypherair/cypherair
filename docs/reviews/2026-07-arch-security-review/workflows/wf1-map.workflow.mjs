export const meta = {
  name: 'cypherair-review-map',
  description: 'Workflow 1 of 2: map & triage the CypherAir codebase. Recall-oriented dead-code discovery (mechanical enumeration + optional periphery baseline, symmetric evidence, surface-do-not-drop) plus test/legacy/docs/FFI census. Opus verifies claims; a completeness critic guards against silent misses.',
  phases: [
    { title: 'Map', detail: 'subsystem inventory + MANDATORY zero-reference enumeration (non-omission)', model: 'sonnet' },
    { title: 'FFI boundary', detail: 'generated-type shapes leaking past Services/FFI into App/Models', model: 'sonnet' },
    { title: 'Test census', detail: 'classify every test file: real-guard vs vacuous vs brittle-negative', model: 'sonnet' },
    { title: 'Vestigial analysis', detail: 'reachable-but-obsolete migration/version/capability code via producer-consumer precondition analysis', model: 'sonnet' },
    { title: 'Docs census', detail: 'stale facts, dead-code refs, bloat, outdated requirements', model: 'sonnet' },
    { title: 'Reconcile periphery', detail: 'verify each tool-reported unused declaration (only if a periphery baseline was supplied)', model: 'opus' },
    { title: 'Verify (Opus)', detail: 'evidence-backed verdicts: dead-code, docs, and vestigial migration/capability (FFI deferred to WF2)', model: 'opus' },
    { title: 'Crypto touchpoints', detail: 'build the security-track work-list for Workflow 2', model: 'sonnet' },
  ],
}

// ===== shared schema fragments ===============================================
const FILE_ENTRY = {
  type: 'object',
  required: ['path', 'loc', 'role', 'sizeConcern', 'declStats'],
  properties: {
    path: { type: 'string' },
    loc: { type: 'integer' },
    role: { type: 'string', description: 'one line: what this file is responsible for' },
    sizeConcern: { type: 'string', enum: ['none', 'watch', 'oversized'] },
    cohesion: { type: 'string', description: 'if oversized/watch: one cohesive job or several? decomposition hint' },
    declStats: {
      type: 'object', required: ['scanned', 'zeroRef'],
      properties: {
        scanned: { type: 'integer', description: 'how many top-level declarations you enumerated in this file' },
        zeroRef: { type: 'integer', description: 'how many had zero production references' },
      },
      description: 'anti-silence: proves you enumerated rather than eyeballed',
    },
    zeroRefDeclarations: {
      type: 'array',
      description: 'EVERY declaration with zero production references. Omitting one is a failure. Include even suspected-dynamic ones (note the caveat).',
      items: {
        type: 'object', required: ['symbol', 'kind'],
        properties: {
          symbol: { type: 'string' },
          kind: { type: 'string', description: 'type / func / property / case / extension / protocol' },
          dynamicUsageCaveat: { type: 'string', description: 'if it could be reached dynamically (#selector, KVC, SwiftUI reflection, Codable, target-membership, string lookup), say how; else empty' },
        },
      },
    },
    smells: {
      type: 'array',
      items: {
        type: 'object', required: ['kind', 'detail'],
        properties: { kind: { type: 'string', description: 'layering-violation, duplication, god-object, boundary-leak, ...' }, detail: { type: 'string' } },
      },
    },
  },
}
const SUBSYSTEM_SCHEMA = {
  type: 'object', required: ['module', 'files'],
  properties: {
    module: { type: 'string' },
    files: { type: 'array', items: FILE_ENTRY },
    crossCutting: { type: 'array', items: { type: 'string' }, description: 'nine-key-family duplication, repeated patterns worth unifying' },
    exportedFfiUnused: { type: 'array', items: { type: 'string' }, description: 'Rust chunks only: #[uniffi::export] fns with no Swift call site' },
    notes: { type: 'string' },
  },
}
const DEADCODE_VERDICT_SCHEMA = {
  type: 'object', required: ['verdicts'],
  properties: {
    verdicts: {
      type: 'array',
      items: {
        type: 'object', required: ['symbol', 'path', 'verdict', 'searchesRun'],
        properties: {
          symbol: { type: 'string' }, path: { type: 'string' },
          // NOTE: no "inconclusive" escape hatch. Uncertain => removal-candidate (surfaced), not silence.
          verdict: { type: 'string', enum: ['dead-confirmed', 'live-confirmed', 'removal-candidate'] },
          searchesRun: { type: 'string', description: 'the exact searches you ran (repo-wide, incl. tests + build config + dynamic vectors)' },
          referencesFound: { type: 'string', description: 'REQUIRED for live-confirmed: the concrete reference/entry point. Empty is not allowed for live-confirmed.' },
          removalNote: { type: 'string', description: 'for removal-candidate: the dynamic caveat to settle by deleting + building' },
        },
      },
    },
  },
}
const TEST_CENSUS_SCHEMA = {
  type: 'object', required: ['files'],
  properties: {
    files: {
      type: 'array',
      items: {
        type: 'object', required: ['path', 'verdict'],
        properties: {
          path: { type: 'string' },
          approxTests: { type: 'integer' },
          verdict: { type: 'string', enum: ['real-guard', 'mixed', 'vacuous', 'brittle-negative', 'source-audit'] },
          reason: { type: 'string', description: 'concrete: what regression it would (or would not) catch' },
          pruneSuspects: { type: 'array', items: { type: 'string' }, description: 'specific test names worth deleting' },
        },
      },
    },
  },
}
const VESTIGIAL_SCHEMA = {
  type: 'object', required: ['sites'],
  properties: {
    sites: {
      type: 'array',
      items: {
        type: 'object', required: ['path', 'symbol', 'kind', 'precondition', 'producerClass', 'hypothesis'],
        properties: {
          path: { type: 'string' }, symbol: { type: 'string' },
          kind: { type: 'string', enum: ['version-guard', 'format-fallback', 'migration-fn', 'legacy-artifact-check', 'capability-branch', 'other'] },
          precondition: { type: 'string', description: 'the guard that gates this code (e.g. schemaVersion != current, legacy file exists, switch on a version enum)' },
          readsState: { type: 'string', description: 'the persisted/external state this branch consumes' },
          producer: { type: 'string', description: 'the code path that WRITES that state, if you found it' },
          producerClass: { type: 'string', enum: ['current-code', 'prior-version-only', 'migration-only', 'external', 'none-found', 'unknown'] },
          hypothesis: { type: 'string', enum: ['vestigial-remove', 'live', 'unknown'] },
          coRemoveTests: { type: 'array', items: { type: 'string' }, description: 'existing tests that exercise this branch — co-removed with it' },
          evidence: { type: 'string' },
        },
      },
    },
  },
}
const VESTIGIAL_VERDICT_SCHEMA = {
  type: 'object', required: ['verdicts'],
  properties: {
    verdicts: {
      type: 'array',
      items: {
        type: 'object', required: ['path', 'symbol', 'confirmed', 'behavioralProof'],
        properties: {
          path: { type: 'string' }, symbol: { type: 'string' },
          // "live" = a CURRENT code path produces the guarded state (behavioral fact, not a reference count).
          // Unpublished app: forward-compat / version scaffolding with NO current producer is REMOVE, not keep.
          confirmed: { type: 'string', enum: ['remove', 'live', 'needs-runtime-check'] },
          removeRationale: { type: 'string', enum: ['obsolete-handles-past-data', 'speculative-forward-compat-scaffold', 'self-referential-migration-only', 'n/a'] },
          behavioralProof: { type: 'string', description: 'WHY the precondition can or cannot occur in a fresh CypherAir X install that never ran a prior shipped version' },
          producerFound: { type: 'string', description: 'the concrete writer of the consumed state, or "none in current code"' },
          cascade: { type: 'string', description: 'types/fields/cases orphaned (and then dead-code-detectable) once this trunk is removed' },
          coRemoveTests: { type: 'array', items: { type: 'string' }, description: 'existing tests that exercise THIS code and are deleted WITH it. Do NOT propose any NEW test asserting the removal or characterizing the old behavior — that just re-encodes the dead concept.' },
          removalRisk: { type: 'string' },
        },
      },
    },
  },
}
const DOCS_SCHEMA = {
  type: 'object', required: ['docs'],
  properties: {
    docs: {
      type: 'array',
      items: {
        type: 'object', required: ['path'],
        properties: {
          path: { type: 'string' },
          staleFacts: { type: 'array', items: { type: 'string' } },
          deadCodeRefs: { type: 'array', items: { type: 'string' } },
          bloat: { type: 'array', items: { type: 'string' } },
          staleRequirements: { type: 'array', items: { type: 'string' } },
        },
      },
    },
  },
}
const DOCS_VERDICT_SCHEMA = {
  type: 'object', required: ['verdicts'],
  properties: {
    verdicts: {
      type: 'array',
      items: {
        type: 'object', required: ['doc', 'claim', 'confirmed'],
        properties: {
          doc: { type: 'string' }, claim: { type: 'string' },
          type: { type: 'string', enum: ['stale-fact', 'dead-code-ref'] },
          confirmed: { type: 'string', enum: ['confirmed-stale', 'actually-current', 'inconclusive'] },
          correctValue: { type: 'string' }, evidence: { type: 'string' },
        },
      },
    },
  },
}
const FFI_LEAK_SCHEMA = {
  type: 'object', required: ['leaks'],
  properties: {
    leaks: {
      type: 'array',
      items: {
        type: 'object', required: ['generatedType', 'usedIn', 'layer'],
        properties: {
          generatedType: { type: 'string' },
          usedIn: { type: 'string', description: 'file:line' },
          layer: { type: 'string', enum: ['View', 'ScreenModel', 'Model', 'Extension', 'other'] },
          sanctionedGuess: { type: 'boolean' },
          note: { type: 'string' },
        },
      },
    },
  },
}
// FFI-leak and vestigial VERDICT schemas live in WF2 (the verify workflow) — WF1 only collects them (Sonnet).
const PERIPHERY_VERDICT_SCHEMA = {
  type: 'object', required: ['verdicts'],
  properties: {
    verdicts: {
      type: 'array',
      items: {
        type: 'object', required: ['symbol', 'verdict', 'evidence'],
        properties: {
          symbol: { type: 'string' }, location: { type: 'string' },
          verdict: { type: 'string', enum: ['dead-confirmed', 'live-confirmed', 'removal-candidate'] },
          evidence: { type: 'string', description: 'live-confirmed must cite the reference periphery missed (e.g. dynamic dispatch)' },
        },
      },
    },
  },
}
const CRYPTO_SCHEMA = {
  type: 'object', required: ['touchpoints'],
  properties: {
    touchpoints: {
      type: 'array',
      items: {
        type: 'object', required: ['path', 'concern'],
        properties: {
          path: { type: 'string' },
          concern: { type: 'string', description: 'format-selection, AEAD-hardfail, sig-verify, custody, memory-zeroize, randomness, ffi-seam, kdf' },
          why: { type: 'string' },
        },
      },
    },
  },
}

function zeroRefsOf(map) {
  return (map?.files || []).flatMap(f => (f.zeroRefDeclarations || []).map(d => ({ path: f.path, symbol: d.symbol, kind: d.kind, caveat: d.dynamicUsageCaveat || '' })))
}

// ===== phase 1: subsystem map (mandatory enumeration)  ->  Opus classify =====
phase('Map')
const SUBSYSTEMS = [
  { label: 'app-crypto-flows', scope: 'Sources/App/Encrypt/**, Sources/App/Decrypt/**, Sources/App/Sign/** (views + screen models)' },
  { label: 'app-contacts', scope: 'Sources/App/Contacts/** INCLUDING Contacts/Import/ (AppSceneIncomingURLRouter, IncomingURLImportCoordinator, PublicKeyImportLoader, ContactImportWorkflow) — the URL-scheme input path' },
  { label: 'app-keys', scope: 'Sources/App/Keys/** (key generation, backup, import, revocation, modify-expiry, device-bound sheets; watch for nine-key-family copy-paste)' },
  { label: 'app-onboarding', scope: 'Sources/App/Onboarding/** (tutorial + onboarding stores/views)' },
  { label: 'app-settings', scope: 'Sources/App/Settings/** (AboutView, settings screens, source/compliance)' },
  { label: 'app-common', scope: 'Sources/App/Common/** (shared views, presentation helpers, error presentation) — many small files; enumerate ALL of them' },
  { label: 'app-root-shell', scope: 'Sources/App root .swift files (AppContainer, CypherAirApp, AppStartupCoordinator, AppLoadWarningCoordinator, AppShellComposition, AppLaunchConfiguration, AppRoute, HomeView, ContentView) + Sources/App/Shell/** + Sources/App/DesignSystem/**' },
  { label: 'security-protecteddata', scope: 'Sources/Security/ProtectedData/** (stores, AppLockController, SQLCipher DB, registry)' },
  { label: 'security-se-custody', scope: 'Sources/Security root SecureEnclave*.swift (custody handles, composite, managers) + Sources/Security/Mocks/**' },
  { label: 'security-auth-keychain', scope: 'Sources/Security root non-SecureEnclave .swift: AuthenticationManager + Auth*, Keychain*, KeyMigrationCoordinator, PrivateKeyEnvelope + PrivateKeyRewrap*/ModeSwitch*, KeyBundleStore, KeyMetadataPersistence, Argon2idMemoryGuard, MemoryZeroingUtility, EnvelopePlistInspector' },
  { label: 'services-ffi', scope: 'Sources/Services/FFI/** (PGP*OperationAdapter, PgpError->CypherAirError normalization)' },
  { label: 'services-keymgmt', scope: 'Sources/Services/KeyManagement/**, Sources/Services/KeyManagementService.swift' },
  { label: 'services-other', scope: 'ALL Sources/Services/*.swift root files (Contact* services, Encryption/Decryption/Signing/PasswordMessage/CertificateSignature/SelfTest services, QRService, DiskSpaceChecker, FileProgressReporter, ImportablePublicCertificateInspection, ContactsSearchIndex, etc.) + Sources/Services/SQLCipher/**' },
  { label: 'models-core', scope: 'ALL Sources/Models/*.swift root files (PGPKey*, Certificate*, Signature*, CypherAirError, config + protected-settings types) — enumerate every one' },
  { label: 'models-contacts-ext', scope: 'Sources/Models/Contacts/** + Sources/Extensions/**' },
  { label: 'rust-core-keys', scope: 'pgp-mobile/src: lib.rs, error.rs, armor.rs, qr_url.rs, keys.rs, keys/** (generation, expiry, revocation, s2k, profile, key_info, public_certificates, selector_discovery, secret_transfer, composite_custody_generation, secure_enclave_generation), password.rs' },
  { label: 'rust-messages', scope: 'pgp-mobile/src: encrypt.rs, decrypt.rs, streaming.rs, sign.rs, verify.rs, cert_signature.rs, signature_details.rs, composite_classical.rs, composite_kem.rs, external_decryptor(.rs + dir), external_composite_decryptor(.rs + dir), external_signer(.rs + dir), external_composite_signer(.rs + dir)' },
]
const subsystemResults = await pipeline(
  SUBSYSTEMS,
  s => agent(
    `You are mapping one subsystem of CypherAir X (an unpublished, offline OpenPGP app). Read the files under: ${s.scope}. Do NOT edit anything.\n\n` +
    `Two jobs:\n` +
    `(1) STRUCTURE: per file, its role in one line; sizeConcern (oversized only if doing several unrelated jobs, not merely long); smells (crypto/Keychain logic in a SwiftUI body, duplication, god-objects, error-boundary leaks). In crossCutting, note copy-paste across the nine key families worth unifying.\n` +
    `(2) DEAD-CODE ENUMERATION — this is mechanical, not a judgment call. For each file, enumerate its top-level declarations (types, funcs, properties, cases, extensions) and grep the WHOLE repo for references to each. Report declStats {scanned, zeroRef}, and in zeroRefDeclarations list EVERY declaration with zero PRODUCTION references (references only from tests count as zero-production — note that). ` +
    `Do NOT omit a zero-reference symbol because you assume it's used somewhere or reached dynamically — instead include it and record the dynamicUsageCaveat (#selector/KVC/SwiftUI reflection/Codable/target-membership/string lookup). Omitting a zero-reference declaration is a failure of this task. It is fine to over-list; a later Opus pass and the compiler will adjudicate. Enumerate EVERY file in the chunk individually — never sample or truncate; a large chunk just means more entries, and declStats.scanned must be a real per-file count.` +
    (s.label.startsWith('rust') ? `\n(3) RUST FFI: also list any #[uniffi::export] function that has no call site in any Swift file (exportedFfiUnused) — the app never invokes it.` : ''),
    { label: `map:${s.label}`, phase: 'Map', model: 'sonnet', schema: SUBSYSTEM_SCHEMA },
  ),
  (map, s) => {
    const zeroRefs = zeroRefsOf(map)
    if (!zeroRefs.length) return { map, deadCodeVerdicts: [] }
    return agent(
      `Independently adjudicate these zero-reference declarations in CypherAir X. For EACH, run your own exhaustive repo-wide search (production + tests + build config + dynamic-dispatch vectors) and return a verdict with the searches you ran:\n` +
      `- dead-confirmed: your search found NO production reference and no viable dynamic-usage path. This IS a real finding — report it as dead. Do not soften it.\n` +
      `- live-confirmed: you found a concrete reference or entry point — you MUST cite it in referencesFound (an empty referencesFound is not a valid live verdict).\n` +
      `- removal-candidate: plausibly dead but a dynamic-usage caveat means only deleting + building can settle it — surface it as a candidate, never drop it.\n` +
      `There is deliberately no "inconclusive" verdict: uncertainty resolves to removal-candidate (surfaced), not silence. Candidates:\n` +
      zeroRefs.map(x => `- ${x.symbol} [${x.kind}] @ ${x.path}${x.caveat ? ` (caveat: ${x.caveat})` : ''}`).join('\n'),
      { label: `classify-dead:${s.label}`, phase: 'Verify (Opus)', model: 'opus', effort: 'high', schema: DEADCODE_VERDICT_SCHEMA },
    ).then(v => ({ map, deadCodeVerdicts: v?.verdicts || [] }))
  },
)

// ===== phase 2: FFI-shape leak map  ->  Opus adjudication (pipeline) =========
phase('FFI boundary')
const FFI_CHUNKS = [
  { label: 'ffi-leak-app', scope: 'Sources/App/** (Views + ScreenModels)' },
  { label: 'ffi-leak-models-ext', scope: 'Sources/Models/** and Sources/Extensions/**' },
  { label: 'ffi-leak-services-security', scope: 'Sources/Services/** (EXCLUDING Sources/Services/FFI/) and Sources/Security/** — generated types should be normalized at Services/FFI before reaching these higher-level consumers too' },
]
// Sonnet collects leak candidates in WF1; the Opus boundary-violation adjudication runs in WF2.
const ffiResults = await parallel(FFI_CHUNKS.map(c => () =>
  agent(
    `CypherAir X compiles its UniFFI-generated bindings (Sources/PgpMobile/pgp_mobile.swift, ~134 public types) directly INTO the app module, so there is no import wall: any generated type is visible everywhere. The project rule: generated FFI shapes must be normalized to app vocabulary at Sources/Services/FFI/ and NOT appear in high-level layers.\n\n` +
    `Step 1: read Sources/PgpMobile/pgp_mobile.swift and list the generated public DOMAIN types (enums/structs/records: KeyProfile, MessageQuantumSafety, PasswordDecryptStatus, DetailedSignatureStatus, SignatureVerificationState, PgpError, CertificateSignatureStatus, records, ...). IGNORE plumbing: FfiConverter*, *_lift/_lower, RustBuffer, UniffiHandleMap, internal Protocols.\n` +
    `Step 2: grep those type names across ${c.scope}, excluding Sources/Services/FFI/ and Sources/PgpMobile/.\n` +
    `Report each occurrence: the type, file:line, layer, and a best-guess whether it's a legit mapping point or a real shape-leak. Do NOT edit.`,
    { label: c.label, phase: 'FFI boundary', model: 'sonnet', schema: FFI_LEAK_SCHEMA },
  )
))

// ===== phase 3: test census (Sonnet only) ===================================
phase('Test census')
const TEST_CHUNKS = [
  { label: 'svc-tests-a', scope: 'Tests/ServiceTests, files starting A-E (alphabetical by filename)' },
  { label: 'svc-tests-b', scope: 'Tests/ServiceTests, files starting F-K' },
  { label: 'svc-tests-c', scope: 'Tests/ServiceTests, files starting L-P' },
  { label: 'svc-tests-d', scope: 'Tests/ServiceTests, files starting Q-Z' },
  { label: 'device-ffi-ui-tests', scope: 'Tests/DeviceSecurityTests, Tests/FFIIntegrationTests, UITests' },
  { label: 'rust-tests-a', scope: 'pgp-mobile/tests, files A-M (top level + subdirs)' },
  { label: 'rust-tests-b', scope: 'pgp-mobile/tests, files N-Z (top level + subdirs) + pgp-mobile/src embedded #[cfg(test)] modules' },
]
const testResults = await parallel(TEST_CHUNKS.map(t => () =>
  agent(
    `Census the test files under: ${t.scope}. Read them; do NOT edit.\n\n` +
    `Standard: a test worth keeping guards behavior a later change could quietly break. Classify each file: real-guard (asserts real behavior a regression would break) / vacuous (restates the implementation, asserts constants/enums, or tests the framework) / brittle-negative (a negative assertion that breaks on benign refactors while catching little — considered worse than no test here; a test whose only job is to assert some old thing is absent/removed is a brittle-negative that re-encodes a dead concept) / source-audit (greps/inspects source text rather than exercising behavior) / mixed (name the prune suspects). Tests that exercise migration / old-version / obsolete-format behavior are prune candidates — they pin cruft that is itself slated for removal. Give a concrete reason per file and list specific test-method names worth deleting. Do not recommend deleting real coverage.`,
    { label: `test:${t.label}`, phase: 'Test census', model: 'sonnet', schema: TEST_CENSUS_SCHEMA },
  )
))

// ===== phase 4: vestigial / obsolete-reachable analysis (producer-consumer) =
// Migration/version/capability code is REACHABLE (has callers) so NO reference
// tool finds it. Detection = purpose-reachability: can the guard's precondition
// occur in a fresh CypherAir X install? Discriminator = who WRITES the state it reads.
phase('Vestigial analysis')
const VESTIGIAL_CHUNKS = [
  { label: 'persisted-format-versions', scope: 'Every *FormatVersion / *SchemaVersion field and its guard/switch branches: Sources/Security/PrivateKeyEnvelope.swift, Sources/Security/ProtectedData/KeyMetadataDomainStore.swift, ProtectedDataRegistry.swift, ProtectedDataDomain.swift, and any other versioned persisted record. Cross-check docs/PERSISTED_STATE_INVENTORY.md as ground truth for what data actually exists on disk.' },
  { label: 'format-fallback-legacy-readers', scope: 'Decoders/readers that try a new format then fall back to an old one; existence checks for legacy files or Keychain items (incl. "v1" key prefixes); any oldFormat/legacy decode branch across Sources/Security, Sources/Services, Sources/Models.' },
  { label: 'se-rewrap-migration', scope: 'The KeyMigration* / PrivateKeyRewrapRecovery* / rewrap cluster in Sources/Security + AuthenticationManager migration hooks. (Expected LIVE crash-recovery — confirm the producer of the pending/interrupted state is CURRENT code.)' },
  { label: 'capability-branches', scope: 'PGPKeyCapabilityResolver, FileProtectionCapabilityProvider, and any capability enum/branch. (Expected LIVE runtime policy — confirm each gates on the current runtime environment, not old-vs-new app capability.)' },
]
// Sonnet does producer-consumer discovery; Opus verifies each candidate with a behavioral proof (in WF1, per maintainer).
const vestigialResults = await pipeline(
  VESTIGIAL_CHUNKS,
  v => agent(
    `Find REACHABLE-BUT-OBSOLETE code under: ${v.scope}. This is NOT dead-code detection — this code has live callers and runs on every load. Read; do NOT edit.\n\n` +
    `CypherAir X is UNPUBLISHED: no prior shipped version ever wrote data to a user's device. For each migration/version/capability branch, do PRODUCER-CONSUMER analysis:\n` +
    `1. PRECONDITION — state the guard that gates this branch (e.g. schemaVersion != current, legacy artifact exists, switch on a version enum).\n` +
    `2. STATE — identify the persisted/external state the guard reads, then find WHO WRITES it (the producer) by searching the repo.\n` +
    `3. PRODUCER CLASS — current-code (a current path can create it) / prior-version-only (only a past shipped version could) / migration-only (only the migration code itself) / external / none-found.\n` +
    `Hypothesis: vestigial-remove (precondition can NEVER be true in a fresh install — producer is prior-version-only / migration-only / none; this INCLUDES speculative forward-compat version scaffolding, which an unpublished app does not need and should shed) ; live (current code produces the state, e.g. in-app SE re-wrap crash recovery, or it gates on the runtime environment) ; unknown. Also list any EXISTING tests that exercise this branch (coRemoveTests) — they are deleted WITH it. Give evidence. Surface generously — this is about behavior, not reference counts.`,
    { label: `vestigial:${v.label}`, phase: 'Vestigial analysis', model: 'sonnet', schema: VESTIGIAL_SCHEMA },
  ),
  (map, v) => {
    const targets = (map?.sites || []).filter(s => s.hypothesis !== 'live')
    if (!targets.length) return { map, vestigialVerdicts: [] }
    return agent(
      `Verify these reachable-but-obsolete MIGRATION / CAPABILITY candidates with a BEHAVIORAL proof, NOT a reference count. For each, determine whether its precondition can EVER be true in a fresh CypherAir X install that never ran a prior shipped version. The discriminator: does CURRENT code write the state the guard checks for? Trace the producer yourself. Classify: remove (precondition unreachable — give the behavioralProof, the removeRationale, the cascade of types/fields orphaned once the trunk is removed, and coRemoveTests = existing tests deleted with it; speculative forward-compat scaffolding with no current producer is REMOVE — an unpublished app needs no version bridge) / live (cite the current producer or runtime path) / needs-runtime-check. Do NOT propose any new test that asserts the removal or characterizes the old behavior — that only re-encodes the dead code. No silent drops. Candidates:\n` +
      targets.map(s => `- ${s.symbol} @ ${s.path} [${s.kind}] precondition="${s.precondition}" reads="${s.readsState || '?'}" producer="${s.producer || '?'}"(${s.producerClass}) hypothesis=${s.hypothesis}`).join('\n'),
      { label: `verify-vestigial:${v.label}`, phase: 'Verify (Opus)', model: 'opus', effort: 'high', schema: VESTIGIAL_VERDICT_SCHEMA },
    ).then(vd => ({ map, vestigialVerdicts: vd?.verdicts || [] }))
  },
)

// ===== phase 5: docs census  ->  Opus verify (pipeline) =====================
phase('Docs census')
const DOC_CHUNKS = [
  { label: 'docs-core', scope: 'docs/SECURITY.md, docs/ARCHITECTURE.md, docs/TDD.md, docs/POST_QUANTUM.md' },
  { label: 'docs-product', scope: 'docs/PRD.md, docs/APP_STORE_LISTING.md, docs/SECURE_ENCLAVE_CUSTODY.md, docs/PERSISTED_STATE_INVENTORY.md' },
  { label: 'docs-process', scope: 'docs/TESTING.md, docs/RELEASE.md, docs/WORKFLOW.md, docs/ARM64E_STATUS.md' },
  { label: 'docs-root', scope: 'CLAUDE.md, AGENTS.md, README.md (root)' },
]
const docsResults = await pipeline(
  DOC_CHUNKS,
  d => agent(
    `Review the docs under: ${d.scope} for CypherAir X (unpublished, offline OpenPGP app that inherited docs from the older CypherAir). Read; do NOT edit.\n\n` +
    `Flag: stale facts (now-wrong claims — wrong counts, renamed types, superseded design); references to code that looks removed/renamed/dead; bloat (redundant/overlong/duplicated sections that belong in one home); outdated requirements that no longer match the new project. Quote the specific claim and say why it's stale. Do not rewrite — inventory only.`,
    { label: `docs:${d.label}`, phase: 'Docs census', model: 'sonnet', schema: DOCS_SCHEMA },
  ),
  (census, d) => {
    const claims = (census?.docs || []).flatMap(doc => [
      ...(doc.staleFacts || []).map(c => ({ doc: doc.path, claim: c, type: 'stale-fact' })),
      ...(doc.deadCodeRefs || []).map(c => ({ doc: doc.path, claim: c, type: 'dead-code-ref' })),
    ])
    if (!claims.length) return { census, docsVerdicts: [] }
    return agent(
      `Verify these documentation-staleness claims against the CURRENT CypherAir X code. For each, open the relevant code and confirm confirmed-stale (give the correct value) / actually-current / inconclusive, with evidence. Claims:\n` +
      claims.map(c => `- [${c.type}] ${c.doc}: ${c.claim}`).join('\n'),
      { label: `verify-docs:${d.label}`, phase: 'Verify (Opus)', model: 'opus', effort: 'high', schema: DOCS_VERDICT_SCHEMA },
    ).then(v => ({ census, docsVerdicts: v?.verdicts || [] }))
  },
)

// ===== phase 6: reconcile the periphery baseline (only if supplied) ==========
// args.peripheryChunks: string[]  (main loop runs `periphery scan` and splits its output)
let peripheryResults = []
if (args && Array.isArray(args.peripheryChunkFiles) && args.peripheryChunkFiles.length) {
  phase('Reconcile periphery')
  peripheryResults = await parallel(args.peripheryChunkFiles.map((path, i) => () =>
    agent(
      `Read the file at ${path} — it holds slice ${i + 1}/${args.peripheryChunkFiles.length} of periphery's unused-declaration findings for CypherAir X (an offline OpenPGP app; repo root is the current working directory). periphery is deterministic but has known false positives around dynamic dispatch, protocol witnesses, @objc/#selector, Codable synthesis, and target membership. Verify EACH listed item against the repo yourself and return a verdict for every one: dead-confirmed (genuinely unused — a real removal finding) / live-confirmed (periphery was wrong — cite the exact reference it missed) / removal-candidate (settle by delete + build). This is the model-INDEPENDENT floor: an item here that the map phase did not surface is exactly the kind of miss we care about, so adjudicate carefully. Do NOT edit anything.`,
      { label: `periphery:${i + 1}`, phase: 'Reconcile periphery', model: 'opus', effort: 'high', schema: PERIPHERY_VERDICT_SCHEMA },
    )
  )).then(r => r.filter(Boolean))
} else {
  log('No periphery baseline supplied — relying on mandatory enumeration + Opus classify.')
}

// (Completeness critic removed per maintainer 2026-07-07. The dead-code recall floor is mechanical —
//  periphery + mandatory enumeration (scanned/zeroRef counts) + symmetric verdicts — not an LLM opinion.
//  The "is any subsystem's yield implausibly low?" check is done by the main loop during map assembly.)

// ===== phase 7: crypto touchpoints (Sonnet; feeds Workflow 2) ================
phase('Crypto touchpoints')
const CRYPTO_CHUNKS = [
  { label: 'crypto-swift', scope: 'Swift: Sources/Services (Encryption/Decryption/Signing/PasswordMessage), Sources/Services/FFI adapters, Sources/Security (SE wrap, Keychain, zeroing, Argon2id, randomness)' },
  { label: 'crypto-rust', scope: 'Rust: pgp-mobile/src encrypt/decrypt/streaming/sign/verify/password/cert_signature/signature_details/armor/composite_classical/composite_kem/keys/external_* — format selection, AEAD, sig verify, KDF, zeroize, getrandom' },
]
const cryptoResults = await parallel(CRYPTO_CHUNKS.map(c => () =>
  agent(
    `Build a work-list of crypto/security touchpoints under: ${c.scope}, so a later deep pass knows where to look. Read; do NOT edit or judge correctness yet. Tag each relevant file with the security lens: format-selection (SEIPDv2 vs v4 by recipient), AEAD-hardfail (must abort, never emit partial plaintext), sig-verify (incl. the known dual status/verificationState debt), custody (SE wrap / Keychain protection class / split-custody non-exportability / SQLCipher key), memory-zeroize (all paths incl. errors), randomness (secure-only), ffi-seam (panics/error-mapping/buffer ownership across UniFFI), kdf (Argon2id params). Be inclusive.`,
    { label: `crypto:${c.label}`, phase: 'Crypto touchpoints', model: 'sonnet', schema: CRYPTO_SCHEMA },
  )
))

// ===== assemble (report/synthesis done by the main loop) ====================
log('Map + verification complete — assembling inventory.')
return {
  subsystems: subsystemResults.filter(Boolean),
  ffi: ffiResults.filter(Boolean),
  tests: testResults.filter(Boolean),
  vestigial: vestigialResults.filter(Boolean),
  docs: docsResults.filter(Boolean),
  periphery: peripheryResults,
  crypto: cryptoResults.filter(Boolean),
}
