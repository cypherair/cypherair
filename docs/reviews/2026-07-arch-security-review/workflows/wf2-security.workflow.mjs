export const meta = {
  name: 'cypherair-review-security',
  description: 'Workflow 2 of 2: security & crypto-correctness deep pass. All-Opus. ~19 assessment lenses → dedup → each finding verified by 5 perspective-diverse max-effort Opus skeptics (reality-gate: trace+exploit decisive; refuted/contested surfaced, never dropped) → completeness critic. Read-only.',
  phases: [
    { title: 'Assess', detail: '~19 Opus lenses produce candidate security findings from the real code (capped + deduped)', model: 'opus' },
    { title: 'Verify', detail: '5 perspective-diverse max-effort Opus skeptics per finding; trace+exploit or majority confirms', model: 'opus' },
    { title: 'Completeness', detail: 'unexamined crypto paths / attacker capabilities / invariants + contested-finding re-look', model: 'opus' },
  ],
}

const PRE =
  'CypherAir X is an UNPUBLISHED, offline OpenPGP app (zero network). Crypto engine = Sequoia PGP (Rust, crypto-openssl backend) exposed to a Swift app via UniFFI; Swift owns custody/Keychain/Secure-Enclave/UI. Crown-jewel invariants: ' +
  '(1) AEAD hard-fail — an authentication failure during decryption MUST abort immediately and NEVER surface partial plaintext; ' +
  '(2) profile-correct format auto-selection — never send SEIPDv2 to a v4-only recipient; ' +
  '(3) Secure-Enclave-custody private keys are NON-EXPORTABLE (no code path yields raw private material); ' +
  '(4) all key/passphrase/plaintext buffers are zeroed on ALL paths incl. errors (Rust `zeroize`, Swift `resetBytes(in:)`); ' +
  '(5) secure random only (Rust `getrandom`, Swift `SecRandomCopyBytes`/CryptoKit); ' +
  '(6) NO plaintext, private keys, or passphrases in logs (`print`/`os_log`/`NSLog`); ' +
  '(7) zero network code paths; (8) MIE / hardware memory-tagging entitlements stay enabled. ' +
  'You are hunting REAL security defects — confidentiality, integrity, authentication, custody, memory-safety, and untrusted-input robustness — not style. The repo root is the working directory. Do NOT edit anything.'

// ---------- schemas ----------
const FINDING_SCHEMA = {
  type: 'object', required: ['findings'],
  properties: {
    findings: {
      type: 'array',
      items: {
        type: 'object', required: ['title', 'location', 'defect', 'severity', 'failureScenario'],
        properties: {
          title: { type: 'string' },
          location: { type: 'string', description: 'file:line (the exact site)' },
          defect: { type: 'string' },
          invariant: { type: 'string', description: 'which crown-jewel invariant / hard constraint it violates' },
          failureScenario: { type: 'string', description: 'CONCRETE attacker input/state → security-relevant bad outcome' },
          severity: { type: 'string', enum: ['critical', 'high', 'medium', 'low', 'info'] },
          confidence: { type: 'string', enum: ['high', 'medium', 'low'] },
        },
      },
    },
  },
}
const VERDICT_SCHEMA = {
  type: 'object', required: ['verdict', 'reason'],
  properties: {
    verdict: { type: 'string', enum: ['confirmed', 'refuted', 'uncertain'] },
    reason: { type: 'string', description: 'evidence from the ACTUAL current code (quote lines)' },
    concreteScenario: { type: 'string', description: 'if confirmed: the concrete repro/exploit' },
    severity: { type: 'string', enum: ['critical', 'high', 'medium', 'low', 'info'] },
  },
}
const COMPLETENESS_SCHEMA = {
  type: 'object', required: ['gaps'],
  properties: {
    gaps: {
      type: 'array',
      items: {
        type: 'object', required: ['area', 'notExamined'],
        properties: {
          area: { type: 'string' },
          notExamined: { type: 'string' },
          suggestedProbe: { type: 'string' },
          severityIfReal: { type: 'string', enum: ['critical', 'high', 'medium', 'low', 'info'] },
        },
      },
    },
    contestedWorthReopening: { type: 'array', items: { type: 'string' }, description: 'contested findings that look like genuine under-ranked defects' },
    overall: { type: 'string' },
  },
}

// ---------- 5 perspective-diverse skeptics (trace + exploit are the reality-gate) ----------
const SKEPTICS = [
  { key: 'trace', role: 'Trace the EXACT current code path at the finding location. Does the code actually do what the finding claims? Quote the specific lines. If the finding misreads the code or the site has changed, vote refuted.' },
  { key: 'exploit', role: 'Construct a CONCRETE attacker scenario/input that triggers the defect and yields a security-relevant bad outcome (plaintext leak, forged signature accepted, key exfiltration, downgrade, panic/DoS, etc.). If you cannot construct one or the path is unreachable, vote refuted.' },
  { key: 'invariant', role: 'Identify precisely which crown-jewel invariant or hard constraint is violated. If none is actually violated (behavior within spec), vote refuted.' },
  { key: 'severity', role: 'Independently assess real-world severity and blast radius (all users? one key family? requires local device access? attacker-supplied message only?). Vote confirmed for a genuine security defect, refuted for a pure robustness/style nit.' },
  { key: 'design-intent', role: 'Check whether this is intentional/correct by design — a documented tradeoff, a Sequoia guarantee, a deliberate fail-closed, or covered by a test. Read nearby comments/docs/tests. If the "bug" is a misunderstanding of the design, vote refuted.' },
]

const tp = args && args.touchpointsFile ? args.touchpointsFile : '/tmp/wf2-touchpoints-by-lens.json'
const kf = args && args.knownFindingsFile ? args.knownFindingsFile : '/tmp/wf2-known-findings.md'

// ---------- assessment lenses ----------
const LENSES = [
  { label: 'format-selection', effort: 'high', key: 'format-selection',
    scope: 'pgp-mobile/src/encrypt.rs, decrypt.rs, lib.rs, keys/key_info.rs, keys/profile.rs; Sources/Services/EncryptionService.swift, DecryptionService.swift',
    focus: 'SEIPDv2-vs-v4 format selection by recipient key version; never emit SEIPDv2 to a v4-only holder; profile-correct auto-selection (constraint #8).' },
  { label: 'aead-hardfail', effort: 'xhigh', key: 'AEAD-hardfail',
    scope: 'pgp-mobile/src/decrypt.rs, streaming.rs, password.rs; Sources/Services/DecryptionService.swift, PasswordMessageService.swift',
    focus: 'AEAD/MDC authentication failure MUST abort and NEVER surface partial plaintext (#3). Hunt for early plaintext emission, buffered writes before auth completes, ignored/underchecked verification errors, streaming flush-before-verify.' },
  { label: 'sig-verify', effort: 'xhigh', key: 'sig-verify',
    scope: 'pgp-mobile/src/verify.rs, sign.rs, signature_details.rs, cert_signature.rs; Sources/Models/Signature*, DetailedSignatureVerification*; Sources/Services/SigningService.swift, CertificateSignatureService.swift',
    focus: 'Acceptance of forged/invalid/expired/revoked signatures; the dual status/verificationState model causing a bad signature to read as good; empty-signature vs notSigned confusion; certification trust.' },
  { label: 'recipient-revocation', effort: 'max', key: 'sig-verify',
    scope: 'pgp-mobile/src/encrypt.rs (collect_recipients, build_recipients), keys/key_info.rs, keys/revocation.rs, keys/expiry.rs',
    focus: 'WCR-01 class: encrypting to a REVOKED encryption subkey while primary is live (missing `.revoked(false)` — `.alive()` checks only expiry). Verify ALL recipient entry points (encrypt, encrypt_binary, external-p256-signer, streaming encrypt_file*). Also expiry-vs-revocation handling.' },
  { label: 'untrusted-parsing-dos', effort: 'high', key: null,
    scope: 'pgp-mobile/src/armor.rs, qr_url.rs, keys/selector_discovery.rs, keys/public_certificates.rs, keys.rs (import_secret_key), decrypt.rs + streaming.rs (packet parse/decompression); Sources/App/Contacts/Import/** (AppSceneIncomingURLRouter, IncomingURLImportCoordinator, PublicKeyImportLoader, ContactImportWorkflow), Sources/Services/QRService.swift, ContactImportMatcher.swift, ImportablePublicCertificateInspection.swift, Sources/Services/FFI/** import adapters',
    focus: 'FFI-reachable parsing of ATTACKER-controlled input (messages, keys, certs, cypherair:// QR/URL). Hunt: panics (unwrap/expect/slice-index) = abort/DoS; unbounded allocation / decompression bombs; deep recursion / entity flooding (userids/subkeys/sigs); armor/CRC robustness; acceptance of malformed/malicious cert or key; and the LOCKED-state cypherair:// import path (WCR-02).' },
  { label: 'custody-se', effort: 'high', key: 'custody',
    scope: 'Sources/Security/SecureEnclave*.swift (custody handles, managers, digest signer, key agreement); Sources/Services/KeyManagement/SecureEnclaveCustodyGenerationService.swift',
    focus: 'SE key-wrapping correctness; NON-EXPORTABILITY of SE-custody private keys (no path yields raw private material); access-control policy (biometry/devicePasscode); handle lifecycle.' },
  { label: 'custody-splitpqc', effort: 'high', key: 'custody',
    scope: 'Sources/Security/SecureEnclaveComposite*.swift, SecureEnclaveCustodyKeyAgreement.swift; pgp-mobile/src/keys/composite_custody_generation, keys/secure_enclave_generation, composite_classical.rs, composite_kem.rs, external_composite_*',
    focus: 'Split-custody PQC (ML-DSA/ML-KEM): non-exportability of the SE-held component; correct composite decapsulation/signing; classical-component envelope handling; no secret leak in the external-provider bridge.' },
  { label: 'custody-keychain', effort: 'high', key: 'custody',
    scope: 'Sources/Security/Keychain*.swift, KeyBundleStore.swift, KeyMetadataPersistence.swift, PrivateKeyEnvelope.swift',
    focus: 'Keychain protection classes / accessibility (no kSecAttrAccessibleAlways; correct WhenUnlocked…ThisDeviceOnly choices); envelope integrity; items excluded from backup/sync.' },
  { label: 'custody-atrest', effort: 'high', key: 'custody',
    scope: 'Sources/Security/ProtectedData/** (incl. ContactsSQLCipherDatabase); Sources/Services/SQLCipher/**',
    focus: 'SQLCipher key derivation/handling; ProtectedData domain gating opened only after privacy auth; file-protection classes; no plaintext DB / key material at rest.' },
  { label: 'zeroize-rust', effort: 'high', key: 'memory-zeroize',
    scope: 'pgp-mobile/src/** (secret-handling modules: keys*, password, decrypt, streaming, composite*, external_*)',
    focus: 'zeroize coverage of secret key material, passphrases, plaintext on ALL paths incl. error/early-return; secrets escaping via clones, Vec reallocation, or owned buffers returned across FFI. Report the highest-value misses, not every buffer.' },
  { label: 'zeroize-swift', effort: 'high', key: 'memory-zeroize',
    scope: 'Sources/Security/MemoryZeroingUtility.swift and Data buffers holding keys/passphrases/plaintext across Sources/Security and Sources/Services',
    focus: 'resetBytes(in:) on sensitive Data on ALL paths incl. errors/defers; passphrases in immutable Swift String (cannot be zeroed); buffers handed to FFI then not zeroed. Report the highest-value misses.' },
  { label: 'randomness-sidechannel', effort: 'high', key: 'randomness',
    scope: 'Rust getrandom/rand usage across pgp-mobile/src; Swift SecRandomCopyBytes/CryptoKit in Sources/Security; comparison sites for MACs/tags/tokens/fingerprints',
    focus: 'secure random ONLY (no weak rand/arc4random/predictable seeds); constant-time comparison for secret-dependent values; error text/timing leaking secret-dependent info.' },
  { label: 'kdf-argon2', effort: 'high', key: 'kdf',
    scope: 'pgp-mobile/src/password.rs, keys/s2k.rs; Sources/Security/Argon2idMemoryGuard.swift',
    focus: 'Argon2id parameters (memory/iterations/parallelism) meet policy; S2K correctness; password-message KDF; memory-guard bounds and OOM behavior.' },
  { label: 'ffi-errmap', effort: 'high', key: 'ffi-seam',
    scope: 'pgp-mobile/src/lib.rs (the UniFFI boundary), error.rs; Sources/Services/FFI/** adapters',
    focus: 'completeness of PgpError→CypherAirError normalization (any unmapped/opaque case reaching UI); error info leakage across the seam; boundary-level panics not already covered by untrusted-parsing-dos.' },
  { label: 'ffi-ownership-leaks', effort: 'high', key: 'ffi-seam',
    scope: 'pgp-mobile/src (owned/RustBuffer returns); Sources/Services/FFI/**; the WF1 FFI-leak candidates: MessageQuantumSafety in Sources/App/Encrypt/EncryptScreenModel.swift, External*Request in Sources/Security/SecureEnclaveCompositeOperations.swift + SecureEnclaveCustodyKeyAgreement.swift',
    focus: 'sensitive-buffer ownership across UniFFI (double-free / use-after-free / non-zeroed secret buffers); generated FFI types leaking past Services/FFI into ScreenModels/Models carrying raw failure categories.' },
  { label: 'concurrency-sensitive', effort: 'high', key: null,
    scope: 'Sources/Security/** and Sources/Services/** — @preconcurrency import sites and actors/stores holding key material',
    focus: 'data races on key/passphrase/plaintext buffers; @preconcurrency seams hiding real races; non-Sendable secrets crossing isolation; TOCTOU on custody state.' },
  { label: 'network-permissions-mie', effort: 'high', key: null,
    scope: 'whole repo + CypherAir-Info.plist + *.entitlements (grep + reason)',
    focus: 'The 3 hard constraints not owned by another lens: (1) ZERO network — no URLSession/NWConnection/Network framework/socket/http(s) anywhere; (2) minimal permissions — Info.plist/entitlements expose ONLY NSFaceIDUsageDescription (no camera/contacts/photos/network); (6) MIE / hardware-memory-tagging Enhanced Security entitlements present + enabled. Report each violation with file:line.' },
  { label: 'logging-leaks', effort: 'high', key: null,
    scope: 'whole repo — print(/os_log/NSLog/logger./debugPrint/String(describing:) in Swift; println!/eprintln!/dbg!/tracing in Rust',
    focus: 'any log/print of key material, passphrase, plaintext, or a value that transitively contains them (constraint #4 — high severity). Report concrete sites only.' },
  { label: 'known-findings', effort: 'high', key: null,
    scope: `re-verify the security-relevant open items in ${kf}`,
    focus: `Read ${kf}. Re-verify against CURRENT code the SECURITY-relevant open findings — WCR-02, WCR-03, WCR-04, WCR-05 and SR-FIX-05 (SKIP WCR-01: the recipient-revocation lens owns it; SKIP informational/test-quality rows WCR-06+). For each: still-open / fixed / never-valid, with current file:line evidence. Treat still-open items as findings.` },
]

const SEV = { critical: 5, high: 4, medium: 3, low: 2, info: 1 }
const sev = f => SEV[f && f.severity] || 0

// ---------- Assess (barrier) ----------
phase('Assess')
const assessed = (await parallel(LENSES.map(L => () =>
  agent(
    `${PRE}\n\nYou are the '${L.label}' security assessor. Read the code under: ${L.scope}.` +
    (L.key ? ` Also read ${tp} and use its "${L.key}" array as flagged starting points, but follow the code wherever it leads.` : '') +
    `\n\nFOCUS: ${L.focus}\n\nProduce candidate findings, MOST SEVERE FIRST. Each needs: a precise location (file:line), the defect in current code, the invariant/constraint violated, a CONCRETE failure scenario (attacker input/state → security-relevant bad outcome), and a severity. Be thorough and surface genuine suspicions — recall-oriented; a 5-skeptic max-effort pass kills false positives. Do NOT invent findings: if a genuine audit finds nothing real, return an empty list.`,
    { label: `assess:${L.label}`, phase: 'Assess', model: 'opus', effort: L.effort, schema: FINDING_SCHEMA },
  ).then(res => ({ lens: L.label, findings: ((res && res.findings) || []).map(f => ({ ...f, lens: L.label })) }))
))).filter(Boolean)

// per-lens cap (6, severity-sorted) — surface any overflow instead of silently dropping
const CAP = 6
let overflow = []
const capped = assessed.map(r => {
  const sorted = r.findings.slice().sort((a, b) => sev(b) - sev(a))
  if (sorted.length > CAP) overflow.push(...sorted.slice(CAP).map(f => ({ ...f, note: 'over per-lens cap — unverified' })))
  return { ...r, findings: sorted.slice(0, CAP) }
})
// cross-lens dedup by (file, title-keyword); merge lens provenance, keep max severity
const norm = s => String(s || '').toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim()
const seen = new Map()
for (const f of capped.flatMap(r => r.findings)) {
  const k = String(f.location || '').split(':')[0].trim() + '::' + norm(f.title).slice(0, 50)
  if (!seen.has(k)) seen.set(k, { ...f, lenses: [f.lens] })
  else { const e = seen.get(k); if (!e.lenses.includes(f.lens)) e.lenses.push(f.lens); if (sev(f) > sev(e)) e.severity = f.severity }
}
let deduped = [...seen.values()].sort((a, b) => sev(b) - sev(a))
// global backstop against runaway verify cost — surface the tail unverified rather than drop
const GLOBAL = 70
let unverified = []
if (deduped.length > GLOBAL) { unverified = deduped.slice(GLOBAL).map(f => ({ ...f, note: 'over global verify cap — unverified' })); deduped = deduped.slice(0, GLOBAL) }
log(`Assess: ${capped.flatMap(r => r.findings).length} capped findings → ${deduped.length} deduped to verify (${overflow.length} over per-lens cap, ${unverified.length} over global cap — all surfaced unverified). Verifying each with 5 max-effort skeptics.`)

// assess-first gate: return candidate findings for review before the expensive verify phase.
// Later: resume this same runId with args.verify=true → the 19 assess agents replay from cache, verify runs live.
if (!(args && args.verify)) {
  log(`Assess-only run complete — ${deduped.length} candidate findings for review (verify phase gated).`)
  return { mode: 'assess', findings: deduped, overflow, unverified }
}

// ---------- Verify (tiered: HIGH/critical → 3 max-effort skeptics; others → 1 xhigh verifier) ----------
phase('Verify')
const HIGH_SKEPTICS = SKEPTICS.filter(s => ['trace', 'exploit', 'invariant'].includes(s.key)) // 3
const isHigh = f => f.severity === 'high' || f.severity === 'critical'
const findingHeader = f =>
  `${PRE}\n\nA prior pass raised this candidate security finding:\n` +
  `Title: ${f.title}\nLocation: ${f.location}\nLens(es): ${(f.lenses || [f.lens]).join(', ')}\nDefect: ${f.defect}\n` +
  `Invariant claimed: ${f.invariant || '(unspecified)'}\nClaimed failure scenario: ${f.failureScenario}\nClaimed severity: ${f.severity}\n\n`
const verified = (await parallel(deduped.map(f => () => {
  if (isHigh(f)) {
    return parallel(HIGH_SKEPTICS.map(sk => () =>
      agent(
        findingHeader(f) + `You are skeptic role '${sk.key}': ${sk.role}\n\nRead the ACTUAL current code yourself before voting. Default to 'refuted' if you cannot substantiate the claim. Vote confirmed / refuted / uncertain with evidence (quote lines), a concrete scenario if confirmed, and your independent severity.`,
        { label: `verify-hi:${sk.key}`, phase: 'Verify', model: 'opus', effort: 'max', schema: VERDICT_SCHEMA },
      ).then(v => (v ? { sk: sk.key, ...v } : null))
    )).then(votes => {
      const v = votes.filter(Boolean)
      const role = Object.fromEntries(v.map(x => [x.sk, x.verdict]))
      const confirmed = v.filter(x => x.verdict === 'confirmed').length
      const realityGate = role.trace === 'confirmed' && role.exploit === 'confirmed'
      return { ...f, tier: 'high-3max', votes: v, confirmedCount: confirmed, realityGate,
        decision: (realityGate || confirmed >= 2) ? 'confirmed' : (confirmed >= 1 ? 'contested' : 'refuted') }
    })
  }
  return agent(
    findingHeader(f) + `You are the SOLE verifier. Do ALL of: (1) trace the exact current code path (quote lines); (2) try to construct a concrete exploit/repro, or show it is unreachable; (3) name the invariant/constraint violated, if any; (4) assess real severity/blast-radius; (5) check whether it is intentional/correct-by-design (comments/docs/tests). Then vote confirmed / refuted / uncertain with evidence, a concrete scenario if confirmed, and your independent severity. Default to 'refuted' if you cannot substantiate the claim from the current code.`,
    { label: `verify-solo:${(f.location || '').split('/').pop()}`, phase: 'Verify', model: 'opus', effort: 'xhigh', schema: VERDICT_SCHEMA },
  ).then(v => {
    const vote = v || { verdict: 'uncertain', reason: 'no result' }
    return { ...f, tier: 'solo-xhigh', votes: [vote], confirmedCount: vote.verdict === 'confirmed' ? 1 : 0,
      decision: vote.verdict === 'confirmed' ? 'confirmed' : (vote.verdict === 'uncertain' ? 'contested' : 'refuted') }
  })
}))).filter(Boolean)

// ---------- Completeness critic ----------
phase('Completeness')
const summary = verified.map(f => ({ lens: f.lens, title: f.title, location: f.location, severity: f.severity, decision: f.decision, confirmed: f.confirmedCount }))
const contested = verified.filter(f => f.decision === 'contested').map(f => `${f.title} @ ${f.location} (${f.confirmedCount}/5)`)
const critique = await agent(
  `${PRE}\n\nA security deep-pass ran ~19 lenses over the crypto/custody/FFI/parsing surface and verified each candidate with 5 skeptics. Finding set (title/location/severity/decision):\n${JSON.stringify(summary, null, 2)}\n\n` +
  `CONTESTED findings (real per some skeptics but not majority — check these for under-ranked genuine defects):\n${JSON.stringify(contested, null, 2)}\n\n` +
  `You are the completeness critic. (a) What crypto path, attacker capability, key family (v4/v6/Ed448/ML-DSA/ML-KEM/SE-custody/split-custody), or crown-jewel invariant was NOT examined or only shallowly touched? Name files/functions + a suggested probe + severity-if-real. (b) In contestedWorthReopening, list any contested finding that looks like a genuine defect the panel under-ranked.`,
  { label: 'completeness:security', phase: 'Completeness', model: 'opus', effort: 'xhigh', schema: COMPLETENESS_SCHEMA },
)

log('Security deep-pass complete — assembling findings.')
return { findings: verified, unverifiedOverflow: overflow.concat(unverified), completeness: critique }
