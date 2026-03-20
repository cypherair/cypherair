## Comprehensive Test Suite Analysis for CypherAir

### Overview
The CypherAir project has a well-structured test suite across 13 test files with 4 distinct test layers. Total test count: **170+ tests** covering FFI integration, services, security, device-only features, and GnuPG interoperability.

---

## 1. FFIIntegrationTests.swift
**File**: `/Tests/FFIIntegrationTests/FFIIntegrationTests.swift`
**Tests**: 42 tests

### Test Categories

#### C5.1 Binary Round-Trip (4 tests)
- `test_binaryRoundTrip_profileA_dataPreservedAcrossFFI()` - Profile A data round-trip
- `test_binaryRoundTrip_profileB_dataPreservedAcrossFFI()` - Profile B data round-trip
- `test_binaryRoundTrip_largeData_1MB_profileA()` - 1 MB file Profile A
- `test_binaryRoundTrip_largeData_1MB_profileB()` - 1 MB file Profile B

#### C5.2 Unicode Round-Trip (2 tests)
- `test_unicodeRoundTrip_chineseEmojiPreserved()` - Multiple Unicode test strings (Chinese, emoji, math symbols, Arabic, mixed)
- `test_unicodeRoundTrip_userIdPreserved()` - User ID with Chinese name survives FFI

#### C5.3 Error Enum Mapping (11 tests)
- `test_errorMapping_noMatchingKey()` - Decrypt with wrong key
- `test_errorMapping_integrityCheckFailed_profileA()` - 1-bit flip Profile A (SEIPDv1)
- `test_errorMapping_aeadAuthenticationFailed_profileB()` - 1-bit flip Profile B (SEIPDv2 AEAD hard-fail)
- `test_errorMapping_corruptData()` - Garbage input
- `test_errorMapping_wrongPassphrase()` - Export/import with wrong passphrase
- `test_errorMapping_invalidKeyData()` - Invalid key input
- `test_errorMapping_badSignature_cleartextVerify()` - Tampered cleartext signature
- `test_errorMapping_unknownSigner_viaCleartextVerify()` - Signer not in verification keys
- `test_errorMapping_armorError()` - Malformed armor
- `test_errorMapping_signingFailed_invalidKey()` - Invalid signing key
- `test_errorMapping_encryptionFailed_noRecipients()` - Empty recipients list
- `test_errorMapping_revocationError_invalidData()` - Garbage revocation cert
- `test_errorMapping_s2kError_profileB_wrongPassphrase()` - Argon2id wrong passphrase
- `test_errorMapping_badSignature_detachedVerify()` - Detached sig on tampered data

#### C5.5 KeyProfile Enum (3 tests)
- `test_keyProfileEnum_universal_producesV4()` - Profile A → v4 key
- `test_keyProfileEnum_advanced_producesV6()` - Profile B → v6 key
- `test_keyProfileEnum_bothProfiles_generateCompleteKeys()` - Both profiles produce complete keys

#### C5.6 Concurrent Encrypt (1 test)
- `test_concurrentEncrypt_threadsafe()` - 10 concurrent encrypt tasks succeed

#### C5.7 Concurrent Encrypt/Decrypt (2 tests)
- `test_concurrentEncryptDecrypt_threadsafe()` - 5 encrypt + 5 decrypt tasks mixed
- `test_concurrentEncryptDecrypt_profileB_threadsafe()` - Profile B concurrent mixed operations

#### C4: Argon2id Memory Guard Tests (9 tests)
- `test_argon2idGuard_profileB_512MB_8GBDevice_passes()` - 512 MB on 8GB device
- `test_argon2idGuard_1GB_lowMemory_throwsExceeded()` - 1 GB exceeds 75% threshold
- `test_argon2idGuard_1GB_ampleMemory_passes()` - 1 GB on ample memory
- `test_argon2idGuard_2GB_moderateMemory_throwsExceeded()` - 2 GB exceeds threshold
- `test_argon2idGuard_exact75PercentBoundary_passes()` - At boundary threshold
- `test_argon2idGuard_justBelow75PercentBoundary_throwsExceeded()` - 1 byte below boundary
- `test_argon2idGuard_profileA_iteratedSalted_alwaysPasses()` - Profile A no-op
- `test_argon2idGuard_argon2idTypeZeroMemory_passes()` - Argon2id with zero memory
- `test_argon2idGuard_unknownS2kType_passes()` - Unknown S2K type no-op
- `test_argon2idGuard_queriesMemoryProviderExactlyOnce()` - Verify single query

#### Phase 1/Phase 2 Two-Phase Decryption (7 tests)
- `test_parseRecipients_profileA_returnsMatchingKeyIDs()` - Phase 1 Profile A
- `test_parseRecipients_profileB_returnsMatchingKeyIDs()` - Phase 1 Profile B
- `test_twoPhaseDecrypt_noMatchingKey_phase1SucceedsPhase2Fails()` - Wrong key Phase 2 fail
- `test_parseRecipients_garbageData_throwsError()` - Garbage Phase 1
- `test_twoPhaseDecrypt_multiRecipient_bothCanDecrypt()` - Multi-recipient Phase 1/2
- `test_errorMapping_keyExpired_detectsExpiredKey()` - Expired key detection
- `test_matchRecipients_*()` - 3 tests for matchRecipients FFI

#### Memory Zeroing Tests (7 tests)
- `test_dataZeroize_setsAllBytesToZero()`
- `test_dataZeroize_emptyData_noop()`
- `test_dataZeroize_largeBuffer_allZeros()` - 1 MB buffer
- `test_arrayZeroize_setsAllElementsToZero()`
- `test_arrayZeroize_emptyArray_noop()`
- `test_sensitiveData_explicitZeroize_clearsData()`
- `test_sensitiveData_deinit_zerosStorage()`

### Coverage Summary
- **Positive tests**: Key round-trip encrypt/decrypt for both profiles
- **Negative tests**: Tamper detection (1-bit flip), wrong key, invalid input, garbage data
- **Both profiles**: All crypto tests run for both Profile A and Profile B
- **FFI boundary**: Unicode preservation, Error enum mapping, concurrent thread safety
- **Argon2id**: Memory guard validation with mocked memory for Profile B
- **Memory safety**: Data zeroing for sensitive buffers

---

## 2. DeviceSecurityTests.swift
**File**: `/Tests/DeviceSecurityTests/DeviceSecurityTests.swift`
**Status**: Guard skips tests without Secure Enclave (SE only on device)
**Coverage**: Likely Secure Enclave wrapping/unwrapping, biometric auth, auth mode switching, crash recovery, MIE validation

---

## 3. TestHelpers.swift
**File**: `/Tests/ServiceTests/TestHelpers.swift`
**Purpose**: Factory functions and mock infrastructure for Services layer tests
**Exports**:
- `makeKeyManagement()` - Creates KeyManagementService with mocks (SE, Keychain, Authenticator)
- `makeContactService()` - Creates ContactService with temp directory
- `generateAndStoreKey()` - Helper to generate and store keys
- `generateProfileAKey()` - Generate Profile A key
- `generateProfileBKey()` - Generate Profile B key
- `makeServiceStack()` - Complete service stack with all mocks
- `ServiceStack` struct - Container for all services and mocks

---

## 4. QRServiceTests.swift
**File**: `/Tests/ServiceTests/QRServiceTests.swift`
**Tests**: 17 tests

### Test Categories

#### Positive: Valid URL Round-Trip (4 tests)
- `test_parseImportURL_validV1URL_profileA_returnsPublicKeyData()` - v1 URL Profile A
- `test_parseImportURL_validV1URL_profileB_returnsPublicKeyData()` - v1 URL Profile B
- `test_parseImportURL_roundTrip_fingerprintMatches()` - Fingerprint survives round-trip
- `test_parseImportURL_roundTrip_profileB_fingerprintMatches()` - Profile B fingerprint

#### Negative: Wrong Scheme (2 tests)
- `test_parseImportURL_wrongScheme_https_throwsInvalidQRCode()`
- `test_parseImportURL_wrongScheme_http_throwsInvalidQRCode()`

#### Negative: Wrong Host/Path (1 test)
- `test_parseImportURL_wrongHost_throwsInvalidQRCode()`

#### Negative: Unsupported Version (1 test)
- `test_parseImportURL_unsupportedVersion_v2_throwsUnsupportedQRVersion()`

#### Negative: Missing/Invalid Payload (3 tests)
- `test_parseImportURL_missingPayload_throwsInvalidKeyData()` - Empty payload
- `test_parseImportURL_invalidBase64_throwsCorruptData()` - Invalid base64url
- `test_parseImportURL_validBase64ButNotPGP_throwsInvalidKeyData()` - Valid base64 but non-PGP

#### Negative: Secret Key Material (1 test)
- `test_parseImportURL_secretKeyMaterial_throwsError()` - Rejects secret keys

#### Negative: URL Length Limit (2 tests)
- `test_parseImportURL_exceedsMaxLength_throwsInvalidQRCode()` - Over 4096 chars
- `test_parseImportURL_atMaxLength_doesNotThrowLengthError()` - Exactly 4096 chars

#### QR Code Generation (2 tests)
- `test_generateQRCode_validPublicKey_returnsCIImage()`
- `test_generateQRCode_emptyData_throwsError()`

### Coverage Summary
- **Security-critical**: Validates parsing of untrusted external input from QR codes
- **Both profiles**: v4 and v6 key support
- **Negative tests**: Malformed URLs, wrong schemes, invalid base64, secret key rejection, DoS protection (URL length limit)

---

## 5. KeyManagementServiceTests.swift
**File**: `/Tests/ServiceTests/KeyManagementServiceTests.swift`
**Tests**: 50+ tests (partial read)

### Test Categories

#### Key Generation: Profile A (2 tests)
- `test_generateKey_profileA_storesKeychainItems()` - 4 Keychain items per profile A key
- `test_generateKey_profileA_returnsCorrectIdentity()` - v4 key, universal profile

#### Key Generation: Profile B (2 tests)
- `test_generateKey_profileB_storesKeychainItems()` - 4 Keychain items per profile B key
- `test_generateKey_profileB_returnsCorrectIdentity()` - v6 key, advanced profile

#### Default Key Logic (2 tests)
- `test_generateKey_firstKey_isDefault()`
- `test_generateKey_secondKey_isNotDefault()`

#### SE Interaction (2 tests)
- `test_generateKey_seWrapCalled()` - SE.generate() and SE.wrap() called
- `test_generateKey_profileB_seWrapCalled()` - Profile B SE interaction

#### Key Loading (3 tests)
- `test_loadKeys_emptyKeychain_returnsEmpty()`
- `test_loadKeys_withStoredMetadata_loadsKeys()`
- `test_loadKeys_corruptMetadata_skipsCorruptEntry()`

#### Key Export (3 tests)
- `test_exportKey_profileA_returnsArmoredData()` - ASCII armor with PGP header
- `test_exportKey_marksKeyAsBackedUp()`
- `test_exportKey_nonexistentFingerprint_throwsError()`

#### Key Deletion (3 tests)
- `test_deleteKey_removesKeychainItems()`
- `test_deleteKey_removesFromKeysArray()`
- `test_deleteKey_reassignsDefaultIfNeeded()` - Remaining key becomes default

#### Unwrap Private Key (3 tests)
- `test_unwrapPrivateKey_validFingerprint_returnsData()`
- `test_unwrapPrivateKey_unknownFingerprint_throwsError()`
- `test_unwrapPrivateKey_profileB_returnsData()`

#### Key Import/Restore (2 tests)
- `test_importKey_profileA_exportThenImport_fingerprintMatches()` - Full round-trip
- `test_importKey_profileB_exportThenImport_fingerprintMatches()` - Profile B export/import

#### Default Key (4 tests)
- `test_setDefaultKey_switchesDefault()`
- `test_defaultKey_returnsFirstDefault()`
- `test_defaultKey_noKeys_returnsNil()`
- `test_setDefaultKey_persistsAcrossReload()`

#### Duplicate Key Import Guard (2 tests)
- `test_importKey_duplicateFingerprint_throwsDuplicateKeyError()` - Profile A guard
- `test_importKey_duplicateFingerprint_profileB_throwsDuplicateKeyError()` - Profile B guard

#### Modify Expiry (5 tests)
- `test_modifyExpiry_profileA_updatesExpiryDate()`
- `test_modifyExpiry_profileB_updatesExpiryDate()`
- `test_modifyExpiry_setsAndClearsCrashRecoveryFlag()`
- `test_modifyExpiryCrashRecovery_oldAndPendingExist_deletesPending()`

### Coverage Summary
- **Both profiles**: All operations tested for A and B
- **Key lifecycle**: Generation, loading, export, import, deletion, modification
- **SE integration**: Verified wrapping/unwrapping calls
- **Crash recovery**: Modify expiry interrupted recovery
- **Duplicate protection**: Guards against re-importing existing keys

---

## 6. DecryptionServiceTests.swift
**File**: `/Tests/ServiceTests/DecryptionServiceTests.swift`
**Tests**: 20+ tests

### Test Categories

#### Phase 1: Parse Recipients (4 tests)
- `test_parseRecipients_returnsNonEmptyKeyIds()` - Profile A key IDs
- `test_parseRecipients_profileB_returnsNonEmptyKeyIds()` - Profile B key IDs
- `test_parseRecipients_noMatchingKey_throwsError()` - When user doesn't have recipient key
- `test_parseRecipients_doesNotTriggerSeUnwrap()` - **CRITICAL**: No SE auth at Phase 1

#### Phase 2: Decrypt (Authentication Required) (3 tests)
- `test_decrypt_phase2_profileA_returnsPlaintext()` - Profile A decryption
- `test_decrypt_phase2_profileB_returnsPlaintext()` - Profile B decryption
- `test_decrypt_phase2_withSignature_returnsValidVerification()` - Signature verification
- `test_decrypt_phase2_triggersSeUnwrap()` - **CRITICAL**: Phase 2 must trigger SE auth
- `test_decrypt_phase2_noMatchedKey_throwsError()` - No matched key error

#### Tamper Detection (1-Bit Flip) (2 tests)
- `test_decrypt_profileA_tamperedCiphertext_throwsIntegrityError()` - MDC check Profile A
- `test_decrypt_profileB_tamperedCiphertext_throwsAEADError()` - AEAD hard-fail Profile B

#### Full Round-Trip via Engine (3 tests)
- `test_encryptDecrypt_profileA_fullRoundTrip()` - Encrypt → decrypt via engine
- `test_encryptDecrypt_profileB_fullRoundTrip()` - Profile B round-trip
- `test_encryptDecrypt_unicodePreserved()` - Unicode preservation across decrypt

#### Phase 2 via DecryptionService (2 tests)
- `test_decryptViaService_profileA_fullFlow()` - Service layer A
- `test_decryptViaService_profileB_fullFlow()` - Service layer B

#### End-to-End via decryptMessage() (4 tests)
- `test_decryptMessage_profileA_endToEnd()` - Both Phase 1 + Phase 2
- `test_decryptMessage_profileB_endToEnd()` - Profile B end-to-end
- `test_parseRecipients_profileA_matchesCorrectKey()` - Correct key matching
- `test_parseRecipients_profileB_matchesCorrectKey()` - Profile B key matching

### Coverage Summary
- **CRITICAL SECURITY**: Phase 1/Phase 2 boundary validation
  - Phase 1 **must NOT** trigger SE unwrap
  - Phase 2 **must** trigger SE unwrap (biometric auth)
- **Both profiles**: Full encryption/decryption for A and B
- **Tamper detection**: 1-bit flip triggers integrity/AEAD failure
- **Two-phase decryption model**: Validates the security boundary

---

## 7. EncryptionServiceTests.swift
**File**: `/Tests/ServiceTests/EncryptionServiceTests.swift`
**Tests**: 30+ tests (partial read)

### Test Categories

#### Text Encryption: Profile A (1 test)
- `test_encryptText_profileA_producesNonEmptyCiphertext()`

#### Text Encryption: Profile B (1 test)
- `test_encryptText_profileB_producesNonEmptyCiphertext()`

#### No Recipients (1 test)
- `test_encryptText_noRecipients_throwsError()` - Validation

#### Unknown Recipient (1 test)
- `test_encryptText_unknownRecipient_throwsError()`

#### Signing (1 test)
- `test_encryptText_withSignature_succeeds()`

#### Encrypt-to-Self (4 tests)
- `test_encryptText_encryptToSelf_canDecryptWithOwnKey()` - Profile A
- `test_encryptText_encryptToSelfOff_cannotDecryptWithSenderKey()` - Profile A negative
- `test_encryptText_profileB_encryptToSelf_canDecryptWithOwnKey()` - Profile B
- `test_encryptText_profileB_encryptToSelfOff_cannotDecryptWithSenderKey()` - Profile B negative

#### File Encryption: Size Validation (3 tests)
- `test_encryptFile_underLimit_succeeds()` - 1 KB file
- `test_encryptFile_over100MB_throwsFileTooLarge()` - File size validation
- `test_encryptFile_exactly100MB_succeeds()` - Boundary test
- `test_encryptFile_profileB_underLimit_succeeds()`

#### Cross-Profile (2 tests)
- `test_encryptText_profileBSender_profileARecipient_succeeds()` - Profile B sender → Profile A recipient
- `test_encryptText_mixedRecipients_v4AndV6_bothCanDecrypt()` - Mixed v4+v6 → SEIPDv1 (lowest common denominator)

#### Encrypt-to-Self: No Default Key (1 test)
- `test_encryptText_encryptToSelf_noDefaultKey_throwsNoKeySelected()`

#### Encrypt-to-Self: Key Selection (2 tests)
- `test_encryptText_encryptToSelfWithSpecificKey_canDecryptWithThatKey()` - Non-default key
- `test_encryptText_encryptToSelfFingerprintNil_usesDefaultKey()` - Fallback to default

### Coverage Summary
- **Both profiles**: Profile A and B encryption tested
- **Cross-profile**: Format auto-selection (v4→SEIPDv1, v6→SEIPDv2, mixed→SEIPDv1)
- **Encrypt-to-self**: Feature toggle, key selection, default fallback
- **File size validation**: Boundary testing at 100 MB limit
- **Negative tests**: No recipients, unknown recipients, no default key

---

## 8. SigningServiceTests.swift
**File**: `/Tests/ServiceTests/SigningServiceTests.swift`
**Tests**: 16 tests

### Test Categories

#### Cleartext Signing (2 tests)
- `test_signCleartext_profileA_producesSignedMessage()` - "BEGIN PGP SIGNED MESSAGE"
- `test_signCleartext_profileB_producesSignedMessage()`

#### Detached Signing (2 tests)
- `test_signDetached_profileA_producesDetachedSignature()`
- `test_signDetached_profileB_producesDetachedSignature()`

#### Cleartext Verification (4 tests)
- `test_verifyCleartext_validSignature_returnsValid()` - Profile A
- `test_verifyCleartext_profileB_validSignature_returnsValid()` - Profile B
- `test_verifyCleartext_tamperedMessage_returnsBad()` - Tampered detection
- `test_verifyCleartext_profileB_tamperedMessage_returnsBad()` - Profile B tamper

#### Unknown Signer (2 tests)
- `test_verifyCleartext_unknownSigner_returnsUnknownSigner()` - Profile A
- `test_verifyCleartext_profileB_unknownSigner_returnsUnknownSigner()` - Profile B

#### Detached Verification (2 tests)
- `test_verifyDetached_validSignature_returnsValid()` - Profile A
- `test_verifyDetached_profileB_validSignature_returnsValid()` - Profile B

#### Tamper Detection (2 tests)
- `test_verifyDetached_tamperedData_returnsBad()` - Data mismatch
- `test_verifyDetached_profileB_tamperedData_returnsBad()` - Profile B tamper

#### Expired Signer Key (2 tests)
- `test_verifyCleartext_expiredSignerKey_returnsExpiredOrWarning()` - Profile A
- `test_verifyCleartext_profileB_expiredSignerKey_returnsExpiredOrWarning()` - Profile B

#### Known Contact Resolution (2 tests)
- `test_verifyCleartext_knownContact_resolvesSigner()` - Profile A
- `test_verifyCleartext_profileB_knownContact_resolvesSigner()` - Profile B

### Coverage Summary
- **Both profiles**: All signing/verification for A and B
- **Positive tests**: Valid signatures verify as .valid
- **Negative tests**: Tampered messages, unknown signers, expired keys
- **Graded results**: .valid, .bad, .unknownSigner statuses

---

## 9. ModelTests.swift
**File**: `/Tests/ServiceTests/ModelTests.swift`
**Tests**: 40+ tests (partial read)

### Test Categories

#### CypherAirError: PgpError Mapping (20+ tests)
- Maps every `PgpError` variant to `CypherAirError`:
  - `.AeadAuthenticationFailed` → `.aeadAuthenticationFailed`
  - `.NoMatchingKey` → `.noMatchingKey`
  - `.UnsupportedAlgorithm` → `.unsupportedAlgorithm`
  - `.KeyExpired` → `.keyExpired`
  - `.BadSignature` → `.badSignature`
  - `.UnknownSigner` → `.unknownSigner`
  - `.CorruptData` → `.corruptData`
  - `.WrongPassphrase` → `.wrongPassphrase`
  - `.InvalidKeyData` → `.invalidKeyData`
  - `.EncryptionFailed` → `.encryptionFailed`
  - `.SigningFailed` → `.signingFailed`
  - `.ArmorError` → `.armorError`
  - `.IntegrityCheckFailed` → `.integrityCheckFailed`
  - `.Argon2idMemoryExceeded` → `.argon2idMemoryExceeded`
  - `.RevocationError` → `.revocationError`
  - `.KeyGenerationFailed` → `.keyGenerationFailed`
  - `.S2kError` → `.s2kError`
  - `.InternalError` → `.internalError`

#### Contact: Display Name (3 tests)
- `test_contact_displayName_withNameAndEmail_extractsName()` - Parses name from "Name <email>"
- `test_contact_displayName_nilUserId_returnsUnknown()` - Fallback
- `test_contact_displayName_noAngleBrackets_returnsUserId()`

#### Contact: Email Extraction (3 tests)
- `test_contact_email_extractsFromUserId()` - Extracts from angle brackets
- `test_contact_email_noAngleBrackets_returnsNil()`
- `test_contact_email_nilUserId_returnsNil()`

#### Contact: canEncryptTo (4 tests)
- `test_contact_canEncryptTo_validKey_returnsTrue()` - Has subkey, not revoked/expired
- `test_contact_canEncryptTo_expired_returnsFalse()`
- `test_contact_canEncryptTo_revoked_returnsFalse()`
- `test_contact_canEncryptTo_noSubkey_returnsFalse()`

#### PGPKeyIdentity: Computed Properties (2 tests)
- `test_pgpKeyIdentity_shortKeyId_returnsLast16Chars()`
- `test_pgpKeyIdentity_formattedFingerprint_groupsOf4()`

#### KeyProfile+Codable (2 tests)
- `test_keyProfile_encodeDecode_universal_roundTrip()`
- `test_keyProfile_encodeDecode_advanced_roundTrip()`

### Coverage Summary
- **Error mapping**: Every PgpError variant maps to CypherAirError
- **Contact model**: Display name, email extraction, encryption capability checks
- **Identity model**: Key ID formatting, fingerprint formatting
- **Serialization**: Profile encoding/decoding

---

## 10. ContactServiceTests.swift
**File**: `/Tests/ServiceTests/ContactServiceTests.swift`
**Tests**: 15+ tests

### Test Categories

#### Load Contacts (1 test)
- `test_loadContacts_emptyDirectory_returnsEmpty()`

#### Add Contact (3 tests)
- `test_addContact_validPublicKey_returnsAdded()` - Profile A key
- `test_addContact_duplicateFingerprint_returnsDuplicate()` - Duplicate detection
- `test_addContact_sameUserIdDifferentFingerprint_returnsKeyUpdateDetected()` - Key update detection

#### Remove Contact (1 test)
- `test_removeContact_existingContact_removesFromArray()`

#### Confirm Key Update (1 test)
- `test_confirmKeyUpdate_replacesOldContact()` - Old file removed, new file created

#### Binary Key Import (3 tests)
- `test_addContact_binaryPublicKey_profileA_returnsAdded()` - Binary format (not armored)
- `test_addContact_binaryPublicKey_profileB_returnsAdded()`
- `test_addContact_armoredPublicKey_profileA_returnsAdded()` - Regression: armored format still works

#### Lookup (1 test)
- `test_contactsMatchingKeyIds_returnsCorrectContacts()` - By full fingerprint

### Coverage Summary
- **Both profiles**: A and B contact add/remove
- **Duplicate detection**: Same fingerprint not added twice
- **Key update detection**: Same UID but different fingerprint
- **Binary format**: Handles both binary and armored public keys
- **File I/O**: Contact files stored/removed on disk

---

## 11. FixtureLoader.swift
**File**: `/Tests/ServiceTests/FixtureLoader.swift`
**Purpose**: Load pre-generated GnuPG fixture files from test bundle
**Exports**:
- `loadData(_ name: String, ext: String)` - Raw binary data
- `loadString(_ name: String, ext: String)` - UTF-8 string
- `FixtureError` - Error types (.notFound, .invalidEncoding)

---

## 12. GnuPGInteropTests.swift
**File**: `/Tests/ServiceTests/GnuPGInteropTests.swift`
**Tests**: 8 tests
**Approach**: Pre-generated GnuPG fixture files (Approach A from TESTING.md §7)

### Test Categories

#### C3.1 Import GnuPG Public Key (1 test)
- `test_c3_1_importGnuPGPublicKey_armored_parsesCorrectly()` - GnuPG v4 key → Profile A detection

#### C3.4 Decrypt GnuPG Encrypted Messages (2 tests)
- `test_c3_4_decryptGnuPGMessage_armored_matchesPlaintext()` - Armored .asc
- `test_c3_4_decryptGnuPGMessage_binary_matchesPlaintext()` - Binary .gpg

#### C3.5 Verify GnuPG Signatures (3 tests)
- `test_c3_5_verifyGnuPGCleartextSignature_returnsValid()`
- `test_c3_5_verifyGnuPGDetachedSignature_armored_returnsValid()` - .asc signature
- `test_c3_5_verifyGnuPGDetachedSignature_binary_returnsValid()` - .sig signature

#### C3.6 Tamper Detection (2 tests)
- `test_c3_6_tamperedGnuPGCiphertext_throwsIntegrityError()` - GnuPG ciphertext tampered
- `test_c3_6_tamperedSequoiaCiphertext_forGnuPGKey_throwsIntegrityError()` - Sequoia→GnuPG tamper

#### C3.7 Full Round-Trip (1 test)
- `test_c3_7_fullRoundtrip_encryptToGnuPGKey_thenDecrypt()` - Sequoia encrypt → GnuPG key → Sequoia decrypt

#### C2A.9 Compressed Message (1 test)
- `test_c2a_9_decryptDeflateCompressedMessage_matchesPlaintext()` - DEFLATE compression

### Coverage Summary
- **Profile A only**: GnuPG is v4 (Profile A) compatible
- **Fixtures**: Pre-generated by `pgp-mobile/tests/fixtures/generate_gpg_fixtures.sh`
- **Bidirectional**: GnuPG→Sequoia and Sequoia→GnuPG operations
- **Formats**: Armored and binary, cleartext and detached signatures
- **Compression**: DEFLATE-compressed message decryption

---

## 13. StreamingServiceTests.swift
**File**: `/Tests/ServiceTests/StreamingServiceTests.swift`
**Tests**: 6+ tests

### Test Categories

#### Encrypt/Decrypt Round-Trip: Profile A (1 test)
- `test_encryptFileStreaming_profileA_roundTrip()` - File streaming encrypt/decrypt

#### Encrypt/Decrypt Round-Trip: Profile B (1 test)
- `test_encryptFileStreaming_profileB_roundTrip()`

#### Sign/Verify Round-Trip: Profile A (1 test)
- `test_signDetachedStreaming_profileA_roundTrip()`

#### Sign/Verify Round-Trip: Profile B (1 test)
- `test_signDetachedStreaming_profileB_roundTrip()`

#### Cancellation (1 test)
- `test_encryptFileStreaming_cancellation_throwsOperationCancelled()` - Progress reporter cancellation

#### Insufficient Disk Space (1 test)
- `test_encryptFileStreaming_insufficientDiskSpace_throws()` - Mock disk space validation

#### Tamper Detection (1 test)
- `test_decryptFileStreaming_tamperedFile_throwsError()` - 1-bit flip file tamper

### Coverage Summary
- **Both profiles**: A and B file streaming tested
- **Round-trip**: Full encrypt/decrypt/sign/verify via file streaming
- **Cancellation**: Progress reporter cancellation support
- **Disk space**: Validation before streaming operations
- **Tamper detection**: Integrity checks on encrypted files

---

## Test Coverage Summary Table

| Category | Profile A | Profile B | Both | Test Count |
|----------|-----------|-----------|------|-----------|
| Key Generation | ✅ | ✅ | All ops | 4 |
| Encryption | ✅ | ✅ | 30+ |
| Decryption | ✅ | ✅ | 20+ |
| Signing/Verification | ✅ | ✅ | 16 |
| File Streaming | ✅ | ✅ | 6+ |
| Argon2id Memory Guard | N/A | ✅ | 9 |
| GnuPG Interop | ✅ | N/A | 8 |
| FFI/Concurrency | ✅ | ✅ | 42 |
| Error Mapping | ✅ | ✅ | 14+ |
| Models/Contact | ✅ | ✅ | 18+ |
| QR/URL Parsing | ✅ | ✅ | 17 |
| **TOTAL** | **~100** | **~90** | **170+** |

---

## Key Gaps in Test Coverage

### Identified Gaps:

1. **DeviceSecurityTests.swift**: Not fully read (guard-skipped on simulator). Likely covers:
   - Secure Enclave wrapping/unwrapping
   - Biometric authentication modes (Standard vs High Security)
   - Auth mode switching
   - Crash recovery for interrupted mode switch
   - MIE (Memory Integrity Enforcement) on A19 devices

2. **Password/Passphrase Tests**: Missing explicit tests for:
   - Passphrase validation length/strength
   - Passphrase mismatch during export

3. **Key Expiry Tests**: Limited coverage
   - Only 2 tests on key expiry behavior
   - Missing: Expired key import, modify expiry edge cases

4. **High Security Mode**: No tests visible for:
   - Biometrics unavailable blocking operations
   - Mode switch with no backup warning

5. **Streaming Cancellation**: Limited (only 1 cancellation test shown)

6. **macOS/iPad-specific**: No platform-specific tests visible (conditional compilation for clipboard, background tasks)

7. **Contact Update Workflow**: Limited testing of key update detection → confirmation flow

8. **File Type Handling**: No tests for:
   - .asc vs .gpg file import
   - .sig (detached signature) file handling
   - File picker integration

---

## Mock Infrastructure

**Mocks in use**:
- `MockSecureEnclave` - Software P-256 + AES-GCM (same algorithm, no hardware binding)
- `MockKeychain` - In-memory storage with save/load/delete tracking
- `MockAuthenticator` - Controlled biometric/passcode auth results
- `MockMemoryInfo` - Argon2id memory guard testing
- `MockDiskSpace` - Disk space validation testing
- `FileProgressReporter` - File streaming progress/cancellation

---

## Test Execution Requirements

**Test Plans**:
- `CypherAir-UnitTests.xctestplan` (Layers 2-3): Simulator, CI
- `CypherAir-DeviceTests.xctestplan` (Layer 4): Physical device only

**Commands**:
```bash
# Rust unit tests
cargo test --manifest-path pgp-mobile/Cargo.toml

# Swift unit + FFI (simulator)
xcodebuild test -scheme CypherAir -testPlan CypherAir-UnitTests \
    -destination 'platform=iOS Simulator,name=iPhone 17'

# Device security tests (physical device)
xcodebuild test -scheme CypherAir -testPlan CypherAir-DeviceTests \
    -destination 'platform=iOS,name=<DEVICE_NAME>'
```

---

## Notable Testing Patterns

1. **Two-Phase Decryption Boundary**: Critical security test validating Phase 1 does NOT trigger SE unwrap, Phase 2 does
2. **AEAD Hard-Fail**: Tamper detection tests confirm immediate failure on authentication tag mismatch
3. **Memory Zeroing**: Explicit tests for `Data.zeroize()` and `Array.zeroize()` on sensitive buffers
4. **Cross-Profile**: Mixed v4+v6 recipients produce SEIPDv1 (lowest common denominator)
5. **Fixture-based GnuPG**: Pre-generated files avoid GPL compliance issues with running gpg in CI
6. **Concurrent FFI**: 10+ concurrent encrypt/decrypt tasks verify thread safety across UniFFI boundary
7. **Mock-backed Services**: Allows deterministic testing without real Secure Enclave hardware

This is a comprehensive, well-organized test suite covering crypto, security boundaries, services, FFI integration, and platform-specific functionality.
