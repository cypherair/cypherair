import XCTest
@testable import CypherAir

extension FFIIntegrationTests {
    // MARK: - Concurrent Encrypt (Thread Safety)

    /// 10 concurrent encryption tasks must all succeed.
    func test_concurrentEncrypt_threadsafe() async throws {
        let key = try engine.generateKey(
            name: "Concurrent", email: nil, expirySeconds: nil, profile: .universal
        )

        try await withThrowingTaskGroup(of: Data.self) { group in
            for i in 0..<10 {
                group.addTask { [engine] in
                    guard let engine else { throw ConcurrentTestError.engineDeallocated }
                    let plaintext = Data("Message \(i) for concurrent test".utf8)
                    return try engine.encrypt(
                        plaintext: plaintext,
                        recipients: [key.publicKeyData],
                        signingKey: nil,
                        encryptToSelf: nil
                    )
                }
            }

            var results: [Data] = []
            for try await ciphertext in group {
                XCTAssertFalse(ciphertext.isEmpty)
                results.append(ciphertext)
            }

            XCTAssertEqual(results.count, 10, "All 10 concurrent encryptions must succeed")
        }
    }

    // MARK: - Concurrent Encrypt + Decrypt (Thread Safety)

    /// Mixed concurrent encrypt and decrypt operations.
    func test_concurrentEncryptDecrypt_threadsafe() async throws {
        let key = try engine.generateKey(
            name: "MixedConcurrent", email: nil, expirySeconds: nil, profile: .universal
        )

        // Pre-encrypt some messages for decryption tasks
        var preCiphertexts: [Data] = []
        for i in 0..<5 {
            let ct = try engine.encrypt(
                plaintext: Data("Pre-encrypted \(i)".utf8),
                recipients: [key.publicKeyData],
                signingKey: nil,
                encryptToSelf: nil
            )
            preCiphertexts.append(ct)
        }

        try await withThrowingTaskGroup(of: Bool.self) { group in
            // 5 encrypt tasks
            for i in 0..<5 {
                group.addTask { [engine] in
                    guard let engine else { throw ConcurrentTestError.engineDeallocated }
                    let plaintext = Data("Encrypt task \(i)".utf8)
                    let ct = try engine.encrypt(
                        plaintext: plaintext,
                        recipients: [key.publicKeyData],
                        signingKey: nil,
                        encryptToSelf: nil
                    )
                    return !ct.isEmpty
                }
            }

            // 5 decrypt tasks
            for i in 0..<5 {
                let ct = preCiphertexts[i]
                group.addTask { [engine] in
                    guard let engine else { throw ConcurrentTestError.engineDeallocated }
                    let result = try engine.decryptDetailed(
                        ciphertext: ct,
                        secretKeys: [key.certData],
                        verificationKeys: []
                    )
                    return !result.plaintext.isEmpty
                }
            }

            var successCount = 0
            for try await success in group {
                XCTAssertTrue(success)
                successCount += 1
            }

            XCTAssertEqual(successCount, 10, "All 10 concurrent operations must succeed")
        }
    }

    /// Concurrent operations with Modern High (AEAD).
    func test_concurrentEncryptDecrypt_modernHigh_threadsafe() async throws {
        let key = try engine.generateKey(
            name: "ConcurrentB", email: nil, expirySeconds: nil, profile: .advanced
        )

        let preCiphertext = try engine.encrypt(
            plaintext: Data("Modern High concurrent".utf8),
            recipients: [key.publicKeyData],
            signingKey: nil,
            encryptToSelf: nil
        )

        try await withThrowingTaskGroup(of: Bool.self) { group in
            // Mix encrypt and decrypt
            for i in 0..<10 {
                if i % 2 == 0 {
                    group.addTask { [engine] in
                        guard let engine else { throw ConcurrentTestError.engineDeallocated }
                        let ct = try engine.encrypt(
                            plaintext: Data("B-\(i)".utf8),
                            recipients: [key.publicKeyData],
                            signingKey: nil,
                            encryptToSelf: nil
                        )
                        return !ct.isEmpty
                    }
                } else {
                    group.addTask { [engine] in
                        guard let engine else { throw ConcurrentTestError.engineDeallocated }
                        let result = try engine.decryptDetailed(
                            ciphertext: preCiphertext,
                            secretKeys: [key.certData],
                            verificationKeys: []
                        )
                        return !result.plaintext.isEmpty
                    }
                }
            }

            var count = 0
            for try await success in group {
                XCTAssertTrue(success)
                count += 1
            }
            XCTAssertEqual(count, 10)
        }
    }
}

/// Error thrown when PgpEngine is unexpectedly nil in concurrent test closures.
private enum ConcurrentTestError: Error {
    case engineDeallocated
}
