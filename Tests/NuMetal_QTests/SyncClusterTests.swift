import Foundation
import XCTest
@testable import NuMetal_Q

final class SyncClusterTests: XCTestCase {
    func testSyncRejectsExpiredSignedMessage() async throws {
        let engine = try await AcceptanceSupport.makeEngine()
        let context = try await AcceptanceSupport.makeContext(engine: engine, name: "SyncExpiredMessage")
        let sessionKey = AcceptanceSupport.makeSessionKey()
        let publicInputs = [Fq(1), Fq(2)]

        let handle = try await context.seed(
            witness: AcceptanceSupport.makeWitness(seed: 71),
            publicInputs: publicInputs
        )
        let sealedExport = try await context.seal(
            handle,
            sessionKey: sessionKey,
            signerKeyID: Data("sync-signer".utf8),
            attestation: Data("sync-attestation".utf8),
            signEnvelope: AcceptanceSupport.signer
        )

        let senderID = UUID()
        let recipientID = UUID()
        let sender = try SyncChannel(
            localDeviceID: senderID,
            hpkeSharedSecret: AcceptanceSupport.sharedSecret,
            salt: AcceptanceSupport.syncSalt,
            info: AcceptanceSupport.syncInfo,
            attestationVerifier: AcceptanceSupport.attestationVerifier
        )
        let recipient = try SyncChannel(
            localDeviceID: recipientID,
            hpkeSharedSecret: AcceptanceSupport.sharedSecret,
            salt: AcceptanceSupport.syncSalt,
            info: AcceptanceSupport.syncInfo,
            attestationVerifier: AcceptanceSupport.attestationVerifier
        )

        let message = try await sender.seal(
            envelope: sealedExport.proofEnvelope,
            recipientID: recipientID,
            kemCiphertext: Data("kem".utf8),
            sign: AcceptanceSupport.signer
        )

        var stale = SyncMessage(
            messageID: message.messageID,
            senderDeviceID: message.senderDeviceID,
            recipientDeviceID: message.recipientDeviceID,
            encapsulatedKey: message.encapsulatedKey,
            ciphertext: message.ciphertext,
            nonce: message.nonce,
            tag: message.tag,
            signature: Data(),
            timestamp: message.timestamp.addingTimeInterval(-(60 * 60 * 25))
        )
        stale = SyncMessage(
            messageID: stale.messageID,
            senderDeviceID: stale.senderDeviceID,
            recipientDeviceID: stale.recipientDeviceID,
            encapsulatedKey: stale.encapsulatedKey,
            ciphertext: stale.ciphertext,
            nonce: stale.nonce,
            tag: stale.tag,
            signature: try AcceptanceSupport.signer(stale.signingPayload()),
            timestamp: stale.timestamp
        )

        do {
            _ = try await recipient.openEnvelope(
                message: stale,
                verifySignature: AcceptanceSupport.verifier
            )
            XCTFail("Expected stale sync message to be rejected")
        } catch let error as SyncError {
            XCTAssertEqual(error, .invalidTimestamp)
        }
    }

    func testSyncRejectsEmptyEncapsulatedKey() async throws {
        let engine = try await AcceptanceSupport.makeEngine()
        let context = try await AcceptanceSupport.makeContext(engine: engine, name: "SyncEmptyKEM")
        let sessionKey = AcceptanceSupport.makeSessionKey()
        let publicInputs = [Fq(1), Fq(2)]

        let handle = try await context.seed(
            witness: AcceptanceSupport.makeWitness(seed: 79),
            publicInputs: publicInputs
        )
        let sealedExport = try await context.seal(
            handle,
            sessionKey: sessionKey,
            signerKeyID: Data("sync-signer".utf8),
            attestation: Data("sync-attestation".utf8),
            signEnvelope: AcceptanceSupport.signer
        )

        let sender = try SyncChannel(
            localDeviceID: UUID(),
            hpkeSharedSecret: AcceptanceSupport.sharedSecret,
            salt: AcceptanceSupport.syncSalt,
            info: AcceptanceSupport.syncInfo,
            attestationVerifier: AcceptanceSupport.attestationVerifier
        )

        do {
            _ = try await sender.seal(
                envelope: sealedExport.proofEnvelope,
                recipientID: UUID(),
                kemCiphertext: Data(),
                sign: AcceptanceSupport.signer
            )
            XCTFail("Expected empty encapsulated key to be rejected")
        } catch let error as SyncError {
            XCTAssertEqual(error, .invalidEncapsulatedKey)
        }
    }

    func testSyncRejectsEmptySharedSecretConfiguration() async throws {
        let engine = try await AcceptanceSupport.makeEngine()
        let context = try await AcceptanceSupport.makeContext(engine: engine, name: "SyncEmptySecret")
        let sessionKey = AcceptanceSupport.makeSessionKey()
        let publicInputs = [Fq(1), Fq(2)]

        let handle = try await context.seed(
            witness: AcceptanceSupport.makeWitness(seed: 89),
            publicInputs: publicInputs
        )
        let sealedExport = try await context.seal(
            handle,
            sessionKey: sessionKey,
            signerKeyID: Data("sync-signer".utf8),
            attestation: Data("sync-attestation".utf8),
            signEnvelope: AcceptanceSupport.signer
        )

        let sender = try SyncChannel(
            localDeviceID: UUID(),
            hpkeSharedSecret: Data(),
            salt: AcceptanceSupport.syncSalt,
            info: AcceptanceSupport.syncInfo,
            attestationVerifier: AcceptanceSupport.attestationVerifier
        )

        do {
            _ = try await sender.seal(
                envelope: sealedExport.proofEnvelope,
                recipientID: UUID(),
                kemCiphertext: Data("kem".utf8),
                sign: AcceptanceSupport.signer
            )
            XCTFail("Expected empty shared secret to be rejected")
        } catch let error as SyncError {
            XCTAssertEqual(error, .invalidSharedSecret)
        }
    }

    func testSyncRejectsReplayedSignedMessage() async throws {
        let engine = try await AcceptanceSupport.makeEngine()
        let context = try await AcceptanceSupport.makeContext(engine: engine, name: "SyncReplayShape")
        let sessionKey = AcceptanceSupport.makeSessionKey()
        let publicInputs = [Fq(1), Fq(2)]

        let handle = try await context.seed(
            witness: AcceptanceSupport.makeWitness(seed: 61),
            publicInputs: publicInputs
        )
        let sealedExport = try await context.seal(
            handle,
            sessionKey: sessionKey,
            signerKeyID: Data("sync-signer".utf8),
            attestation: Data("sync-attestation".utf8),
            signEnvelope: AcceptanceSupport.signer
        )

        let senderID = UUID()
        let recipientID = UUID()
        let sender = try SyncChannel(
            localDeviceID: senderID,
            hpkeSharedSecret: AcceptanceSupport.sharedSecret,
            salt: AcceptanceSupport.syncSalt,
            info: AcceptanceSupport.syncInfo,
            attestationVerifier: AcceptanceSupport.attestationVerifier
        )
        let recipient = try SyncChannel(
            localDeviceID: recipientID,
            hpkeSharedSecret: AcceptanceSupport.sharedSecret,
            salt: AcceptanceSupport.syncSalt,
            info: AcceptanceSupport.syncInfo,
            attestationVerifier: AcceptanceSupport.attestationVerifier
        )

        let message = try await sender.seal(
            envelope: sealedExport.proofEnvelope,
            recipientID: recipientID,
            kemCiphertext: Data("kem".utf8),
            sign: AcceptanceSupport.signer
        )

        _ = try await recipient.openEnvelope(
            message: message,
            verifySignature: AcceptanceSupport.verifier
        )

        do {
            _ = try await recipient.openEnvelope(
                message: message,
                verifySignature: AcceptanceSupport.verifier
            )
            XCTFail("Expected replayed sync message to be rejected")
        } catch let error as SyncError {
            XCTAssertEqual(error, .replayedMessage)
        }
    }

    func testClusterRejectsNegativeFoldArityBeforeSigning() async throws {
        let principal = ClusterSession(
            role: .principal,
            fragmentSigner: AcceptanceSupport.signer,
            peerVerifier: AcceptanceSupport.verifier,
            attestationVerifier: AcceptanceSupport.attestationVerifier
        )
        let coProver = ClusterSession(
            role: .coProver,
            fragmentSigner: AcceptanceSupport.signer,
            peerVerifier: AcceptanceSupport.verifier,
            attestationVerifier: AcceptanceSupport.attestationVerifier
        )

        let principalID = await principal.deviceID
        let coProverID = await coProver.deviceID
        try await principal.pair(peerDeviceID: coProverID, sharedSecret: AcceptanceSupport.sharedSecret)
        try await coProver.pair(peerDeviceID: principalID, sharedSecret: AcceptanceSupport.sharedSecret)

        let lane = WitnessLane(
            descriptor: LaneDescriptor(index: 0, name: "lane", width: .u8, length: 2),
            values: [Fq(7), Fq(9)]
        )
        let delegation = try NuPolicy.standard.authorizeDelegation(
            lanes: [lane],
            attestation: Data("cluster-attestation".utf8),
            encode: AcceptanceSupport.serializeLanes
        )

        do {
            _ = try await principal.createFoldFragment(
                shapeDigest: ShapeDigest(bytes: [UInt8](repeating: 11, count: 32)),
                delegation: delegation,
                foldArity: -1
            )
            XCTFail("Expected negative fold arity to be rejected")
        } catch let error as ClusterError {
            if case .invalidFragment = error {
                return
            }
            XCTFail("Unexpected cluster error: \(error)")
        }
    }

    func testSyncRequiresAttestationAndRoundTripsEnvelope() async throws {
        let engine = try await AcceptanceSupport.makeEngine()
        let context = try await AcceptanceSupport.makeContext(engine: engine, name: "SyncShape")
        let sessionKey = AcceptanceSupport.makeSessionKey()
        let publicInputs = [Fq(1), Fq(2)]

        let handle = try await context.seed(
            witness: AcceptanceSupport.makeWitness(seed: 19),
            publicInputs: publicInputs
        )
        let sealedExport = try await context.seal(
            handle,
            sessionKey: sessionKey,
            signerKeyID: Data("sync-signer".utf8),
            attestation: Data("sync-attestation".utf8),
            signEnvelope: AcceptanceSupport.signer
        )

        let senderID = UUID()
        let recipientID = UUID()
        let sender = try SyncChannel(
            localDeviceID: senderID,
            hpkeSharedSecret: AcceptanceSupport.sharedSecret,
            salt: AcceptanceSupport.syncSalt,
            info: AcceptanceSupport.syncInfo,
            attestationVerifier: AcceptanceSupport.attestationVerifier
        )
        let recipient = try SyncChannel(
            localDeviceID: recipientID,
            hpkeSharedSecret: AcceptanceSupport.sharedSecret,
            salt: AcceptanceSupport.syncSalt,
            info: AcceptanceSupport.syncInfo,
            attestationVerifier: AcceptanceSupport.attestationVerifier
        )

        let message = try await sender.seal(
            envelope: sealedExport.proofEnvelope,
            recipientID: recipientID,
            kemCiphertext: Data("kem".utf8),
            sign: AcceptanceSupport.signer
        )
        let opened = try await recipient.openEnvelope(
            message: message,
            verifySignature: AcceptanceSupport.verifier
        )
        XCTAssertEqual(opened.profileID, sealedExport.proofEnvelope.profileID)
        XCTAssertEqual(opened.shapeDigest, sealedExport.proofEnvelope.shapeDigest)
        XCTAssertEqual(opened.attestation, sealedExport.proofEnvelope.attestation)

        let unattestedEnvelope = try AcceptanceSupport.resignEnvelope(
            sealedExport.proofEnvelope,
            attestation: .some(nil)
        )

        do {
            _ = try await sender.seal(
                envelope: unattestedEnvelope,
                recipientID: recipientID,
                kemCiphertext: Data("kem".utf8),
                sign: AcceptanceSupport.signer
            )
            XCTFail("Expected attestation requirement")
        } catch let error as SyncError {
            XCTAssertEqual(error, .attestationRequired)
        }
    }

    func testClusterDelegationStripsConfinedWitnessAndRequiresAttestation() async throws {
        let principal = ClusterSession(
            role: .principal,
            fragmentSigner: AcceptanceSupport.signer,
            peerVerifier: AcceptanceSupport.verifier,
            attestationVerifier: AcceptanceSupport.attestationVerifier
        )
        let coProver = ClusterSession(
            role: .coProver,
            fragmentSigner: AcceptanceSupport.signer,
            peerVerifier: AcceptanceSupport.verifier,
            attestationVerifier: AcceptanceSupport.attestationVerifier
        )
        try await coProver.installWorkExecutor(
            ClusterWorkExecutor(
                fold: { payload, context, arity in
                    XCTAssertEqual(arity, 2)
                    XCTAssertEqual(context.confinedIndices, [1])
                    XCTAssertEqual(context.laneClasses["secretLane"], .deviceConfined)
                    XCTAssertEqual(context.attestation, Data("cluster-attestation".utf8))
                    return payload
                }
            )
        )

        let principalID = await principal.deviceID
        let coProverID = await coProver.deviceID
        try await principal.pair(peerDeviceID: coProverID, sharedSecret: AcceptanceSupport.sharedSecret)
        try await coProver.pair(peerDeviceID: principalID, sharedSecret: AcceptanceSupport.sharedSecret)

        let publicLane = WitnessLane(
            descriptor: LaneDescriptor(index: 0, name: "publicLane", width: .u8, length: 4),
            values: [Fq(1), Fq(2), Fq(3), Fq(4)]
        )
        let confinedLane = WitnessLane(
            descriptor: LaneDescriptor(index: 1, name: "secretLane", width: .u16, length: 4),
            values: [Fq(9), Fq(10), Fq(11), Fq(12)]
        )
        let policy = NuPolicy(
            laneClasses: [
                "publicLane": .public,
                "secretLane": .deviceConfined,
            ],
            defaultClass: .syncableEncrypted,
            clusterDelegationAllowed: true,
            maxDelegatableClass: .syncableEncrypted,
            delegationRequiresAttestation: true,
            syncRequiresAttestation: true
        )

        let delegation = try policy.authorizeDelegation(
            lanes: [publicLane, confinedLane],
            attestation: Data("cluster-attestation".utf8),
            encode: AcceptanceSupport.serializeLanes
        )

        XCTAssertEqual(delegation.confinedIndices, [1])
        XCTAssertEqual(delegation.laneClasses["publicLane"], .public)
        XCTAssertEqual(delegation.laneClasses["secretLane"], .deviceConfined)

        let decoded = try AcceptanceSupport.deserializeLaneValues(delegation.payload)
        XCTAssertEqual(decoded[0], [1, 2, 3, 4])
        XCTAssertEqual(decoded[1], [0, 0, 0, 0])

        let fragment = try await principal.createFoldFragment(
            shapeDigest: ShapeDigest(bytes: [UInt8](repeating: 7, count: 32)),
            delegation: delegation,
            foldArity: 2
        )

        XCTAssertEqual(fragment.confinedIndices, [1])
        XCTAssertEqual(fragment.laneClasses["secretLane"], .deviceConfined)
        XCTAssertEqual(fragment.attestation, Data("cluster-attestation".utf8))

        let result = try await coProver.processFragment(fragment)
        let returned = try await principal.receiveResult(result)
        XCTAssertEqual(try AcceptanceSupport.deserializeLaneValues(returned)[1], [0, 0, 0, 0])

        XCTAssertThrowsError(
            try policy.authorizeDelegation(
                lanes: [publicLane, confinedLane],
                attestation: nil,
                encode: AcceptanceSupport.serializeLanes
            )
        )
    }

    func testClusterPairRejectsEmptySharedSecret() async throws {
        let principal = ClusterSession(
            role: .principal,
            fragmentSigner: AcceptanceSupport.signer,
            peerVerifier: AcceptanceSupport.verifier,
            attestationVerifier: AcceptanceSupport.attestationVerifier
        )

        do {
            try await principal.pair(peerDeviceID: UUID(), sharedSecret: Data())
            XCTFail("Expected empty shared secret to be rejected")
        } catch let error as ClusterError {
            if case .invalidSharedSecret = error {
                return
            }
            XCTFail("Unexpected cluster error: \(error)")
        }
    }

    func testClusterDuplicateFragmentReturnsCachedResultWithoutReexecution() async throws {
        actor InvocationCounter {
            private(set) var count = 0

            func increment() {
                count += 1
            }

            func value() -> Int {
                count
            }
        }

        let counter = InvocationCounter()
        let principal = ClusterSession(
            role: .principal,
            fragmentSigner: AcceptanceSupport.signer,
            peerVerifier: AcceptanceSupport.verifier,
            attestationVerifier: AcceptanceSupport.attestationVerifier
        )
        let coProver = ClusterSession(
            role: .coProver,
            fragmentSigner: AcceptanceSupport.signer,
            peerVerifier: AcceptanceSupport.verifier,
            attestationVerifier: AcceptanceSupport.attestationVerifier
        )
        try await coProver.installWorkExecutor(
            ClusterWorkExecutor(
                fold: { payload, _, _ in
                    await counter.increment()
                    return payload
                }
            )
        )

        let principalID = await principal.deviceID
        let coProverID = await coProver.deviceID
        try await principal.pair(peerDeviceID: coProverID, sharedSecret: AcceptanceSupport.sharedSecret)
        try await coProver.pair(peerDeviceID: principalID, sharedSecret: AcceptanceSupport.sharedSecret)

        let lane = WitnessLane(
            descriptor: LaneDescriptor(index: 0, name: "lane", width: .u8, length: 2),
            values: [Fq(4), Fq(8)]
        )
        let delegation = try NuPolicy.standard.authorizeDelegation(
            lanes: [lane],
            attestation: Data("cluster-attestation".utf8),
            encode: AcceptanceSupport.serializeLanes
        )
        let fragment = try await principal.createFoldFragment(
            shapeDigest: ShapeDigest(bytes: [UInt8](repeating: 13, count: 32)),
            delegation: delegation,
            foldArity: 2
        )

        let first = try await coProver.processFragment(fragment)
        let second = try await coProver.processFragment(fragment)

        let invocationCount = await counter.value()
        XCTAssertEqual(invocationCount, 1)
        XCTAssertEqual(first.fragmentID, second.fragmentID)
        XCTAssertEqual(first.sessionID, second.sessionID)
        XCTAssertEqual(first.encryptedResult, second.encryptedResult)
        XCTAssertEqual(first.signature, second.signature)
        XCTAssertEqual(first.timestamp, second.timestamp)
    }

    func testClusterProcessingFailsClosedWithoutExecutor() async throws {
        let principal = ClusterSession(
            role: .principal,
            fragmentSigner: AcceptanceSupport.signer,
            peerVerifier: AcceptanceSupport.verifier,
            attestationVerifier: AcceptanceSupport.attestationVerifier
        )
        let coProver = ClusterSession(
            role: .coProver,
            fragmentSigner: AcceptanceSupport.signer,
            peerVerifier: AcceptanceSupport.verifier,
            attestationVerifier: AcceptanceSupport.attestationVerifier
        )

        let principalID = await principal.deviceID
        let coProverID = await coProver.deviceID
        try await principal.pair(peerDeviceID: coProverID, sharedSecret: AcceptanceSupport.sharedSecret)
        try await coProver.pair(peerDeviceID: principalID, sharedSecret: AcceptanceSupport.sharedSecret)

        let lane = WitnessLane(
            descriptor: LaneDescriptor(index: 0, name: "lane", width: .u8, length: 2),
            values: [Fq(1), Fq(2)]
        )
        let delegation = try NuPolicy.standard.authorizeDelegation(
            lanes: [lane],
            attestation: Data("cluster-attestation".utf8),
            encode: AcceptanceSupport.serializeLanes
        )
        let fragment = try await principal.createFoldFragment(
            shapeDigest: ShapeDigest(bytes: [UInt8](repeating: 3, count: 32)),
            delegation: delegation,
            foldArity: 2
        )

        do {
            _ = try await coProver.processFragment(fragment)
            XCTFail("Expected missing executor to fail closed")
        } catch let error as ClusterError {
            if case .executorUnavailable = error {
                return
            }
            XCTFail("Unexpected cluster error: \(error)")
        }
    }

    func testClusterRejectsTamperedFragmentSignature() async throws {
        let principal = ClusterSession(
            role: .principal,
            fragmentSigner: AcceptanceSupport.signer,
            peerVerifier: AcceptanceSupport.verifier,
            attestationVerifier: AcceptanceSupport.attestationVerifier
        )
        let coProver = ClusterSession(
            role: .coProver,
            fragmentSigner: AcceptanceSupport.signer,
            peerVerifier: AcceptanceSupport.verifier,
            attestationVerifier: AcceptanceSupport.attestationVerifier
        )
        try await coProver.installWorkExecutor(
            ClusterWorkExecutor(
                fold: { payload, _, _ in payload }
            )
        )

        let principalID = await principal.deviceID
        let coProverID = await coProver.deviceID
        try await principal.pair(peerDeviceID: coProverID, sharedSecret: AcceptanceSupport.sharedSecret)
        try await coProver.pair(peerDeviceID: principalID, sharedSecret: AcceptanceSupport.sharedSecret)

        let lane = WitnessLane(
            descriptor: LaneDescriptor(index: 0, name: "lane", width: .u8, length: 2),
            values: [Fq(7), Fq(9)]
        )
        let delegation = try NuPolicy.standard.authorizeDelegation(
            lanes: [lane],
            attestation: Data("cluster-attestation".utf8),
            encode: AcceptanceSupport.serializeLanes
        )
        var fragment = try await principal.createFoldFragment(
            shapeDigest: ShapeDigest(bytes: [UInt8](repeating: 5, count: 32)),
            delegation: delegation,
            foldArity: 2
        )
        fragment.signature = Data("tampered".utf8)

        do {
            _ = try await coProver.processFragment(fragment)
            XCTFail("Expected tampered signature to fail")
        } catch let error as ClusterError {
            if case .signatureInvalid = error {
                return
            }
            XCTFail("Unexpected cluster error: \(error)")
        }
    }

    func testCoProverRejectsFragmentWithMismatchedRemoteSessionID() async throws {
        let principal = ClusterSession(
            role: .principal,
            fragmentSigner: AcceptanceSupport.signer,
            peerVerifier: AcceptanceSupport.verifier,
            attestationVerifier: AcceptanceSupport.attestationVerifier
        )
        let coProver = ClusterSession(
            role: .coProver,
            fragmentSigner: AcceptanceSupport.signer,
            peerVerifier: AcceptanceSupport.verifier,
            attestationVerifier: AcceptanceSupport.attestationVerifier
        )
        try await coProver.installWorkExecutor(
            ClusterWorkExecutor(
                fold: { payload, _, _ in payload }
            )
        )

        let principalID = await principal.deviceID
        let coProverID = await coProver.deviceID
        try await principal.pair(peerDeviceID: coProverID, sharedSecret: AcceptanceSupport.sharedSecret)
        try await coProver.pair(peerDeviceID: principalID, sharedSecret: AcceptanceSupport.sharedSecret)

        let lane = WitnessLane(
            descriptor: LaneDescriptor(index: 0, name: "lane", width: .u8, length: 2),
            values: [Fq(1), Fq(2)]
        )
        let delegation = try NuPolicy.standard.authorizeDelegation(
            lanes: [lane],
            attestation: Data("cluster-attestation".utf8),
            encode: AcceptanceSupport.serializeLanes
        )
        let fragment = try await principal.createFoldFragment(
            shapeDigest: ShapeDigest(bytes: [UInt8](repeating: 5, count: 32)),
            delegation: delegation,
            foldArity: 2
        )

        let result = try await coProver.processFragment(fragment)
        _ = try await principal.receiveResult(result)

        let mismatchedSessionID = UUID()
        var tampered = JobFragment(
            fragmentID: fragment.fragmentID,
            sessionID: mismatchedSessionID,
            kind: fragment.kind,
            shapeDigest: fragment.shapeDigest,
            encryptedPayload: fragment.encryptedPayload,
            laneClasses: fragment.laneClasses,
            confinedIndices: fragment.confinedIndices,
            attestation: fragment.attestation,
            timestamp: fragment.timestamp
        )
        tampered.signature = try AcceptanceSupport.signer(tampered.signingPayload())

        do {
            _ = try await coProver.processFragment(tampered)
            XCTFail("Expected co-prover to reject mismatched remote session ID")
        } catch let error as ClusterError {
            if case .sessionExpired = error {
                return
            }
            XCTFail("Unexpected cluster error: \(error)")
        }
    }
}
