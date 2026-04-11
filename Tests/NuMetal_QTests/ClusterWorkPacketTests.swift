import Foundation
import XCTest
@testable import NuMetal_Q

final class ClusterWorkPacketTests: XCTestCase {
    func testHachiSealWorkPacketDeserializeRejectsInvalidPayload() throws {
        let encoded = Data("not-json".utf8)

        XCTAssertThrowsError(try HachiClusterSealWorkPacket.deserialize(encoded))
    }

    func testFoldWorkPacketExecutesThroughClusterExecutor() async throws {
        let engine = try await AcceptanceSupport.makeEngine()
        let principal = try await engine.startClusterAsPrincipal(
            fragmentSigner: AcceptanceSupport.signer,
            peerVerifier: AcceptanceSupport.verifier,
            attestationVerifier: nonEmptyAttestationVerifier
        )
        let coProver = try await engine.startClusterAsCoProver(
            fragmentSigner: AcceptanceSupport.signer,
            peerVerifier: AcceptanceSupport.verifier,
            attestationVerifier: nonEmptyAttestationVerifier
        )
        try await coProver.installWorkExecutor(await engine.clusterWorkExecutor())

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
            values: [Fq(99), Fq(100), Fq(101), Fq(102)]
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
        let stripped = policy.stripForDelegation(lanes: [publicLane, confinedLane])
        let packet = ClusterFoldWorkPacket(
            lanes: stripped.delegatable,
            keySeed: Array(0..<32),
            keySlotCount: 8
        )
        let decodedPacket = try ClusterFoldWorkPacket.deserialize(packet.serialize())
        XCTAssertEqual(decodedPacket.keySlotCount, packet.keySlotCount)
        XCTAssertEqual(decodedPacket.lanes.count, packet.lanes.count)

        let delegation = DelegationPayload(
            payload: packet.serialize(),
            laneClasses: [
                "publicLane": .public,
                "secretLane": .deviceConfined,
            ],
            confinedIndices: stripped.confinedIndices,
            attestation: Data("cluster-attestation".utf8)
        )
        let fragment = try await principal.createFoldFragment(
            shapeDigest: ShapeDigest(bytes: [UInt8](repeating: 7, count: 32)),
            delegation: delegation,
            foldArity: 2
        )
        let result = try await coProver.processFragment(fragment)
        let returned = try await principal.receiveResult(result)
        let foldResult = try ClusterFoldWorkResult.deserialize(returned)

        XCTAssertTrue(foldResult.isValid(for: packet))
        XCTAssertEqual(foldResult.packedWitness.count, 2)
        XCTAssertEqual(foldResult.laneCommitments.count, 2)
        XCTAssertEqual(
            Array(foldResult.packedWitness[0].coeffs.prefix(4)).map(\.v),
            [1, 2, 3, 4]
        )
        XCTAssertEqual(Array(foldResult.packedWitness[1].coeffs.prefix(4)).map(\.v), [0, 0, 0, 0])
    }

    func testDecomposeWorkPacketExecutesThroughClusterExecutor() async throws {
        let principal = try ClusterSession(
            role: .principal,
            fragmentSigner: AcceptanceSupport.signer,
            peerVerifier: AcceptanceSupport.verifier,
            attestationVerifier: nonEmptyAttestationVerifier
        )
        let coProver = try ClusterSession(
            role: .coProver,
            fragmentSigner: AcceptanceSupport.signer,
            peerVerifier: AcceptanceSupport.verifier,
            attestationVerifier: nonEmptyAttestationVerifier
        )
        try await coProver.installWorkExecutor(ClusterWorkExecutor.standard())

        let principalID = await principal.deviceID
        let coProverID = await coProver.deviceID
        try await principal.pair(peerDeviceID: coProverID, sharedSecret: AcceptanceSupport.sharedSecret)
        try await coProver.pair(peerDeviceID: principalID, sharedSecret: AcceptanceSupport.sharedSecret)

        let keySeed = (64..<96).map(UInt8.init)
        let key = AjtaiKey.expand(seed: keySeed, slotCount: 16)
        let input = AcceptanceSupport.samplePiDECInput(key: key)
        let packet = ClusterDecomposeWorkPacket(
            witness: input.witness,
            commitment: input.commitment,
            keySeed: keySeed,
            keySlotCount: key.slotCount,
            decompBase: input.decompBase,
            decompLimbs: input.decompLimbs
        )
        let decodedPacket = try ClusterDecomposeWorkPacket.deserialize(packet.serialize())
        XCTAssertEqual(decodedPacket.witness.count, packet.witness.count)
        XCTAssertEqual(decodedPacket.decompLimbs, packet.decompLimbs)

        let fragment = try await principal.createDecomposeFragment(
            shapeDigest: ShapeDigest(bytes: [UInt8](repeating: 9, count: 32)),
            workPackage: packet.serialize(),
            attestation: Data("cluster-attestation".utf8)
        )
        let result = try await coProver.processFragment(fragment)
        let returned = try await principal.receiveResult(result)
        let decomposeResult = try ClusterDecomposeWorkResult.deserialize(returned)

        XCTAssertTrue(decomposeResult.isValid(for: packet))
        XCTAssertEqual(decomposeResult.decomposedWitness.count, packet.witness.count)
        XCTAssertEqual(decomposeResult.limbCommitments.count, Int(packet.decompLimbs))
    }

    func testFoldWorkResultRejectsTamperedLaneCommitment() async throws {
        let lane = WitnessLane(
            descriptor: LaneDescriptor(index: 0, name: "lane", width: .u8, length: 4),
            values: [Fq(1), Fq(2), Fq(3), Fq(4)]
        )
        let packet = ClusterFoldWorkPacket(
            lanes: [lane],
            keySeed: Array(0..<32),
            keySlotCount: 4
        )
        let valid = try await packet.execute()
        let tamperedCommitment = ClusterLaneCommitment(
            laneName: valid.laneCommitments[0].laneName,
            slotOffset: valid.laneCommitments[0].slotOffset,
            slotCount: valid.laneCommitments[0].slotCount,
            commitment: AjtaiCommitment(value: valid.laneCommitments[0].commitment.value + RingElement(constant: .one))
        )
        let tampered = ClusterFoldWorkResult(
            packedWitness: valid.packedWitness,
            aggregatedCommitment: valid.aggregatedCommitment,
            laneCommitments: [tamperedCommitment]
        )

        XCTAssertFalse(tampered.isValid(for: packet))
    }

    func testDecomposeWorkResultRejectsTamperedReconstructedCommitment() async throws {
        let keySeed = (64..<96).map(UInt8.init)
        let key = AjtaiKey.expand(seed: keySeed, slotCount: 16)
        let input = AcceptanceSupport.samplePiDECInput(key: key)
        let packet = ClusterDecomposeWorkPacket(
            witness: input.witness,
            commitment: input.commitment,
            keySeed: keySeed,
            keySlotCount: key.slotCount,
            decompBase: input.decompBase,
            decompLimbs: input.decompLimbs
        )
        let valid = try await packet.execute()
        let tampered = ClusterDecomposeWorkResult(
            decomposedWitness: valid.decomposedWitness,
            limbCommitments: valid.limbCommitments,
            consistencyChallenge: valid.consistencyChallenge,
            reconstructedCommitment: AjtaiCommitment(value: valid.reconstructedCommitment.value + RingElement(constant: .one))
        )

        XCTAssertFalse(tampered.isValid(for: packet))
    }

    func testHachiSealCommitPacketExecutesThroughClusterExecutor() async throws {
        let (principal, coProver) = try await makePairedClusterSessions()
        let packet = makeSealCommitPacket()
        let decodedPacket = try HachiClusterSealWorkPacket.deserialize(try packet.serialize())
        XCTAssertEqual(decodedPacket, packet)

        let fragment = try await principal.createSealFragment(
            shapeDigest: ShapeDigest(bytes: [UInt8](repeating: 5, count: 32)),
            vaultEncryptedWorkPackage: try packet.serialize(),
            attestation: Data("cluster-attestation".utf8)
        )
        let result = try await coProver.processFragment(fragment)
        let returned = try await principal.receiveResult(result)
        let sealResult = try HachiClusterSealWorkResult.deserialize(returned)

        XCTAssertTrue(sealResult.isValid(for: packet))
        XCTAssertEqual(sealResult.operation, .commit)
        XCTAssertNotNil(sealResult.commitments)
        XCTAssertNil(sealResult.openings)
    }

    func testHachiSealOpenPacketExecutesThroughClusterExecutor() async throws {
        let (principal, coProver) = try await makePairedClusterSessions()
        let packet = makeSealOpenPacket()
        let decodedPacket = try HachiClusterSealWorkPacket.deserialize(try packet.serialize())
        XCTAssertEqual(decodedPacket, packet)

        let fragment = try await principal.createSealFragment(
            shapeDigest: ShapeDigest(bytes: [UInt8](repeating: 6, count: 32)),
            vaultEncryptedWorkPackage: try packet.serialize(),
            attestation: Data("cluster-attestation".utf8)
        )
        let result = try await coProver.processFragment(fragment)
        let returned = try await principal.receiveResult(result)
        let sealResult = try HachiClusterSealWorkResult.deserialize(returned)

        XCTAssertTrue(sealResult.isValid(for: packet))
        XCTAssertEqual(sealResult.operation, .open)
        XCTAssertNil(sealResult.commitments)
        XCTAssertNotNil(sealResult.openings)
    }

    func testHachiSealWorkPacketDoesNotSerializeBlindingShareFields() throws {
        let encoded = try makeSealOpenPacket().serialize()
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: encoded) as? [String: Any])

        XCTAssertNil(object["blindingWitnessPolynomial"])
        XCTAssertNil(object["blindingRowPolynomials"])
        XCTAssertNil(object["blindingQueries"])
        XCTAssertNil(object["blindingBatchSeedDigest"])
    }

    func testHachiSealWorkPacketRejectsLegacyBlindingShareFields() throws {
        var object = try XCTUnwrap(
            JSONSerialization.jsonObject(with: try makeSealOpenPacket().serialize()) as? [String: Any]
        )
        object["blindingQueries"] = []
        let legacy = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])

        XCTAssertThrowsError(try HachiClusterSealWorkPacket.deserialize(legacy))
    }

    func testClusterSealFlowDelegatesMaskedShareOnlyAndVerifies() async throws {
        let engine = try await AcceptanceSupport.makeEngine()
        let compiledShape = try AcceptanceSupport.makeCompiledShape(name: "ClusterSealSplitShare")
        let context = await engine.createContext(
            compiledShape: compiledShape,
            policy: .standard,
            appID: "NuMetalQ.Tests.ClusterSeal",
            teamID: "NuMetalQ",
            attestationVerifier: nonEmptyAttestationVerifier
        )
        let handle = try await context.seed(
            witness: AcceptanceSupport.makeWitness(seed: 101),
            publicInputs: [Fq(101), Fq(108)],
            publicHeader: AcceptanceSupport.packedPublicHeader([Fq(101), Fq(108)])
        )
        let principal = try await engine.startClusterAsPrincipal(
            fragmentSigner: AcceptanceSupport.signer,
            peerVerifier: AcceptanceSupport.verifier,
            attestationVerifier: nonEmptyAttestationVerifier
        )
        let coProver = try await engine.startClusterAsCoProver(
            fragmentSigner: AcceptanceSupport.signer,
            peerVerifier: AcceptanceSupport.verifier,
            attestationVerifier: nonEmptyAttestationVerifier
        )
        try await coProver.installWorkExecutor(await engine.clusterWorkExecutor())

        let principalID = await principal.deviceID
        let coProverID = await coProver.deviceID
        try await principal.pair(peerDeviceID: coProverID, sharedSecret: AcceptanceSupport.sharedSecret)
        try await coProver.pair(peerDeviceID: principalID, sharedSecret: AcceptanceSupport.sharedSecret)

        let export = try await context.sealUsingCluster(
            handle,
            sessionKey: AcceptanceSupport.makeSessionKey(),
            clusterSession: principal,
            attestation: Data("cluster-attestation".utf8),
            signerKeyID: Data("test-signer".utf8),
            dispatchFragment: { fragment in
                try await coProver.processFragment(fragment)
            },
            signEnvelope: AcceptanceSupport.signer
        )
        let verification = try await context.verify(
            envelope: export.proofEnvelope,
            verifySignature: AcceptanceSupport.verifier,
            expectedSignerKeyID: Data("test-signer".utf8),
            requireAttestation: true
        )

        XCTAssertTrue(verification.isValid)
    }

    func testHachiSealWorkResultRejectsTamperedCommitments() throws {
        let packet = makeSealCommitPacket()
        let valid = try packet.execute()
        guard let commitments = valid.commitments else {
            return XCTFail("Expected commit result")
        }

        let tampered = HachiClusterSealWorkResult(
            operation: .commit,
            commitments: HachiClusterSealCommitments(
                witnessCommitment: tampered(commitment: commitments.witnessCommitment),
                matrixEvaluationCommitments: commitments.matrixEvaluationCommitments
            ),
            openings: nil
        )

        XCTAssertFalse(tampered.isValid(for: packet))
    }

    func testClusterRejectsStaleFragmentTimestamps() async throws {
        let replayCacheDirectory = makeReplayCacheDirectory()
        let principal = try ClusterSession(
            role: .principal,
            fragmentSigner: AcceptanceSupport.signer,
            peerVerifier: AcceptanceSupport.verifier,
            attestationVerifier: nonEmptyAttestationVerifier,
            replayCacheDirectory: replayCacheDirectory
        )
        let coProver = try ClusterSession(
            role: .coProver,
            fragmentSigner: AcceptanceSupport.signer,
            peerVerifier: AcceptanceSupport.verifier,
            attestationVerifier: nonEmptyAttestationVerifier,
            replayCacheDirectory: replayCacheDirectory
        )

        let principalID = await principal.deviceID
        let coProverID = await coProver.deviceID
        try await principal.pair(peerDeviceID: coProverID, sharedSecret: AcceptanceSupport.sharedSecret)
        try await coProver.pair(peerDeviceID: principalID, sharedSecret: AcceptanceSupport.sharedSecret)

        let keySeed = (32..<64).map(UInt8.init)
        let key = AjtaiKey.expand(seed: keySeed, slotCount: 16)
        let input = AcceptanceSupport.samplePiDECInput(key: key)
        let packet = ClusterDecomposeWorkPacket(
            witness: input.witness,
            commitment: input.commitment,
            keySeed: keySeed,
            keySlotCount: key.slotCount,
            decompBase: input.decompBase,
            decompLimbs: input.decompLimbs
        )
        let fragment = try await principal.createDecomposeFragment(
            shapeDigest: ShapeDigest(bytes: [UInt8](repeating: 0xA1, count: 32)),
            workPackage: packet.serialize(),
            attestation: Data("cluster-attestation".utf8)
        )

        var stale = JobFragment(
            fragmentID: fragment.fragmentID,
            sessionID: fragment.sessionID,
            kind: fragment.kind,
            shapeDigest: fragment.shapeDigest,
            encryptedPayload: fragment.encryptedPayload,
            laneClasses: fragment.laneClasses,
            confinedIndices: fragment.confinedIndices,
            attestation: fragment.attestation,
            signature: nil,
            timestamp: Date(timeIntervalSinceNow: -(60 * 60 * 25))
        )
        stale.signature = try AcceptanceSupport.signer(stale.signingPayload())

        do {
            _ = try await coProver.processFragment(stale)
            XCTFail("Expected stale cluster fragment to be rejected")
        } catch let error as ClusterError {
            guard case .invalidTimestamp = error else {
                return XCTFail("Unexpected error: \(error)")
            }
        }
    }

    func testClusterRejectsReplayedFragmentAcrossSessionRestart() async throws {
        let replayCacheDirectory = makeReplayCacheDirectory()
        let principal = try ClusterSession(
            role: .principal,
            fragmentSigner: AcceptanceSupport.signer,
            peerVerifier: AcceptanceSupport.verifier,
            attestationVerifier: nonEmptyAttestationVerifier,
            replayCacheDirectory: replayCacheDirectory
        )
        let firstCoProver = try ClusterSession(
            role: .coProver,
            fragmentSigner: AcceptanceSupport.signer,
            peerVerifier: AcceptanceSupport.verifier,
            attestationVerifier: nonEmptyAttestationVerifier,
            replayCacheDirectory: replayCacheDirectory
        )
        try await firstCoProver.installWorkExecutor(ClusterWorkExecutor.standard())

        let principalID = await principal.deviceID
        let firstCoProverID = await firstCoProver.deviceID
        try await principal.pair(peerDeviceID: firstCoProverID, sharedSecret: AcceptanceSupport.sharedSecret)
        try await firstCoProver.pair(peerDeviceID: principalID, sharedSecret: AcceptanceSupport.sharedSecret)

        let keySeed = (96..<128).map(UInt8.init)
        let key = AjtaiKey.expand(seed: keySeed, slotCount: 16)
        let input = AcceptanceSupport.samplePiDECInput(key: key)
        let packet = ClusterDecomposeWorkPacket(
            witness: input.witness,
            commitment: input.commitment,
            keySeed: keySeed,
            keySlotCount: key.slotCount,
            decompBase: input.decompBase,
            decompLimbs: input.decompLimbs
        )
        let fragment = try await principal.createDecomposeFragment(
            shapeDigest: ShapeDigest(bytes: [UInt8](repeating: 0xB2, count: 32)),
            workPackage: packet.serialize(),
            attestation: Data("cluster-attestation".utf8)
        )

        _ = try await firstCoProver.processFragment(fragment)

        let restartedCoProver = try ClusterSession(
            role: .coProver,
            fragmentSigner: AcceptanceSupport.signer,
            peerVerifier: AcceptanceSupport.verifier,
            attestationVerifier: nonEmptyAttestationVerifier,
            replayCacheDirectory: replayCacheDirectory
        )
        try await restartedCoProver.pair(peerDeviceID: principalID, sharedSecret: AcceptanceSupport.sharedSecret)

        do {
            _ = try await restartedCoProver.processFragment(fragment)
            XCTFail("Expected replayed cluster fragment to be rejected after restart")
        } catch let error as ClusterError {
            guard case .replayedFragment = error else {
                return XCTFail("Unexpected error: \(error)")
            }
        }
    }

    func testClusterProcessFragmentAcceptsStrictStableDeviceAttestation() async throws {
        let principal = try ClusterSession(
            role: .principal,
            fragmentSigner: AcceptanceSupport.signer,
            peerVerifier: AcceptanceSupport.verifier,
            attestationVerifier: nonEmptyAttestationVerifier
        )
        let coProver = try ClusterSession(
            role: .coProver,
            fragmentSigner: AcceptanceSupport.signer,
            peerVerifier: AcceptanceSupport.verifier,
            attestationVerifier: AcceptanceSupport.attestationVerifier
        )
        try await coProver.installWorkExecutor(ClusterWorkExecutor.standard())

        let principalID = await principal.deviceID
        let coProverID = await coProver.deviceID
        try await principal.pair(peerDeviceID: coProverID, sharedSecret: AcceptanceSupport.sharedSecret)
        try await coProver.pair(peerDeviceID: principalID, sharedSecret: AcceptanceSupport.sharedSecret)

        let packet = ClusterDecomposeWorkPacket(
            witness: [RingElement.zero],
            commitment: AjtaiCommitment(value: .zero),
            keySeed: Array(0..<32),
            keySlotCount: 8,
            decompBase: 2,
            decompLimbs: 13
        )
        let fragment = try await principal.createDecomposeFragment(
            shapeDigest: ShapeDigest(bytes: [UInt8](repeating: 0xC3, count: 32)),
            workPackage: packet.serialize(),
            attestation: Data("placeholder".utf8)
        )
        let strictAttestation = try AcceptanceSupport.makeAttestation(
            context: AttestationContext(
                purpose: .clusterDelegation,
                localDeviceID: principalID,
                remoteDeviceID: coProverID,
                sessionID: fragment.sessionID,
                shapeDigest: fragment.shapeDigest,
                timestamp: fragment.timestamp,
                payloadDigest: NuSecurityDigest.sha256(fragment.attestationBindingPayload())
            )
        )
        var strictFragment = JobFragment(
            fragmentID: fragment.fragmentID,
            sessionID: fragment.sessionID,
            kind: fragment.kind,
            shapeDigest: fragment.shapeDigest,
            encryptedPayload: fragment.encryptedPayload,
            laneClasses: fragment.laneClasses,
            confinedIndices: fragment.confinedIndices,
            attestation: strictAttestation,
            signature: nil,
            timestamp: fragment.timestamp
        )
        strictFragment.signature = try AcceptanceSupport.signer(strictFragment.signingPayload())

        let result = try await coProver.processFragment(strictFragment)
        let returned = try await principal.receiveResult(result)
        let decoded = try ClusterDecomposeWorkResult.deserialize(returned)
        XCTAssertTrue(decoded.isValid(for: packet))
    }

    private func makePairedClusterSessions() async throws -> (principal: ClusterSession, coProver: ClusterSession) {
        let principal = try ClusterSession(
            role: .principal,
            fragmentSigner: AcceptanceSupport.signer,
            peerVerifier: AcceptanceSupport.verifier,
            attestationVerifier: nonEmptyAttestationVerifier
        )
        let coProver = try ClusterSession(
            role: .coProver,
            fragmentSigner: AcceptanceSupport.signer,
            peerVerifier: AcceptanceSupport.verifier,
            attestationVerifier: nonEmptyAttestationVerifier
        )
        try await coProver.installWorkExecutor(ClusterWorkExecutor.standard())

        let principalID = await principal.deviceID
        let coProverID = await coProver.deviceID
        try await principal.pair(peerDeviceID: coProverID, sharedSecret: AcceptanceSupport.sharedSecret)
        try await coProver.pair(peerDeviceID: principalID, sharedSecret: AcceptanceSupport.sharedSecret)
        return (principal, coProver)
    }

    private func makeSealCommitPacket() -> HachiClusterSealWorkPacket {
        HachiClusterSealWorkPacket(
            operation: .commit,
            maskedWitnessPolynomial: MultilinearPoly(
                numVars: 1,
                evals: [Fq(3), Fq(5)]
            ),
            maskedRowPolynomials: [
                MultilinearPoly(numVars: 1, evals: [Fq(7), Fq(11)])
            ]
        )
    }

    private func makeSealOpenPacket() -> HachiClusterSealWorkPacket {
        HachiClusterSealWorkPacket(
            operation: .open,
            maskedWitnessPolynomial: MultilinearPoly(
                numVars: 1,
                evals: [Fq(3), Fq(5)]
            ),
            maskedRowPolynomials: [
                MultilinearPoly(numVars: 1, evals: [Fq(7), Fq(11)])
            ],
            maskedQueries: [
                SpartanPCSQuery(oracle: .witness(), point: [Fq(29)], value: Fq(61)),
                SpartanPCSQuery(oracle: .matrixRow(0), point: [Fq(31)], value: Fq(131))
            ],
            pcsBatchSeedDigest: [UInt8](repeating: 0xAA, count: 32)
        )
    }

    private func tampered(commitment: HachiPCSCommitment) -> HachiPCSCommitment {
        var tableDigest = commitment.tableDigest
        if tableDigest.isEmpty {
            tableDigest = [0x01]
        } else {
            tableDigest[0] ^= 0x01
        }
        return HachiPCSCommitment(
            oracle: commitment.oracle,
            mode: commitment.mode,
            tableCommitment: commitment.tableCommitment,
            directPackedOuterCommitments: commitment.directPackedOuterCommitments,
            tableDigest: tableDigest,
            parameterDigest: commitment.parameterDigest,
            valueCount: commitment.valueCount,
            packedChunkCount: commitment.packedChunkCount,
            statementDigest: commitment.statementDigest
        )
    }

    private func makeReplayCacheDirectory() -> URL {
        FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
    }
}

private let nonEmptyAttestationVerifier: AttestationVerifier = { attestation, _ in
    !attestation.isEmpty
}
