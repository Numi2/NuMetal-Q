import Foundation
import XCTest
@testable import NuMetal_Q

final class ClusterWorkPacketTests: XCTestCase {
    func testHachiSealWorkPacketDeserializeRejectsInvalidMagic() throws {
        let packet = makeSealPacket()
        var encoded = packet.serialize()
        encoded[0] ^= 0x01

        XCTAssertThrowsError(try HachiClusterSealWorkPacket.deserialize(encoded))
    }

    func testFoldWorkPacketExecutesThroughClusterExecutor() async throws {
        let engine = try await AcceptanceSupport.makeEngine()
        let principal = await engine.startClusterAsPrincipal(
            fragmentSigner: AcceptanceSupport.signer,
            peerVerifier: AcceptanceSupport.verifier,
            attestationVerifier: nonEmptyAttestationVerifier
        )
        let coProver = await engine.startClusterAsCoProver(
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
        let principal = ClusterSession(
            role: .principal,
            fragmentSigner: AcceptanceSupport.signer,
            peerVerifier: AcceptanceSupport.verifier,
            attestationVerifier: nonEmptyAttestationVerifier
        )
        let coProver = ClusterSession(
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

    func testHachiSealWorkPacketExecutesThroughClusterExecutor() async throws {
        let principal = ClusterSession(
            role: .principal,
            fragmentSigner: AcceptanceSupport.signer,
            peerVerifier: AcceptanceSupport.verifier,
            attestationVerifier: nonEmptyAttestationVerifier
        )
        let coProver = ClusterSession(
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

        let packet = makeSealPacket()
        let decodedPacket = try HachiClusterSealWorkPacket.deserialize(packet.serialize())
        XCTAssertEqual(decodedPacket.sealBackendID, packet.sealBackendID)
        XCTAssertEqual(decodedPacket.sealParamDigest, packet.sealParamDigest)
        XCTAssertEqual(decodedPacket.scheduleDigest, packet.scheduleDigest)

        let fragment = try await principal.createSealFragment(
            shapeDigest: ShapeDigest(bytes: [UInt8](repeating: 5, count: 32)),
            vaultEncryptedWorkPackage: packet.serialize(),
            attestation: Data("cluster-attestation".utf8)
        )
        let result = try await coProver.processFragment(fragment)
        let returned = try await principal.receiveResult(result)
        let sealResult = try HachiClusterSealWorkResult.deserialize(returned)

        XCTAssertTrue(sealResult.isValid(for: packet))
        XCTAssertEqual(sealResult.statementDigest, Data(packet.statementDigest))
        XCTAssertEqual(sealResult.scheduleDigest, Data(packet.scheduleDigest))
        XCTAssertEqual(sealResult.witnessCommitmentRoot, Data(packet.witnessCommitmentRoot))
    }

    func testHachiSealWorkResultRejectsTamperedExecutionDigest() {
        let packet = makeSealPacket()
        let valid = packet.execute()
        var tamperedDigest = valid.executionDigest
        tamperedDigest[0] ^= 0x01

        let tampered = HachiClusterSealWorkResult(
            sealBackendID: valid.sealBackendID,
            sealParamDigest: valid.sealParamDigest,
            statementDigest: valid.statementDigest,
            scheduleDigest: valid.scheduleDigest,
            witnessCommitmentRoot: valid.witnessCommitmentRoot,
            executionDigest: tamperedDigest
        )

        XCTAssertFalse(tampered.isValid(for: packet))
    }

    private func makeSealPacket() -> HachiClusterSealWorkPacket {
        HachiClusterSealWorkPacket(
            sealBackendID: NuSealConstants.productionBackendID,
            sealParamDigest: [UInt8](repeating: 0x21, count: 32),
            statementDigest: [UInt8](repeating: 0x32, count: 32),
            scheduleDigest: [UInt8](repeating: 0x43, count: 32),
            witnessCommitmentRoot: [UInt8](repeating: 0x54, count: 32)
        )
    }
}

private let nonEmptyAttestationVerifier: AttestationVerifier = { attestation, _ in
    !attestation.isEmpty
}
