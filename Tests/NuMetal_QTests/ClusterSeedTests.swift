import Foundation
import XCTest
@testable import NuMetal_Q

final class ClusterSeedTests: XCTestCase {
    func testClusterSeedReusesSessionAndFeedsNormalProofFlow() async throws {
        let engine = try await AcceptanceSupport.makeEngine()
        let compiledShape = try makeTwoLaneCompiledShape()
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
        let context = await engine.createContext(
            compiledShape: compiledShape,
            policy: policy,
            appID: "NuMetalQ.Tests.ClusterSeed",
            attestationVerifier: AcceptanceSupport.attestationVerifier
        )

        let principal = await engine.startClusterAsPrincipal(
            fragmentSigner: AcceptanceSupport.signer,
            peerVerifier: AcceptanceSupport.verifier,
            attestationVerifier: AcceptanceSupport.attestationVerifier
        )
        let coProver = await engine.startClusterAsCoProver(
            fragmentSigner: AcceptanceSupport.signer,
            peerVerifier: AcceptanceSupport.verifier,
            attestationVerifier: AcceptanceSupport.attestationVerifier
        )
        try await coProver.installWorkExecutor(await engine.clusterWorkExecutor())

        let principalID = await principal.deviceID
        let coProverID = await coProver.deviceID
        try await principal.pair(peerDeviceID: coProverID, sharedSecret: AcceptanceSupport.sharedSecret)
        try await coProver.pair(peerDeviceID: principalID, sharedSecret: AcceptanceSupport.sharedSecret)

        let attestation = Data("cluster-attestation".utf8)
        let publicInputs = [Fq(3), Fq(5)]

        let first = try await context.seedUsingCluster(
            witness: makeTwoLaneWitness(publicSeed: 11, secretSeed: 41),
            publicInputs: publicInputs,
            clusterSession: principal,
            attestation: attestation,
            dispatchFragment: { fragment in
                try await coProver.processFragment(fragment)
            }
        )
        XCTAssertEqual(first.confinedIndices, [1])
        XCTAssertNotEqual(first.delegatedCommitment, first.finalCommitment)

        let second = try await context.seedUsingCluster(
            witness: makeTwoLaneWitness(publicSeed: 17, secretSeed: 53),
            publicInputs: publicInputs,
            clusterSession: principal,
            attestation: attestation,
            dispatchFragment: { fragment in
                try await coProver.processFragment(fragment)
            }
        )
        XCTAssertEqual(second.confinedIndices, [1])

        let sessionState = await principal.state
        if case .paired = sessionState {
            // expected reusable steady state
        } else {
            XCTFail("Expected principal session to remain paired, got \(sessionState)")
        }

        let sessionKey = AcceptanceSupport.makeSessionKey()
        let sealedExport = try await context.seal(
            first.handle,
            sessionKey: sessionKey,
            signerKeyID: Data("cluster-seed-signer".utf8),
            attestation: attestation,
            signEnvelope: AcceptanceSupport.signer
        )
        let verification = try await engine.verify(
            envelope: sealedExport.proofEnvelope,
            compiledShape: compiledShape,
            verifySignature: AcceptanceSupport.verifier,
            attestationVerifier: AcceptanceSupport.attestationVerifier,
            sessionKey: sessionKey
        )

        XCTAssertTrue(verification.isValid)
        let restored = try await context.resume(
            envelope: sealedExport.proofEnvelope,
            resumeArtifact: sealedExport.resumeArtifact,
            verifySignature: AcceptanceSupport.verifier,
            sessionKey: sessionKey
        )
        XCTAssertEqual(restored.shapeDigest, compiledShape.shape.digest)
    }

    func testClusterSealUsesDelegatableHandle() async throws {
        let engine = try await AcceptanceSupport.makeEngine()
        let compiledShape = try AcceptanceSupport.makeCompiledShape(name: "ClusterSealShape")
        let context = await engine.createContext(
            compiledShape: compiledShape,
            policy: .standard,
            appID: "NuMetalQ.Tests.ClusterSeal",
            attestationVerifier: AcceptanceSupport.attestationVerifier
        )
        let (principal, coProver) = try await makeClusterPair(engine: engine)

        let publicInputs = [Fq(3), Fq(5)]
        let handle = try await context.seed(
            witness: AcceptanceSupport.makeWitness(seed: 29),
            publicInputs: publicInputs
        )

        let eligibility = try await context.clusterEligibility(for: handle)
        XCTAssertEqual(eligibility, ClusterExecutionEligibility.allowed)

        let sessionKey = AcceptanceSupport.makeSessionKey()
        let sealedExport = try await context.sealUsingCluster(
            handle,
            sessionKey: sessionKey,
            clusterSession: principal,
            attestation: Data("cluster-attestation".utf8),
            signerKeyID: Data("cluster-seal-signer".utf8),
            dispatchFragment: { fragment in
                try await coProver.processFragment(fragment)
            },
            signEnvelope: AcceptanceSupport.signer
        )

        let verification = try await engine.verify(
            envelope: sealedExport.proofEnvelope,
            compiledShape: compiledShape,
            verifySignature: AcceptanceSupport.verifier,
            attestationVerifier: AcceptanceSupport.attestationVerifier,
            sessionKey: sessionKey
        )
        XCTAssertTrue(verification.isValid)
    }

    func testClusterSealDispatchesRemoteSealFragments() async throws {
        let engine = try await AcceptanceSupport.makeEngine()
        let compiledShape = try AcceptanceSupport.makeCompiledShape(name: "ClusterSealDispatchShape")
        let context = await engine.createContext(
            compiledShape: compiledShape,
            policy: .standard,
            appID: "NuMetalQ.Tests.ClusterSealDispatch",
            attestationVerifier: AcceptanceSupport.attestationVerifier
        )
        let (principal, coProver) = try await makeClusterPair(engine: engine)

        let publicInputs = [Fq(2), Fq(3)]
        let handle = try await context.seed(
            witness: AcceptanceSupport.makeWitness(seed: 17),
            publicInputs: publicInputs
        )
        let recorder = FragmentRecorder()

        let sessionKey = AcceptanceSupport.makeSessionKey()
        let sealedExport = try await context.sealUsingCluster(
            handle,
            sessionKey: sessionKey,
            clusterSession: principal,
            attestation: Data("cluster-attestation".utf8),
            signerKeyID: Data("cluster-seal-dispatch-signer".utf8),
            dispatchFragment: { fragment in
                await recorder.record(fragment.kind)
                return try await coProver.processFragment(fragment)
            },
            signEnvelope: AcceptanceSupport.signer
        )

        let verification = try await engine.verify(
            envelope: sealedExport.proofEnvelope,
            compiledShape: compiledShape,
            verifySignature: AcceptanceSupport.verifier,
            attestationVerifier: AcceptanceSupport.attestationVerifier,
            sessionKey: sessionKey
        )
        XCTAssertTrue(verification.isValid)
        let sealCount = await recorder.sealCount()
        XCTAssertGreaterThan(sealCount, 0)
    }

    func testClusterSealAfterResumePreservesDelegatableProvenance() async throws {
        let engine = try await AcceptanceSupport.makeEngine()
        let compiledShape = try AcceptanceSupport.makeCompiledShape(name: "ClusterSealResumeShape")
        let context = await engine.createContext(
            compiledShape: compiledShape,
            policy: .standard,
            appID: "NuMetalQ.Tests.ClusterSealResume",
            attestationVerifier: AcceptanceSupport.attestationVerifier
        )
        let (principal, coProver) = try await makeClusterPair(engine: engine)

        let publicInputs = [Fq(7), Fq(11)]
        let handle = try await context.seed(
            witness: AcceptanceSupport.makeWitness(seed: 59),
            publicInputs: publicInputs
        )
        let sessionKey = AcceptanceSupport.makeSessionKey()
        let sealedExport = try await context.seal(
            handle,
            sessionKey: sessionKey,
            signerKeyID: Data("cluster-seal-resume-signer".utf8),
            attestation: Data("cluster-attestation".utf8),
            signEnvelope: AcceptanceSupport.signer
        )

        let resumedContext = await engine.createContext(
            compiledShape: compiledShape,
            policy: .standard,
            appID: "NuMetalQ.Tests.ClusterSealResume.Restored",
            attestationVerifier: AcceptanceSupport.attestationVerifier
        )
        let restored = try await resumedContext.resume(
            envelope: sealedExport.proofEnvelope,
            resumeArtifact: sealedExport.resumeArtifact,
            verifySignature: AcceptanceSupport.verifier,
            sessionKey: sessionKey
        )
        let restoredEligibility = try await resumedContext.clusterEligibility(for: restored)
        XCTAssertEqual(restoredEligibility, ClusterExecutionEligibility.allowed)

        let resealedExport = try await resumedContext.sealUsingCluster(
            restored,
            sessionKey: sessionKey,
            clusterSession: principal,
            attestation: Data("cluster-attestation".utf8),
            signerKeyID: Data("cluster-seal-resume-signer".utf8),
            dispatchFragment: { fragment in
                try await coProver.processFragment(fragment)
            },
            signEnvelope: AcceptanceSupport.signer
        )

        let verification = try await engine.verify(
            envelope: resealedExport.proofEnvelope,
            compiledShape: compiledShape,
            verifySignature: AcceptanceSupport.verifier,
            attestationVerifier: AcceptanceSupport.attestationVerifier,
            sessionKey: sessionKey
        )
        XCTAssertTrue(verification.isValid)
    }

    func testClusterSealRejectsConfinedHandleButLocalSealStillWorks() async throws {
        let engine = try await AcceptanceSupport.makeEngine()
        let compiledShape = try makeTwoLaneCompiledShape()
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
        let context = await engine.createContext(
            compiledShape: compiledShape,
            policy: policy,
            appID: "NuMetalQ.Tests.ClusterSealDenied",
            attestationVerifier: AcceptanceSupport.attestationVerifier
        )
        let (principal, coProver) = try await makeClusterPair(engine: engine)

        let receipt = try await context.seedUsingCluster(
            witness: makeTwoLaneWitness(publicSeed: 13, secretSeed: 71),
            publicInputs: [Fq(3), Fq(5)],
            clusterSession: principal,
            attestation: Data("cluster-attestation".utf8),
            dispatchFragment: { fragment in
                try await coProver.processFragment(fragment)
            }
        )
        let sessionKey = AcceptanceSupport.makeSessionKey()
        let sealedExport = try await context.seal(
            receipt.handle,
            sessionKey: sessionKey,
            signerKeyID: Data("cluster-seal-signer".utf8),
            attestation: Data("cluster-attestation".utf8),
            signEnvelope: AcceptanceSupport.signer
        )

        let resumedContext = await engine.createContext(
            compiledShape: compiledShape,
            policy: policy,
            appID: "NuMetalQ.Tests.ClusterSealDenied.Restored",
            attestationVerifier: AcceptanceSupport.attestationVerifier
        )
        let restored = try await resumedContext.resume(
            envelope: sealedExport.proofEnvelope,
            resumeArtifact: sealedExport.resumeArtifact,
            verifySignature: AcceptanceSupport.verifier,
            sessionKey: sessionKey
        )
        let restoredEligibility = try await resumedContext.clusterEligibility(for: restored)
        XCTAssertEqual(
            restoredEligibility,
            ClusterExecutionEligibility.blocked(maxWitnessClass: WitnessClass.deviceConfined)
        )

        do {
            _ = try await resumedContext.sealUsingCluster(
                restored,
                sessionKey: AcceptanceSupport.makeSessionKey(),
                clusterSession: principal,
                attestation: Data("cluster-attestation".utf8),
                signerKeyID: Data("cluster-seal-signer".utf8),
                dispatchFragment: { fragment in
                    try await coProver.processFragment(fragment)
                },
                signEnvelope: AcceptanceSupport.signer
            )
            XCTFail("Expected cluster seal to reject confined provenance")
        } catch let error as ProofContextError {
            if case .clusterDelegationProhibited(.deviceConfined) = error {
                // expected
            } else {
                XCTFail("Unexpected proof context error: \(error)")
            }
        }

        let resealedExport = try await resumedContext.seal(
            restored,
            sessionKey: sessionKey,
            signerKeyID: Data("cluster-seal-signer".utf8),
            attestation: Data("cluster-attestation".utf8),
            signEnvelope: AcceptanceSupport.signer
        )
        let verification = try await engine.verify(
            envelope: resealedExport.proofEnvelope,
            compiledShape: compiledShape,
            verifySignature: AcceptanceSupport.verifier,
            attestationVerifier: AcceptanceSupport.attestationVerifier,
            sessionKey: sessionKey
        )
        XCTAssertTrue(verification.isValid)
    }

    private func makeClusterPair(engine: NuMeQ) async throws -> (ClusterSession, ClusterSession) {
        let principal = await engine.startClusterAsPrincipal(
            fragmentSigner: AcceptanceSupport.signer,
            peerVerifier: AcceptanceSupport.verifier,
            attestationVerifier: AcceptanceSupport.attestationVerifier
        )
        let coProver = await engine.startClusterAsCoProver(
            fragmentSigner: AcceptanceSupport.signer,
            peerVerifier: AcceptanceSupport.verifier,
            attestationVerifier: AcceptanceSupport.attestationVerifier
        )
        try await coProver.installWorkExecutor(await engine.clusterWorkExecutor())

        let principalID = await principal.deviceID
        let coProverID = await coProver.deviceID
        try await principal.pair(peerDeviceID: coProverID, sharedSecret: AcceptanceSupport.sharedSecret)
        try await coProver.pair(peerDeviceID: principalID, sharedSecret: AcceptanceSupport.sharedSecret)
        return (principal, coProver)
    }

    private actor FragmentRecorder {
        private var sealFragments = 0

        func record(_ kind: FragmentKind) {
            if case .seal = kind {
                sealFragments += 1
            }
        }

        func sealCount() -> Int {
            sealFragments
        }
    }

    private func makeTwoLaneCompiledShape() throws -> CompiledShape {
        let publicLane = LaneDescriptor(index: 0, name: "publicLane", width: .u8, length: 4)
        let secretLane = LaneDescriptor(index: 1, name: "secretLane", width: .u16, length: 4)
        let relation = CCSRelation(
            m: 1,
            n: 130,
            nPublic: 2,
            matrices: [
                SparseMatrix(rows: 1, cols: 130, rowPtr: [0, 0], colIdx: [], values: []),
            ],
            gates: [
                CCSGate(coefficient: .zero, matrixIndices: [0]),
            ]
        )

        return try AcceptanceSupport.makeCompiledShape(
            name: "ClusterSeedShape",
            relation: relation,
            lanes: [publicLane, secretLane],
            publicHeaderSize: 16,
            targetGPUFamilies: ["cluster-seed"]
        )
    }

    private func makeTwoLaneWitness(publicSeed: UInt64, secretSeed: UInt64) -> Witness {
        let publicLane = WitnessLane(
            descriptor: LaneDescriptor(index: 0, name: "publicLane", width: .u8, length: 4),
            values: (0..<4).map { Fq((publicSeed + UInt64($0 * 3)) & 0xFF) }
        )
        let secretLane = WitnessLane(
            descriptor: LaneDescriptor(index: 1, name: "secretLane", width: .u16, length: 4),
            values: (0..<4).map { Fq((secretSeed + UInt64($0 * 5)) & 0xFFFF) }
        )
        return Witness(lanes: [publicLane, secretLane])
    }
}
