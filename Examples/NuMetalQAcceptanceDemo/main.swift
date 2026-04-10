import Foundation
import CryptoKit
import NuMetal_Q

@main
struct NuMetalQAcceptanceDemo {
    static func main() async throws {
        let signer = try makeSigningMaterial()
        let compiledShape = try makeCompiledShape(signer: signer)
        let clusterShape = try makeClusterCompiledShape(signer: signer)
        let metalContext = try MetalContext()

        let engine = try await NuMeQ()

        let profile = await engine.activeProfile
        let params = await engine.publicParams
        let scheduler = await engine.schedulerParams
        let certificate = await engine.generateCertificate()
        let compiledCertificate = try ProfileCertificate.decodeArtifactData(
            compiledShape.shapePack.profileCertificate
        )
        let challengeSetDescription = profile.challengeSet.map(String.init).joined(separator: ", ")

        print("NuMetalQ Acceptance Demo")
        print("========================")

        printSection("Profile")
        print("profile: \(profile.name)")
        print("security bits: \(profile.securityBits)")
        print("parameter pin: \(hexPrefix(compiledCertificate.parameterPin, count: 8))")
        print("challenge set: \(challengeSetDescription)")
        print("irreducibility proof: \(certificate.irreducibilityProof.verified)")
        print("derived params verify: \(params.verify())")
        print("scheduler: arity=\(scheduler.maxArity) queueDepth=\(scheduler.queueDepth) aggressiveSeal=\(scheduler.aggressiveSeal)")

        printSection("Shape Compiler")
        print("shape: \(compiledShape.shape.name)")
        print("shape digest: \(hexPrefix(compiledShape.shape.digest.bytes, count: 8))")
        print("lanes: \(compiledShape.shape.lanes.count)")
        print("commitment bits: \(compiledShape.shape.totalCommitmentBits)")
        print("shape pack signature bytes: \(compiledShape.shapePack.signature.count)")
        for config in compiledShape.shapePack.kernelConfigs {
            print(
                "kernel[\(config.gpuFamilyTag)]: tg=\(config.threadgroupSize) tiles=\(config.tilesPerThreadgroup) foldArity=\(config.foldArity)"
            )
        }

        printSection("Metal")
        print("device: \(metalContext.device.name)")
        print("gpu family: \(metalContext.gpuFamilyTag)")
        print("max threads per threadgroup: \(metalContext.maxThreadsPerThreadgroupWidth)")

        let superNeoReport = try await runSuperNeoFoldingDemo(metalContext: metalContext)
        printSection("SuperNeo Folding")
        print("stages exercised: PiCCS x2, PiRLC, PiDEC")
        print("PiDEC input: canonical bounded witness packet")
        print("PiCCS verified: \(superNeoReport.piCCSVerified)")
        print("PiCCS metal matches CPU: \(superNeoReport.piCCSMetalMatches)")
        print("PiCCS sum-check rounds: \(superNeoReport.sumcheckRounds)")
        print("PiRLC verified: \(superNeoReport.piRLCVerified)")
        print("PiRLC metal matches CPU: \(superNeoReport.piRLCMetalMatches)")
        print("ring challenge coeff[0]: \(superNeoReport.ringChallengeScalars)")
        print("cross-term commitments: \(superNeoReport.crossTermCommitmentCount)")
        print("PiDEC verified: \(superNeoReport.piDECVerified)")
        print("PiDEC metal matches CPU: \(superNeoReport.piDECMetalMatches)")
        print("decomposition limbs: \(superNeoReport.decompositionLimbCount)")
        print("warmed thread execution width: \(metalContext.threadExecutionWidth)")

        let localFlow = try await runSDKFlow(
            engine: engine,
            compiledShape: compiledShape,
            signer: signer
        )
        printSection("SDK Flow")
        print("seed handles: \(localFlow.seedCount)")
        print("logical statement count: \(localFlow.logicalStatementCount)")
        print("seal backend: \(localFlow.envelope.sealBackendID)")
        print("envelope signature valid: \(localFlow.signatureValid)")
        print("verify result: \(localFlow.verification.isValid)")
        print("resumed chain: \(localFlow.restored.chainID.uuidString)")
        print("sealed logical statements: \(localFlow.logicalStatementCount)")
        print("outer Spartan rounds: \(localFlow.sealProof.terminalProof.outerSumcheck.roundEvaluations.count)")
        print("PCS batch classes: \(localFlow.hachiBatchClassCount)")
        print("PCS openings: \(localFlow.hachiOpeningCount)")
        print("matrix commitments: \(localFlow.matrixCommitmentCount)")

        let clusterReport = try await runClusterDemo(
            engine: engine,
            compiledShape: compiledShape,
            clusterShape: clusterShape,
            signer: signer
        )
        printSection("Cluster")
        print("confined lane indices: \(clusterReport.confinedIndices)")
        print("delegated commitment differs from final: \(clusterReport.delegatedCommitmentChanged)")
        print("confined-handle eligibility: \(clusterReport.confinedEligibility)")
        print("session returned to paired: \(clusterReport.sessionReusable)")
        print("delegatable-handle eligibility: \(clusterReport.delegatableEligibility)")
        print("cluster seal verify result: \(clusterReport.clusterVerification.isValid)")

        let syncReport = try await runSyncDemo(
            envelope: localFlow.envelope,
            signer: signer
        )
        printSection("Sync")
        print("message id: \(syncReport.messageID.uuidString)")
        print("ciphertext bytes: \(syncReport.ciphertextBytes)")
        print("signature bytes: \(syncReport.signatureBytes)")
        print("attestation carried through sync: \(syncReport.attestationPresent)")
        print("opened envelope matches original: \(syncReport.envelopeRoundTrip)")

        printSection("Completed")
        print("acceptance demo succeeded across profile, compiler, metal, SuperNeo stages, SDK flow, cluster, and sync")
    }

    private static func runSuperNeoFoldingDemo(
        metalContext: MetalContext
    ) async throws -> SuperNeoStageReport {
        let relation = makeSuperNeoStageRelation()
        let key = AjtaiKey.expand(
            seed: NuProfile.canonical.paramSeed,
            slotCount: NuProfile.canonical.commitmentRank * NuProfile.canonical.ringDegree
        )
        let witnesses = [
            makeSuperNeoStageWitness(seed: 11),
            makeSuperNeoStageWitness(seed: 29),
        ]

        var piRLCInputs = [PiRLC.Input]()
        var piCCSVerified = true
        var piCCSMetalMatches = true
        var sumcheckRounds = 0

        for (index, witness) in witnesses.enumerated() {
            let piCCSInput = PiCCS.Input(
                relation: relation,
                publicInputs: [],
                witness: witness,
                relaxationFactor: .one
            )

            var cpuTranscript = NuTranscriptField(domain: "NuMetalQ.AcceptanceDemo.SuperNeo.PiCCS.\(index)")
            let cpuOutput = PiCCS.prove(input: piCCSInput, transcript: &cpuTranscript)

            var verifyTranscript = NuTranscriptField(domain: "NuMetalQ.AcceptanceDemo.SuperNeo.PiCCS.\(index)")
            piCCSVerified = piCCSVerified && PiCCS.verify(
                input: piCCSInput,
                output: cpuOutput,
                transcript: &verifyTranscript
            )

            var metalTranscript = NuTranscriptField(domain: "NuMetalQ.AcceptanceDemo.SuperNeo.PiCCS.\(index)")
            let metalOutput = try await PiCCS.proveMetal(
                input: piCCSInput,
                transcript: &metalTranscript,
                context: metalContext
            )
            piCCSMetalMatches = piCCSMetalMatches && metalOutput == cpuOutput
            sumcheckRounds = max(sumcheckRounds, cpuOutput.sumCheckProof.roundPolynomials.count)

            let ringWitness = [packFieldVectorToRing(witness)]
            let commitment = AjtaiCommitter.commit(key: key, witness: ringWitness)
            piRLCInputs.append(PiRLC.Input(
                commitment: commitment,
                witness: ringWitness,
                publicInputs: [],
                ccsEvaluations: cpuOutput.evaluations,
                relaxationFactor: .one,
                errorTerms: []
            ))
        }

        var cpuPiRLCTranscript = NuTranscriptField(domain: "NuMetalQ.AcceptanceDemo.SuperNeo.PiRLC")
        let cpuPiRLC = PiRLC.prove(
            inputs: piRLCInputs,
            key: key,
            transcript: &cpuPiRLCTranscript
        )

        var verifyPiRLCTranscript = NuTranscriptField(domain: "NuMetalQ.AcceptanceDemo.SuperNeo.PiRLC")
        let piRLCVerified = PiRLC.verify(
            inputs: piRLCInputs,
            output: cpuPiRLC,
            key: key,
            transcript: &verifyPiRLCTranscript
        )

        var metalPiRLCTranscript = NuTranscriptField(domain: "NuMetalQ.AcceptanceDemo.SuperNeo.PiRLC")
        let metalPiRLC = try await PiRLC.proveMetal(
            inputs: piRLCInputs,
            key: key,
            transcript: &metalPiRLCTranscript,
            context: metalContext
        )

        let boundedPiDECWitness = makeBoundedPiDECWitness()
        let piDECInput = PiDEC.Input(
            witness: boundedPiDECWitness,
            commitment: AjtaiCommitter.commit(key: key, witness: boundedPiDECWitness),
            key: key,
            decompBase: NuProfile.canonical.decompBase,
            decompLimbs: NuProfile.canonical.decompLimbs
        )

        var cpuPiDECTranscript = NuTranscriptField(domain: "NuMetalQ.AcceptanceDemo.SuperNeo.PiDEC")
        let cpuPiDEC = PiDEC.prove(
            input: piDECInput,
            transcript: &cpuPiDECTranscript
        )

        var verifyPiDECTranscript = NuTranscriptField(domain: "NuMetalQ.AcceptanceDemo.SuperNeo.PiDEC")
        let piDECVerified = PiDEC.verify(
            input: piDECInput,
            output: cpuPiDEC,
            transcript: &verifyPiDECTranscript
        )

        var metalPiDECTranscript = NuTranscriptField(domain: "NuMetalQ.AcceptanceDemo.SuperNeo.PiDEC")
        let metalPiDEC = try await PiDEC.proveMetal(
            input: piDECInput,
            transcript: &metalPiDECTranscript,
            context: metalContext
        )

        try require(piCCSVerified, "PiCCS verification failed")
        try require(piCCSMetalMatches, "PiCCS Metal path diverged from CPU")
        try require(piRLCVerified, "PiRLC verification failed")
        try require(metalPiRLC == cpuPiRLC, "PiRLC Metal path diverged from CPU")
        try require(piDECVerified, "PiDEC verification failed")
        try require(metalPiDEC == cpuPiDEC, "PiDEC Metal path diverged from CPU")

        return SuperNeoStageReport(
            piCCSVerified: piCCSVerified,
            piCCSMetalMatches: piCCSMetalMatches,
            sumcheckRounds: sumcheckRounds,
            piRLCVerified: piRLCVerified,
            piRLCMetalMatches: metalPiRLC == cpuPiRLC,
            ringChallengeScalars: cpuPiRLC.ringChallenges.map { $0.coeffs[0].v },
            crossTermCommitmentCount: cpuPiRLC.crossTermCommitments.count,
            piDECVerified: piDECVerified,
            piDECMetalMatches: metalPiDEC == cpuPiDEC,
            decompositionLimbCount: cpuPiDEC.limbCommitments.count
        )
    }

    private static func runSDKFlow(
        engine: NuMeQ,
        compiledShape: CompiledShape,
        signer: DemoSigningMaterial
    ) async throws -> SDKFlowReport {
        let context = await engine.createContext(
            compiledShape: compiledShape,
            policy: .standard,
            appID: "NuMetalQ.AcceptanceDemo.SDK",
            teamID: demoTeamID,
            attestationVerifier: demoAttestationVerifier
        )

        let seeds: [UInt64] = [11, 29, 47, 83]
        let handles = try await withThrowingTaskGroup(of: ProofHandle.self) { group in
            for (index, seed) in seeds.enumerated() {
                group.addTask {
                    try await context.seed(
                        witness: makeWitness(seed: seed),
                        publicInputs: [Fq(UInt64(index + 3)), Fq(UInt64(index + 5))]
                    )
                }
            }

            var results = [ProofHandle]()
            for try await handle in group {
                results.append(handle)
            }
            return results
        }

        let fusedPair = try await context.fuse(handles[0], handles[1])
        let fusedMany = try await context.fuseMany([fusedPair, handles[2], handles[3]])

        let sessionKey = makeSessionKey()
        let sealedExport = try await context.seal(
            fusedMany,
            sessionKey: sessionKey,
            signerKeyID: signer.signerKeyID,
            attestation: Data("demo-attestation".utf8),
            signEnvelope: signer.sign
        )

        let verification = try await engine.verify(
            envelope: sealedExport.proofEnvelope,
            compiledShape: compiledShape,
            verifySignature: signer.verifyEnvelope,
            expectedAppID: "NuMetalQ.AcceptanceDemo.SDK",
            expectedTeamID: demoTeamID,
            attestationVerifier: demoAttestationVerifier,
            requireAttestation: true
        )
        try require(verification.isValid, "SDK envelope verification failed")

        let signatureValid = try sealedExport.proofEnvelope.isSignatureValid(verify: signer.verifyEnvelope)
        try require(signatureValid, "Envelope signature check failed")

        let restored = try await context.resume(
            envelope: sealedExport.proofEnvelope,
            resumeArtifact: sealedExport.resumeArtifact,
            verifySignature: signer.verifyEnvelope,
            requireAttestation: true,
            sessionKey: sessionKey
        )
        let sealProof = try sealedExport.proofEnvelope.proof()

        let batchClasses = sealProof.terminalProof.pcsOpeningProof.classes
        let hachiOpenings = batchClasses.reduce(0) { partial, batchClass in
            partial + batchClass.openings.count
        }

        return SDKFlowReport(
            seedCount: handles.count,
            logicalStatementCount: handles.count,
            envelope: sealedExport.proofEnvelope,
            signatureValid: signatureValid,
            verification: verification,
            restored: restored,
            sealProof: sealProof,
            hachiBatchClassCount: batchClasses.count,
            hachiOpeningCount: hachiOpenings,
            matrixCommitmentCount: sealProof.terminalProof.matrixEvaluationCommitments.count
        )
    }

    private static func runClusterDemo(
        engine: NuMeQ,
        compiledShape: CompiledShape,
        clusterShape: CompiledShape,
        signer: DemoSigningMaterial
    ) async throws -> ClusterDemoReport {
        let principal = try await engine.startClusterAsPrincipal(
            fragmentSigner: signer.sign,
            peerVerifier: signer.verify,
            attestationVerifier: demoAttestationVerifier
        )
        let coProver = try await engine.startClusterAsCoProver(
            fragmentSigner: signer.sign,
            peerVerifier: signer.verify,
            attestationVerifier: demoAttestationVerifier
        )
        try await coProver.installWorkExecutor(await engine.clusterWorkExecutor())

        let principalID = await principal.deviceID
        let coProverID = await coProver.deviceID
        try await principal.pair(peerDeviceID: coProverID, sharedSecret: syncSharedSecret)
        try await coProver.pair(peerDeviceID: principalID, sharedSecret: syncSharedSecret)

        let attestation = Data("cluster-attestation".utf8)
        let confinedPolicy = NuPolicy(
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
        let confinedContext = await engine.createContext(
            compiledShape: clusterShape,
            policy: confinedPolicy,
            appID: "NuMetalQ.AcceptanceDemo.ClusterSeed",
            teamID: demoTeamID,
            attestationVerifier: demoAttestationVerifier
        )
        let clusterSeedReceipt = try await confinedContext.seedUsingCluster(
            witness: makeTwoLaneWitness(publicSeed: 13, secretSeed: 71),
            publicInputs: [Fq(3), Fq(5)],
            clusterSession: principal,
            attestation: attestation,
            dispatchFragment: { fragment in
                try await coProver.processFragment(fragment)
            }
        )

        let confinedEligibility = try await confinedContext.clusterEligibility(
            for: clusterSeedReceipt.handle
        )
        let sessionReusable: Bool
        switch await principal.state {
        case .paired:
            sessionReusable = true
        default:
            sessionReusable = false
        }

        let clusterSealContext = await engine.createContext(
            compiledShape: compiledShape,
            policy: .standard,
            appID: "NuMetalQ.AcceptanceDemo.ClusterSeal",
            teamID: demoTeamID,
            attestationVerifier: demoAttestationVerifier
        )
        let delegatableHandle = try await clusterSealContext.seed(
            witness: makeWitness(seed: 59),
            publicInputs: [Fq(7), Fq(11)]
        )
        let delegatableEligibility = try await clusterSealContext.clusterEligibility(
            for: delegatableHandle
        )

        let sessionKey = makeSessionKey()
        let clusterExport = try await clusterSealContext.sealUsingCluster(
            delegatableHandle,
            sessionKey: sessionKey,
            clusterSession: principal,
            attestation: attestation,
            signerKeyID: signer.signerKeyID,
            dispatchFragment: { fragment in
                try await coProver.processFragment(fragment)
            },
            signEnvelope: signer.sign
        )
        let clusterVerification = try await engine.verify(
            envelope: clusterExport.proofEnvelope,
            compiledShape: compiledShape,
            verifySignature: signer.verifyEnvelope,
            expectedAppID: "NuMetalQ.AcceptanceDemo.ClusterSeal",
            expectedTeamID: demoTeamID,
            attestationVerifier: demoAttestationVerifier,
            requireAttestation: true
        )
        try require(clusterVerification.isValid, "Cluster seal verification failed")

        return ClusterDemoReport(
            confinedIndices: clusterSeedReceipt.confinedIndices,
            delegatedCommitmentChanged: clusterSeedReceipt.delegatedCommitment != clusterSeedReceipt.finalCommitment,
            confinedEligibility: describe(clusterEligibility: confinedEligibility),
            sessionReusable: sessionReusable,
            delegatableEligibility: describe(clusterEligibility: delegatableEligibility),
            clusterVerification: clusterVerification
        )
    }

    private static func runSyncDemo(
        envelope: ProofEnvelope,
        signer: DemoSigningMaterial
    ) async throws -> SyncDemoReport {
        let senderID = UUID()
        let recipientID = UUID()
        let sender = try SyncChannel(
            localDeviceID: senderID,
            hpkeSharedSecret: syncSharedSecret,
            salt: syncSalt,
            info: syncInfo,
            attestationVerifier: demoAttestationVerifier
        )
        let recipient = try SyncChannel(
            localDeviceID: recipientID,
            hpkeSharedSecret: syncSharedSecret,
            salt: syncSalt,
            info: syncInfo,
            attestationVerifier: demoAttestationVerifier
        )

        let message = try await sender.seal(
            envelope: envelope,
            recipientID: recipientID,
            kemCiphertext: Data("demo-kem".utf8),
            sign: signer.sign
        )
        let opened = try await recipient.openEnvelope(
            message: message,
            verifySignature: signer.verify
        )

        let roundTrip = opened.serialize() == envelope.serialize()
        try require(roundTrip, "Sync round-trip changed the envelope")

        return SyncDemoReport(
            messageID: message.messageID,
            ciphertextBytes: message.ciphertext.count,
            signatureBytes: message.signature.count,
            attestationPresent: opened.attestation != nil,
            envelopeRoundTrip: roundTrip
        )
    }

    private static func makeCompiledShape(signer: DemoSigningMaterial) throws -> CompiledShape {
        let lane = LaneDescriptor(index: 0, name: "amounts", width: .u16, length: 64)
        let relation = CCSRelation(
            m: 1,
            n: 66,
            nPublic: 2,
            matrices: [
                SparseMatrix(rows: 1, cols: 66, rowPtr: [0, 0], colIdx: [], values: []),
            ],
            gates: [
                CCSGate(coefficient: .zero, matrixIndices: [0]),
            ]
        )

        return try makeCompiledShape(
            signer: signer,
            name: "AcceptanceDemo",
            relation: relation,
            lanes: [lane],
            publicHeaderSize: 16,
            targetGPUFamilies: ["acceptance-demo"]
        )
    }

    private static func makeClusterCompiledShape(signer: DemoSigningMaterial) throws -> CompiledShape {
        let publicLane = LaneDescriptor(index: 0, name: "publicLane", width: .u8, length: 4)
        let secretLane = LaneDescriptor(index: 1, name: "secretLane", width: .u16, length: 4)
        let relation = CCSRelation(
            m: 1,
            n: 10,
            nPublic: 2,
            matrices: [
                SparseMatrix(rows: 1, cols: 10, rowPtr: [0, 0], colIdx: [], values: []),
            ],
            gates: [
                CCSGate(coefficient: .zero, matrixIndices: [0]),
            ]
        )

        return try makeCompiledShape(
            signer: signer,
            name: "AcceptanceDemo.Cluster",
            relation: relation,
            lanes: [publicLane, secretLane],
            publicHeaderSize: 16,
            targetGPUFamilies: ["cluster-demo"]
        )
    }

    private static func makeCompiledShape(
        signer: DemoSigningMaterial,
        name: String,
        relation: CCSRelation,
        lanes: [LaneDescriptor],
        publicHeaderSize: Int,
        targetGPUFamilies: [String]
    ) throws -> CompiledShape {
        let compiler = ShapeCompiler(
            config: .init(
                signShapePack: signer.sign,
                targetGPUFamilies: targetGPUFamilies,
                defaultArity: 4
            )
        )
        let shapePack = try compiler.compile(
            name: name,
            relation: relation,
            lanes: lanes,
            publicHeaderByteCount: UInt32(clamping: publicHeaderSize)
        )
        let shape = Shape(
            digest: shapePack.shapeDigest,
            name: name,
            relation: relation,
            lanes: lanes,
            publicHeaderSize: publicHeaderSize,
            defaultArity: 4
        )
        return try CompiledShape(shape: shape, shapePack: shapePack, verifySignature: signer.verify)
    }

    private static func makeWitness(seed: UInt64) -> Witness {
        let lane = LaneDescriptor(index: 0, name: "amounts", width: .u16, length: 64)
        let values = (0..<64).map { offset in
            Fq((seed + UInt64(offset * 3)) & 0xFFFF)
        }
        return Witness(lanes: [WitnessLane(descriptor: lane, values: values)])
    }

    private static func makeTwoLaneWitness(publicSeed: UInt64, secretSeed: UInt64) -> Witness {
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

    private static func makeSuperNeoStageRelation() -> CCSRelation {
        let identity = SparseMatrix(
            rows: 4,
            cols: 4,
            rowPtr: [0, 1, 2, 3, 4],
            colIdx: [0, 1, 2, 3],
            values: [.one, .one, .one, .one]
        )
        return CCSRelation(
            m: 4,
            n: 4,
            nPublic: 0,
            matrices: [identity, identity],
            gates: [
                CCSGate(coefficient: .one, matrixIndices: [0]),
                CCSGate(coefficient: -Fq.one, matrixIndices: [1]),
            ]
        )
    }

    private static func makeSuperNeoStageWitness(seed: UInt64) -> [Fq] {
        (0..<4).map { offset in
            Fq(seed + UInt64(offset * 7) + 3)
        }
    }

    private static func makeBoundedPiDECWitness() -> [RingElement] {
        (0..<2).map { ringIndex in
            RingElement(coeffs: (0..<RingElement.degree).map { coeffIndex in
                Fq(UInt64((ringIndex * 17 + coeffIndex * 3) % 8))
            })
        }
    }

    private static func packFieldVectorToRing(_ values: [Fq]) -> RingElement {
        var padded = values
        if padded.count < RingElement.degree {
            padded.append(contentsOf: [Fq](repeating: .zero, count: RingElement.degree - padded.count))
        }
        return RingElement(coeffs: Array(padded.prefix(RingElement.degree)))
    }
}

private struct DemoSigningMaterial {
    let signerKeyID: Data
    let sign: PQSignClosure
    let verify: PQVerifyClosure
    let verifyEnvelope: PQKeyedVerifyClosure
}

private struct SuperNeoStageReport {
    let piCCSVerified: Bool
    let piCCSMetalMatches: Bool
    let sumcheckRounds: Int
    let piRLCVerified: Bool
    let piRLCMetalMatches: Bool
    let ringChallengeScalars: [UInt64]
    let crossTermCommitmentCount: Int
    let piDECVerified: Bool
    let piDECMetalMatches: Bool
    let decompositionLimbCount: Int
}

private struct SDKFlowReport {
    let seedCount: Int
    let logicalStatementCount: Int
    let envelope: ProofEnvelope
    let signatureValid: Bool
    let verification: VerificationResult
    let restored: ProofHandle
    let sealProof: PublicSealProof
    let hachiBatchClassCount: Int
    let hachiOpeningCount: Int
    let matrixCommitmentCount: Int
}

private struct ClusterDemoReport {
    let confinedIndices: [Int]
    let delegatedCommitmentChanged: Bool
    let confinedEligibility: String
    let sessionReusable: Bool
    let delegatableEligibility: String
    let clusterVerification: VerificationResult
}

private struct SyncDemoReport {
    let messageID: UUID
    let ciphertextBytes: Int
    let signatureBytes: Int
    let attestationPresent: Bool
    let envelopeRoundTrip: Bool
}

private extension NuMetalQAcceptanceDemo {
    static let demoTeamID = "NuMetalQ.AcceptanceDemo"
    static let syncSharedSecret = Data(repeating: 0x33, count: 32)
    static let syncSalt = Data("NuMetalQ.Sync.Salt".utf8)
    static let syncInfo = Data("NuMetalQ.Sync.Info".utf8)

    static func makeSessionKey() -> SymmetricKey {
        SymmetricKey(data: Data(repeating: 0xA5, count: 32))
    }

    static func makeSigningMaterial() throws -> DemoSigningMaterial {
        if #available(iOS 26.0, macOS 26.0, watchOS 26.0, tvOS 26.0, macCatalyst 26.0, visionOS 26.0, *) {
            let identity = try ApplePostQuantum.makeMLDSA87Identity()
            return DemoSigningMaterial(
                signerKeyID: identity.signerKeyID,
                sign: identity.sign,
                verify: identity.verify,
                verifyEnvelope: identity.verifyEnvelope
            )
        }

        let key = SymmetricKey(data: Data(repeating: 0x42, count: 32))
        let sign: PQSignClosure = { message in
            Data(HMAC<SHA256>.authenticationCode(for: message, using: key))
        }
        let verify: PQVerifyClosure = { message, signature in
            let expected = Data(HMAC<SHA256>.authenticationCode(for: message, using: key))
            return expected == signature
        }
        let signerKeyID = Data("demo-signer".utf8)
        let verifyEnvelope: PQKeyedVerifyClosure = { message, signature, candidateSignerKeyID in
            guard candidateSignerKeyID == signerKeyID else {
                return false
            }
            let expected = Data(HMAC<SHA256>.authenticationCode(for: message, using: key))
            return expected == signature
        }
        return DemoSigningMaterial(
            signerKeyID: signerKeyID,
            sign: sign,
            verify: verify,
            verifyEnvelope: verifyEnvelope
        )
    }

    static let demoAttestationVerifier: AttestationVerifier = { attestation, context in
        switch context.purpose {
        case .clusterDelegation, .clusterExecution:
            guard attestation == Data("cluster-attestation".utf8) else {
                return false
            }
            return context.sessionID != nil
                && context.shapeDigest != nil
                && context.payloadDigest.isEmpty == false
        case .envelopeExport, .envelopeVerification, .syncEnvelope:
            let accepted = [
                Data("demo-attestation".utf8),
                Data("cluster-attestation".utf8),
            ]
            guard accepted.contains(attestation) else {
                return false
            }
            return context.appID?.hasPrefix("NuMetalQ.AcceptanceDemo") == true
                && context.teamID == demoTeamID
                && context.shapeDigest != nil
                && context.signerKeyID?.isEmpty == false
                && context.payloadDigest.isEmpty == false
        }
    }
}

private func printSection(_ title: String) {
    print("")
    print(title)
    print(String(repeating: "-", count: title.count))
}

private func hexPrefix(_ bytes: [UInt8], count: Int) -> String {
    bytes.prefix(count).map { String(format: "%02x", $0) }.joined()
}

private func describe(clusterEligibility: ClusterExecutionEligibility) -> String {
    switch clusterEligibility {
    case .allowed:
        return "allowed"
    case .blocked(let witnessClass):
        return "blocked(\(witnessClass))"
    }
}

private func require(_ condition: @autoclosure () -> Bool, _ message: String) throws {
    guard condition() else {
        throw DemoError.checkFailed(message)
    }
}

private enum DemoError: Error {
    case checkFailed(String)
}
