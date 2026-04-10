import Foundation
import CryptoKit

// MARK: - Proof Context
// Scoped proving session for a single shape.
// resume() verifies an envelope and rebinds a fresh recursive state.

/// A scoped proving session bound to a specific CCS shape.
///
/// ProofContext provides the high-level API for creating and combining
/// proofs for one compiled shape.
///
/// All FoldState objects are managed internally and never exposed.
/// The export surface is a signed public ProofEnvelope plus an encrypted
/// ResumeArtifact for private state restoration.
public actor ProofContext {
    let compiledShape: CompiledShape
    let foldEngine: FoldEngine
    let sealBackend: any NuSealCompiler
    let vault: FoldVault
    let profile: NuProfile
    let policy: NuPolicy
    let appID: String
    let teamID: String
    let attestationVerifier: AttestationVerifier?

    /// Active fold states in this context (by chain ID).
    var activeStates: [UUID: FoldState] = [:]

    init(
        compiledShape: CompiledShape,
        foldEngine: FoldEngine,
        sealBackend: any NuSealCompiler,
        vault: FoldVault,
        profile: NuProfile,
        policy: NuPolicy,
        appID: String,
        teamID: String,
        attestationVerifier: AttestationVerifier? = nil
    ) {
        self.compiledShape = compiledShape
        self.foldEngine = foldEngine
        self.sealBackend = sealBackend
        self.vault = vault
        self.profile = profile
        self.policy = policy
        self.appID = appID
        self.teamID = teamID
        self.attestationVerifier = attestationVerifier
    }

    // MARK: - Seed

    /// Create a base-case proof from initial inputs (no prior proofs).
    ///
    /// This is the leaf of the proof DAG. The witness is consumed
    /// and never stored in cleartext.
    public func seed(
        witness: Witness,
        publicInputs: [Fq],
        publicHeader: Data
    ) async throws -> ProofHandle {
        try validateSeedInputs(witness: witness, publicInputs: publicInputs, publicHeader: publicHeader)
        let witnessClass = maxWitnessClass(for: witness)
        let state: FoldState
        do {
            state = try await foldEngine.seed(
                shape: compiledShape.shape,
                witness: witness,
                publicInputs: publicInputs,
                publicHeader: publicHeader,
                witnessClass: witnessClass
            )
        } catch FoldEngineError.witnessExceedsPiDECRepresentability(let maxMagnitude, let base, let limbs) {
            throw ProofContextError.witnessExceedsPiDECRepresentability(
                maxMagnitude: maxMagnitude,
                base: base,
                limbs: limbs
            )
        }
        activeStates[state.chainID] = state
        return ProofHandle(chainID: state.chainID, shapeDigest: compiledShape.shape.digest)
    }

    /// Create a base-case proof using a paired co-prover for sanitized witness
    /// packing and commitment work, while keeping device-confined lanes local.
    ///
    /// The co-prover only sees the policy-stripped witness packet. The principal
    /// verifies the returned packet result, re-injects the confined lanes locally,
    /// and materializes the final seed state without exporting raw `FoldState`.
    public func seedUsingCluster(
        witness: Witness,
        publicInputs: [Fq],
        publicHeader: Data,
        clusterSession: ClusterSession,
        attestation: Data? = nil,
        dispatchFragment: @Sendable (JobFragment) async throws -> FragmentResult
    ) async throws -> ClusterSeedReceipt {
        try validateSeedInputs(witness: witness, publicInputs: publicInputs, publicHeader: publicHeader)
        let keyParameters = await foldEngine.clusterKeyParameters()
        let delegation: DelegationPayload
        do {
            delegation = try policy.authorizeDelegation(
                lanes: witness.lanes,
                attestation: attestation,
                encode: { lanes in
                    ClusterFoldWorkPacket(
                        lanes: lanes,
                        keySeed: keyParameters.seed,
                        keySlotCount: keyParameters.slotCount
                    ).serialize()
                }
            )
        } catch let violation as PolicyViolation {
            throw ProofContextError.policyViolation(violation)
        }

        let packet = try ClusterFoldWorkPacket.deserialize(delegation.payload)
        let fragment = try await clusterSession.createFoldFragment(
            shapeDigest: compiledShape.shape.digest,
            delegation: delegation,
            foldArity: Int(compiledShape.shape.defaultArity)
        )
        let response = try await clusterSession.roundTrip(fragment, dispatch: dispatchFragment)
        let remoteResult = try ClusterFoldWorkResult.deserialize(response)
        guard remoteResult.isValid(for: packet) else {
            throw ProofContextError.clusterResultInvalid
        }

        let materialized = try remoteResult.integratingConfinedLanes(
            from: witness,
            confinedIndices: delegation.confinedIndices,
            keySeed: keyParameters.seed,
            keySlotCount: keyParameters.slotCount
        )
        let witnessClass = maxWitnessClass(for: witness)
        let state: FoldState
        do {
            state = try await foldEngine.seedPrepared(
                shape: compiledShape.shape,
                commitment: materialized.commitment,
                packedWitness: materialized.packedWitness,
                publicInputs: publicInputs,
                publicHeader: publicHeader,
                witnessClass: witnessClass
            )
        } catch FoldEngineError.witnessExceedsPiDECRepresentability(let maxMagnitude, let base, let limbs) {
            throw ProofContextError.witnessExceedsPiDECRepresentability(
                maxMagnitude: maxMagnitude,
                base: base,
                limbs: limbs
            )
        }
        activeStates[state.chainID] = state

        return ClusterSeedReceipt(
            handle: ProofHandle(chainID: state.chainID, shapeDigest: compiledShape.shape.digest),
            delegatedCommitment: remoteResult.aggregatedCommitment,
            finalCommitment: materialized.commitment,
            confinedIndices: delegation.confinedIndices,
            laneCommitments: remoteResult.laneCommitments
        )
    }

    // MARK: - Binary Fuse

    /// Combine exactly two proofs into one ( binary fuse).
    ///
    /// Both input proofs must be for the same shape.
    /// The result is a new proof that attests to both inputs.
    public func fuse(_ a: ProofHandle, _ b: ProofHandle) async throws -> ProofHandle {
        guard let first = activeStates[a.chainID],
              let second = activeStates[b.chainID] else {
            throw ProofContextError.handleNotFound
        }
        let fused = try await combineAggregateStates([first, second])
        activeStates[fused.chainID] = fused
        return ProofHandle(chainID: fused.chainID, shapeDigest: compiledShape.shape.digest)
    }

    /// Combine multiple proofs (k-ary fold, generalizes binary fuse).
    ///
    /// `fuseMany` is a runtime optimization only; the public semantics
    /// remain like binary fuse.
    public func fuseMany(_ handles: [ProofHandle]) async throws -> ProofHandle {
        guard handles.count >= 2 else { throw ProofContextError.insufficientInputs }
        let states = try handles.map { handle in
            guard let state = activeStates[handle.chainID] else {
                throw ProofContextError.handleNotFound
            }
            return state
        }
        let fused = try await combineAggregateStates(states)
        activeStates[fused.chainID] = fused
        return ProofHandle(chainID: fused.chainID, shapeDigest: compiledShape.shape.digest)
    }

    // MARK: - Seal

    /// Compile the terminal decider for the final accumulator and export the
    /// public proof separately from the encrypted resume state.
    ///
    /// The proof semantic ends at `D_Nu(acc*) = 1`. The FoldState is consumed,
    /// and only the signed public ProofEnvelope plus encrypted ResumeArtifact
    /// are returned.
    public func seal(
        _ handle: ProofHandle,
        sessionKey: SymmetricKey,
        wrappedArtifactKeys: Data = Data(),
        signerKeyID: Data = Data(),
        attestation: Data? = nil,
        signEnvelope: @Sendable @escaping (Data) throws -> Data
    ) async throws -> SealedExport {
        guard let state = activeStates[handle.chainID] else {
            throw ProofContextError.handleNotFound
        }
        try await prepareStateForSealing(state)
        try requireExportEligibility(attestation: attestation)

        let sealProof = try await sealBackend.seal(
            state: state,
            shape: compiledShape.shape,
            publicHeader: state.publicHeader
        )

        let builder = EnvelopeBuilder(
            profileID: profile.profileID,
            appID: appID,
            teamID: teamID,
            privacyMode: .fullZK,
            signerKeyID: signerKeyID,
            sealParamDigest: Data(NuParams.derive(from: profile).seal.parameterDigest)
        )
        let envelope = try builder.build(
            proof: sealProof,
            sign: signEnvelope,
            attestation: attestation
        )
        let resumePayload = try makeResumePayload(for: state)
        let resumeArtifact = try ResumeArtifactBuilder.build(
            payload: resumePayload,
            proof: sealProof,
            sessionKey: sessionKey,
            wrappedArtifactKeys: wrappedArtifactKeys
        )
        try verifyEnvelopeAttestation(
            envelope,
            requireAttestation: envelope.attestation != nil,
            purpose: .envelopeVerification
        )

        activeStates.removeValue(forKey: handle.chainID)

        return SealedExport(proofEnvelope: envelope, resumeArtifact: resumeArtifact)
    }

    /// Compile the Hachi terminal decider for the final accumulator and wrap
    /// the proof body key for an Apple ML-KEM recipient.
#if NUMETALQ_APPLE_PQ
    @available(iOS 26.0, macOS 26.0, watchOS 26.0, tvOS 26.0, macCatalyst 26.0, visionOS 26.0, *)
    public func seal(
        _ handle: ProofHandle,
        recipientPublicKey: MLKEM1024.PublicKey,
        signerKeyID: Data = Data(),
        attestation: Data? = nil,
        signEnvelope: @Sendable @escaping (Data) throws -> Data
    ) async throws -> SealedExport {
        guard let state = activeStates[handle.chainID] else {
            throw ProofContextError.handleNotFound
        }
        try await prepareStateForSealing(state)
        try requireExportEligibility(attestation: attestation)

        let sealProof = try await sealBackend.seal(
            state: state,
            shape: compiledShape.shape,
            publicHeader: state.publicHeader
        )

        let builder = EnvelopeBuilder(
            profileID: profile.profileID,
            appID: appID,
            teamID: teamID,
            privacyMode: .fullZK,
            signerKeyID: signerKeyID,
            sealParamDigest: Data(NuParams.derive(from: profile).seal.parameterDigest)
        )
        let envelope = try builder.build(
            proof: sealProof,
            sign: signEnvelope,
            attestation: attestation
        )
        let resumePayload = try makeResumePayload(for: state)
        let resumeArtifact = try ResumeArtifactBuilder.build(
            payload: resumePayload,
            proof: sealProof,
            recipientPublicKey: recipientPublicKey
        )
        try verifyEnvelopeAttestation(
            envelope,
            requireAttestation: envelope.attestation != nil,
            purpose: .envelopeVerification
        )

        activeStates.removeValue(forKey: handle.chainID)
        return SealedExport(proofEnvelope: envelope, resumeArtifact: resumeArtifact)
    }
#endif

    /// Compress a delegatable proof into a succinct SealProof using a paired
    /// co-prover for Lightning PCS witness commitment/opening work.
    ///
    /// This fails closed when the handle's provenance includes non-delegatable
    /// witness material such as `deviceConfined` or `ephemeralDerived`.
    public func sealUsingCluster(
        _ handle: ProofHandle,
        sessionKey: SymmetricKey,
        clusterSession: ClusterSession,
        attestation: Data,
        wrappedArtifactKeys: Data = Data(),
        signerKeyID: Data = Data(),
        dispatchFragment: @Sendable (JobFragment) async throws -> FragmentResult,
        signEnvelope: @Sendable @escaping (Data) throws -> Data
    ) async throws -> SealedExport {
        guard let state = activeStates[handle.chainID] else {
            throw ProofContextError.handleNotFound
        }
        try await prepareStateForSealing(state)
        try requireExportEligibility(attestation: attestation)
        try requireClusterEligibility(for: state, attestation: attestation)

        let sealProof = try await sealBackend.sealUsingCluster(
            state: state,
            shape: compiledShape.shape,
            publicHeader: state.publicHeader,
            clusterSession: clusterSession,
            attestation: attestation,
            dispatchFragment: dispatchFragment
        )

        let builder = EnvelopeBuilder(
            profileID: profile.profileID,
            appID: appID,
            teamID: teamID,
            privacyMode: .fullZK,
            signerKeyID: signerKeyID,
            sealParamDigest: Data(NuParams.derive(from: profile).seal.parameterDigest)
        )
        let envelope = try builder.build(
            proof: sealProof,
            sign: signEnvelope,
            attestation: attestation
        )
        let resumePayload = try makeResumePayload(for: state)
        let resumeArtifact = try ResumeArtifactBuilder.build(
            payload: resumePayload,
            proof: sealProof,
            sessionKey: sessionKey,
            wrappedArtifactKeys: wrappedArtifactKeys
        )
        try verifyEnvelopeAttestation(
            envelope,
            requireAttestation: true,
            purpose: .envelopeVerification
        )

        activeStates.removeValue(forKey: handle.chainID)
        return SealedExport(proofEnvelope: envelope, resumeArtifact: resumeArtifact)
    }

    /// Cluster seal path that wraps the proof body key for an Apple ML-KEM recipient.
#if NUMETALQ_APPLE_PQ
    @available(iOS 26.0, macOS 26.0, watchOS 26.0, tvOS 26.0, macCatalyst 26.0, visionOS 26.0, *)
    public func sealUsingCluster(
        _ handle: ProofHandle,
        recipientPublicKey: MLKEM1024.PublicKey,
        clusterSession: ClusterSession,
        attestation: Data,
        signerKeyID: Data = Data(),
        dispatchFragment: @Sendable (JobFragment) async throws -> FragmentResult,
        signEnvelope: @Sendable @escaping (Data) throws -> Data
    ) async throws -> SealedExport {
        guard let state = activeStates[handle.chainID] else {
            throw ProofContextError.handleNotFound
        }
        try await prepareStateForSealing(state)
        try requireExportEligibility(attestation: attestation)
        try requireClusterEligibility(for: state, attestation: attestation)

        let sealProof = try await sealBackend.sealUsingCluster(
            state: state,
            shape: compiledShape.shape,
            publicHeader: state.publicHeader,
            clusterSession: clusterSession,
            attestation: attestation,
            dispatchFragment: dispatchFragment
        )

        let builder = EnvelopeBuilder(
            profileID: profile.profileID,
            appID: appID,
            teamID: teamID,
            privacyMode: .fullZK,
            signerKeyID: signerKeyID,
            sealParamDigest: Data(NuParams.derive(from: profile).seal.parameterDigest)
        )
        let envelope = try builder.build(
            proof: sealProof,
            sign: signEnvelope,
            attestation: attestation
        )
        let resumePayload = try makeResumePayload(for: state)
        let resumeArtifact = try ResumeArtifactBuilder.build(
            payload: resumePayload,
            proof: sealProof,
            recipientPublicKey: recipientPublicKey
        )
        try verifyEnvelopeAttestation(
            envelope,
            requireAttestation: true,
            purpose: .envelopeVerification
        )

        activeStates.removeValue(forKey: handle.chainID)
        return SealedExport(proofEnvelope: envelope, resumeArtifact: resumeArtifact)
    }
#endif

    private func makeResumePayload(for state: FoldState) throws -> ResumePayload {
        guard state.kind == .recursiveAccumulator,
              let accumulator = state.recursiveAccumulator else {
            throw ProofContextError.proofVerificationFailed
        }
        return ResumePayload(
            accumulatorArtifact: try accumulator.serialized(),
            normBudgetSnapshot: NormBudgetSnapshot(normBudget: state.normBudget),
            provenanceClass: state.maxWitnessClass,
            stageAudit: state.stageAudit
        )
    }

    private func prepareStateForSealing(_ state: FoldState) async throws {
        try requireAggregateState(state)
        try await ensureRecursiveStateIntegrity(state)
        try requirePersistenceEligibility(for: state)
    }

    // MARK: - Resume

    public func resume(
        envelope: ProofEnvelope,
        resumeArtifact: ResumeArtifact,
        verifySignature: PQKeyedVerifyClosure,
        requireAttestation: Bool = false,
        sessionKey: SymmetricKey
    ) async throws -> ProofHandle {
        let verification = try await verify(
            envelope: envelope,
            verifySignature: verifySignature,
            requireAttestation: requireAttestation
        )
        guard verification.isValid else {
            throw ProofContextError.proofVerificationFailed
        }

        let proof = try envelope.proof()
        let payload = try resumeArtifact.decryptPayload(using: sessionKey, proof: proof)
        let state = try await foldEngine.restoreSealedState(
            shape: compiledShape.shape,
            proof: proof,
            payload: payload
        )
        activeStates[state.chainID] = state
        return ProofHandle(chainID: state.chainID, shapeDigest: state.shapeDigest)
    }

    public func resume(
        envelope: ProofEnvelope,
        resumeArtifact: ResumeArtifact,
        verifySignature: @escaping PQVerifyClosure,
        expectedSignerKeyID: Data,
        requireAttestation: Bool = false,
        sessionKey: SymmetricKey
    ) async throws -> ProofHandle {
        try await resume(
            envelope: envelope,
            resumeArtifact: resumeArtifact,
            verifySignature: keyedEnvelopeVerifier(
                expectedSignerKeyID: expectedSignerKeyID,
                verifySignature: verifySignature
            ),
            requireAttestation: requireAttestation,
            sessionKey: sessionKey
        )
    }

#if NUMETALQ_APPLE_PQ
    @available(iOS 26.0, macOS 26.0, watchOS 26.0, tvOS 26.0, macCatalyst 26.0, visionOS 26.0, *)
    public func resume(
        envelope: ProofEnvelope,
        resumeArtifact: ResumeArtifact,
        verifySignature: PQKeyedVerifyClosure,
        requireAttestation: Bool = false,
        artifactPrivateKey: MLKEM1024.PrivateKey
    ) async throws -> ProofHandle {
        try await resume(
            envelope: envelope,
            resumeArtifact: resumeArtifact,
            verifySignature: verifySignature,
            requireAttestation: requireAttestation,
            sessionKey: try resumeArtifact.unwrapArtifactKey(using: artifactPrivateKey)
        )
    }

    @available(iOS 26.0, macOS 26.0, watchOS 26.0, tvOS 26.0, macCatalyst 26.0, visionOS 26.0, *)
    public func resume(
        envelope: ProofEnvelope,
        resumeArtifact: ResumeArtifact,
        verifySignature: PQKeyedVerifyClosure,
        requireAttestation: Bool = false,
        artifactPrivateKey: SecureEnclave.MLKEM1024.PrivateKey
    ) async throws -> ProofHandle {
        try await resume(
            envelope: envelope,
            resumeArtifact: resumeArtifact,
            verifySignature: verifySignature,
            requireAttestation: requireAttestation,
            sessionKey: try resumeArtifact.unwrapArtifactKey(using: artifactPrivateKey)
        )
    }
#endif

}
