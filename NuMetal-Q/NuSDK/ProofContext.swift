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
    private let compiledShape: CompiledShape
    private let foldEngine: FoldEngine
    private let sealBackend: any NuSealCompiler
    private let vault: FoldVault
    private let profile: NuProfile
    private let policy: NuPolicy
    private let appID: String
    private let teamID: String
    private let attestationVerifier: AttestationVerifier?

    /// Active fold states in this context (by chain ID).
    private var activeStates: [UUID: FoldState] = [:]

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
    public func seed(witness: Witness, publicInputs: [Fq]) async throws -> ProofHandle {
        try validateSeedInputs(witness: witness, publicInputs: publicInputs)
        let witnessClass = maxWitnessClass(for: witness)
        let state = try await foldEngine.seed(
            shape: compiledShape.shape,
            witness: witness,
            publicInputs: publicInputs,
            witnessClass: witnessClass
        )
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
        clusterSession: ClusterSession,
        attestation: Data,
        dispatchFragment: @Sendable (JobFragment) async throws -> FragmentResult
    ) async throws -> ClusterSeedReceipt {
        try validateSeedInputs(witness: witness, publicInputs: publicInputs)
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
        let state = try await foldEngine.seedPrepared(
            shape: compiledShape.shape,
            commitment: materialized.commitment,
            packedWitness: materialized.packedWitness,
            publicInputs: publicInputs,
            witnessClass: witnessClass
        )
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
        try requireAggregateState(state)
        try await ensureRecursiveStateIntegrity(state)

        let publicHeader = Data(state.publicInputs.flatMap { $0.toBytes() })

        let sealProof = try await sealBackend.seal(
            state: state,
            shape: compiledShape.shape,
            publicHeader: publicHeader
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
            purpose: .envelopeExport
        )

        activeStates.removeValue(forKey: handle.chainID)

        return SealedExport(proofEnvelope: envelope, resumeArtifact: resumeArtifact)
    }

    /// Compile the Hachi terminal decider for the final accumulator and wrap
    /// the proof body key for an Apple ML-KEM recipient.
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
        try requireAggregateState(state)
        try await ensureRecursiveStateIntegrity(state)

        let publicHeader = Data(state.publicInputs.flatMap { $0.toBytes() })
        let sealProof = try await sealBackend.seal(
            state: state,
            shape: compiledShape.shape,
            publicHeader: publicHeader
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
            purpose: .envelopeExport
        )

        activeStates.removeValue(forKey: handle.chainID)
        return SealedExport(proofEnvelope: envelope, resumeArtifact: resumeArtifact)
    }

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
        try requireAggregateState(state)
        try await ensureRecursiveStateIntegrity(state)
        try requireClusterEligibility(for: state, attestation: attestation)

        let publicHeader = Data(state.publicInputs.flatMap { $0.toBytes() })
        let sealProof = try await sealBackend.sealUsingCluster(
            state: state,
            shape: compiledShape.shape,
            publicHeader: publicHeader,
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
            purpose: .envelopeExport
        )

        activeStates.removeValue(forKey: handle.chainID)
        return SealedExport(proofEnvelope: envelope, resumeArtifact: resumeArtifact)
    }

    /// Cluster seal path that wraps the proof body key for an Apple ML-KEM recipient.
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
        try requireAggregateState(state)
        try await ensureRecursiveStateIntegrity(state)
        try requireClusterEligibility(for: state, attestation: attestation)

        let publicHeader = Data(state.publicInputs.flatMap { $0.toBytes() })
        let sealProof = try await sealBackend.sealUsingCluster(
            state: state,
            shape: compiledShape.shape,
            publicHeader: publicHeader,
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
            purpose: .envelopeExport
        )

        activeStates.removeValue(forKey: handle.chainID)
        return SealedExport(proofEnvelope: envelope, resumeArtifact: resumeArtifact)
    }

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
        verifySignature: PQVerifyClosure,
        requireAttestation: Bool = false,
        sessionKey: SymmetricKey
    ) async throws -> ProofHandle {
        try await resume(
            envelope: envelope,
            resumeArtifact: resumeArtifact,
            verifySignature: { message, signature, _ in
                try verifySignature(message, signature)
            },
            requireAttestation: requireAttestation,
            sessionKey: sessionKey
        )
    }

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

    // MARK: - Verify

    /// Verify a ProofEnvelope's signature and public terminal proof against the compiled shape.
    ///
    /// This is a static verification: it checks the envelope's cryptographic
    /// bindings without requiring any prover state.
    public func verify(
        envelope: ProofEnvelope,
        verifySignature: PQKeyedVerifyClosure,
        requireAttestation: Bool = false,
        sessionKey: SymmetricKey? = nil
    ) async throws -> VerificationResult {
        do {
            try envelope.validateCryptographicFormat()
        } catch let error as ProofEnvelopeValidationError {
            return VerificationResult(
                isValid: false,
                reason: verificationFailure(for: error)
            )
        }

        // 1. Signature check
        guard try envelope.isSignatureValid(verify: verifySignature) else {
            return VerificationResult(isValid: false, reason: .signatureInvalid)
        }

        // 2. Shape binding check
        guard envelope.shapeDigest == compiledShape.shape.digest else {
            return VerificationResult(isValid: false, reason: .shapeMismatch)
        }

        // 3. Profile binding check
        guard envelope.profileID == profile.profileID else {
            return VerificationResult(isValid: false, reason: .profileMismatch)
        }

        // 4. Backend binding check
        guard envelope.sealBackendID == sealBackend.backendID else {
            return VerificationResult(isValid: false, reason: .backendMismatch)
        }
        guard envelope.sealParamDigest == Data(NuParams.derive(from: profile).seal.parameterDigest) else {
            return VerificationResult(isValid: false, reason: .proofInvalid)
        }

        switch validateEnvelopeAttestation(
            envelope,
            requireAttestation: requireAttestation,
            purpose: .envelopeVerification
        ) {
        case .valid:
            break
        case .required:
            return VerificationResult(isValid: false, reason: .attestationRequired)
        case .verifierMissing:
            return VerificationResult(isValid: false, reason: .attestationVerifierMissing)
        case .invalid:
            return VerificationResult(isValid: false, reason: .attestationInvalid)
        }

        _ = sessionKey

        let proof: PublicSealProof
        do {
            proof = try envelope.proof()
        } catch {
            return VerificationResult(isValid: false, reason: .proofInvalid)
        }
        guard await sealBackend.verify(
            proof: proof,
            shape: compiledShape.shape,
            publicHeader: envelope.publicHeaderBytes
        ) else {
            return VerificationResult(isValid: false, reason: .proofInvalid)
        }

        return VerificationResult(isValid: true, reason: nil)
    }

    public func verify(
        envelope: ProofEnvelope,
        verifySignature: PQVerifyClosure,
        requireAttestation: Bool = false,
        sessionKey: SymmetricKey? = nil
    ) async throws -> VerificationResult {
        try await verify(
            envelope: envelope,
            verifySignature: { message, signature, _ in
                try verifySignature(message, signature)
            },
            requireAttestation: requireAttestation,
            sessionKey: sessionKey
        )
    }

    @available(iOS 26.0, macOS 26.0, watchOS 26.0, tvOS 26.0, macCatalyst 26.0, visionOS 26.0, *)
    public func verify(
        envelope: ProofEnvelope,
        verifySignature: PQKeyedVerifyClosure,
        requireAttestation: Bool = false,
        artifactPrivateKey: MLKEM1024.PrivateKey
    ) async throws -> VerificationResult {
        try await verify(
            envelope: envelope,
            verifySignature: verifySignature,
            requireAttestation: requireAttestation
        )
    }

    @available(iOS 26.0, macOS 26.0, watchOS 26.0, tvOS 26.0, macCatalyst 26.0, visionOS 26.0, *)
    public func verify(
        envelope: ProofEnvelope,
        verifySignature: PQKeyedVerifyClosure,
        requireAttestation: Bool = false,
        artifactPrivateKey: SecureEnclave.MLKEM1024.PrivateKey
    ) async throws -> VerificationResult {
        try await verify(
            envelope: envelope,
            verifySignature: verifySignature,
            requireAttestation: requireAttestation
        )
    }

    // MARK: - Policy

    /// The active witness-class policy for this context.
    public var activePolicy: NuPolicy { policy }

    /// Validate witness lanes against the active policy for a given operation.
    public func validateForDelegation(laneIDs: [String], attestation: Data? = nil) -> PolicyViolation? {
        policy.validateForDelegation(laneIDs: laneIDs, attestation: attestation)
    }

    /// Current cluster-delegation eligibility for a handle.
    public func clusterEligibility(for handle: ProofHandle) throws -> ClusterExecutionEligibility {
        guard let state = activeStates[handle.chainID] else {
            throw ProofContextError.handleNotFound
        }
        try requireAggregateState(state)
        return eligibility(for: state)
    }

    private func maxWitnessClass(for witness: Witness) -> WitnessClass {
        witness.lanes.reduce(.public) { current, lane in
            stricter(current, policy.classForLane(lane.descriptor.name))
        }
    }

    private func requireAggregateState(_ state: FoldState) throws {
        guard state.typedTrace == nil,
              state.blindingMask == .zero,
              state.statementCount > 0 else {
            throw ProofContextError.unsupportedStoredState
        }

        switch state.kind {
        case .aggregateStatements:
            return
        case .recursiveAccumulator:
            guard state.recursiveAccumulator != nil else {
                throw ProofContextError.unsupportedStoredState
            }
        case .typedTrace:
            throw ProofContextError.unsupportedStoredState
        }
    }

    private func validateSeedInputs(witness: Witness, publicInputs: [Fq]) throws {
        try witness.validateSemanticIntegrity()

        let expectedLanes = compiledShape.shape.lanes
        guard witness.lanes.count == expectedLanes.count else {
            throw ProofContextError.witnessShapeMismatch
        }
        for (actual, expected) in zip(witness.lanes, expectedLanes) {
            guard actual.descriptor == expected else {
                throw ProofContextError.witnessShapeMismatch
            }
        }

        let expectedWitnessCount = compiledShape.shape.relation.n - compiledShape.shape.relation.nPublic
        let packedWitnessCount =
            WitnessPacking.packWitnessToRings(lanes: witness.lanes).count * RingElement.degree
        guard packedWitnessCount == expectedWitnessCount else {
            throw ProofContextError.invalidWitnessElementCount(
                expected: expectedWitnessCount,
                actual: packedWitnessCount
            )
        }

        let expectedPublicCount = compiledShape.shape.relation.nPublic
        guard publicInputs.count == expectedPublicCount else {
            throw ProofContextError.invalidPublicInputCount(
                expected: expectedPublicCount,
                actual: publicInputs.count
            )
        }
    }

    private func decodePublicInputs(from publicHeader: Data) throws -> [Fq] {
        guard publicHeader.count == compiledShape.shape.publicHeaderSize,
              publicHeader.count.isMultiple(of: MemoryLayout<UInt64>.size) else {
            throw ProofContextError.invalidPublicInputCount(
                expected: compiledShape.shape.relation.nPublic,
                actual: publicHeader.count / MemoryLayout<UInt64>.size
            )
        }

        let publicInputs = stride(
            from: 0,
            to: publicHeader.count,
            by: MemoryLayout<UInt64>.size
        ).compactMap { offset -> Fq? in
            Fq.fromBytes(Array(publicHeader[offset..<offset + MemoryLayout<UInt64>.size]))
        }

        guard publicInputs.count == compiledShape.shape.relation.nPublic else {
            throw ProofContextError.invalidPublicInputCount(
                expected: compiledShape.shape.relation.nPublic,
                actual: publicInputs.count
            )
        }
        return publicInputs
    }

    private func requirePersistenceEligibility(for state: FoldState) throws {
        guard state.maxWitnessClass != .ephemeralDerived else {
            throw ProofContextError.policyViolation(
                PolicyViolation(
                    kind: .ephemeralCannotPersist,
                    laneID: nil,
                    message: "ephemeralDerived witness material cannot be persisted"
                )
            )
        }
    }

    private func verifyEnvelopeAttestation(
        _ envelope: ProofEnvelope,
        requireAttestation: Bool,
        purpose: AttestationPurpose
    ) throws {
        switch validateEnvelopeAttestation(
            envelope,
            requireAttestation: requireAttestation,
            purpose: purpose
        ) {
        case .valid:
            return
        case .required:
            throw ProofContextError.attestationValidation(.invalidAttestation)
        case .verifierMissing:
            throw ProofContextError.attestationValidation(.missingVerifier)
        case .invalid:
            throw ProofContextError.attestationValidation(.invalidAttestation)
        }
    }

    private func validateEnvelopeAttestation(
        _ envelope: ProofEnvelope,
        requireAttestation: Bool,
        purpose: AttestationPurpose
    ) -> EnvelopeAttestationValidation {
        guard let attestation = envelope.attestation, attestation.isEmpty == false else {
            return requireAttestation ? .required : .valid
        }
        guard let attestationVerifier else {
            return .verifierMissing
        }
        let context = AttestationContext(
            purpose: purpose,
            appID: envelope.appID,
            shapeDigest: envelope.shapeDigest,
            signerKeyID: envelope.signerKeyID,
            timestamp: envelope.timestamp,
            payloadDigest: NuSecurityDigest.sha256(envelope.attestationBindingPayload())
        )
        do {
            return try attestationVerifier(attestation, context) ? .valid : .invalid
        } catch {
            return .invalid
        }
    }

    private func combineAggregateStates(_ states: [FoldState]) async throws -> FoldState {
        guard states.isEmpty == false else {
            throw ProofContextError.insufficientInputs
        }
        try states.forEach(requireAggregateState)
        for state in states {
            try await ensureRecursiveStateIntegrity(state)
        }
        guard Set(states.map(\.shapeDigest)) == Set([compiledShape.shape.digest]) else {
            throw ProofContextError.shapeMismatch
        }
        do {
            return try await foldEngine.fold(
                states: states,
                relation: compiledShape.shape.relation
            )
        } catch FoldEngineError.witnessPackingExceedsKeySlots {
            throw ProofContextError.accumulatorTooLarge
        } catch FoldEngineError.invalidAggregateState,
                FoldEngineError.invalidRecursiveAccumulator,
                FoldEngineError.invalidPublicInputCount,
                FoldEngineError.recursiveStageVerificationFailed,
                FoldEngineError.shapeMismatch,
                FoldEngineError.unsupportedWitnessRepresentation {
            throw ProofContextError.unsupportedStoredState
        }
    }

    private func ensureRecursiveStateIntegrity(_ state: FoldState) async throws {
        guard state.kind == .recursiveAccumulator else {
            return
        }
        guard try await foldEngine.verifyRecursiveState(
            state: state,
            relation: compiledShape.shape.relation
        ) else {
            throw ProofContextError.unsupportedStoredState
        }
    }

    private func eligibility(for state: FoldState) -> ClusterExecutionEligibility {
        if state.maxWitnessClass.rawValue <= policy.maxDelegatableClass.rawValue {
            return .allowed
        }
        return .blocked(maxWitnessClass: state.maxWitnessClass)
    }

    private func requireClusterEligibility(for state: FoldState, attestation: Data?) throws {
        if let violation = policy.validateForDelegation(laneIDs: [], attestation: attestation) {
            throw ProofContextError.policyViolation(violation)
        }
        switch eligibility(for: state) {
        case .allowed:
            return
        case .blocked(let witnessClass):
            throw ProofContextError.clusterDelegationProhibited(witnessClass)
        }
    }

    private func stricter(_ lhs: WitnessClass, _ rhs: WitnessClass) -> WitnessClass {
        lhs.rawValue >= rhs.rawValue ? lhs : rhs
    }
}

private enum EnvelopeAttestationValidation {
    case valid
    case required
    case verifierMissing
    case invalid
}

/// Opaque handle to an in-progress proof.
///
/// ProofHandle is a lightweight reference to a FoldState managed by a ProofContext.
/// The underlying state is never exposed through this handle.
public struct ProofHandle: Sendable, Hashable {
    public let chainID: UUID
    public let shapeDigest: ShapeDigest
}

/// Receipt for a cluster-assisted seed operation.
public struct ClusterSeedReceipt: Sendable {
    public let handle: ProofHandle
    public let delegatedCommitment: AjtaiCommitment
    public let finalCommitment: AjtaiCommitment
    public let confinedIndices: [Int]
    public let laneCommitments: [ClusterLaneCommitment]
}

public enum ClusterExecutionEligibility: Sendable, Equatable {
    case allowed
    case blocked(maxWitnessClass: WitnessClass)
}

/// Result of envelope verification.
public struct VerificationResult: Sendable {
    public let isValid: Bool
    public let reason: VerificationFailure?
}

public enum VerificationFailure: Sendable, Equatable {
    case signatureInvalid
    case signerIdentityMissing
    case unsupportedEnvelopeVersion
    case shapeMismatch
    case profileMismatch
    case backendMismatch
    case attestationRequired
    case attestationVerifierMissing
    case attestationInvalid
    case decryptionFailed
    case proofInvalid
}

func verificationFailure(for error: ProofEnvelopeValidationError) -> VerificationFailure {
    switch error {
    case .unsupportedVersion:
        return .unsupportedEnvelopeVersion
    case .missingSignerKeyID:
        return .signerIdentityMissing
    case .invalidTimestamp:
        return .decryptionFailed
    case .invalidSealBackend, .missingTeamID, .invalidPublicHeaderDigest, .missingProofBytes:
        return .proofInvalid
    }
}

public enum ProofContextError: Error, Sendable {
    case handleNotFound
    case insufficientInputs
    case shapeMismatch
    case witnessShapeMismatch
    case invalidWitnessElementCount(expected: Int, actual: Int)
    case invalidPublicInputCount(expected: Int, actual: Int)
    case sealFailed
    case recursiveFoldingUnavailable
    case unsupportedStoredState
    case accumulatorTooLarge
    case policyViolation(PolicyViolation)
    case attestationValidation(AttestationValidationError)
    case clusterResultInvalid
    case clusterDelegationProhibited(WitnessClass)
    case proofVerificationFailed
}
