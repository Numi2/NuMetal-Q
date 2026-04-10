import Foundation

// MARK: - Fold Engine
// Orchestrates the three-stage SuperNeo folding pipeline.
// Binary folding with norm-budget-aware decomposition scheduling.
// Logical API: seed + binary fuse.
// Physical execution: PiCCS → PiRLC → PiDEC as needed.
//
// Stage order (SuperNeo paper):
//   1. PiCCS  — strong: sum-check reduction of CCS claims
//   2. PiRLC  — weak: random linear combination over evaluation claims
//   3. PiDEC  — decomposition: norm reset from B = b^k back to b

/// Configuration for the fold engine.
public struct FoldConfig: Sendable {
    /// Maximum internal batch size for staged binary reduction.
    public let maxArity: Int

    /// Decomposition base b.
    public let decompBase: UInt8

    /// Number of decomposition limbs.
    public let decompLimbs: UInt8

    /// Norm bound before decomposition is required.
    public let normBound: UInt64

    /// Fixed PiDEC cadence certified into the active profile.
    public let decompositionInterval: UInt32

    /// Commitment key slot count.
    public let keySlots: Int

    /// Canonical configuration for AG64-SNQ-129-A.
    public static let canonical = FoldConfig(
        maxArity: 2,
        decompBase: NuProfile.canonical.decompBase,
        decompLimbs: NuProfile.canonical.decompLimbs,
        normBound: NuProfile.canonical.normBound,
        decompositionInterval: UInt32(NuProfile.canonical.decompositionInterval),
        keySlots: NuProfile.canonical.commitmentRank * NuProfile.canonical.ringDegree
    )

    public init(
        maxArity: Int,
        decompBase: UInt8,
        decompLimbs: UInt8,
        normBound: UInt64,
        decompositionInterval: UInt32,
        keySlots: Int
    ) {
        self.maxArity = maxArity
        self.decompBase = decompBase
        self.decompLimbs = decompLimbs
        self.normBound = normBound
        self.decompositionInterval = decompositionInterval
        self.keySlots = keySlots
    }
}

/// The fold engine orchestrates SuperNeo's three-stage protocol.
///
/// Usage:
/// 1. Create a seed state via `seed(shape:witness:publicInputs:publicHeader:)`
/// 2. Fold states together via `fold(states:relation:)`
/// 3. Seal a final state via `SealEngine`
///
/// The engine executes PiDEC on the fixed cadence certified by the active profile.
public actor FoldEngine {
    private let config: FoldConfig
    private let keySeed: [UInt8]
    private let key: AjtaiKey
    private var metalContext: MetalContext?

    public init(config: FoldConfig = .canonical, seed: [UInt8] = []) {
        self.config = config
        self.keySeed = seed.isEmpty ? NuProfile.canonical.foldParameterSeed : seed
        self.key = AjtaiKey.expand(seed: self.keySeed, slotCount: config.keySlots)
    }

    /// Attach a Metal context for GPU-accelerated operations.
    public func setMetalContext(_ context: MetalContext) {
        self.metalContext = context
    }

    /// Create a seed FoldState from a base-case computation.
    internal func seed(
        shape: Shape,
        witness: Witness,
        publicInputs: [Fq],
        publicHeader: Data,
        witnessClass: WitnessClass
    ) async throws -> FoldState {
        try witness.validateSemanticIntegrity()
        let rings = WitnessPacking.packWitnessToRings(lanes: witness.lanes)

        var commitmentAcc = RingElement.zero
        var slot = 0
        for lane in witness.lanes {
            let laneComm = AjtaiCommitter.commitLane(key: key, lane: lane, slotOffset: slot)
            commitmentAcc += laneComm.value
            let slotsUsed = WitnessPacking.slotCount(for: lane)
            slot += slotsUsed
        }
        guard slot <= key.slotCount else {
            throw FoldEngineError.witnessPackingExceedsKeySlots(
                required: slot,
                available: key.slotCount
            )
        }

        return try await seedPrepared(
            shape: shape,
            commitment: AjtaiCommitment(value: commitmentAcc),
            packedWitness: rings,
            publicInputs: publicInputs,
            publicHeader: publicHeader,
            witnessClass: witnessClass
        )
    }

    /// Create a seed state from pre-packed witness rings and a matching
    /// aggregate commitment that were prepared and verified elsewhere.
    internal func seedPrepared(
        shape: Shape,
        commitment: AjtaiCommitment,
        packedWitness: [RingElement],
        publicInputs: [Fq],
        publicHeader: Data,
        witnessClass: WitnessClass
    ) async throws -> FoldState {
        try requirePiDECRepresentableWitness(packedWitness)
        let witnessFieldCount = shape.relation.n - shape.relation.nPublic
        let witnessFields = WitnessPacking.unpackFieldVector(
            from: packedWitness,
            originalLength: witnessFieldCount
        )

        var normBudget = NormBudget(
            bound: config.normBound,
            decompBase: config.decompBase,
            decompLimbs: config.decompLimbs,
            decompositionInterval: config.decompositionInterval
        )
        normBudget.currentNorm = packedWitness.map(\.infinityNorm).max() ?? 0

        let piCCSInput = PiCCS.Input(
            relation: shape.relation,
            publicInputs: publicInputs,
            witness: witnessFields,
            relaxationFactor: .one
        )

        let epoch: UInt64 = 0
        let arity = 1
        var transcript = makeRecursiveTranscript(
            shapeDigest: shape.digest,
            epoch: epoch,
            arity: arity
        )
        let piCCSTranscript = transcript
        let piCCSOutput = try await provePiCCS(
            input: piCCSInput,
            transcript: &transcript
        )

        var piCCSVerifyTranscript = piCCSTranscript
        guard PiCCS.verify(
            input: piCCSInput,
            output: piCCSOutput,
            transcript: &piCCSVerifyTranscript
        ) else {
            throw FoldEngineError.recursiveStageVerificationFailed(stage: .piCCS)
        }

        var stageAudit = [
            Self.makeStageRecord(
                epoch: epoch,
                stage: .piCCS,
                arity: arity,
                relation: shape.relation,
                witnessRingCount: packedWitness.count,
                normBefore: normBudget.currentNorm,
                normAfter: normBudget.currentNorm
            )
        ]

        let openingWitness: AccumulatorOpeningWitness
        if normBudget.requiresScheduledDecomposition {
            let piDECInput = PiDEC.Input(
                witness: packedWitness,
                commitment: commitment,
                key: key,
                decompBase: config.decompBase,
                decompLimbs: config.decompLimbs
            )
            let piDECTranscript = transcript
            let piDECOutput = try await provePiDEC(
                input: piDECInput,
                transcript: &transcript
            )

            var piDECVerifyTranscript = piDECTranscript
            guard PiDEC.verify(
                input: piDECInput,
                output: piDECOutput,
                transcript: &piDECVerifyTranscript
            ) else {
                throw FoldEngineError.recursiveStageVerificationFailed(stage: .piDEC)
            }

            let normBeforeDecomposition = normBudget.currentNorm
            normBudget.recordDecomposition()
            stageAudit.append(
                Self.makeStageRecord(
                    epoch: epoch,
                    stage: .piDEC,
                    arity: arity,
                    relation: shape.relation,
                    witnessRingCount: packedWitness.count,
                    normBefore: normBeforeDecomposition,
                    normAfter: normBudget.currentNorm
                )
            )
            openingWitness = AccumulatorOpeningWitness(
                decomposition: piDECOutput,
                decompBase: config.decompBase,
                decompLimbs: config.decompLimbs
            )
        } else {
            openingWitness = AccumulatorOpeningWitness(
                canonicalWitness: packedWitness,
                decompBase: config.decompBase,
                decompLimbs: config.decompLimbs
            )
        }

        let sourceClaim = CCSClaim(
            commitment: commitment,
            publicInputs: publicInputs,
            publicHeader: publicHeader,
            witnessRingCount: UInt32(clamping: packedWitness.count),
            witnessFieldCount: UInt32(clamping: witnessFieldCount)
        )
        let reducedClaim = try makePiCCSClaim(
            commitment: commitment,
            publicInputs: publicInputs,
            output: piCCSOutput
        )
        let accumulator = FoldAccumulator(
            epoch: epoch,
            arity: UInt32(arity),
            statementCount: 1,
            seed: SeedAccumulatorData(
                sourceClaim: sourceClaim,
                reducedClaim: reducedClaim,
                proof: piCCSOutput,
                openingWitness: openingWitness
            )
        )

        return FoldState(
            kind: .recursiveAccumulator,
            chainID: UUID(),
            epoch: epoch,
            shapeDigest: shape.digest,
            commitment: accumulator.currentCommitment,
            accumulatedWitness: [],
            publicInputs: publicInputs,
            publicHeader: publicHeader,
            statementCount: 1,
            normBudget: normBudget,
            errorTerms: reducedClaim.errorTerms,
            blindingMask: .zero,
            relaxationFactor: reducedClaim.relaxationFactor,
            maxWitnessClass: witnessClass,
            stageAudit: stageAudit,
            recursiveAccumulator: accumulator,
            typedTrace: nil
        )
    }

    /// Public-parameter material needed for typed cluster work packets.
    internal func clusterKeyParameters() -> (seed: [UInt8], slotCount: Int) {
        (keySeed, config.keySlots)
    }

    internal func commitmentSlotCount() -> Int {
        key.slotCount
    }

    internal func commit(witness: [RingElement]) -> AjtaiCommitment {
        AjtaiCommitter.commit(key: key, witness: witness)
    }

    internal func restoreSealedState(
        shape: Shape,
        proof: PublicSealProof,
        payload: ResumePayload
    ) throws -> FoldState {
        let accumulator = try FoldAccumulator.deserialize(payload.accumulatorArtifact)
        guard accumulator.version == FoldAccumulator.currentVersion else {
            throw FoldEngineError.invalidRecursiveAccumulator
        }

        guard accumulator.currentClaim.publicInputs == proof.statement.publicInputs,
              accumulator.leafPublicHeader() == proof.statement.publicHeader else {
            throw FoldEngineError.invalidRecursiveAccumulator
        }

        let normBudget = payload.normBudgetSnapshot.materialize()

        return FoldState(
            kind: .recursiveAccumulator,
            chainID: UUID(),
            epoch: accumulator.epoch,
            shapeDigest: shape.digest,
            commitment: accumulator.currentCommitment,
            accumulatedWitness: [],
            publicInputs: accumulator.leafPublicInputs(),
            publicHeader: accumulator.leafPublicHeader(),
            statementCount: accumulator.statementCount,
            normBudget: normBudget,
            errorTerms: accumulator.currentClaim.errorTerms,
            blindingMask: .zero,
            relaxationFactor: accumulator.currentClaim.relaxationFactor,
            maxWitnessClass: payload.provenanceClass,
            stageAudit: payload.stageAudit,
            recursiveAccumulator: accumulator,
            typedTrace: nil
        )
    }

    /// Fold multiple states together using the three-stage protocol.
    ///
    /// The persisted state remains explicitly non-relaxed: we keep the full
    /// canonical aggregate witness/commitment for every logical statement in the
    /// batch. PiCCS, PiRLC, and PiDEC execute as self-verified transcript stages
    /// over that aggregate so the production fold path stays sound without
    /// persisting a relaxed accumulator witness.
    internal func fold(states: [FoldState], relation: CCSRelation) async throws -> FoldState {
        guard states.count >= 2 else {
            throw FoldEngineError.insufficientInputs
        }

        var pending = states
        while pending.count > 1 {
            var nextRound = [FoldState]()
            nextRound.reserveCapacity((pending.count + 1) / 2)

            var index = 0
            while index < pending.count {
                let remaining = pending.count - index
                if remaining == 1 {
                    nextRound.append(pending[index])
                    index += 1
                    continue
                }

                let batchSize = recommendedBatchSize(
                    for: pending[index..<pending.count],
                    maxArity: min(config.maxArity, remaining)
                )
                let end = index + batchSize
                let batch = Array(pending[index..<end])
                nextRound.append(try await foldBatch(states: batch, relation: relation))
                index = end
            }

            pending = nextRound
        }

        return pending[0]
    }

    /// Execute PiDEC decomposition on a state whose norm exceeded the budget.
    private func decompose(
        state: FoldState,
        transcript: inout NuTranscriptField
    ) throws -> FoldState {
        try requirePiDECRepresentableWitness(state.accumulatedWitness)
        let piDECInput = PiDEC.Input(
            witness: state.accumulatedWitness,
            commitment: state.commitment,
            key: key,
            decompBase: config.decompBase,
            decompLimbs: config.decompLimbs
        )

        let piDECOutput = PiDEC.prove(input: piDECInput, transcript: &transcript)

        var newWitness = [RingElement]()
        for decomp in piDECOutput.decomposedWitness {
            newWitness.append(contentsOf: decomp)
        }

        var newState = state
        newState.accumulatedWitness = newWitness
        newState.commitment = AjtaiCommitter.commit(key: key, witness: newWitness)
        newState.normBudget.recordDecomposition()
        return newState
    }

    private static func makeStageRecord(
        epoch: UInt64,
        stage: FoldStageKind,
        arity: Int,
        relation: CCSRelation,
        witnessRingCount: Int,
        normBefore: UInt64,
        normAfter: UInt64
    ) -> FoldStageRecord {
        FoldStageRecord(
            epoch: epoch,
            stage: stage,
            arity: UInt8(clamping: arity),
            relationConstraintCount: UInt32(clamping: relation.m),
            witnessRingCount: UInt32(clamping: witnessRingCount),
            normBefore: normBefore,
            normAfter: normAfter
        )
    }

    private func provePiCCS(
        input: PiCCS.Input,
        transcript: inout NuTranscriptField
    ) async throws -> PiCCS.Output {
        if let metalContext {
            return try await PiCCS.proveMetal(
                input: input,
                transcript: &transcript,
                context: metalContext
            )
        }
        return PiCCS.prove(input: input, transcript: &transcript)
    }

    private func provePiRLC(
        inputs: [PiRLC.Input],
        transcript: inout NuTranscriptField
    ) async throws -> PiRLC.Output {
        if let metalContext {
            return try await PiRLC.proveMetal(
                inputs: inputs,
                key: key,
                transcript: &transcript,
                context: metalContext
            )
        }
        return PiRLC.prove(inputs: inputs, key: key, transcript: &transcript)
    }

    private func provePiDEC(
        input: PiDEC.Input,
        transcript: inout NuTranscriptField
    ) async throws -> PiDEC.Output {
        try requirePiDECRepresentableWitness(input.witness)
        if let metalContext {
            return try await PiDEC.proveMetal(
                input: input,
                transcript: &transcript,
                context: metalContext
            )
        }
        return PiDEC.prove(input: input, transcript: &transcript)
    }

    private func requirePiDECRepresentableWitness(_ witness: [RingElement]) throws {
        guard Decomposition.witnessFits(
            witness,
            base: config.decompBase,
            numLimbs: config.decompLimbs
        ) else {
            throw FoldEngineError.witnessExceedsPiDECRepresentability(
                maxMagnitude: Decomposition.maxCenteredMagnitude(in: witness),
                base: config.decompBase,
                limbs: config.decompLimbs
            )
        }
    }

    private func canonicalWitnessFieldVector(
        from state: FoldState,
        relation: CCSRelation
    ) throws -> [Fq] {
        let witnessLength = (relation.n - relation.nPublic) * Int(state.statementCount)
        let canonicalRings = try WitnessPacking.canonicalizeRings(
            state.accumulatedWitness,
            originalFieldCount: witnessLength,
            decompBase: config.decompBase,
            decompLimbs: config.decompLimbs
        )
        return WitnessPacking.unpackFieldVector(
            from: canonicalRings,
            originalLength: witnessLength
        )
    }

    private func isSingleLevelDecomposed(ringCount: Int, canonicalRingCount: Int) -> Bool {
        canonicalRingCount > 0 && ringCount == canonicalRingCount * Int(config.decompLimbs)
    }

    private func recommendedBatchSize(
        for states: ArraySlice<FoldState>,
        maxArity: Int
    ) -> Int {
        guard states.count > 1 else { return states.count }

        return min(states.count, min(maxArity, 2))
    }

    private func foldBatch(states: [FoldState], relation: CCSRelation) async throws -> FoldState {
        guard states.count >= 2 else {
            throw FoldEngineError.insufficientInputs
        }

        try states.forEach(validateRecursiveInputState)
        try states.forEach { state in
            try verifyRecursiveStateIfPresent(state, relation: relation)
        }
        guard states.map(\.shapeDigest).allSatisfy({ $0 == states[0].shapeDigest }) else {
            throw FoldEngineError.shapeMismatch
        }

        let epoch = (states.map(\.epoch).max() ?? 0) &+ 1
        let directArity = states.count
        let totalStatementCopies = states.reduce(0) { partial, state in
            partial + Int(state.statementCount)
        }
        guard totalStatementCopies > 0, totalStatementCopies <= Int(UInt32.max) else {
            throw FoldEngineError.invalidAggregateState
        }
        let batchedAuditRelation = batchedRelation(relation, copies: max(1, directArity))
        let accumulators = try states.map { state -> FoldAccumulator in
            guard let accumulator = state.recursiveAccumulator else {
                throw FoldEngineError.invalidRecursiveAccumulator
            }
            return accumulator
        }

        var transcript = makeRecursiveTranscript(
            shapeDigest: states[0].shapeDigest,
            epoch: epoch,
            arity: directArity
        )
        var currentStageAudit = [FoldStageRecord]()
        currentStageAudit.reserveCapacity(2)
        let piRLCInputs = try accumulators.map(makePiRLCInput(from:))

        var foldedNormBudget = mergedNormBudget(for: states)
        let piRLCTranscript = transcript
        let piRLCOutput = try await provePiRLC(
            inputs: piRLCInputs,
            transcript: &transcript
        )

        var piRLCVerifyTranscript = piRLCTranscript
        guard PiRLC.verify(
            inputs: piRLCInputs,
            output: piRLCOutput,
            key: key,
            transcript: &piRLCVerifyTranscript
        ) else {
            throw FoldEngineError.recursiveStageVerificationFailed(stage: .piRLC)
        }

        let normBeforeFold = foldedNormBudget.currentNorm
        let challengeMagnitude = piRLCOutput.ringChallenges.map(\.infinityNorm).max() ?? 0
        foldedNormBudget.recordFold(arity: directArity, challengeMagnitude: challengeMagnitude)
        try requirePiDECRepresentableWitness(piRLCOutput.foldedWitness)

        currentStageAudit.append(
            Self.makeStageRecord(
                epoch: epoch,
                stage: .piRLC,
                arity: directArity,
                relation: batchedAuditRelation,
                witnessRingCount: piRLCOutput.foldedWitness.count,
                normBefore: normBeforeFold,
                normAfter: foldedNormBudget.currentNorm
            )
        )

        let openingWitness: AccumulatorOpeningWitness
        if foldedNormBudget.requiresScheduledDecomposition {
            let piDECInput = PiDEC.Input(
                witness: piRLCOutput.foldedWitness,
                commitment: piRLCOutput.foldedCommitment,
                key: key,
                decompBase: config.decompBase,
                decompLimbs: config.decompLimbs
            )
            let piDECTranscript = transcript
            let piDECOutputValue = try await provePiDEC(
                input: piDECInput,
                transcript: &transcript
            )

            var piDECVerifyTranscript = piDECTranscript
            guard PiDEC.verify(
                input: piDECInput,
                output: piDECOutputValue,
                transcript: &piDECVerifyTranscript
            ) else {
                throw FoldEngineError.recursiveStageVerificationFailed(stage: .piDEC)
            }

            let normBeforeDecomposition = foldedNormBudget.currentNorm
            foldedNormBudget.recordDecomposition()

            currentStageAudit.append(
                Self.makeStageRecord(
                    epoch: epoch,
                    stage: .piDEC,
                    arity: directArity,
                    relation: batchedAuditRelation,
                    witnessRingCount: piRLCOutput.foldedWitness.count,
                    normBefore: normBeforeDecomposition,
                    normAfter: foldedNormBudget.currentNorm
                )
            )

            openingWitness = AccumulatorOpeningWitness(
                decomposition: piDECOutputValue,
                decompBase: config.decompBase,
                decompLimbs: config.decompLimbs
            )
        } else {
            openingWitness = AccumulatorOpeningWitness(
                canonicalWitness: piRLCOutput.foldedWitness,
                decompBase: config.decompBase,
                decompLimbs: config.decompLimbs
            )
        }

        let recursiveAccumulator = FoldAccumulator(
            epoch: epoch,
            arity: UInt32(clamping: directArity),
            statementCount: UInt32(totalStatementCopies),
            fold: FoldAccumulatorData(
                childAccumulators: accumulators,
                foldedClaim: try makeFoldedCEClaim(from: piRLCOutput),
                piRLCProof: piRLCOutput,
                openingWitness: openingWitness
            )
        )

        return try makeRecursiveFoldState(
            from: states,
            epoch: epoch,
            normBudget: foldedNormBudget,
            appendedStageAudit: currentStageAudit,
            recursiveAccumulator: recursiveAccumulator
        )
    }

    internal func verifyRecursiveState(
        state: FoldState,
        relation: CCSRelation,
        executionMode: VerificationExecutionMode = .automatic,
        traceCollector: MetalTraceCollector? = nil
    ) throws -> Bool {
        guard state.kind == .recursiveAccumulator,
              state.typedTrace == nil,
              state.statementCount > 0,
              let accumulator = state.recursiveAccumulator else {
            return false
        }

        guard accumulator.epoch == state.epoch,
              accumulator.statementCount == state.statementCount else {
            return false
        }

        guard let summary = try verifyAccumulator(
            accumulator,
            relation: relation,
            shapeDigest: state.shapeDigest,
            executionMode: executionMode,
            traceCollector: traceCollector
        ) else {
            return false
        }
        guard summary.currentClaim.relaxationFactor == state.relaxationFactor,
              summary.currentClaim.errorTerms == state.errorTerms else {
            return false
        }
        return summary.statementCount == state.statementCount
            && summary.currentCommitment == state.commitment
            && summary.leafPublicInputs == state.publicInputs
            && summary.leafPublicHeader == state.publicHeader
    }

    private func validateRecursiveInputState(_ state: FoldState) throws {
        guard state.typedTrace == nil,
              state.blindingMask == .zero,
              state.statementCount > 0 else {
            throw FoldEngineError.invalidAggregateState
        }

        switch state.kind {
        case .aggregateStatements:
            return
        case .recursiveAccumulator:
            guard state.recursiveAccumulator != nil else {
                throw FoldEngineError.invalidRecursiveAccumulator
            }
        case .typedTrace:
            throw FoldEngineError.invalidAggregateState
        }
    }

    private func makeRecursiveTranscript(
        shapeDigest: ShapeDigest,
        epoch: UInt64,
        arity: Int
    ) -> NuTranscriptField {
        var transcript = NuTranscriptField(domain: "NuMeQ.FoldEngine.Accumulator.v2")
        transcript.absorb(field: Fq(UInt64(epoch)))
        transcript.absorb(field: Fq(UInt64(arity)))
        for byte in shapeDigest.bytes {
            transcript.absorb(field: Fq(UInt64(byte)))
        }
        return transcript
    }

    private func makePiRLCInput(from accumulator: FoldAccumulator) throws -> PiRLC.Input {
        try PiRLC.Input(
            commitment: accumulator.currentCommitment,
            witness: accumulator.currentWitness(),
            publicInputs: accumulator.currentClaim.publicInputs,
            ccsEvaluations: accumulator.currentClaim.matrixEvaluations,
            relaxationFactor: accumulator.currentClaim.relaxationFactor,
            errorTerms: accumulator.currentClaim.errorTerms
        )
    }

    private func makePiCCSClaim(
        commitment: AjtaiCommitment,
        publicInputs: [Fq],
        output: PiCCS.Output
    ) throws -> CEClaim {
        CEClaim(
            kind: .piCCSReduced,
            commitment: commitment,
            publicInputs: publicInputs,
            evaluationPoint: output.sumCheckProof.challengePoint,
            matrixEvaluations: output.evaluations,
            reductionChallenges: output.challenges,
            relaxationFactor: .one,
            errorTerms: [],
            transcriptBinding: try RecursiveAccumulatorCodec.digest(output, domain: .piCCSClaim)
        )
    }

    private func makeFoldedCEClaim(from output: PiRLC.Output) throws -> CEClaim {
        CEClaim(
            kind: .piRLCFolded,
            commitment: output.foldedCommitment,
            publicInputs: output.foldedPublicInputs,
            evaluationPoint: nil,
            matrixEvaluations: output.foldedEvaluations,
            reductionChallenges: nil,
            relaxationFactor: output.foldedRelaxation,
            errorTerms: output.foldedError,
            transcriptBinding: try RecursiveAccumulatorCodec.digest(output, domain: .piRLCClaim)
        )
    }

    private func verifyRecursiveStateIfPresent(
        _ state: FoldState,
        relation: CCSRelation
    ) throws {
        guard state.kind == .recursiveAccumulator else {
            return
        }
        guard try verifyRecursiveState(state: state, relation: relation) else {
            throw FoldEngineError.invalidRecursiveAccumulator
        }
    }

    private func mergedNormBudget(for states: [FoldState]) -> NormBudget {
        var merged = NormBudget(
            bound: config.normBound,
            decompBase: config.decompBase,
            decompLimbs: config.decompLimbs,
            decompositionInterval: config.decompositionInterval
        )
        merged.currentNorm = states.map(\.normBudget.currentNorm).max() ?? 0
        merged.foldsSinceDecomp = states.map(\.normBudget.foldsSinceDecomp).max() ?? 0
        return merged
    }

    private struct VerifiedAccumulatorSummary {
        let statementCount: UInt32
        let currentCommitment: AjtaiCommitment
        let currentClaim: CEClaim
        let currentWitness: [RingElement]
        let leafPublicInputs: [Fq]
        let leafPublicHeader: Data
    }

    private func verifyAccumulator(
        _ accumulator: FoldAccumulator,
        relation: CCSRelation,
        shapeDigest: ShapeDigest,
        executionMode: VerificationExecutionMode,
        traceCollector: MetalTraceCollector?
    ) throws -> VerifiedAccumulatorSummary? {
        guard accumulator.version == FoldAccumulator.currentVersion else {
            return nil
        }

        switch accumulator.nodeKind {
        case .seed:
            guard accumulator.arity == 1,
                  accumulator.statementCount == 1,
                  let seed = accumulator.seed,
                  accumulator.fold == nil else {
                return nil
            }

            let canonicalWitness = try seed.openingWitness.reconstructedWitness()
            guard seed.sourceClaim.witnessRingCount == UInt32(clamping: canonicalWitness.count) else {
                return nil
            }
            guard try commitWitnessesForVerification(
                [canonicalWitness],
                executionMode: executionMode,
                traceCollector: traceCollector
            )[0] == seed.sourceClaim.commitment else {
                return nil
            }

            let witnessFields = WitnessPacking.unpackFieldVector(
                from: canonicalWitness,
                originalLength: Int(seed.sourceClaim.witnessFieldCount)
            )
            guard relation.isSatisfied(by: seed.sourceClaim.publicInputs + witnessFields) else {
                return nil
            }

            var transcript = makeRecursiveTranscript(
                shapeDigest: shapeDigest,
                epoch: accumulator.epoch,
                arity: Int(accumulator.arity)
            )
            let piCCSInput = PiCCS.Input(
                relation: relation,
                publicInputs: seed.sourceClaim.publicInputs,
                witness: witnessFields,
                relaxationFactor: .one
            )
            if let metalContext = metalContext(for: executionMode) {
                guard try PiCCS.verifyMetal(
                    input: piCCSInput,
                    output: seed.proof,
                    transcript: &transcript,
                    context: metalContext,
                    trace: traceCollector
                ) else {
                    return nil
                }
            } else {
                guard PiCCS.verify(
                    input: piCCSInput,
                    output: seed.proof,
                    transcript: &transcript
                ) else {
                    return nil
                }
            }
            guard let verifiedWitness = try verifyOpeningWitness(
                seed.openingWitness,
                commitment: seed.sourceClaim.commitment,
                transcript: &transcript,
                executionMode: executionMode,
                traceCollector: traceCollector
            ), verifiedWitness == canonicalWitness else {
                return nil
            }

            let expectedClaim = try makePiCCSClaim(
                commitment: seed.sourceClaim.commitment,
                publicInputs: seed.sourceClaim.publicInputs,
                output: seed.proof
            )
            guard seed.reducedClaim == expectedClaim else {
                return nil
            }

            return VerifiedAccumulatorSummary(
                statementCount: accumulator.statementCount,
                currentCommitment: expectedClaim.commitment,
                currentClaim: expectedClaim,
                currentWitness: canonicalWitness,
                leafPublicInputs: seed.sourceClaim.publicInputs,
                leafPublicHeader: seed.sourceClaim.publicHeader
            )

        case .fold:
            guard accumulator.arity >= 2,
                  let fold = accumulator.fold,
                  accumulator.seed == nil,
                  fold.childAccumulators.count == Int(accumulator.arity) else {
                return nil
            }

            var childSummaries = [VerifiedAccumulatorSummary]()
            childSummaries.reserveCapacity(fold.childAccumulators.count)
            for child in fold.childAccumulators {
                guard let summary = try verifyAccumulator(
                    child,
                    relation: relation,
                    shapeDigest: shapeDigest,
                    executionMode: executionMode,
                    traceCollector: traceCollector
                ) else {
                    return nil
                }
                childSummaries.append(summary)
            }

            let childStatementCount = childSummaries.reduce(UInt64(0)) { partial, summary in
                partial + UInt64(summary.statementCount)
            }
            guard childStatementCount == UInt64(accumulator.statementCount) else {
                return nil
            }

            var transcript = makeRecursiveTranscript(
                shapeDigest: shapeDigest,
                epoch: accumulator.epoch,
                arity: Int(accumulator.arity)
            )
            let piRLCInputs = childSummaries.map { summary in
                PiRLC.Input(
                    commitment: summary.currentCommitment,
                    witness: summary.currentWitness,
                    publicInputs: summary.currentClaim.publicInputs,
                    ccsEvaluations: summary.currentClaim.matrixEvaluations,
                    relaxationFactor: summary.currentClaim.relaxationFactor,
                    errorTerms: summary.currentClaim.errorTerms
                )
            }
            if let metalContext = metalContext(for: executionMode) {
                guard try verifyPiRLCMetal(
                    inputs: piRLCInputs,
                    output: fold.piRLCProof,
                    transcript: &transcript,
                    context: metalContext,
                    traceCollector: traceCollector
                ) else {
                    return nil
                }
            } else {
                guard PiRLC.verify(
                    inputs: piRLCInputs,
                    output: fold.piRLCProof,
                    key: key,
                    transcript: &transcript
                ) else {
                    return nil
                }
            }

            let expectedClaim = try makeFoldedCEClaim(from: fold.piRLCProof)
            guard fold.foldedClaim == expectedClaim else {
                return nil
            }
            guard let verifiedWitness = try verifyOpeningWitness(
                fold.openingWitness,
                commitment: fold.piRLCProof.foldedCommitment,
                transcript: &transcript,
                executionMode: executionMode,
                traceCollector: traceCollector
            ), verifiedWitness == fold.piRLCProof.foldedWitness else {
                return nil
            }
            guard try commitWitnessesForVerification(
                [verifiedWitness],
                executionMode: executionMode,
                traceCollector: traceCollector
            )[0] == expectedClaim.commitment else {
                return nil
            }

            return VerifiedAccumulatorSummary(
                statementCount: accumulator.statementCount,
                currentCommitment: expectedClaim.commitment,
                currentClaim: expectedClaim,
                currentWitness: verifiedWitness,
                leafPublicInputs: childSummaries.flatMap(\.leafPublicInputs),
                leafPublicHeader: childSummaries.reduce(into: Data()) { partial, summary in
                    partial.append(summary.leafPublicHeader)
                }
            )

        }
    }

    private func verifyOpeningWitness(
        _ openingWitness: AccumulatorOpeningWitness,
        commitment: AjtaiCommitment,
        transcript: inout NuTranscriptField,
        executionMode: VerificationExecutionMode,
        traceCollector: MetalTraceCollector?
    ) throws -> [RingElement]? {
        switch openingWitness.kind {
        case .canonical:
            guard let witness = openingWitness.canonicalWitness,
                  openingWitness.decomposition == nil else {
                return nil
            }
            return try commitWitnessesForVerification(
                [witness],
                executionMode: executionMode,
                traceCollector: traceCollector
            )[0] == commitment ? witness : nil

        case .decomposed:
            guard openingWitness.canonicalWitness == nil,
                  let decomposition = openingWitness.decomposition else {
                return nil
            }
            let witness = try openingWitness.reconstructedWitness()
            let piDECInput = PiDEC.Input(
                witness: witness,
                commitment: commitment,
                key: key,
                decompBase: openingWitness.decompBase,
                decompLimbs: openingWitness.decompLimbs
            )
            if let metalContext = metalContext(for: executionMode) {
                guard try verifyPiDECMetal(
                    input: piDECInput,
                    output: decomposition,
                    transcript: &transcript,
                    context: metalContext,
                    traceCollector: traceCollector
                ) else {
                    return nil
                }
            } else {
                guard PiDEC.verify(
                    input: piDECInput,
                    output: decomposition,
                    transcript: &transcript
                ) else {
                    return nil
                }
            }
            return witness
        }
    }

    private func commitWitnessesForVerification(
        _ witnesses: [[RingElement]]
    ) throws -> [AjtaiCommitment] {
        try commitWitnessesForVerification(
            witnesses,
            executionMode: .automatic,
            traceCollector: nil
        )
    }

    private func commitWitnessesForVerification(
        _ witnesses: [[RingElement]],
        executionMode: VerificationExecutionMode,
        traceCollector: MetalTraceCollector?
    ) throws -> [AjtaiCommitment] {
        if let metalContext = metalContext(for: executionMode) {
            return try AjtaiCommitter.commitBatchMetal(
                context: metalContext,
                key: key,
                witnessBatches: witnesses,
                trace: traceCollector.map {
                    TimedDispatchTraceContext(
                        collector: $0,
                        stage: "recursiveVerifier",
                        iteration: $0.defaultIteration,
                        dispatchLabel: "recursiveVerifier.commit_batch"
                    )
                }
            )
        }
        return witnesses.map { commit(witness: $0) }
    }

    private func verifyPiDECMetal(
        input: PiDEC.Input,
        output: PiDEC.Output,
        transcript: inout NuTranscriptField,
        context: MetalContext,
        traceCollector: MetalTraceCollector?
    ) throws -> Bool {
        try PiDEC.verifyMetal(
            input: input,
            output: output,
            transcript: &transcript,
            context: context,
            trace: traceCollector
        )
    }

    private func verifyPiRLCMetal(
        inputs: [PiRLC.Input],
        output: PiRLC.Output,
        transcript: inout NuTranscriptField,
        context: MetalContext,
        traceCollector: MetalTraceCollector?
    ) throws -> Bool {
        try PiRLC.verifyMetal(
            inputs: inputs,
            output: output,
            key: key,
            transcript: &transcript,
            context: context,
            trace: traceCollector
        )
    }

    private func metalContext(for executionMode: VerificationExecutionMode) -> MetalContext? {
        switch executionMode {
        case .automatic, .metalAssisted:
            return metalContext
        case .cpuOnly:
            return nil
        }
    }

    private func computeCrossTermsMetal(
        inputs: [PiRLC.Input],
        context: MetalContext
    ) throws -> [[RingElement]] {
        guard inputs.count >= 2 else { return [] }

        var lhs = [RingElement]()
        var rhs = [RingElement]()
        var spans = [Range<Int>]()
        lhs.reserveCapacity((inputs.count - 1) * inputs[0].witness.count)
        rhs.reserveCapacity(lhs.capacity)

        let baselineWitness = inputs[0].witness
        for input in inputs.dropFirst() {
            let start = lhs.count
            let count = min(baselineWitness.count, input.witness.count)
            lhs.append(contentsOf: baselineWitness.prefix(count))
            rhs.append(contentsOf: input.witness.prefix(count))
            spans.append(start..<(start + count))
        }

        let products = try AG64RingMetal.multiplyBatch(context: context, lhs: lhs, rhs: rhs)
        return spans.map { Array(products[$0]) }
    }

    private func buildScalarChallengeRings(base: Fq, count: Int) -> [RingElement] {
        var rings = [RingElement]()
        rings.reserveCapacity(count)
        var power = Fq.one
        for _ in 0..<count {
            rings.append(RingElement(constant: power))
            power *= base
        }
        return rings
    }

    private func decomposeWitnessMetal(
        witness: [RingElement],
        decompBase: UInt8,
        decompLimbs: UInt8,
        context: MetalContext
    ) throws -> [[RingElement]] {
        let flatCoefficients = witness.flatMap(\.coeffs)
        let valueCount = flatCoefficients.count

        return try context.withTransientArena { arena in
            guard let inputBuffer = arena.uploadFieldElements(flatCoefficients),
                  let paramsBuffer = arena.makeSharedSlice(length: 3 * MemoryLayout<UInt32>.size),
                  let outputBuffer = arena.makeSharedSlice(
                    length: valueCount * Int(decompLimbs) * MemoryLayout<UInt32>.size * 2
                  ) else {
                throw NuMetalError.heapCreationFailed
            }

            let paramsPointer = paramsBuffer.typedContents(as: UInt32.self, capacity: 3)
            paramsPointer[0] = UInt32(valueCount)
            paramsPointer[1] = UInt32(
                Decomposition.metalLimbBitWidth(forBase: UInt64(decompBase)) ?? 0
            )
            paramsPointer[2] = UInt32(decompLimbs)

            let dispatcher = KernelDispatcher(context: context)
            try dispatcher.dispatchDecompose(
                inputBuffer: inputBuffer,
                outputBuffer: outputBuffer,
                paramsBuffer: paramsBuffer,
                numElements: valueCount,
                decompBase: decompBase,
                numLimbs: decompLimbs
            )

            let outputPointer = outputBuffer.typedContents(
                as: UInt32.self,
                capacity: valueCount * Int(decompLimbs) * 2
            )
            let totalValueCount = valueCount * Int(decompLimbs)
            let coeffsPerRing = RingElement.degree

            return (0..<witness.count).map { ringIndex in
                (0..<Int(decompLimbs)).map { limbIndex in
                    var storage = [UInt32](repeating: 0, count: coeffsPerRing * 2)
                    for coeffIndex in 0..<coeffsPerRing {
                        let flatIndex = limbIndex * valueCount + ringIndex * coeffsPerRing + coeffIndex
                        storage[coeffIndex] = outputPointer[flatIndex]
                        storage[coeffsPerRing + coeffIndex] = outputPointer[totalValueCount + flatIndex]
                    }
                    return RingElement(
                        coeffs: MetalFieldPacking.unpackFieldElementsSoA(storage, count: coeffsPerRing)
                    )
                }
            }
        }
    }

    private func makeRecursiveFoldState(
        from states: [FoldState],
        epoch: UInt64,
        normBudget: NormBudget,
        appendedStageAudit: [FoldStageRecord],
        recursiveAccumulator: FoldAccumulator
    ) throws -> FoldState {
        guard recursiveAccumulator.statementCount > 0 else {
            throw FoldEngineError.invalidAggregateState
        }

        let combinedPublicInputs = recursiveAccumulator.leafPublicInputs()
        let combinedPublicHeader = recursiveAccumulator.leafPublicHeader()
        guard combinedPublicInputs == states.flatMap(\.publicInputs) else {
            throw FoldEngineError.invalidAggregateState
        }
        guard combinedPublicHeader == states.reduce(into: Data(), { partial, state in
            partial.append(state.publicHeader)
        }) else {
            throw FoldEngineError.invalidAggregateState
        }

        let maxWitnessClass = states.reduce(.public) { current, state in
            current.rawValue >= state.maxWitnessClass.rawValue ? current : state.maxWitnessClass
        }

        return FoldState(
            kind: .recursiveAccumulator,
            chainID: UUID(),
            epoch: epoch,
            shapeDigest: states[0].shapeDigest,
            commitment: recursiveAccumulator.currentCommitment,
            accumulatedWitness: [],
            publicInputs: combinedPublicInputs,
            publicHeader: combinedPublicHeader,
            statementCount: recursiveAccumulator.statementCount,
            normBudget: normBudget,
            errorTerms: recursiveAccumulator.currentClaim.errorTerms,
            blindingMask: .zero,
            relaxationFactor: recursiveAccumulator.currentClaim.relaxationFactor,
            maxWitnessClass: maxWitnessClass,
            stageAudit: states.flatMap(\.stageAudit) + appendedStageAudit,
            recursiveAccumulator: recursiveAccumulator,
            typedTrace: nil
        )
    }

    private func batchedRelation(_ relation: CCSRelation, copies: Int) -> CCSRelation {
        guard copies > 1 else { return relation }

        let matrices = relation.matrices.map { matrix in
            makeBlockDiagonal(matrix: matrix, copies: copies, columnWidth: relation.n)
        }

        return CCSRelation(
            m: relation.m * copies,
            n: relation.n * copies,
            nPublic: relation.nPublic * copies,
            matrices: matrices,
            gates: relation.gates
        )
    }

    private func makeBlockDiagonal(
        matrix: SparseMatrix,
        copies: Int,
        columnWidth: Int
    ) -> SparseMatrix {
        var rowPtr = [UInt32]()
        rowPtr.reserveCapacity(matrix.rows * copies + 1)
        rowPtr.append(0)

        var colIdx = [UInt32]()
        colIdx.reserveCapacity(matrix.colIdx.count * copies)
        var values = [Fq]()
        values.reserveCapacity(matrix.values.count * copies)

        var runningNNZ: UInt32 = 0
        for copy in 0..<copies {
            let columnOffset = UInt32(copy * columnWidth)
            for row in 0..<matrix.rows {
                let start = Int(matrix.rowPtr[row])
                let end = Int(matrix.rowPtr[row + 1])
                for entry in start..<end {
                    colIdx.append(matrix.colIdx[entry] + columnOffset)
                    values.append(matrix.values[entry])
                    runningNNZ &+= 1
                }
                rowPtr.append(runningNNZ)
            }
        }

        return SparseMatrix(
            rows: matrix.rows * copies,
            cols: matrix.cols * copies,
            rowPtr: rowPtr,
            colIdx: colIdx,
            values: values
        )
    }
}

internal enum FoldEngineError: Error, Sendable {
    case insufficientInputs
    case shapeMismatch
    case invalidAggregateState
    case invalidRecursiveAccumulator
    case invalidPublicInputCount(expected: Int, actual: Int)
    case nestedDecompositionUnsupported
    case unsupportedWitnessRepresentation(actualRingCount: Int)
    case witnessPackingExceedsKeySlots(required: Int, available: Int)
    case witnessExceedsPiDECRepresentability(maxMagnitude: UInt64, base: UInt8, limbs: UInt8)
    case recursiveStageVerificationFailed(stage: FoldStageKind)
}

private struct RecursiveClaimInput: Sendable {
    let relation: CCSRelation
    let publicInputs: [Fq]
    let canonicalWitness: [RingElement]
    let commitment: AjtaiCommitment
    let piCCSInput: PiCCS.Input
}
