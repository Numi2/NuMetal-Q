// MARK: - PiRLC: Weak Interactive Random Linear Combination
// Second of the three SuperNeo transcript stages.
// ΠRLC is the WEAK interactive reduction that performs a random
// linear combination over challenges from the strong sampling set C.
//
// Given k CCS instances, PiRLC folds them into a single relaxed CCS
// instance via random ring challenges sampled from C = {-1, 0, 1, 2}.

/// PiRLC protocol stage: fold multiple CCS instances into one.
///
/// Given running instances (Cᵢ, wᵢ, xᵢ, uᵢ, eᵢ) for i = 1..k,
/// the verifier sends ring challenges ρ₁, ..., ρₖ sampled from the
/// challenge set C and the prover computes the folded instance:
///   C' = Σ ρᵢ Cᵢ
///   w' = Σ ρᵢ wᵢ
///   x' = Σ ρᵢ xᵢ
///   u' = Σ ρᵢ uᵢ
///   e' = cross-term computation
public struct PiRLC: Sendable {

    /// Inputs to the RLC folding stage.
    public struct Input: Sendable {
        public let commitment: AjtaiCommitment
        public let witness: [RingElement]
        public let publicInputs: [Fq]
        public let ccsEvaluations: [Fq]
        public let relaxationFactor: Fq
        public let errorTerms: [RingElement]

        public init(
            commitment: AjtaiCommitment,
            witness: [RingElement],
            publicInputs: [Fq],
            ccsEvaluations: [Fq],
            relaxationFactor: Fq,
            errorTerms: [RingElement]
        ) {
            self.commitment = commitment
            self.witness = witness
            self.publicInputs = publicInputs
            self.ccsEvaluations = ccsEvaluations
            self.relaxationFactor = relaxationFactor
            self.errorTerms = errorTerms
        }
    }

    /// Output of the RLC folding stage.
    public struct Output: Sendable, Codable, Equatable {
        public let foldedCommitment: AjtaiCommitment
        public let foldedWitness: [RingElement]
        public let foldedPublicInputs: [Fq]
        public let foldedEvaluations: [Fq]
        public let foldedRelaxation: Fq
        public let foldedError: [RingElement]
        public let crossTermCommitments: [AjtaiCommitment]
        /// Ring challenges used (from sampling set C).
        public let ringChallenges: [RingElement]

        public init(
            foldedCommitment: AjtaiCommitment,
            foldedWitness: [RingElement],
            foldedPublicInputs: [Fq],
            foldedEvaluations: [Fq],
            foldedRelaxation: Fq,
            foldedError: [RingElement],
            crossTermCommitments: [AjtaiCommitment],
            ringChallenges: [RingElement]
        ) {
            self.foldedCommitment = foldedCommitment
            self.foldedWitness = foldedWitness
            self.foldedPublicInputs = foldedPublicInputs
            self.foldedEvaluations = foldedEvaluations
            self.foldedRelaxation = foldedRelaxation
            self.foldedError = foldedError
            self.crossTermCommitments = crossTermCommitments
            self.ringChallenges = ringChallenges
        }
    }

    /// Execute PiRLC prover on a batch of instances.
    public static func prove(
        inputs: [Input],
        key: AjtaiKey,
        transcript: inout NuTranscriptField
    ) -> Output {
        let k = inputs.count
        precondition(k >= 2, "PiRLC requires at least 2 instances")
        precondition(hasCompatibleErrorShapes(inputs), "PiRLC error term shape mismatch")

        transcript.absorbLabel("PiRLC_k=\(k)")
        absorb(inputs: inputs, into: &transcript)

        // Compute cross-terms T_j for j = 1..k-1
        var crossTerms = [[RingElement]]()
        for j in 1..<k {
            var cross = [RingElement]()
            let w0 = inputs[0].witness
            let wj = inputs[j].witness
            for idx in 0..<min(w0.count, wj.count) {
                cross.append(w0[idx] * wj[idx])
            }
            crossTerms.append(cross)
        }

        let crossCommitments = crossTerms.map { terms in
            AjtaiCommitter.commit(key: key, witness: terms)
        }

        for cc in crossCommitments {
            transcript.absorb(ring: cc.value)
        }

        // Sample ring challenges from C = {-1, 0, 1, 2}
        let ringChallenges: [RingElement] = (0..<k).map { _ in
            NuSampler.challengeRingFromC(transcript: &transcript)
        }

        let scalarChallenges = deriveScalarChallenges(
            transcript: &transcript,
            count: k
        )

        // Fold: linear combination with ring challenges
        let witnessLen = inputs[0].witness.count
        var foldedWitness = [RingElement](repeating: .zero, count: witnessLen)
        var foldedCommitmentRing = RingElement.zero
        var foldedPI = [Fq](repeating: .zero, count: inputs[0].publicInputs.count)
        var foldedEvaluations = [Fq](repeating: .zero, count: inputs[0].ccsEvaluations.count)
        var foldedU = Fq.zero

        for i in 0..<k {
            let rho = ringChallenges[i]
            let rhoScalar = scalarChallenges[i]
            for j in 0..<witnessLen {
                foldedWitness[j] += rho * inputs[i].witness[j]
            }
            foldedCommitmentRing += rho * inputs[i].commitment.value
            for j in 0..<foldedPI.count {
                foldedPI[j] += rhoScalar * inputs[i].publicInputs[j]
            }
            for j in 0..<foldedEvaluations.count {
                foldedEvaluations[j] += rhoScalar * inputs[i].ccsEvaluations[j]
            }
            foldedU += rhoScalar * inputs[i].relaxationFactor
        }

        let foldedError = foldErrorTerms(
            inputs: inputs,
            crossTerms: crossTerms,
            ringChallenges: ringChallenges
        )

        return Output(
            foldedCommitment: AjtaiCommitment(value: foldedCommitmentRing),
            foldedWitness: foldedWitness,
            foldedPublicInputs: foldedPI,
            foldedEvaluations: foldedEvaluations,
            foldedRelaxation: foldedU,
            foldedError: foldedError,
            crossTermCommitments: crossCommitments,
            ringChallenges: ringChallenges
        )
    }

    /// Metal-backed PiRLC prover.
    ///
    /// Cross-term commitments stay on the canonical Fq4 commitment path so the
    /// Metal prover cannot diverge from the certified ring arithmetic contract.
    public static func proveMetal(
        inputs: [Input],
        key: AjtaiKey,
        transcript: inout NuTranscriptField,
        context: MetalContext
    ) async throws -> Output {
        let k = inputs.count
        precondition(k >= 2, "PiRLC requires at least 2 instances")
        precondition(hasCompatibleErrorShapes(inputs), "PiRLC error term shape mismatch")

        transcript.absorbLabel("PiRLC_k=\(k)")
        absorb(inputs: inputs, into: &transcript)

        var crossTerms = [[RingElement]]()
        for j in 1..<k {
            var cross = [RingElement]()
            let w0 = inputs[0].witness
            let wj = inputs[j].witness
            for idx in 0..<min(w0.count, wj.count) {
                cross.append(w0[idx] * wj[idx])
            }
            crossTerms.append(cross)
        }

        var crossCommitments = [AjtaiCommitment]()
        crossCommitments.reserveCapacity(crossTerms.count)
        for terms in crossTerms {
            let commitment = try await AjtaiCommitter.commitMetal(
                context: context,
                key: key,
                witness: terms
            )
            crossCommitments.append(commitment)
            transcript.absorb(ring: commitment.value)
        }

        let ringChallenges: [RingElement] = (0..<k).map { _ in
            NuSampler.challengeRingFromC(transcript: &transcript)
        }
        let scalarChallenges = deriveScalarChallenges(
            transcript: &transcript,
            count: k
        )

        let witnessLen = inputs[0].witness.count
        var foldedWitness = [RingElement](repeating: .zero, count: witnessLen)
        var foldedCommitmentRing = RingElement.zero
        var foldedPI = [Fq](repeating: .zero, count: inputs[0].publicInputs.count)
        var foldedEvaluations = [Fq](repeating: .zero, count: inputs[0].ccsEvaluations.count)
        var foldedU = Fq.zero

        for i in 0..<k {
            let rho = ringChallenges[i]
            let rhoScalar = scalarChallenges[i]
            for j in 0..<witnessLen {
                foldedWitness[j] += rho * inputs[i].witness[j]
            }
            foldedCommitmentRing += rho * inputs[i].commitment.value
            for j in 0..<foldedPI.count {
                foldedPI[j] += rhoScalar * inputs[i].publicInputs[j]
            }
            for j in 0..<foldedEvaluations.count {
                foldedEvaluations[j] += rhoScalar * inputs[i].ccsEvaluations[j]
            }
            foldedU += rhoScalar * inputs[i].relaxationFactor
        }

        let foldedError = foldErrorTerms(
            inputs: inputs,
            crossTerms: crossTerms,
            ringChallenges: ringChallenges
        )

        return Output(
            foldedCommitment: AjtaiCommitment(value: foldedCommitmentRing),
            foldedWitness: foldedWitness,
            foldedPublicInputs: foldedPI,
            foldedEvaluations: foldedEvaluations,
            foldedRelaxation: foldedU,
            foldedError: foldedError,
            crossTermCommitments: crossCommitments,
            ringChallenges: ringChallenges
        )
    }

    /// Verify PiRLC folding (verifier side).
    public static func verify(
        inputs: [Input],
        output: Output,
        key: AjtaiKey,
        transcript: inout NuTranscriptField
    ) -> Bool {
        let k = inputs.count
        guard k >= 2 else { return false }
        guard allInputsShareShape(inputs) else { return false }
        guard hasCompatibleErrorShapes(inputs) else { return false }
        transcript.absorbLabel("PiRLC_k=\(k)")
        absorb(inputs: inputs, into: &transcript)

        let crossTerms = computeCrossTerms(inputs: inputs)
        let expectedCrossCommitments = crossTerms.map { terms in
            AjtaiCommitter.commit(key: key, witness: terms)
        }
        guard output.crossTermCommitments == expectedCrossCommitments else { return false }

        for commitment in expectedCrossCommitments {
            transcript.absorb(ring: commitment.value)
        }

        let ringChallenges: [RingElement] = (0..<k).map { _ in
            NuSampler.challengeRingFromC(transcript: &transcript)
        }
        guard ringChallenges == output.ringChallenges else { return false }

        let scalarChallenges = deriveScalarChallenges(
            transcript: &transcript,
            count: k
        )
        let expected = fold(
            inputs: inputs,
            crossTerms: crossTerms,
            ringChallenges: ringChallenges,
            scalarChallenges: scalarChallenges
        )
        return output.foldedCommitment == expected.foldedCommitment
            && output.foldedWitness == expected.foldedWitness
            && output.foldedPublicInputs == expected.foldedPublicInputs
            && output.foldedEvaluations == expected.foldedEvaluations
            && output.foldedRelaxation == expected.foldedRelaxation
            && output.foldedError == expected.foldedError
    }

    public static func verifyMetal(
        inputs: [Input],
        output: Output,
        key: AjtaiKey,
        transcript: inout NuTranscriptField,
        context: MetalContext
    ) throws -> Bool {
        try verifyMetal(
            inputs: inputs,
            output: output,
            key: key,
            transcript: &transcript,
            context: context,
            trace: nil
        )
    }

    package static func verifyMetal(
        inputs: [Input],
        output: Output,
        key: AjtaiKey,
        transcript: inout NuTranscriptField,
        context: MetalContext,
        trace: MetalTraceCollector?
    ) throws -> Bool {
        let k = inputs.count
        guard k >= 2 else { return false }
        guard allInputsShareShape(inputs) else { return false }
        guard hasCompatibleErrorShapes(inputs) else { return false }

        transcript.absorbLabel("PiRLC_k=\(k)")
        absorb(inputs: inputs, into: &transcript)

        let crossTerms = try computeCrossTermsMetal(inputs: inputs, context: context, trace: trace)
        let expectedCrossCommitments = try AjtaiCommitter.commitBatchMetal(
            context: context,
            key: key,
            witnessBatches: crossTerms,
            trace: trace.map {
                TimedDispatchTraceContext(
                    collector: $0,
                    stage: "piRLC",
                    iteration: $0.defaultIteration,
                    dispatchLabel: "piRLC.cross_term_commit_batch"
                )
            }
        )
        guard output.crossTermCommitments == expectedCrossCommitments else { return false }

        for commitment in expectedCrossCommitments {
            transcript.absorb(ring: commitment.value)
        }

        let ringChallenges: [RingElement] = (0..<k).map { _ in
            NuSampler.challengeRingFromC(transcript: &transcript)
        }
        guard ringChallenges == output.ringChallenges else { return false }

        let scalarChallenges = deriveScalarChallenges(
            transcript: &transcript,
            count: k
        )
        let foldedWitness = try AG64RingMetal.bindFold(
            context: context,
            challengeRings: ringChallenges,
            inputs: inputs.map(\.witness),
            ringCount: inputs[0].witness.count,
            trace: trace.map {
                TimedDispatchTraceContext(
                    collector: $0,
                    stage: "piRLC",
                    iteration: $0.defaultIteration,
                    dispatchLabel: "piRLC.fold_witness"
                )
            }
        )
        let foldedCommitment = try AG64RingMetal.bindFold(
            context: context,
            challengeRings: ringChallenges,
            inputs: inputs.map { [$0.commitment.value] },
            ringCount: 1,
            trace: trace.map {
                TimedDispatchTraceContext(
                    collector: $0,
                    stage: "piRLC",
                    iteration: $0.defaultIteration,
                    dispatchLabel: "piRLC.fold_commitment"
                )
            }
        )[0]

        var foldedPublicInputs = [Fq](repeating: .zero, count: inputs[0].publicInputs.count)
        var foldedEvaluations = [Fq](repeating: .zero, count: inputs[0].ccsEvaluations.count)
        var foldedRelaxation = Fq.zero
        for index in 0..<k {
            let rhoScalar = scalarChallenges[index]
            for publicInputIndex in 0..<foldedPublicInputs.count {
                foldedPublicInputs[publicInputIndex] += rhoScalar * inputs[index].publicInputs[publicInputIndex]
            }
            for evaluationIndex in 0..<foldedEvaluations.count {
                foldedEvaluations[evaluationIndex] += rhoScalar * inputs[index].ccsEvaluations[evaluationIndex]
            }
            foldedRelaxation += rhoScalar * inputs[index].relaxationFactor
        }

        let foldedError = foldErrorTerms(
            inputs: inputs,
            crossTerms: crossTerms,
            ringChallenges: ringChallenges
        )

        return output.foldedCommitment == AjtaiCommitment(value: foldedCommitment)
            && output.foldedWitness == foldedWitness
            && output.foldedPublicInputs == foldedPublicInputs
            && output.foldedEvaluations == foldedEvaluations
            && output.foldedRelaxation == foldedRelaxation
            && output.foldedError == foldedError
    }

    private static func allInputsShareShape(_ inputs: [Input]) -> Bool {
        guard let first = inputs.first else { return false }
        let witnessCount = first.witness.count
        let publicInputCount = first.publicInputs.count
        let evaluationCount = first.ccsEvaluations.count

        return inputs.dropFirst().allSatisfy {
            $0.witness.count == witnessCount
                && $0.publicInputs.count == publicInputCount
                && $0.ccsEvaluations.count == evaluationCount
        }
    }

    private static func hasCompatibleErrorShapes(_ inputs: [Input]) -> Bool {
        let nonEmptyCounts = Set(inputs.map(\.errorTerms.count).filter { $0 > 0 })
        return nonEmptyCounts.count <= 1
    }

    private static func absorb(
        inputs: [Input],
        into transcript: inout NuTranscriptField
    ) {
        for input in inputs {
            transcript.absorb(ring: input.commitment.value)
            for pi in input.publicInputs {
                transcript.absorb(field: pi)
            }
            for evaluation in input.ccsEvaluations {
                transcript.absorb(field: evaluation)
            }
            transcript.absorb(field: input.relaxationFactor)
            for errorTerm in input.errorTerms {
                transcript.absorb(ring: errorTerm)
            }
        }
    }

    private static func computeCrossTerms(inputs: [Input]) -> [[RingElement]] {
        let k = inputs.count
        guard k >= 2 else { return [] }

        return (1..<k).map { j in
            let w0 = inputs[0].witness
            let wj = inputs[j].witness
            return (0..<min(w0.count, wj.count)).map { index in
                w0[index] * wj[index]
            }
        }
    }

    private static func computeCrossTermsMetal(
        inputs: [Input],
        context: MetalContext
    ) throws -> [[RingElement]] {
        try computeCrossTermsMetal(inputs: inputs, context: context, trace: nil)
    }

    private static func computeCrossTermsMetal(
        inputs: [Input],
        context: MetalContext,
        trace: MetalTraceCollector?
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

        let products = try AG64RingMetal.multiplyBatch(
            context: context,
            lhs: lhs,
            rhs: rhs,
            trace: trace.map {
                TimedDispatchTraceContext(
                    collector: $0,
                    stage: "piRLC",
                    iteration: $0.defaultIteration,
                    dispatchLabel: "piRLC.cross_terms"
                )
            }
        )
        return spans.map { Array(products[$0]) }
    }

    private static func fold(
        inputs: [Input],
        crossTerms: [[RingElement]],
        ringChallenges: [RingElement],
        scalarChallenges: [Fq]
    ) -> (
        foldedCommitment: AjtaiCommitment,
        foldedWitness: [RingElement],
        foldedPublicInputs: [Fq],
        foldedEvaluations: [Fq],
        foldedRelaxation: Fq,
        foldedError: [RingElement]
    ) {
        let witnessLen = inputs[0].witness.count
        var foldedWitness = [RingElement](repeating: .zero, count: witnessLen)
        var foldedCommitmentRing = RingElement.zero
        var foldedPI = [Fq](repeating: .zero, count: inputs[0].publicInputs.count)
        var foldedEvaluations = [Fq](repeating: .zero, count: inputs[0].ccsEvaluations.count)
        var foldedU = Fq.zero

        for i in 0..<inputs.count {
            let rho = ringChallenges[i]
            let rhoScalar = scalarChallenges[i]
            for j in 0..<witnessLen {
                foldedWitness[j] += rho * inputs[i].witness[j]
            }
            foldedCommitmentRing += rho * inputs[i].commitment.value
            for j in 0..<foldedPI.count {
                foldedPI[j] += rhoScalar * inputs[i].publicInputs[j]
            }
            for j in 0..<foldedEvaluations.count {
                foldedEvaluations[j] += rhoScalar * inputs[i].ccsEvaluations[j]
            }
            foldedU += rhoScalar * inputs[i].relaxationFactor
        }

        return (
            foldedCommitment: AjtaiCommitment(value: foldedCommitmentRing),
            foldedWitness: foldedWitness,
            foldedPublicInputs: foldedPI,
            foldedEvaluations: foldedEvaluations,
            foldedRelaxation: foldedU,
            foldedError: foldErrorTerms(
                inputs: inputs,
                crossTerms: crossTerms,
                ringChallenges: ringChallenges
            )
        )
    }

    private static func deriveScalarChallenges(
        transcript: inout NuTranscriptField,
        count: Int
    ) -> [Fq] {
        // Field-valued claims need full-field Fiat-Shamir challenges rather than
        // a 2-bit projection of the weak ring-fold challenge set.
        transcript.challengeVector(domain: "PiRLC.scalar_fold", count: count)
    }

    private static func foldErrorTerms(
        inputs: [Input],
        crossTerms: [[RingElement]],
        ringChallenges: [RingElement]
    ) -> [RingElement] {
        let inheritedLength = inputs.map(\.errorTerms.count).max() ?? 0
        let crossTermLength = crossTerms.map(\.count).max() ?? 0
        let foldedLength = max(inheritedLength, crossTermLength)
        guard foldedLength > 0 else {
            return []
        }

        var foldedError = [RingElement](repeating: .zero, count: foldedLength)

        for (inputIndex, input) in inputs.enumerated() {
            let rho = ringChallenges[inputIndex]
            for errorIndex in input.errorTerms.indices {
                foldedError[errorIndex] += rho * input.errorTerms[errorIndex]
            }
        }

        for crossIndex in crossTerms.indices {
            let rho = ringChallenges[crossIndex + 1]
            for errorIndex in crossTerms[crossIndex].indices {
                foldedError[errorIndex] += rho * crossTerms[crossIndex][errorIndex]
            }
        }

        return foldedError
    }
}
