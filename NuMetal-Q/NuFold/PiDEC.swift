import Metal

// MARK: - PiDEC: Decomposition Stage
// Third SuperNeo transcript stage.
// ΠDEC is the final norm-reduction step that resets the claim norm
// from B = b^k back to b by decomposing accumulated witness ring elements.
//
// This is where SuperNeo's multi-folding amortizes decomposition costs.

/// PiDEC protocol stage: norm decomposition.
///
/// When the accumulated witness norm exceeds the budget, PiDEC
/// decomposes each centered ring coefficient into bounded limbs and proves
/// that the decomposition is correct via a commitment check.
public struct PiDEC: Sendable {

    public struct Input: Sendable {
        public let witness: [RingElement]
        public let commitment: AjtaiCommitment
        public let key: AjtaiKey
        public let decompBase: UInt8
        public let decompLimbs: UInt8

        public init(
            witness: [RingElement],
            commitment: AjtaiCommitment,
            key: AjtaiKey,
            decompBase: UInt8,
            decompLimbs: UInt8
        ) {
            self.witness = witness
            self.commitment = commitment
            self.key = key
            self.decompBase = decompBase
            self.decompLimbs = decompLimbs
        }
    }

    public struct Output: Sendable, Codable, Equatable {
        /// Decomposed witness: for each original ring element, its limbs.
        public let decomposedWitness: [[RingElement]]
        /// Commitments to each decomposition limb vector.
        public let limbCommitments: [AjtaiCommitment]
        /// Proof that decomposition is consistent.
        public let consistencyProof: DecompConsistencyProof

        public init(
            decomposedWitness: [[RingElement]],
            limbCommitments: [AjtaiCommitment],
            consistencyProof: DecompConsistencyProof
        ) {
            self.decomposedWitness = decomposedWitness
            self.limbCommitments = limbCommitments
            self.consistencyProof = consistencyProof
        }
    }

    public static func prove(
        input: Input,
        transcript: inout NuTranscriptField
    ) -> Output {
        transcript.absorbLabel("PiDEC_base=\(input.decompBase)_limbs=\(input.decompLimbs)")
        transcript.absorb(ring: input.commitment.value)

        var allDecomposed = [[RingElement]]()
        var limbVectors = [[RingElement]]()

        for _ in 0..<Int(input.decompLimbs) {
            limbVectors.append([RingElement]())
        }

        for element in input.witness {
            let decomp = Decomposition.decompose(
                element: element,
                base: input.decompBase,
                numLimbs: input.decompLimbs
            )
            allDecomposed.append(decomp.limbs)
            for (l, limb) in decomp.limbs.enumerated() {
                limbVectors[l].append(limb)
            }
        }

        // Commit to each limb vector
        var limbCommitments = [AjtaiCommitment]()
        for limbVec in limbVectors {
            let comm = AjtaiCommitter.commit(key: input.key, witness: limbVec)
            limbCommitments.append(comm)
            transcript.absorb(ring: comm.value)
        }

        let challenge = transcript.squeezeChallenge()

        // Consistency check: prove that Σ_l b^l · limbCommitment[l] == original commitment
        let B = Fq(UInt64(input.decompBase))
        var reconstructedComm = RingElement.zero
        var power = Fq.one
        for comm in limbCommitments {
            reconstructedComm += power * comm.value
            power *= B
        }

        let consistencyProof = DecompConsistencyProof(
            challenge: challenge,
            reconstructedCommitment: AjtaiCommitment(value: reconstructedComm)
        )

        return Output(
            decomposedWitness: allDecomposed,
            limbCommitments: limbCommitments,
            consistencyProof: consistencyProof
        )
    }

    /// Metal-backed PiDEC prover.
    ///
    /// The centered coefficient decomposition is performed on GPU and limb commitments use
    /// the Metal sparse-rotation path so the full stage can be checked against the
    /// CPU reference implementation.
    public static func proveMetal(
        input: Input,
        transcript: inout NuTranscriptField,
        context: MetalContext
    ) async throws -> Output {
        transcript.absorbLabel("PiDEC_base=\(input.decompBase)_limbs=\(input.decompLimbs)")
        transcript.absorb(ring: input.commitment.value)

        let allDecomposed = try decomposeWitnessMetal(
            witness: input.witness,
            decompBase: input.decompBase,
            decompLimbs: input.decompLimbs,
            context: context
        )
        var limbVectors = Array(repeating: [RingElement](), count: Int(input.decompLimbs))
        for limbs in allDecomposed {
            guard limbs.count == Int(input.decompLimbs) else {
                throw NuMetalError.executionFailed
            }
            for (index, limb) in limbs.enumerated() {
                limbVectors[index].append(limb)
            }
        }

        var limbCommitments = [AjtaiCommitment]()
        limbCommitments.reserveCapacity(limbVectors.count)
        for limbVec in limbVectors {
            let commitment = try await AjtaiCommitter.commitMetal(
                context: context,
                key: input.key,
                witness: limbVec
            )
            limbCommitments.append(commitment)
            transcript.absorb(ring: commitment.value)
        }

        let challenge = transcript.squeezeChallenge()
        let baseElement = Fq(UInt64(input.decompBase))
        var reconstructed = RingElement.zero
        var power = Fq.one
        for commitment in limbCommitments {
            reconstructed += power * commitment.value
            power *= baseElement
        }

        return Output(
            decomposedWitness: allDecomposed,
            limbCommitments: limbCommitments,
            consistencyProof: DecompConsistencyProof(
                challenge: challenge,
                reconstructedCommitment: AjtaiCommitment(value: reconstructed)
            )
        )
    }

    public static func verifyMetal(
        input: Input,
        output: Output,
        transcript: inout NuTranscriptField,
        context: MetalContext
    ) throws -> Bool {
        try verifyMetal(
            input: input,
            output: output,
            transcript: &transcript,
            context: context,
            trace: nil
        )
    }

    package static func verifyMetal(
        input: Input,
        output: Output,
        transcript: inout NuTranscriptField,
        context: MetalContext,
        trace: MetalTraceCollector?
    ) throws -> Bool {
        guard output.decomposedWitness.count == input.witness.count else { return false }
        guard output.limbCommitments.count == Int(input.decompLimbs) else { return false }

        transcript.absorbLabel("PiDEC_base=\(input.decompBase)_limbs=\(input.decompLimbs)")
        transcript.absorb(ring: input.commitment.value)

        let expectedDecomposition = try decomposeWitnessMetal(
            witness: input.witness,
            decompBase: input.decompBase,
            decompLimbs: input.decompLimbs,
            context: context,
            trace: trace
        )
        guard output.decomposedWitness == expectedDecomposition else { return false }

        var limbVectors = Array(repeating: [RingElement](), count: Int(input.decompLimbs))
        for limbs in output.decomposedWitness {
            guard limbs.count == Int(input.decompLimbs) else { return false }
            for (index, limb) in limbs.enumerated() {
                guard limb.coeffs.allSatisfy({ $0.centeredMagnitude < UInt64(input.decompBase) }) else {
                    return false
                }
                limbVectors[index].append(limb)
            }
        }

        let expectedCommitments = try AjtaiCommitter.commitBatchMetal(
            context: context,
            key: input.key,
            witnessBatches: limbVectors,
            trace: trace.map {
                TimedDispatchTraceContext(
                    collector: $0,
                    stage: "piDEC",
                    iteration: $0.defaultIteration,
                    dispatchLabel: "piDEC.limb_commit_batch"
                )
            }
        )
        guard output.limbCommitments == expectedCommitments else { return false }

        for commitment in expectedCommitments {
            transcript.absorb(ring: commitment.value)
        }

        let challenge = transcript.squeezeChallenge()
        guard challenge == output.consistencyProof.challenge else { return false }

        let challengeRings = scalarChallengeRings(
            base: Fq(UInt64(input.decompBase)),
            count: expectedCommitments.count
        )
        let reconstructed = try AG64RingMetal.bindFold(
            context: context,
            challengeRings: challengeRings,
            inputs: expectedCommitments.map { [$0.value] },
            ringCount: 1,
            trace: trace.map {
                TimedDispatchTraceContext(
                    collector: $0,
                    stage: "piDEC",
                    iteration: $0.defaultIteration,
                    dispatchLabel: "piDEC.reconstruct_commitment"
                )
            }
        )[0]

        let reconstructedCommitment = AjtaiCommitment(value: reconstructed)
        guard reconstructedCommitment == output.consistencyProof.reconstructedCommitment else {
            return false
        }
        return reconstructedCommitment == input.commitment
    }

    public static func verify(
        input: Input,
        output: Output,
        transcript: inout NuTranscriptField
    ) -> Bool {
        guard output.decomposedWitness.count == input.witness.count else { return false }
        guard output.limbCommitments.count == Int(input.decompLimbs) else { return false }

        transcript.absorbLabel("PiDEC_base=\(input.decompBase)_limbs=\(input.decompLimbs)")
        transcript.absorb(ring: input.commitment.value)

        let expectedDecomposition = input.witness.map {
            Decomposition.decompose(
                element: $0,
                base: input.decompBase,
                numLimbs: input.decompLimbs
            ).limbs
        }
        guard output.decomposedWitness == expectedDecomposition else { return false }

        var limbVectors = Array(repeating: [RingElement](), count: Int(input.decompLimbs))
        for limbs in output.decomposedWitness {
            guard limbs.count == Int(input.decompLimbs) else { return false }
            for (index, limb) in limbs.enumerated() {
                guard limb.coeffs.allSatisfy({ $0.centeredMagnitude < UInt64(input.decompBase) }) else {
                    return false
                }
                limbVectors[index].append(limb)
            }
        }

        let expectedCommitments = limbVectors.map { AjtaiCommitter.commit(key: input.key, witness: $0) }
        guard output.limbCommitments == expectedCommitments else { return false }

        for commitment in expectedCommitments {
            transcript.absorb(ring: commitment.value)
        }

        let challenge = transcript.squeezeChallenge()
        guard challenge == output.consistencyProof.challenge else { return false }

        let B = Fq(UInt64(input.decompBase))
        var reconstructed = RingElement.zero
        var power = Fq.one
        for commitment in expectedCommitments {
            reconstructed += power * commitment.value
            power *= B
        }

        let reconstructedCommitment = AjtaiCommitment(value: reconstructed)
        guard reconstructedCommitment == output.consistencyProof.reconstructedCommitment else {
            return false
        }

        return reconstructedCommitment == input.commitment
    }

    private static func scalarChallengeRings(base: Fq, count: Int) -> [RingElement] {
        var rings = [RingElement]()
        rings.reserveCapacity(count)
        var power = Fq.one
        for _ in 0..<count {
            rings.append(RingElement(constant: power))
            power *= base
        }
        return rings
    }

    private static func decomposeWitnessMetal(
        witness: [RingElement],
        decompBase: UInt8,
        decompLimbs: UInt8,
        context: MetalContext
    ) throws -> [[RingElement]] {
        try decomposeWitnessMetal(
            witness: witness,
            decompBase: decompBase,
            decompLimbs: decompLimbs,
            context: context,
            trace: nil
        )
    }

    private static func decomposeWitnessMetal(
        witness: [RingElement],
        decompBase: UInt8,
        decompLimbs: UInt8,
        context: MetalContext,
        trace: MetalTraceCollector?
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
            if let trace {
                _ = try dispatcher.dispatchDecomposeTimed(
                    inputBuffer: inputBuffer,
                    outputBuffer: outputBuffer,
                    paramsBuffer: paramsBuffer,
                    numElements: valueCount,
                    decompBase: decompBase,
                    numLimbs: decompLimbs,
                    trace: TimedDispatchTraceContext(
                        collector: trace,
                        stage: "piDEC",
                        iteration: trace.defaultIteration,
                        dispatchLabel: "piDEC.decompose"
                    )
                )
            } else {
                try dispatcher.dispatchDecompose(
                    inputBuffer: inputBuffer,
                    outputBuffer: outputBuffer,
                    paramsBuffer: paramsBuffer,
                    numElements: valueCount,
                    decompBase: decompBase,
                    numLimbs: decompLimbs
                )
            }

            let outputPointer = outputBuffer.typedContents(
                as: UInt32.self,
                capacity: valueCount * Int(decompLimbs) * 2
            )

            let ringCount = witness.count
            let coeffsPerRing = RingElement.degree
            let totalValueCount = valueCount * Int(decompLimbs)
            return (0..<ringCount).map { ringIndex in
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
}

/// Proof that decomposition is consistent with the original commitment.
public struct DecompConsistencyProof: Sendable, Codable, Equatable {
    public let challenge: Fq
    public let reconstructedCommitment: AjtaiCommitment
}
