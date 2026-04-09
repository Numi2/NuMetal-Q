import Metal

// MARK: - PiCCS: Strong Interactive CCS Reduction
// First of the three SuperNeo transcript stages.
// ΠCCS is the STRONG interactive reduction that uses sum-check-style work
// to reduce CCS and CE claims into CE claims.
//
// Given a folded CCS instance with matrices M₁..Mₜ, gates, and
// accumulated witness w, PiCCS reduces the m-constraint check to
// a single inner-product check by sampling a random vector τ ∈ Fq^m
// and running a sum-check over the linearized relation.

/// PiCCS protocol stage: strong CCS reduction via sum-check.
///
/// Given a CCS relation with m constraints, PiCCS reduces the multi-matrix
/// check to a single inner-product relation via random τ sampling and
/// sum-check compression.
public struct PiCCS: Sendable {

    public struct Input: Sendable {
        public let relation: CCSRelation
        public let publicInputs: [Fq]
        public let witness: [Fq]
        public let relaxationFactor: Fq

        public init(
            relation: CCSRelation,
            publicInputs: [Fq],
            witness: [Fq],
            relaxationFactor: Fq
        ) {
            self.relation = relation
            self.publicInputs = publicInputs
            self.witness = witness
            self.relaxationFactor = relaxationFactor
        }
    }

    public struct Output: Sendable, Codable, Equatable {
        /// The evaluated multilinear polynomials at the random point.
        public let evaluations: [Fq]
        /// The random challenges used.
        public let challenges: [Fq]
        /// Sum-check proof for the linearized relation.
        public let sumCheckProof: SumCheckProof

        public init(
            evaluations: [Fq],
            challenges: [Fq],
            sumCheckProof: SumCheckProof
        ) {
            self.evaluations = evaluations
            self.challenges = challenges
            self.sumCheckProof = sumCheckProof
        }
    }

    /// Execute PiCCS prover.
    public static func prove(
        input: Input,
        transcript: inout NuTranscriptField
    ) -> Output {
        let m = input.relation.m
        transcript.absorbLabel("PiCCS_m=\(m)")
        bindStatement(input, transcript: &transcript)

        let tau = transcript.squeezeChallenges(count: m)
        let poly = linearizedPolynomial(for: input, tau: tau)
        let sumCheckProof = SumCheck.prove(polynomial: poly, transcript: &transcript)
        let evaluations = projectedMatrixEvaluations(for: input, tau: tau)

        return Output(
            evaluations: evaluations,
            challenges: tau,
            sumCheckProof: sumCheckProof
        )
    }

    /// Metal-backed PiCCS prover.
    ///
    /// The multilinear sum-check reduction runs through the GPU partial-sum
    /// kernel while relation evaluation and transcript plumbing remain identical
    /// to the CPU reference path.
    public static func proveMetal(
        input: Input,
        transcript: inout NuTranscriptField,
        context: MetalContext
    ) async throws -> Output {
        let m = input.relation.m
        transcript.absorbLabel("PiCCS_m=\(m)")
        bindStatement(input, transcript: &transcript)

        let tau = transcript.squeezeChallenges(count: m)
        let matrixEvaluations = try metalMatrixEvaluations(for: input, context: context)
        let poly = linearizedPolynomial(for: input, tau: tau, matrixEvaluations: matrixEvaluations)
        let sumCheckProof = try await SumCheck.proveMetal(
            polynomial: poly,
            transcript: &transcript,
            context: context
        )
        let evaluations = projectedMatrixEvaluations(
            for: input,
            tau: tau,
            matrixEvaluations: matrixEvaluations
        )

        return Output(
            evaluations: evaluations,
            challenges: tau,
            sumCheckProof: sumCheckProof
        )
    }

    /// Verify PiCCS.
    public static func verify(
        input: Input,
        output: Output,
        transcript: inout NuTranscriptField
    ) -> Bool {
        let m = input.relation.m
        transcript.absorbLabel("PiCCS_m=\(m)")
        bindStatement(input, transcript: &transcript)

        let tau = transcript.squeezeChallenges(count: m)
        guard tau == output.challenges else { return false }
        guard output.evaluations == projectedMatrixEvaluations(for: input, tau: tau) else { return false }

        let numVars = ceilLog2(m)
        let poly = linearizedPolynomial(for: input, tau: tau)
        guard poly.evals.reduce(.zero, +).isZero else { return false }
        guard SumCheck.verify(
            proof: output.sumCheckProof,
            numVars: numVars,
            claimedSum: .zero,
            transcript: &transcript
        ) else {
            return false
        }

        return poly.evaluate(at: output.sumCheckProof.challengePoint) == output.sumCheckProof.finalEvaluation
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
        let m = input.relation.m
        transcript.absorbLabel("PiCCS_m=\(m)")
        bindStatement(input, transcript: &transcript)

        let tau = transcript.squeezeChallenges(count: m)
        guard tau == output.challenges else { return false }

        let matrixEvaluations = try metalMatrixEvaluations(for: input, context: context, trace: trace)
        guard output.evaluations == projectedMatrixEvaluations(
            for: input,
            tau: tau,
            matrixEvaluations: matrixEvaluations
        ) else {
            return false
        }

        let numVars = ceilLog2(m)
        let poly = linearizedPolynomial(for: input, tau: tau, matrixEvaluations: matrixEvaluations)
        guard poly.evals.reduce(.zero, +).isZero else { return false }
        guard SumCheck.verify(
            proof: output.sumCheckProof,
            numVars: numVars,
            claimedSum: .zero,
            transcript: &transcript
        ) else {
            return false
        }

        return poly.evaluate(at: output.sumCheckProof.challengePoint) == output.sumCheckProof.finalEvaluation
    }

    private static func fullAssignment(for input: Input) -> [Fq] {
        precondition(input.witness.count + input.relation.nPublic == input.relation.n)

        var publicSlice = Array(input.publicInputs.prefix(input.relation.nPublic))
        if publicSlice.count < input.relation.nPublic {
            publicSlice.append(
                contentsOf: [Fq](repeating: .zero, count: input.relation.nPublic - publicSlice.count)
            )
        }

        return publicSlice + input.witness
    }

    private static func bindStatement(
        _ input: Input,
        transcript: inout NuTranscriptField
    ) {
        transcript.absorbLabel("PiCCS.statement.v1")
        transcript.absorb(field: Fq(UInt64(input.relation.m)))
        transcript.absorb(field: Fq(UInt64(input.relation.n)))
        transcript.absorb(field: Fq(UInt64(input.relation.nPublic)))
        transcript.absorb(field: Fq(UInt64(input.relation.matrices.count)))
        for matrix in input.relation.matrices {
            transcript.absorb(field: Fq(UInt64(matrix.rows)))
            transcript.absorb(field: Fq(UInt64(matrix.cols)))
            transcript.absorb(field: Fq(UInt64(matrix.rowPtr.count)))
            for value in matrix.rowPtr {
                transcript.absorb(field: Fq(UInt64(value)))
            }
            transcript.absorb(field: Fq(UInt64(matrix.colIdx.count)))
            for value in matrix.colIdx {
                transcript.absorb(field: Fq(UInt64(value)))
            }
            transcript.absorb(domain: "matrix.values", scalars: matrix.values)
        }
        transcript.absorb(field: Fq(UInt64(input.relation.gates.count)))
        for gate in input.relation.gates {
            transcript.absorb(field: gate.coefficientField)
            transcript.absorb(field: Fq(UInt64(gate.matrixIndices.count)))
            for index in gate.matrixIndices {
                transcript.absorb(field: Fq(UInt64(index)))
            }
        }
        transcript.absorb(domain: "publicInputs", scalars: input.publicInputs)
        transcript.absorb(domain: "witness", scalars: input.witness)
        transcript.absorb(domain: "relaxationFactor", scalar: input.relaxationFactor)
    }

    private static func linearizedPolynomial(
        for input: Input,
        tau: [Fq],
        matrixEvaluations: [[Fq]]? = nil
    ) -> MultilinearPoly {
        let m = input.relation.m
        let z = fullAssignment(for: input)
        let numVars = ceilLog2(m)

        let matrixEvaluations = matrixEvaluations ?? input.relation.matrices.map { $0.matvec(z) }
        var evalTable = [Fq](repeating: .zero, count: 1 << numVars)
        for i in 0..<m {
            var gateSum = Fq.zero
            for gate in input.relation.gates {
                var hadamard = Fq.one
                for midx in gate.matrixIndices {
                    hadamard *= matrixEvaluations[Int(midx)][i]
                }
                gateSum += gate.coefficientField * hadamard
            }
            evalTable[i] = tau[i] * gateSum
        }

        return MultilinearPoly(numVars: numVars, evals: evalTable)
    }

    private static func projectedMatrixEvaluations(
        for input: Input,
        tau: [Fq],
        matrixEvaluations: [[Fq]]? = nil
    ) -> [Fq] {
        let m = input.relation.m
        let computed = matrixEvaluations ?? input.relation.matrices.map {
            $0.matvec(fullAssignment(for: input))
        }
        return computed.map { mv -> Fq in
            var acc = Fq.zero
            for i in 0..<min(m, mv.count) {
                acc += tau[i] * mv[i]
            }
            return acc
        }
    }

    static func metalMatrixEvaluations(
        for input: Input,
        context: MetalContext
    ) throws -> [[Fq]] {
        try metalMatrixEvaluations(for: input, context: context, trace: nil)
    }

    package static func metalMatrixEvaluations(
        for input: Input,
        context: MetalContext,
        trace: MetalTraceCollector?
    ) throws -> [[Fq]] {
        let z = fullAssignment(for: input)
        return try input.relation.matrices.enumerated().map { matrixIndex, matrix in
            if matrix.values.isEmpty {
                return [Fq](repeating: .zero, count: matrix.rows)
            }

            return try context.withTransientArena { arena in
                guard let xBuffer = arena.uploadFieldElements(z) else {
                    throw NuMetalError.heapCreationFailed
                }

                guard let rowPtrBuffer = arena.makeSharedSlice(
                        length: matrix.rowPtr.count * MemoryLayout<UInt32>.size
                      ),
                      let colIdxBuffer = arena.makeSharedSlice(
                        length: matrix.colIdx.count * MemoryLayout<UInt32>.size
                      ),
                      let valuesBuffer = arena.uploadFieldElements(matrix.values),
                      let paramsBuffer = arena.makeSharedSlice(
                        length: 3 * MemoryLayout<UInt32>.size
                      ),
                      let yBuffer = arena.makeSharedSlice(
                        length: matrix.rows * MemoryLayout<UInt32>.size * 2
                      ) else {
                    throw NuMetalError.heapCreationFailed
                }

                let rowPtrPointer = rowPtrBuffer.typedContents(as: UInt32.self, capacity: matrix.rowPtr.count)
                for (index, value) in matrix.rowPtr.enumerated() {
                    rowPtrPointer[index] = value
                }

                let colIdxPointer = colIdxBuffer.typedContents(as: UInt32.self, capacity: matrix.colIdx.count)
                for (index, value) in matrix.colIdx.enumerated() {
                    colIdxPointer[index] = value
                }

                let paramsPointer = paramsBuffer.typedContents(as: UInt32.self, capacity: 3)
                paramsPointer[0] = UInt32(matrix.rows)
                paramsPointer[1] = UInt32(matrix.values.count)
                paramsPointer[2] = UInt32(z.count)

                let dispatcher = KernelDispatcher(context: context)
                if let trace {
                    _ = try dispatcher.dispatchMatrixLiftTimed(
                        rowPtrBuffer: rowPtrBuffer,
                        colIdxBuffer: colIdxBuffer,
                        valuesBuffer: valuesBuffer,
                        xBuffer: xBuffer,
                        yBuffer: yBuffer,
                        paramsBuffer: paramsBuffer,
                        numRows: matrix.rows,
                        trace: TimedDispatchTraceContext(
                            collector: trace,
                            stage: "piCCS",
                            iteration: 0,
                            dispatchLabel: "piCCS.matrix_lift[\(matrixIndex)]"
                        )
                    )
                } else {
                    try dispatcher.dispatchMatrixLift(
                        rowPtrBuffer: rowPtrBuffer,
                        colIdxBuffer: colIdxBuffer,
                        valuesBuffer: valuesBuffer,
                        xBuffer: xBuffer,
                        yBuffer: yBuffer,
                        paramsBuffer: paramsBuffer,
                        numRows: matrix.rows
                    )
                }

                let resultPointer = yBuffer.typedContents(as: UInt32.self, capacity: matrix.rows * 2)
                let packed = Array(UnsafeBufferPointer(start: resultPointer, count: matrix.rows * 2))
                return MetalFieldPacking.unpackFieldElementsSoA(packed, count: matrix.rows)
            }
        }
    }
}

// MARK: - Sum-Check Protocol

/// Proof produced by the sum-check protocol.
public struct SumCheckProof: Sendable, Codable, Equatable {
    /// Round polynomials: for each variable, the univariate polynomial
    /// s_i(X) = Σ_{b ∈ {0,1}^{ν-i-1}} p(r₁,...,rᵢ₋₁, X, b_{i+1},...,b_ν)
    public let roundPolynomials: [[Fq]]  // each is degree+1 evaluations

    /// Challenge point derived from the transcript while proving the sum-check.
    public let challengePoint: [Fq]

    /// Final evaluation at the random point.
    public let finalEvaluation: Fq
}

/// Sum-check protocol implementation.
public enum SumCheck {

    /// Prove a sum-check for polynomial p over {0,1}^ν, claiming Σ p(x) = 0.
    public static func prove(
        polynomial: MultilinearPoly,
        transcript: inout NuTranscriptField
    ) -> SumCheckProof {
        var current = polynomial
        var rounds = [[Fq]]()
        var challengePoint = [Fq]()
        transcript.absorbLabel("sumcheck_start")

        for _ in 0..<polynomial.numVars {
            let half = current.evals.count / 2

            var s0 = Fq.zero
            var s1 = Fq.zero
            for j in 0..<half {
                s0 += current.evals[2 * j]
                s1 += current.evals[2 * j + 1]
            }

            let roundPoly = [s0, s1]
            rounds.append(roundPoly)

            transcript.absorb(field: s0)
            transcript.absorb(field: s1)
            let challenge = transcript.squeezeChallenge()
            challengePoint.append(challenge)

            current = current.bindFirst(to: challenge)
        }

        return SumCheckProof(
            roundPolynomials: rounds,
            challengePoint: challengePoint,
            finalEvaluation: current.evals[0]
        )
    }

    /// Metal-backed sum-check prover.
    public static func proveMetal(
        polynomial: MultilinearPoly,
        transcript: inout NuTranscriptField,
        context: MetalContext
    ) async throws -> SumCheckProof {
        var current = polynomial
        var rounds = [[Fq]]()
        var challengePoint = [Fq]()
        transcript.absorbLabel("sumcheck_start")

        for _ in 0..<polynomial.numVars {
            let (s0, s1) = try metalPartialSums(evals: current.evals, context: context)
            let roundPoly = [s0, s1]
            rounds.append(roundPoly)

            transcript.absorb(field: s0)
            transcript.absorb(field: s1)
            let challenge = transcript.squeezeChallenge()
            challengePoint.append(challenge)
            current = current.bindFirst(to: challenge)
        }

        return SumCheckProof(
            roundPolynomials: rounds,
            challengePoint: challengePoint,
            finalEvaluation: current.evals[0]
        )
    }

    /// Verify a sum-check proof.
    public static func verify(
        proof: SumCheckProof,
        numVars: Int,
        claimedSum: Fq,
        transcript: inout NuTranscriptField
    ) -> Bool {
        var expectedSum = claimedSum
        transcript.absorbLabel("sumcheck_start")
        guard proof.challengePoint.count == numVars else { return false }

        for round in 0..<numVars {
            guard round < proof.roundPolynomials.count else { return false }
            let rp = proof.roundPolynomials[round]
            guard rp.count >= 2 else { return false }

            let actualSum = rp[0] + rp[1]
            guard actualSum == expectedSum else { return false }

            transcript.absorb(field: rp[0])
            transcript.absorb(field: rp[1])
            let challenge = transcript.squeezeChallenge()
            guard challenge == proof.challengePoint[round] else { return false }

            expectedSum = rp[0] * (Fq.one - challenge) + rp[1] * challenge
        }

        return expectedSum == proof.finalEvaluation
    }

    static func metalPartialSums(
        evals: [Fq],
        context: MetalContext
    ) throws -> (Fq, Fq) {
        try context.withTransientArena { arena in
            let dispatcher = KernelDispatcher(context: context)
            var currentBuffer = try unwrapOrThrow(arena.uploadFieldElements(evals))
            var currentCount = evals.count
            let reductionWidth = max(1, min(SchedulerParams.production.threadgroupSize, context.maxThreadsPerThreadgroupWidth))

            while currentCount > 2 {
                let pairCount = currentCount / 2
                let reducedPairCount = max(1, (pairCount + reductionWidth - 1) / reductionWidth)
                let nextCount = max(2, reducedPairCount * 2)

                guard let paramsBuffer = arena.makeSharedSlice(length: 2 * MemoryLayout<UInt32>.size),
                      let outputBuffer = arena.makeSharedSlice(
                        length: nextCount * MemoryLayout<UInt32>.size * 2
                      ) else {
                    throw NuMetalError.heapCreationFailed
                }

                let paramsPointer = paramsBuffer.typedContents(as: UInt32.self, capacity: 2)
                paramsPointer[0] = UInt32(currentCount)
                paramsPointer[1] = UInt32(nextCount)
                let outputPointer = outputBuffer.typedContents(as: UInt32.self, capacity: nextCount * 2)
                outputPointer.initialize(repeating: 0, count: nextCount * 2)

                try dispatcher.dispatchSumCheckPartial(
                    evalBuffer: currentBuffer,
                    outputBuffer: outputBuffer,
                    paramsBuffer: paramsBuffer,
                    numElements: currentCount
                )

                currentBuffer = outputBuffer
                currentCount = nextCount
            }

            let finalPointer = currentBuffer.typedContents(as: UInt32.self, capacity: 4)
            let packed = Array(UnsafeBufferPointer(start: finalPointer, count: 4))
            let unpacked = MetalFieldPacking.unpackFieldElementsSoA(packed, count: 2)
            return (unpacked[0], unpacked[1])
        }
    }
}

private func unwrapOrThrow<T>(_ value: T?) throws -> T {
    guard let value else {
        throw NuMetalError.heapCreationFailed
    }
    return value
}

/// Ceiling log2.
func ceilLog2(_ n: Int) -> Int {
    n <= 1 ? 0 : (Int.bitWidth - (n - 1).leadingZeroBitCount)
}
