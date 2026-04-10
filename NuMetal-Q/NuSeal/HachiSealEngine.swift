import Foundation

public actor HachiSealEngine: NuSealCompiler {
    public nonisolated let backendID: String = NuSealConstants.productionBackendID

    private let profile = NuProfile.canonical
    private let params = NuParams.derive(from: .canonical)
    private let parameterBundle = NuParams.derive(from: .canonical).seal
    private let pcsBackend = HachiPCSBackend()
    private var metalContext: MetalContext?
    private static let parameters = HachiSealParameters(
        modulus: Fq.modulus,
        outerRingDegree: 1024,
        innerRingDegree: 64,
        extensionDegree: 4,
        decompositionBase: NuProfile.canonical.decompBase,
        certifiedNormCeiling: NuProfile.canonical.normBound
    )

    public init() {}

    public func setMetalContext(_ context: MetalContext) async {
        metalContext = context
    }

    internal func seal(
        state: FoldState,
        shape: Shape,
        publicHeader: Data
    ) async throws -> PublicSealProof {
        guard state.kind == .recursiveAccumulator,
              let accumulator = state.recursiveAccumulator else {
            throw SpartanSealError.serializationFailure
        }

        let statement = makeStatement(
            accumulator: accumulator,
            shape: shape,
            publicHeader: publicHeader
        )

        let terminalProof = try await buildTerminalProof(
            accumulator: accumulator,
            shape: shape,
            statement: statement,
            executionMode: .automatic,
            traceCollector: nil
        )

        return PublicSealProof(statement: statement, terminalProof: terminalProof)
    }

    internal func sealUsingCluster(
        state: FoldState,
        shape: Shape,
        publicHeader: Data,
        clusterSession: ClusterSession,
        attestation: Data,
        dispatchFragment: @Sendable (JobFragment) async throws -> FragmentResult
    ) async throws -> PublicSealProof {
        guard state.kind == .recursiveAccumulator,
              let accumulator = state.recursiveAccumulator else {
            throw SpartanSealError.serializationFailure
        }

        let statement = makeStatement(
            accumulator: accumulator,
            shape: shape,
            publicHeader: publicHeader
        )
        let terminalProof = try await buildTerminalProofUsingCluster(
            accumulator: accumulator,
            shape: shape,
            statement: statement,
            clusterSession: clusterSession,
            attestation: attestation,
            dispatchFragment: dispatchFragment
        )
        let proof = PublicSealProof(statement: statement, terminalProof: terminalProof)
        guard await verify(
            proof: proof,
            shape: shape,
            publicHeader: publicHeader,
            executionMode: .automatic,
            traceCollector: nil
        ) else {
            throw SpartanSealError.invalidClusterSealResult(.witness())
        }
        return proof
    }

    private func makeStatement(
        accumulator: FoldAccumulator,
        shape: Shape,
        publicHeader: Data
    ) -> PublicSealStatement {
        PublicSealStatement(
            backendID: backendID,
            sealTranscriptID: NuSealConstants.sealTranscriptID,
            shapeDigest: shape.digest,
            deciderLayoutDigest: digest(
                Array(ShapeArtifact.sealCompilationBundle(for: shape)),
                domain: "NuMeQ.Decider.Layout"
            ),
            sealParamDigest: parameterBundle.parameterDigest,
            publicHeader: publicHeader,
            publicInputs: accumulator.currentClaim.publicInputs
        )
    }

    public func verify(
        proof: PublicSealProof,
        shape: Shape,
        publicHeader: Data
    ) async -> Bool {
        await verify(
            proof: proof,
            shape: shape,
            publicHeader: publicHeader,
            executionMode: .automatic,
            traceCollector: nil
        )
    }

    func verify(
        proof: PublicSealProof,
        shape: Shape,
        publicHeader: Data,
        executionMode: VerificationExecutionMode,
        traceCollector: MetalTraceCollector?
    ) async -> Bool {
        await verifySemantically(
            proof: proof,
            shape: shape,
            publicHeader: publicHeader,
            executionMode: executionMode,
            traceCollector: traceCollector
        ).isValid
    }

    package func verifySemantically(
        proof: PublicSealProof,
        shape: Shape,
        publicHeader: Data,
        executionMode: VerificationExecutionMode,
        traceCollector: MetalTraceCollector?
    ) async -> HachiVerificationOutcome {
        var diagnostics = HachiVerificationDiagnostics()
        func fail(_ message: String) -> HachiVerificationOutcome {
            diagnostics.recordFailure(message)
            return HachiVerificationOutcome(isValid: false, diagnostics: diagnostics)
        }

        do {
            guard proof.version == PublicSealProof.currentVersion else {
                return fail("seal proof version mismatch")
            }
            guard proof.statement.backendID == backendID else {
                return fail("seal backend mismatch")
            }
            guard proof.statement.sealTranscriptID == NuSealConstants.sealTranscriptID else {
                return fail("seal transcript mismatch")
            }
            guard proof.statement.shapeDigest == shape.digest else {
                return fail("shape digest mismatch")
            }
            guard proof.statement.publicHeader == publicHeader else {
                return fail("public header mismatch")
            }
            guard proof.statement.sealParamDigest == parameterBundle.parameterDigest else {
                return fail("seal parameter digest mismatch")
            }

            let expectedLayoutDigest = digest(
                Array(ShapeArtifact.sealCompilationBundle(for: shape)),
                domain: "NuMeQ.Decider.Layout"
            )
            guard proof.statement.deciderLayoutDigest == expectedLayoutDigest else {
                return fail("decider layout digest mismatch")
            }
            guard proof.statement.publicInputs.count == shape.relation.nPublic else {
                return fail("public input count mismatch")
            }

            var transcript = makeTranscript(for: proof.statement)
            absorbMaskedCommitments(proof.terminalProof, into: &transcript)
            absorbBlindingCommitments(proof.terminalProof, into: &transcript)

            let tau = transcript.challengeVector(
                label: "numeq.decider.spartan.outer.tau",
                count: shape.rowVariableCount
            )
            let (rowPoint, outerValue) = try verifySumcheck(
                proof: proof.terminalProof.outerSumcheck,
                variableCount: shape.rowVariableCount,
                degreeBound: max(1, shape.maxRelationDegree),
                claimedSum: .zero,
                transcript: &transcript,
                label: "numeq.decider.spartan.outer"
            )

            let rowValues = proof.terminalProof.claimedEvaluations.matrixRowEvaluations
            guard rowValues.count == shape.relation.matrices.count else {
                return fail("matrix row evaluation count mismatch")
            }
            let rowConstraint = try shape.rowConstraint(rowEvaluations: rowValues)
            let expectedOuterValue = eqWeight(challenge: tau, point: rowPoint) * rowConstraint
            guard outerValue == expectedOuterValue else {
                return fail("outer sumcheck terminal mismatch")
            }

            let gamma = transcript.challengeScalar(label: "numeq.decider.spartan.inner.gamma")
            let claimedInnerSum = try combinedInnerClaim(
                shape: shape,
                publicInputs: proof.statement.publicInputs,
                rowPoint: rowPoint,
                rowValues: rowValues,
                gamma: gamma
            )
            let (columnPoint, innerValue) = try verifySumcheck(
                proof: proof.terminalProof.innerSumcheck,
                variableCount: shape.witnessVariableCount,
                degreeBound: 2,
                claimedSum: claimedInnerSum,
                transcript: &transcript,
                label: "numeq.decider.spartan.inner"
            )

            guard proof.terminalProof.claimedEvaluations.rowPoint == rowPoint else {
                return fail("row challenge mismatch")
            }
            guard proof.terminalProof.claimedEvaluations.columnPoint == columnPoint else {
                return fail("column challenge mismatch")
            }

            let witnessEvaluation = proof.terminalProof.claimedEvaluations.witnessEvaluation
            let expectedInnerValue = witnessEvaluation * (
                try combinedMatrixValue(
                    shape: shape,
                    rowPoint: rowPoint,
                    columnPoint: columnPoint,
                    gamma: gamma
                )
            )
            guard innerValue == expectedInnerValue else {
                return fail("inner sumcheck terminal mismatch")
            }

            guard proof.terminalProof.blindingCommitments.matrixRows.count == shape.relation.matrices.count else {
                return fail("matrix blinding commitment count mismatch")
            }
            guard proof.terminalProof.blindingEvaluations.matrixRows.count == shape.relation.matrices.count else {
                return fail("matrix blinding evaluation count mismatch")
            }
            guard proof.terminalProof.matrixEvaluationCommitments.count == shape.relation.matrices.count else {
                return fail("matrix commitment count mismatch")
            }

            let maskedQueries = maskedQueries(for: proof.terminalProof)
            let blindingQueries = blindingQueries(for: proof.terminalProof)
            guard try pcsBackend.verifyBatch(
                commitments: maskedCommitments(for: proof.terminalProof),
                queries: maskedQueries,
                proof: proof.terminalProof.pcsOpeningProof,
                transcript: &transcript,
                context: metalContext(for: executionMode),
                traceCollector: traceCollector,
                diagnostics: &diagnostics
            ) else {
                return HachiVerificationOutcome(isValid: false, diagnostics: diagnostics)
            }

            guard try pcsBackend.verifyBatch(
                commitments: blindingCommitments(for: proof.terminalProof),
                queries: blindingQueries,
                proof: proof.terminalProof.blindingOpeningProof,
                transcript: &transcript,
                context: metalContext(for: executionMode),
                traceCollector: traceCollector,
                diagnostics: &diagnostics
            ) else {
                return HachiVerificationOutcome(isValid: false, diagnostics: diagnostics)
            }

            return HachiVerificationOutcome(isValid: true, diagnostics: diagnostics)
        } catch {
            diagnostics.recordFailure("hachi semantic verification threw \(error)")
            return HachiVerificationOutcome(isValid: false, diagnostics: diagnostics)
        }
    }
}

public typealias SealEngine = HachiSealEngine

private extension HachiSealEngine {
    func buildTerminalProof(
        accumulator: FoldAccumulator,
        shape: Shape,
        statement: PublicSealStatement,
        executionMode: VerificationExecutionMode,
        traceCollector: MetalTraceCollector?
    ) async throws -> HachiTerminalProof {
        let prepared = try prepareTerminalPolynomials(
            accumulator: accumulator,
            shape: shape,
            statement: statement
        )
        let activeMetalContext = metalContext(for: executionMode)
        let maskedWitnessCommitment = try pcsBackend.commit(
            label: .witness(),
            polynomial: prepared.maskedWitnessPolynomial,
            context: activeMetalContext,
            traceCollector: traceCollector
        )
        let maskedRowCommitments = try prepared.maskedRowPolynomials.enumerated().map { index, polynomial in
            try pcsBackend.commit(
                label: .matrixRow(index),
                polynomial: polynomial,
                context: activeMetalContext,
                traceCollector: traceCollector
            )
        }
        let blindingWitnessCommitment = try pcsBackend.commit(
            label: .witness(),
            polynomial: prepared.blindingWitnessPolynomial,
            context: activeMetalContext,
            traceCollector: traceCollector
        )
        let blindingRowCommitments = try prepared.blindingRowPolynomials.enumerated().map { index, polynomial in
            try pcsBackend.commit(
                label: .matrixRow(index),
                polynomial: polynomial,
                context: activeMetalContext,
                traceCollector: traceCollector
            )
        }
        let blindingCommitments = SpartanBlindingCommitments(
            witness: blindingWitnessCommitment,
            matrixRows: blindingRowCommitments
        )
        let evaluated = try evaluateTerminalProofState(
            shape: shape,
            statement: statement,
            prepared: prepared,
            witnessCommitment: maskedWitnessCommitment,
            matrixEvaluationCommitments: maskedRowCommitments,
            blindingCommitments: blindingCommitments
        )
        let pcsOpeningProof = try pcsBackend.openBatch(
            polynomials: prepared.maskedPolynomialsByOracle,
            queries: evaluated.maskedQueries,
            batchSeedDigest: evaluated.pcsBatchSeedDigest,
            context: activeMetalContext,
            traceCollector: traceCollector
        )
        let blindingOpeningProof = try pcsBackend.openBatch(
            polynomials: prepared.blindingPolynomialsByOracle,
            queries: evaluated.blindingQueries,
            batchSeedDigest: evaluated.blindingBatchSeedDigest,
            context: activeMetalContext,
            traceCollector: traceCollector
        )

        return HachiTerminalProof(
            witnessCommitment: maskedWitnessCommitment,
            matrixEvaluationCommitments: maskedRowCommitments,
            blindingCommitments: blindingCommitments,
            outerSumcheck: evaluated.outerSumcheck,
            innerSumcheck: evaluated.innerSumcheck,
            claimedEvaluations: evaluated.claimedEvaluations,
            blindingEvaluations: evaluated.blindingEvaluations,
            pcsOpeningProof: pcsOpeningProof,
            blindingOpeningProof: blindingOpeningProof
        )
    }

    func buildTerminalProofUsingCluster(
        accumulator: FoldAccumulator,
        shape: Shape,
        statement: PublicSealStatement,
        clusterSession: ClusterSession,
        attestation: Data,
        dispatchFragment: @Sendable (JobFragment) async throws -> FragmentResult
    ) async throws -> HachiTerminalProof {
        let prepared = try prepareTerminalPolynomials(
            accumulator: accumulator,
            shape: shape,
            statement: statement
        )
        let commitPacket = HachiClusterSealWorkPacket(
            operation: .commit,
            maskedWitnessPolynomial: prepared.maskedWitnessPolynomial,
            maskedRowPolynomials: prepared.maskedRowPolynomials,
            blindingWitnessPolynomial: prepared.blindingWitnessPolynomial,
            blindingRowPolynomials: prepared.blindingRowPolynomials
        )
        let commitResult = try await performClusterSealWork(
            packet: commitPacket,
            shapeDigest: shape.digest,
            clusterSession: clusterSession,
            attestation: attestation,
            dispatchFragment: dispatchFragment
        )
        guard commitResult.operation == .commit,
              let commitments = commitResult.commitments else {
            throw SpartanSealError.invalidClusterSealResult(.witness())
        }

        let evaluated = try evaluateTerminalProofState(
            shape: shape,
            statement: statement,
            prepared: prepared,
            witnessCommitment: commitments.witnessCommitment,
            matrixEvaluationCommitments: commitments.matrixEvaluationCommitments,
            blindingCommitments: commitments.blindingCommitments
        )
        let openPacket = HachiClusterSealWorkPacket(
            operation: .open,
            maskedWitnessPolynomial: prepared.maskedWitnessPolynomial,
            maskedRowPolynomials: prepared.maskedRowPolynomials,
            blindingWitnessPolynomial: prepared.blindingWitnessPolynomial,
            blindingRowPolynomials: prepared.blindingRowPolynomials,
            maskedQueries: evaluated.maskedQueries,
            blindingQueries: evaluated.blindingQueries,
            pcsBatchSeedDigest: evaluated.pcsBatchSeedDigest,
            blindingBatchSeedDigest: evaluated.blindingBatchSeedDigest
        )
        let openResult = try await performClusterSealWork(
            packet: openPacket,
            shapeDigest: shape.digest,
            clusterSession: clusterSession,
            attestation: attestation,
            dispatchFragment: dispatchFragment
        )
        guard openResult.operation == .open,
              let openings = openResult.openings else {
            throw SpartanSealError.invalidClusterSealResult(.witness())
        }

        return HachiTerminalProof(
            witnessCommitment: commitments.witnessCommitment,
            matrixEvaluationCommitments: commitments.matrixEvaluationCommitments,
            blindingCommitments: commitments.blindingCommitments,
            outerSumcheck: evaluated.outerSumcheck,
            innerSumcheck: evaluated.innerSumcheck,
            claimedEvaluations: evaluated.claimedEvaluations,
            blindingEvaluations: evaluated.blindingEvaluations,
            pcsOpeningProof: openings.pcsOpeningProof,
            blindingOpeningProof: openings.blindingOpeningProof
        )
    }

    func performClusterSealWork(
        packet: HachiClusterSealWorkPacket,
        shapeDigest: ShapeDigest,
        clusterSession: ClusterSession,
        attestation: Data,
        dispatchFragment: @Sendable (JobFragment) async throws -> FragmentResult
    ) async throws -> HachiClusterSealWorkResult {
        let fragment = try await clusterSession.createSealFragment(
            shapeDigest: shapeDigest,
            vaultEncryptedWorkPackage: try packet.serialize(),
            attestation: attestation
        )
        let response = try await clusterSession.roundTrip(fragment, dispatch: dispatchFragment)
        let result = try HachiClusterSealWorkResult.deserialize(response)
        guard result.isValid(for: packet) else {
            throw SpartanSealError.invalidClusterSealResult(.witness())
        }
        return result
    }

    func prepareTerminalPolynomials(
        accumulator: FoldAccumulator,
        shape: Shape,
        statement: PublicSealStatement
    ) throws -> PreparedTerminalPolynomials {
        let canonicalWitness = try accumulator.currentWitness()
        let witnessFields = WitnessPacking.unpackFieldVector(
            from: canonicalWitness,
            originalLength: shape.relation.n - shape.relation.nPublic
        )
        let witnessPolynomial = try shape.makeWitnessPolynomial(from: witnessFields)
        let rowPolynomials = try (0..<shape.relation.matrices.count).map { index in
            try shape.makeRowEvaluationPolynomial(
                matrix: index,
                publicInput: statement.publicInputs,
                witness: witnessFields,
                witnessPolynomial: witnessPolynomial
            )
        }

        let randomness = oracleRandomnessMap(matrixCount: shape.relation.matrices.count)
        let witnessBlind = try shape.blindPolynomial(
            witnessPolynomial,
            for: .witness(),
            randomness: randomness[.witness()] ?? randomBytes(count: 32)
        )

        var maskedRowPolynomials = [MultilinearPoly]()
        maskedRowPolynomials.reserveCapacity(rowPolynomials.count)
        var blindingRowPolynomials = [MultilinearPoly]()
        blindingRowPolynomials.reserveCapacity(rowPolynomials.count)
        for (index, polynomial) in rowPolynomials.enumerated() {
            let blinded = try shape.blindPolynomial(
                polynomial,
                for: .matrixRow(index),
                randomness: randomness[.matrixRow(index)] ?? randomBytes(count: 32)
            )
            maskedRowPolynomials.append(blinded.blinded)
            blindingRowPolynomials.append(blinded.blinding)
        }

        return PreparedTerminalPolynomials(
            witnessPolynomial: witnessPolynomial,
            rowPolynomials: rowPolynomials,
            maskedWitnessPolynomial: witnessBlind.blinded,
            maskedRowPolynomials: maskedRowPolynomials,
            blindingWitnessPolynomial: witnessBlind.blinding,
            blindingRowPolynomials: blindingRowPolynomials
        )
    }

    func evaluateTerminalProofState(
        shape: Shape,
        statement: PublicSealStatement,
        prepared: PreparedTerminalPolynomials,
        witnessCommitment: HachiPCSCommitment,
        matrixEvaluationCommitments: [HachiPCSCommitment],
        blindingCommitments: SpartanBlindingCommitments<HachiPCSCommitment>
    ) throws -> EvaluatedTerminalProofState {
        var transcript = makeTranscript(for: statement)
        let placeholder = HachiTerminalProof(
            witnessCommitment: witnessCommitment,
            matrixEvaluationCommitments: matrixEvaluationCommitments,
            blindingCommitments: blindingCommitments,
            outerSumcheck: SpartanSumcheckProof(roundEvaluations: []),
            innerSumcheck: SpartanSumcheckProof(roundEvaluations: []),
            claimedEvaluations: SpartanClaimedEvaluations(
                rowPoint: [],
                columnPoint: [],
                matrixRowEvaluations: [],
                witnessEvaluation: .zero
            ),
            blindingEvaluations: SpartanBlindingEvaluations(matrixRows: [], witness: .zero),
            pcsOpeningProof: HachiPCSBatchOpeningProof(batchSeedDigest: [], classes: []),
            blindingOpeningProof: HachiPCSBatchOpeningProof(batchSeedDigest: [], classes: [])
        )
        absorbMaskedCommitments(placeholder, into: &transcript)
        absorbBlindingCommitments(placeholder, into: &transcript)

        let tau = transcript.challengeVector(
            label: "numeq.decider.spartan.outer.tau",
            count: shape.rowVariableCount
        )
        let outer = try proveSumcheck(
            variableCount: shape.rowVariableCount,
            degreeBound: max(1, shape.maxRelationDegree),
            claimedSum: .zero,
            transcript: &transcript,
            label: "numeq.decider.spartan.outer"
        ) { point in
            let evaluations = try prepared.rowPolynomials.map { try shape.evaluate($0, at: point) }
            return self.eqWeight(challenge: tau, point: point)
                * (try shape.rowConstraint(rowEvaluations: evaluations))
        }

        let rowValues = try prepared.rowPolynomials.map { try shape.evaluate($0, at: outer.finalPoint) }
        let gamma = transcript.challengeScalar(label: "numeq.decider.spartan.inner.gamma")
        let innerClaim = try combinedInnerClaim(
            shape: shape,
            publicInputs: statement.publicInputs,
            rowPoint: outer.finalPoint,
            rowValues: rowValues,
            gamma: gamma
        )
        let inner = try proveSumcheck(
            variableCount: shape.witnessVariableCount,
            degreeBound: 2,
            claimedSum: innerClaim,
            transcript: &transcript,
            label: "numeq.decider.spartan.inner"
        ) { point in
            let witnessValue = try shape.evaluate(prepared.witnessPolynomial, at: point)
            let matrixValue = try self.combinedMatrixValue(
                shape: shape,
                rowPoint: outer.finalPoint,
                columnPoint: point,
                gamma: gamma
            )
            return witnessValue * matrixValue
        }

        let witnessEvaluation = try shape.evaluate(prepared.witnessPolynomial, at: inner.finalPoint)
        let blindingWitnessEvaluation = try shape.evaluate(
            prepared.blindingWitnessPolynomial,
            at: inner.finalPoint
        )
        let blindingRowEvaluations = try prepared.blindingRowPolynomials.map {
            try shape.evaluate($0, at: outer.finalPoint)
        }
        let maskedQueries = maskedQueries(
            rowPoint: outer.finalPoint,
            columnPoint: inner.finalPoint,
            rowValues: rowValues,
            witnessEvaluation: witnessEvaluation,
            blindingRowEvaluations: blindingRowEvaluations,
            blindingWitnessEvaluation: blindingWitnessEvaluation
        )
        let blindingQueries = blindingQueries(
            rowPoint: outer.finalPoint,
            columnPoint: inner.finalPoint,
            blindingRowEvaluations: blindingRowEvaluations,
            blindingWitnessEvaluation: blindingWitnessEvaluation
        )
        let pcsBatchSeedDigest = transcript.challengeBytes(
            label: "numeq.decider.hachi.batch.seed",
            count: 32
        )
        let blindingBatchSeedDigest = transcript.challengeBytes(
            label: "numeq.decider.hachi.batch.seed",
            count: 32
        )

        return EvaluatedTerminalProofState(
            outerSumcheck: outer.proof,
            innerSumcheck: inner.proof,
            claimedEvaluations: SpartanClaimedEvaluations(
                rowPoint: outer.finalPoint,
                columnPoint: inner.finalPoint,
                matrixRowEvaluations: rowValues,
                witnessEvaluation: witnessEvaluation
            ),
            blindingEvaluations: SpartanBlindingEvaluations(
                matrixRows: blindingRowEvaluations,
                witness: blindingWitnessEvaluation
            ),
            maskedQueries: maskedQueries,
            blindingQueries: blindingQueries,
            pcsBatchSeedDigest: pcsBatchSeedDigest,
            blindingBatchSeedDigest: blindingBatchSeedDigest
        )
    }

    func makeTranscript(for statement: PublicSealStatement) -> NuTranscriptSeal {
        var transcript = NuTranscriptSeal(domain: statement.sealTranscriptID)
        transcript.absorb(label: "numeq.decider.backend", bytes: Data(statement.backendID.utf8))
        transcript.absorb(label: "numeq.decider.transcript_id", bytes: Data(statement.sealTranscriptID.utf8))
        transcript.absorb(label: "numeq.decider.shape_digest", bytes: Data(statement.shapeDigest.bytes))
        transcript.absorb(label: "numeq.decider.decider_layout_digest", bytes: Data(statement.deciderLayoutDigest))
        transcript.absorb(label: "numeq.decider.parameter_digest", bytes: Data(statement.sealParamDigest))
        transcript.absorb(label: "numeq.decider.public_header", bytes: statement.publicHeader)
        transcript.absorb(label: "numeq.decider.public_inputs", scalars: statement.publicInputs)
        return transcript
    }

    func absorbMaskedCommitments(
        _ proof: HachiTerminalProof,
        into transcript: inout NuTranscriptSeal
    ) {
        transcript.absorb(
            label: "numeq.decider.masked_commitments",
            bytes: commitmentBytes(
                witness: proof.witnessCommitment,
                rows: proof.matrixEvaluationCommitments
            )
        )
    }

    func absorbBlindingCommitments(
        _ proof: HachiTerminalProof,
        into transcript: inout NuTranscriptSeal
    ) {
        transcript.absorb(
            label: "numeq.decider.blinding_commitments",
            bytes: commitmentBytes(
                witness: proof.blindingCommitments.witness,
                rows: proof.blindingCommitments.matrixRows
            )
        )
    }

    func commitmentBytes(
        witness: HachiPCSCommitment,
        rows: [HachiPCSCommitment]
    ) -> Data {
        var writer = BinaryWriter()
        appendCommitmentDigest(witness, into: &writer)
        writer.append(UInt32(clamping: rows.count))
        for row in rows {
            appendCommitmentDigest(row, into: &writer)
        }
        return writer.data
    }

    private func appendCommitmentDigest(
        _ commitment: HachiPCSCommitment,
        into writer: inout BinaryWriter
    ) {
        writer.append(commitment.mode.rawValue)
        writer.append(UInt32(clamping: commitment.directPackedOuterCommitments.count))
        for outerCommitment in commitment.directPackedOuterCommitments {
            writer.append(Data(outerCommitment.value.toBytes()))
        }
        writer.appendLengthPrefixed(Data(commitment.tableDigest))
        writer.appendLengthPrefixed(Data(commitment.merkleRoot))
        writer.append(commitment.packedChunkCount)
        writer.appendLengthPrefixed(Data(commitment.statementDigest))
    }

    func maskedCommitments(for proof: HachiTerminalProof) -> [SpartanOracleID: HachiPCSCommitment] {
        Dictionary(
            uniqueKeysWithValues:
                [(.witness(), proof.witnessCommitment)]
                + proof.matrixEvaluationCommitments.map { ($0.oracle, $0) }
        )
    }

    func blindingCommitments(for proof: HachiTerminalProof) -> [SpartanOracleID: HachiPCSCommitment] {
        Dictionary(
            uniqueKeysWithValues:
                [(.witness(), proof.blindingCommitments.witness)]
                + proof.blindingCommitments.matrixRows.map { ($0.oracle, $0) }
        )
    }

    func maskedQueries(for proof: HachiTerminalProof) -> [SpartanPCSQuery<Fq>] {
        maskedQueries(
            rowPoint: proof.terminalProofRowPoint,
            columnPoint: proof.terminalProofColumnPoint,
            rowValues: proof.claimedEvaluations.matrixRowEvaluations,
            witnessEvaluation: proof.claimedEvaluations.witnessEvaluation,
            blindingRowEvaluations: proof.blindingEvaluations.matrixRows,
            blindingWitnessEvaluation: proof.blindingEvaluations.witness
        )
    }

    func maskedQueries(
        rowPoint: [Fq],
        columnPoint: [Fq],
        rowValues: [Fq],
        witnessEvaluation: Fq,
        blindingRowEvaluations: [Fq],
        blindingWitnessEvaluation: Fq
    ) -> [SpartanPCSQuery<Fq>] {
        [SpartanPCSQuery(
            oracle: .witness(),
            point: columnPoint,
            value: witnessEvaluation + blindingWitnessEvaluation
        )] + rowValues.enumerated().map { index, value in
            SpartanPCSQuery(
                oracle: .matrixRow(index),
                point: rowPoint,
                value: value + blindingRowEvaluations[index]
            )
        }
    }

    func blindingQueries(for proof: HachiTerminalProof) -> [SpartanPCSQuery<Fq>] {
        blindingQueries(
            rowPoint: proof.terminalProofRowPoint,
            columnPoint: proof.terminalProofColumnPoint,
            blindingRowEvaluations: proof.blindingEvaluations.matrixRows,
            blindingWitnessEvaluation: proof.blindingEvaluations.witness
        )
    }

    func blindingQueries(
        rowPoint: [Fq],
        columnPoint: [Fq],
        blindingRowEvaluations: [Fq],
        blindingWitnessEvaluation: Fq
    ) -> [SpartanPCSQuery<Fq>] {
        [SpartanPCSQuery(
            oracle: .witness(),
            point: columnPoint,
            value: blindingWitnessEvaluation
        )] + blindingRowEvaluations.enumerated().map { index, value in
            SpartanPCSQuery(
                oracle: .matrixRow(index),
                point: rowPoint,
                value: value
            )
        }
    }

    func proveSumcheck(
        variableCount: Int,
        degreeBound: Int,
        claimedSum: Fq,
        transcript: inout NuTranscriptSeal,
        label: String,
        evaluator: @escaping ([Fq]) throws -> Fq
    ) throws -> (proof: SpartanSumcheckProof, finalPoint: [Fq], finalValue: Fq) {
        var challenges = [Fq]()
        challenges.reserveCapacity(variableCount)
        var expectedSum = claimedSum
        var rounds = [[Fq]]()
        rounds.reserveCapacity(variableCount)

        for round in 0..<variableCount {
            let roundValues = try (0...degreeBound).map { pointValue in
                try sumOverSuffixes(
                    prefix: challenges,
                    currentValue: Fq(UInt64(pointValue)),
                    suffixCount: variableCount - round - 1,
                    evaluator: evaluator
                )
            }
            rounds.append(roundValues)
            transcript.absorb(label: "\(label).round.\(round)", scalars: roundValues)
            let challenge = transcript.challengeScalar(label: "\(label).challenge.\(round)")
            challenges.append(challenge)
            expectedSum = interpolate(roundValues, at: challenge)
        }

        return (
            SpartanSumcheckProof(roundEvaluations: rounds, terminalMask: .zero),
            challenges,
            expectedSum
        )
    }

    func verifySumcheck(
        proof: SpartanSumcheckProof,
        variableCount: Int,
        degreeBound: Int,
        claimedSum: Fq,
        transcript: inout NuTranscriptSeal,
        label: String
    ) throws -> (finalPoint: [Fq], finalValue: Fq) {
        guard proof.roundEvaluations.count == variableCount else {
            throw SpartanSealError.invalidSumcheckRoundCount(
                expected: variableCount,
                actual: proof.roundEvaluations.count
            )
        }
        var expectedSum = claimedSum
        var challenges = [Fq]()
        challenges.reserveCapacity(variableCount)

        for (round, roundValues) in proof.roundEvaluations.enumerated() {
            guard roundValues.count == degreeBound + 1 else {
                throw SpartanSealError.invalidSumcheckRoundDegree(
                    expected: degreeBound + 1,
                    actual: roundValues.count
                )
            }
            guard roundValues[0] + roundValues[1] == expectedSum else {
                throw SpartanSealError.invalidSumcheckRound
            }
            transcript.absorb(label: "\(label).round.\(round)", scalars: roundValues)
            let challenge = transcript.challengeScalar(label: "\(label).challenge.\(round)")
            challenges.append(challenge)
            expectedSum = interpolate(roundValues, at: challenge)
        }

        return (challenges, expectedSum - proof.terminalMask)
    }

    func sumOverSuffixes(
        prefix: [Fq],
        currentValue: Fq,
        suffixCount: Int,
        evaluator: @escaping ([Fq]) throws -> Fq
    ) throws -> Fq {
        if suffixCount == 0 {
            return try evaluator(prefix + [currentValue])
        }

        let fixedPrefix = prefix + [currentValue]
        let termCount = 1 << suffixCount
        var accumulator = Fq.zero
        for mask in 0..<termCount {
            var point = fixedPrefix
            point.reserveCapacity(fixedPrefix.count + suffixCount)
            for bit in 0..<suffixCount {
                point.append(((mask >> bit) & 1) == 1 ? .one : .zero)
            }
            accumulator += try evaluator(point)
        }
        return accumulator
    }

    func interpolate(_ samples: [Fq], at point: Fq) -> Fq {
        guard samples.count > 1 else {
            return samples.first ?? .zero
        }
        var result = Fq.zero
        for (index, sample) in samples.enumerated() {
            let xj = Fq(UInt64(index))
            var numerator = Fq.one
            var denominator = Fq.one
            for other in samples.indices where other != index {
                let xm = Fq(UInt64(other))
                numerator *= (point - xm)
                denominator *= (xj - xm)
            }
            result += sample * numerator * denominator.inverse()
        }
        return result
    }

    func eqWeight(challenge: [Fq], point: [Fq]) -> Fq {
        precondition(challenge.count == point.count, "eq weight arity mismatch")
        return zip(challenge, point).reduce(.one) { partial, pair in
            let (lhs, rhs) = pair
            return partial * ((lhs * rhs) + ((Fq.one - lhs) * (Fq.one - rhs)))
        }
    }

    func combinedInnerClaim(
        shape: Shape,
        publicInputs: [Fq],
        rowPoint: [Fq],
        rowValues: [Fq],
        gamma: Fq
    ) throws -> Fq {
        var accumulator = Fq.zero
        var power = Fq.one
        for index in rowValues.indices {
            let publicContribution = try shape.publicContribution(
                ofMatrix: index,
                publicInput: publicInputs,
                atRowPoint: rowPoint
            )
            accumulator += power * (rowValues[index] - publicContribution)
            power *= gamma
        }
        return accumulator
    }

    func combinedMatrixValue(
        shape: Shape,
        rowPoint: [Fq],
        columnPoint: [Fq],
        gamma: Fq
    ) throws -> Fq {
        var accumulator = Fq.zero
        var power = Fq.one
        for index in 0..<shape.relation.matrices.count {
            accumulator += power * (try shape.matrixValue(
                ofMatrix: index,
                rowPoint: rowPoint,
                columnPoint: columnPoint
            ))
            power *= gamma
        }
        return accumulator
    }

    func oracleRandomnessMap(matrixCount: Int) -> [SpartanOracleID: [UInt8]] {
        var values: [SpartanOracleID: [UInt8]] = [.witness(): randomBytes(count: 32)]
        for index in 0..<matrixCount {
            values[.matrixRow(index)] = randomBytes(count: 32)
        }
        return values
    }

    func randomBytes(count: Int) -> [UInt8] {
        var rng = SystemRandomNumberGenerator()
        return (0..<count).map { _ in UInt8.random(in: .min ... .max, using: &rng) }
    }

    func batchScheduleDigest(for proof: HachiPCSBatchOpeningProof) -> [UInt8] {
        digest(
            proof.classes.flatMap { $0.scheduleDigest },
            domain: "NuMeQ.Decider.BatchSchedule"
        )
    }

    func digest(_ bytes: [UInt8], domain: String) -> [UInt8] {
        NuSealCShake256.cshake256(
            data: Data(bytes),
            domain: domain,
            count: 32
        )
    }

    func metalContext(for executionMode: VerificationExecutionMode) -> MetalContext? {
        switch executionMode {
        case .automatic, .metalAssisted:
            return metalContext
        case .cpuOnly:
            return nil
        }
    }
}

private struct PreparedTerminalPolynomials {
    let witnessPolynomial: MultilinearPoly
    let rowPolynomials: [MultilinearPoly]
    let maskedWitnessPolynomial: MultilinearPoly
    let maskedRowPolynomials: [MultilinearPoly]
    let blindingWitnessPolynomial: MultilinearPoly
    let blindingRowPolynomials: [MultilinearPoly]

    var maskedPolynomialsByOracle: [SpartanOracleID: MultilinearPoly] {
        Dictionary(
            uniqueKeysWithValues:
                [(.witness(), maskedWitnessPolynomial)]
                + maskedRowPolynomials.enumerated().map { (.matrixRow($0.offset), $0.element) }
        )
    }

    var blindingPolynomialsByOracle: [SpartanOracleID: MultilinearPoly] {
        Dictionary(
            uniqueKeysWithValues:
                [(.witness(), blindingWitnessPolynomial)]
                + blindingRowPolynomials.enumerated().map { (.matrixRow($0.offset), $0.element) }
        )
    }
}

private struct EvaluatedTerminalProofState {
    let outerSumcheck: SpartanSumcheckProof
    let innerSumcheck: SpartanSumcheckProof
    let claimedEvaluations: SpartanClaimedEvaluations<Fq>
    let blindingEvaluations: SpartanBlindingEvaluations<Fq>
    let maskedQueries: [SpartanPCSQuery<Fq>]
    let blindingQueries: [SpartanPCSQuery<Fq>]
    let pcsBatchSeedDigest: [UInt8]
    let blindingBatchSeedDigest: [UInt8]
}

private extension HachiTerminalProof {
    var terminalProofRowPoint: [Fq] { claimedEvaluations.rowPoint }
    var terminalProofColumnPoint: [Fq] { claimedEvaluations.columnPoint }
}
