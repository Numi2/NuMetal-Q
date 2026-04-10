import Foundation

internal struct HachiPCSBackend {
    let parameterBundle: HachiSealParameterBundle

    init(
        parameterBundle: HachiSealParameterBundle = NuParams.derive(from: .canonical).seal
    ) {
        self.parameterBundle = parameterBundle
    }

    private var directPackedParameters: DirectPackedPoKParameters {
        parameterBundle.directPackedPoK
    }

    func commit(
        label: SpartanOracleID,
        polynomial: MultilinearPoly,
        context: MetalContext? = nil,
        traceCollector: MetalTraceCollector? = nil
    ) throws -> HachiPCSCommitment {
        try buildOracleArtifact(
            label: label,
            polynomial: polynomial,
            context: context,
            traceCollector: traceCollector
        ).commitment
    }

    func openBatch(
        polynomials: [SpartanOracleID: MultilinearPoly],
        queries: [SpartanPCSQuery<Fq>],
        transcript: inout NuTranscriptSeal,
        context: MetalContext? = nil,
        traceCollector: MetalTraceCollector? = nil
    ) throws -> HachiPCSBatchOpeningProof {
        let batchSeedDigest = transcript.challengeBytes(
            label: "numeq.decider.hachi.batch.seed",
            count: 32
        )
        return try openBatch(
            polynomials: polynomials,
            queries: queries,
            batchSeedDigest: batchSeedDigest,
            context: context,
            traceCollector: traceCollector
        )
    }

    func openBatch(
        polynomials: [SpartanOracleID: MultilinearPoly],
        queries: [SpartanPCSQuery<Fq>],
        batchSeedDigest: [UInt8],
        context: MetalContext? = nil,
        traceCollector: MetalTraceCollector? = nil
    ) throws -> HachiPCSBatchOpeningProof {
        let artifacts = try Dictionary(
            uniqueKeysWithValues: polynomials.map { oracle, polynomial in
                (
                    oracle,
                    try buildOracleArtifact(
                        label: oracle,
                        polynomial: polynomial,
                        context: context,
                        traceCollector: traceCollector
                    )
                )
            }
        )

        let grouped = Dictionary(grouping: queries) { query in
            pointKey(query.point)
        }

        let classes = try grouped.keys.sorted().map { key -> HachiPCSBatchClassOpeningProof in
            let classQueries = grouped[key] ?? []
            guard let point = classQueries.first?.point else {
                throw SpartanSealError.invalidPCSBatchClassPoint
            }
            let scheduleDigest = scheduleDigest(
                point: point,
                oracles: classQueries.map(\.oracle),
                batchSeedDigest: batchSeedDigest
            )
            let pointDigest = digest(
                point.flatMap { $0.toBytes() },
                domain: "NuMeQ.Decider.Hachi.Point"
            )
            let openings = try classQueries.map { query in
                guard let polynomial = polynomials[query.oracle] else {
                    throw SpartanSealError.missingPCSOracle(query.oracle)
                }
                guard let artifact = artifacts[query.oracle] else {
                    throw SpartanSealError.missingPCSOracle(query.oracle)
                }
                let evaluation = polynomial.evaluate(at: query.point)
                let evaluationDigest = digest(
                    evaluation.toBytes(),
                    domain: "NuMeQ.Decider.Hachi.Eval"
                )
                guard let material = artifact.directPackedWitnessMaterial else {
                    throw SpartanSealError.serializationFailure
                }
                return HachiPCSOpening(
                    oracle: query.oracle,
                    evaluation: evaluation,
                    scheduleDigest: scheduleDigest,
                    evaluationDigest: evaluationDigest,
                    directPacked: try makeDirectPackedOpening(
                        material: material,
                        commitment: artifact.commitment,
                        point: query.point,
                        evaluation: evaluation,
                        context: context
                    )
                )
            }
            return HachiPCSBatchClassOpeningProof(
                point: point,
                pointDigest: pointDigest,
                scheduleDigest: scheduleDigest,
                openings: openings.sorted { lhs, rhs in
                    pointKey(lhs.oracle) < pointKey(rhs.oracle)
                }
            )
        }

        return HachiPCSBatchOpeningProof(
            batchSeedDigest: batchSeedDigest,
            classes: classes
        )
    }

    func verifyBatch(
        commitments: [SpartanOracleID: HachiPCSCommitment],
        queries: [SpartanPCSQuery<Fq>],
        proof: HachiPCSBatchOpeningProof,
        transcript: inout NuTranscriptSeal,
        context: MetalContext? = nil,
        traceCollector: MetalTraceCollector? = nil,
        diagnostics: inout HachiVerificationDiagnostics
    ) throws -> Bool {
        let batchSeedDigest = transcript.challengeBytes(
            label: "numeq.decider.hachi.batch.seed",
            count: 32
        )
        guard proof.batchSeedDigest == batchSeedDigest else {
            diagnostics.recordFailure("invalid hachi pcs batch seed")
            return false
        }

        let expectedClassOrder = proof.classes.map { pointKey($0.point) }.sorted()
        guard proof.classes.map({ pointKey($0.point) }) == expectedClassOrder else {
            diagnostics.recordFailure("non-canonical hachi pcs class ordering")
            return false
        }

        var seenClassKeys = Set<String>()
        _ = context
        _ = traceCollector
        let expectedQueries = Dictionary(
            uniqueKeysWithValues: queries.map { query in
                (
                    "\(pointKey(query.point))::\(pointKey(query.oracle))",
                    query
                )
            }
        )
        let openingCount = proof.classes.reduce(0) { partial, classProof in
            partial + classProof.openings.count
        }
        guard openingCount == queries.count else {
            diagnostics.recordFailure("invalid hachi pcs opening count")
            return false
        }

        for classProof in proof.classes {
            let classKey = pointKey(classProof.point)
            guard seenClassKeys.insert(classKey).inserted else {
                diagnostics.recordFailure("duplicate hachi pcs class point \(classKey)")
                return false
            }

            let expectedPointDigest = pointDigest(classProof.point)
            guard classProof.pointDigest == expectedPointDigest else {
                diagnostics.recordFailure("invalid hachi pcs point digest for \(classKey)")
                return false
            }

            let expectedOpeningOrder = classProof.openings.map(\.oracle).map(pointKey).sorted()
            guard classProof.openings.map({ pointKey($0.oracle) }) == expectedOpeningOrder else {
                diagnostics.recordFailure("non-canonical hachi pcs oracle ordering for \(classKey)")
                return false
            }

            var seenOracles = Set<SpartanOracleID>()
            let expectedScheduleDigest = scheduleDigest(
                point: classProof.point,
                oracles: classProof.openings.map(\.oracle),
                batchSeedDigest: batchSeedDigest
            )
            guard classProof.scheduleDigest == expectedScheduleDigest else {
                diagnostics.recordFailure("invalid hachi pcs schedule digest for \(classKey)")
                return false
            }

            for opening in classProof.openings {
                guard seenOracles.insert(opening.oracle).inserted else {
                    diagnostics.recordFailure("duplicate hachi pcs oracle \(pointKey(opening.oracle))")
                    return false
                }
                guard let commitment = commitments[opening.oracle] else {
                    diagnostics.recordFailure("missing hachi pcs commitment \(pointKey(opening.oracle))")
                    return false
                }
                guard commitment.oracle == opening.oracle else {
                    diagnostics.recordFailure("commitment oracle mismatch for \(pointKey(opening.oracle))")
                    return false
                }
                guard commitment.parameterDigest == parameterBundle.parameterDigest else {
                    diagnostics.recordFailure("invalid hachi pcs parameter digest for \(pointKey(opening.oracle))")
                    return false
                }
                guard opening.scheduleDigest == classProof.scheduleDigest else {
                    diagnostics.recordFailure("opening schedule digest mismatch for \(pointKey(opening.oracle))")
                    return false
                }

                let queryKey = "\(classKey)::\(pointKey(opening.oracle))"
                guard let query = expectedQueries[queryKey] else {
                    diagnostics.recordFailure("missing hachi pcs query \(pointKey(opening.oracle)) at \(classKey)")
                    return false
                }
                guard query.point == classProof.point else {
                    diagnostics.recordFailure("query point mismatch for \(pointKey(opening.oracle))")
                    return false
                }
                guard opening.evaluation == query.value else {
                    diagnostics.recordFailure("invalid blinded evaluation for \(pointKey(opening.oracle))")
                    return false
                }
                guard opening.evaluationDigest == evaluationDigest(query.value) else {
                    diagnostics.recordFailure("invalid evaluation digest for \(pointKey(opening.oracle))")
                    return false
                }

                guard opening.mode == .directPacked else {
                    diagnostics.recordFailure("expected direct-packed opening for \(pointKey(opening.oracle))")
                    return false
                }
                guard verifyDirectPackedOpening(
                    opening: opening,
                    commitment: commitment,
                    point: classProof.point,
                    context: context,
                    diagnostics: &diagnostics
                ) else {
                    return false
                }
            }
        }

        return true
    }

    private func buildOracleArtifact(
        label: SpartanOracleID,
        polynomial: MultilinearPoly,
        context: MetalContext?,
        traceCollector: MetalTraceCollector?
    ) throws -> HachiPCSOracleArtifact {
        _ = traceCollector
        let packed = WitnessPacking.packFieldVectorToRings(polynomial.evals)
        return try buildDirectPackedOracleArtifact(
            label: label,
            packedWitness: packed,
            valueCount: polynomial.evals.count,
            context: context
        )
    }

    private func buildDirectPackedOracleArtifact(
        label: SpartanOracleID,
        packedWitness: [RingElement],
        valueCount: Int,
        context: MetalContext?
    ) throws -> HachiPCSOracleArtifact {
        let material = try buildDirectPackedWitnessMaterial(
            packedWitness: packedWitness,
            context: context
        )
        let statementDigest = directPackedStatementDigest(
            packedChunkCount: packedWitness.count,
            valueCount: valueCount
        )
        let aggregateOuterCommitment = AjtaiCommitment(
            value: material.chunks.reduce(RingElement.zero) { partial, chunk in
                partial + chunk.outerCommitment.value
            }
        )
        return HachiPCSOracleArtifact(
            commitment: HachiPCSCommitment(
                oracle: label,
                mode: .directPacked,
                tableCommitment: aggregateOuterCommitment,
                directPackedOuterCommitments: material.chunks.map(\.outerCommitment),
                tableDigest: statementDigest,
                parameterDigest: parameterBundle.parameterDigest,
                valueCount: UInt32(clamping: valueCount),
                packedChunkCount: UInt32(clamping: packedWitness.count),
                statementDigest: statementDigest
            ),
            directPackedWitnessMaterial: material
        )
    }

    func scheduleDigest(
        point: [Fq],
        oracles: [SpartanOracleID],
        batchSeedDigest: [UInt8]
    ) -> [UInt8] {
        var bytes = batchSeedDigest
        bytes.append(contentsOf: point.flatMap { $0.toBytes() })
        for oracle in oracles.sorted(by: { pointKey($0) < pointKey($1) }) {
            bytes.append(contentsOf: pointKey(oracle).utf8)
        }
        return digest(bytes, domain: "NuMeQ.Decider.Hachi.Schedule")
    }

    func pointDigest(_ point: [Fq]) -> [UInt8] {
        digest(
            point.flatMap { $0.toBytes() },
            domain: "NuMeQ.Decider.Hachi.Point"
        )
    }

    func evaluationDigest(_ evaluation: Fq) -> [UInt8] {
        digest(
            evaluation.toBytes(),
            domain: "NuMeQ.Decider.Hachi.Eval"
        )
    }

    private func digest(_ bytes: [UInt8], domain: String) -> [UInt8] {
        NuSealCShake256.cshake256(
            data: Data(bytes),
            domain: domain,
            count: 32
        )
    }

    func pointKey(_ point: [Fq]) -> String {
        point.map { String($0.v) }.joined(separator: ":")
    }

    func pointKey(_ oracle: SpartanOracleID) -> String {
        "\(oracle.kind.rawValue):\(oracle.index ?? -1)"
    }

    private func makeDirectPackedOpening(
        material: DirectPackedWitnessMaterial,
        commitment: HachiPCSCommitment,
        point: [Fq],
        evaluation: Fq,
        context: MetalContext?
    ) throws -> HachiDirectPackedOpeningProof {
        let statement = try makeDirectPackedStatement(
            commitment: commitment,
            point: point,
            evaluation: evaluation
        )
        let proof = try ShortLinearWitnessPoK.prove(
            statement: statement,
            witness: material,
            context: context
        )
        return HachiDirectPackedOpeningProof(
            packedChunkCount: commitment.packedChunkCount,
            relationProof: proof
        )
    }

    private func verifyDirectPackedOpening(
        opening: HachiPCSOpening,
        commitment: HachiPCSCommitment,
        point: [Fq],
        context: MetalContext?,
        diagnostics: inout HachiVerificationDiagnostics
    ) -> Bool {
        guard let directPacked = opening.directPacked else {
            diagnostics.recordFailure("missing direct-packed opening payload for \(pointKey(opening.oracle))")
            return false
        }
        guard commitment.mode == .directPacked else {
            diagnostics.recordArtifactDiff(
                oracle: opening.oracle,
                component: "commitmentMode",
                detail: "expected direct-packed commitment mode"
            )
            return false
        }
        guard directPacked.packedChunkCount == commitment.packedChunkCount else {
            diagnostics.recordArtifactDiff(
                oracle: opening.oracle,
                component: "packedChunkCount",
                detail: "expected \(commitment.packedChunkCount), got \(directPacked.packedChunkCount)"
            )
            return false
        }
        guard commitment.statementDigest == directPackedStatementDigest(
            packedChunkCount: Int(commitment.packedChunkCount),
            valueCount: Int(commitment.valueCount)
        ) else {
            diagnostics.recordArtifactDiff(
                oracle: opening.oracle,
                component: "statementDigest",
                detail: "invalid direct-packed statement digest"
            )
            return false
        }

        do {
            let statement = try makeDirectPackedStatement(
                commitment: commitment,
                point: point,
                evaluation: opening.evaluation
            )
            guard try ShortLinearWitnessPoK.verify(
                statement: statement,
                proof: directPacked.relationProof,
                context: context
            ) else {
                diagnostics.recordArtifactDiff(
                    oracle: opening.oracle,
                    component: "relationProof",
                    detail: "direct-packed short linear witness proof rejected"
                )
                return false
            }
            return true
        } catch {
            diagnostics.recordArtifactDiff(
                oracle: opening.oracle,
                component: "relationProof",
                detail: "verification failed with error: \(error)"
            )
            return false
        }
    }

    private func directPackedBindingKey(slotCount: Int) -> AjtaiKey {
        AjtaiKey.expand(
            seed: directPackedParameters.witnessBindingSeed,
            slotCount: max(1, slotCount)
        )
    }

    private func directPackedRelationKey(slotCount: Int) -> AjtaiKey {
        AjtaiKey.expand(
            seed: directPackedParameters.relationSeed,
            slotCount: max(1, slotCount)
        )
    }

    private func directPackedOuterKey(slotCount: Int) -> AjtaiKey {
        AjtaiKey.expand(
            seed: directPackedParameters.outerSeed,
            slotCount: max(1, slotCount)
        )
    }

    private func directPackedBindingImageKey(slotCount: Int) -> AjtaiKey {
        AjtaiKey.expand(
            seed: directPackedParameters.bindingImageSeed,
            slotCount: max(1, slotCount)
        )
    }

    private func directPackedRelationImageKey(slotCount: Int) -> AjtaiKey {
        AjtaiKey.expand(
            seed: directPackedParameters.relationImageSeed,
            slotCount: max(1, slotCount)
        )
    }

    private func directPackedEvaluationImageKey() -> AjtaiKey {
        AjtaiKey.expand(
            seed: directPackedParameters.evaluationImageSeed,
            slotCount: 1
        )
    }

    private func directPackedOuterImageKey(slotCount: Int) -> AjtaiKey {
        AjtaiKey.expand(
            seed: directPackedParameters.outerImageSeed,
            slotCount: max(1, slotCount)
        )
    }

    func makePackedEqLinearFunctional(
        point: [Fq],
        ell: Int,
        packedChunkCount: Int,
        valueCount: Int
    ) -> [[Fq]] {
        precondition(point.count == ell)
        precondition(packedChunkCount >= 1)
        let evaluationCount = 1 << ell
        precondition(valueCount == evaluationCount)

        let weights = multilinearEqWeights(point: point)
        return (0..<packedChunkCount).map { chunkIndex in
            (0..<RingElement.degree).map { coeffIndex in
                let flatIndex = chunkIndex * RingElement.degree + coeffIndex
                return flatIndex < weights.count ? weights[flatIndex] : .zero
            }
        }
    }

    private func multilinearEqWeights(point: [Fq]) -> [Fq] {
        let evaluationCount = 1 << point.count
        return (0..<evaluationCount).map { index in
            point.enumerated().reduce(Fq.one) { partial, entry in
                let bit = (index >> entry.offset) & 1
                return partial * (bit == 0 ? (Fq.one - entry.element) : entry.element)
            }
        }
    }

    private func buildDirectPackedWitnessMaterial(
        packedWitness: [RingElement],
        context: MetalContext?
    ) throws -> DirectPackedWitnessMaterial {
        return try ShortLinearWitnessPoK.buildWitnessMaterial(
            packedWitness: packedWitness,
            parameters: directPackedParameters,
            relationKey: directPackedRelationKey(slotCount: Int(directPackedParameters.decompositionLimbs)),
            outerKey: directPackedOuterKey(slotCount: Int(directPackedParameters.decompositionLimbs)),
            context: context
        )
    }

    private func makeDirectPackedStatement(
        commitment: HachiPCSCommitment,
        point: [Fq],
        evaluation: Fq
    ) throws -> ShortLinearWitnessStatement {
        let packedChunkCount = Int(commitment.packedChunkCount)
        let limbCount = Int(directPackedParameters.decompositionLimbs)
        let lambda = makeDirectPackedEvaluationWeights(
            point: point,
            packedChunkCount: packedChunkCount,
            valueCount: Int(commitment.valueCount)
        )
        let bindingKey = directPackedBindingKey(slotCount: limbCount)
        let relationKey = directPackedRelationKey(slotCount: limbCount)
        let outerKey = directPackedOuterKey(slotCount: limbCount)

        return ShortLinearWitnessStatement(
            parameters: directPackedParameters,
            statementDigest: commitment.statementDigest,
            evaluationWeightDigest: digest(
                lambda.flatMap { chunk in
                    chunk.flatMap { $0.toBytes() }
                },
                domain: "NuMeQ.Decider.Hachi.DirectPacked.Lambda"
            ),
            chunkCount: packedChunkCount,
            limbCount: limbCount,
            bindingKey: bindingKey,
            relationKey: relationKey,
            outerKey: outerKey,
            bindingImageKey: directPackedBindingImageKey(slotCount: packedChunkCount),
            relationImageKey: directPackedRelationImageKey(slotCount: packedChunkCount),
            evaluationImageKey: directPackedEvaluationImageKey(),
            outerImageKey: directPackedOuterImageKey(slotCount: packedChunkCount),
            evaluationWeights: lambda,
            outerCommitments: commitment.directPackedOuterCommitments,
            claimedValue: evaluation
        )
    }

    private func makeDirectPackedEvaluationWeights(
        point: [Fq],
        packedChunkCount: Int,
        valueCount: Int
    ) -> [[RingElement]] {
        let lambdaByChunk = makePackedEqLinearFunctional(
            point: point,
            ell: point.count,
            packedChunkCount: packedChunkCount,
            valueCount: valueCount
        )
        let base = Fq(UInt64(directPackedParameters.decompositionBase))
        return lambdaByChunk.map { chunkWeights in
            var scale = Fq.one
            var limbWeights = [RingElement]()
            limbWeights.reserveCapacity(Int(directPackedParameters.decompositionLimbs))
            for _ in 0..<Int(directPackedParameters.decompositionLimbs) {
                limbWeights.append(
                    RingElement(coeffs: chunkWeights.map { scale * $0 })
                )
                scale *= base
            }
            return limbWeights
        }
    }

    private func directPackedStatementDigest(
        packedChunkCount: Int,
        valueCount: Int
    ) -> [UInt8] {
        var writer = BinaryWriter()
        writer.appendLengthPrefixed(directPackedParameters.parameterDigest)
        writer.append(UInt32(clamping: packedChunkCount))
        writer.append(UInt32(clamping: valueCount))
        return digest(
            [UInt8](writer.data),
            domain: "NuMeQ.Decider.Hachi.DirectPacked.Statement"
        )
    }

    private func compareCommitment(
        provided: HachiPCSCommitment,
        expected: HachiPCSCommitment,
        diagnostics: inout HachiVerificationDiagnostics
    ) -> Bool {
        for diff in diffCommitments(expected: expected, actual: provided) {
            diagnostics.recordArtifactDiff(
                oracle: diff.oracle,
                component: diff.component,
                detail: diff.detail
            )
            return false
        }
        return true
    }

    private func diffArtifacts(
        expected: HachiPCSOracleArtifact,
        actual: HachiPCSOracleArtifact
    ) -> [HachiPCSArtifactDiff] {
        let commitmentDiffs = diffCommitments(
            expected: expected.commitment,
            actual: actual.commitment
        )
        if commitmentDiffs.isEmpty == false {
            return commitmentDiffs
        }
        return []
    }

    private func diffCommitments(
        expected: HachiPCSCommitment,
        actual: HachiPCSCommitment
    ) -> [HachiPCSArtifactDiff] {
        let oracle = expected.oracle
        guard actual.oracle == expected.oracle else {
            return [
                HachiPCSArtifactDiff(
                    oracle: oracle,
                    component: "oracle",
                    detail: "expected \(pointKey(expected.oracle)), got \(pointKey(actual.oracle))"
                )
            ]
        }
        if actual.mode != expected.mode {
            return [HachiPCSArtifactDiff(oracle: oracle, component: "mode", detail: "expected \(expected.mode), got \(actual.mode)")]
        }
        if actual.tableCommitment != expected.tableCommitment {
            return [HachiPCSArtifactDiff(oracle: oracle, component: "tableCommitment", detail: "commitment mismatch")]
        }
        if actual.directPackedOuterCommitments != expected.directPackedOuterCommitments {
            return [HachiPCSArtifactDiff(oracle: oracle, component: "directPackedOuterCommitments", detail: "outer commitment vector mismatch")]
        }
        if actual.parameterDigest != expected.parameterDigest {
            return [HachiPCSArtifactDiff(oracle: oracle, component: "parameterDigest", detail: "parameter digest mismatch")]
        }
        if actual.valueCount != expected.valueCount {
            return [HachiPCSArtifactDiff(oracle: oracle, component: "valueCount", detail: "expected \(expected.valueCount), got \(actual.valueCount)")]
        }
        if actual.packedChunkCount != expected.packedChunkCount {
            return [HachiPCSArtifactDiff(oracle: oracle, component: "packedChunkCount", detail: "expected \(expected.packedChunkCount), got \(actual.packedChunkCount)")]
        }
        if actual.statementDigest != expected.statementDigest {
            return [HachiPCSArtifactDiff(oracle: oracle, component: "statementDigest", detail: "digest mismatch")]
        }
        if actual.tableDigest != expected.tableDigest {
            return [HachiPCSArtifactDiff(oracle: oracle, component: "tableDigest", detail: "digest mismatch")]
        }
        return []
    }
}

private struct HachiPCSOracleArtifact {
    let commitment: HachiPCSCommitment
    let directPackedWitnessMaterial: DirectPackedWitnessMaterial?
}
