import Foundation
import Metal

internal struct DirectPackedWitnessChunk {
    let packedWitness: RingElement
    let shortWitness: [RingElement]
    let outerDigits: [RingElement]
    let outerCommitment: AjtaiCommitment
}

internal struct DirectPackedWitnessMaterial {
    let packedWitness: [RingElement]
    let chunks: [DirectPackedWitnessChunk]
}

internal struct ShortLinearWitnessStatement {
    let parameters: DirectPackedPoKParameters
    let statementDigest: [UInt8]
    let evaluationWeightDigest: [UInt8]
    let chunkCount: Int
    let limbCount: Int
    let bindingKey: AjtaiKey
    let relationKey: AjtaiKey
    let outerKey: AjtaiKey
    let bindingImageKey: AjtaiKey
    let relationImageKey: AjtaiKey
    let evaluationImageKey: AjtaiKey
    let outerImageKey: AjtaiKey
    let evaluationWeights: [[RingElement]]
    let outerCommitments: [AjtaiCommitment]
    let claimedValue: Fq
}

internal enum ShortLinearWitnessPoKError: Error, Sendable {
    case rejectionExhausted
    case malformedStatement
}

internal enum ShortLinearWitnessPoK {
    private struct DiscreteGaussianTable {
        let cumulativeMagnitudes: [Double]
    }

    private static let discreteGaussianSupportMultiplier = 16.0
    private static let canonicalDiscreteGaussianTables: [UInt32: DiscreteGaussianTable] = {
        let canonicalSigmas: [UInt32] = [4096, 8192]
        var tables = [UInt32: DiscreteGaussianTable]()
        tables.reserveCapacity(canonicalSigmas.count)
        for sigma in canonicalSigmas {
            tables[sigma] = buildDiscreteGaussianTable(sigma: sigma)
        }
        return tables
    }()

    static func buildWitnessMaterial(
        packedWitness: [RingElement],
        parameters: DirectPackedPoKParameters,
        relationKey: AjtaiKey,
        outerKey: AjtaiKey,
        context: MetalContext?
    ) throws -> DirectPackedWitnessMaterial {
        let chunks = try packedWitness.map { packed -> DirectPackedWitnessChunk in
            let shortWitness = try flattenDecomposition(
                of: [packed],
                base: parameters.decompositionBase,
                limbs: parameters.decompositionLimbs,
                context: context
            )
            let innerCommitment = try ringLinearForm(
                coefficients: relationKey.keys,
                witness: shortWitness,
                context: context
            )
            let outerDigits = try flattenDecomposition(
                of: [innerCommitment],
                base: parameters.decompositionBase,
                limbs: parameters.decompositionLimbs,
                context: context
            )
            let outerCommitment = AjtaiCommitment(
                value: try ringLinearForm(
                    coefficients: outerKey.keys,
                    witness: outerDigits,
                    context: context
                )
            )
            return DirectPackedWitnessChunk(
                packedWitness: packed,
                shortWitness: shortWitness,
                outerDigits: outerDigits,
                outerCommitment: outerCommitment
            )
        }
        return DirectPackedWitnessMaterial(
            packedWitness: packedWitness,
            chunks: chunks
        )
    }

    static func prove(
        statement: ShortLinearWitnessStatement,
        witness: DirectPackedWitnessMaterial,
        context: MetalContext?
    ) throws -> ShortLinearWitnessProof {
        guard witness.chunks.count == statement.chunkCount,
              statement.outerCommitments.count == statement.chunkCount,
              statement.evaluationWeights.count == statement.chunkCount,
              statement.bindingKey.slotCount == statement.limbCount,
              statement.relationKey.slotCount == statement.limbCount,
              statement.outerKey.slotCount == statement.limbCount,
              statement.bindingImageKey.slotCount == statement.chunkCount,
              statement.relationImageKey.slotCount == statement.chunkCount,
              statement.evaluationImageKey.slotCount == 1,
              statement.outerImageKey.slotCount == statement.chunkCount else {
            throw ShortLinearWitnessPoKError.malformedStatement
        }

        let paddedCount = nextPowerOfTwo(statement.limbCount)
        var shortStates = witness.chunks.map { padVector($0.shortWitness, to: paddedCount) }
        var outerStates = witness.chunks.map { padVector($0.outerDigits, to: paddedCount) }
        var bindingCoefficients = Array(
            repeating: padVector(statement.bindingKey.keys, to: paddedCount),
            count: statement.chunkCount
        )
        var relationShortCoefficients = Array(
            repeating: padVector(statement.relationKey.keys, to: paddedCount),
            count: statement.chunkCount
        )
        var relationOuterCoefficients = Array(
            repeating: padVector(decodeCoefficients(count: statement.limbCount, base: statement.parameters.decompositionBase), to: paddedCount),
            count: statement.chunkCount
        )
        var evaluationWeights = statement.evaluationWeights.map { padVector($0, to: paddedCount) }
        var outerCoefficients = Array(
            repeating: padVector(statement.outerKey.keys, to: paddedCount),
            count: statement.chunkCount
        )

        let initialBindingVector = try witness.chunks.map {
            try ringLinearForm(
                coefficients: statement.bindingKey.keys,
                witness: $0.shortWitness,
                context: context
            )
        }
        let initialBindingCommitment = try commitImage(
            key: statement.bindingImageKey,
            values: initialBindingVector,
            context: context
        )
        let zeroTargetCommitment = try commitImage(
            key: statement.relationImageKey,
            values: [RingElement](repeating: .zero, count: statement.chunkCount),
            context: context
        )
        let initialEvaluationCommitment = try commitImage(
            key: statement.evaluationImageKey,
            values: [RingElement(constant: statement.claimedValue)],
            context: context
        )
        let initialOuterCommitment = try commitImage(
            key: statement.outerImageKey,
            values: statement.outerCommitments.map(\.value),
            context: context
        )

        var bindingTarget = initialBindingCommitment
        var relationTarget = zeroTargetCommitment
        var evaluationTarget = initialEvaluationCommitment
        var outerTarget = initialOuterCommitment
        var transcript = makeTranscript(
            statement: statement,
            initialBindingCommitment: initialBindingCommitment
        )
        var accumulatorRounds = [ShortLinearWitnessAccumulatorRound]()
        accumulatorRounds.reserveCapacity(expectedRoundCount(forPaddedCount: paddedCount))

        while paddedVectorWidth(of: shortStates) > 1 {
            let half = paddedVectorWidth(of: shortStates) / 2
            var bindingLeft = [RingElement]()
            var bindingRight = [RingElement]()
            var relationLeft = [RingElement]()
            var relationRight = [RingElement]()
            var outerLeft = [RingElement]()
            var outerRight = [RingElement]()
            var evaluationLeft = Fq.zero
            var evaluationRight = Fq.zero

            bindingLeft.reserveCapacity(statement.chunkCount)
            bindingRight.reserveCapacity(statement.chunkCount)
            relationLeft.reserveCapacity(statement.chunkCount)
            relationRight.reserveCapacity(statement.chunkCount)
            outerLeft.reserveCapacity(statement.chunkCount)
            outerRight.reserveCapacity(statement.chunkCount)

            for chunkIndex in 0..<statement.chunkCount {
                let shortLeft = Array(shortStates[chunkIndex][..<half])
                let shortRight = Array(shortStates[chunkIndex][half...])
                let outerLeftState = Array(outerStates[chunkIndex][..<half])
                let outerRightState = Array(outerStates[chunkIndex][half...])

                let bindingLeftCoefficients = Array(bindingCoefficients[chunkIndex][..<half])
                let bindingRightCoefficients = Array(bindingCoefficients[chunkIndex][half...])
                let relationShortLeft = Array(relationShortCoefficients[chunkIndex][..<half])
                let relationShortRight = Array(relationShortCoefficients[chunkIndex][half...])
                let relationOuterLeft = Array(relationOuterCoefficients[chunkIndex][..<half])
                let relationOuterRight = Array(relationOuterCoefficients[chunkIndex][half...])
                let evaluationLeftCoefficients = Array(evaluationWeights[chunkIndex][..<half])
                let evaluationRightCoefficients = Array(evaluationWeights[chunkIndex][half...])
                let outerLeftCoefficients = Array(outerCoefficients[chunkIndex][..<half])
                let outerRightCoefficients = Array(outerCoefficients[chunkIndex][half...])

                bindingLeft.append(
                    try ringLinearForm(
                        coefficients: bindingRightCoefficients,
                        witness: shortLeft,
                        context: context
                    )
                )
                bindingRight.append(
                    try ringLinearForm(
                        coefficients: bindingLeftCoefficients,
                        witness: shortRight,
                        context: context
                    )
                )
                relationLeft.append(
                    try ringLinearForm(
                        coefficients: relationShortRight,
                        witness: shortLeft,
                        context: context
                    )
                    + (try ringLinearForm(
                        coefficients: relationOuterRight,
                        witness: outerLeftState,
                        context: context
                    ))
                )
                relationRight.append(
                    try ringLinearForm(
                        coefficients: relationShortLeft,
                        witness: shortRight,
                        context: context
                    )
                    + (try ringLinearForm(
                        coefficients: relationOuterLeft,
                        witness: outerRightState,
                        context: context
                    ))
                )
                evaluationLeft += try scalarLinearForm(
                    weights: evaluationRightCoefficients,
                    witness: shortLeft,
                    context: context
                )
                evaluationRight += try scalarLinearForm(
                    weights: evaluationLeftCoefficients,
                    witness: shortRight,
                    context: context
                )
                outerLeft.append(
                    try ringLinearForm(
                        coefficients: outerRightCoefficients,
                        witness: outerLeftState,
                        context: context
                    )
                )
                outerRight.append(
                    try ringLinearForm(
                        coefficients: outerLeftCoefficients,
                        witness: outerRightState,
                        context: context
                    )
                )
            }

            let round = ShortLinearWitnessAccumulatorRound(
                bindingLeft: try commitImage(
                    key: statement.bindingImageKey,
                    values: bindingLeft,
                    context: context
                ),
                bindingRight: try commitImage(
                    key: statement.bindingImageKey,
                    values: bindingRight,
                    context: context
                ),
                relationLeft: try commitImage(
                    key: statement.relationImageKey,
                    values: relationLeft,
                    context: context
                ),
                relationRight: try commitImage(
                    key: statement.relationImageKey,
                    values: relationRight,
                    context: context
                ),
                evaluationLeft: try commitImage(
                    key: statement.evaluationImageKey,
                    values: [RingElement(constant: evaluationLeft)],
                    context: context
                ),
                evaluationRight: try commitImage(
                    key: statement.evaluationImageKey,
                    values: [RingElement(constant: evaluationRight)],
                    context: context
                ),
                outerLeft: try commitImage(
                    key: statement.outerImageKey,
                    values: outerLeft,
                    context: context
                ),
                outerRight: try commitImage(
                    key: statement.outerImageKey,
                    values: outerRight,
                    context: context
                )
            )
            accumulatorRounds.append(round)
            absorb(round: round, transcript: &transcript)

            let challenge = foldingChallenge(transcript: &transcript)
            guard let challengeInverse = challenge.inverted() else {
                throw ShortLinearWitnessPoKError.malformedStatement
            }
            bindingTarget = AjtaiCommitment(
                value: bindingTarget.value
                    + challenge * round.bindingRight.value
                    + challengeInverse * round.bindingLeft.value
            )
            relationTarget = AjtaiCommitment(
                value: relationTarget.value
                    + challenge * round.relationRight.value
                    + challengeInverse * round.relationLeft.value
            )
            evaluationTarget = AjtaiCommitment(
                value: evaluationTarget.value
                    + challenge * round.evaluationRight.value
                    + challengeInverse * round.evaluationLeft.value
            )
            outerTarget = AjtaiCommitment(
                value: outerTarget.value
                    + challenge * round.outerRight.value
                    + challengeInverse * round.outerLeft.value
            )

            shortStates = try shortStates.map { try fold(vector: $0, challenge: challenge, context: context) }
            outerStates = try outerStates.map { try fold(vector: $0, challenge: challenge, context: context) }
            bindingCoefficients = try bindingCoefficients.map { try fold(vector: $0, challenge: challengeInverse, context: context) }
            relationShortCoefficients = try relationShortCoefficients.map { try fold(vector: $0, challenge: challengeInverse, context: context) }
            relationOuterCoefficients = try relationOuterCoefficients.map { try fold(vector: $0, challenge: challengeInverse, context: context) }
            evaluationWeights = try evaluationWeights.map { try fold(vector: $0, challenge: challengeInverse, context: context) }
            outerCoefficients = try outerCoefficients.map { try fold(vector: $0, challenge: challengeInverse, context: context) }
        }

        let residualShort = try shortStates.map {
            guard let first = $0.first else { throw ShortLinearWitnessPoKError.malformedStatement }
            return first
        }
        let residualOuter = try outerStates.map {
            guard let first = $0.first else { throw ShortLinearWitnessPoKError.malformedStatement }
            return first
        }
        let finalBindingCoefficients = try bindingCoefficients.map {
            guard let first = $0.first else { throw ShortLinearWitnessPoKError.malformedStatement }
            return first
        }
        let finalRelationShortCoefficients = try relationShortCoefficients.map {
            guard let first = $0.first else { throw ShortLinearWitnessPoKError.malformedStatement }
            return first
        }
        let finalRelationOuterCoefficients = try relationOuterCoefficients.map {
            guard let first = $0.first else { throw ShortLinearWitnessPoKError.malformedStatement }
            return first
        }
        let finalEvaluationWeights = try evaluationWeights.map {
            guard let first = $0.first else { throw ShortLinearWitnessPoKError.malformedStatement }
            return first
        }
        let finalOuterCoefficients = try outerCoefficients.map {
            guard let first = $0.first else { throw ShortLinearWitnessPoKError.malformedStatement }
            return first
        }

        for restartNonce in UInt32(0)..<UInt32(statement.parameters.maxRestartCount) {
            let maskShort = sampleMaskVectors(
                count: statement.chunkCount,
                sigma: statement.parameters.finalMaskSigma,
                statementDigest: statement.statementDigest,
                evaluationWeightDigest: statement.evaluationWeightDigest,
                bindingCommitment: initialBindingCommitment,
                restartNonce: restartNonce,
                label: "short"
            )
            let maskOuter = sampleMaskVectors(
                count: statement.chunkCount,
                sigma: statement.parameters.finalMaskSigma,
                statementDigest: statement.statementDigest,
                evaluationWeightDigest: statement.evaluationWeightDigest,
                bindingCommitment: initialBindingCommitment,
                restartNonce: restartNonce,
                label: "outer"
            )

            let bindingMaskVector = zip(finalBindingCoefficients, maskShort).map { coefficient, mask in
                coefficient * mask
            }
            let relationMaskVector = zip3(finalRelationShortCoefficients, maskShort, finalRelationOuterCoefficients, maskOuter).map {
                $0.0 * $0.1 + $0.2 * $0.3
            }
            let evaluationMask = zip(maskShort, finalEvaluationWeights).reduce(Fq.zero) { partial, pair in
                partial + constantTermInnerProduct(pair.0, pair.1)
            }
            let outerMaskVector = zip(finalOuterCoefficients, maskOuter).map { coefficient, mask in
                coefficient * mask
            }

            let finalOpeningTemplate = ShortLinearWitnessFinalOpening(
                bindingMaskCommitment: try commitImage(
                    key: statement.bindingImageKey,
                    values: bindingMaskVector,
                    context: context
                ),
                relationMaskCommitment: try commitImage(
                    key: statement.relationImageKey,
                    values: relationMaskVector,
                    context: context
                ),
                evaluationMaskCommitment: try commitImage(
                    key: statement.evaluationImageKey,
                    values: [RingElement(constant: evaluationMask)],
                    context: context
                ),
                outerMaskCommitment: try commitImage(
                    key: statement.outerImageKey,
                    values: outerMaskVector,
                    context: context
                ),
                shortResponses: [],
                outerResponses: []
            )

            var sigmaTranscript = transcript
            sigmaTranscript.absorbLabel("restart=\(restartNonce)")
            absorb(finalOpening: finalOpeningTemplate, transcript: &sigmaTranscript)
            let sigmaChallenge = responseChallenge(transcript: &sigmaTranscript)

            let shortResponses = zip(maskShort, residualShort).map { mask, residual in
                mask + sigmaChallenge * residual
            }
            let outerResponses = zip(maskOuter, residualOuter).map { mask, residual in
                mask + sigmaChallenge * residual
            }
            guard responsesStayBound(
                shortResponses: shortResponses,
                outerResponses: outerResponses,
                bound: statement.parameters.maxAcceptedResponseBound
            ) else {
                continue
            }
            guard rejectionAccepts(
                maskShort: maskShort,
                maskOuter: maskOuter,
                shortResponses: shortResponses,
                outerResponses: outerResponses,
                sigma: statement.parameters.finalMaskSigma,
                rejectionSlack: statement.parameters.rejectionSlack,
                statement: statement,
                bindingCommitment: initialBindingCommitment,
                restartNonce: restartNonce
            ) else {
                continue
            }

            let finalOpening = ShortLinearWitnessFinalOpening(
                bindingMaskCommitment: finalOpeningTemplate.bindingMaskCommitment,
                relationMaskCommitment: finalOpeningTemplate.relationMaskCommitment,
                evaluationMaskCommitment: finalOpeningTemplate.evaluationMaskCommitment,
                outerMaskCommitment: finalOpeningTemplate.outerMaskCommitment,
                shortResponses: shortResponses,
                outerResponses: outerResponses
            )
            let proof = ShortLinearWitnessProof(
                initialBindingCommitment: initialBindingCommitment,
                accumulatorRounds: accumulatorRounds,
                finalOpening: finalOpening,
                restartNonce: restartNonce,
                transcriptBinding: []
            )
            let binding = transcriptBindingDigest(statement: statement, proof: proof)
            return ShortLinearWitnessProof(
                initialBindingCommitment: initialBindingCommitment,
                accumulatorRounds: accumulatorRounds,
                finalOpening: finalOpening,
                restartNonce: restartNonce,
                transcriptBinding: binding
            )
        }

        throw ShortLinearWitnessPoKError.rejectionExhausted
    }

    static func verify(
        statement: ShortLinearWitnessStatement,
        proof: ShortLinearWitnessProof,
        context: MetalContext?
    ) throws -> Bool {
        guard proof.transcriptBinding == transcriptBindingDigest(statement: statement, proof: proof),
              statement.outerCommitments.count == statement.chunkCount,
              statement.evaluationWeights.count == statement.chunkCount,
              proof.finalOpening.shortResponses.count == statement.chunkCount,
              proof.finalOpening.outerResponses.count == statement.chunkCount,
              responsesStayBound(
                shortResponses: proof.finalOpening.shortResponses,
                outerResponses: proof.finalOpening.outerResponses,
                bound: statement.parameters.maxAcceptedResponseBound
              ) else {
            return false
        }

        let paddedCount = nextPowerOfTwo(statement.limbCount)
        var bindingCoefficients = Array(
            repeating: padVector(statement.bindingKey.keys, to: paddedCount),
            count: statement.chunkCount
        )
        var relationShortCoefficients = Array(
            repeating: padVector(statement.relationKey.keys, to: paddedCount),
            count: statement.chunkCount
        )
        var relationOuterCoefficients = Array(
            repeating: padVector(decodeCoefficients(count: statement.limbCount, base: statement.parameters.decompositionBase), to: paddedCount),
            count: statement.chunkCount
        )
        var evaluationWeights = statement.evaluationWeights.map { padVector($0, to: paddedCount) }
        var outerCoefficients = Array(
            repeating: padVector(statement.outerKey.keys, to: paddedCount),
            count: statement.chunkCount
        )

        let expectedRoundCount = expectedRoundCount(forPaddedCount: paddedCount)
        guard proof.accumulatorRounds.count == expectedRoundCount else {
            return false
        }

        var bindingTarget = proof.initialBindingCommitment
        var relationTarget = try commitImage(
            key: statement.relationImageKey,
            values: [RingElement](repeating: .zero, count: statement.chunkCount),
            context: context
        )
        var evaluationTarget = try commitImage(
            key: statement.evaluationImageKey,
            values: [RingElement(constant: statement.claimedValue)],
            context: context
        )
        var outerTarget = try commitImage(
            key: statement.outerImageKey,
            values: statement.outerCommitments.map(\.value),
            context: context
        )
        var transcript = makeTranscript(
            statement: statement,
            initialBindingCommitment: proof.initialBindingCommitment
        )

        for round in proof.accumulatorRounds {
            absorb(round: round, transcript: &transcript)
            let challenge = foldingChallenge(transcript: &transcript)
            guard let challengeInverse = challenge.inverted() else {
                return false
            }
            bindingTarget = AjtaiCommitment(
                value: bindingTarget.value
                    + challenge * round.bindingRight.value
                    + challengeInverse * round.bindingLeft.value
            )
            relationTarget = AjtaiCommitment(
                value: relationTarget.value
                    + challenge * round.relationRight.value
                    + challengeInverse * round.relationLeft.value
            )
            evaluationTarget = AjtaiCommitment(
                value: evaluationTarget.value
                    + challenge * round.evaluationRight.value
                    + challengeInverse * round.evaluationLeft.value
            )
            outerTarget = AjtaiCommitment(
                value: outerTarget.value
                    + challenge * round.outerRight.value
                    + challengeInverse * round.outerLeft.value
            )

            bindingCoefficients = try bindingCoefficients.map { try fold(vector: $0, challenge: challengeInverse, context: context) }
            relationShortCoefficients = try relationShortCoefficients.map { try fold(vector: $0, challenge: challengeInverse, context: context) }
            relationOuterCoefficients = try relationOuterCoefficients.map { try fold(vector: $0, challenge: challengeInverse, context: context) }
            evaluationWeights = try evaluationWeights.map { try fold(vector: $0, challenge: challengeInverse, context: context) }
            outerCoefficients = try outerCoefficients.map { try fold(vector: $0, challenge: challengeInverse, context: context) }
        }

        let finalBindingCoefficients = try bindingCoefficients.map {
            guard let first = $0.first else { throw ShortLinearWitnessPoKError.malformedStatement }
            return first
        }
        let finalRelationShortCoefficients = try relationShortCoefficients.map {
            guard let first = $0.first else { throw ShortLinearWitnessPoKError.malformedStatement }
            return first
        }
        let finalRelationOuterCoefficients = try relationOuterCoefficients.map {
            guard let first = $0.first else { throw ShortLinearWitnessPoKError.malformedStatement }
            return first
        }
        let finalEvaluationWeights = try evaluationWeights.map {
            guard let first = $0.first else { throw ShortLinearWitnessPoKError.malformedStatement }
            return first
        }
        let finalOuterCoefficients = try outerCoefficients.map {
            guard let first = $0.first else { throw ShortLinearWitnessPoKError.malformedStatement }
            return first
        }

        var sigmaTranscript = transcript
        sigmaTranscript.absorbLabel("restart=\(proof.restartNonce)")
        absorb(finalOpening: proof.finalOpening.maskCommitmentsOnly, transcript: &sigmaTranscript)
        let sigmaChallenge = responseChallenge(transcript: &sigmaTranscript)

        let bindingResponseCommitment = try commitImage(
            key: statement.bindingImageKey,
            values: zip(finalBindingCoefficients, proof.finalOpening.shortResponses).map { coefficient, response in
                coefficient * response
            },
            context: context
        )
        let relationResponseCommitment = try commitImage(
            key: statement.relationImageKey,
            values: zip3(
                finalRelationShortCoefficients,
                proof.finalOpening.shortResponses,
                finalRelationOuterCoefficients,
                proof.finalOpening.outerResponses
            ).map { $0.0 * $0.1 + $0.2 * $0.3 },
            context: context
        )
        let evaluationResponseCommitment = try commitImage(
            key: statement.evaluationImageKey,
            values: [
                RingElement(
                    constant: zip(proof.finalOpening.shortResponses, finalEvaluationWeights).reduce(Fq.zero) { partial, pair in
                        partial + constantTermInnerProduct(pair.0, pair.1)
                    }
                )
            ],
            context: context
        )
        let outerResponseCommitment = try commitImage(
            key: statement.outerImageKey,
            values: zip(finalOuterCoefficients, proof.finalOpening.outerResponses).map { coefficient, response in
                coefficient * response
            },
            context: context
        )

        return bindingResponseCommitment.value
            == proof.finalOpening.bindingMaskCommitment.value + sigmaChallenge * bindingTarget.value
            && relationResponseCommitment.value
            == proof.finalOpening.relationMaskCommitment.value + sigmaChallenge * relationTarget.value
            && evaluationResponseCommitment.value
            == proof.finalOpening.evaluationMaskCommitment.value + sigmaChallenge * evaluationTarget.value
            && outerResponseCommitment.value
            == proof.finalOpening.outerMaskCommitment.value + sigmaChallenge * outerTarget.value
    }

    private static func makeTranscript(
        statement: ShortLinearWitnessStatement,
        initialBindingCommitment: AjtaiCommitment
    ) -> NuTranscriptField {
        var transcript = NuTranscriptField(domain: "NuMeQ.Decider.Hachi.DirectPacked.Accumulator")
        transcript.absorbLabel("parameters")
        absorb(bytes: statement.parameters.accumulatorDomain.bytes, transcript: &transcript)
        absorb(bytes: statement.parameters.securityProfileDigest, transcript: &transcript)
        transcript.absorbLabel("statement")
        absorb(bytes: statement.statementDigest, transcript: &transcript)
        transcript.absorbLabel("evaluationWeights")
        absorb(bytes: statement.evaluationWeightDigest, transcript: &transcript)
        transcript.absorb(ring: initialBindingCommitment.value)
        transcript.absorbLabel("outerCommitments")
        statement.outerCommitments.forEach { transcript.absorb(ring: $0.value) }
        transcript.absorb(field: statement.claimedValue)
        return transcript
    }

    private static func absorb(
        round: ShortLinearWitnessAccumulatorRound,
        transcript: inout NuTranscriptField
    ) {
        transcript.absorb(ring: round.bindingLeft.value)
        transcript.absorb(ring: round.bindingRight.value)
        transcript.absorb(ring: round.relationLeft.value)
        transcript.absorb(ring: round.relationRight.value)
        transcript.absorb(ring: round.evaluationLeft.value)
        transcript.absorb(ring: round.evaluationRight.value)
        transcript.absorb(ring: round.outerLeft.value)
        transcript.absorb(ring: round.outerRight.value)
    }

    private static func absorb(
        finalOpening: ShortLinearWitnessFinalOpening,
        transcript: inout NuTranscriptField
    ) {
        transcript.absorb(ring: finalOpening.bindingMaskCommitment.value)
        transcript.absorb(ring: finalOpening.relationMaskCommitment.value)
        transcript.absorb(ring: finalOpening.evaluationMaskCommitment.value)
        transcript.absorb(ring: finalOpening.outerMaskCommitment.value)
    }

    private static func foldingChallenge(transcript: inout NuTranscriptField) -> Fq {
        switch transcript.squeezeChallenge().v % 2 {
        case 0:
            return -Fq.one
        default:
            return .one
        }
    }

    private static func responseChallenge(transcript: inout NuTranscriptField) -> Fq {
        switch transcript.squeezeChallenge().v % 2 {
        case 0:
            return -Fq.one
        default:
            return .one
        }
    }

    private static func fold(
        vector: [RingElement],
        challenge: Fq,
        context: MetalContext?
    ) throws -> [RingElement] {
        precondition(vector.count.isMultiple(of: 2))
        let half = vector.count / 2
        let left = Array(vector[..<half])
        let right = Array(vector[half...])
        guard let context else {
            return zip(left, right).map { lhs, rhs in
                lhs + challenge * rhs
            }
        }
        return try AG64RingMetal.bindFold(
            context: context,
            challengeRings: [
                RingElement(constant: .one),
                RingElement(constant: challenge),
            ],
            inputs: [left, right],
            ringCount: half
        )
    }

    private static func ringLinearForm(
        coefficients: [RingElement],
        witness: [RingElement],
        context: MetalContext?
    ) throws -> RingElement {
        precondition(coefficients.count == witness.count)
        guard coefficients.isEmpty == false else { return .zero }
        guard let context else {
            return AjtaiCommitter.commit(
                key: AjtaiKey(keys: coefficients),
                witness: witness
            ).value
        }
        return try AjtaiCommitter.commitBatchMetal(
            context: context,
            key: AjtaiKey(keys: coefficients),
            witnessBatches: [witness]
        )[0].value
    }

    private static func commitImage(
        key: AjtaiKey,
        values: [RingElement],
        context: MetalContext?
    ) throws -> AjtaiCommitment {
        precondition(key.slotCount == values.count)
        guard let context else {
            return AjtaiCommitter.commit(key: key, witness: values)
        }
        return try AjtaiCommitter.commitBatchMetal(
            context: context,
            key: key,
            witnessBatches: [values]
        )[0]
    }

    private static func scalarLinearForm(
        weights: [RingElement],
        witness: [RingElement],
        context: MetalContext?
    ) throws -> Fq {
        precondition(weights.count == witness.count)
        guard weights.isEmpty == false else { return .zero }
        let sigmaWeights = weights.map(negacyclicSigma)
        if let context {
            let products = try AG64RingMetal.multiplyBatch(
                context: context,
                lhs: witness,
                rhs: sigmaWeights
            )
            return products.reduce(.zero) { partial, ring in
                partial + ring.coeffs[0]
            }
        }
        return zip(witness, sigmaWeights).reduce(.zero) { partial, pair in
            partial + (pair.0 * pair.1).coeffs[0]
        }
    }

    private static func constantTermInnerProduct(_ witness: RingElement, _ weight: RingElement) -> Fq {
        (witness * negacyclicSigma(weight)).coeffs[0]
    }

    private static func negacyclicSigma(_ value: RingElement) -> RingElement {
        var coeffs = [Fq](repeating: .zero, count: RingElement.degree)
        coeffs[0] = value.coeffs[0]
        for index in 1..<RingElement.degree {
            coeffs[RingElement.degree - index] = -value.coeffs[index]
        }
        return RingElement(coeffs: coeffs)
    }

    private static func sampleMaskVectors(
        count: Int,
        sigma: UInt32,
        statementDigest: [UInt8],
        evaluationWeightDigest: [UInt8],
        bindingCommitment: AjtaiCommitment,
        restartNonce: UInt32,
        label: String
    ) -> [RingElement] {
        (0..<count).map { vectorIndex in
            sampleMaskRing(
                sigma: sigma,
                statementDigest: statementDigest,
                evaluationWeightDigest: evaluationWeightDigest,
                bindingCommitment: bindingCommitment,
                restartNonce: restartNonce,
                label: label,
                vectorIndex: vectorIndex
            )
        }
    }

    private static func sampleMaskRing(
        sigma: UInt32,
        statementDigest: [UInt8],
        evaluationWeightDigest: [UInt8],
        bindingCommitment: AjtaiCommitment,
        restartNonce: UInt32,
        label: String,
        vectorIndex: Int
    ) -> RingElement {
        let coeffs = (0..<RingElement.degree).map { coefficientIndex in
            discreteGaussianCoefficient(
                sigma: sigma,
                statementDigest: statementDigest,
                evaluationWeightDigest: evaluationWeightDigest,
                bindingCommitment: bindingCommitment,
                restartNonce: restartNonce,
                label: label,
                vectorIndex: vectorIndex,
                coefficientIndex: coefficientIndex
            )
        }
        return RingElement(coeffs: coeffs)
    }

    // Inverse-CDF sampler over a centered integer Gaussian with negligible tail
    // truncation at 16*sigma, then reduced coefficientwise into Fq.
    private static func discreteGaussianCoefficient(
        sigma: UInt32,
        statementDigest: [UInt8],
        evaluationWeightDigest: [UInt8],
        bindingCommitment: AjtaiCommitment,
        restartNonce: UInt32,
        label: String,
        vectorIndex: Int,
        coefficientIndex: Int
    ) -> Fq {
        var writer = BinaryWriter()
        writer.appendLengthPrefixed(statementDigest)
        writer.appendLengthPrefixed(evaluationWeightDigest)
        writer.append(Data(bindingCommitment.value.toBytes()))
        writer.append(restartNonce)
        writer.append(UInt32(clamping: vectorIndex))
        writer.append(UInt32(clamping: coefficientIndex))
        writer.appendLengthPrefixed(Data(label.utf8))
        let digest = NuSealCShake256.cshake256(
            data: writer.data,
            domain: "NuMeQ.Decider.Hachi.DirectPacked.GaussianMask",
            count: 16
        )
        let magnitudeRaw = LittleEndianCodec.uint64(from: digest[0..<8])
        let signRaw = LittleEndianCodec.uint64(from: digest[8..<16])
        let magnitude = sampleDiscreteGaussianMagnitude(
            sigma: sigma,
            raw: magnitudeRaw
        )
        return Fq.fromCenteredMagnitude(
            magnitude,
            isNegative: magnitude != 0 && (signRaw & 1) == 1
        )
    }

    private static func sampleDiscreteGaussianMagnitude(
        sigma: UInt32,
        raw: UInt64
    ) -> UInt64 {
        let table = discreteGaussianTable(for: sigma)
        let target = unitInterval(from: raw)
        return UInt64(lowerBound(in: table.cumulativeMagnitudes, target: target))
    }

    private static func discreteGaussianTable(for sigma: UInt32) -> DiscreteGaussianTable {
        canonicalDiscreteGaussianTables[sigma] ?? buildDiscreteGaussianTable(sigma: sigma)
    }

    private static func buildDiscreteGaussianTable(sigma: UInt32) -> DiscreteGaussianTable {
        let sigmaValue = Double(max(1, sigma))
        let support = max(1, Int(ceil(sigmaValue * discreteGaussianSupportMultiplier)))
        let varianceDenominator = 2.0 * sigmaValue * sigmaValue

        var weights = [Double]()
        weights.reserveCapacity(support + 1)
        weights.append(1.0)
        var total = 1.0
        if support > 0 {
            for magnitude in 1...support {
                let magnitudeValue = Double(magnitude)
                let weight = 2.0 * exp(-(magnitudeValue * magnitudeValue) / varianceDenominator)
                weights.append(weight)
                total += weight
            }
        }

        var cumulativeMagnitudes = [Double]()
        cumulativeMagnitudes.reserveCapacity(weights.count)
        var running = 0.0
        for weight in weights {
            running += weight / total
            cumulativeMagnitudes.append(running)
        }
        if cumulativeMagnitudes.isEmpty == false {
            cumulativeMagnitudes[cumulativeMagnitudes.count - 1] = 1.0
        }

        return DiscreteGaussianTable(cumulativeMagnitudes: cumulativeMagnitudes)
    }

    private static func unitInterval(from raw: UInt64) -> Double {
        Double(raw >> 11) * 0x1p-53
    }

    private static func lowerBound(in cumulative: [Double], target: Double) -> Int {
        var lower = 0
        var upper = cumulative.count
        while lower < upper {
            let mid = lower + (upper - lower) / 2
            if cumulative[mid] < target {
                lower = mid + 1
            } else {
                upper = mid
            }
        }
        return min(lower, max(0, cumulative.count - 1))
    }

    private static func rejectionAccepts(
        maskShort: [RingElement],
        maskOuter: [RingElement],
        shortResponses: [RingElement],
        outerResponses: [RingElement],
        sigma: UInt32,
        rejectionSlack: UInt32,
        statement: ShortLinearWitnessStatement,
        bindingCommitment: AjtaiCommitment,
        restartNonce: UInt32
    ) -> Bool {
        let sigmaSquared = max(1.0, Double(sigma) * Double(sigma))
        let logSlack = log(max(1.0, Double(rejectionSlack)))
        let maskNorm = squaredNorm(maskShort) + squaredNorm(maskOuter)
        let responseNorm = squaredNorm(shortResponses) + squaredNorm(outerResponses)
        let logAcceptance = min(0.0, ((maskNorm - responseNorm) / (2.0 * sigmaSquared)) - logSlack)

        var writer = BinaryWriter()
        writer.appendLengthPrefixed(statement.statementDigest)
        writer.appendLengthPrefixed(statement.evaluationWeightDigest)
        writer.append(Data(bindingCommitment.value.toBytes()))
        writer.append(restartNonce)
        writer.appendLengthPrefixed(statement.parameters.rejectionDomain)
        let digest = NuSealCShake256.cshake256(
            data: writer.data,
            domain: "NuMeQ.Decider.Hachi.DirectPacked.RejectionCoin",
            count: 8
        )
        let raw = LittleEndianCodec.uint64(from: digest[0..<8])
        let coin = max(Double(raw) / Double(UInt64.max), Double.leastNonzeroMagnitude)
        return log(coin) <= logAcceptance
    }

    private static func squaredNorm(_ vectors: [RingElement]) -> Double {
        vectors.reduce(0.0) { partial, vector in
            partial + vector.coeffs.reduce(0.0) { coeffPartial, coeff in
                let centered = Double(coeff.centeredSignedValue)
                return coeffPartial + centered * centered
            }
        }
    }

    private static func responsesStayBound(
        shortResponses: [RingElement],
        outerResponses: [RingElement],
        bound: UInt64
    ) -> Bool {
        (shortResponses + outerResponses).allSatisfy { response in
            response.coeffs.allSatisfy { $0.centeredMagnitude < bound }
        }
    }

    private static func flattenedLimbVectors(_ decomposition: [[RingElement]]) -> [RingElement] {
        guard let limbCount = decomposition.first?.count else { return [] }
        return (0..<limbCount).flatMap { limbIndex in
            decomposition.map { $0[limbIndex] }
        }
    }

    private static func flattenDecomposition(
        of witness: [RingElement],
        base: UInt8,
        limbs: UInt8,
        context: MetalContext?
    ) throws -> [RingElement] {
        if let context {
            let decomposition = try decomposeWitnessMetal(
                witness: witness,
                decompBase: base,
                decompLimbs: limbs,
                context: context
            )
            return flattenedLimbVectors(decomposition)
        }
        return flattenedLimbVectors(
            witness.map {
                Decomposition.decompose(
                    element: $0,
                    base: base,
                    numLimbs: limbs
                ).limbs
            }
        )
    }

    private static func decomposeWitnessMetal(
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
            paramsPointer[1] = UInt32(Decomposition.metalLimbBitWidth(forBase: UInt64(decompBase)) ?? 0)
            paramsPointer[2] = UInt32(decompLimbs)

            try KernelDispatcher(context: context).dispatchDecompose(
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
            let ringCount = witness.count
            let totalValueCount = valueCount * Int(decompLimbs)
            return (0..<ringCount).map { ringIndex in
                (0..<Int(decompLimbs)).map { limbIndex in
                    var storage = [UInt32](repeating: 0, count: RingElement.degree * 2)
                    for coefficientIndex in 0..<RingElement.degree {
                        let flatIndex = limbIndex * valueCount + ringIndex * RingElement.degree + coefficientIndex
                        storage[coefficientIndex] = outputPointer[flatIndex]
                        storage[RingElement.degree + coefficientIndex] = outputPointer[totalValueCount + flatIndex]
                    }
                    return RingElement(
                        coeffs: MetalFieldPacking.unpackFieldElementsSoA(
                            storage,
                            count: RingElement.degree
                        )
                    )
                }
            }
        }
    }

    private static func decodeCoefficients(count: Int, base: UInt8) -> [RingElement] {
        let baseField = Fq(UInt64(base))
        var power = Fq.one
        var coefficients = [RingElement]()
        coefficients.reserveCapacity(count)
        for _ in 0..<count {
            coefficients.append(-(power * RingElement(constant: .one)))
            power *= baseField
        }
        return coefficients
    }

    private static func padVector(_ vector: [RingElement], to count: Int) -> [RingElement] {
        guard vector.count < count else { return vector }
        return vector + [RingElement](repeating: .zero, count: count - vector.count)
    }

    private static func paddedVectorWidth(of vectors: [[RingElement]]) -> Int {
        vectors.first?.count ?? 0
    }

    private static func nextPowerOfTwo(_ value: Int) -> Int {
        guard value > 1 else { return 1 }
        var candidate = 1
        while candidate < value {
            candidate <<= 1
        }
        return candidate
    }

    private static func expectedRoundCount(forPaddedCount paddedCount: Int) -> Int {
        paddedCount <= 1 ? 0 : paddedCount.trailingZeroBitCount
    }

    private static func transcriptBindingDigest(
        statement: ShortLinearWitnessStatement,
        proof: ShortLinearWitnessProof
    ) -> [UInt8] {
        var writer = BinaryWriter()
        writer.appendLengthPrefixed(statement.statementDigest)
        writer.appendLengthPrefixed(statement.evaluationWeightDigest)
        writer.append(Data(proof.initialBindingCommitment.value.toBytes()))
        writer.append(UInt32(clamping: proof.accumulatorRounds.count))
        for round in proof.accumulatorRounds {
            writer.append(Data(round.bindingLeft.value.toBytes()))
            writer.append(Data(round.bindingRight.value.toBytes()))
            writer.append(Data(round.relationLeft.value.toBytes()))
            writer.append(Data(round.relationRight.value.toBytes()))
            writer.append(Data(round.evaluationLeft.value.toBytes()))
            writer.append(Data(round.evaluationRight.value.toBytes()))
            writer.append(Data(round.outerLeft.value.toBytes()))
            writer.append(Data(round.outerRight.value.toBytes()))
        }
        writer.append(Data(proof.finalOpening.bindingMaskCommitment.value.toBytes()))
        writer.append(Data(proof.finalOpening.relationMaskCommitment.value.toBytes()))
        writer.append(Data(proof.finalOpening.evaluationMaskCommitment.value.toBytes()))
        writer.append(Data(proof.finalOpening.outerMaskCommitment.value.toBytes()))
        writer.append(UInt32(clamping: proof.finalOpening.shortResponses.count))
        proof.finalOpening.shortResponses.forEach { writer.append(Data($0.toBytes())) }
        writer.append(UInt32(clamping: proof.finalOpening.outerResponses.count))
        proof.finalOpening.outerResponses.forEach { writer.append(Data($0.toBytes())) }
        writer.append(proof.restartNonce)
        return NuSealCShake256.cshake256(
            data: writer.data,
            domain: "NuMeQ.Decider.Hachi.DirectPacked.TranscriptBinding",
            count: 32
        )
    }

    private static func absorb(bytes: [UInt8], transcript: inout NuTranscriptField) {
        transcript.absorbLabel("bytes_\(bytes.count)")
        for chunkStart in stride(from: 0, to: bytes.count, by: 7) {
            let chunk = Array(bytes[chunkStart..<min(chunkStart + 7, bytes.count)])
            var packed: UInt64 = UInt64(chunk.count)
            for (index, byte) in chunk.enumerated() {
                packed |= UInt64(byte) << (UInt64(index) * 8 + 8)
            }
            transcript.absorb(field: Fq(packed))
        }
    }
}

private extension Data {
    var bytes: [UInt8] { Array(self) }
}

private extension ShortLinearWitnessFinalOpening {
    var maskCommitmentsOnly: ShortLinearWitnessFinalOpening {
        ShortLinearWitnessFinalOpening(
            bindingMaskCommitment: bindingMaskCommitment,
            relationMaskCommitment: relationMaskCommitment,
            evaluationMaskCommitment: evaluationMaskCommitment,
            outerMaskCommitment: outerMaskCommitment,
            shortResponses: [],
            outerResponses: []
        )
    }
}

private func zip3<T, U, V, W>(
    _ a: [T],
    _ b: [U],
    _ c: [V],
    _ d: [W]
) -> [(T, U, V, W)] {
    zip(zip(a, b), zip(c, d)).map { (($0.0), ($0.1), ($1.0), ($1.1)) }
}
