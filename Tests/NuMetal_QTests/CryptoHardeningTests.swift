import Foundation
import CryptoKit
import XCTest
@testable import NuMetal_Q

final class CryptoHardeningTests: XCTestCase {
    func testMetalFieldPackingRoundTripsSoALayout() {
        let baseValues: [Fq] = [Fq(3), Fq(5), Fq(7), Fq(11)]
        let packedBase = MetalFieldPacking.packFieldElementsSoA(baseValues, paddedTo: 8)
        XCTAssertEqual(packedBase.count, 16)
        XCTAssertEqual(MetalFieldPacking.unpackFieldElementsSoA(packedBase, count: baseValues.count), baseValues)

        let rings = [
            AcceptanceSupport.randomRing(seed: 101, index: 0),
            AcceptanceSupport.randomRing(seed: 202, index: 1),
        ]
        let packedRings = MetalFieldPacking.packRingElementsSoA(rings, paddedTo: 4)
        XCTAssertEqual(packedRings.count, 4 * RingElement.degree * 2)
        XCTAssertEqual(
            MetalFieldPacking.unpackRingElementsSoA(packedRings, ringCount: rings.count),
            rings
        )

        let extValues = [
            Fq2(a: Fq(13), b: Fq(17)),
            Fq2(a: Fq(19), b: Fq(23)),
        ]
        let packedExt = MetalFieldPacking.packFq2SoA(extValues, paddedTo: 4)
        XCTAssertEqual(packedExt.count, 16)
        XCTAssertEqual(packedExt[0], UInt32(truncatingIfNeeded: extValues[0].a.v))
        XCTAssertEqual(packedExt[4], UInt32(truncatingIfNeeded: extValues[0].a.v >> 32))
        XCTAssertEqual(packedExt[8], UInt32(truncatingIfNeeded: extValues[0].b.v))
        XCTAssertEqual(packedExt[12], UInt32(truncatingIfNeeded: extValues[0].b.v >> 32))
    }

    func testRotationMatrixMatchesNegacyclicMultiplication() {
        let lhsVectors = [
            RingElement.zero,
            basisRing(at: 0),
            basisRing(at: 7, coefficient: Fq(13)),
            AcceptanceSupport.randomRing(seed: 909, index: 0),
        ]
        let rhsVectors = [
            basisRing(at: 0, coefficient: Fq(5)),
            basisRing(at: 63, coefficient: Fq(Fq.modulus &- 1)),
            AcceptanceSupport.randomRing(seed: 1234, index: 1),
        ]

        for lhs in lhsVectors {
            let rotation = RotationMatrix(element: lhs)
            for rhs in rhsVectors {
                XCTAssertEqual(rotation.apply(to: rhs), lhs * rhs)
            }
        }
    }

    func testCompiledShapeCarriesVersionedMetalABI() throws {
        let compiled = try AcceptanceSupport.makeCompiledShape(name: "VersionedMetalABI")
        XCTAssertEqual(compiled.shapePack.version, ShapePack.currentVersion)
        XCTAssertFalse(compiled.shapePack.gpuLiftedMatrices.isEmpty)
        XCTAssertTrue(compiled.shapePack.kernelConfigs.allSatisfy {
            $0.storageLayoutVersion == MetalStorageLayout.currentVersion
                && $0.laneTile == MetalStorageLayout.laneTile
                && $0.matrixRowTile == MetalStorageLayout.matrixRowTile
                && $0.threadExecutionWidthMultiple == MetalStorageLayout.threadExecutionWidthMultiple
                && $0.sealChunkSize > 0
                && $0.merkleChunkSize > 0
        })
    }

    func testProfileCertificateDeterministicArtifactIncludesFullQuarticEta() throws {
        let artifact = try ProfileCertificate.deterministicArtifactData(for: .canonical)
        let certificate = try ProfileCertificate.decodeArtifactData(artifact)
        let digest = try ProfileCertificate.deterministicArtifactDigest(for: .canonical)

        XCTAssertEqual(certificate.profile.version, 3)
        XCTAssertEqual(digest, Array(SHA256.hash(data: artifact)))

        let constantTerm = try XCTUnwrap(
            certificate.quarticPolynomial.terms.first(where: { $0.exponent == 0 })
        )
        XCTAssertEqual(
            constantTerm.coefficient,
            [
                Fq.modulus &- NuProfile.canonical.quarticEta[0],
                Fq.modulus &- NuProfile.canonical.quarticEta[1],
            ]
        )
        XCTAssertEqual(certificate.algebraicTower.deciderFieldDegree, 4)
        XCTAssertEqual(certificate.algebraicTower.qFourthMinusOneTwoAdicity, 7)
        XCTAssertEqual(
            certificate.moduleSIS.witnessSlotCount,
            NuProfile.canonical.commitmentRank * RingElement.degree
        )
        XCTAssertEqual(
            certificate.piDECSchedule.decompositionInterval,
            NuProfile.canonical.decompositionInterval
        )
        XCTAssertEqual(certificate.hachiDecider.relationID, "D_Nu")
        XCTAssertEqual(certificate.releasePolicy.minimumRawSecurityBits, 192)
        XCTAssertEqual(certificate.releasePolicy.minimumComposedSecurityBits, 128)
        XCTAssertTrue(certificate.isValid)
    }

    func testFq4SubfieldProjectionHelpersRejectNonBaseElements() {
        let base = Fq4(real: Fq(7))
        XCTAssertTrue(Fq4Convolution.isBaseSubfieldElement(base))
        XCTAssertEqual(Fq4Convolution.tryProjectToBaseField(base), Fq(7))

        let nonBase = Fq4(a: Fq2(a: Fq(3), b: Fq(5)), b: Fq2(a: .one, b: .zero))
        XCTAssertFalse(Fq4Convolution.isBaseSubfieldElement(nonBase))
        XCTAssertNil(Fq4Convolution.tryProjectToBaseField(nonBase))
    }

    func testPiCCSDirectAndNegative() {
        let relation = CCSRelation(
            m: 1,
            n: 2,
            nPublic: 0,
            matrices: [
                SparseMatrix(rows: 1, cols: 2, rowPtr: [0, 0], colIdx: [], values: [])
            ],
            gates: [CCSGate(coefficient: .zero, matrixIndices: [0])]
        )
        let input = PiCCS.Input(
            relation: relation,
            publicInputs: [],
            witness: [Fq(9), Fq(11)],
            relaxationFactor: .one
        )
        var transcript = NuTranscriptField(domain: "Tests.PiCCS")
        let output = PiCCS.prove(input: input, transcript: &transcript)

        var verifyTranscript = NuTranscriptField(domain: "Tests.PiCCS")
        XCTAssertTrue(PiCCS.verify(input: input, output: output, transcript: &verifyTranscript))

        let tampered = PiCCS.Output(
            evaluations: [output.evaluations[0] + .one] + output.evaluations.dropFirst(),
            challenges: output.challenges,
            sumCheckProof: output.sumCheckProof
        )
        var tamperedTranscript = NuTranscriptField(domain: "Tests.PiCCS")
        XCTAssertFalse(PiCCS.verify(input: input, output: tampered, transcript: &tamperedTranscript))
    }

    func testPiRLCDirectAndNegative() {
        let key = NuParams.derive(from: .canonical).fold.commitmentKey
        let inputs = AcceptanceSupport.samplePiRLCInputs(key: key, seed: 77)
        var transcript = NuTranscriptField(domain: "Tests.PiRLC")
        let output = PiRLC.prove(inputs: inputs, key: key, transcript: &transcript)

        var verifyTranscript = NuTranscriptField(domain: "Tests.PiRLC")
        XCTAssertTrue(PiRLC.verify(inputs: inputs, output: output, key: key, transcript: &verifyTranscript))

        let tampered = PiRLC.Output(
            foldedCommitment: AjtaiCommitment(value: output.foldedCommitment.value + RingElement(constant: .one)),
            foldedWitness: output.foldedWitness,
            foldedPublicInputs: output.foldedPublicInputs,
            foldedEvaluations: output.foldedEvaluations,
            foldedRelaxation: output.foldedRelaxation,
            foldedError: output.foldedError,
            crossTermCommitments: output.crossTermCommitments,
            ringChallenges: output.ringChallenges
        )
        var tamperedTranscript = NuTranscriptField(domain: "Tests.PiRLC")
        XCTAssertFalse(PiRLC.verify(inputs: inputs, output: tampered, key: key, transcript: &tamperedTranscript))
    }

    func testPiDECDirectAndNegative() {
        let key = NuParams.derive(from: .canonical).fold.commitmentKey
        let input = AcceptanceSupport.samplePiDECInput(key: key, seed: 88)
        var transcript = NuTranscriptField(domain: "Tests.PiDEC")
        let output = PiDEC.prove(input: input, transcript: &transcript)

        var verifyTranscript = NuTranscriptField(domain: "Tests.PiDEC")
        XCTAssertTrue(PiDEC.verify(input: input, output: output, transcript: &verifyTranscript))

        let tamperedCommitments = [AjtaiCommitment(value: output.limbCommitments[0].value + RingElement(constant: .one))]
            + output.limbCommitments.dropFirst()
        let tampered = PiDEC.Output(
            decomposedWitness: output.decomposedWitness,
            limbCommitments: tamperedCommitments,
            consistencyProof: output.consistencyProof
        )
        var tamperedTranscript = NuTranscriptField(domain: "Tests.PiDEC")
        XCTAssertFalse(PiDEC.verify(input: input, output: tampered, transcript: &tamperedTranscript))
    }

    func testSumCheckDirectAndNegative() {
        let polynomial = AcceptanceSupport.samplePolynomial(seed: 5, numVars: 3)
        var transcript = NuTranscriptField(domain: "Tests.SumCheck")
        let proof = SumCheck.prove(polynomial: polynomial, transcript: &transcript)

        var verifyTranscript = NuTranscriptField(domain: "Tests.SumCheck")
        XCTAssertTrue(
            SumCheck.verify(
                proof: proof,
                numVars: polynomial.numVars,
                claimedSum: polynomial.evals.reduce(.zero, +),
                transcript: &verifyTranscript
            )
        )

        let tampered = SumCheckProof(
            roundPolynomials: [[proof.roundPolynomials[0][0] + .one, proof.roundPolynomials[0][1]]] + Array(proof.roundPolynomials.dropFirst()),
            challengePoint: proof.challengePoint,
            finalEvaluation: proof.finalEvaluation
        )
        var tamperedTranscript = NuTranscriptField(domain: "Tests.SumCheck")
        XCTAssertFalse(
            SumCheck.verify(
                proof: tampered,
                numVars: polynomial.numVars,
                claimedSum: polynomial.evals.reduce(.zero, +),
                transcript: &tamperedTranscript
            )
        )
    }

    func testAjtaiCommitMetalMatchesCPU() async throws {
        let context = try AcceptanceSupport.metalContextOrSkip()
        let key = AjtaiKey.expand(seed: [UInt8](repeating: 0x44, count: 32), slotCount: 4)
        let witnessVectors: [[RingElement]] = [
            [],
            [.zero],
            [
                basisRing(at: 0),
                basisRing(at: 63, coefficient: Fq(raw: Fq.modulus &- 1)),
            ],
            (0..<4).map { AcceptanceSupport.randomRing(seed: 101, index: UInt64($0)) },
            (0..<4).map { AcceptanceSupport.randomRing(seed: 303, index: UInt64($0 + 9)) },
        ]

        for witness in witnessVectors {
            let cpu = AjtaiCommitter.commit(key: key, witness: witness)
            let gpu = try await AjtaiCommitter.commitMetal(context: context, key: key, witness: witness)
            XCTAssertEqual(gpu, cpu)
        }
    }

    func testAG64RingMetalMatchesCPU() throws {
        let context = try AcceptanceSupport.metalContextOrSkip()
        let vectors = [
            RingElement.zero,
            basisRing(at: 0),
            basisRing(at: 17),
            basisRing(at: 63, coefficient: Fq(raw: Fq.modulus &- 1)),
            AcceptanceSupport.randomRing(seed: 111, index: 0),
            AcceptanceSupport.randomRing(seed: 222, index: 10),
            AcceptanceSupport.randomRing(seed: 333, index: 21),
        ]

        for lhs in vectors {
            for rhs in vectors {
                XCTAssertEqual(
                    try AG64RingMetal.multiply(context: context, lhs: lhs, rhs: rhs),
                    lhs * rhs
                )
            }
        }
    }

    func testAjtaiCommitBatchMetalMatchesCPU() throws {
        let context = try AcceptanceSupport.metalContextOrSkip()
        let key = AjtaiKey.expand(seed: [UInt8](repeating: 0x55, count: 32), slotCount: 4)
        let witnesses: [[RingElement]] = [
            [],
            [.zero],
            (0..<4).map { AcceptanceSupport.randomRing(seed: 707, index: UInt64($0)) },
            (0..<3).map { AcceptanceSupport.randomRing(seed: 909, index: UInt64($0 + 7)) },
        ]

        let cpu = witnesses.map { AjtaiCommitter.commit(key: key, witness: $0) }
        let gpu = try AjtaiCommitter.commitBatchMetal(context: context, key: key, witnessBatches: witnesses)
        XCTAssertEqual(gpu, cpu)
    }

    func testAG64RingBindFoldMetalMatchesCPU() throws {
        let context = try AcceptanceSupport.metalContextOrSkip()
        let challenges = [
            AcceptanceSupport.randomRing(seed: 1_001, index: 0),
            AcceptanceSupport.randomRing(seed: 1_002, index: 1),
            AcceptanceSupport.randomRing(seed: 1_003, index: 2),
        ]
        let inputs: [[RingElement]] = (0..<challenges.count).map { sourceIndex in
            (0..<4).map { ringIndex in
                AcceptanceSupport.randomRing(
                    seed: 1_100 + UInt64(sourceIndex * 17),
                    index: UInt64(ringIndex)
                )
            }
        }

        let gpu = try AG64RingMetal.bindFold(
            context: context,
            challengeRings: challenges,
            inputs: inputs,
            ringCount: 4
        )
        let cpu = (0..<4).map { ringIndex in
            inputs.indices.reduce(RingElement.zero) { partial, sourceIndex in
                partial + challenges[sourceIndex] * inputs[sourceIndex][ringIndex]
            }
        }
        XCTAssertEqual(gpu, cpu)
    }

    func testPiCCSMetalMatchesCPU() async throws {
        let context = try AcceptanceSupport.metalContextOrSkip()
        let input = AcceptanceSupport.samplePiCCSInput(seed: 17)
        var cpuTranscript = NuTranscriptField(domain: "Tests.PiCCS.Metal")
        var gpuTranscript = NuTranscriptField(domain: "Tests.PiCCS.Metal")
        let cpu = PiCCS.prove(input: input, transcript: &cpuTranscript)
        let gpu = try await PiCCS.proveMetal(input: input, transcript: &gpuTranscript, context: context)
        XCTAssertEqual(gpu, cpu)
    }

    func testPiRLCMetalMatchesCPU() async throws {
        let context = try AcceptanceSupport.metalContextOrSkip()
        let key = NuParams.derive(from: .canonical).fold.commitmentKey
        let inputs = AcceptanceSupport.samplePiRLCInputs(key: key, seed: 33)
        var cpuTranscript = NuTranscriptField(domain: "Tests.PiRLC.Metal")
        var gpuTranscript = NuTranscriptField(domain: "Tests.PiRLC.Metal")
        let cpu = PiRLC.prove(inputs: inputs, key: key, transcript: &cpuTranscript)
        let gpu = try await PiRLC.proveMetal(inputs: inputs, key: key, transcript: &gpuTranscript, context: context)
        XCTAssertEqual(gpu, cpu)
    }

    func testPiDECMetalMatchesCPU() async throws {
        let context = try AcceptanceSupport.metalContextOrSkip()
        let key = NuParams.derive(from: .canonical).fold.commitmentKey
        let input = AcceptanceSupport.samplePiDECInput(key: key, seed: 61)
        var cpuTranscript = NuTranscriptField(domain: "Tests.PiDEC.Metal")
        var gpuTranscript = NuTranscriptField(domain: "Tests.PiDEC.Metal")
        let cpu = PiDEC.prove(input: input, transcript: &cpuTranscript)
        let gpu = try await PiDEC.proveMetal(input: input, transcript: &gpuTranscript, context: context)
        XCTAssertEqual(gpu, cpu)
    }

    func testPiRLCVerifyMetalMatchesCPUAndRejectsTamperedCrossTerms() throws {
        let context = try AcceptanceSupport.metalContextOrSkip()
        let key = NuParams.derive(from: .canonical).fold.commitmentKey
        let inputs = AcceptanceSupport.samplePiRLCInputs(key: key, seed: 33)
        var transcript = NuTranscriptField(domain: "Tests.PiRLC.VerifyMetal")
        let output = PiRLC.prove(inputs: inputs, key: key, transcript: &transcript)

        var cpuTranscript = NuTranscriptField(domain: "Tests.PiRLC.VerifyMetal")
        XCTAssertTrue(PiRLC.verify(inputs: inputs, output: output, key: key, transcript: &cpuTranscript))

        var gpuTranscript = NuTranscriptField(domain: "Tests.PiRLC.VerifyMetal")
        XCTAssertTrue(try PiRLC.verifyMetal(
            inputs: inputs,
            output: output,
            key: key,
            transcript: &gpuTranscript,
            context: context
        ))

        let tampered = PiRLC.Output(
            foldedCommitment: output.foldedCommitment,
            foldedWitness: output.foldedWitness,
            foldedPublicInputs: output.foldedPublicInputs,
            foldedEvaluations: output.foldedEvaluations,
            foldedRelaxation: output.foldedRelaxation,
            foldedError: output.foldedError,
            crossTermCommitments: [AjtaiCommitment(value: output.crossTermCommitments[0].value + RingElement(constant: .one))]
                + output.crossTermCommitments.dropFirst(),
            ringChallenges: output.ringChallenges
        )

        var tamperedCPUTranscript = NuTranscriptField(domain: "Tests.PiRLC.VerifyMetal")
        XCTAssertFalse(PiRLC.verify(inputs: inputs, output: tampered, key: key, transcript: &tamperedCPUTranscript))

        var tamperedGPUTranscript = NuTranscriptField(domain: "Tests.PiRLC.VerifyMetal")
        XCTAssertFalse(try PiRLC.verifyMetal(
            inputs: inputs,
            output: tampered,
            key: key,
            transcript: &tamperedGPUTranscript,
            context: context
        ))
    }

    func testPiDECVerifyMetalMatchesCPUAndRejectsTamperedReconstructedCommitment() throws {
        let context = try AcceptanceSupport.metalContextOrSkip()
        let key = NuParams.derive(from: .canonical).fold.commitmentKey
        let input = AcceptanceSupport.samplePiDECInput(key: key, seed: 61)
        var transcript = NuTranscriptField(domain: "Tests.PiDEC.VerifyMetal")
        let output = PiDEC.prove(input: input, transcript: &transcript)

        var cpuTranscript = NuTranscriptField(domain: "Tests.PiDEC.VerifyMetal")
        XCTAssertTrue(PiDEC.verify(input: input, output: output, transcript: &cpuTranscript))

        var gpuTranscript = NuTranscriptField(domain: "Tests.PiDEC.VerifyMetal")
        XCTAssertTrue(try PiDEC.verifyMetal(
            input: input,
            output: output,
            transcript: &gpuTranscript,
            context: context
        ))

        let tampered = PiDEC.Output(
            decomposedWitness: output.decomposedWitness,
            limbCommitments: output.limbCommitments,
            consistencyProof: DecompConsistencyProof(
                challenge: output.consistencyProof.challenge,
                reconstructedCommitment: AjtaiCommitment(
                    value: output.consistencyProof.reconstructedCommitment.value + RingElement(constant: .one)
                )
            )
        )

        var tamperedCPUTranscript = NuTranscriptField(domain: "Tests.PiDEC.VerifyMetal")
        XCTAssertFalse(PiDEC.verify(input: input, output: tampered, transcript: &tamperedCPUTranscript))

        var tamperedGPUTranscript = NuTranscriptField(domain: "Tests.PiDEC.VerifyMetal")
        XCTAssertFalse(try PiDEC.verifyMetal(
            input: input,
            output: tampered,
            transcript: &tamperedGPUTranscript,
            context: context
        ))
    }

    func testRecursiveVerifierMetalMatchesCPUAndRejectsTampering() async throws {
        let context = try AcceptanceSupport.metalContextOrSkip()
        let compiledShape = try AcceptanceSupport.makeCompiledShape(name: "RecursiveVerifyMetal")
        let relation = compiledShape.shape.relation
        let publicInputs = [Fq(3), Fq(5)]
        let config = FoldConfig(
            maxArity: 4,
            decompBase: NuProfile.canonical.decompBase,
            decompLimbs: 18,
            normBound: NuProfile.canonical.normBound,
            decompositionInterval: 1,
            keySlots: NuProfile.canonical.commitmentRank * RingElement.degree
        )

        let cpuEngine = FoldEngine(config: config, seed: NuProfile.canonical.foldParameterSeed)
        let gpuEngine = FoldEngine(config: config, seed: NuProfile.canonical.foldParameterSeed)
        await gpuEngine.setMetalContext(context)

        let seedA = try await cpuEngine.seed(
            shape: compiledShape.shape,
            witness: AcceptanceSupport.makeBoundedWitness(seed: 11, maxElement: 1 << 12),
            publicInputs: publicInputs,
            witnessClass: .public
        )
        let seedB = try await cpuEngine.seed(
            shape: compiledShape.shape,
            witness: AcceptanceSupport.makeBoundedWitness(seed: 29, maxElement: 1 << 12),
            publicInputs: publicInputs,
            witnessClass: .public
        )
        let folded = try await cpuEngine.fold(states: [seedA, seedB], relation: relation)

        let cpuSeedValid = try await cpuEngine.verifyRecursiveState(state: seedA, relation: relation)
        let gpuSeedValid = try await gpuEngine.verifyRecursiveState(state: seedA, relation: relation)
        let cpuFoldValid = try await cpuEngine.verifyRecursiveState(state: folded, relation: relation)
        let gpuFoldValid = try await gpuEngine.verifyRecursiveState(state: folded, relation: relation)
        XCTAssertTrue(cpuSeedValid)
        XCTAssertTrue(gpuSeedValid)
        XCTAssertTrue(cpuFoldValid)
        XCTAssertTrue(gpuFoldValid)
        XCTAssertEqual(folded.recursiveAccumulator?.fold?.openingWitness.kind, .decomposed)

        let tamperedSeedProof = PiCCS.Output(
            evaluations: [seedA.recursiveAccumulator!.seed!.proof.evaluations[0] + .one]
                + seedA.recursiveAccumulator!.seed!.proof.evaluations.dropFirst(),
            challenges: seedA.recursiveAccumulator!.seed!.proof.challenges,
            sumCheckProof: seedA.recursiveAccumulator!.seed!.proof.sumCheckProof
        )
        var tamperedSeedAccumulator = seedA.recursiveAccumulator!
        tamperedSeedAccumulator = FoldAccumulator(
            epoch: tamperedSeedAccumulator.epoch,
            arity: tamperedSeedAccumulator.arity,
            statementCount: tamperedSeedAccumulator.statementCount,
            seed: SeedAccumulatorData(
                sourceClaim: tamperedSeedAccumulator.seed!.sourceClaim,
                reducedClaim: tamperedSeedAccumulator.seed!.reducedClaim,
                proof: tamperedSeedProof,
                openingWitness: tamperedSeedAccumulator.seed!.openingWitness
            )
        )
        var tamperedSeedState = seedA
        tamperedSeedState.recursiveAccumulator = tamperedSeedAccumulator
        let cpuTamperedSeedValid = try await cpuEngine.verifyRecursiveState(
            state: tamperedSeedState,
            relation: relation
        )
        let gpuTamperedSeedValid = try await gpuEngine.verifyRecursiveState(
            state: tamperedSeedState,
            relation: relation
        )
        XCTAssertFalse(cpuTamperedSeedValid)
        XCTAssertFalse(gpuTamperedSeedValid)

        let tamperedCrossTermProof = PiRLC.Output(
            foldedCommitment: folded.recursiveAccumulator!.fold!.piRLCProof.foldedCommitment,
            foldedWitness: folded.recursiveAccumulator!.fold!.piRLCProof.foldedWitness,
            foldedPublicInputs: folded.recursiveAccumulator!.fold!.piRLCProof.foldedPublicInputs,
            foldedEvaluations: folded.recursiveAccumulator!.fold!.piRLCProof.foldedEvaluations,
            foldedRelaxation: folded.recursiveAccumulator!.fold!.piRLCProof.foldedRelaxation,
            foldedError: folded.recursiveAccumulator!.fold!.piRLCProof.foldedError,
            crossTermCommitments: [AjtaiCommitment(value: folded.recursiveAccumulator!.fold!.piRLCProof.crossTermCommitments[0].value + RingElement(constant: .one))]
                + folded.recursiveAccumulator!.fold!.piRLCProof.crossTermCommitments.dropFirst(),
            ringChallenges: folded.recursiveAccumulator!.fold!.piRLCProof.ringChallenges
        )
        var tamperedFoldAccumulator = folded.recursiveAccumulator!
        tamperedFoldAccumulator = FoldAccumulator(
            epoch: tamperedFoldAccumulator.epoch,
            arity: tamperedFoldAccumulator.arity,
            statementCount: tamperedFoldAccumulator.statementCount,
            fold: FoldAccumulatorData(
                childAccumulators: tamperedFoldAccumulator.fold!.childAccumulators,
                foldedClaim: tamperedFoldAccumulator.fold!.foldedClaim,
                piRLCProof: tamperedCrossTermProof,
                openingWitness: tamperedFoldAccumulator.fold!.openingWitness
            )
        )
        var tamperedFoldState = folded
        tamperedFoldState.recursiveAccumulator = tamperedFoldAccumulator
        let cpuTamperedFoldValid = try await cpuEngine.verifyRecursiveState(
            state: tamperedFoldState,
            relation: relation
        )
        let gpuTamperedFoldValid = try await gpuEngine.verifyRecursiveState(
            state: tamperedFoldState,
            relation: relation
        )
        XCTAssertFalse(cpuTamperedFoldValid)
        XCTAssertFalse(gpuTamperedFoldValid)

        let tamperedDecomposition = PiDEC.Output(
            decomposedWitness: folded.recursiveAccumulator!.fold!.openingWitness.decomposition!.decomposedWitness,
            limbCommitments: folded.recursiveAccumulator!.fold!.openingWitness.decomposition!.limbCommitments,
            consistencyProof: DecompConsistencyProof(
                challenge: folded.recursiveAccumulator!.fold!.openingWitness.decomposition!.consistencyProof.challenge,
                reconstructedCommitment: AjtaiCommitment(
                    value: folded.recursiveAccumulator!.fold!.openingWitness.decomposition!.consistencyProof.reconstructedCommitment.value + RingElement(constant: .one)
                )
            )
        )
        let tamperedOpeningWitness = AccumulatorOpeningWitness(
            decomposition: tamperedDecomposition,
            decompBase: folded.recursiveAccumulator!.fold!.openingWitness.decompBase,
            decompLimbs: folded.recursiveAccumulator!.fold!.openingWitness.decompLimbs
        )
        let tamperedOpeningAccumulator = FoldAccumulator(
            epoch: folded.recursiveAccumulator!.epoch,
            arity: folded.recursiveAccumulator!.arity,
            statementCount: folded.recursiveAccumulator!.statementCount,
            fold: FoldAccumulatorData(
                childAccumulators: folded.recursiveAccumulator!.fold!.childAccumulators,
                foldedClaim: folded.recursiveAccumulator!.fold!.foldedClaim,
                piRLCProof: folded.recursiveAccumulator!.fold!.piRLCProof,
                openingWitness: tamperedOpeningWitness
            )
        )
        var tamperedOpeningState = folded
        tamperedOpeningState.recursiveAccumulator = tamperedOpeningAccumulator
        let cpuTamperedOpeningValid = try await cpuEngine.verifyRecursiveState(
            state: tamperedOpeningState,
            relation: relation
        )
        let gpuTamperedOpeningValid = try await gpuEngine.verifyRecursiveState(
            state: tamperedOpeningState,
            relation: relation
        )
        XCTAssertFalse(cpuTamperedOpeningValid)
        XCTAssertFalse(gpuTamperedOpeningValid)
    }

    func testMetalTraceCollectorPreservesOrderAndOffsets() {
        let collector = MetalTraceCollector(iteration: 3)
        collector.append(
            stage: "piRLC",
            iteration: collector.defaultIteration,
            dispatchLabel: "piRLC.cross_terms",
            kernelFamily: .ringMultiplyAG64,
            timing: MetalDispatchTiming(
                cpuMilliseconds: 1.5,
                gpuMilliseconds: 0.5,
                counterSamplingAvailable: true,
                threadExecutionWidth: 32,
                threadgroupWidth: 64,
                counterSampleCaptured: true
            )
        )
        collector.append(
            stage: "piRLC",
            iteration: collector.defaultIteration,
            dispatchLabel: "piRLC.fold_witness",
            kernelFamily: .ringBindFoldBatch,
            timing: MetalDispatchTiming(
                cpuMilliseconds: 2.0,
                gpuMilliseconds: 0.75,
                counterSamplingAvailable: true,
                threadExecutionWidth: 32,
                threadgroupWidth: 64,
                counterSampleCaptured: true
            )
        )

        let samples = collector.snapshot()
        XCTAssertEqual(samples.map(\.ordinal), [0, 1])
        XCTAssertEqual(samples.map(\.iteration), [3, 3])
        XCTAssertEqual(samples[0].gpuStartOffsetUs, 0)
        XCTAssertEqual(samples[0].gpuEndOffsetUs, 500)
        XCTAssertEqual(samples[1].gpuStartOffsetUs, 500)
        XCTAssertEqual(samples[1].gpuEndOffsetUs, 1_250)
    }

    func testPiCCSVerifyMetalTraceCollectorCapturesMatrixLift() throws {
        let context = try AcceptanceSupport.metalContextOrSkip()
        let input = AcceptanceSupport.samplePiCCSInput(seed: 17)
        let collector = MetalTraceCollector(iteration: 0)
        let evaluations = try PiCCS.metalMatrixEvaluations(for: input, context: context, trace: collector)

        let samples = collector.snapshot()
        XCTAssertEqual(evaluations.count, input.relation.matrices.count)
        XCTAssertFalse(samples.isEmpty)
        XCTAssertTrue(samples.allSatisfy { $0.threadgroupWidth % $0.threadExecutionWidth == 0 })
        XCTAssertEqual(samples.first?.dispatchLabel, "piCCS.matrix_lift[0]")
    }

    func testRecursiveVerifierExecutionModesAndTraceMatch() async throws {
        let context = try AcceptanceSupport.metalContextOrSkip()
        let compiledShape = try AcceptanceSupport.makeCompiledShape(name: "RecursiveVerifyModes")
        let relation = compiledShape.shape.relation
        let publicInputs = [Fq(3), Fq(5)]
        let engine = FoldEngine(config: .canonical, seed: NuProfile.canonical.foldParameterSeed)
        await engine.setMetalContext(context)

        let seedA = try await engine.seed(
            shape: compiledShape.shape,
            witness: AcceptanceSupport.makeBoundedWitness(seed: 11, maxElement: 1 << 12),
            publicInputs: publicInputs,
            witnessClass: .public
        )
        let traceCollector = MetalTraceCollector(iteration: 0)

        let cpuOnlyValid = try await engine.verifyRecursiveState(
            state: seedA,
            relation: relation,
            executionMode: .cpuOnly
        )
        let assistedValid = try await engine.verifyRecursiveState(
            state: seedA,
            relation: relation,
            executionMode: .metalAssisted,
            traceCollector: traceCollector
        )
        XCTAssertTrue(cpuOnlyValid)
        XCTAssertTrue(assistedValid)
        XCTAssertFalse(traceCollector.snapshot().isEmpty)
    }

    func testHachiPCSCPUAndMetalArtifactsMatch() throws {
        let context = try AcceptanceSupport.metalContextOrSkip()
        let backend = HachiPCSBackend()
        let polynomials = [
            AcceptanceSupport.samplePolynomial(seed: 7, numVars: 2),
            AcceptanceSupport.samplePolynomial(seed: 19, numVars: 3),
            AcceptanceSupport.samplePolynomial(seed: 43, numVars: 4),
        ]

        for (index, polynomial) in polynomials.enumerated() {
            let witnessDiffs = try backend.compareCPUAndMetalArtifacts(
                label: .witness(),
                polynomial: polynomial,
                context: context
            )
            XCTAssertTrue(
                witnessDiffs.isEmpty,
                "witness diffs[\(index)]: \(witnessDiffs)"
            )

            let rowDiffs = try backend.compareCPUAndMetalArtifacts(
                label: .matrixRow(index),
                polynomial: polynomial,
                context: context
            )
            XCTAssertTrue(
                rowDiffs.isEmpty,
                "row diffs[\(index)]: \(rowDiffs)"
            )
        }
    }

    func testNuMeQSealVerifyCpuOnlyMatchesMetalAssistedAndCapturesTrace() async throws {
        let context = try AcceptanceSupport.metalContextOrSkip()
        let (proof, shape, publicHeader) = try await makeRealSealProof()
        let verifier = HachiSealEngine()
        await verifier.setMetalContext(context)

        let cpuOutcome = await verifier.verifySemantically(
            proof: proof,
            shape: shape,
            publicHeader: publicHeader,
            executionMode: .cpuOnly,
            traceCollector: nil
        )
        let traceCollector = MetalTraceCollector(iteration: 0)
        let assistedOutcome = await verifier.verifySemantically(
            proof: proof,
            shape: shape,
            publicHeader: publicHeader,
            executionMode: .metalAssisted,
            traceCollector: traceCollector
        )

        XCTAssertTrue(cpuOutcome.isValid, cpuOutcome.diagnostics.summary)
        XCTAssertTrue(assistedOutcome.isValid, assistedOutcome.diagnostics.summary)
        XCTAssertFalse(traceCollector.snapshot().isEmpty)
    }

    func testOnlyCurrentVaultHeaderAccepted() async throws {
        let vault = FoldVault(storageDirectory: FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString))
        let state = FoldState(
            shapeDigest: ShapeDigest(bytes: [UInt8](repeating: 0x31, count: 32)),
            commitment: AjtaiCommitment(value: .zero),
            witness: [.zero],
            publicInputs: [Fq(1), Fq(2)],
            normBudget: NormBudget(bound: 8, decompBase: 2, decompLimbs: 3),
            maxWitnessClass: .public
        )

        let current = try await vault.serializeStateForTesting(state)
        let restored = try await vault.deserializeStateForTesting(current)
        XCTAssertEqual(restored.chainID, state.chainID)

        for header in ["NuMeQFv4", "NuMeQFv3", "NuMeQFv2"] {
            let tampered = Data(header.utf8) + current.dropFirst(Data("NuMeQFv6".utf8).count)
            do {
                _ = try await vault.deserializeStateForTesting(tampered)
                XCTFail("Expected \(header) to be rejected")
            } catch let error as VaultError {
                XCTAssertEqual(error, .corruptedData)
            }
        }
    }

    func testHachiVerifierRejectsCriticalMutations() async throws {
        let (proof, shape, publicHeader) = try await makeRealSealProof()
        let verifier = HachiSealEngine()

        let mutatedProofs = [
            replace(
                proof,
                statement: replace(
                    proof.statement,
                    sealParamDigest: flipped(proof.statement.sealParamDigest)
                )
            ),
            replace(
                proof,
                statement: replace(
                    proof.statement,
                    finalAccumulatorCommitment: AjtaiCommitment(
                        value: proof.statement.finalAccumulatorCommitment.value + RingElement(constant: .one)
                    )
                )
            ),
            replace(
                proof,
                statement: replace(
                    proof.statement,
                    publicInputs: [Fq(9)]
                )
            ),
            mutate(proof) { terminalProof in
                let claimed = SpartanClaimedEvaluations<Fq>(
                    rowPoint: terminalProof.claimedEvaluations.rowPoint,
                    columnPoint: [Fq(9)] + terminalProof.claimedEvaluations.columnPoint.dropFirst(),
                    matrixRowEvaluations: terminalProof.claimedEvaluations.matrixRowEvaluations,
                    witnessEvaluation: terminalProof.claimedEvaluations.witnessEvaluation
                )
                return replace(terminalProof, claimedEvaluations: claimed)
            },
            mutate(proof) { terminalProof in
                let firstClass = tryMutateFirstClass(terminalProof.pcsOpeningProof) { klass in
                    HachiPCSBatchClassOpeningProof(
                        point: klass.point,
                        pointDigest: klass.pointDigest,
                        scheduleDigest: flipped(klass.scheduleDigest),
                        openings: klass.openings
                    )
                }
                return replace(terminalProof, pcsOpeningProof: firstClass)
            },
            mutate(proof) { terminalProof in
                let firstClass = tryMutateFirstClass(terminalProof.pcsOpeningProof) { klass in
                    guard let opening = klass.openings.first else { return klass }
                    let mutatedOpening = HachiPCSOpening(
                        oracle: opening.oracle,
                        evaluation: opening.evaluation,
                        scheduleDigest: opening.scheduleDigest,
                        evaluationDigest: opening.evaluationDigest,
                        codewordIndex: opening.codewordIndex &+ 1,
                        codewordValue: opening.codewordValue,
                        merkleAuthenticationPath: opening.merkleAuthenticationPath
                    )
                    return HachiPCSBatchClassOpeningProof(
                        point: klass.point,
                        pointDigest: klass.pointDigest,
                        scheduleDigest: klass.scheduleDigest,
                        openings: [mutatedOpening] + klass.openings.dropFirst()
                    )
                }
                return replace(terminalProof, pcsOpeningProof: firstClass)
            },
            mutate(proof) { terminalProof in
                let firstClass = tryMutateFirstClass(terminalProof.pcsOpeningProof) { klass in
                    guard let opening = klass.openings.first else { return klass }
                    let mutatedOpening = HachiPCSOpening(
                        oracle: opening.oracle,
                        evaluation: opening.evaluation,
                        scheduleDigest: opening.scheduleDigest,
                        evaluationDigest: opening.evaluationDigest,
                        codewordIndex: opening.codewordIndex,
                        codewordValue: opening.codewordValue,
                        merkleAuthenticationPath: [flipped(opening.merkleAuthenticationPath.first ?? [])]
                            + opening.merkleAuthenticationPath.dropFirst()
                    )
                    return HachiPCSBatchClassOpeningProof(
                        point: klass.point,
                        pointDigest: klass.pointDigest,
                        scheduleDigest: klass.scheduleDigest,
                        openings: [mutatedOpening] + klass.openings.dropFirst()
                    )
                }
                return replace(terminalProof, pcsOpeningProof: firstClass)
            },
            replace(
                proof,
                statement: replace(
                    proof.statement,
                    deciderLayoutDigest: flipped(proof.statement.deciderLayoutDigest)
                )
            ),
            replace(
                proof,
                statement: replace(
                    proof.statement,
                    backendID: "bogus-backend"
                )
            ),
            replace(
                proof,
                statement: replace(
                    proof.statement,
                    sealTranscriptID: "NuTranscriptSeal/cSHAKE256/SpartanD_Nu/v0"
                )
            )
        ]

        for mutated in mutatedProofs {
            let isValid = await verifier.verify(proof: mutated, shape: shape, publicHeader: publicHeader)
            XCTAssertFalse(isValid)
        }
    }

    func testHachiVerifierRejectsCriticalMutationsAcrossExecutionModes() async throws {
        let context = try AcceptanceSupport.metalContextOrSkip()
        let (proof, shape, publicHeader) = try await makeRealSealProof()
        let verifier = HachiSealEngine()
        await verifier.setMetalContext(context)

        let mutatedProofs = [
            replace(
                proof,
                statement: replace(
                    proof.statement,
                    finalAccumulatorCommitment: AjtaiCommitment(
                        value: proof.statement.finalAccumulatorCommitment.value + RingElement(constant: .one)
                    )
                )
            ),
            replace(
                proof,
                statement: replace(
                    proof.statement,
                    deciderLayoutDigest: flipped(proof.statement.deciderLayoutDigest)
                )
            ),
            mutate(proof) { terminalProof in
                let firstClass = tryMutateFirstClass(terminalProof.pcsOpeningProof) { klass in
                    guard let opening = klass.openings.first else { return klass }
                    let mutatedOpening = HachiPCSOpening(
                        oracle: opening.oracle,
                        evaluation: opening.evaluation,
                        scheduleDigest: opening.scheduleDigest,
                        evaluationDigest: opening.evaluationDigest,
                        codewordIndex: opening.codewordIndex,
                        codewordValue: opening.codewordValue,
                        merkleAuthenticationPath: [flipped(opening.merkleAuthenticationPath.first ?? [])]
                            + opening.merkleAuthenticationPath.dropFirst()
                    )
                    return HachiPCSBatchClassOpeningProof(
                        point: klass.point,
                        pointDigest: klass.pointDigest,
                        scheduleDigest: klass.scheduleDigest,
                        openings: [mutatedOpening] + klass.openings.dropFirst()
                    )
                }
                return replace(terminalProof, pcsOpeningProof: firstClass)
            },
        ]

        for mutated in mutatedProofs {
            let cpuOnly = await verifier.verifySemantically(
                proof: mutated,
                shape: shape,
                publicHeader: publicHeader,
                executionMode: .cpuOnly,
                traceCollector: nil
            )
            let assisted = await verifier.verifySemantically(
                proof: mutated,
                shape: shape,
                publicHeader: publicHeader,
                executionMode: .metalAssisted,
                traceCollector: nil
            )
            XCTAssertFalse(cpuOnly.isValid, "cpuOnly unexpectedly accepted: \(cpuOnly.diagnostics.summary)")
            XCTAssertFalse(assisted.isValid, "metalAssisted unexpectedly accepted: \(assisted.diagnostics.summary)")
        }
    }

    private func makeRealSealProof() async throws -> (PublicSealProof, Shape, Data) {
        let engine = try await AcceptanceSupport.makeEngine()
        let compiledShape = try AcceptanceSupport.makeCompiledShape(name: "HachiTamper")
        let context = await engine.createContext(
            compiledShape: compiledShape,
            policy: .standard,
            appID: "NuMetalQ.CryptoHardening",
            attestationVerifier: AcceptanceSupport.attestationVerifier
        )
        let handle = try await context.seed(
            witness: AcceptanceSupport.makeWitness(seed: 42),
            publicInputs: [Fq(3), Fq(5)]
        )
        let sessionKey = AcceptanceSupport.makeSessionKey()
        let sealedExport = try await context.seal(
            handle,
            sessionKey: sessionKey,
            signerKeyID: Data("hardening-signer".utf8),
            attestation: Data("hardening-attestation".utf8),
            signEnvelope: AcceptanceSupport.signer
        )
        return (
            try sealedExport.proofEnvelope.proof(),
            compiledShape.shape,
            sealedExport.proofEnvelope.publicHeaderBytes
        )
    }

    private func flipped(_ bytes: [UInt8]) -> [UInt8] {
        guard bytes.isEmpty == false else { return [1] }
        var copy = bytes
        copy[0] ^= 0x01
        return copy
    }

    private func basisRing(at index: Int, coefficient: Fq = .one) -> RingElement {
        var coeffs = [Fq](repeating: .zero, count: RingElement.degree)
        coeffs[index] = coefficient
        return RingElement(coeffs: coeffs)
    }

    private func tryMutateFirstClass(
        _ openingProof: HachiPCSBatchOpeningProof,
        transform: (HachiPCSBatchClassOpeningProof) -> HachiPCSBatchClassOpeningProof
    ) -> HachiPCSBatchOpeningProof {
        guard let first = openingProof.classes.first else {
            return openingProof
        }
        return HachiPCSBatchOpeningProof(
            batchSeedDigest: openingProof.batchSeedDigest,
            classes: [transform(first)] + openingProof.classes.dropFirst()
        )
    }

    private func mutate(
        _ proof: PublicSealProof,
        _ transform: (HachiTerminalProof) -> HachiTerminalProof
    ) -> PublicSealProof {
        replace(proof, terminalProof: transform(proof.terminalProof))
    }

    private func replace(
        _ proof: PublicSealProof,
        statement: PublicSealStatement? = nil,
        terminalProof: HachiTerminalProof? = nil
    ) -> PublicSealProof {
        PublicSealProof(
            statement: statement ?? proof.statement,
            terminalProof: terminalProof ?? proof.terminalProof
        )
    }

    private func replace(
        _ statement: PublicSealStatement,
        backendID: String? = nil,
        sealTranscriptID: String? = nil,
        deciderLayoutDigest: [UInt8]? = nil,
        sealParamDigest: [UInt8]? = nil,
        publicHeader: Data? = nil,
        publicInputs: [Fq]? = nil,
        finalAccumulatorCommitment: AjtaiCommitment? = nil
    ) -> PublicSealStatement {
        PublicSealStatement(
            backendID: backendID ?? statement.backendID,
            sealTranscriptID: sealTranscriptID ?? statement.sealTranscriptID,
            shapeDigest: statement.shapeDigest,
            deciderLayoutDigest: deciderLayoutDigest ?? statement.deciderLayoutDigest,
            sealParamDigest: sealParamDigest ?? statement.sealParamDigest,
            publicHeader: publicHeader ?? statement.publicHeader,
            instanceCount: statement.instanceCount,
            finalAccumulatorCommitment: finalAccumulatorCommitment ?? statement.finalAccumulatorCommitment,
            publicInputs: publicInputs ?? statement.publicInputs,
            relaxationFactor: statement.relaxationFactor,
            errorTerms: statement.errorTerms
        )
    }

    private func replace(
        _ proof: HachiTerminalProof,
        claimedEvaluations: SpartanClaimedEvaluations<Fq>? = nil,
        pcsOpeningProof: HachiPCSBatchOpeningProof? = nil
    ) -> HachiTerminalProof {
        HachiTerminalProof(
            witnessCommitment: proof.witnessCommitment,
            matrixEvaluationCommitments: proof.matrixEvaluationCommitments,
            blindingCommitments: proof.blindingCommitments,
            outerSumcheck: proof.outerSumcheck,
            innerSumcheck: proof.innerSumcheck,
            claimedEvaluations: claimedEvaluations ?? proof.claimedEvaluations,
            blindingEvaluations: proof.blindingEvaluations,
            pcsOpeningProof: pcsOpeningProof ?? proof.pcsOpeningProof,
            blindingOpeningProof: proof.blindingOpeningProof
        )
    }
}
