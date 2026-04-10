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
        XCTAssertTrue(certificate.isValid)
        XCTAssertEqual(certificate.hachiDecider.relationID, "D_Nu")
        XCTAssertTrue(certificate.releasePolicy.informationalOnly)
        XCTAssertEqual(
            certificate.estimatorTranscript.model,
            "heuristic profile estimate (informational only)"
        )
    }

    func testFq4SubfieldProjectionHelpersRejectNonBaseElements() {
        let base = Fq4(real: Fq(7))
        XCTAssertTrue(Fq4Convolution.isBaseSubfieldElement(base))
        XCTAssertEqual(Fq4Convolution.tryProjectToBaseField(base), Fq(7))

        let nonBase = Fq4(a: Fq2(a: Fq(3), b: Fq(5)), b: Fq2(a: .one, b: .zero))
        XCTAssertFalse(Fq4Convolution.isBaseSubfieldElement(nonBase))
        XCTAssertNil(Fq4Convolution.tryProjectToBaseField(nonBase))
    }

    func testCheckedInversionRejectsZeroAcrossTower() {
        XCTAssertNil(Fq.zero.inverted())
        XCTAssertNil(Fq2.zero.inverted())
        XCTAssertNil(Fq4.zero.inverted())
        XCTAssertEqual(Fq(7).inverted().map { Fq(7) * $0 }, .one)
    }

    func testTranscriptByteAbsorptionDistinguishesFormerReductionCollision() {
        let zeroBytes = Data(repeating: 0x00, count: MemoryLayout<UInt64>.size)
        let modulusBytes = withUnsafeBytes(of: Fq.modulus.littleEndian) { Data($0) }

        var left = NuTranscriptField(domain: "Tests.Transcript.InjectiveBytes")
        left.absorb(domain: "payload", bytes: zeroBytes)

        var right = NuTranscriptField(domain: "Tests.Transcript.InjectiveBytes")
        right.absorb(domain: "payload", bytes: modulusBytes)

        XCTAssertNotEqual(
            left.challengeScalar(domain: "challenge"),
            right.challengeScalar(domain: "challenge")
        )
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

    func testPiCCSRejectsOutputForDifferentStatement() {
        let input = AcceptanceSupport.samplePiCCSInput(seed: 31)
        var transcript = NuTranscriptField(domain: "Tests.PiCCS.StatementBinding")
        let output = PiCCS.prove(input: input, transcript: &transcript)

        let tamperedInput = PiCCS.Input(
            relation: input.relation,
            publicInputs: input.publicInputs,
            witness: [input.witness[0] + .one] + Array(input.witness.dropFirst()),
            relaxationFactor: input.relaxationFactor
        )
        var verifyTranscript = NuTranscriptField(domain: "Tests.PiCCS.StatementBinding")
        XCTAssertFalse(PiCCS.verify(input: tamperedInput, output: output, transcript: &verifyTranscript))
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

    func testPiRLCRejectsOutputForDifferentStatement() {
        let key = NuParams.derive(from: .canonical).fold.commitmentKey
        let inputs = AcceptanceSupport.samplePiRLCInputs(key: key, seed: 91)
        var transcript = NuTranscriptField(domain: "Tests.PiRLC.StatementBinding")
        let output = PiRLC.prove(inputs: inputs, key: key, transcript: &transcript)

        let tamperedFirst = PiRLC.Input(
            commitment: inputs[0].commitment,
            witness: inputs[0].witness,
            publicInputs: [inputs[0].publicInputs[0] + .one] + Array(inputs[0].publicInputs.dropFirst()),
            ccsEvaluations: inputs[0].ccsEvaluations,
            relaxationFactor: inputs[0].relaxationFactor,
            errorTerms: inputs[0].errorTerms
        )
        var tamperedInputs = inputs
        tamperedInputs[0] = tamperedFirst

        var verifyTranscript = NuTranscriptField(domain: "Tests.PiRLC.StatementBinding")
        XCTAssertFalse(PiRLC.verify(inputs: tamperedInputs, output: output, key: key, transcript: &verifyTranscript))
    }

    func testPiRLCRejectsOutputWhenInheritedErrorTermsChange() {
        let key = NuParams.derive(from: .canonical).fold.commitmentKey
        let inputs = AcceptanceSupport.samplePiRLCInputs(key: key, seed: 117)
        var transcript = NuTranscriptField(domain: "Tests.PiRLC.ErrorTerms")
        let output = PiRLC.prove(inputs: inputs, key: key, transcript: &transcript)

        let tamperedFirst = PiRLC.Input(
            commitment: inputs[0].commitment,
            witness: inputs[0].witness,
            publicInputs: inputs[0].publicInputs,
            ccsEvaluations: inputs[0].ccsEvaluations,
            relaxationFactor: inputs[0].relaxationFactor,
            errorTerms: [inputs[0].errorTerms[0] + RingElement(constant: .one)]
        )
        var tamperedInputs = inputs
        tamperedInputs[0] = tamperedFirst

        var verifyTranscript = NuTranscriptField(domain: "Tests.PiRLC.ErrorTerms")
        XCTAssertFalse(PiRLC.verify(inputs: tamperedInputs, output: output, key: key, transcript: &verifyTranscript))
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

    func testPiDECRejectsOutputForDifferentInputCommitment() {
        let key = NuParams.derive(from: .canonical).fold.commitmentKey
        let input = AcceptanceSupport.samplePiDECInput(key: key, seed: 101)
        var transcript = NuTranscriptField(domain: "Tests.PiDEC.StatementBinding")
        let output = PiDEC.prove(input: input, transcript: &transcript)

        let tamperedInput = PiDEC.Input(
            witness: input.witness,
            commitment: AjtaiCommitment(value: input.commitment.value + RingElement(constant: .one)),
            key: input.key,
            decompBase: input.decompBase,
            decompLimbs: input.decompLimbs
        )
        var verifyTranscript = NuTranscriptField(domain: "Tests.PiDEC.StatementBinding")
        XCTAssertFalse(PiDEC.verify(input: tamperedInput, output: output, transcript: &verifyTranscript))
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

    func testSumCheckRejectsWrongClaimedSum() {
        let polynomial = AcceptanceSupport.samplePolynomial(seed: 19, numVars: 4)
        var transcript = NuTranscriptField(domain: "Tests.SumCheck.ClaimBinding")
        let proof = SumCheck.prove(polynomial: polynomial, transcript: &transcript)

        var verifyTranscript = NuTranscriptField(domain: "Tests.SumCheck.ClaimBinding")
        XCTAssertFalse(
            SumCheck.verify(
                proof: proof,
                numVars: polynomial.numVars,
                claimedSum: polynomial.evals.reduce(.zero, +) + .one,
                transcript: &verifyTranscript
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

    func testDirectPackedOpeningMetalMatchesCPU() throws {
        let context = try AcceptanceSupport.metalContextOrSkip()
        let cpuFixture = try directPackedFixture(context: nil)
        let metalFixture = try directPackedFixture(context: context)

        XCTAssertEqual(cpuFixture.commitment, metalFixture.commitment)
        XCTAssertEqual(cpuFixture.proof, metalFixture.proof)

        var cpuDiagnostics = HachiVerificationDiagnostics()
        var cpuTranscript = NuTranscriptSeal(domain: "Tests.DirectPacked.Parity")
        XCTAssertTrue(
            try cpuFixture.backend.verifyBatch(
                commitments: [cpuFixture.oracle: cpuFixture.commitment],
                queries: [cpuFixture.query],
                proof: metalFixture.proof,
                transcript: &cpuTranscript,
                context: nil,
                traceCollector: nil,
                diagnostics: &cpuDiagnostics
            )
        )
        XCTAssertEqual(cpuDiagnostics.summary, "ok")

        var metalDiagnostics = HachiVerificationDiagnostics()
        var metalTranscript = NuTranscriptSeal(domain: "Tests.DirectPacked.Parity")
        XCTAssertTrue(
            try metalFixture.backend.verifyBatch(
                commitments: [metalFixture.oracle: metalFixture.commitment],
                queries: [metalFixture.query],
                proof: cpuFixture.proof,
                transcript: &metalTranscript,
                context: context,
                traceCollector: nil,
                diagnostics: &metalDiagnostics
            )
        )
        XCTAssertEqual(metalDiagnostics.summary, "ok")
    }

    func testDirectPackedOpeningRejectsTranscriptBindingTamper() throws {
        let fixture = try directPackedFixture(context: nil)
        let classProof = try XCTUnwrap(fixture.proof.classes.first)
        let opening = try XCTUnwrap(classProof.openings.first)
        let directPacked = try XCTUnwrap(opening.directPacked)
        XCTAssertFalse(directPacked.relationProof.transcriptBinding.isEmpty)

        var tamperedTranscriptBinding = directPacked.relationProof.transcriptBinding
        tamperedTranscriptBinding[0] ^= 0x01

        let tamperedRelationProof = ShortLinearWitnessProof(
            initialBindingCommitment: directPacked.relationProof.initialBindingCommitment,
            accumulatorRounds: directPacked.relationProof.accumulatorRounds,
            finalOpening: directPacked.relationProof.finalOpening,
            restartNonce: directPacked.relationProof.restartNonce,
            transcriptBinding: tamperedTranscriptBinding
        )
        let tamperedDirectPacked = HachiDirectPackedOpeningProof(
            packedChunkCount: directPacked.packedChunkCount,
            relationProof: tamperedRelationProof
        )
        let tamperedOpening = HachiPCSOpening(
            oracle: opening.oracle,
            evaluation: opening.evaluation,
            scheduleDigest: opening.scheduleDigest,
            evaluationDigest: opening.evaluationDigest,
            directPacked: tamperedDirectPacked
        )
        let tamperedClass = HachiPCSBatchClassOpeningProof(
            point: classProof.point,
            pointDigest: classProof.pointDigest,
            scheduleDigest: classProof.scheduleDigest,
            openings: [tamperedOpening]
        )
        let tamperedProof = HachiPCSBatchOpeningProof(
            batchSeedDigest: fixture.proof.batchSeedDigest,
            classes: [tamperedClass]
        )

        var diagnostics = HachiVerificationDiagnostics()
        var transcript = NuTranscriptSeal(domain: "Tests.DirectPacked.Parity")
        XCTAssertFalse(
            try fixture.backend.verifyBatch(
                commitments: [fixture.oracle: fixture.commitment],
                queries: [fixture.query],
                proof: tamperedProof,
                transcript: &transcript,
                context: nil,
                traceCollector: nil,
                diagnostics: &diagnostics
            )
        )
        XCTAssertNotEqual(diagnostics.summary, "ok")
    }

    private func basisRing(at index: Int, coefficient: Fq = .one) -> RingElement {
        var coeffs = [Fq](repeating: .zero, count: RingElement.degree)
        coeffs[index] = coefficient
        return RingElement(coeffs: coeffs)
    }

    private func directPackedFixture(
        context: MetalContext?
    ) throws -> (
        backend: HachiPCSBackend,
        oracle: SpartanOracleID,
        commitment: HachiPCSCommitment,
        query: SpartanPCSQuery<Fq>,
        proof: HachiPCSBatchOpeningProof
    ) {
        let backend = HachiPCSBackend()
        let oracle = SpartanOracleID.witness()
        let polynomial = AcceptanceSupport.samplePolynomial(seed: 77, numVars: 6)
        let point: [Fq] = [Fq(3), Fq(5), Fq(7), Fq(11), Fq(13), Fq(17)]
        let query = SpartanPCSQuery(
            oracle: oracle,
            point: point,
            value: polynomial.evaluate(at: point)
        )
        let commitment = try backend.commit(
            label: oracle,
            polynomial: polynomial,
            context: context,
            traceCollector: nil
        )
        var transcript = NuTranscriptSeal(domain: "Tests.DirectPacked.Parity")
        let proof = try backend.openBatch(
            polynomials: [oracle: polynomial],
            queries: [query],
            transcript: &transcript,
            context: context,
            traceCollector: nil
        )
        return (backend, oracle, commitment, query, proof)
    }
}
