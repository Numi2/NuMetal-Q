import Foundation
import XCTest
@testable import NuMetal_Q

final class HachiPCSVerifierBoundaryTests: XCTestCase {
    func testVerifyBatchAPIBoundaryIsPublicOnly() throws {
        let protocolSource = try String(
            contentsOfFile: "/Users/home/NuMetal-Q/NuMetal-Q/NuSeal/SpartanProof.swift",
            encoding: .utf8
        )
        let backendSource = try String(
            contentsOfFile: "/Users/home/NuMetal-Q/NuMetal-Q/NuSeal/HachiPCSBackend.swift",
            encoding: .utf8
        )

        let signatures = [
            try extractVerifyBatchSignature(from: protocolSource),
            try extractVerifyBatchSignature(from: backendSource),
        ]
        let requiredTerms = ["commitments", "queries", "proof", "transcript"]
        let bannedTerms = [
            "MultilinearPoly",
            "polynomials",
            "canonicalWitness",
            "accumulatorArtifact",
            "codeword",
        ]

        for signature in signatures {
            for required in requiredTerms {
                XCTAssertTrue(signature.contains(required), "missing required verifier input \(required) in \(signature)")
            }
            for banned in bannedTerms {
                XCTAssertFalse(signature.contains(banned), "unexpected secret-derived verifier input \(banned) in \(signature)")
            }
        }
    }

    func testDirectPackedProofShapeRemovesPublicReductionObject() throws {
        let source = try String(
            contentsOfFile: "/Users/home/NuMetal-Q/NuMetal-Q/NuSeal/SpartanProof.swift",
            encoding: .utf8
        )
        let directPackedBody = try extractStructBody(
            named: "HachiDirectPackedOpeningProof",
            from: source
        )

        XCTAssertTrue(source.contains("enum HachiPCSOpeningMode"))
        XCTAssertTrue(source.contains("case directPacked"))
        XCTAssertFalse(directPackedBody.contains("codewordIndex"))
        XCTAssertFalse(directPackedBody.contains("codewordValue"))
        XCTAssertFalse(directPackedBody.contains("merkleAuthenticationPath"))
        XCTAssertFalse(source.contains("[[RingElement]]"))
        XCTAssertFalse(source.contains("HachiDirectPackedSigmaRound"))
    }

    func testVerifyRejectsCorruptedPCSOpeningField() async throws {
        let engine = try await AcceptanceSupport.makeEngine()
        let compiledShape = try AcceptanceSupport.makeCompiledShape(name: "PCSOpeningMutation")
        let context = await engine.createContext(
            compiledShape: compiledShape,
            policy: .standard,
            appID: "NuMetalQ.PCSVerifierBoundary",
            attestationVerifier: AcceptanceSupport.attestationVerifier
        )

        let handle = try await context.seed(
            witness: AcceptanceSupport.makeWitness(seed: 91),
            publicInputs: [Fq(3), Fq(5)]
        )
        let sessionKey = AcceptanceSupport.makeSessionKey()
        let sealedExport = try await context.seal(
            handle,
            sessionKey: sessionKey,
            signerKeyID: Data("pcs-verifier-signer".utf8),
            attestation: Data("pcs-verifier-attestation".utf8),
            signEnvelope: AcceptanceSupport.signer
        )

        let valid = try await engine.verify(
            envelope: sealedExport.proofEnvelope,
            compiledShape: compiledShape,
            verifySignature: AcceptanceSupport.verifier,
            sessionKey: sessionKey
        )
        if valid.isValid == false {
            let semanticVerifier = HachiSealEngine()
            let semantic = await semanticVerifier.verifySemantically(
                proof: try sealedExport.proofEnvelope.proof(),
                shape: compiledShape.shape,
                publicHeader: sealedExport.proofEnvelope.publicHeaderBytes,
                executionMode: .cpuOnly,
                traceCollector: nil
            )
            XCTFail(semantic.diagnostics.summary)
        }
        XCTAssertTrue(valid.isValid)

        let proof = try sealedExport.proofEnvelope.proof()
        let firstClass = try XCTUnwrap(
            proof.terminalProof.pcsOpeningProof.classes.first(where: { $0.point.isEmpty == false })
        )
        let firstOpening = try XCTUnwrap(firstClass.openings.first)
        guard firstOpening.mode == .directPacked,
              let directPacked = firstOpening.directPacked else {
            throw XCTSkip("expected direct-packed opening in AG64 small-table regime")
        }
        var mutatedShortResponses = directPacked.relationProof.finalOpening.shortResponses
        mutatedShortResponses[0].coeffs[0] += .one
        let mutatedFinalOpening = ShortLinearWitnessFinalOpening(
            bindingMaskCommitment: directPacked.relationProof.finalOpening.bindingMaskCommitment,
            relationMaskCommitment: directPacked.relationProof.finalOpening.relationMaskCommitment,
            evaluationMaskCommitment: directPacked.relationProof.finalOpening.evaluationMaskCommitment,
            outerMaskCommitment: directPacked.relationProof.finalOpening.outerMaskCommitment,
            shortResponses: mutatedShortResponses,
            outerResponses: directPacked.relationProof.finalOpening.outerResponses
        )
        let mutatedOpening = HachiPCSOpening(
            oracle: firstOpening.oracle,
            evaluation: firstOpening.evaluation,
            scheduleDigest: firstOpening.scheduleDigest,
            evaluationDigest: firstOpening.evaluationDigest,
            directPacked: HachiDirectPackedOpeningProof(
                packedChunkCount: directPacked.packedChunkCount,
                relationProof: ShortLinearWitnessProof(
                    initialBindingCommitment: directPacked.relationProof.initialBindingCommitment,
                    accumulatorRounds: directPacked.relationProof.accumulatorRounds,
                    finalOpening: mutatedFinalOpening,
                    restartNonce: directPacked.relationProof.restartNonce,
                    transcriptBinding: directPacked.relationProof.transcriptBinding
                )
            )
        )
        let mutatedClass = HachiPCSBatchClassOpeningProof(
            point: firstClass.point,
            pointDigest: firstClass.pointDigest,
            scheduleDigest: firstClass.scheduleDigest,
            openings: [mutatedOpening] + firstClass.openings.dropFirst()
        )
        let mutatedPCSProof = HachiPCSBatchOpeningProof(
            batchSeedDigest: proof.terminalProof.pcsOpeningProof.batchSeedDigest,
            classes: [mutatedClass] + proof.terminalProof.pcsOpeningProof.classes.dropFirst()
        )
        let mutatedTerminalProof = HachiTerminalProof(
            witnessCommitment: proof.terminalProof.witnessCommitment,
            matrixEvaluationCommitments: proof.terminalProof.matrixEvaluationCommitments,
            blindingCommitments: proof.terminalProof.blindingCommitments,
            outerSumcheck: proof.terminalProof.outerSumcheck,
            innerSumcheck: proof.terminalProof.innerSumcheck,
            claimedEvaluations: proof.terminalProof.claimedEvaluations,
            blindingEvaluations: proof.terminalProof.blindingEvaluations,
            pcsOpeningProof: mutatedPCSProof,
            blindingOpeningProof: proof.terminalProof.blindingOpeningProof
        )
        let tamperedEnvelope = try AcceptanceSupport.resignEnvelope(
            sealedExport.proofEnvelope,
            proofBytes: try SealProofCodec.serialize(
                PublicSealProof(
                    statement: proof.statement,
                    terminalProof: mutatedTerminalProof
                )
            )
        )

        let tampered = try await engine.verify(
            envelope: tamperedEnvelope,
            compiledShape: compiledShape,
            verifySignature: AcceptanceSupport.verifier,
            sessionKey: sessionKey
        )
        XCTAssertFalse(tampered.isValid)
        XCTAssertEqual(tampered.reason, VerificationFailure.proofInvalid)
    }

    func testVerifyRejectsChangedPCSQueryPoint() async throws {
        let engine = try await AcceptanceSupport.makeEngine()
        let compiledShape = try AcceptanceSupport.makeCompiledShape(name: "PCSQueryPointMutation")
        let context = await engine.createContext(
            compiledShape: compiledShape,
            policy: .standard,
            appID: "NuMetalQ.PCSQueryMutation",
            attestationVerifier: AcceptanceSupport.attestationVerifier
        )

        let handle = try await context.seed(
            witness: AcceptanceSupport.makeWitness(seed: 92),
            publicInputs: [Fq(3), Fq(5)]
        )
        let sessionKey = AcceptanceSupport.makeSessionKey()
        let sealedExport = try await context.seal(
            handle,
            sessionKey: sessionKey,
            signerKeyID: Data("pcs-query-signer".utf8),
            attestation: Data("pcs-query-attestation".utf8),
            signEnvelope: AcceptanceSupport.signer
        )

        let proof = try sealedExport.proofEnvelope.proof()
        let backend = HachiPCSBackend()
        let firstClass = try XCTUnwrap(
            proof.terminalProof.pcsOpeningProof.classes.first(where: { $0.point.isEmpty == false })
        )
        var mutatedPoint = firstClass.point
        mutatedPoint[0] += .one
        let mutatedScheduleDigest = backend.scheduleDigest(
            point: mutatedPoint,
            oracles: firstClass.openings.map(\.oracle),
            batchSeedDigest: proof.terminalProof.pcsOpeningProof.batchSeedDigest
        )
        let mutatedOpenings = firstClass.openings.map { opening in
            switch opening.mode {
            case .directPacked:
                return HachiPCSOpening(
                    oracle: opening.oracle,
                    evaluation: opening.evaluation,
                    scheduleDigest: mutatedScheduleDigest,
                    evaluationDigest: opening.evaluationDigest,
                    directPacked: opening.directPacked!
                )
            case .general:
                return HachiPCSOpening(
                    oracle: opening.oracle,
                    evaluation: opening.evaluation,
                    scheduleDigest: mutatedScheduleDigest,
                    evaluationDigest: opening.evaluationDigest,
                    general: opening.general!
                )
            }
        }
        let mutatedClass = HachiPCSBatchClassOpeningProof(
            point: mutatedPoint,
            pointDigest: backend.pointDigest(mutatedPoint),
            scheduleDigest: mutatedScheduleDigest,
            openings: mutatedOpenings
        )
        let mutatedPCSProof = HachiPCSBatchOpeningProof(
            batchSeedDigest: proof.terminalProof.pcsOpeningProof.batchSeedDigest,
            classes: [mutatedClass] + proof.terminalProof.pcsOpeningProof.classes.dropFirst()
        )
        let tamperedEnvelope = try AcceptanceSupport.resignEnvelope(
            sealedExport.proofEnvelope,
            proofBytes: try SealProofCodec.serialize(
                PublicSealProof(
                    statement: proof.statement,
                    terminalProof: HachiTerminalProof(
                        witnessCommitment: proof.terminalProof.witnessCommitment,
                        matrixEvaluationCommitments: proof.terminalProof.matrixEvaluationCommitments,
                        blindingCommitments: proof.terminalProof.blindingCommitments,
                        outerSumcheck: proof.terminalProof.outerSumcheck,
                        innerSumcheck: proof.terminalProof.innerSumcheck,
                        claimedEvaluations: proof.terminalProof.claimedEvaluations,
                        blindingEvaluations: proof.terminalProof.blindingEvaluations,
                        pcsOpeningProof: mutatedPCSProof,
                        blindingOpeningProof: proof.terminalProof.blindingOpeningProof
                    )
                )
            )
        )

        let tampered = try await engine.verify(
            envelope: tamperedEnvelope,
            compiledShape: compiledShape,
            verifySignature: AcceptanceSupport.verifier,
            sessionKey: sessionKey
        )
        XCTAssertFalse(tampered.isValid)
        XCTAssertEqual(tampered.reason, VerificationFailure.proofInvalid)
    }

    private func extractVerifyBatchSignature(from source: String) throws -> String {
        guard let start = source.range(of: "func verifyBatch") else {
            throw XCTSkip("verifyBatch signature missing")
        }
        guard let end = source[start.lowerBound...].range(of: "throws -> Bool") else {
            throw XCTSkip("verifyBatch return signature missing")
        }
        return String(source[start.lowerBound...end.upperBound])
    }

    private func extractStructBody(named name: String, from source: String) throws -> String {
        guard let start = source.range(of: "struct \(name)") else {
            throw XCTSkip("missing struct \(name)")
        }
        guard let bodyStart = source[start.lowerBound...].firstIndex(of: "{") else {
            throw XCTSkip("missing body for \(name)")
        }
        var depth = 0
        for index in source[bodyStart...].indices {
            if source[index] == "{" {
                depth += 1
            } else if source[index] == "}" {
                depth -= 1
                if depth == 0 {
                    return String(source[source.index(after: bodyStart)..<index])
                }
            }
        }
        throw XCTSkip("unterminated struct \(name)")
    }
}
