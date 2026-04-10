import XCTest
@testable import NuMetal_Q

final class ProofContextValidationTests: XCTestCase {
    func testSeedAcceptsWitnessCountThatUsesPartialFinalRing() async throws {
        let engine = try await AcceptanceSupport.makeEngine()
        let lane = LaneDescriptor(index: 0, name: "partial", width: .u16, length: 70)
        let relation = CCSRelation(
            m: 1,
            n: 72,
            nPublic: 2,
            matrices: [
                SparseMatrix(rows: 1, cols: 72, rowPtr: [0, 0], colIdx: [], values: []),
            ],
            gates: [
                CCSGate(coefficient: .zero, matrixIndices: [0]),
            ]
        )
        let compiledShape = try AcceptanceSupport.makeCompiledShape(
            name: "PartialWitnessSeed",
            relation: relation,
            lanes: [lane],
            publicHeaderSize: 16
        )
        let context = await engine.createContext(compiledShape: compiledShape)
        let witness = Witness(
            lanes: [
                WitnessLane(
                    descriptor: lane,
                    values: (0..<70).map { Fq(UInt64($0 + 1)) }
                )
            ]
        )

        let handle = try await context.seed(
            witness: witness,
            publicInputs: [Fq(5), Fq(9)],
            publicHeader: AcceptanceSupport.packedPublicHeader([Fq(5), Fq(9)])
        )

        XCTAssertEqual(handle.shapeDigest, compiledShape.shape.digest)
    }
}
