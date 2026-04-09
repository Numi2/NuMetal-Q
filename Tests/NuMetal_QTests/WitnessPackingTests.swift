import XCTest
@testable import NuMetal_Q

final class WitnessPackingTests: XCTestCase {
    func testExactSuperNeoEmbeddingWritesTupleIntoRingCoefficients() {
        let lane = WitnessLane(
            descriptor: LaneDescriptor(index: 0, name: "tuple", width: .field, length: 64),
            values: (0..<64).map { Fq(UInt64($0 + 1)) }
        )

        let rings = WitnessPacking.packLaneToRings(lane)

        XCTAssertEqual(WitnessPacking.slotCount(for: lane), 1)
        XCTAssertEqual(rings.count, 1)
        XCTAssertEqual(rings[0].coeffs, lane.values)
    }

    func testEmbeddingZeroPadsOnlyFinalPartialRing() {
        let lane = WitnessLane(
            descriptor: LaneDescriptor(index: 1, name: "partial", width: .u16, length: 70),
            values: (0..<70).map { Fq(UInt64($0 + 11)) }
        )

        let rings = WitnessPacking.packLaneToRings(lane)

        XCTAssertEqual(WitnessPacking.slotCount(for: lane), 2)
        XCTAssertEqual(rings.count, 2)
        XCTAssertEqual(Array(rings[0].coeffs.prefix(64)), Array(lane.values.prefix(64)))
        XCTAssertEqual(Array(rings[1].coeffs.prefix(6)), Array(lane.values.suffix(6)))
        XCTAssertTrue(rings[1].coeffs.dropFirst(6).allSatisfy(\.isZero))
    }

    func testEmbeddingRoundTripsOriginalFieldVector() {
        let values = (0..<97).map { Fq(UInt64(($0 * 19 + 5) % 257)) }

        let rings = WitnessPacking.packFieldVectorToRings(values)
        let unpacked = WitnessPacking.unpackFieldVector(from: rings, originalLength: values.count)

        XCTAssertEqual(unpacked, values)
    }
}
