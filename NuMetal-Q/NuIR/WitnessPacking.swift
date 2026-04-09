import Foundation

// MARK: - Witness Packing
// SuperNeo's canonical embedding maps each contiguous d-tuple of field
// elements to one ring element by writing the tuple directly as coefficients.
// For AG64, d = 64, so a length-(64 * n) field vector becomes a length-n ring
// vector with only zero-padding on the final partial tuple.

internal enum WitnessPacking {
    enum Error: Swift.Error, Sendable {
        case unsupportedRepresentation(expectedCanonicalRings: Int, actualRings: Int)
    }

    static func valuesPerRing(for descriptor: LaneDescriptor) -> Int {
        _ = descriptor
        return RingElement.degree
    }

    static func slotCount(for lane: WitnessLane) -> Int {
        guard lane.values.isEmpty == false else { return 0 }
        let capacity = valuesPerRing(for: lane.descriptor)
        return (lane.values.count + capacity - 1) / capacity
    }

    static func packLaneToRings(_ lane: WitnessLane) -> [RingElement] {
        packFieldVectorToRings(lane.values)
    }

    static func packWitnessToRings(lanes: [WitnessLane]) -> [RingElement] {
        lanes.flatMap(packLaneToRings)
    }

    static func packFieldVectorToRings(_ values: [Fq]) -> [RingElement] {
        guard values.isEmpty == false else { return [] }

        let ringCount = (values.count + RingElement.degree - 1) / RingElement.degree
        var rings = [RingElement]()
        rings.reserveCapacity(ringCount)

        for ringIndex in 0..<ringCount {
            let start = ringIndex * RingElement.degree
            let end = min(start + RingElement.degree, values.count)
            var coeffs = [Fq](repeating: .zero, count: RingElement.degree)
            for (offset, value) in values[start..<end].enumerated() {
                coeffs[offset] = value
            }
            rings.append(RingElement(coeffs: coeffs))
        }

        return rings
    }

    static func unpackFieldVector(from rings: [RingElement], originalLength: Int? = nil) -> [Fq] {
        let flattened = rings.flatMap(\.coeffs)
        guard let originalLength else {
            return flattened
        }
        return Array(flattened.prefix(originalLength))
    }

    static func canonicalRingCount(forFieldCount count: Int) -> Int {
        guard count > 0 else { return 0 }
        return (count + RingElement.degree - 1) / RingElement.degree
    }

    static func canonicalizeRings(
        _ rings: [RingElement],
        originalFieldCount: Int,
        decompBase: UInt8,
        decompLimbs: UInt8
    ) throws -> [RingElement] {
        let canonicalCount = canonicalRingCount(forFieldCount: originalFieldCount)
        if rings.count == canonicalCount {
            return rings
        }

        let decomposedCount = canonicalCount * Int(decompLimbs)
        if canonicalCount > 0, rings.count == decomposedCount {
            return stride(from: 0, to: rings.count, by: Int(decompLimbs)).map { start in
                let end = start + Int(decompLimbs)
                return Decomposition(
                    limbs: Array(rings[start..<end]),
                    base: UInt64(decompBase)
                ).reconstruct()
            }
        }

        if canonicalCount == 0, rings.isEmpty {
            return []
        }

        throw Error.unsupportedRepresentation(
            expectedCanonicalRings: canonicalCount,
            actualRings: rings.count
        )
    }
}
