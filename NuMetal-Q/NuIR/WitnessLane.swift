// MARK: - Witness Lane Types
// The compiler tracks witness lane widths for masking, bounds enforcement, and
// auditability. The canonical SuperNeo embedding still writes one field element
// per ring coefficient; widths are metadata, not a signal to bit-pack values.

/// Width classification for a witness lane.
///
/// Lane widths remain explicit through CCS lowering and witness sanitation,
/// even though the canonical embedding maps one field element to one ring
/// coefficient in the recursive path.
public enum LaneWidth: UInt8, Sendable, Hashable, Codable, CaseIterable {
    case bit     = 1
    case u8      = 8
    case u16     = 16
    case u32     = 32
    case u64     = 64
    case bounded = 128  // bounded integer with explicit bound
    case field   = 255  // full Fq element

    /// Number of bits needed to represent one value in this lane.
    public var bitWidth: Int {
        switch self {
        case .bit:     return 1
        case .u8:      return 8
        case .u16:     return 16
        case .u32:     return 32
        case .u64:     return 64
        case .bounded: return 64  // actual bound stored in LaneDescriptor
        case .field:   return 64
        }
    }
}

/// Descriptor for a single witness lane in a CCS shape.
public struct LaneDescriptor: Sendable, Hashable, Codable {
    /// Lane index within the shape.
    public let index: UInt32

    /// Human-readable name for debugging.
    public let name: String

    /// Width classification.
    public let width: LaneWidth

    /// For bounded lanes, the exclusive upper bound.
    /// For other lanes, this is derived from width.
    public let bound: UInt64

    /// Number of rows (values) in this lane.
    public let length: UInt32

    public init(index: UInt32, name: String, width: LaneWidth, bound: UInt64 = 0, length: UInt32) {
        self.index = index
        self.name = name
        self.width = width
        switch width {
        case .bounded:
            self.bound = bound
        case .bit:
            self.bound = 2
        case .u8:
            self.bound = 1 << 8
        case .u16:
            self.bound = 1 << 16
        case .u32:
            self.bound = 1 << 32
        case .u64, .field:
            self.bound = 0
        }
        self.length = length
    }

    /// Commitment cost in bits (proportional to decomposition base needed).
    public var commitmentBitCost: Int {
        switch width {
        case .bit:     return 1
        case .u8:      return 8
        case .u16:     return 16
        case .u32:     return 32
        case .u64:     return 64
        case .bounded:
            if bound <= 1 { return 1 }
            return max(1, 64 - (bound &- 1).leadingZeroBitCount)
        case .field:   return 64
        }
    }
}

/// Concrete witness data for one lane.
public struct WitnessLane: Sendable, Codable, Hashable {
    public let descriptor: LaneDescriptor
    public var values: [Fq]

    public init(descriptor: LaneDescriptor, values: [Fq]) {
        precondition(values.count == Int(descriptor.length))
        self.descriptor = descriptor
        self.values = values
    }
}

/// Full witness assignment for a CCS instance.
public struct Witness: Sendable, Codable, Hashable {
    public let lanes: [WitnessLane]

    public init(lanes: [WitnessLane]) {
        self.lanes = lanes
    }

    /// Flatten all lanes into a single coefficient vector (for sum-check evaluation).
    public func flatten() -> [Fq] {
        lanes.flatMap(\.values)
    }

    /// Total number of field elements across all lanes.
    public var totalElements: Int {
        lanes.reduce(0) { $0 + Int($1.descriptor.length) }
    }
}

public enum WitnessValidationError: Error, Sendable, Equatable {
    case invalidLength(laneName: String, expected: Int, actual: Int)
    case invalidBound(laneName: String, bound: UInt64)
    case valueOutOfRange(
        laneName: String,
        index: Int,
        value: UInt64,
        width: LaneWidth,
        upperBound: UInt64
    )
}

internal extension Witness {
    func validateSemanticIntegrity() throws {
        try lanes.forEach { lane in
            try lane.validateSemanticIntegrity()
        }
    }
}

internal extension WitnessLane {
    func validateSemanticIntegrity() throws {
        let expectedCount = Int(descriptor.length)
        guard values.count == expectedCount else {
            throw WitnessValidationError.invalidLength(
                laneName: descriptor.name,
                expected: expectedCount,
                actual: values.count
            )
        }

        let upperBound: UInt64?
        switch descriptor.width {
        case .bit:
            upperBound = 2
        case .u8:
            upperBound = 1 << 8
        case .u16:
            upperBound = 1 << 16
        case .u32:
            upperBound = 1 << 32
        case .u64, .field:
            upperBound = nil
        case .bounded:
            guard descriptor.bound > 0, descriptor.bound <= Fq.modulus else {
                throw WitnessValidationError.invalidBound(
                    laneName: descriptor.name,
                    bound: descriptor.bound
                )
            }
            upperBound = descriptor.bound
        }

        guard let upperBound else {
            return
        }

        for (index, value) in values.enumerated() where value.v >= upperBound {
            throw WitnessValidationError.valueOutOfRange(
                laneName: descriptor.name,
                index: index,
                value: value.v,
                width: descriptor.width,
                upperBound: upperBound
            )
        }
    }
}
