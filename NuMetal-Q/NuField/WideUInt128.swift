/// Portable unsigned 128-bit accumulator used for norm accounting.
///
/// Swift's standard-library `UInt128` is availability-gated on some toolchains.
/// This type keeps norm computations deterministic across Xcode and SwiftPM.
public struct WideUInt128: Sendable, Hashable, Codable, CustomStringConvertible {
    public let high: UInt64
    public let low: UInt64

    public init(high: UInt64 = 0, low: UInt64 = 0) {
        self.high = high
        self.low = low
    }

    public init(_ value: UInt64) {
        self.init(high: 0, low: value)
    }

    public static let zero = WideUInt128()

    public static func + (lhs: WideUInt128, rhs: WideUInt128) -> WideUInt128 {
        let (low, carry) = lhs.low.addingReportingOverflow(rhs.low)
        let high = lhs.high &+ rhs.high &+ (carry ? 1 : 0)
        return WideUInt128(high: high, low: low)
    }

    public static func += (lhs: inout WideUInt128, rhs: WideUInt128) {
        lhs = lhs + rhs
    }

    public static func multiply(_ lhs: UInt64, _ rhs: UInt64) -> WideUInt128 {
        let product = lhs.multipliedFullWidth(by: rhs)
        return WideUInt128(high: product.high, low: product.low)
    }

    public var description: String {
        if high == 0 {
            return "\(low)"
        }
        let highHex = String(high, radix: 16)
        let lowHex = String(low, radix: 16)
        let paddedLow = String(repeating: "0", count: max(0, 16 - lowHex.count)) + lowHex
        return "0x\(highHex)\(paddedLow)"
    }
}
