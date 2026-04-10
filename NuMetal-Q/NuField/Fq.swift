// MARK: - Almost Goldilocks64 Base Field
// q = (2^64 - 2^32 + 1) - 32 = 0xFFFFFFFF00000001 - 0x20 = 0xFFFFFFFEFFFFFFE1

/// Almost Goldilocks prime field element.
///
/// The modulus q = 2^64 − 2^32 − 31 keeps efficient Solinas-style reduction
/// with only a small perturbation from the standard Goldilocks prime.
/// This gives ~129-bit Module-SIS security when used with Φ = X^64 + 1, d = 64, K = Fq².
public struct Fq: Sendable, Hashable, Codable, NuField {
    /// The raw limb, always in [0, q).
    public private(set) var v: UInt64

    /// The Almost Goldilocks modulus: 2^64 − 2^32 − 31.
    public static let modulus: UInt64 = 0xFFFF_FFFE_FFFF_FFE1

    /// Precomputed constant: 2^32 + 31, used in Solinas-style reduction.
    public static let solinas32: UInt64 = 0x0000_0001_0000_001F

    public static let zero = Fq(raw: 0)
    public static let one  = Fq(raw: 1)

    init(raw: UInt64) {
        self.v = raw
    }

    /// Canonical reduction: if v >= q, subtract q.
    public init(_ value: UInt64) {
        self.v = value
        if self.v >= Self.modulus {
            self.v &-= Self.modulus
        }
    }

    // MARK: Solinas-style reduction for 128-bit product
    // For q = 2^64 − 2^32 − 31, if z = z_hi * 2^64 + z_lo then
    // z mod q ≡ z_lo + z_hi * (2^32 + 31) mod q
    // which may require a second fold since (2^32+31) * max(z_hi) can exceed 2^64.

    static func reduceFull(hi: UInt64, lo: UInt64) -> Fq {
        var folded = WideUInt128(high: hi, low: lo)
        repeat {
            folded = WideUInt128(folded.low) + WideUInt128.multiply(folded.high, solinas32)
        } while folded.high != 0

        var result = Fq(raw: folded.low)
        if result.v >= modulus { result.v &-= modulus }
        if result.v >= modulus { result.v &-= modulus }
        return result
    }
}

// MARK: - Arithmetic

extension Fq {
    public static func + (lhs: Fq, rhs: Fq) -> Fq {
        let (sum, overflow) = lhs.v.addingReportingOverflow(rhs.v)
        var r = sum
        if overflow || r >= modulus {
            r &-= modulus
        }
        return Fq(raw: r)
    }

    public static func - (lhs: Fq, rhs: Fq) -> Fq {
        if lhs.v >= rhs.v {
            return Fq(raw: lhs.v &- rhs.v)
        } else {
            return Fq(raw: modulus &- rhs.v &+ lhs.v)
        }
    }

    public static prefix func - (x: Fq) -> Fq {
        x.v == 0 ? .zero : Fq(raw: modulus &- x.v)
    }

    public static func * (lhs: Fq, rhs: Fq) -> Fq {
        let (hi, lo) = lhs.v.multipliedFullWidth(by: rhs.v)
        return reduceFull(hi: hi, lo: lo)
    }

    public static func += (lhs: inout Fq, rhs: Fq) { lhs = lhs + rhs }
    public static func -= (lhs: inout Fq, rhs: Fq) { lhs = lhs - rhs }
    public static func *= (lhs: inout Fq, rhs: Fq) { lhs = lhs * rhs }

    /// Compute a^exp mod q via square-and-multiply.
    public func pow(_ exp: UInt64) -> Fq {
        var base = self
        var result = Fq.one
        var e = exp
        while e > 0 {
            if e & 1 == 1 { result *= base }
            base *= base
            e >>= 1
        }
        return result
    }

    /// Modular inverse via Fermat's little theorem: a^(q-2) mod q.
    ///
    /// Returns `nil` for zero so callers cannot silently treat `0` as invertible.
    public func inverted() -> Fq? {
        guard isZero == false else { return nil }
        return pow(Self.modulus &- 2)
    }

    func uncheckedInverse() -> Fq {
        precondition(isZero == false, "zero is not invertible in Fq")
        return pow(Self.modulus &- 2)
    }

    /// Check if this element is zero.
    public var isZero: Bool { v == 0 }

    /// Absolute value of the centered lift in [0, q/2].
    var centeredMagnitude: UInt64 {
        let half = Self.modulus / 2
        return v <= half ? v : Self.modulus &- v
    }

    /// Centered signed lift in [-(q-1)/2, (q-1)/2].
    var centeredSignedValue: Int64 {
        let magnitude = centeredMagnitude
        if v <= Self.modulus / 2 {
            return Int64(magnitude)
        }
        return -Int64(magnitude)
    }

    static func fromCenteredMagnitude(_ magnitude: UInt64, isNegative: Bool) -> Fq {
        precondition(magnitude < modulus, "centered magnitude must stay in the base field")
        guard magnitude != 0 else { return .zero }
        return isNegative ? Fq(raw: modulus &- magnitude) : Fq(raw: magnitude)
    }

    /// Serialize to canonical little-endian 8-byte representation.
    public func toBytes() -> [UInt8] {
        withUnsafeBytes(of: v.littleEndian) { Array($0) }
    }

    /// Deserialize from little-endian 8-byte representation.
    public static func fromBytes(_ bytes: [UInt8]) -> Fq? {
        guard bytes.count == 8 else { return nil }
        let value = LittleEndianCodec.uint64(from: bytes)
        guard value < modulus else { return nil }
        return Fq(raw: value)
    }
}

// MARK: - CustomStringConvertible

extension Fq: CustomStringConvertible {
    public var description: String { "Fq(\(v))" }
}
