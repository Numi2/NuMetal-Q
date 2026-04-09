// MARK: - Ring Element in Fq[X] / (X^64 + 1)
// Φ(X) = X^64 + 1 is the cyclotomic polynomial for the SuperNeo embedding.
// d = 64 coefficients, each in Fq.
//
// Multiplication uses scalar extension through the certified quartic tower.
// The abstract ring remains Rq = Fq[X]/(X^64 + 1); convolution executes in Fq4
// and is projected back into Fq with mandatory subfield checks.

/// Polynomial ring element in Rq = Fq[X]/(X^64 + 1).
///
/// Ring product: multiplication mod Φ(X) = X^64 + 1 means
/// X^64 ≡ -1, so shifting by k positions negacyclically rotates
/// and negates wrapped coefficients.
public struct RingElement: Sendable, Hashable, Codable {
    public static let degree = 64

    /// Coefficients c[0]..c[63] representing c[0] + c[1]·X + ... + c[63]·X^63.
    public var coeffs: [Fq]

    public static let zero = RingElement(coeffs: [Fq](repeating: .zero, count: degree))

    public init(coeffs: [Fq]) {
        precondition(coeffs.count == Self.degree)
        self.coeffs = coeffs
    }

    /// Single-coefficient element: value · X^0.
    public init(constant: Fq) {
        var c = [Fq](repeating: .zero, count: Self.degree)
        c[0] = constant
        self.coeffs = c
    }

    /// Negacyclic rotation by k positions: multiply by X^k in Rq.
    /// X^k * (c₀ + c₁X + ... + c_{63}X^{63}) mod (X^64 + 1)
    public func rotate(by k: Int) -> RingElement {
        let d = Self.degree
        let k = ((k % d) + d) % d
        var out = [Fq](repeating: .zero, count: d)
        for i in 0..<d {
            let j = (i + k) % d
            if i + k >= d {
                out[j] = -coeffs[i]  // wraps past X^64 → negate
            } else {
                out[j] = coeffs[i]
            }
        }
        return RingElement(coeffs: out)
    }
}

// MARK: - Arithmetic

extension RingElement {
    public static func + (lhs: RingElement, rhs: RingElement) -> RingElement {
        RingElement(coeffs: zip(lhs.coeffs, rhs.coeffs).map { $0 + $1 })
    }

    public static func - (lhs: RingElement, rhs: RingElement) -> RingElement {
        RingElement(coeffs: zip(lhs.coeffs, rhs.coeffs).map { $0 - $1 })
    }

    public static prefix func - (x: RingElement) -> RingElement {
        RingElement(coeffs: x.coeffs.map { -$0 })
    }

    /// Scalar multiplication by a field element.
    public static func * (scalar: Fq, rhs: RingElement) -> RingElement {
        RingElement(coeffs: rhs.coeffs.map { scalar * $0 })
    }

    public static func += (lhs: inout RingElement, rhs: RingElement) { lhs = lhs + rhs }
    public static func -= (lhs: inout RingElement, rhs: RingElement) { lhs = lhs - rhs }

    /// Negacyclic ring multiplication routed through the quartic tower.
    public static func * (lhs: RingElement, rhs: RingElement) -> RingElement {
        Fq4Convolution.multiplyNegacyclic(lhs, rhs)
    }

    /// Infinity norm: max |c_i| where |c| is min(c, q - c).
    public var infinityNorm: UInt64 {
        let q = Fq.modulus
        let half = q / 2
        return coeffs.reduce(0) { max($0, $1.v <= half ? $1.v : q - $1.v) }
    }

    /// L2 norm squared (useful for norm budget tracking).
    public var l2NormSquared: WideUInt128 {
        let q = Fq.modulus
        let half = q / 2
        return coeffs.reduce(.zero) { acc, c in
            let centered = c.v <= half ? c.v : q - c.v
            return acc + WideUInt128.multiply(centered, centered)
        }
    }

    public func toBytes() -> [UInt8] {
        coeffs.flatMap { $0.toBytes() }
    }

    public static func fromBytes(_ bytes: [UInt8]) -> RingElement? {
        guard bytes.count == degree * 8 else { return nil }
        var coeffs = [Fq]()
        coeffs.reserveCapacity(degree)
        for i in 0..<degree {
            guard let c = Fq.fromBytes(Array(bytes[i*8..<(i+1)*8])) else { return nil }
            coeffs.append(c)
        }
        return RingElement(coeffs: coeffs)
    }
}
