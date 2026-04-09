// MARK: - Quadratic Extension Field K = Fq²
// Fq² = Fq[u] / (u² − β)   where β = 3, a verified nonsquare in Fq.
//
// For the Almost Goldilocks modulus q = 2^64 − 2^32 − 31 we have q ≡ 1 (mod 4),
// so −1 is a square and x² + 1 is REDUCIBLE — it cannot define a field extension.
// β = 3 is a quadratic nonsquare in Fq (verified at build time by the profile
// certificate via Euler's criterion: 3^((q−1)/2) ≡ −1 mod q).
//
// Elements are a + b·u with a, b ∈ Fq, and u² = β = 3.
// This is the coefficient domain for the SuperNeo embedding with d = 64.

public struct Fq2: Sendable, Hashable {
    public var a: Fq  // real part
    public var b: Fq  // u-coefficient

    /// The quadratic nonsquare used to define Fq².
    /// Irreducibility proof: β^((q-1)/2) ≡ -1 (mod q), shipped in the profile certificate.
    public static let beta = Fq(raw: 3)

    public static let zero = Fq2(a: .zero, b: .zero)
    public static let one  = Fq2(a: .one,  b: .zero)
    public static let u    = Fq2(a: .zero, b: .one)

    public init(a: Fq, b: Fq) {
        self.a = a
        self.b = b
    }

    public init(real: Fq) {
        self.a = real
        self.b = .zero
    }

    /// Verify at runtime that β is indeed a nonsquare in Fq (Euler's criterion).
    /// Returns true iff β^((q-1)/2) ≡ q-1 (mod q), i.e. the Legendre symbol is -1.
    public static func verifyIrreducibility() -> Bool {
        let qMinus1Over2 = (Fq.modulus &- 1) >> 1
        let result = beta.pow(qMinus1Over2)
        return result == Fq(raw: Fq.modulus &- 1)
    }
}

// MARK: - Arithmetic
// (a₀ + b₀·u)(a₁ + b₁·u) = (a₀a₁ + β·b₀b₁) + (a₀b₁ + a₁b₀)·u
// Karatsuba: 3 base-field muls instead of 4.

extension Fq2 {
    public static func + (lhs: Fq2, rhs: Fq2) -> Fq2 {
        Fq2(a: lhs.a + rhs.a, b: lhs.b + rhs.b)
    }

    public static func - (lhs: Fq2, rhs: Fq2) -> Fq2 {
        Fq2(a: lhs.a - rhs.a, b: lhs.b - rhs.b)
    }

    public static prefix func - (x: Fq2) -> Fq2 {
        Fq2(a: -x.a, b: -x.b)
    }

    public static func * (lhs: Fq2, rhs: Fq2) -> Fq2 {
        // Karatsuba with u² = β:
        //   real = a₀·a₁ + β·b₀·b₁
        //   imag = (a₀+b₀)(a₁+b₁) − a₀·a₁ − b₀·b₁
        let aa = lhs.a * rhs.a
        let bb = lhs.b * rhs.b
        let ab_sum = (lhs.a + lhs.b) * (rhs.a + rhs.b)
        return Fq2(
            a: aa + beta * bb,           // a₀a₁ + β·b₀b₁
            b: ab_sum - aa - bb          // a₀b₁ + a₁b₀
        )
    }

    /// Scalar multiplication by base field element.
    public static func * (lhs: Fq, rhs: Fq2) -> Fq2 {
        Fq2(a: lhs * rhs.a, b: lhs * rhs.b)
    }

    public static func += (lhs: inout Fq2, rhs: Fq2) { lhs = lhs + rhs }
    public static func -= (lhs: inout Fq2, rhs: Fq2) { lhs = lhs - rhs }
    public static func *= (lhs: inout Fq2, rhs: Fq2) { lhs = lhs * rhs }

    /// Conjugate: conj(a + b·u) = a − b·u
    public var conjugate: Fq2 { Fq2(a: a, b: -b) }

    /// Norm: N(a + b·u) = a² − β·b²
    public var norm: Fq { a * a - Fq2.beta * (b * b) }

    /// Inverse: (a + b·u)^(-1) = conj / norm  where norm = a² − β·b²
    public func inverse() -> Fq2 {
        let n = norm.inverse()
        return Fq2(a: a * n, b: (-b) * n)
    }

    public var isZero: Bool { a.isZero && b.isZero }

    public func toBytes() -> [UInt8] { a.toBytes() + b.toBytes() }

    public static func fromBytes(_ bytes: [UInt8]) -> Fq2? {
        guard bytes.count == 16 else { return nil }
        guard let a = Fq.fromBytes(Array(bytes[0..<8])),
              let b = Fq.fromBytes(Array(bytes[8..<16])) else { return nil }
        return Fq2(a: a, b: b)
    }
}

extension Fq2: CustomStringConvertible {
    public var description: String { "Fq2(\(a.v), \(b.v))" }
}
