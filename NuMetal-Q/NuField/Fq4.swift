import Foundation

// MARK: - Quartic Tower Field Fq4
// Fq4 = Fq2[v] / (v^2 - eta), with eta chosen deterministically and certified.

public struct Fq4: Sendable, Hashable {
    public var a: Fq2
    public var b: Fq2

    public static let zero = Fq4(a: .zero, b: .zero)
    public static let one = Fq4(a: .one, b: .zero)

    public init(a: Fq2, b: Fq2) {
        self.a = a
        self.b = b
    }

    public init(real: Fq) {
        self.a = Fq2(real: real)
        self.b = .zero
    }

    public init(real: Fq2) {
        self.a = real
        self.b = .zero
    }
}

extension Fq4 {
    public static func + (lhs: Fq4, rhs: Fq4) -> Fq4 {
        Fq4(a: lhs.a + rhs.a, b: lhs.b + rhs.b)
    }

    public static func - (lhs: Fq4, rhs: Fq4) -> Fq4 {
        Fq4(a: lhs.a - rhs.a, b: lhs.b - rhs.b)
    }

    public static prefix func - (value: Fq4) -> Fq4 {
        Fq4(a: -value.a, b: -value.b)
    }

    public static func * (lhs: Fq4, rhs: Fq4) -> Fq4 {
        let eta = AG64FieldTower.canonical.quarticEta
        let aa = lhs.a * rhs.a
        let bb = lhs.b * rhs.b
        let cross = (lhs.a + lhs.b) * (rhs.a + rhs.b) - aa - bb
        return Fq4(
            a: aa + (eta * bb),
            b: cross
        )
    }

    public static func += (lhs: inout Fq4, rhs: Fq4) { lhs = lhs + rhs }
    public static func -= (lhs: inout Fq4, rhs: Fq4) { lhs = lhs - rhs }
    public static func *= (lhs: inout Fq4, rhs: Fq4) { lhs = lhs * rhs }

    public var conjugate: Fq4 { Fq4(a: a, b: -b) }

    public var norm: Fq2 {
        let eta = AG64FieldTower.canonical.quarticEta
        return a * a - eta * (b * b)
    }

    public func inverse() -> Fq4 {
        let inverseNorm = norm.inverse()
        return Fq4(a: a * inverseNorm, b: (-b) * inverseNorm)
    }

    public var isZero: Bool { a.isZero && b.isZero }

    func pow(_ exponent: WideUInt128) -> Fq4 {
        var result = Fq4.one
        let base = self
        for bit in exponent.bitIndicesReversed {
            result *= result
            if exponent.bit(at: bit) {
                result *= base
            }
        }
        return result
    }
}

public struct AG64FieldTower: Sendable, Hashable {
    public let quadraticNonResidue: Fq
    public let quarticEta: Fq2
    public let etaWitness: [UInt64]

    public static let canonical: AG64FieldTower = {
        let eta = deterministicQuarticEta()
        return AG64FieldTower(
            quadraticNonResidue: Fq2.beta,
            quarticEta: eta,
            etaWitness: [eta.a.v, eta.b.v]
        )
    }()

    public var quarticEtaEncoding: [UInt64] {
        [quarticEta.a.v, quarticEta.b.v]
    }
}

internal extension AG64FieldTower {
    static func deterministicQuarticEta() -> Fq2 {
        let candidates: [Fq2] = [
            Fq2(a: .one, b: .one),
            Fq2(a: Fq(2), b: .one),
            Fq2(a: .zero, b: .one),
            Fq2(a: Fq(5), b: Fq(7)),
            Fq2(a: Fq(11), b: Fq(3)),
        ]
        for candidate in candidates where isQuarticIrreducible(candidate) {
            return candidate
        }
        return Fq2(a: .one, b: .one)
    }

    static func isQuarticIrreducible(_ eta: Fq2) -> Bool {
        guard eta.isZero == false else { return false }
        return isSquareInFq2(eta) == false
    }

    private static func isSquareInFq2(_ value: Fq2) -> Bool {
        if value.isZero {
            return true
        }
        let qSquared = square(UInt64(Fq.modulus))
        let exponent = shiftRightOne(subtractOne(qSquared))
        return value.pow(exponent) == .one
    }

    private static func square(_ value: UInt64) -> WideUInt128 {
        WideUInt128.multiply(value, value)
    }

    private static func subtractOne(_ value: WideUInt128) -> WideUInt128 {
        if value.low > 0 {
            return WideUInt128(high: value.high, low: value.low &- 1)
        }
        return WideUInt128(high: value.high &- 1, low: UInt64.max)
    }

    private static func shiftRightOne(_ value: WideUInt128) -> WideUInt128 {
        let carry = (value.high & 1) << 63
        return WideUInt128(high: value.high >> 1, low: (value.low >> 1) | carry)
    }
}

internal extension Fq2 {
    func pow(_ exponent: WideUInt128) -> Fq2 {
        var result = Fq2.one
        let base = self
        for bit in exponent.bitIndicesReversed {
            result *= result
            if exponent.bit(at: bit) {
                result *= base
            }
        }
        return result
    }
}

internal extension WideUInt128 {
    var bitIndicesReversed: [Int] {
        Array((0..<128).reversed())
    }

    func bit(at index: Int) -> Bool {
        precondition((0..<128).contains(index))
        if index >= 64 {
            return ((high >> (index - 64)) & 1) == 1
        }
        return ((low >> index) & 1) == 1
    }
}

internal enum Fq4Convolution {
    static func multiplyNegacyclic(_ lhs: RingElement, _ rhs: RingElement) -> RingElement {
        let degree = RingElement.degree
        var accumulator = [Fq4](repeating: .zero, count: degree)
        for i in 0..<degree {
            if lhs.coeffs[i].isZero { continue }
            for j in 0..<degree {
                if rhs.coeffs[j].isZero { continue }
                let product = multiplyBaseFieldCoefficients(lhs.coeffs[i], rhs.coeffs[j])
                let index = i + j
                if index < degree {
                    accumulator[index] = requireBaseSubfield(accumulator[index] + product)
                } else {
                    accumulator[index - degree] = requireBaseSubfield(
                        accumulator[index - degree] - product
                    )
                }
            }
        }

        let projected = accumulator.map(projectToBaseField)
        return RingElement(coeffs: projected)
    }

    static func isBaseSubfieldElement(_ value: Fq4) -> Bool {
        value.b.isZero && value.a.b.isZero
    }

    static func tryProjectToBaseField(_ value: Fq4) -> Fq? {
        guard isBaseSubfieldElement(value) else {
            return nil
        }
        return value.a.a
    }

    private static func multiplyBaseFieldCoefficients(_ lhs: Fq, _ rhs: Fq) -> Fq4 {
        let product = Fq4(real: lhs) * Fq4(real: rhs)
        return requireBaseSubfield(product)
    }

    private static func requireBaseSubfield(_ value: Fq4) -> Fq4 {
        guard isBaseSubfieldElement(value) else {
            preconditionFailure("Fq4 ring kernel escaped the AG64 base subfield")
        }
        return value
    }

    private static func projectToBaseField(_ value: Fq4) -> Fq {
        tryProjectToBaseField(requireBaseSubfield(value))!
    }
}
