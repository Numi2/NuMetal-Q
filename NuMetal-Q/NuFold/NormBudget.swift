// MARK: - Norm Budget Tracking
// SuperNeo folding grows the witness norm at each fold step.
// The norm budget tracks accumulated growth and determines when
// decomposition (PiDEC) is needed to re-normalize.
//
// Physical execution must be k-ary and norm-budget aware because
// SuperNeo provides multi-folding to amortize decomposition costs.

/// Tracks the accumulated norm of a folded witness.
///
/// After each fold, the witness coefficients may grow. When the norm
/// reaches the certified cadence, a PiDEC decomposition step is executed.
public struct NormBudget: Sendable {
    /// Maximum allowed infinity norm before decomposition is required.
    public let bound: UInt64

    /// Current estimated infinity norm of the accumulated witness.
    public var currentNorm: UInt64

    /// Number of folds since last decomposition.
    public var foldsSinceDecomp: UInt32

    /// Fixed PiDEC cadence certified into the active profile.
    public let decompositionInterval: UInt32

    /// Decomposition base b.
    public let decompBase: UInt8

    /// Number of decomposition limbs.
    public let decompLimbs: UInt8

    public init(
        bound: UInt64,
        decompBase: UInt8,
        decompLimbs: UInt8,
        decompositionInterval: UInt32 = UInt32(NuProfile.canonical.decompositionInterval)
    ) {
        self.bound = bound
        self.currentNorm = 0
        self.foldsSinceDecomp = 0
        self.decompBase = decompBase
        self.decompLimbs = decompLimbs
        self.decompositionInterval = max(1, decompositionInterval)
    }

    /// Whether the fixed PiDEC schedule requires decomposition now.
    public var requiresScheduledDecomposition: Bool {
        foldsSinceDecomp >= decompositionInterval
    }

    /// Update norm estimate after a k-ary fold with given challenge magnitude.
    public mutating func recordFold(arity k: Int, challengeMagnitude: UInt64) {
        currentNorm = currentNorm &* UInt64(k) &+ challengeMagnitude
        foldsSinceDecomp += 1
    }

    /// Reset norm after decomposition.
    public mutating func recordDecomposition() {
        currentNorm = UInt64(decompBase) - 1
        foldsSinceDecomp = 0
    }

}

/// Decomposition of a ring element into bounded limbs.
///
/// Given r with centered coefficients, decompose each coefficient c into
/// limbs c = c₀ + c₁·B + c₂·B² + ... where each cᵢ has centered norm < B.
public struct Decomposition: Sendable {
    public let limbs: [RingElement]
    public let base: UInt64

    /// Decompose a ring element into bounded limbs.
    public static func decompose(
        element: RingElement,
        base: UInt8,
        numLimbs: UInt8
    ) -> Decomposition {
        let B = UInt64(base)
        precondition(B >= 2, "decomposition base must be at least 2")
        let limbCount = Int(numLimbs)
        var limbs = [RingElement]()
        limbs.reserveCapacity(limbCount)

        for l in 0..<limbCount {
            var coeffs = [Fq](repeating: .zero, count: RingElement.degree)
            for i in 0..<RingElement.degree {
                let coefficient = element.coeffs[i]
                let isNegative = coefficient.centeredSignedValue < 0
                var magnitude = coefficient.centeredMagnitude
                for _ in 0..<l {
                    magnitude /= B
                }
                let digit = magnitude % B
                coeffs[i] = Fq.fromCenteredMagnitude(digit, isNegative: isNegative)
            }
            limbs.append(RingElement(coeffs: coeffs))
        }
        return Decomposition(limbs: limbs, base: B)
    }

    /// Reconstruct the original element from limbs.
    public func reconstruct() -> RingElement {
        var result = RingElement.zero
        var power = Fq.one
        let b = Fq(base)
        for limb in limbs {
            result += power * limb
            power *= b
        }
        return result
    }

    static func metalLimbBitWidth(forBase base: UInt64) -> UInt8? {
        guard base >= 2, (base & (base &- 1)) == 0 else { return nil }
        return UInt8(base.trailingZeroBitCount)
    }
}
