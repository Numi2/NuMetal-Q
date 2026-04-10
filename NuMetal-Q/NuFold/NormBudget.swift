// MARK: - Norm Budget Tracking
// SuperNeo folding grows the witness norm at each fold step.
// The norm budget tracks accumulated growth and determines when
// decomposition (PiDEC) is needed to re-normalize.

/// Tracks the accumulated scheduler estimate of a folded witness.
///
/// `currentNorm` is an operational proxy used to trigger the fixed PiDEC cadence.
/// It is not a certified convolution bound for negacyclic multiplication.
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

    /// Update the scheduler proxy after a fold step with given challenge magnitude.
    public mutating func recordFold(arity k: Int, challengeMagnitude: UInt64) {
        let arity = UInt64(max(1, k))
        let scaledNorm = currentNorm.multipliedReportingOverflow(by: arity)
        let grownNorm = scaledNorm.partialValue.addingReportingOverflow(challengeMagnitude)
        currentNorm = bound
        if scaledNorm.overflow == false, grownNorm.overflow == false {
            currentNorm = min(bound, grownNorm.partialValue)
        }
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

    public static func coefficientFits(
        _ coefficient: Fq,
        base: UInt8,
        numLimbs: UInt8
    ) -> Bool {
        let B = UInt64(base)
        precondition(B >= 2, "decomposition base must be at least 2")
        var magnitude = coefficient.centeredMagnitude
        for _ in 0..<Int(numLimbs) {
            magnitude /= B
        }
        return magnitude == 0
    }

    public static func elementFits(
        _ element: RingElement,
        base: UInt8,
        numLimbs: UInt8
    ) -> Bool {
        element.coeffs.allSatisfy { coefficientFits($0, base: base, numLimbs: numLimbs) }
    }

    public static func witnessFits(
        _ witness: [RingElement],
        base: UInt8,
        numLimbs: UInt8
    ) -> Bool {
        witness.allSatisfy { elementFits($0, base: base, numLimbs: numLimbs) }
    }

    public static func maxCenteredMagnitude(in witness: [RingElement]) -> UInt64 {
        witness
            .flatMap(\.coeffs)
            .map(\.centeredMagnitude)
            .max() ?? 0
    }

    public static func representabilityCeiling(
        base: UInt8,
        numLimbs: UInt8
    ) -> UInt64? {
        let B = UInt64(base)
        precondition(B >= 2, "decomposition base must be at least 2")
        var ceiling: UInt64 = 1
        for _ in 0..<Int(numLimbs) {
            let (product, overflow) = ceiling.multipliedReportingOverflow(by: B)
            if overflow {
                return nil
            }
            ceiling = product
        }
        return ceiling
    }

    /// Decompose a ring element into bounded limbs.
    public static func decompose(
        element: RingElement,
        base: UInt8,
        numLimbs: UInt8
    ) -> Decomposition {
        let B = UInt64(base)
        precondition(B >= 2, "decomposition base must be at least 2")
        precondition(
            elementFits(element, base: base, numLimbs: numLimbs),
            "PiDEC input coefficient exceeds the configured representability ceiling"
        )
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
