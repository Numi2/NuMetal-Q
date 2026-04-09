// MARK: - Multilinear Polynomial
// The folding and seal stack lives in the sum-check/multilinear world.
// Multilinear-native instead of 's univariate bias.

/// Dense multilinear polynomial over Fq in evaluation form.
///
/// A multilinear polynomial in ν variables is stored as its 2^ν evaluations
/// over the Boolean hypercube {0,1}^ν.
public struct MultilinearPoly: Sendable, Codable, Hashable {
    /// Number of variables.
    public let numVars: Int

    /// Evaluations indexed by binary assignment: evals[b_{ν-1} ... b_1 b_0].
    public var evals: [Fq]

    public init(numVars: Int, evals: [Fq]) {
        precondition(evals.count == 1 << numVars)
        self.numVars = numVars
        self.evals = evals
    }

    /// Create the zero polynomial with given number of variables.
    public static func zero(numVars: Int) -> MultilinearPoly {
        MultilinearPoly(numVars: numVars, evals: [Fq](repeating: .zero, count: 1 << numVars))
    }

    /// Evaluate at a point r ∈ Fq^ν by iterated linear interpolation.
    public func evaluate(at point: [Fq]) -> Fq {
        precondition(point.count == numVars)
        var table = evals
        for i in 0..<numVars {
            let half = table.count / 2
            var next = [Fq](repeating: .zero, count: half)
            let ri = point[i]
            let oneMinusR = Fq.one - ri
            for j in 0..<half {
                next[j] = oneMinusR * table[2 * j] + ri * table[2 * j + 1]
            }
            table = next
        }
        return table[0]
    }

    /// Fix the first variable to a challenge r, reducing ν to ν−1.
    public func bindFirst(to r: Fq) -> MultilinearPoly {
        let half = evals.count / 2
        let oneMinusR = Fq.one - r
        var next = [Fq](repeating: .zero, count: half)
        for j in 0..<half {
            next[j] = oneMinusR * evals[2 * j] + r * evals[2 * j + 1]
        }
        return MultilinearPoly(numVars: numVars - 1, evals: next)
    }

    /// Element-wise addition.
    public static func + (lhs: MultilinearPoly, rhs: MultilinearPoly) -> MultilinearPoly {
        precondition(lhs.numVars == rhs.numVars)
        return MultilinearPoly(
            numVars: lhs.numVars,
            evals: zip(lhs.evals, rhs.evals).map(+)
        )
    }

    /// Scalar multiplication.
    public static func * (scalar: Fq, rhs: MultilinearPoly) -> MultilinearPoly {
        MultilinearPoly(numVars: rhs.numVars, evals: rhs.evals.map { scalar * $0 })
    }

    /// Element-wise (Hadamard) product.
    public func hadamard(with other: MultilinearPoly) -> MultilinearPoly {
        precondition(numVars == other.numVars)
        return MultilinearPoly(
            numVars: numVars,
            evals: zip(evals, other.evals).map(*)
        )
    }
}
