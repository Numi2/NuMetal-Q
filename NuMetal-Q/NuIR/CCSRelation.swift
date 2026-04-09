// MARK: - Customizable Constraint System (CCS)
// CCS generalizes R1CS, Plonkish, and AIR.
// SuperNeo's relation is CCS, so NuMeQ lowers everything to CCS.
//
// A CCS instance has:
//   - Matrices M₁, ..., Mₜ ∈ Fq^{m×n}
//   - Multisets S₁, ..., Sₛ ⊆ [t]
//   - Coefficients c₁, ..., cₛ ∈ Fq
//   - Satisfying witness z ∈ Fq^n such that:
//     Σᵢ cᵢ · (∘_{j ∈ Sᵢ} Mⱼ · z) = 0
//   where ∘ denotes Hadamard (entry-wise) product.

/// Sparse matrix in CSR (compressed sparse row) format over Fq.
public struct SparseMatrix: Sendable {
    public let rows: Int
    public let cols: Int

    /// Row pointers: rowPtr[i] is the index into colIdx/values where row i starts.
    public let rowPtr: [UInt32]

    /// Column indices for non-zero entries.
    public let colIdx: [UInt32]

    /// Non-zero values.
    public let values: [Fq]

    public var nnz: Int { values.count }

    public init(rows: Int, cols: Int, rowPtr: [UInt32], colIdx: [UInt32], values: [Fq]) {
        precondition(rowPtr.count == rows + 1)
        precondition(colIdx.count == values.count)
        self.rows = rows
        self.cols = cols
        self.rowPtr = rowPtr
        self.colIdx = colIdx
        self.values = values
    }

    /// Sparse matrix-vector product: y = M · z.
    public func matvec(_ z: [Fq]) -> [Fq] {
        precondition(z.count == cols)
        var y = [Fq](repeating: .zero, count: rows)
        for i in 0..<rows {
            let start = Int(rowPtr[i])
            let end = Int(rowPtr[i + 1])
            var acc = Fq.zero
            for k in start..<end {
                acc += values[k] * z[Int(colIdx[k])]
            }
            y[i] = acc
        }
        return y
    }
}

/// A single CCS multiset term: coefficient c · ∏_{j ∈ S} (Mⱼ · z)
public struct CCSGate: Sendable, Codable {
    /// Coefficient for this gate.
    public let coefficient: UInt64  // stored as raw Fq value

    /// Indices into the matrix array for this Hadamard product term.
    public let matrixIndices: [UInt16]

    public init(coefficient: Fq, matrixIndices: [UInt16]) {
        self.coefficient = coefficient.v
        self.matrixIndices = matrixIndices
    }

    public var coefficientField: Fq { Fq(raw: coefficient) }
}

/// Full CCS relation definition.
public struct CCSRelation: Sendable {
    /// Number of constraints (rows).
    public let m: Int

    /// Number of witness variables (columns), including public input.
    public let n: Int

    /// Number of public input variables (first nPublic entries of z).
    public let nPublic: Int

    /// Sparse constraint matrices M₁, ..., Mₜ.
    public let matrices: [SparseMatrix]

    /// Gate definitions: each gate has a coefficient and a multiset of matrix indices.
    public let gates: [CCSGate]

    public init(m: Int, n: Int, nPublic: Int, matrices: [SparseMatrix], gates: [CCSGate]) {
        self.m = m
        self.n = n
        self.nPublic = nPublic
        self.matrices = matrices
        self.gates = gates
    }

    /// Verify that witness z satisfies the relation (CPU reference check).
    public func isSatisfied(by z: [Fq]) -> Bool {
        precondition(z.count == n)
        var sum = [Fq](repeating: .zero, count: m)

        for gate in gates {
            var hadamard = [Fq](repeating: .one, count: m)
            for midx in gate.matrixIndices {
                let product = matrices[Int(midx)].matvec(z)
                for i in 0..<m {
                    hadamard[i] *= product[i]
                }
            }
            let c = gate.coefficientField
            for i in 0..<m {
                sum[i] += c * hadamard[i]
            }
        }

        return sum.allSatisfy(\.isZero)
    }
}
