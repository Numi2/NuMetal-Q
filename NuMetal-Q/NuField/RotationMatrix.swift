// MARK: - Rotation Matrix Representation
// For d ≤ 64 and |F| ≤ 64, the SuperNeo paper says ring products are most
// efficiently implemented as rotation-matrix field operations.
//
// For a ∈ Rq, the matrix Rot(a) ∈ Fq^{d×d} is the negacyclic convolution
// matrix such that Rot(a) · b_vec = (a · b)_vec for all b ∈ Rq.
//
// Row i stores the coefficient of b_j in output coefficient i:
//   Rot(a)[i, j] = a_{i-j}            when i >= j
//   Rot(a)[i, j] = -a_{i-j+d}         when i < j
// which is the canonical negacyclic Toeplitz/circulant layout.

/// Precomputed rotation matrix for a ring element.
///
/// Used for the Ajtai commitment hot path. The Metal kernel applies these
/// as sparse rotation-add operations rather than full matrix-vector products.
public struct RotationMatrix: Sendable {
    public let d: Int
    public var rows: [[Fq]]

    /// Build the full d×d negacyclic convolution matrix for element a.
    public init(element a: RingElement) {
        self.d = RingElement.degree
        var mat = [[Fq]]()
        mat.reserveCapacity(d)
        for i in 0..<d {
            var row = [Fq]()
            row.reserveCapacity(d)
            for j in 0..<d {
                if i >= j {
                    row.append(a.coeffs[i - j])
                } else {
                    row.append(-a.coeffs[(i - j) + d])
                }
            }
            mat.append(row)
        }
        self.rows = mat
    }

    /// Sparse representation: for each row, only the non-zero (column, value, negated) triples.
    public struct SparseEntry: Sendable {
        public let col: UInt16
        public let value: Fq
    }

    /// Extract sparse entries for GPU upload (only non-zero coefficients).
    public func sparseRows() -> [[SparseEntry]] {
        rows.map { row in
            row.enumerated().compactMap { (col, val) in
                val.isZero ? nil : SparseEntry(col: UInt16(col), value: val)
            }
        }
    }

    /// Apply Rot(a) to vector b, producing a·b in coefficient form.
    public func apply(to b: RingElement) -> RingElement {
        var result = [Fq](repeating: .zero, count: d)
        for i in 0..<d {
            var acc = Fq.zero
            for j in 0..<d {
                acc += rows[i][j] * b.coeffs[j]
            }
            result[i] = acc
        }
        return RingElement(coeffs: result)
    }
}

// MARK: - Rotation Table for GPU Upload

/// Packed rotation table suitable for Metal buffer upload.
/// Stores precomputed Rot(a_i) tables for commitment key vectors.
public struct RotationTable: Sendable {
    public struct PackedRow: Sendable {
        public let entries: [RotationMatrix.SparseEntry]
        public let rowIndex: UInt32
    }

    /// All sparse rows for all key ring elements, packed contiguously.
    public var packedRows: [PackedRow]
    public let keyCount: Int

    public init(keys: [RingElement]) {
        self.keyCount = keys.count
        var packed = [PackedRow]()
        for (ki, key) in keys.enumerated() {
            let rot = RotationMatrix(element: key)
            let sparse = rot.sparseRows()
            for (ri, row) in sparse.enumerated() {
                packed.append(PackedRow(
                    entries: row,
                    rowIndex: UInt32(ki * RingElement.degree + ri)
                ))
            }
        }
        self.packedRows = packed
    }
}
