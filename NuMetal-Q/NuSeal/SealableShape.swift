import Foundation

extension Shape: NuSealableCCSShape {
    public typealias Scalar = Fq
    public typealias Polynomial = MultilinearPoly

    public var matrixCount: Int { relation.matrices.count }
    public var rowVariableCount: Int { max(0, ceilLog2(relation.m)) }
    public var witnessVariableCount: Int { max(0, ceilLog2(max(1, relation.n - relation.nPublic))) }
    public var publicInputCount: Int { relation.nPublic }
    public var maxRelationDegree: Int {
        relation.gates.map { $0.matrixIndices.count }.max() ?? 0
    }

    public func makeWitnessPolynomial(from witness: [Fq]) throws -> MultilinearPoly {
        try validateWitness(witness)
        let paddedCount = max(1, 1 << witnessVariableCount)
        var evals = witness
        evals.append(contentsOf: [Fq](repeating: .zero, count: paddedCount - witness.count))
        return MultilinearPoly(numVars: witnessVariableCount, evals: evals)
    }

    public func makeRowEvaluationPolynomial(
        matrix index: Int,
        publicInput: [Fq],
        witness: [Fq],
        witnessPolynomial: MultilinearPoly
    ) throws -> MultilinearPoly {
        _ = witnessPolynomial
        let fullAssignment = try makeFullAssignment(publicInput: publicInput, witness: witness)
        let matrix = relation.matrices[index]
        var rowValues = matrix.matvec(fullAssignment)
        let paddedCount = max(1, 1 << rowVariableCount)
        rowValues.append(contentsOf: [Fq](repeating: .zero, count: paddedCount - rowValues.count))
        return MultilinearPoly(numVars: rowVariableCount, evals: rowValues)
    }

    public func evaluate(_ polynomial: MultilinearPoly, at point: [Fq]) throws -> Fq {
        polynomial.evaluate(at: point)
    }

    public func publicContribution(
        ofMatrix index: Int,
        publicInput: [Fq],
        atRowPoint rowPoint: [Fq]
    ) throws -> Fq {
        try validatePublicInput(publicInput)
        guard rowPoint.count == rowVariableCount else {
            throw SpartanSealError.relationArityMismatch(
                expected: rowVariableCount,
                actual: rowPoint.count
            )
        }

        let matrix = relation.matrices[index]
        var accumulator = Fq.zero

        for row in 0..<matrix.rows {
            let rowWeight = Self.hypercubeBasisWeight(
                point: rowPoint,
                index: row,
                variableCount: rowVariableCount
            )
            guard rowWeight.isZero == false else { continue }

            let start = Int(matrix.rowPtr[row])
            let end = Int(matrix.rowPtr[row + 1])
            for entry in start..<end {
                let column = Int(matrix.colIdx[entry])
                guard column < relation.nPublic else { continue }
                accumulator += rowWeight * matrix.values[entry] * publicInput[column]
            }
        }

        return accumulator
    }

    public func matrixValue(
        ofMatrix index: Int,
        rowPoint: [Fq],
        columnPoint: [Fq]
    ) throws -> Fq {
        guard rowPoint.count == rowVariableCount else {
            throw SpartanSealError.relationArityMismatch(
                expected: rowVariableCount,
                actual: rowPoint.count
            )
        }
        guard columnPoint.count == witnessVariableCount else {
            throw SpartanSealError.relationArityMismatch(
                expected: witnessVariableCount,
                actual: columnPoint.count
            )
        }

        let matrix = relation.matrices[index]
        var accumulator = Fq.zero

        for row in 0..<matrix.rows {
            let rowWeight = Self.hypercubeBasisWeight(
                point: rowPoint,
                index: row,
                variableCount: rowVariableCount
            )
            guard rowWeight.isZero == false else { continue }

            let start = Int(matrix.rowPtr[row])
            let end = Int(matrix.rowPtr[row + 1])
            for entry in start..<end {
                let fullColumn = Int(matrix.colIdx[entry])
                guard fullColumn >= relation.nPublic else { continue }

                let witnessColumn = fullColumn - relation.nPublic
                let columnWeight = Self.hypercubeBasisWeight(
                    point: columnPoint,
                    index: witnessColumn,
                    variableCount: witnessVariableCount
                )
                accumulator += rowWeight * columnWeight * matrix.values[entry]
            }
        }

        return accumulator
    }

    public func rowConstraint(rowEvaluations: [Fq]) throws -> Fq {
        guard rowEvaluations.count == matrixCount else {
            throw SpartanSealError.relationArityMismatch(
                expected: matrixCount,
                actual: rowEvaluations.count
            )
        }

        var accumulator = Fq.zero
        for gate in relation.gates {
            var product = gate.coefficientField
            for matrixIndex in gate.matrixIndices {
                product *= rowEvaluations[Int(matrixIndex)]
            }
            accumulator += product
        }
        return accumulator
    }

    public func blindPolynomial(
        _ polynomial: MultilinearPoly,
        for oracle: SpartanOracleID,
        randomness: [UInt8]
    ) throws -> (blinded: MultilinearPoly, blinding: MultilinearPoly) {
        let variableCount = try variableCount(for: oracle)
        guard polynomial.numVars == variableCount else {
            throw SpartanSealError.relationArityMismatch(
                expected: variableCount,
                actual: polynomial.numVars
            )
        }

        let blinding = Self.makeBlindingPolynomial(
            variableCount: variableCount,
            oracle: oracle,
            randomness: randomness
        )
        return (polynomial + blinding, blinding)
    }

    private var witnessCount: Int {
        relation.n - relation.nPublic
    }

    private func makeFullAssignment(publicInput: [Fq], witness: [Fq]) throws -> [Fq] {
        try validatePublicInput(publicInput)
        try validateWitness(witness)
        return publicInput + witness
    }

    private func validatePublicInput(_ publicInput: [Fq]) throws {
        guard publicInput.count == relation.nPublic else {
            throw SpartanSealError.invalidPublicInput(
                expected: relation.nPublic,
                actual: publicInput.count
            )
        }
    }

    private func validateWitness(_ witness: [Fq]) throws {
        guard witness.count == witnessCount else {
            throw SpartanSealError.invalidWitnessLength(
                expected: witnessCount,
                actual: witness.count
            )
        }
    }

    private static func hypercubeBasisWeight(
        point: [Fq],
        index: Int,
        variableCount: Int
    ) -> Fq {
        precondition(point.count == variableCount, "basis weight requires matching arity")

        var accumulator = Fq.one
        for bit in 0..<variableCount {
            if ((index >> bit) & 1) == 1 {
                accumulator *= point[bit]
            } else {
                accumulator *= (Fq.one - point[bit])
            }
        }
        return accumulator
    }

    private func variableCount(for oracle: SpartanOracleID) throws -> Int {
        switch oracle.kind {
        case .witness:
            return witnessVariableCount
        case .matrixRowEvaluation:
            guard let index = oracle.index, (0..<matrixCount).contains(index) else {
                throw SpartanSealError.invalidOracleBlinding(oracle)
            }
            return rowVariableCount
        }
    }

    private static func makeBlindingPolynomial(
        variableCount: Int,
        oracle: SpartanOracleID,
        randomness: [UInt8]
    ) -> MultilinearPoly {
        let evalCount = max(1, 1 << variableCount)
        var digest = NuSealCShake256(domain: "NuMeQ.Seal.OracleBlinding")
        digest.absorb(randomness)
        digest.absorbLabel(oracle.kind.rawValue)
        digest.absorb(field: Fq(UInt64((oracle.index ?? -1) + 1)))
        digest.absorb(field: Fq(UInt64(variableCount)))
        let evals = (0..<evalCount).map { _ in digest.squeezeFieldElement() }
        return MultilinearPoly(numVars: variableCount, evals: evals)
    }
}
