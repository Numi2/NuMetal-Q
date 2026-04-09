import Foundation

package func decodePublicInputs(
    from publicHeader: Data,
    shape: Shape
) throws -> [Fq] {
    guard publicHeader.count == shape.publicHeaderSize,
          publicHeader.count.isMultiple(of: MemoryLayout<UInt64>.size) else {
        throw ProofContextError.invalidPublicInputCount(
            expected: shape.relation.nPublic,
            actual: publicHeader.count / MemoryLayout<UInt64>.size
        )
    }

    let publicInputs = stride(
        from: 0,
        to: publicHeader.count,
        by: MemoryLayout<UInt64>.size
    ).compactMap { offset -> Fq? in
        Fq.fromBytes(Array(publicHeader[offset..<offset + MemoryLayout<UInt64>.size]))
    }

    guard publicInputs.count == shape.relation.nPublic else {
        throw ProofContextError.invalidPublicInputCount(
            expected: shape.relation.nPublic,
            actual: publicInputs.count
        )
    }
    return publicInputs
}

package func publicStatementMatchesHeader(
    publicHeader: Data,
    publicInputs: [Fq],
    shape: Shape
) -> Bool {
    guard let decoded = try? decodePublicInputs(from: publicHeader, shape: shape) else {
        return false
    }
    return decoded == publicInputs
}
