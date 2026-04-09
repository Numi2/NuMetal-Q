import Metal

// MARK: - Ajtai Commitment
// Lattice-based commitment using the SuperNeo embedding.
// Commitment products are evaluated over the AG64/Fq4 arithmetic stack.
//
// The commitment key is a vector of ring elements a = (a₁, ..., aₙ) ∈ Rq^n.
// Committing to a witness vector w = (w₁, ..., wₙ) ∈ Rq^n:
//   C = Σᵢ aᵢ · wᵢ ∈ Rq
//
// The production path keeps the public statement in AG64 while executing
// coefficient products through the quartic tower.

/// Ajtai commitment key: a vector of ring elements sampled from a public seed.
public struct AjtaiKey: Sendable {
    /// The commitment key ring elements.
    public let keys: [RingElement]

    /// Precomputed rotation tables for GPU dispatch.
    public let rotationTable: RotationTable

    /// Number of witness slots this key can commit to.
    public var slotCount: Int { keys.count }

    public init(keys: [RingElement]) {
        self.keys = keys
        self.rotationTable = RotationTable(keys: keys)
    }

    /// Generate a deterministic commitment key from a public seed.
    ///
    /// Uses the artifact-layer SHA-256 expander to derive the public
    /// Ajtai matrix from the canonical root seed.
    public static func expand(seed: [UInt8], slotCount: Int) -> AjtaiKey {
        let coefficients = NuParameterExpander.expandFieldElements(
            domain: "NuMeQ.Params.AjtaiKey",
            seed: seed,
            label: "slots=\(slotCount)",
            count: slotCount * RingElement.degree
        )
        var keys = [RingElement]()
        keys.reserveCapacity(slotCount)
        for i in 0..<slotCount {
            let start = i * RingElement.degree
            let end = start + RingElement.degree
            keys.append(RingElement(coeffs: Array(coefficients[start..<end])))
        }
        return AjtaiKey(keys: keys)
    }
}

/// The result of an Ajtai commitment: a single ring element.
public struct AjtaiCommitment: Sendable, Hashable, Codable {
    public let value: RingElement

    public init(value: RingElement) {
        self.value = value
    }

    /// Infinity norm of the commitment (for norm budget checks).
    public var infinityNorm: UInt64 { value.infinityNorm }
}

/// Reference implementation of the Ajtai commitment over the quartic stack.
public enum AjtaiCommitter {
    /// Commit to a vector of ring elements using the given key.
    ///
    /// Vectors shorter than `key.slotCount` are zero-padded so variable-length
    /// witnesses from packing, decomposition limbs, and PiDEC stay valid.
    public static func commit(key: AjtaiKey, witness: [RingElement]) -> AjtaiCommitment {
        precondition(witness.count <= key.slotCount)
        var acc = RingElement.zero
        for i in 0..<witness.count {
            acc += key.keys[i] * witness[i]
        }
        return AjtaiCommitment(value: acc)
    }

    /// Metal entrypoint intentionally reuses the canonical Fq4 arithmetic path.
    public static func commitMetal(
        context: MetalContext,
        key: AjtaiKey,
        witness: [RingElement]
    ) async throws -> AjtaiCommitment {
        precondition(witness.count <= key.slotCount)
        let paddedWitness = witness + [RingElement](repeating: .zero, count: key.slotCount - witness.count)
        return try context.withTransientArena { arena in
            guard let keyBuffer = arena.uploadAjtaiRotationRowsSoA(key),
                  let witnessBuffer = arena.uploadRingElementsSoA(paddedWitness, paddedTo: key.slotCount),
                  let outputBuffer = arena.makeSharedSlice(
                    length: RingElement.degree * MemoryLayout<UInt32>.size * 2
                  ),
                  let keyCountBuffer = arena.makeSharedSlice(length: MemoryLayout<UInt32>.size) else {
                throw NuMetalError.heapCreationFailed
            }

            keyCountBuffer.typedContents(as: UInt32.self, capacity: 1)[0] = UInt32(key.slotCount)

            let dispatcher = KernelDispatcher(context: context)
            try dispatcher.dispatchSparseRotationCommit(
                keyRingCoefficients: keyBuffer,
                witnessBuffer: witnessBuffer,
                outputBuffer: outputBuffer,
                keyCountBuffer: keyCountBuffer
            )

            let outputCount = RingElement.degree
            let pointer = outputBuffer.typedContents(as: UInt32.self, capacity: outputCount * 2)
            let packed = Array(UnsafeBufferPointer(start: pointer, count: outputCount * 2))
            let ring = MetalFieldPacking.unpackRingElementsSoA(packed, ringCount: 1)[0]
            return AjtaiCommitment(value: ring)
        }
    }

    static func commitBatchMetal(
        context: MetalContext,
        key: AjtaiKey,
        witnessBatches: [[RingElement]]
    ) throws -> [AjtaiCommitment] {
        try commitBatchMetal(
            context: context,
            key: key,
            witnessBatches: witnessBatches,
            trace: nil
        )
    }

    package static func commitBatchMetal(
        context: MetalContext,
        key: AjtaiKey,
        witnessBatches: [[RingElement]],
        trace: TimedDispatchTraceContext?
    ) throws -> [AjtaiCommitment] {
        guard witnessBatches.isEmpty == false else { return [] }

        let paddedWitnessBatches = witnessBatches.map { witness in
            witness + [RingElement](repeating: .zero, count: key.slotCount - witness.count)
        }

        guard let keyBuffer = context.uploadAjtaiRotationRowsSoA(key),
              let witnessBuffer = context.uploadRingBatchSoA(paddedWitnessBatches, paddedInnerCount: key.slotCount),
              let outputBuffer = context.makeSharedBuffer(
                length: witnessBatches.count * RingElement.degree * MemoryLayout<UInt32>.size * 2
              ) else {
            throw NuMetalError.heapCreationFailed
        }

        let dispatcher = KernelDispatcher(context: context)
        if let trace {
            _ = try dispatcher.dispatchSparseRotationCommitBatchTimed(
                keyRingCoefficients: keyBuffer,
                witnessBatchBuffer: witnessBuffer,
                outputBuffer: outputBuffer,
                keyCount: key.slotCount,
                batchCount: witnessBatches.count,
                trace: trace
            )
        } else {
            try dispatcher.dispatchSparseRotationCommitBatch(
                keyRingCoefficients: keyBuffer,
                witnessBatchBuffer: witnessBuffer,
                outputBuffer: outputBuffer,
                keyCount: key.slotCount,
                batchCount: witnessBatches.count
            )
        }

        let outputCount = witnessBatches.count * RingElement.degree
        let pointer = outputBuffer.contents().bindMemory(to: UInt32.self, capacity: outputCount * 2)
        let packed = Array(UnsafeBufferPointer(start: pointer, count: outputCount * 2))
        return MetalFieldPacking.unpackRingElementsSoA(packed, ringCount: witnessBatches.count).map {
            AjtaiCommitment(value: $0)
        }
    }

    /// Commit to one witness lane using the canonical SuperNeo embedding.
    /// Each contiguous 64-tuple of field elements becomes one ring element.
    public static func commitLane(
        key: AjtaiKey,
        lane: WitnessLane,
        slotOffset: Int
    ) -> AjtaiCommitment {
        let rings = WitnessPacking.packLaneToRings(lane)
        let numSlots = rings.count

        precondition(slotOffset + numSlots <= key.slotCount)
        var acc = RingElement.zero
        for i in 0..<numSlots {
            acc += key.keys[slotOffset + i] * rings[i]
        }
        return AjtaiCommitment(value: acc)
    }
}
