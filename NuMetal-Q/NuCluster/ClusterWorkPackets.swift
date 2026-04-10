import Foundation

private extension BinaryReader {
    mutating func readCanonicalFq() throws -> Fq {
        let raw = try readUInt64()
        guard raw < Fq.modulus else {
            throw ClusterWorkPacketError.invalidFormat
        }
        return Fq(raw: raw)
    }
}

// MARK: - Typed Cluster Work Packets
// Cluster transport stays encrypted and signed, but the delegated payloads
// themselves are now typed and verifiable rather than opaque byte blobs.

public enum ClusterWorkPacketError: Error, Sendable {
    case invalidFormat
    case keyCapacityExceeded
    case commitmentMismatch
    case pointArityMismatch
    case invalidConfinedIndex
    case laneCommitmentMismatch
    case invalidWitness(WitnessValidationError)
    case witnessExceedsPiDECRepresentability(maxMagnitude: UInt64, base: UInt8, limbs: UInt8)
}

public struct ClusterLaneCommitment: Sendable {
    public let laneName: String
    public let slotOffset: Int
    public let slotCount: Int
    public let commitment: AjtaiCommitment

    public init(
        laneName: String,
        slotOffset: Int,
        slotCount: Int,
        commitment: AjtaiCommitment
    ) {
        self.laneName = laneName
        self.slotOffset = slotOffset
        self.slotCount = slotCount
        self.commitment = commitment
    }
}

public struct ClusterFoldWorkPacket: Sendable {
    public let lanes: [WitnessLane]
    public let keySeed: [UInt8]
    public let keySlotCount: Int

    public init(
        lanes: [WitnessLane],
        keySeed: [UInt8],
        keySlotCount: Int
    ) {
        self.lanes = lanes
        self.keySeed = keySeed
        self.keySlotCount = keySlotCount
    }

    public func serialize() -> Data {
        var writer = BinaryWriter()
        writer.append(UInt32(lanes.count))
        for lane in lanes {
            ClusterPacketCodec.encode(lane, into: &writer)
        }
        writer.appendLengthPrefixed(keySeed)
        writer.append(UInt32(clamping: keySlotCount))
        return writer.data
    }

    public static func deserialize(_ data: Data) throws -> ClusterFoldWorkPacket {
        var reader = BinaryReader(data)
        let laneCount = try Int(reader.readUInt32())
        let lanes = try (0..<laneCount).map { _ in
            try ClusterPacketCodec.decodeWitnessLane(from: &reader)
        }
        let keySeed = try reader.readLengthPrefixedBytes()
        let keySlotCount = try Int(reader.readUInt32())
        guard reader.isAtEnd else { throw ClusterWorkPacketError.invalidFormat }
        return ClusterFoldWorkPacket(
            lanes: lanes,
            keySeed: keySeed,
            keySlotCount: keySlotCount
        )
    }

    public func execute(metalContext: MetalContext? = nil) async throws -> ClusterFoldWorkResult {
        let validatedLanes = try ClusterPacketCodec.validatedWitnessLanes(lanes)
        let requiredSlots = validatedLanes.reduce(0) { partial, lane in
            partial + ClusterPacketCodec.slotCount(for: lane)
        }
        guard requiredSlots <= keySlotCount else {
            throw ClusterWorkPacketError.keyCapacityExceeded
        }

        let key = AjtaiKey.expand(seed: keySeed, slotCount: keySlotCount)
        let packedWitness = ClusterPacketCodec.packWitnessToRings(lanes: validatedLanes)
        let aggregatedCommitment: AjtaiCommitment
        if let metalContext {
            aggregatedCommitment = try await AjtaiCommitter.commitMetal(
                context: metalContext,
                key: key,
                witness: packedWitness
            )
        } else {
            aggregatedCommitment = AjtaiCommitter.commit(key: key, witness: packedWitness)
        }

        var laneCommitments = [ClusterLaneCommitment]()
        laneCommitments.reserveCapacity(validatedLanes.count)
        var slotOffset = 0
        for lane in validatedLanes {
            let slotCount = ClusterPacketCodec.slotCount(for: lane)
            let commitment = AjtaiCommitter.commitLane(key: key, lane: lane, slotOffset: slotOffset)
            laneCommitments.append(ClusterLaneCommitment(
                laneName: lane.descriptor.name,
                slotOffset: slotOffset,
                slotCount: slotCount,
                commitment: commitment
            ))
            slotOffset += slotCount
        }

        return ClusterFoldWorkResult(
            packedWitness: packedWitness,
            aggregatedCommitment: aggregatedCommitment,
            laneCommitments: laneCommitments
        )
    }
}

public struct ClusterFoldWorkResult: Sendable {
    public let packedWitness: [RingElement]
    public let aggregatedCommitment: AjtaiCommitment
    public let laneCommitments: [ClusterLaneCommitment]

    public init(
        packedWitness: [RingElement],
        aggregatedCommitment: AjtaiCommitment,
        laneCommitments: [ClusterLaneCommitment]
    ) {
        self.packedWitness = packedWitness
        self.aggregatedCommitment = aggregatedCommitment
        self.laneCommitments = laneCommitments
    }

    public func serialize() -> Data {
        var writer = BinaryWriter()
        ClusterPacketCodec.encode(rings: packedWitness, into: &writer)
        ClusterPacketCodec.encode(aggregatedCommitment, into: &writer)
        writer.append(UInt32(laneCommitments.count))
        for laneCommitment in laneCommitments {
            let laneName = Data(laneCommitment.laneName.utf8)
            writer.appendLengthPrefixed(laneName)
            writer.append(UInt32(clamping: laneCommitment.slotOffset))
            writer.append(UInt32(clamping: laneCommitment.slotCount))
            ClusterPacketCodec.encode(laneCommitment.commitment, into: &writer)
        }
        return writer.data
    }

    public static func deserialize(_ data: Data) throws -> ClusterFoldWorkResult {
        var reader = BinaryReader(data)
        let packedWitness = try ClusterPacketCodec.decodeRings(from: &reader)
        let aggregatedCommitment = try ClusterPacketCodec.decodeCommitment(from: &reader)
        let laneCount = try Int(reader.readUInt32())
        let laneCommitments = try (0..<laneCount).map { _ -> ClusterLaneCommitment in
            let nameData = try reader.readLengthPrefixedData()
            guard let laneName = String(data: nameData, encoding: .utf8) else {
                throw ClusterWorkPacketError.invalidFormat
            }
            let slotOffset = try Int(reader.readUInt32())
            let slotCount = try Int(reader.readUInt32())
            let commitment = try ClusterPacketCodec.decodeCommitment(from: &reader)
            return ClusterLaneCommitment(
                laneName: laneName,
                slotOffset: slotOffset,
                slotCount: slotCount,
                commitment: commitment
            )
        }
        guard reader.isAtEnd else { throw ClusterWorkPacketError.invalidFormat }
        return ClusterFoldWorkResult(
            packedWitness: packedWitness,
            aggregatedCommitment: aggregatedCommitment,
            laneCommitments: laneCommitments
        )
    }

    public func isValid(for packet: ClusterFoldWorkPacket) -> Bool {
        guard let validatedLanes = try? ClusterPacketCodec.validatedWitnessLanes(packet.lanes) else {
            return false
        }
        let expectedPacked = ClusterPacketCodec.packWitnessToRings(lanes: validatedLanes)
        guard packedWitness == expectedPacked else { return false }

        let requiredSlots = validatedLanes.reduce(0) { partial, lane in
            partial + ClusterPacketCodec.slotCount(for: lane)
        }
        guard requiredSlots <= packet.keySlotCount else { return false }

        let key = AjtaiKey.expand(seed: packet.keySeed, slotCount: packet.keySlotCount)
        let expectedCommitment = AjtaiCommitter.commit(key: key, witness: expectedPacked)
        guard aggregatedCommitment == expectedCommitment else { return false }
        guard laneCommitments.count == validatedLanes.count else { return false }

        var slotOffset = 0
        for (lane, laneCommitment) in zip(validatedLanes, laneCommitments) {
            let slotCount = ClusterPacketCodec.slotCount(for: lane)
            guard laneCommitment.laneName == lane.descriptor.name else { return false }
            guard laneCommitment.slotOffset == slotOffset else { return false }
            guard laneCommitment.slotCount == slotCount else { return false }
            let expectedLaneCommitment = AjtaiCommitter.commitLane(key: key, lane: lane, slotOffset: slotOffset)
            guard laneCommitment.commitment == expectedLaneCommitment else { return false }
            slotOffset += slotCount
        }

        return true
    }

    func integratingConfinedLanes(
        from witness: Witness,
        confinedIndices: [Int],
        keySeed: [UInt8],
        keySlotCount: Int
    ) throws -> (packedWitness: [RingElement], commitment: AjtaiCommitment) {
        guard laneCommitments.count == witness.lanes.count else {
            throw ClusterWorkPacketError.laneCommitmentMismatch
        }

        let key = AjtaiKey.expand(seed: keySeed, slotCount: keySlotCount)
        var combinedWitness = packedWitness
        var combinedCommitmentValue = aggregatedCommitment.value

        for confinedIndex in confinedIndices {
            guard witness.lanes.indices.contains(confinedIndex) else {
                throw ClusterWorkPacketError.invalidConfinedIndex
            }
            let lane = try ClusterPacketCodec.validatedWitnessLane(witness.lanes[confinedIndex])
            let laneCommitment = laneCommitments[confinedIndex]
            guard laneCommitment.laneName == lane.descriptor.name else {
                throw ClusterWorkPacketError.laneCommitmentMismatch
            }

            let laneRings = ClusterPacketCodec.packWitnessToRings(lanes: [lane])
            guard laneCommitment.slotOffset + laneRings.count <= combinedWitness.count else {
                throw ClusterWorkPacketError.invalidFormat
            }
            for (ringOffset, ring) in laneRings.enumerated() {
                combinedWitness[laneCommitment.slotOffset + ringOffset] += ring
            }

            let localCommitment = AjtaiCommitter.commitLane(
                key: key,
                lane: lane,
                slotOffset: laneCommitment.slotOffset
            )
            combinedCommitmentValue += localCommitment.value
        }

        return (
            packedWitness: combinedWitness,
            commitment: AjtaiCommitment(value: combinedCommitmentValue)
        )
    }
}

public struct ClusterDecomposeWorkPacket: Sendable {
    public let witness: [RingElement]
    public let commitment: AjtaiCommitment
    public let keySeed: [UInt8]
    public let keySlotCount: Int
    public let decompBase: UInt8
    public let decompLimbs: UInt8

    public init(
        witness: [RingElement],
        commitment: AjtaiCommitment,
        keySeed: [UInt8],
        keySlotCount: Int,
        decompBase: UInt8,
        decompLimbs: UInt8
    ) {
        self.witness = witness
        self.commitment = commitment
        self.keySeed = keySeed
        self.keySlotCount = keySlotCount
        self.decompBase = decompBase
        self.decompLimbs = decompLimbs
    }

    public func serialize() -> Data {
        var writer = BinaryWriter()
        ClusterPacketCodec.encode(rings: witness, into: &writer)
        ClusterPacketCodec.encode(commitment, into: &writer)
        writer.appendLengthPrefixed(keySeed)
        writer.append(UInt32(clamping: keySlotCount))
        writer.append(decompBase)
        writer.append(decompLimbs)
        return writer.data
    }

    public static func deserialize(_ data: Data) throws -> ClusterDecomposeWorkPacket {
        var reader = BinaryReader(data)
        let witness = try ClusterPacketCodec.decodeRings(from: &reader)
        let commitment = try ClusterPacketCodec.decodeCommitment(from: &reader)
        let keySeed = try reader.readLengthPrefixedBytes()
        let keySlotCount = try Int(reader.readUInt32())
        let decompBase = try reader.readUInt8()
        let decompLimbs = try reader.readUInt8()
        guard reader.isAtEnd else { throw ClusterWorkPacketError.invalidFormat }
        return ClusterDecomposeWorkPacket(
            witness: witness,
            commitment: commitment,
            keySeed: keySeed,
            keySlotCount: keySlotCount,
            decompBase: decompBase,
            decompLimbs: decompLimbs
        )
    }

    public func execute(metalContext: MetalContext? = nil) async throws -> ClusterDecomposeWorkResult {
        let key = AjtaiKey.expand(seed: keySeed, slotCount: keySlotCount)
        guard witness.count <= key.slotCount else {
            throw ClusterWorkPacketError.keyCapacityExceeded
        }

        let expectedCommitment = AjtaiCommitter.commit(key: key, witness: witness)
        guard expectedCommitment == commitment else {
            throw ClusterWorkPacketError.commitmentMismatch
        }
        guard Decomposition.witnessFits(
            witness,
            base: decompBase,
            numLimbs: decompLimbs
        ) else {
            throw ClusterWorkPacketError.witnessExceedsPiDECRepresentability(
                maxMagnitude: Decomposition.maxCenteredMagnitude(in: witness),
                base: decompBase,
                limbs: decompLimbs
            )
        }

        var transcript = NuTranscriptField(domain: "NuMeQ.Cluster.PiDEC")
        let input = PiDEC.Input(
            witness: witness,
            commitment: commitment,
            key: key,
            decompBase: decompBase,
            decompLimbs: decompLimbs
        )
        let output: PiDEC.Output
        if let metalContext {
            output = try await PiDEC.proveMetal(
                input: input,
                transcript: &transcript,
                context: metalContext
            )
        } else {
            output = PiDEC.prove(input: input, transcript: &transcript)
        }

        return ClusterDecomposeWorkResult(
            decomposedWitness: output.decomposedWitness,
            limbCommitments: output.limbCommitments,
            consistencyChallenge: output.consistencyProof.challenge,
            reconstructedCommitment: output.consistencyProof.reconstructedCommitment
        )
    }
}

public struct ClusterDecomposeWorkResult: Sendable {
    public let decomposedWitness: [[RingElement]]
    public let limbCommitments: [AjtaiCommitment]
    public let consistencyChallenge: Fq
    public let reconstructedCommitment: AjtaiCommitment

    public init(
        decomposedWitness: [[RingElement]],
        limbCommitments: [AjtaiCommitment],
        consistencyChallenge: Fq,
        reconstructedCommitment: AjtaiCommitment
    ) {
        self.decomposedWitness = decomposedWitness
        self.limbCommitments = limbCommitments
        self.consistencyChallenge = consistencyChallenge
        self.reconstructedCommitment = reconstructedCommitment
    }

    public func serialize() -> Data {
        var writer = BinaryWriter()
        writer.append(UInt32(decomposedWitness.count))
        for limbs in decomposedWitness {
            ClusterPacketCodec.encode(rings: limbs, into: &writer)
        }
        writer.append(UInt32(limbCommitments.count))
        for commitment in limbCommitments {
            ClusterPacketCodec.encode(commitment, into: &writer)
        }
        writer.append(consistencyChallenge.v)
        ClusterPacketCodec.encode(reconstructedCommitment, into: &writer)
        return writer.data
    }

    public static func deserialize(_ data: Data) throws -> ClusterDecomposeWorkResult {
        var reader = BinaryReader(data)
        let witnessCount = try Int(reader.readUInt32())
        let decomposedWitness = try (0..<witnessCount).map { _ in
            try ClusterPacketCodec.decodeRings(from: &reader)
        }
        let commitmentCount = try Int(reader.readUInt32())
        let limbCommitments = try (0..<commitmentCount).map { _ in
            try ClusterPacketCodec.decodeCommitment(from: &reader)
        }
        let consistencyChallenge = try reader.readCanonicalFq()
        let reconstructedCommitment = try ClusterPacketCodec.decodeCommitment(from: &reader)
        guard reader.isAtEnd else { throw ClusterWorkPacketError.invalidFormat }
        return ClusterDecomposeWorkResult(
            decomposedWitness: decomposedWitness,
            limbCommitments: limbCommitments,
            consistencyChallenge: consistencyChallenge,
            reconstructedCommitment: reconstructedCommitment
        )
    }

    public func isValid(for packet: ClusterDecomposeWorkPacket) -> Bool {
        let key = AjtaiKey.expand(seed: packet.keySeed, slotCount: packet.keySlotCount)
        guard witnessFitsKey(packet: packet, key: key) else { return false }

        var transcript = NuTranscriptField(domain: "NuMeQ.Cluster.PiDEC")
        let input = PiDEC.Input(
            witness: packet.witness,
            commitment: packet.commitment,
            key: key,
            decompBase: packet.decompBase,
            decompLimbs: packet.decompLimbs
        )
        let output = PiDEC.Output(
            decomposedWitness: decomposedWitness,
            limbCommitments: limbCommitments,
            consistencyProof: DecompConsistencyProof(
                challenge: consistencyChallenge,
                reconstructedCommitment: reconstructedCommitment
            )
        )
        guard PiDEC.verify(input: input, output: output, transcript: &transcript) else {
            return false
        }
        return reconstructedCommitment == packet.commitment
    }

    private func witnessFitsKey(packet: ClusterDecomposeWorkPacket, key: AjtaiKey) -> Bool {
        guard packet.witness.count <= key.slotCount else { return false }
        let expectedCommitment = AjtaiCommitter.commit(key: key, witness: packet.witness)
        return expectedCommitment == packet.commitment
    }
}

public enum HachiClusterSealOperation: String, Sendable, Codable, Equatable {
    case commit
    case open
}

public struct HachiClusterSealCommitments: Sendable, Codable, Equatable {
    public let witnessCommitment: HachiPCSCommitment
    public let matrixEvaluationCommitments: [HachiPCSCommitment]
    public let blindingCommitments: SpartanBlindingCommitments<HachiPCSCommitment>

    public init(
        witnessCommitment: HachiPCSCommitment,
        matrixEvaluationCommitments: [HachiPCSCommitment],
        blindingCommitments: SpartanBlindingCommitments<HachiPCSCommitment>
    ) {
        self.witnessCommitment = witnessCommitment
        self.matrixEvaluationCommitments = matrixEvaluationCommitments
        self.blindingCommitments = blindingCommitments
    }
}

public struct HachiClusterSealOpenings: Sendable, Codable, Equatable {
    public let pcsOpeningProof: HachiPCSBatchOpeningProof
    public let blindingOpeningProof: HachiPCSBatchOpeningProof

    public init(
        pcsOpeningProof: HachiPCSBatchOpeningProof,
        blindingOpeningProof: HachiPCSBatchOpeningProof
    ) {
        self.pcsOpeningProof = pcsOpeningProof
        self.blindingOpeningProof = blindingOpeningProof
    }
}

public struct HachiClusterSealWorkPacket: Sendable, Codable, Equatable {
    public let operation: HachiClusterSealOperation
    public let maskedWitnessPolynomial: MultilinearPoly
    public let maskedRowPolynomials: [MultilinearPoly]
    public let blindingWitnessPolynomial: MultilinearPoly
    public let blindingRowPolynomials: [MultilinearPoly]
    public let maskedQueries: [SpartanPCSQuery<Fq>]
    public let blindingQueries: [SpartanPCSQuery<Fq>]
    public let pcsBatchSeedDigest: [UInt8]
    public let blindingBatchSeedDigest: [UInt8]

    public init(
        operation: HachiClusterSealOperation,
        maskedWitnessPolynomial: MultilinearPoly,
        maskedRowPolynomials: [MultilinearPoly],
        blindingWitnessPolynomial: MultilinearPoly,
        blindingRowPolynomials: [MultilinearPoly],
        maskedQueries: [SpartanPCSQuery<Fq>] = [],
        blindingQueries: [SpartanPCSQuery<Fq>] = [],
        pcsBatchSeedDigest: [UInt8] = [],
        blindingBatchSeedDigest: [UInt8] = []
    ) {
        self.operation = operation
        self.maskedWitnessPolynomial = maskedWitnessPolynomial
        self.maskedRowPolynomials = maskedRowPolynomials
        self.blindingWitnessPolynomial = blindingWitnessPolynomial
        self.blindingRowPolynomials = blindingRowPolynomials
        self.maskedQueries = maskedQueries
        self.blindingQueries = blindingQueries
        self.pcsBatchSeedDigest = pcsBatchSeedDigest
        self.blindingBatchSeedDigest = blindingBatchSeedDigest
    }

    public func serialize() throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return try encoder.encode(self)
    }

    public static func deserialize(_ data: Data) throws -> HachiClusterSealWorkPacket {
        let decoder = JSONDecoder()
        do {
            return try decoder.decode(Self.self, from: data)
        } catch {
            throw ClusterWorkPacketError.invalidFormat
        }
    }

    public func execute(metalContext: MetalContext? = nil) throws -> HachiClusterSealWorkResult {
        let backend = HachiPCSBackend()
        switch operation {
        case .commit:
            let witnessCommitment = try backend.commit(
                label: .witness(),
                polynomial: maskedWitnessPolynomial,
                context: metalContext,
                traceCollector: nil
            )
            let matrixEvaluationCommitments = try maskedRowPolynomials.enumerated().map { index, polynomial in
                try backend.commit(
                    label: .matrixRow(index),
                    polynomial: polynomial,
                    context: metalContext,
                    traceCollector: nil
                )
            }
            let blindingWitnessCommitment = try backend.commit(
                label: .witness(),
                polynomial: blindingWitnessPolynomial,
                context: metalContext,
                traceCollector: nil
            )
            let blindingRowCommitments = try blindingRowPolynomials.enumerated().map { index, polynomial in
                try backend.commit(
                    label: .matrixRow(index),
                    polynomial: polynomial,
                    context: metalContext,
                    traceCollector: nil
                )
            }
            return HachiClusterSealWorkResult(
                operation: .commit,
                commitments: HachiClusterSealCommitments(
                    witnessCommitment: witnessCommitment,
                    matrixEvaluationCommitments: matrixEvaluationCommitments,
                    blindingCommitments: SpartanBlindingCommitments(
                        witness: blindingWitnessCommitment,
                        matrixRows: blindingRowCommitments
                    )
                ),
                openings: nil
            )
        case .open:
            let pcsOpeningProof = try backend.openBatch(
                polynomials: maskedPolynomialsByOracle,
                queries: maskedQueries,
                batchSeedDigest: pcsBatchSeedDigest,
                context: metalContext,
                traceCollector: nil
            )
            let blindingOpeningProof = try backend.openBatch(
                polynomials: blindingPolynomialsByOracle,
                queries: blindingQueries,
                batchSeedDigest: blindingBatchSeedDigest,
                context: metalContext,
                traceCollector: nil
            )
            return HachiClusterSealWorkResult(
                operation: .open,
                commitments: nil,
                openings: HachiClusterSealOpenings(
                    pcsOpeningProof: pcsOpeningProof,
                    blindingOpeningProof: blindingOpeningProof
                )
            )
        }
    }

    private var maskedPolynomialsByOracle: [SpartanOracleID: MultilinearPoly] {
        Dictionary(
            uniqueKeysWithValues:
                [(.witness(), maskedWitnessPolynomial)]
                + maskedRowPolynomials.enumerated().map { (.matrixRow($0.offset), $0.element) }
        )
    }

    private var blindingPolynomialsByOracle: [SpartanOracleID: MultilinearPoly] {
        Dictionary(
            uniqueKeysWithValues:
                [(.witness(), blindingWitnessPolynomial)]
                + blindingRowPolynomials.enumerated().map { (.matrixRow($0.offset), $0.element) }
        )
    }
}

public struct HachiClusterSealWorkResult: Sendable, Codable, Equatable {
    public let operation: HachiClusterSealOperation
    public let commitments: HachiClusterSealCommitments?
    public let openings: HachiClusterSealOpenings?

    public init(
        operation: HachiClusterSealOperation,
        commitments: HachiClusterSealCommitments?,
        openings: HachiClusterSealOpenings?
    ) {
        self.operation = operation
        self.commitments = commitments
        self.openings = openings
    }

    public func serialize() throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return try encoder.encode(self)
    }

    public static func deserialize(_ data: Data) throws -> HachiClusterSealWorkResult {
        let decoder = JSONDecoder()
        do {
            return try decoder.decode(Self.self, from: data)
        } catch {
            throw ClusterWorkPacketError.invalidFormat
        }
    }

    public func isValid(for packet: HachiClusterSealWorkPacket) -> Bool {
        guard let expected = try? packet.execute() else {
            return false
        }
        return expected == self
    }
}

public extension ClusterWorkExecutor {
    static func standard(metalContext: MetalContext? = nil) -> ClusterWorkExecutor {
        ClusterWorkExecutor(
            fold: { payload, _, _ in
                let packet = try ClusterFoldWorkPacket.deserialize(payload)
                let result = try await packet.execute(metalContext: metalContext)
                return result.serialize()
            },
            seal: { payload, _ in
                let packet = try HachiClusterSealWorkPacket.deserialize(payload)
                return try packet.execute(metalContext: metalContext).serialize()
            },
            decompose: { payload, _ in
                let packet = try ClusterDecomposeWorkPacket.deserialize(payload)
                let result = try await packet.execute(metalContext: metalContext)
                return result.serialize()
            }
        )
    }
}

enum ClusterPacketCodec {
    static func encode(_ lane: WitnessLane, into writer: inout BinaryWriter) {
        writer.append(lane.descriptor.index)
        writer.appendLengthPrefixed(Data(lane.descriptor.name.utf8))
        writer.append(lane.descriptor.width.rawValue)
        writer.append(lane.descriptor.bound)
        writer.append(lane.descriptor.length)
        writer.append(UInt32(lane.values.count))
        for value in lane.values {
            writer.append(value.v)
        }
    }

    static func decodeWitnessLane(from reader: inout BinaryReader) throws -> WitnessLane {
        let index = try reader.readUInt32()
        let nameData = try reader.readLengthPrefixedData()
        guard let name = String(data: nameData, encoding: .utf8) else {
            throw ClusterWorkPacketError.invalidFormat
        }
        guard let width = LaneWidth(rawValue: try reader.readUInt8()) else {
            throw ClusterWorkPacketError.invalidFormat
        }
        let bound = try reader.readUInt64()
        let length = try reader.readUInt32()
        let valueCount = try Int(reader.readUInt32())
        guard valueCount == Int(length) else {
            throw ClusterWorkPacketError.invalidFormat
        }
        let values = try (0..<valueCount).map { _ in try reader.readCanonicalFq() }
        let lane = WitnessLane(
            descriptor: LaneDescriptor(
                index: index,
                name: name,
                width: width,
                bound: bound,
                length: length
            ),
            values: values
        )
        return try validatedWitnessLane(lane)
    }

    static func encode(_ commitment: AjtaiCommitment, into writer: inout BinaryWriter) {
        writer.append(Data(commitment.value.toBytes()))
    }

    static func decodeCommitment(from reader: inout BinaryReader) throws -> AjtaiCommitment {
        let bytes = try reader.readData(count: RingElement.degree * MemoryLayout<UInt64>.size)
        guard let ring = RingElement.fromBytes(Array(bytes)) else {
            throw ClusterWorkPacketError.invalidFormat
        }
        return AjtaiCommitment(value: ring)
    }

    static func encode(rings: [RingElement], into writer: inout BinaryWriter) {
        writer.append(UInt32(rings.count))
        for ring in rings {
            writer.append(Data(ring.toBytes()))
        }
    }

    static func decodeRings(from reader: inout BinaryReader) throws -> [RingElement] {
        let count = try Int(reader.readUInt32())
        return try (0..<count).map { _ in
            let bytes = try reader.readData(count: RingElement.degree * MemoryLayout<UInt64>.size)
            guard let ring = RingElement.fromBytes(Array(bytes)) else {
                throw ClusterWorkPacketError.invalidFormat
            }
            return ring
        }
    }

    static func validatedWitnessLane(_ lane: WitnessLane) throws -> WitnessLane {
        do {
            try lane.validateSemanticIntegrity()
        } catch let error as WitnessValidationError {
            throw ClusterWorkPacketError.invalidWitness(error)
        }
        return lane
    }

    static func validatedWitnessLanes(_ lanes: [WitnessLane]) throws -> [WitnessLane] {
        try lanes.map(validatedWitnessLane)
    }

    static func slotCount(for lane: WitnessLane) -> Int {
        WitnessPacking.slotCount(for: lane)
    }

    static func packWitnessToRings(lanes: [WitnessLane]) -> [RingElement] {
        WitnessPacking.packWitnessToRings(lanes: lanes)
    }
}
