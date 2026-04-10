import Foundation

public enum SealProofCodec {
    private static let magic = Data("NuSealZK".utf8)

    fileprivate enum Limits {
        static let digestBytes = 32
        static let backendIDBytes = 128
        static let transcriptIDBytes = 128
        static let publicHeaderBytes = 64 * 1024
        static let publicInputs = 65_536
        static let ringElements = 65_536
        static let sumcheckRounds = 4_096
        static let sumcheckEvaluations = 64
        static let pcsClasses = 4_096
        static let pcsOpenings = 4_096
        static let shortLinearRounds = 4_096
        static let shortLinearResponses = 4_096
        static let commitments = 4_096
        static let shortTranscriptBindingBytes = 64
        static let oracleDigestBytes = 64
        static let accumulatorArtifactBytes = 16 * 1024 * 1024
        static let resumeStageAuditRecords = 16_384
    }

    public static func serialize(_ proof: PublicSealProof) throws -> Data {
        var writer = BinaryWriter()
        writer.append(magic)
        encode(proof, into: &writer)
        return writer.data
    }

    public static func deserialize(_ data: Data) throws -> PublicSealProof {
        var reader = BinaryReader(data)
        guard try reader.readData(count: magic.count) == magic else {
            throw BinaryReader.Error.invalidData
        }
        let proof = try decodeProof(from: &reader)
        guard reader.isAtEnd else {
            throw BinaryReader.Error.invalidData
        }
        guard proof.version == PublicSealProof.currentVersion,
              proof.statement.backendID == NuSealConstants.productionBackendID,
              proof.statement.sealTranscriptID == NuSealConstants.sealTranscriptID else {
            throw BinaryReader.Error.invalidData
        }
        return proof
    }

    static func statementDigest(for statement: PublicSealStatement) -> [UInt8] {
        var writer = BinaryWriter()
        encode(statement, into: &writer)
        return NuSealCShake256.cshake256(
            data: writer.data,
            domain: "NuMeQ.Seal.Statement",
            count: 32
        )
    }

    static func proofDigest(for serializedProof: Data) -> [UInt8] {
        NuSealCShake256.cshake256(
            data: serializedProof,
            domain: "NuMeQ.Seal.PublicProof",
            count: 32
        )
    }

    private static func encode(_ proof: PublicSealProof, into writer: inout BinaryWriter) {
        writer.append(proof.version)
        encode(proof.statement, into: &writer)
        encode(proof.terminalProof, into: &writer)
    }

    private static func decodeProof(from reader: inout BinaryReader) throws -> PublicSealProof {
        let version = try reader.readUInt16()
        let statement = try decodeStatement(from: &reader)
        let terminalProof = try decodeTerminalProof(from: &reader)
        guard version == PublicSealProof.currentVersion else {
            throw BinaryReader.Error.invalidData
        }
        return PublicSealProof(statement: statement, terminalProof: terminalProof)
    }

    private static func encode(_ statement: PublicSealStatement, into writer: inout BinaryWriter) {
        encode(statement.backendID, into: &writer)
        encode(statement.sealTranscriptID, into: &writer)
        encode(statement.shapeDigest, into: &writer)
        writer.appendLengthPrefixed(statement.deciderLayoutDigest)
        writer.appendLengthPrefixed(statement.sealParamDigest)
        writer.appendLengthPrefixed(statement.publicHeader)
        encode(statement.publicInputs, into: &writer)
    }

    private static func decodeStatement(from reader: inout BinaryReader) throws -> PublicSealStatement {
        let statement = PublicSealStatement(
            backendID: try decodeString(from: &reader, maxBytes: Limits.backendIDBytes),
            sealTranscriptID: try decodeString(from: &reader, maxBytes: Limits.transcriptIDBytes),
            shapeDigest: try decodeShapeDigest(from: &reader),
            deciderLayoutDigest: try reader.readLengthPrefixedBytes(maxCount: Limits.digestBytes),
            sealParamDigest: try reader.readLengthPrefixedBytes(maxCount: Limits.digestBytes),
            publicHeader: try reader.readLengthPrefixedData(maxCount: Limits.publicHeaderBytes),
            publicInputs: try decodeFqArray(
                from: &reader,
                minCount: 1,
                maxCount: Limits.publicInputs
            )
        )
        return statement
    }

    private static func encode(_ proof: HachiTerminalProof, into writer: inout BinaryWriter) {
        encode(proof.witnessCommitment, into: &writer)
        encode(proof.matrixEvaluationCommitments, into: &writer)
        encode(proof.blindingCommitments, into: &writer)
        encode(proof.outerSumcheck, into: &writer)
        encode(proof.innerSumcheck, into: &writer)
        encode(proof.claimedEvaluations, into: &writer)
        encode(proof.blindingEvaluations, into: &writer)
        encode(proof.pcsOpeningProof, into: &writer)
        encode(proof.blindingOpeningProof, into: &writer)
    }

    private static func decodeTerminalProof(from reader: inout BinaryReader) throws -> HachiTerminalProof {
        HachiTerminalProof(
            witnessCommitment: try decodeHachiCommitment(from: &reader),
            matrixEvaluationCommitments: try decodeHachiCommitmentArray(from: &reader),
            blindingCommitments: try decodeBlindingCommitments(from: &reader),
            outerSumcheck: try decodeSumcheck(from: &reader),
            innerSumcheck: try decodeSumcheck(from: &reader),
            claimedEvaluations: try decodeClaimedEvaluations(from: &reader),
            blindingEvaluations: try decodeBlindingEvaluations(from: &reader),
            pcsOpeningProof: try decodeBatchOpeningProof(from: &reader),
            blindingOpeningProof: try decodeBatchOpeningProof(from: &reader)
        )
    }

    private static func encode(_ commitments: SpartanBlindingCommitments<HachiPCSCommitment>, into writer: inout BinaryWriter) {
        encode(commitments.witness, into: &writer)
        encode(commitments.matrixRows, into: &writer)
    }

    private static func decodeBlindingCommitments(from reader: inout BinaryReader) throws -> SpartanBlindingCommitments<HachiPCSCommitment> {
        SpartanBlindingCommitments(
            witness: try decodeHachiCommitment(from: &reader),
            matrixRows: try decodeHachiCommitmentArray(from: &reader)
        )
    }

    private static func encode(_ proof: SpartanSumcheckProof, into writer: inout BinaryWriter) {
        writer.append(UInt32(clamping: proof.roundEvaluations.count))
        for round in proof.roundEvaluations {
            encode(round, into: &writer)
        }
        encode(proof.terminalMask, into: &writer)
    }

    private static func decodeSumcheck(from reader: inout BinaryReader) throws -> SpartanSumcheckProof {
        let roundCount = Int(try reader.readUInt32())
        guard roundCount <= Limits.sumcheckRounds else {
            throw BinaryReader.Error.invalidData
        }
        var rounds = [[Fq]]()
        rounds.reserveCapacity(roundCount)
        for _ in 0..<roundCount {
            rounds.append(try decodeFqArray(from: &reader, maxCount: Limits.sumcheckEvaluations))
        }
        let terminalMask = try decodeFq(from: &reader)
        return SpartanSumcheckProof(roundEvaluations: rounds, terminalMask: terminalMask)
    }

    private static func encode(_ evaluations: SpartanClaimedEvaluations<Fq>, into writer: inout BinaryWriter) {
        encode(evaluations.rowPoint, into: &writer)
        encode(evaluations.columnPoint, into: &writer)
        encode(evaluations.matrixRowEvaluations, into: &writer)
        encode(evaluations.witnessEvaluation, into: &writer)
    }

    private static func decodeClaimedEvaluations(from reader: inout BinaryReader) throws -> SpartanClaimedEvaluations<Fq> {
        SpartanClaimedEvaluations(
            rowPoint: try decodeFqArray(from: &reader, maxCount: Limits.publicInputs),
            columnPoint: try decodeFqArray(from: &reader, maxCount: Limits.publicInputs),
            matrixRowEvaluations: try decodeFqArray(from: &reader, maxCount: Limits.publicInputs),
            witnessEvaluation: try decodeFq(from: &reader)
        )
    }

    private static func encode(_ evaluations: SpartanBlindingEvaluations<Fq>, into writer: inout BinaryWriter) {
        encode(evaluations.matrixRows, into: &writer)
        encode(evaluations.witness, into: &writer)
    }

    private static func decodeBlindingEvaluations(from reader: inout BinaryReader) throws -> SpartanBlindingEvaluations<Fq> {
        SpartanBlindingEvaluations(
            matrixRows: try decodeFqArray(from: &reader, maxCount: Limits.publicInputs),
            witness: try decodeFq(from: &reader)
        )
    }

    private static func encode(_ proof: HachiPCSBatchOpeningProof, into writer: inout BinaryWriter) {
        writer.appendLengthPrefixed(proof.batchSeedDigest)
        writer.append(UInt32(clamping: proof.classes.count))
        for classProof in proof.classes {
            encode(classProof, into: &writer)
        }
    }

    private static func decodeBatchOpeningProof(from reader: inout BinaryReader) throws -> HachiPCSBatchOpeningProof {
        let batchSeedDigest = try reader.readLengthPrefixedBytes(maxCount: Limits.digestBytes)
        let classCount = Int(try reader.readUInt32())
        guard classCount <= Limits.pcsClasses else {
            throw BinaryReader.Error.invalidData
        }
        var classes = [HachiPCSBatchClassOpeningProof]()
        classes.reserveCapacity(classCount)
        for _ in 0..<classCount {
            classes.append(try decodeBatchClassProof(from: &reader))
        }
        return HachiPCSBatchOpeningProof(batchSeedDigest: batchSeedDigest, classes: classes)
    }

    private static func encode(_ proof: HachiPCSBatchClassOpeningProof, into writer: inout BinaryWriter) {
        encode(proof.point, into: &writer)
        writer.appendLengthPrefixed(proof.pointDigest)
        writer.appendLengthPrefixed(proof.scheduleDigest)
        writer.append(UInt32(clamping: proof.openings.count))
        for opening in proof.openings {
            encode(opening, into: &writer)
        }
    }

    private static func decodeBatchClassProof(from reader: inout BinaryReader) throws -> HachiPCSBatchClassOpeningProof {
        let point = try decodeFqArray(from: &reader, maxCount: Limits.publicInputs)
        let pointDigest = try reader.readLengthPrefixedBytes(maxCount: Limits.oracleDigestBytes)
        let scheduleDigest = try reader.readLengthPrefixedBytes(maxCount: Limits.oracleDigestBytes)
        let openingCount = Int(try reader.readUInt32())
        guard openingCount <= Limits.pcsOpenings else {
            throw BinaryReader.Error.invalidData
        }
        var openings = [HachiPCSOpening]()
        openings.reserveCapacity(openingCount)
        for _ in 0..<openingCount {
            openings.append(try decodeOpening(from: &reader))
        }
        return HachiPCSBatchClassOpeningProof(
            point: point,
            pointDigest: pointDigest,
            scheduleDigest: scheduleDigest,
            openings: openings
        )
    }

    private static func encode(_ opening: HachiPCSOpening, into writer: inout BinaryWriter) {
        encode(opening.oracle, into: &writer)
        encode(opening.evaluation, into: &writer)
        writer.appendLengthPrefixed(opening.scheduleDigest)
        writer.appendLengthPrefixed(opening.evaluationDigest)
        writer.append(opening.mode.rawValue)
        guard let directPacked = opening.directPacked else {
            preconditionFailure("direct-packed opening missing payload")
        }
        encode(directPacked, into: &writer)
    }

    private static func decodeOpening(from reader: inout BinaryReader) throws -> HachiPCSOpening {
        let oracle = try decodeOracleID(from: &reader)
        let evaluation = try decodeFq(from: &reader)
        let scheduleDigest = try reader.readLengthPrefixedBytes(maxCount: Limits.oracleDigestBytes)
        let evaluationDigest = try reader.readLengthPrefixedBytes(maxCount: Limits.oracleDigestBytes)
        guard let mode = HachiPCSOpeningMode(rawValue: try reader.readUInt8()),
              mode == .directPacked else {
            throw BinaryReader.Error.invalidData
        }
        return HachiPCSOpening(
            oracle: oracle,
            evaluation: evaluation,
            scheduleDigest: scheduleDigest,
            evaluationDigest: evaluationDigest,
            directPacked: try decodeDirectPackedOpening(from: &reader)
        )
    }

    private static func encode(_ proof: HachiDirectPackedOpeningProof, into writer: inout BinaryWriter) {
        writer.append(proof.packedChunkCount)
        encode(proof.relationProof, into: &writer)
    }

    private static func decodeDirectPackedOpening(from reader: inout BinaryReader) throws -> HachiDirectPackedOpeningProof {
        HachiDirectPackedOpeningProof(
            packedChunkCount: try reader.readUInt32(),
            relationProof: try decodeShortLinearWitnessProof(from: &reader)
        )
    }

    private static func encode(_ proof: ShortLinearWitnessProof, into writer: inout BinaryWriter) {
        encode(proof.initialBindingCommitment, into: &writer)
        writer.append(UInt32(clamping: proof.accumulatorRounds.count))
        for round in proof.accumulatorRounds {
            encode(round, into: &writer)
        }
        encode(proof.finalOpening, into: &writer)
        writer.append(proof.restartNonce)
        writer.appendLengthPrefixed(proof.transcriptBinding)
    }

    private static func decodeShortLinearWitnessProof(from reader: inout BinaryReader) throws -> ShortLinearWitnessProof {
        return ShortLinearWitnessProof(
            initialBindingCommitment: try decodeCommitment(from: &reader),
            accumulatorRounds: try decodeAccumulatorRounds(from: &reader),
            finalOpening: try decodeShortLinearWitnessFinalOpening(from: &reader),
            restartNonce: try reader.readUInt32(),
            transcriptBinding: try reader.readLengthPrefixedBytes(maxCount: Limits.shortTranscriptBindingBytes)
        )
    }

    private static func decodeAccumulatorRounds(from reader: inout BinaryReader) throws -> [ShortLinearWitnessAccumulatorRound] {
        let roundCount = Int(try reader.readUInt32())
        guard roundCount <= Limits.shortLinearRounds else {
            throw BinaryReader.Error.invalidData
        }
        var rounds = [ShortLinearWitnessAccumulatorRound]()
        rounds.reserveCapacity(roundCount)
        for _ in 0..<roundCount {
            rounds.append(try decodeShortLinearWitnessAccumulatorRound(from: &reader))
        }
        return rounds
    }

    private static func encode(_ round: ShortLinearWitnessAccumulatorRound, into writer: inout BinaryWriter) {
        encode(round.bindingLeft, into: &writer)
        encode(round.bindingRight, into: &writer)
        encode(round.relationLeft, into: &writer)
        encode(round.relationRight, into: &writer)
        encode(round.evaluationLeft, into: &writer)
        encode(round.evaluationRight, into: &writer)
        encode(round.outerLeft, into: &writer)
        encode(round.outerRight, into: &writer)
    }

    private static func decodeShortLinearWitnessAccumulatorRound(from reader: inout BinaryReader) throws -> ShortLinearWitnessAccumulatorRound {
        ShortLinearWitnessAccumulatorRound(
            bindingLeft: try decodeCommitment(from: &reader),
            bindingRight: try decodeCommitment(from: &reader),
            relationLeft: try decodeCommitment(from: &reader),
            relationRight: try decodeCommitment(from: &reader),
            evaluationLeft: try decodeCommitment(from: &reader),
            evaluationRight: try decodeCommitment(from: &reader),
            outerLeft: try decodeCommitment(from: &reader),
            outerRight: try decodeCommitment(from: &reader)
        )
    }

    private static func encode(_ finalOpening: ShortLinearWitnessFinalOpening, into writer: inout BinaryWriter) {
        encode(finalOpening.bindingMaskCommitment, into: &writer)
        encode(finalOpening.relationMaskCommitment, into: &writer)
        encode(finalOpening.evaluationMaskCommitment, into: &writer)
        encode(finalOpening.outerMaskCommitment, into: &writer)
        writer.append(UInt32(clamping: finalOpening.shortResponses.count))
        for response in finalOpening.shortResponses {
            encode(response, into: &writer)
        }
        writer.append(UInt32(clamping: finalOpening.outerResponses.count))
        for response in finalOpening.outerResponses {
            encode(response, into: &writer)
        }
    }

    private static func decodeShortLinearWitnessFinalOpening(from reader: inout BinaryReader) throws -> ShortLinearWitnessFinalOpening {
        let bindingMaskCommitment = try decodeCommitment(from: &reader)
        let relationMaskCommitment = try decodeCommitment(from: &reader)
        let evaluationMaskCommitment = try decodeCommitment(from: &reader)
        let outerMaskCommitment = try decodeCommitment(from: &reader)
        let shortCount = Int(try reader.readUInt32())
        guard shortCount <= Limits.shortLinearResponses else {
            throw BinaryReader.Error.invalidData
        }
        var shortResponses = [RingElement]()
        shortResponses.reserveCapacity(shortCount)
        for _ in 0..<shortCount {
            shortResponses.append(try decodeRing(from: &reader))
        }
        let outerCount = Int(try reader.readUInt32())
        guard outerCount <= Limits.shortLinearResponses else {
            throw BinaryReader.Error.invalidData
        }
        var outerResponses = [RingElement]()
        outerResponses.reserveCapacity(outerCount)
        for _ in 0..<outerCount {
            outerResponses.append(try decodeRing(from: &reader))
        }
        return ShortLinearWitnessFinalOpening(
            bindingMaskCommitment: bindingMaskCommitment,
            relationMaskCommitment: relationMaskCommitment,
            evaluationMaskCommitment: evaluationMaskCommitment,
            outerMaskCommitment: outerMaskCommitment,
            shortResponses: shortResponses,
            outerResponses: outerResponses
        )
    }

    private static func encode(_ commitment: HachiPCSCommitment, into writer: inout BinaryWriter) {
        encode(commitment.oracle, into: &writer)
        writer.append(commitment.mode.rawValue)
        encode(commitment.tableCommitment, into: &writer)
        writer.append(UInt32(clamping: commitment.directPackedOuterCommitments.count))
        for directPackedOuterCommitment in commitment.directPackedOuterCommitments {
            encode(directPackedOuterCommitment, into: &writer)
        }
        writer.appendLengthPrefixed(commitment.tableDigest)
        writer.appendLengthPrefixed(commitment.parameterDigest)
        writer.append(commitment.valueCount)
        writer.append(commitment.packedChunkCount)
        writer.appendLengthPrefixed(commitment.statementDigest)
    }

    private static func encode(_ commitments: [HachiPCSCommitment], into writer: inout BinaryWriter) {
        writer.append(UInt32(clamping: commitments.count))
        for commitment in commitments {
            encode(commitment, into: &writer)
        }
    }

    private static func decodeHachiCommitment(from reader: inout BinaryReader) throws -> HachiPCSCommitment {
        HachiPCSCommitment(
            oracle: try decodeOracleID(from: &reader),
            mode: try decodeCommitmentMode(from: &reader),
            tableCommitment: try decodeCommitment(from: &reader),
            directPackedOuterCommitments: try decodeCommitmentArray(from: &reader),
            tableDigest: try reader.readLengthPrefixedBytes(maxCount: Limits.digestBytes),
            parameterDigest: try reader.readLengthPrefixedBytes(maxCount: Limits.digestBytes),
            valueCount: try reader.readUInt32(),
            packedChunkCount: try reader.readUInt32(),
            statementDigest: try reader.readLengthPrefixedBytes(maxCount: Limits.digestBytes)
        )
    }

    private static func decodeCommitmentMode(from reader: inout BinaryReader) throws -> HachiPCSCommitmentMode {
        guard let mode = HachiPCSCommitmentMode(rawValue: try reader.readUInt8()),
              mode == .directPacked else {
            throw BinaryReader.Error.invalidData
        }
        return mode
    }

    private static func decodeCommitmentArray(from reader: inout BinaryReader) throws -> [AjtaiCommitment] {
        let count = Int(try reader.readUInt32())
        guard count <= Limits.commitments else {
            throw BinaryReader.Error.invalidData
        }
        var commitments = [AjtaiCommitment]()
        commitments.reserveCapacity(count)
        for _ in 0..<count {
            commitments.append(try decodeCommitment(from: &reader))
        }
        return commitments
    }

    private static func decodeHachiCommitmentArray(from reader: inout BinaryReader) throws -> [HachiPCSCommitment] {
        let count = Int(try reader.readUInt32())
        guard count <= Limits.commitments else {
            throw BinaryReader.Error.invalidData
        }
        var commitments = [HachiPCSCommitment]()
        commitments.reserveCapacity(count)
        for _ in 0..<count {
            commitments.append(try decodeHachiCommitment(from: &reader))
        }
        return commitments
    }

    static func encode(_ commitment: AjtaiCommitment, into writer: inout BinaryWriter) {
        encode(commitment.value, into: &writer)
    }

    static func decodeCommitment(from reader: inout BinaryReader) throws -> AjtaiCommitment {
        AjtaiCommitment(value: try decodeRing(from: &reader))
    }

    private static func encode(_ shapeDigest: ShapeDigest, into writer: inout BinaryWriter) {
        writer.append(Data(shapeDigest.bytes))
    }

    private static func decodeShapeDigest(from reader: inout BinaryReader) throws -> ShapeDigest {
        ShapeDigest(bytes: Array(try reader.readData(count: 32)))
    }

    private static func encode(_ oracle: SpartanOracleID, into writer: inout BinaryWriter) {
        let kind: UInt8
        switch oracle.kind {
        case .witness:
            kind = 0
        case .matrixRowEvaluation:
            kind = 1
        }
        writer.append(kind)
        writer.append(UInt32(clamping: (oracle.index ?? -1) + 1))
    }

    private static func decodeOracleID(from reader: inout BinaryReader) throws -> SpartanOracleID {
        let rawKind = try reader.readUInt8()
        let encodedIndex = Int(try reader.readUInt32()) - 1
        switch rawKind {
        case 0:
            return .witness()
        case 1:
            return .matrixRow(encodedIndex)
        default:
            throw BinaryReader.Error.invalidData
        }
    }

    private static func encode(_ value: String, into writer: inout BinaryWriter) {
        writer.appendLengthPrefixed(Data(value.utf8))
    }

    private static func decodeString(
        from reader: inout BinaryReader,
        maxBytes: Int
    ) throws -> String {
        let data = try reader.readLengthPrefixedData(maxCount: maxBytes)
        guard let value = String(data: data, encoding: .utf8) else {
            throw BinaryReader.Error.invalidData
        }
        return value
    }

    static func encode(_ value: Fq, into writer: inout BinaryWriter) {
        writer.append(Data(value.toBytes()))
    }

    static func decodeFq(from reader: inout BinaryReader) throws -> Fq {
        let bytes = Array(try reader.readData(count: 8))
        guard let value = Fq.fromBytes(bytes) else {
            throw BinaryReader.Error.invalidData
        }
        return value
    }

    static func encode(_ value: RingElement, into writer: inout BinaryWriter) {
        writer.append(Data(value.toBytes()))
    }

    static func decodeRing(from reader: inout BinaryReader) throws -> RingElement {
        let bytes = Array(try reader.readData(count: RingElement.degree * 8))
        guard let value = RingElement.fromBytes(bytes) else {
            throw BinaryReader.Error.invalidData
        }
        return value
    }

    static func encode(_ values: [Fq], into writer: inout BinaryWriter) {
        writer.append(UInt32(clamping: values.count))
        for value in values {
            encode(value, into: &writer)
        }
    }

    static func decodeFqArray(
        from reader: inout BinaryReader,
        minCount: Int = 0,
        maxCount: Int = Limits.publicInputs
    ) throws -> [Fq] {
        let count = Int(try reader.readUInt32())
        guard count >= minCount, count <= maxCount else {
            throw BinaryReader.Error.invalidData
        }
        var values = [Fq]()
        values.reserveCapacity(count)
        for _ in 0..<count {
            values.append(try decodeFq(from: &reader))
        }
        return values
    }

    static func encode(_ values: [RingElement], into writer: inout BinaryWriter) {
        writer.append(UInt32(clamping: values.count))
        for value in values {
            encode(value, into: &writer)
        }
    }

    static func decodeRingArray(
        from reader: inout BinaryReader,
        maxCount: Int = Limits.ringElements
    ) throws -> [RingElement] {
        let count = Int(try reader.readUInt32())
        guard count <= maxCount else {
            throw BinaryReader.Error.invalidData
        }
        var values = [RingElement]()
        values.reserveCapacity(count)
        for _ in 0..<count {
            values.append(try decodeRing(from: &reader))
        }
        return values
    }
}

enum ResumePayloadCodec {
    private static let magic = Data("NuResume".utf8)

    static func serialize(_ payload: ResumePayload) throws -> Data {
        var writer = BinaryWriter()
        writer.append(magic)
        writer.append(payload.version)
        writer.appendLengthPrefixed(payload.accumulatorArtifact)
        encode(payload.normBudgetSnapshot, into: &writer)
        writer.append(payload.provenanceClass.rawValue)
        writer.append(UInt32(clamping: payload.stageAudit.count))
        for record in payload.stageAudit {
            encode(record, into: &writer)
        }
        return writer.data
    }

    static func deserialize(_ data: Data) throws -> ResumePayload {
        var reader = BinaryReader(data)
        guard try reader.readData(count: magic.count) == magic else {
            throw BinaryReader.Error.invalidData
        }
        let version = try reader.readUInt16()
        guard version == ResumePayload.currentVersion else {
            throw BinaryReader.Error.invalidData
        }
        let accumulatorArtifact = try reader.readLengthPrefixedData(maxCount: SealProofCodec.Limits.accumulatorArtifactBytes)
        let normBudgetSnapshot = try decodeNormBudgetSnapshot(from: &reader)
        guard let provenanceClass = WitnessClass(rawValue: try reader.readUInt8()) else {
            throw BinaryReader.Error.invalidData
        }
        let stageAuditCount = Int(try reader.readUInt32())
        guard stageAuditCount <= SealProofCodec.Limits.resumeStageAuditRecords else {
            throw BinaryReader.Error.invalidData
        }
        var stageAudit = [FoldStageRecord]()
        stageAudit.reserveCapacity(stageAuditCount)
        for _ in 0..<stageAuditCount {
            stageAudit.append(try decodeStageRecord(from: &reader))
        }
        guard reader.isAtEnd else {
            throw BinaryReader.Error.invalidData
        }
        return ResumePayload(
            accumulatorArtifact: accumulatorArtifact,
            normBudgetSnapshot: normBudgetSnapshot,
            provenanceClass: provenanceClass,
            stageAudit: stageAudit
        )
    }

    static func encode(_ snapshot: NormBudgetSnapshot, into writer: inout BinaryWriter) {
        writer.append(snapshot.bound)
        writer.append(snapshot.currentNorm)
        writer.append(snapshot.foldsSinceDecomp)
        writer.append(snapshot.decompositionInterval)
        writer.append(snapshot.decompBase)
        writer.append(snapshot.decompLimbs)
    }

    private static func decodeNormBudgetSnapshot(from reader: inout BinaryReader) throws -> NormBudgetSnapshot {
        let bound = try reader.readUInt64()
        let currentNorm = try reader.readUInt64()
        let foldsSinceDecomp = try reader.readUInt32()
        let decompositionInterval = try reader.readUInt32()
        let decompBase = try reader.readUInt8()
        let decompLimbs = try reader.readUInt8()
        var budget = NormBudget(
            bound: bound,
            decompBase: decompBase,
            decompLimbs: decompLimbs,
            decompositionInterval: decompositionInterval
        )
        budget.currentNorm = currentNorm
        budget.foldsSinceDecomp = foldsSinceDecomp
        return NormBudgetSnapshot(normBudget: budget)
    }

    private static func encode(_ record: FoldStageRecord, into writer: inout BinaryWriter) {
        writer.append(record.epoch)
        writer.append(record.stage.rawValue)
        writer.append(record.arity)
        writer.append(record.relationConstraintCount)
        writer.append(record.witnessRingCount)
        writer.append(record.normBefore)
        writer.append(record.normAfter)
    }

    private static func decodeStageRecord(from reader: inout BinaryReader) throws -> FoldStageRecord {
        let epoch = try reader.readUInt64()
        guard let stage = FoldStageKind(rawValue: try reader.readUInt8()) else {
            throw BinaryReader.Error.invalidData
        }
        return FoldStageRecord(
            epoch: epoch,
            stage: stage,
            arity: try reader.readUInt8(),
            relationConstraintCount: try reader.readUInt32(),
            witnessRingCount: try reader.readUInt32(),
            normBefore: try reader.readUInt64(),
            normAfter: try reader.readUInt64()
        )
    }

    static func encode(_ commitment: AjtaiCommitment, into writer: inout BinaryWriter) {
        SealProofCodec.encode(commitment, into: &writer)
    }
}
