import Foundation

public enum SealProofCodec {
    private static let magic = Data("NuSealZK".utf8)

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
        writer.append(statement.instanceCount)
        encode(statement.finalAccumulatorCommitment, into: &writer)
        encode(statement.publicInputs, into: &writer)
        encode(statement.relaxationFactor, into: &writer)
        encode(statement.errorTerms, into: &writer)
    }

    private static func decodeStatement(from reader: inout BinaryReader) throws -> PublicSealStatement {
        PublicSealStatement(
            backendID: try decodeString(from: &reader),
            sealTranscriptID: try decodeString(from: &reader),
            shapeDigest: try decodeShapeDigest(from: &reader),
            deciderLayoutDigest: try reader.readLengthPrefixedBytes(),
            sealParamDigest: try reader.readLengthPrefixedBytes(),
            publicHeader: try reader.readLengthPrefixedData(),
            instanceCount: try reader.readUInt32(),
            finalAccumulatorCommitment: try decodeCommitment(from: &reader),
            publicInputs: try decodeFqArray(from: &reader),
            relaxationFactor: try decodeFq(from: &reader),
            errorTerms: try decodeRingArray(from: &reader)
        )
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
        var rounds = [[Fq]]()
        rounds.reserveCapacity(roundCount)
        for _ in 0..<roundCount {
            rounds.append(try decodeFqArray(from: &reader))
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
            rowPoint: try decodeFqArray(from: &reader),
            columnPoint: try decodeFqArray(from: &reader),
            matrixRowEvaluations: try decodeFqArray(from: &reader),
            witnessEvaluation: try decodeFq(from: &reader)
        )
    }

    private static func encode(_ evaluations: SpartanBlindingEvaluations<Fq>, into writer: inout BinaryWriter) {
        encode(evaluations.matrixRows, into: &writer)
        encode(evaluations.witness, into: &writer)
    }

    private static func decodeBlindingEvaluations(from reader: inout BinaryReader) throws -> SpartanBlindingEvaluations<Fq> {
        SpartanBlindingEvaluations(
            matrixRows: try decodeFqArray(from: &reader),
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
        let batchSeedDigest = try reader.readLengthPrefixedBytes()
        let classCount = Int(try reader.readUInt32())
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
        let point = try decodeFqArray(from: &reader)
        let pointDigest = try reader.readLengthPrefixedBytes()
        let scheduleDigest = try reader.readLengthPrefixedBytes()
        let openingCount = Int(try reader.readUInt32())
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
        writer.append(opening.codewordIndex)
        encode(opening.codewordValue, into: &writer)
        writer.append(UInt32(clamping: opening.merkleAuthenticationPath.count))
        for node in opening.merkleAuthenticationPath {
            writer.appendLengthPrefixed(node)
        }
    }

    private static func decodeOpening(from reader: inout BinaryReader) throws -> HachiPCSOpening {
        let oracle = try decodeOracleID(from: &reader)
        let evaluation = try decodeFq(from: &reader)
        let scheduleDigest = try reader.readLengthPrefixedBytes()
        let evaluationDigest = try reader.readLengthPrefixedBytes()
        let codewordIndex = try reader.readUInt32()
        let codewordValue = try decodeFq(from: &reader)
        let pathCount = Int(try reader.readUInt32())
        var path = [[UInt8]]()
        path.reserveCapacity(pathCount)
        for _ in 0..<pathCount {
            path.append(try reader.readLengthPrefixedBytes())
        }
        return HachiPCSOpening(
            oracle: oracle,
            evaluation: evaluation,
            scheduleDigest: scheduleDigest,
            evaluationDigest: evaluationDigest,
            codewordIndex: codewordIndex,
            codewordValue: codewordValue,
            merkleAuthenticationPath: path
        )
    }

    private static func encode(_ commitment: HachiPCSCommitment, into writer: inout BinaryWriter) {
        encode(commitment.oracle, into: &writer)
        encode(commitment.tableCommitment, into: &writer)
        writer.appendLengthPrefixed(commitment.tableDigest)
        writer.appendLengthPrefixed(commitment.merkleRoot)
        writer.appendLengthPrefixed(commitment.parameterDigest)
        writer.append(commitment.valueCount)
        writer.append(commitment.codewordLength)
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
            tableCommitment: try decodeCommitment(from: &reader),
            tableDigest: try reader.readLengthPrefixedBytes(),
            merkleRoot: try reader.readLengthPrefixedBytes(),
            parameterDigest: try reader.readLengthPrefixedBytes(),
            valueCount: try reader.readUInt32(),
            codewordLength: try reader.readUInt32()
        )
    }

    private static func decodeHachiCommitmentArray(from reader: inout BinaryReader) throws -> [HachiPCSCommitment] {
        let count = Int(try reader.readUInt32())
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

    private static func decodeString(from reader: inout BinaryReader) throws -> String {
        let data = try reader.readLengthPrefixedData()
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

    static func decodeFqArray(from reader: inout BinaryReader) throws -> [Fq] {
        let count = Int(try reader.readUInt32())
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

    static func decodeRingArray(from reader: inout BinaryReader) throws -> [RingElement] {
        let count = Int(try reader.readUInt32())
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
        let accumulatorArtifact = try reader.readLengthPrefixedData()
        let normBudgetSnapshot = try decodeNormBudgetSnapshot(from: &reader)
        guard let provenanceClass = WitnessClass(rawValue: try reader.readUInt8()) else {
            throw BinaryReader.Error.invalidData
        }
        let stageAuditCount = Int(try reader.readUInt32())
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
