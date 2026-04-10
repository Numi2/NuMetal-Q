import Foundation

public protocol NuField: Codable, Hashable, Sendable {
    static var zero: Self { get }
    static var one: Self { get }

    static func + (lhs: Self, rhs: Self) -> Self
    static func - (lhs: Self, rhs: Self) -> Self
    static func * (lhs: Self, rhs: Self) -> Self
    static prefix func - (value: Self) -> Self
}

public protocol NuFieldTranscript: Sendable {
    associatedtype Scalar: NuField

    mutating func absorb(domain: String, scalar: Scalar)
    mutating func absorb(domain: String, scalars: [Scalar])
    mutating func absorb(domain: String, bytes: Data)

    mutating func challengeScalar(domain: String) -> Scalar
    mutating func challengeVector(domain: String, count: Int) -> [Scalar]
}

public protocol NuSealableCCSShape: Sendable {
    associatedtype Scalar: NuField
    associatedtype Polynomial: Sendable

    var matrixCount: Int { get }
    var rowVariableCount: Int { get }
    var witnessVariableCount: Int { get }
    var publicInputCount: Int { get }
    var maxRelationDegree: Int { get }

    func makeWitnessPolynomial(from witness: [Scalar]) throws -> Polynomial

    func makeRowEvaluationPolynomial(
        matrix index: Int,
        publicInput: [Scalar],
        witness: [Scalar],
        witnessPolynomial: Polynomial
    ) throws -> Polynomial

    func evaluate(_ polynomial: Polynomial, at point: [Scalar]) throws -> Scalar

    func publicContribution(
        ofMatrix index: Int,
        publicInput: [Scalar],
        atRowPoint rowPoint: [Scalar]
    ) throws -> Scalar

    func matrixValue(
        ofMatrix index: Int,
        rowPoint: [Scalar],
        columnPoint: [Scalar]
    ) throws -> Scalar

    func rowConstraint(rowEvaluations: [Scalar]) throws -> Scalar

    func blindPolynomial(
        _ polynomial: Polynomial,
        for oracle: SpartanOracleID,
        randomness: [UInt8]
    ) throws -> (blinded: Polynomial, blinding: Polynomial)
}

public protocol NuMultilinearPCS: Sendable {
    associatedtype Scalar: NuField
    associatedtype Polynomial: Sendable
    associatedtype Commitment: Codable & Hashable & Sendable
    associatedtype BatchOpeningProof: Codable & Sendable

    func commit(label: SpartanOracleID, polynomial: Polynomial) throws -> Commitment

    func openBatch<T: NuFieldTranscript>(
        polynomials: [SpartanOracleID: Polynomial],
        commitments: [SpartanOracleID: Commitment],
        queries: [SpartanPCSQuery<Scalar>],
        transcript: inout T
    ) throws -> BatchOpeningProof where T.Scalar == Scalar

    func verifyBatch<T: NuFieldTranscript>(
        commitments: [SpartanOracleID: Commitment],
        queries: [SpartanPCSQuery<Scalar>],
        proof: BatchOpeningProof,
        transcript: inout T
    ) throws -> Bool where T.Scalar == Scalar
}

public protocol NuSumcheckEngine: Sendable {
    associatedtype Scalar: NuField
    associatedtype Proof: Codable & Sendable

    func prove<T: NuFieldTranscript>(
        variableCount: Int,
        degreeBound: Int,
        claimedSum: Scalar,
        transcript: inout T,
        evaluator: @escaping ([Scalar]) throws -> Scalar
    ) throws -> (proof: Proof, finalPoint: [Scalar], finalValue: Scalar) where T.Scalar == Scalar

    func verify<T: NuFieldTranscript>(
        proof: Proof,
        variableCount: Int,
        degreeBound: Int,
        claimedSum: Scalar,
        transcript: inout T
    ) throws -> (finalPoint: [Scalar], finalValue: Scalar) where T.Scalar == Scalar
}

public enum SpartanPCSBackendID: String, Codable, Sendable {
    case lightningPCS
    case latticePCS
}

public enum SpartanOracleKind: String, Codable, Sendable {
    case witness
    case matrixRowEvaluation
}

public struct SpartanOracleID: Hashable, Codable, Sendable {
    public let kind: SpartanOracleKind
    public let index: Int?

    public init(kind: SpartanOracleKind, index: Int? = nil) {
        self.kind = kind
        self.index = index
    }

    public static func witness() -> SpartanOracleID {
        SpartanOracleID(kind: .witness, index: nil)
    }

    public static func matrixRow(_ index: Int) -> SpartanOracleID {
        SpartanOracleID(kind: .matrixRowEvaluation, index: index)
    }
}

public struct SpartanPCSQuery<Scalar: NuField>: Codable, Hashable, Sendable {
    public let oracle: SpartanOracleID
    public let point: [Scalar]
    public let value: Scalar

    public init(oracle: SpartanOracleID, point: [Scalar], value: Scalar) {
        self.oracle = oracle
        self.point = point
        self.value = value
    }
}

public struct SpartanClaimedEvaluations<Scalar: NuField>: Codable, Hashable, Sendable {
    public let rowPoint: [Scalar]
    public let columnPoint: [Scalar]
    public let matrixRowEvaluations: [Scalar]
    public let witnessEvaluation: Scalar

    public init(
        rowPoint: [Scalar],
        columnPoint: [Scalar],
        matrixRowEvaluations: [Scalar],
        witnessEvaluation: Scalar
    ) {
        self.rowPoint = rowPoint
        self.columnPoint = columnPoint
        self.matrixRowEvaluations = matrixRowEvaluations
        self.witnessEvaluation = witnessEvaluation
    }
}

public struct SpartanBlindingCommitments<
    Commitment: Codable & Hashable & Sendable
>: Codable, Hashable, Sendable {
    public let witness: Commitment
    public let matrixRows: [Commitment]

    public init(witness: Commitment, matrixRows: [Commitment]) {
        self.witness = witness
        self.matrixRows = matrixRows
    }
}

public struct SpartanBlindingEvaluations<Scalar: NuField>: Codable, Hashable, Sendable {
    public let matrixRows: [Scalar]
    public let witness: Scalar

    public init(matrixRows: [Scalar], witness: Scalar) {
        self.matrixRows = matrixRows
        self.witness = witness
    }
}

public struct SpartanProof<
    Scalar: NuField,
    Commitment: Codable & Hashable & Sendable,
    OpeningProof: Codable & Sendable,
    SumcheckProof: Codable & Sendable
>: Codable, Sendable {
    public let witnessCommitment: Commitment
    public let matrixEvaluationCommitments: [Commitment]
    public let blindingCommitments: SpartanBlindingCommitments<Commitment>
    public let outerSumcheck: SumcheckProof
    public let innerSumcheck: SumcheckProof
    public let claimedEvaluations: SpartanClaimedEvaluations<Scalar>
    public let blindingEvaluations: SpartanBlindingEvaluations<Scalar>
    public let pcsOpeningProof: OpeningProof
    public let blindingOpeningProof: OpeningProof

    public init(
        witnessCommitment: Commitment,
        matrixEvaluationCommitments: [Commitment],
        blindingCommitments: SpartanBlindingCommitments<Commitment>,
        outerSumcheck: SumcheckProof,
        innerSumcheck: SumcheckProof,
        claimedEvaluations: SpartanClaimedEvaluations<Scalar>,
        blindingEvaluations: SpartanBlindingEvaluations<Scalar>,
        pcsOpeningProof: OpeningProof,
        blindingOpeningProof: OpeningProof
    ) {
        self.witnessCommitment = witnessCommitment
        self.matrixEvaluationCommitments = matrixEvaluationCommitments
        self.blindingCommitments = blindingCommitments
        self.outerSumcheck = outerSumcheck
        self.innerSumcheck = innerSumcheck
        self.claimedEvaluations = claimedEvaluations
        self.blindingEvaluations = blindingEvaluations
        self.pcsOpeningProof = pcsOpeningProof
        self.blindingOpeningProof = blindingOpeningProof
    }
}

public struct SpartanSumcheckProof: Codable, Sendable, Equatable {
    public let roundEvaluations: [[Fq]]
    public let terminalMask: Fq

    public init(roundEvaluations: [[Fq]], terminalMask: Fq = .zero) {
        self.roundEvaluations = roundEvaluations
        self.terminalMask = terminalMask
    }
}

public struct HachiSealParameters: Sendable, Codable, Equatable {
    public let modulus: UInt64
    public let outerRingDegree: UInt32
    public let innerRingDegree: UInt32
    public let extensionDegree: UInt8
    public let decompositionBase: UInt8
    public let recursivePiDECRepresentabilityCeiling: UInt64

    public init(
        modulus: UInt64,
        outerRingDegree: UInt32,
        innerRingDegree: UInt32,
        extensionDegree: UInt8,
        decompositionBase: UInt8,
        recursivePiDECRepresentabilityCeiling: UInt64
    ) {
        self.modulus = modulus
        self.outerRingDegree = outerRingDegree
        self.innerRingDegree = innerRingDegree
        self.extensionDegree = extensionDegree
        self.decompositionBase = decompositionBase
        self.recursivePiDECRepresentabilityCeiling = recursivePiDECRepresentabilityCeiling
    }

    private enum CodingKeys: String, CodingKey {
        case modulus
        case outerRingDegree
        case innerRingDegree
        case extensionDegree
        case decompositionBase
        case recursivePiDECRepresentabilityCeiling
    }

    private enum LegacyCodingKeys: String, CodingKey {
        case certifiedNormCeiling
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let legacyContainer = try decoder.container(keyedBy: LegacyCodingKeys.self)
        self.modulus = try container.decode(UInt64.self, forKey: .modulus)
        self.outerRingDegree = try container.decode(UInt32.self, forKey: .outerRingDegree)
        self.innerRingDegree = try container.decode(UInt32.self, forKey: .innerRingDegree)
        self.extensionDegree = try container.decode(UInt8.self, forKey: .extensionDegree)
        self.decompositionBase = try container.decode(UInt8.self, forKey: .decompositionBase)
        self.recursivePiDECRepresentabilityCeiling =
            try container.decodeIfPresent(UInt64.self, forKey: .recursivePiDECRepresentabilityCeiling)
            ?? legacyContainer.decode(UInt64.self, forKey: .certifiedNormCeiling)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(modulus, forKey: .modulus)
        try container.encode(outerRingDegree, forKey: .outerRingDegree)
        try container.encode(innerRingDegree, forKey: .innerRingDegree)
        try container.encode(extensionDegree, forKey: .extensionDegree)
        try container.encode(decompositionBase, forKey: .decompositionBase)
        try container.encode(
            recursivePiDECRepresentabilityCeiling,
            forKey: .recursivePiDECRepresentabilityCeiling
        )
    }
}

public struct HachiOuterRound: Sendable, Codable, Equatable {
    public let round: UInt32
    public let witnessRingCount: UInt32
    public let challenge: [UInt8]
    public let layerDigest: [UInt8]
    public let isHandoff: Bool

    public init(
        round: UInt32,
        witnessRingCount: UInt32,
        challenge: [UInt8],
        layerDigest: [UInt8],
        isHandoff: Bool
    ) {
        self.round = round
        self.witnessRingCount = witnessRingCount
        self.challenge = challenge
        self.layerDigest = layerDigest
        self.isHandoff = isHandoff
    }
}

public struct NuDigestBundle: Sendable, Codable, Equatable {
    public let profileDigest: [UInt8]
    public let shapeDigest: [UInt8]
    public let shapeSetDigest: [UInt8]
    public let finalAccumulatorDigest: [UInt8]
    public let canonicalHeaderBytes: [UInt8]
    public let canonicalHeaderDigest: [UInt8]
    public let derivationTreeDigest: [UInt8]
    public let transcriptDigest: [UInt8]
    public let provenanceDigest: [UInt8]

    public init(
        profileDigest: [UInt8],
        shapeDigest: [UInt8],
        shapeSetDigest: [UInt8],
        finalAccumulatorDigest: [UInt8],
        canonicalHeaderBytes: [UInt8],
        canonicalHeaderDigest: [UInt8],
        derivationTreeDigest: [UInt8],
        transcriptDigest: [UInt8],
        provenanceDigest: [UInt8]
    ) {
        self.profileDigest = profileDigest
        self.shapeDigest = shapeDigest
        self.shapeSetDigest = shapeSetDigest
        self.finalAccumulatorDigest = finalAccumulatorDigest
        self.canonicalHeaderBytes = canonicalHeaderBytes
        self.canonicalHeaderDigest = canonicalHeaderDigest
        self.derivationTreeDigest = derivationTreeDigest
        self.transcriptDigest = transcriptDigest
        self.provenanceDigest = provenanceDigest
    }
}

public struct HachiPCSCommitment: Sendable, Codable, Hashable, Equatable {
    public let oracle: SpartanOracleID
    public let mode: HachiPCSCommitmentMode
    public let tableCommitment: AjtaiCommitment
    public let directPackedOuterCommitments: [AjtaiCommitment]
    public let tableDigest: [UInt8]
    public let merkleRoot: [UInt8]
    public let parameterDigest: [UInt8]
    public let valueCount: UInt32
    public let codewordLength: UInt32
    public let packedChunkCount: UInt32
    public let statementDigest: [UInt8]

    public init(
        oracle: SpartanOracleID,
        mode: HachiPCSCommitmentMode = .general,
        tableCommitment: AjtaiCommitment,
        directPackedOuterCommitments: [AjtaiCommitment] = [],
        tableDigest: [UInt8],
        merkleRoot: [UInt8],
        parameterDigest: [UInt8],
        valueCount: UInt32,
        codewordLength: UInt32,
        packedChunkCount: UInt32 = 0,
        statementDigest: [UInt8] = []
    ) {
        self.oracle = oracle
        self.mode = mode
        self.tableCommitment = tableCommitment
        self.directPackedOuterCommitments = directPackedOuterCommitments
        self.tableDigest = tableDigest
        self.merkleRoot = merkleRoot
        self.parameterDigest = parameterDigest
        self.valueCount = valueCount
        self.codewordLength = codewordLength
        self.packedChunkCount = packedChunkCount
        self.statementDigest = statementDigest
    }
}

public enum HachiPCSCommitmentMode: UInt8, Sendable, Codable, Equatable {
    case directPacked = 1
    case general = 2
}

public enum HachiPCSOpeningMode: UInt8, Sendable, Codable, Equatable {
    case directPacked = 1
    case general = 2
}

public struct ShortLinearWitnessAccumulatorRound: Sendable, Codable, Equatable {
    public let bindingLeft: AjtaiCommitment
    public let bindingRight: AjtaiCommitment
    public let relationLeft: AjtaiCommitment
    public let relationRight: AjtaiCommitment
    public let evaluationLeft: AjtaiCommitment
    public let evaluationRight: AjtaiCommitment
    public let outerLeft: AjtaiCommitment
    public let outerRight: AjtaiCommitment

    public init(
        bindingLeft: AjtaiCommitment,
        bindingRight: AjtaiCommitment,
        relationLeft: AjtaiCommitment,
        relationRight: AjtaiCommitment,
        evaluationLeft: AjtaiCommitment,
        evaluationRight: AjtaiCommitment,
        outerLeft: AjtaiCommitment,
        outerRight: AjtaiCommitment
    ) {
        self.bindingLeft = bindingLeft
        self.bindingRight = bindingRight
        self.relationLeft = relationLeft
        self.relationRight = relationRight
        self.evaluationLeft = evaluationLeft
        self.evaluationRight = evaluationRight
        self.outerLeft = outerLeft
        self.outerRight = outerRight
    }
}

public struct ShortLinearWitnessFinalOpening: Sendable, Codable, Equatable {
    public let bindingMaskCommitment: AjtaiCommitment
    public let relationMaskCommitment: AjtaiCommitment
    public let evaluationMaskCommitment: AjtaiCommitment
    public let outerMaskCommitment: AjtaiCommitment
    public let shortResponses: [RingElement]
    public let outerResponses: [RingElement]

    public init(
        bindingMaskCommitment: AjtaiCommitment,
        relationMaskCommitment: AjtaiCommitment,
        evaluationMaskCommitment: AjtaiCommitment,
        outerMaskCommitment: AjtaiCommitment,
        shortResponses: [RingElement],
        outerResponses: [RingElement]
    ) {
        self.bindingMaskCommitment = bindingMaskCommitment
        self.relationMaskCommitment = relationMaskCommitment
        self.evaluationMaskCommitment = evaluationMaskCommitment
        self.outerMaskCommitment = outerMaskCommitment
        self.shortResponses = shortResponses
        self.outerResponses = outerResponses
    }
}

public struct ShortLinearWitnessProof: Sendable, Codable, Equatable {
    public let initialBindingCommitment: AjtaiCommitment
    public let accumulatorRounds: [ShortLinearWitnessAccumulatorRound]
    public let finalOpening: ShortLinearWitnessFinalOpening
    public let restartNonce: UInt32
    public let transcriptBinding: [UInt8]

    public init(
        initialBindingCommitment: AjtaiCommitment,
        accumulatorRounds: [ShortLinearWitnessAccumulatorRound],
        finalOpening: ShortLinearWitnessFinalOpening,
        restartNonce: UInt32,
        transcriptBinding: [UInt8]
    ) {
        self.initialBindingCommitment = initialBindingCommitment
        self.accumulatorRounds = accumulatorRounds
        self.finalOpening = finalOpening
        self.restartNonce = restartNonce
        self.transcriptBinding = transcriptBinding
    }
}

public struct HachiDirectPackedOpeningProof: Sendable, Codable, Equatable {
    public let packedChunkCount: UInt32
    public let relationProof: ShortLinearWitnessProof

    public init(
        packedChunkCount: UInt32,
        relationProof: ShortLinearWitnessProof
    ) {
        self.packedChunkCount = packedChunkCount
        self.relationProof = relationProof
    }
}

public struct HachiGeneralPCSOpeningProof: Sendable, Codable, Equatable {
    public let codewordIndex: UInt32
    public let codewordValue: Fq
    public let merkleAuthenticationPath: [[UInt8]]

    public init(
        codewordIndex: UInt32,
        codewordValue: Fq,
        merkleAuthenticationPath: [[UInt8]]
    ) {
        self.codewordIndex = codewordIndex
        self.codewordValue = codewordValue
        self.merkleAuthenticationPath = merkleAuthenticationPath
    }
}

public struct HachiPCSOpening: Sendable, Codable, Equatable {
    public let oracle: SpartanOracleID
    public let evaluation: Fq
    public let scheduleDigest: [UInt8]
    public let evaluationDigest: [UInt8]
    public let mode: HachiPCSOpeningMode
    public let directPacked: HachiDirectPackedOpeningProof?
    public let general: HachiGeneralPCSOpeningProof?

    public init(
        oracle: SpartanOracleID,
        evaluation: Fq,
        scheduleDigest: [UInt8],
        evaluationDigest: [UInt8],
        directPacked: HachiDirectPackedOpeningProof
    ) {
        self.oracle = oracle
        self.evaluation = evaluation
        self.scheduleDigest = scheduleDigest
        self.evaluationDigest = evaluationDigest
        self.mode = .directPacked
        self.directPacked = directPacked
        self.general = nil
    }

    public init(
        oracle: SpartanOracleID,
        evaluation: Fq,
        scheduleDigest: [UInt8],
        evaluationDigest: [UInt8],
        general: HachiGeneralPCSOpeningProof
    ) {
        self.oracle = oracle
        self.evaluation = evaluation
        self.scheduleDigest = scheduleDigest
        self.evaluationDigest = evaluationDigest
        self.mode = .general
        self.directPacked = nil
        self.general = general
    }
}

public struct HachiPCSBatchClassOpeningProof: Sendable, Codable, Equatable {
    public let point: [Fq]
    public let pointDigest: [UInt8]
    public let scheduleDigest: [UInt8]
    public let openings: [HachiPCSOpening]

    public init(
        point: [Fq],
        pointDigest: [UInt8],
        scheduleDigest: [UInt8],
        openings: [HachiPCSOpening]
    ) {
        self.point = point
        self.pointDigest = pointDigest
        self.scheduleDigest = scheduleDigest
        self.openings = openings
    }
}

public struct HachiPCSBatchOpeningProof: Sendable, Codable, Equatable {
    public let batchSeedDigest: [UInt8]
    public let classes: [HachiPCSBatchClassOpeningProof]

    public init(
        batchSeedDigest: [UInt8],
        classes: [HachiPCSBatchClassOpeningProof]
    ) {
        self.batchSeedDigest = batchSeedDigest
        self.classes = classes
    }
}

public struct HachiClaimedEvaluations: Sendable, Codable, Equatable {
    public let rowPoint: [Fq]
    public let columnPoint: [Fq]
    public let matrixRowEvaluations: [Fq]
    public let witnessEvaluation: Fq
    public let rowConstraint: Fq

    public init(
        rowPoint: [Fq],
        columnPoint: [Fq],
        matrixRowEvaluations: [Fq],
        witnessEvaluation: Fq,
        rowConstraint: Fq
    ) {
        self.rowPoint = rowPoint
        self.columnPoint = columnPoint
        self.matrixRowEvaluations = matrixRowEvaluations
        self.witnessEvaluation = witnessEvaluation
        self.rowConstraint = rowConstraint
    }
}

public struct HachiSealProof: Sendable, Codable, Equatable {
    public let backendID: String
    public let sealTranscriptID: String
    public let parameters: HachiSealParameters
    public let parameterDigest: [UInt8]
    public let profileDigest: [UInt8]
    public let publicInputs: [Fq]
    public let relaxationFactor: Fq
    public let errorTerms: [RingElement]
    public let canonicalWitness: [RingElement]
    public let provenanceClass: WitnessClass
    public let stageAudit: [FoldStageRecord]
    public let digestBundle: NuDigestBundle
    public let statementDigest: [UInt8]
    public let deciderLayoutDigest: [UInt8]
    public let batchingScheduleDigest: [UInt8]
    public let witnessCommitment: HachiPCSCommitment
    public let matrixEvaluationCommitments: [HachiPCSCommitment]
    public let blindingSeedDigest: [UInt8]
    public let claimedEvaluations: HachiClaimedEvaluations
    public let openingProof: HachiPCSBatchOpeningProof
    public let outerRounds: [HachiOuterRound]

    public init(
        backendID: String,
        sealTranscriptID: String,
        parameters: HachiSealParameters,
        parameterDigest: [UInt8],
        profileDigest: [UInt8],
        publicInputs: [Fq],
        relaxationFactor: Fq,
        errorTerms: [RingElement],
        canonicalWitness: [RingElement],
        provenanceClass: WitnessClass,
        stageAudit: [FoldStageRecord],
        digestBundle: NuDigestBundle,
        statementDigest: [UInt8],
        deciderLayoutDigest: [UInt8],
        batchingScheduleDigest: [UInt8],
        witnessCommitment: HachiPCSCommitment,
        matrixEvaluationCommitments: [HachiPCSCommitment],
        blindingSeedDigest: [UInt8],
        claimedEvaluations: HachiClaimedEvaluations,
        openingProof: HachiPCSBatchOpeningProof,
        outerRounds: [HachiOuterRound]
    ) {
        self.backendID = backendID
        self.sealTranscriptID = sealTranscriptID
        self.parameters = parameters
        self.parameterDigest = parameterDigest
        self.profileDigest = profileDigest
        self.publicInputs = publicInputs
        self.relaxationFactor = relaxationFactor
        self.errorTerms = errorTerms
        self.canonicalWitness = canonicalWitness
        self.provenanceClass = provenanceClass
        self.stageAudit = stageAudit
        self.digestBundle = digestBundle
        self.statementDigest = statementDigest
        self.deciderLayoutDigest = deciderLayoutDigest
        self.batchingScheduleDigest = batchingScheduleDigest
        self.witnessCommitment = witnessCommitment
        self.matrixEvaluationCommitments = matrixEvaluationCommitments
        self.blindingSeedDigest = blindingSeedDigest
        self.claimedEvaluations = claimedEvaluations
        self.openingProof = openingProof
        self.outerRounds = outerRounds
    }
}

public struct SealProof: Sendable, Codable {
    public static let currentVersion: UInt16 = 8

    public let version: UInt16
    public let sealBackendID: String
    public let sealParamDigest: [UInt8]
    public let shapeDigest: ShapeDigest
    public let publicHeader: Data
    public let instanceCount: UInt32
    public let finalAccumulatorCommitment: AjtaiCommitment
    public let finalAccumulatorArtifact: Data
    public let finalAccumulatorDigest: [UInt8]
    public let hachiProof: HachiSealProof

    public var foldedCommitment: AjtaiCommitment { finalAccumulatorCommitment }

    public init(
        sealBackendID: String = NuSealConstants.productionBackendID,
        sealParamDigest: [UInt8],
        shapeDigest: ShapeDigest,
        publicHeader: Data,
        instanceCount: UInt32,
        finalAccumulatorCommitment: AjtaiCommitment,
        finalAccumulatorArtifact: Data,
        finalAccumulatorDigest: [UInt8],
        hachiProof: HachiSealProof
    ) {
        self.version = Self.currentVersion
        self.sealBackendID = sealBackendID
        self.sealParamDigest = sealParamDigest
        self.shapeDigest = shapeDigest
        self.publicHeader = publicHeader
        self.instanceCount = max(1, instanceCount)
        self.finalAccumulatorCommitment = finalAccumulatorCommitment
        self.finalAccumulatorArtifact = finalAccumulatorArtifact
        self.finalAccumulatorDigest = finalAccumulatorDigest
        self.hachiProof = hachiProof
    }

    public init(
        sealBackendID: String = NuSealConstants.productionBackendID,
        sealParamDigest: [UInt8],
        shapeDigest: ShapeDigest,
        publicHeader: Data,
        instanceCount: UInt32,
        foldedCommitment: AjtaiCommitment,
        finalAccumulatorArtifact: Data,
        finalAccumulatorDigest: [UInt8],
        hachiProof: HachiSealProof
    ) {
        self.init(
            sealBackendID: sealBackendID,
            sealParamDigest: sealParamDigest,
            shapeDigest: shapeDigest,
            publicHeader: publicHeader,
            instanceCount: instanceCount,
            finalAccumulatorCommitment: foldedCommitment,
            finalAccumulatorArtifact: finalAccumulatorArtifact,
            finalAccumulatorDigest: finalAccumulatorDigest,
            hachiProof: hachiProof
        )
    }

    public func serialized() throws -> Data {
        throw LegacySealProofError.serializationUnavailable(version: version)
    }

    public func serializedSizeBytes() throws -> Int {
        try serialized().count
    }
}

public enum LegacySealProofError: Error, Sendable, Equatable {
    case serializationUnavailable(version: UInt16)
}

public enum SpartanSealError: Error, Sendable {
    case invalidPublicInput(expected: Int, actual: Int)
    case invalidWitnessLength(expected: Int, actual: Int)
    case invalidMatrixCommitmentCount(expected: Int, actual: Int)
    case invalidBlindingCommitmentCount(expected: Int, actual: Int)
    case relationArityMismatch(expected: Int, actual: Int)
    case invalidBlindingEvaluationCount(expected: Int, actual: Int)
    case invalidOracleBlinding(SpartanOracleID)
    case duplicatePCSQuery(SpartanOracleID)
    case missingPCSOracle(SpartanOracleID)
    case pcsCommitmentMismatch(SpartanOracleID)
    case invalidPCSOpeningCount(expected: Int, actual: Int)
    case invalidPCSBatchSeed
    case invalidPCSBatchClassCount(expected: Int, actual: Int)
    case duplicatePCSBatchClass([Fq])
    case missingPCSBatchClass([Fq])
    case invalidPCSBatchClassPoint
    case invalidPCSBatchSchedule
    case invalidClusterSealResult(SpartanOracleID)
    case invalidSumcheckRoundCount(expected: Int, actual: Int)
    case invalidSumcheckRoundDegree(expected: Int, actual: Int)
    case invalidSumcheckRound
    case invalidSumcheckTerminal
    case invalidSumcheckMask
    case outerPointMismatch
    case innerPointMismatch
    case outerTerminalMismatch
    case innerTerminalMismatch
    case pcsBatchOpeningFailed
    case blindingBatchOpeningFailed
    case serializationFailure
}
