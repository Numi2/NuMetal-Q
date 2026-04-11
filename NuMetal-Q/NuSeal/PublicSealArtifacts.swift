import Foundation

public typealias HachiTerminalProof = SpartanProof<
    Fq,
    HachiPCSCommitment,
    HachiPCSBatchOpeningProof,
    SpartanSumcheckProof
>

public struct PublicSealStatement: Sendable, Codable, Equatable {
    public let backendID: String
    public let sealTranscriptID: String
    public let shapeDigest: ShapeDigest
    public let deciderLayoutDigest: [UInt8]
    public let sealParamDigest: [UInt8]
    public let publicHeader: Data
    public let publicInputs: [Fq]

    public init(
        backendID: String,
        sealTranscriptID: String,
        shapeDigest: ShapeDigest,
        deciderLayoutDigest: [UInt8],
        sealParamDigest: [UInt8],
        publicHeader: Data,
        publicInputs: [Fq]
    ) {
        self.backendID = backendID
        self.sealTranscriptID = sealTranscriptID
        self.shapeDigest = shapeDigest
        self.deciderLayoutDigest = deciderLayoutDigest
        self.sealParamDigest = sealParamDigest
        self.publicHeader = publicHeader
        self.publicInputs = publicInputs
    }
}

public struct PublicSealProof: Sendable, Codable {
    public static let currentVersion: UInt16 = 6

    public let version: UInt16
    public let statement: PublicSealStatement
    public let terminalProof: HachiTerminalProof

    public init(
        statement: PublicSealStatement,
        terminalProof: HachiTerminalProof
    ) {
        self.version = Self.currentVersion
        self.statement = statement
        self.terminalProof = terminalProof
    }

    public func serialized() throws -> Data {
        try SealProofCodec.serialize(self)
    }

    public func serializedSizeBytes() throws -> Int {
        try serialized().count
    }
}

public struct NormBudgetSnapshot: Sendable, Codable, Equatable {
    public let bound: UInt64
    public let currentNorm: UInt64
    public let foldsSinceDecomp: UInt32
    public let decompositionInterval: UInt32
    public let decompBase: UInt8
    public let decompLimbs: UInt8

    public init(normBudget: NormBudget) {
        self.bound = normBudget.bound
        self.currentNorm = normBudget.currentNorm
        self.foldsSinceDecomp = normBudget.foldsSinceDecomp
        self.decompositionInterval = normBudget.decompositionInterval
        self.decompBase = normBudget.decompBase
        self.decompLimbs = normBudget.decompLimbs
    }

    internal func materialize() -> NormBudget {
        var budget = NormBudget(
            bound: bound,
            decompBase: decompBase,
            decompLimbs: decompLimbs,
            decompositionInterval: decompositionInterval
        )
        budget.currentNorm = currentNorm
        budget.foldsSinceDecomp = foldsSinceDecomp
        return budget
    }
}

internal struct ResumePayload: Sendable, Codable, Equatable {
    static let currentVersion: UInt16 = 2

    let version: UInt16
    let accumulatorArtifact: Data
    let normBudgetSnapshot: NormBudgetSnapshot
    let provenanceClass: WitnessClass
    let stageAudit: [FoldStageRecord]

    init(
        accumulatorArtifact: Data,
        normBudgetSnapshot: NormBudgetSnapshot,
        provenanceClass: WitnessClass,
        stageAudit: [FoldStageRecord]
    ) {
        self.version = Self.currentVersion
        self.accumulatorArtifact = accumulatorArtifact
        self.normBudgetSnapshot = normBudgetSnapshot
        self.provenanceClass = provenanceClass
        self.stageAudit = stageAudit
    }
}

public struct SealedExport: Sendable {
    public let proofEnvelope: ProofEnvelope
    public let resumeArtifact: ResumeArtifact

    public init(proofEnvelope: ProofEnvelope, resumeArtifact: ResumeArtifact) {
        self.proofEnvelope = proofEnvelope
        self.resumeArtifact = resumeArtifact
    }
}
