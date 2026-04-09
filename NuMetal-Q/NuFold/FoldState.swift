import Foundation

// MARK: - Fold State
// Internal recursive fold state. NEVER exported raw.
// Reblinded on every fold epoch.
// Only persisted inside an encrypted FoldVault.

/// The internal recursive state of a SuperNeo folding computation.
///
/// This is the core accumulator that carries committed CCS instances
/// through the fold chain. It contains:
/// - The running Ajtai commitment
/// - The accumulated witness (in folded form)
/// - Norm budget tracking
/// - The Fiat-Shamir transcript state
/// - Blinding randomness for zero-knowledge
///
/// FoldState is NEVER exposed through any public API.
/// It must be reblinded on every fold epoch and encrypted at rest.
internal struct FoldState: Sendable {
    /// Semantic mode for the persisted recursive state.
    ///
    /// `aggregateStatements` is the public ProofContext contract: the committed
    /// witness and public inputs represent a conjunction of base CCS instances.
    /// `recursiveAccumulator` persists the recursive-stage artifacts together
    /// with the aggregate seal material used by the current SDK boundary.
    /// `typedTrace` is the local MetalFoldProver contract: the commitment binds
    /// the full typed witness trace and local verification replays the step DAG.
    var kind: FoldStateKind

    /// Unique identifier for this fold chain.
    let chainID: UUID

    /// Current epoch (number of folds since creation).
    var epoch: UInt64

    /// Shape digest of the current CCS relation.
    let shapeDigest: ShapeDigest

    /// Running Ajtai commitment to the accumulated witness.
    var commitment: AjtaiCommitment

    /// Canonical witness payload committed by `commitment`.
    ///
    /// For aggregate states this is the concatenation of every leaf witness in
    /// fuse order. For typed traces this is the concatenation of every node's
    /// lowered witness in topological order.
    var accumulatedWitness: [RingElement]

    /// Public inputs bound to the state.
    ///
    /// For aggregate states this is the concatenation of every fused instance's
    /// public inputs. For typed traces this is the root header public input.
    var publicInputs: [Fq]

    /// Number of logical statements represented by this state.
    ///
    /// Aggregate states count fused CCS instances. Typed traces count DAG nodes.
    var statementCount: UInt32

    /// Norm budget for decomposition scheduling.
    var normBudget: NormBudget

    /// Error terms accumulated during folding (for the relaxed CCS check).
    var errorTerms: [RingElement]

    /// Blinding randomness for the current epoch.
    var blindingMask: RingElement

    /// Scalar relaxation factor (u in relaxed CCS).
    var relaxationFactor: Fq

    /// Most restrictive witness class that contributed to this state.
    var maxWitnessClass: WitnessClass

    /// Explicit SuperNeo stage audit trail retained across folds.
    var stageAudit: [FoldStageRecord]

    /// Persisted recursive accumulator artifacts for replay verification.
    var recursiveAccumulator: FoldAccumulator?

    /// Optional typed PCD trace used by `MetalFoldProver`.
    var typedTrace: TypedPcdTrace?

    /// Create a fresh FoldState from a seed computation.
    internal init(
        shapeDigest: ShapeDigest,
        commitment: AjtaiCommitment,
        witness: [RingElement],
        publicInputs: [Fq],
        normBudget: NormBudget,
        maxWitnessClass: WitnessClass
    ) {
        self.kind = .aggregateStatements
        self.chainID = UUID()
        self.epoch = 0
        self.shapeDigest = shapeDigest
        self.commitment = commitment
        self.accumulatedWitness = witness
        self.publicInputs = publicInputs
        self.statementCount = 1
        self.normBudget = normBudget
        self.errorTerms = []
        self.blindingMask = .zero
        self.relaxationFactor = .one
        self.maxWitnessClass = maxWitnessClass
        self.stageAudit = []
        self.recursiveAccumulator = nil
        self.typedTrace = nil
    }

    /// Restores a `FoldState` from encrypted vault bytes (full round-trip).
    internal init(
        kind: FoldStateKind = .aggregateStatements,
        chainID: UUID,
        epoch: UInt64,
        shapeDigest: ShapeDigest,
        commitment: AjtaiCommitment,
        accumulatedWitness: [RingElement],
        publicInputs: [Fq],
        statementCount: UInt32 = 1,
        normBudget: NormBudget,
        errorTerms: [RingElement],
        blindingMask: RingElement,
        relaxationFactor: Fq,
        maxWitnessClass: WitnessClass,
        stageAudit: [FoldStageRecord] = [],
        recursiveAccumulator: FoldAccumulator? = nil,
        typedTrace: TypedPcdTrace? = nil
    ) {
        self.kind = kind
        self.chainID = chainID
        self.epoch = epoch
        self.shapeDigest = shapeDigest
        self.commitment = commitment
        self.accumulatedWitness = accumulatedWitness
        self.publicInputs = publicInputs
        self.statementCount = max(1, statementCount)
        self.normBudget = normBudget
        self.errorTerms = errorTerms
        self.blindingMask = blindingMask
        self.relaxationFactor = relaxationFactor
        self.maxWitnessClass = maxWitnessClass
        self.stageAudit = stageAudit
        self.recursiveAccumulator = recursiveAccumulator
        self.typedTrace = typedTrace
    }

    /// Reblind the state for zero-knowledge.
    /// Called on every fold epoch before any external interaction.
    ///
    /// Samples additive ring noise, updates the accumulated witness and Ajtai
    /// commitment consistently (linear masking), and updates `blindingMask`.
    mutating func reblind(using transcript: inout NuTranscriptField, key: AjtaiKey) {
        let n = accumulatedWitness.count
        var noiseVec = [RingElement]()
        noiseVec.reserveCapacity(n)
        var aggregate = RingElement.zero

        for _ in 0..<n {
            let blindBytes = transcript.squeezeBlinding(count: RingElement.degree * 8)
            var coeffs = [Fq]()
            coeffs.reserveCapacity(RingElement.degree)
            for i in 0..<RingElement.degree {
                let start = i * 8
                let raw = LittleEndianCodec.uint64(from: blindBytes[start..<start + 8])
                coeffs.append(Fq(raw % Fq.modulus))
            }
            let noise = RingElement(coeffs: coeffs)
            noiseVec.append(noise)
            aggregate += noise
        }

        let noiseCommitment = AjtaiCommitter.commit(key: key, witness: noiseVec)
        for i in 0..<n {
            accumulatedWitness[i] += noiseVec[i]
        }
        commitment = AjtaiCommitment(value: commitment.value + noiseCommitment.value)
        blindingMask = aggregate
        epoch += 1
    }

    /// Whether the certified PiDEC cadence requires decomposition before the next fold.
    var requiresScheduledDecomposition: Bool { normBudget.requiresScheduledDecomposition }
}

/// A collection of FoldStates being folded together in a k-ary fold.
struct FoldBatch: Sendable {
    let states: [FoldState]
    let arity: Int

    init(states: [FoldState]) {
        precondition(states.count >= 2)
        self.states = states
        self.arity = states.count
    }
}

public enum FoldStageKind: UInt8, Sendable, Codable, Equatable {
    case piCCS = 1
    case piRLC = 2
    case piDEC = 3
}

public struct FoldStageRecord: Sendable, Codable, Equatable {
    public let epoch: UInt64
    public let stage: FoldStageKind
    public let arity: UInt8
    public let relationConstraintCount: UInt32
    public let witnessRingCount: UInt32
    public let normBefore: UInt64
    public let normAfter: UInt64

    public init(
        epoch: UInt64,
        stage: FoldStageKind,
        arity: UInt8,
        relationConstraintCount: UInt32,
        witnessRingCount: UInt32,
        normBefore: UInt64,
        normAfter: UInt64
    ) {
        self.epoch = epoch
        self.stage = stage
        self.arity = arity
        self.relationConstraintCount = relationConstraintCount
        self.witnessRingCount = witnessRingCount
        self.normBefore = normBefore
        self.normAfter = normAfter
    }
}

internal enum FoldStateKind: UInt8, Sendable, Codable, Equatable {
    case aggregateStatements = 1
    case typedTrace = 2
    case recursiveAccumulator = 3
}

internal enum TypedPcdNodeKind: UInt8, Sendable, Codable, Equatable {
    case seed = 1
    case fuse = 2
}

internal struct TypedPcdNode: Sendable, Codable, Equatable {
    let kind: TypedPcdNodeKind
    let stepID: String
    let witness: Witness
    let publicInputs: [Fq]
    let headerBytes: Data
    let childIndices: [UInt32]
}

internal struct TypedPcdTrace: Sendable, Codable, Equatable {
    let nodes: [TypedPcdNode]
    let rootIndex: UInt32
}
