import Foundation

internal struct CCSClaim: Sendable, Codable, Equatable {
    let commitment: AjtaiCommitment
    let publicInputs: [Fq]
    let witnessRingCount: UInt32
    let witnessFieldCount: UInt32
}

internal enum CEClaimKind: UInt8, Sendable, Codable, Equatable {
    case piCCSReduced = 1
    case piRLCFolded = 2
}

internal struct CEClaim: Sendable, Codable, Equatable {
    let kind: CEClaimKind
    let commitment: AjtaiCommitment
    let publicInputs: [Fq]
    let evaluationPoint: [Fq]?
    let matrixEvaluations: [Fq]
    let reductionChallenges: [Fq]?
    let relaxationFactor: Fq
    let errorTerms: [RingElement]
    let transcriptBinding: Data
}

internal enum AccumulatorOpeningKind: UInt8, Sendable, Codable, Equatable {
    case canonical = 1
    case decomposed = 2
}

internal struct AccumulatorOpeningWitness: Sendable, Codable, Equatable {
    let kind: AccumulatorOpeningKind
    let canonicalWitness: [RingElement]?
    let decomposition: PiDEC.Output?
    let decompBase: UInt8
    let decompLimbs: UInt8

    init(canonicalWitness: [RingElement], decompBase: UInt8, decompLimbs: UInt8) {
        self.kind = .canonical
        self.canonicalWitness = canonicalWitness
        self.decomposition = nil
        self.decompBase = decompBase
        self.decompLimbs = decompLimbs
    }

    init(decomposition: PiDEC.Output, decompBase: UInt8, decompLimbs: UInt8) {
        self.kind = .decomposed
        self.canonicalWitness = nil
        self.decomposition = decomposition
        self.decompBase = decompBase
        self.decompLimbs = decompLimbs
    }

    func reconstructedWitness() throws -> [RingElement] {
        switch kind {
        case .canonical:
            guard let canonicalWitness else {
                throw RecursiveAccumulatorError.invalidOpeningWitness
            }
            return canonicalWitness
        case .decomposed:
            guard let decomposition else {
                throw RecursiveAccumulatorError.invalidOpeningWitness
            }
            guard decomposition.decomposedWitness.allSatisfy({ $0.count == Int(decompLimbs) }) else {
                throw RecursiveAccumulatorError.invalidOpeningWitness
            }
            return decomposition.decomposedWitness.map { limbs in
                Decomposition(limbs: limbs, base: UInt64(decompBase)).reconstruct()
            }
        }
    }

    var witnessRingCount: UInt32 {
        switch kind {
        case .canonical:
            UInt32(clamping: canonicalWitness?.count ?? 0)
        case .decomposed:
            UInt32(clamping: decomposition?.decomposedWitness.count ?? 0)
        }
    }
}

internal struct SeedAccumulatorData: Sendable, Codable, Equatable {
    let sourceClaim: CCSClaim
    let reducedClaim: CEClaim
    let proof: PiCCS.Output
    let openingWitness: AccumulatorOpeningWitness
}

internal struct FoldAccumulatorData: Sendable, Codable, Equatable {
    let childAccumulators: [FoldAccumulator]
    let foldedClaim: CEClaim
    let piRLCProof: PiRLC.Output
    let openingWitness: AccumulatorOpeningWitness
}

internal enum FoldAccumulatorNodeKind: UInt8, Sendable, Codable, Equatable {
    case seed = 1
    case fold = 2
}

internal struct FoldAccumulator: Sendable, Codable, Equatable {
    static let currentVersion: UInt16 = 4

    let version: UInt16
    let epoch: UInt64
    let arity: UInt32
    let statementCount: UInt32
    let nodeKind: FoldAccumulatorNodeKind
    let seed: SeedAccumulatorData?
    let fold: FoldAccumulatorData?

    init(
        epoch: UInt64,
        arity: UInt32,
        statementCount: UInt32,
        seed: SeedAccumulatorData
    ) {
        self.version = Self.currentVersion
        self.epoch = epoch
        self.arity = arity
        self.statementCount = statementCount
        self.nodeKind = .seed
        self.seed = seed
        self.fold = nil
    }

    init(
        epoch: UInt64,
        arity: UInt32,
        statementCount: UInt32,
        fold: FoldAccumulatorData
    ) {
        self.version = Self.currentVersion
        self.epoch = epoch
        self.arity = arity
        self.statementCount = statementCount
        self.nodeKind = .fold
        self.seed = nil
        self.fold = fold
    }

    var currentClaim: CEClaim {
        switch nodeKind {
        case .seed:
            seed!.reducedClaim
        case .fold:
            fold!.foldedClaim
        }
    }

    var currentCommitment: AjtaiCommitment { currentClaim.commitment }
    var currentPublicInputs: [Fq] { currentClaim.publicInputs }

    func currentWitness() throws -> [RingElement] {
        switch nodeKind {
        case .seed:
            guard let seed else { throw RecursiveAccumulatorError.invalidNodeShape }
            return try seed.openingWitness.reconstructedWitness()
        case .fold:
            guard let fold else { throw RecursiveAccumulatorError.invalidNodeShape }
            return try fold.openingWitness.reconstructedWitness()
        }
    }

    func leafPublicInputs() -> [Fq] {
        switch nodeKind {
        case .seed:
            seed?.sourceClaim.publicInputs ?? []
        case .fold:
            fold?.childAccumulators.flatMap { $0.leafPublicInputs() } ?? []
        }
    }

    func leafWitnessFieldVector() throws -> [Fq] {
        switch nodeKind {
        case .seed:
            guard let seed else {
                throw RecursiveAccumulatorError.invalidNodeShape
            }
            let canonicalWitness = try seed.openingWitness.reconstructedWitness()
            return WitnessPacking.unpackFieldVector(
                from: canonicalWitness,
                originalLength: Int(seed.sourceClaim.witnessFieldCount)
            )
        case .fold:
            guard let fold else {
                throw RecursiveAccumulatorError.invalidNodeShape
            }
            return try fold.childAccumulators.flatMap { try $0.leafWitnessFieldVector() }
        }
    }

    func serialized() throws -> Data {
        try RecursiveAccumulatorCodec.encode(self)
    }

    func digest() throws -> Data {
        try RecursiveAccumulatorCodec.digest(self, domain: .state)
    }

    static func deserialize(_ data: Data) throws -> FoldAccumulator {
        let accumulator = try RecursiveAccumulatorCodec.decode(Self.self, from: data)
        try accumulator.validateProductionInvariants()
        return accumulator
    }

    private func validateProductionInvariants() throws {
        guard version == Self.currentVersion else {
            throw RecursiveAccumulatorError.unsupportedVersion
        }
        guard statementCount > 0 else {
            throw RecursiveAccumulatorError.invalidNodeShape
        }

        switch nodeKind {
        case .seed:
            guard let seed,
                  fold == nil,
                  arity == 1,
                  statementCount == 1,
                  seed.reducedClaim.kind == .piCCSReduced,
                  seed.openingWitness.decompBase == NuProfile.canonical.decompBase,
                  seed.openingWitness.decompLimbs == NuProfile.canonical.decompLimbs,
                  seed.openingWitness.witnessRingCount == seed.sourceClaim.witnessRingCount,
                  seed.sourceClaim.commitment == seed.reducedClaim.commitment,
                  seed.sourceClaim.publicInputs == seed.reducedClaim.publicInputs else {
                throw RecursiveAccumulatorError.invalidNodeShape
            }
        case .fold:
            guard let fold,
                  seed == nil,
                  arity > 1,
                  fold.childAccumulators.count == Int(arity),
                  fold.foldedClaim.kind == .piRLCFolded,
                  fold.openingWitness.decompBase == NuProfile.canonical.decompBase,
                  fold.openingWitness.decompLimbs == NuProfile.canonical.decompLimbs,
                  fold.openingWitness.witnessRingCount == UInt32(clamping: fold.piRLCProof.foldedWitness.count),
                  fold.piRLCProof.ringChallenges.count == fold.childAccumulators.count,
                  statementCount == fold.childAccumulators.reduce(0, { $0 + $1.statementCount }) else {
                throw RecursiveAccumulatorError.invalidNodeShape
            }
            try fold.childAccumulators.forEach { try $0.validateProductionInvariants() }
        }
    }
}

internal enum RecursiveAccumulatorDigestDomain: String {
    case state = "state"
    case piCCSClaim = "piccs-claim"
    case piRLCClaim = "pirlc-claim"
}

internal enum RecursiveAccumulatorCodec {
    static func encode<T: Encodable>(_ value: T) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return try encoder.encode(value)
    }

    static func decode<T: Decodable>(_ type: T.Type, from data: Data) throws -> T {
        let decoder = JSONDecoder()
        return try decoder.decode(type, from: data)
    }

    static func digest<T: Encodable>(
        _ value: T,
        domain: RecursiveAccumulatorDigestDomain
    ) throws -> Data {
        var payload = Data("NuMeQ.RecursiveAccumulator.\(domain.rawValue).v2".utf8)
        payload.append(try encode(value))
        return Data(
            NuSealCShake256.cshake256(
                data: payload,
                domain: "NuMeQ.RecursiveAccumulator.\(domain.rawValue).v2",
                count: 32
            )
        )
    }
}

internal enum RecursiveAccumulatorError: Error, Sendable {
    case invalidNodeShape
    case invalidOpeningWitness
    case unsupportedVersion
}
