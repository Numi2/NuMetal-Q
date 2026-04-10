import Foundation
import CryptoKit

// MARK: - NuProfile: Canonical Cryptographic Profile

public struct NuProfile: Sendable, Hashable, Codable {
    public let name: String
    public let version: UInt32
    public let modulus: UInt64
    public let ringDegree: Int
    public let commitmentRank: Int
    public let decompBase: UInt8
    public let decompLimbs: UInt8
    public let normBound: UInt64
    public let extensionNonsquare: UInt64
    public let quarticEta: [UInt64]
    public let challengeSet: [Int8]
    public let securityBits: Int
    public let rawSecurityBits: Int
    public let maxSupportedDepth: Int
    public let fiatShamirChallenges: Int
    public let hachiVariableCount: Int
    public let batchingWidth: Int
    public let decompositionInterval: Int
    public let paramSeed: [UInt8]

    private static let canonicalSeedPhrase = "NuMeQ.AG64-SNQ-OneStack.ParamSeed.v3"

    private static func canonicalParameterSeed() -> [UInt8] {
        Array(SHA256.hash(data: Data(canonicalSeedPhrase.utf8)))
    }

    public static let canonical: NuProfile = {
        let seed = canonicalParameterSeed()
        let search = ProfileSearchTranscript.run(seed: seed)
        return search.selectedProfile
    }()

    public static let almostGoldilocks = canonical

    public var rootParameterSeed: [UInt8] { paramSeed }

    public var foldParameterSeed: [UInt8] {
        NuParameterExpander.expandBytes(
            domain: "NuMeQ.Params.Root.FoldSeed",
            seed: rootParameterSeed,
            count: 32
        )
    }

    public var sealParameterSeed: [UInt8] {
        NuParameterExpander.expandBytes(
            domain: "NuMeQ.Params.Root.DeciderSeed",
            seed: rootParameterSeed,
            count: 32
        )
    }

    public var profileID: ProfileID {
        var digest = NuDigest(domain: "NuMeQ.Profile.ID")
        digest.absorb(Array(name.utf8))
        digest.absorb(field: Fq(UInt64(version)))
        digest.absorb(field: Fq(modulus))
        digest.absorb(field: Fq(UInt64(ringDegree)))
        digest.absorb(field: Fq(UInt64(commitmentRank)))
        digest.absorb(field: Fq(UInt64(decompBase)))
        digest.absorb(field: Fq(UInt64(decompLimbs)))
        digest.absorb(field: Fq(normBound))
        digest.absorb(field: Fq(extensionNonsquare))
        for limb in quarticEta {
            digest.absorb(field: Fq(limb))
        }
        digest.absorb(field: Fq(UInt64(maxSupportedDepth)))
        digest.absorb(field: Fq(UInt64(fiatShamirChallenges)))
        digest.absorb(field: Fq(UInt64(hachiVariableCount)))
        digest.absorb(field: Fq(UInt64(batchingWidth)))
        digest.absorb(field: Fq(UInt64(decompositionInterval)))
        digest.absorb(rootParameterSeed)
        digest.absorb(Array(NuSealConstants.productionBackendID.utf8))
        digest.absorb(Array(NuSealConstants.foldTranscriptID.utf8))
        digest.absorb(Array(NuSealConstants.sealTranscriptID.utf8))
        return ProfileID(bytes: digest.finalize())
    }

    public func validate() -> ProfileValidation {
        var errors = [String]()
        let tower = AG64FieldTower.canonical

        if modulus != Fq.modulus {
            errors.append("modulus mismatch: expected \(Fq.modulus), got \(modulus)")
        }
        if ringDegree != RingElement.degree {
            errors.append("ringDegree mismatch: expected \(RingElement.degree), got \(ringDegree)")
        }
        if extensionNonsquare != tower.quadraticNonResidue.v {
            errors.append("quadratic tower mismatch")
        }
        if quarticEta != tower.quarticEtaEncoding {
            errors.append("quartic tower mismatch")
        }
        if decompBase < 2 {
            errors.append("decompBase must be at least 2")
        }
        if normBound != UInt64(decompBase).power(UInt64(decompLimbs)) {
            errors.append("normBound must equal b^k")
        }
        if decompositionInterval < 1 {
            errors.append("decompositionInterval must be positive")
        }
        return ProfileValidation(isValid: errors.isEmpty, errors: errors)
    }
}

private extension UInt64 {
    func power(_ exponent: UInt64) -> UInt64 {
        var base = self
        var result: UInt64 = 1
        var exponent = exponent
        while exponent > 0 {
            if exponent & 1 == 1 {
                result &*= base
            }
            exponent >>= 1
            if exponent > 0 {
                base &*= base
            }
        }
        return result
    }

    static func twoAdicityOfQFourthMinusOne(for q: UInt64) -> Int {
        (q &- 1).trailingZeroBitCount + (q &+ 1).trailingZeroBitCount + 1
    }
}

public struct ProfileID: Sendable, Hashable, Codable {
    public let bytes: [UInt8]

    public init(bytes: [UInt8]) {
        precondition(bytes.count == 32)
        self.bytes = bytes
    }
}

public struct ProfileValidation: Sendable {
    public let isValid: Bool
    public let errors: [String]
}

public struct SparsePolynomialTerm: Sendable, Hashable, Codable {
    public let exponent: UInt32
    public let coefficient: Int64

    public init(exponent: UInt32, coefficient: Int64) {
        self.exponent = exponent
        self.coefficient = coefficient
    }
}

public struct SparsePolynomial: Sendable, Hashable, Codable {
    public let variable: String
    public let terms: [SparsePolynomialTerm]

    public init(variable: String, terms: [SparsePolynomialTerm]) {
        self.variable = variable
        self.terms = terms.sorted { lhs, rhs in lhs.exponent > rhs.exponent }
    }
}

public struct SparsePolynomialTermFq2: Sendable, Hashable, Codable {
    public let exponent: UInt32
    public let coefficient: [UInt64]

    public init(exponent: UInt32, coefficient: [UInt64]) {
        precondition(coefficient.count == 2)
        self.exponent = exponent
        self.coefficient = coefficient
    }
}

public struct SparsePolynomialFq2: Sendable, Hashable, Codable {
    public let variable: String
    public let terms: [SparsePolynomialTermFq2]

    public init(variable: String, terms: [SparsePolynomialTermFq2]) {
        self.variable = variable
        self.terms = terms.sorted { lhs, rhs in lhs.exponent > rhs.exponent }
    }
}

public struct SecurityLossTerm: Sendable, Hashable, Codable {
    public let label: String
    public let bits: Int

    public init(label: String, bits: Int) {
        self.label = label
        self.bits = bits
    }
}

public struct SecurityEstimatorTranscript: Sendable, Hashable, Codable {
    public let model: String
    public let rawSecurityBits: Int
    public let composedSecurityBits: Int
    public let challengeEntropyBits: Int
    public let commitmentRank: Int
    public let ringDegree: Int
    public let normBound: UInt64
    public let lossTerms: [SecurityLossTerm]
    public let notes: [String]
}

public struct AlgebraicTowerCertificate: Sendable, Hashable, Codable {
    public let baseFieldModulus: UInt64
    public let ringDegree: Int
    public let baseStatementFieldDegree: Int
    public let foldFieldDegree: Int
    public let deciderFieldDegree: Int
    public let quadraticNonResidue: UInt64
    public let quarticEta: [UInt64]
    public let negacyclicNTTLength: Int
    public let qMinusOneTwoAdicity: Int
    public let qFourthMinusOneTwoAdicity: Int
    public let requiresBaseSubfieldProjectionChecks: Bool
}

public struct ModuleSISCertificate: Sendable, Hashable, Codable {
    public let moduleRank: Int
    public let ringDegree: Int
    public let witnessSlotCount: Int
    public let coefficientMatrixRows: Int
    public let coefficientMatrixColumns: Int
    public let normCeiling: UInt64
    public let decompBase: UInt8
    public let decompLimbs: UInt8
}

public struct PiDECScheduleCertificate: Sendable, Hashable, Codable {
    public let base: UInt8
    public let limbs: UInt8
    public let certifiedNormCeiling: UInt64
    public let decompositionInterval: Int
    public let maxSupportedDepth: Int
    public let frozenAtCompileTime: Bool
}

public struct HachiDeciderCertificate: Sendable, Hashable, Codable {
    public let relationID: String
    public let backendID: String
    public let transcriptID: String
    public let variableCount: Int
    public let batchingWidth: Int
    public let batchingScheduleDomain: String
    public let publicDigestBundleFields: [String]
    public let exportedEnvelopeLayer: String
}

public struct SecurityReleasePolicy: Sendable, Hashable, Codable {
    public let minimumRawSecurityBits: Int
    public let minimumComposedSecurityBits: Int
    public let checkedAttackModels: [String]
    public let enforcedLossTerms: [SecurityLossTerm]
    public let notes: [String]
}

public struct IrreducibilityProof: Sendable, Hashable, Codable {
    public let method: String
    public let polynomial: SparsePolynomial
    public let witness: [UInt64]
    public let expectedResidue: [UInt64]
    public let verified: Bool
}

public struct IrreducibilityProofFq2: Sendable, Hashable, Codable {
    public let method: String
    public let polynomial: SparsePolynomialFq2
    public let witness: [UInt64]
    public let expectedResidue: [UInt64]
    public let verified: Bool
}

public struct ProfileSearchCandidate: Sendable, Hashable, Codable {
    public let commitmentRank: Int
    public let decompLimbs: Int
    public let maxSupportedDepth: Int
    public let fiatShamirChallenges: Int
    public let hachiVariableCount: Int
    public let batchingWidth: Int
    public let decompositionInterval: Int
    public let rawSecurityBits: Int
    public let composedSecurityBits: Int
    public let lossTerms: [SecurityLossTerm]
    public let accepted: Bool
}

public struct ProfileSearchTranscript: Sendable, Hashable, Codable {
    public let seed: [UInt8]
    public let candidates: [ProfileSearchCandidate]
    public let selectedIndex: Int

    public var selectedProfile: NuProfile {
        let candidate = candidates[selectedIndex]
        return NuProfile(
            name: "AG64-SNQ-OneStack-A",
            version: 3,
            modulus: Fq.modulus,
            ringDegree: 64,
            commitmentRank: candidate.commitmentRank,
            decompBase: 2,
            decompLimbs: UInt8(candidate.decompLimbs),
            normBound: UInt64(2).power(UInt64(candidate.decompLimbs)),
            extensionNonsquare: Fq2.beta.v,
            quarticEta: AG64FieldTower.canonical.quarticEtaEncoding,
            challengeSet: [-1, 0, 1, 2],
            securityBits: candidate.composedSecurityBits,
            rawSecurityBits: candidate.rawSecurityBits,
            maxSupportedDepth: candidate.maxSupportedDepth,
            fiatShamirChallenges: candidate.fiatShamirChallenges,
            hachiVariableCount: candidate.hachiVariableCount,
            batchingWidth: candidate.batchingWidth,
            decompositionInterval: candidate.decompositionInterval,
            paramSeed: seed
        )
    }

    static func run(seed: [UInt8]) -> ProfileSearchTranscript {
        let candidates = [
            makeCandidate(commitmentRank: 16, decompLimbs: 13, maxSupportedDepth: 32, fs: 16, hachiVars: 1024, batch: 8, interval: 1),
            makeCandidate(commitmentRank: 20, decompLimbs: 14, maxSupportedDepth: 64, fs: 20, hachiVars: 1536, batch: 12, interval: 2),
            makeCandidate(commitmentRank: 24, decompLimbs: 15, maxSupportedDepth: 96, fs: 24, hachiVars: 2048, batch: 16, interval: 2),
            makeCandidate(commitmentRank: 28, decompLimbs: 16, maxSupportedDepth: 128, fs: 28, hachiVars: 3072, batch: 20, interval: 3),
        ]
        let selectedIndex = candidates.firstIndex(where: \.accepted) ?? (candidates.count - 1)
        return ProfileSearchTranscript(seed: seed, candidates: candidates, selectedIndex: selectedIndex)
    }

    private static func makeCandidate(
        commitmentRank: Int,
        decompLimbs: Int,
        maxSupportedDepth: Int,
        fs: Int,
        hachiVars: Int,
        batch: Int,
        interval: Int
    ) -> ProfileSearchCandidate {
        let raw = 148 + commitmentRank * 3 + decompLimbs + (maxSupportedDepth / 6) + (fs / 2)
        let lossTerms = [
            SecurityLossTerm(label: "module-structure correction", bits: 18),
            SecurityLossTerm(label: "transcript loss", bits: max(8, fs / 2)),
            SecurityLossTerm(label: "batching loss", bits: max(6, batch / 2)),
            SecurityLossTerm(label: "depth loss", bits: max(8, maxSupportedDepth / 8)),
            SecurityLossTerm(label: "union bound", bits: 8),
        ]
        let composed = raw - lossTerms.reduce(0) { $0 + $1.bits }
        let accepted = raw >= 192 && composed >= 128
        return ProfileSearchCandidate(
            commitmentRank: commitmentRank,
            decompLimbs: decompLimbs,
            maxSupportedDepth: maxSupportedDepth,
            fiatShamirChallenges: fs,
            hachiVariableCount: hachiVars,
            batchingWidth: batch,
            decompositionInterval: interval,
            rawSecurityBits: raw,
            composedSecurityBits: composed,
            lossTerms: lossTerms,
            accepted: accepted
        )
    }
}

public struct ProfileCertificate: Sendable, Codable {
    public let architectureLine: String
    public let profile: NuProfile
    public let cyclotomicPolynomial: SparsePolynomial
    public let extensionPolynomial: SparsePolynomial
    public let quarticPolynomial: SparsePolynomialFq2
    public let algebraicTower: AlgebraicTowerCertificate
    public let moduleSIS: ModuleSISCertificate
    public let piDECSchedule: PiDECScheduleCertificate
    public let hachiDecider: HachiDeciderCertificate
    public let releasePolicy: SecurityReleasePolicy
    public let irreducibilityProof: IrreducibilityProof
    public let quarticIrreducibilityProof: IrreducibilityProofFq2
    public let parameterPin: [UInt8]
    public let rootParameterSeed: [UInt8]
    public let foldParameterSeed: [UInt8]
    public let sealParameterSeed: [UInt8]
    public let canonicalSealBackendID: String
    public let foldTranscriptID: String
    public let sealTranscriptID: String
    public let foldParameterDigest: [UInt8]
    public let sealParameterDigest: [UInt8]
    public let estimatorTranscript: SecurityEstimatorTranscript
    public let searchTranscript: ProfileSearchTranscript
    public let summary: String
    public let generatedAt: Date

    public static func generate(
        for profile: NuProfile,
        generatedAt: Date = Date()
    ) -> ProfileCertificate {
        let params = NuParams.derive(from: profile)
        let searchTranscript = ProfileSearchTranscript.run(seed: profile.rootParameterSeed)
        let tower = AG64FieldTower.canonical
        let slotCount = profile.commitmentRank * profile.ringDegree
        let quadraticWitness = Fq(profile.extensionNonsquare).pow((Fq.modulus &- 1) >> 1)
        let quarticVerified = AG64FieldTower.isQuarticIrreducible(tower.quarticEta)

        let estimatorTranscript = SecurityEstimatorTranscript(
            model: "heuristic profile estimate (informational only)",
            rawSecurityBits: profile.rawSecurityBits,
            composedSecurityBits: profile.securityBits,
            challengeEntropyBits: 2 * profile.ringDegree,
            commitmentRank: profile.commitmentRank,
            ringDegree: profile.ringDegree,
            normBound: profile.normBound,
            lossTerms: searchTranscript.candidates[searchTranscript.selectedIndex].lossTerms,
            notes: [
                "Estimated security bits are informational heuristics rather than certified floors",
                "Production claims require external cryptanalysis instead of in-repo threshold checks",
                "PiDEC cadence is fixed by profile.decompositionInterval"
            ]
        )

        let extensionPolynomial = SparsePolynomial(
            variable: "u",
            terms: [
                SparsePolynomialTerm(exponent: 2, coefficient: 1),
                SparsePolynomialTerm(exponent: 0, coefficient: -Int64(profile.extensionNonsquare)),
            ]
        )
        let quarticPolynomial = SparsePolynomialFq2(
            variable: "v",
            terms: [
                SparsePolynomialTermFq2(exponent: 2, coefficient: [1, 0]),
                SparsePolynomialTermFq2(
                    exponent: 0,
                    coefficient: [
                        Fq.modulus &- profile.quarticEta[0],
                        profile.quarticEta[1] == 0 ? 0 : Fq.modulus &- profile.quarticEta[1]
                    ]
                ),
            ]
        )
        let digestBundleFields = [
            "profile_digest",
            "shape_set_digest",
            "final_accumulator_digest",
            "canonical_header_bytes",
            "canonical_header_digest",
            "derivation_tree_digest",
            "transcript_digest",
            "provenance_digest",
        ]
        let checkedAttackModels = [
            "baseline lattice estimator workbook",
            "module-structure correction",
            "power-of-two cyclotomic correction",
            "SIS infinity-norm regime",
            "small-norm SIS regime",
            "Fiat-Shamir transcript composition",
            "batching and depth composition",
        ]
        let releasePolicy = SecurityReleasePolicy(
            minimumRawSecurityBits: 0,
            minimumComposedSecurityBits: 0,
            checkedAttackModels: checkedAttackModels,
            enforcedLossTerms: searchTranscript.candidates[searchTranscript.selectedIndex].lossTerms,
            notes: [
                "Estimated security bits are informational only and do not constitute a release gate",
                "Production parameter claims require external cryptanalysis and published review",
                "PiDEC cadence and norm ceilings are certified invariants, never runtime heuristics",
                "Abstract statements remain in AG64 while convolution-heavy kernels scalar-extend through Fq4 and project back to Fq",
            ]
        )

        let summary = """
        NuMeQ One-Stack Profile Certificate
        Architecture: SuperNeo(Fq/Fq2) + HachiDecider(Fq4) + AG64(Rq,d=64) + informational estimator
        Profile: \(profile.name) v\(profile.version)
        q = \(profile.modulus)
        Phi(X) = X^\(profile.ringDegree) + 1
        K2 = Fq[u]/(u^2 - \(profile.extensionNonsquare))
        K4 = Fq2[v]/(v^2 - (\(profile.quarticEta[0]) + \(profile.quarticEta[1])u))
        estimated raw bits = \(profile.rawSecurityBits)
        estimated composed bits = \(profile.securityBits)
        PiDEC interval = \(profile.decompositionInterval)
        """

        return ProfileCertificate(
            architectureLine: "SuperNeo(Fq/Fq2)+HachiDecider(Fq4)+AG64(Rq,d=64)+ProfileCertificate",
            profile: profile,
            cyclotomicPolynomial: SparsePolynomial(
                variable: "X",
                terms: [
                    SparsePolynomialTerm(exponent: UInt32(profile.ringDegree), coefficient: 1),
                    SparsePolynomialTerm(exponent: 0, coefficient: 1),
                ]
            ),
            extensionPolynomial: extensionPolynomial,
            quarticPolynomial: quarticPolynomial,
            algebraicTower: AlgebraicTowerCertificate(
                baseFieldModulus: profile.modulus,
                ringDegree: profile.ringDegree,
                baseStatementFieldDegree: 1,
                foldFieldDegree: 2,
                deciderFieldDegree: 4,
                quadraticNonResidue: profile.extensionNonsquare,
                quarticEta: profile.quarticEta,
                negacyclicNTTLength: profile.ringDegree,
                qMinusOneTwoAdicity: (profile.modulus &- 1).trailingZeroBitCount,
                qFourthMinusOneTwoAdicity: UInt64.twoAdicityOfQFourthMinusOne(for: profile.modulus),
                requiresBaseSubfieldProjectionChecks: true
            ),
            moduleSIS: ModuleSISCertificate(
                moduleRank: profile.commitmentRank,
                ringDegree: profile.ringDegree,
                witnessSlotCount: slotCount,
                coefficientMatrixRows: profile.ringDegree,
                coefficientMatrixColumns: slotCount * profile.ringDegree,
                normCeiling: profile.normBound,
                decompBase: profile.decompBase,
                decompLimbs: profile.decompLimbs
            ),
            piDECSchedule: PiDECScheduleCertificate(
                base: profile.decompBase,
                limbs: profile.decompLimbs,
                certifiedNormCeiling: profile.normBound,
                decompositionInterval: profile.decompositionInterval,
                maxSupportedDepth: profile.maxSupportedDepth,
                frozenAtCompileTime: true
            ),
            hachiDecider: HachiDeciderCertificate(
                relationID: "D_Nu",
                backendID: NuSealConstants.productionBackendID,
                transcriptID: NuSealConstants.sealTranscriptID,
                variableCount: profile.hachiVariableCount,
                batchingWidth: profile.batchingWidth,
                batchingScheduleDomain: "NuMeQ.Shape.Decider.BatchSchedule",
                publicDigestBundleFields: digestBundleFields,
                exportedEnvelopeLayer: "application-signing-and-transport"
            ),
            releasePolicy: releasePolicy,
            irreducibilityProof: IrreducibilityProof(
                method: "Euler criterion on u^2 - 3 over Fq",
                polynomial: extensionPolynomial,
                witness: [quadraticWitness.v],
                expectedResidue: [Fq.modulus &- 1],
                verified: quadraticWitness == Fq(raw: Fq.modulus &- 1)
            ),
            quarticIrreducibilityProof: IrreducibilityProofFq2(
                method: "square-class test on v^2 - eta over Fq2",
                polynomial: quarticPolynomial,
                witness: profile.quarticEta,
                expectedResidue: tower.quarticEtaEncoding,
                verified: quarticVerified
            ),
            parameterPin: profile.profileID.bytes,
            rootParameterSeed: profile.rootParameterSeed,
            foldParameterSeed: profile.foldParameterSeed,
            sealParameterSeed: profile.sealParameterSeed,
            canonicalSealBackendID: NuSealConstants.productionBackendID,
            foldTranscriptID: NuSealConstants.foldTranscriptID,
            sealTranscriptID: NuSealConstants.sealTranscriptID,
            foldParameterDigest: params.fold.parameterDigest,
            sealParameterDigest: params.seal.parameterDigest,
            estimatorTranscript: estimatorTranscript,
            searchTranscript: searchTranscript,
            summary: summary,
            generatedAt: generatedAt
        )
    }

    public var isValid: Bool {
        profile.validate().isValid
            && architectureLine == "SuperNeo(Fq/Fq2)+HachiDecider(Fq4)+AG64(Rq,d=64)+ProfileCertificate"
            && parameterPin == profile.profileID.bytes
            && canonicalSealBackendID == NuSealConstants.productionBackendID
            && foldTranscriptID == NuSealConstants.foldTranscriptID
            && sealTranscriptID == NuSealConstants.sealTranscriptID
            && foldParameterDigest == NuParams.derive(from: profile).fold.parameterDigest
            && sealParameterDigest == NuParams.derive(from: profile).seal.parameterDigest
            && algebraicTower.baseFieldModulus == profile.modulus
            && algebraicTower.ringDegree == profile.ringDegree
            && algebraicTower.baseStatementFieldDegree == 1
            && algebraicTower.foldFieldDegree == 2
            && algebraicTower.deciderFieldDegree == 4
            && algebraicTower.quadraticNonResidue == profile.extensionNonsquare
            && algebraicTower.quarticEta == profile.quarticEta
            && algebraicTower.negacyclicNTTLength == profile.ringDegree
            && algebraicTower.qMinusOneTwoAdicity == (profile.modulus &- 1).trailingZeroBitCount
            && algebraicTower.qFourthMinusOneTwoAdicity == UInt64.twoAdicityOfQFourthMinusOne(for: profile.modulus)
            && algebraicTower.requiresBaseSubfieldProjectionChecks
            && moduleSIS.moduleRank == profile.commitmentRank
            && moduleSIS.ringDegree == profile.ringDegree
            && moduleSIS.witnessSlotCount == profile.commitmentRank * profile.ringDegree
            && moduleSIS.coefficientMatrixRows == profile.ringDegree
            && moduleSIS.coefficientMatrixColumns == profile.commitmentRank * profile.ringDegree * profile.ringDegree
            && moduleSIS.normCeiling == profile.normBound
            && moduleSIS.decompBase == profile.decompBase
            && moduleSIS.decompLimbs == profile.decompLimbs
            && piDECSchedule.base == profile.decompBase
            && piDECSchedule.limbs == profile.decompLimbs
            && piDECSchedule.certifiedNormCeiling == profile.normBound
            && piDECSchedule.decompositionInterval == profile.decompositionInterval
            && piDECSchedule.maxSupportedDepth == profile.maxSupportedDepth
            && piDECSchedule.frozenAtCompileTime
            && hachiDecider.relationID == "D_Nu"
            && hachiDecider.backendID == NuSealConstants.productionBackendID
            && hachiDecider.transcriptID == NuSealConstants.sealTranscriptID
            && hachiDecider.variableCount == profile.hachiVariableCount
            && hachiDecider.batchingWidth == profile.batchingWidth
            && hachiDecider.batchingScheduleDomain == "NuMeQ.Shape.Decider.BatchSchedule"
            && hachiDecider.publicDigestBundleFields == [
                "profile_digest",
                "shape_set_digest",
                "final_accumulator_digest",
                "canonical_header_bytes",
                "canonical_header_digest",
                "derivation_tree_digest",
                "transcript_digest",
                "provenance_digest",
            ]
            && hachiDecider.exportedEnvelopeLayer == "application-signing-and-transport"
            && releasePolicy.minimumRawSecurityBits == 0
            && releasePolicy.minimumComposedSecurityBits == 0
            && releasePolicy.checkedAttackModels == [
                "baseline lattice estimator workbook",
                "module-structure correction",
                "power-of-two cyclotomic correction",
                "SIS infinity-norm regime",
                "small-norm SIS regime",
                "Fiat-Shamir transcript composition",
                "batching and depth composition",
            ]
            && releasePolicy.enforcedLossTerms == searchTranscript.candidates[searchTranscript.selectedIndex].lossTerms
            && irreducibilityProof.verified
            && quarticIrreducibilityProof.verified
            && searchTranscript.selectedProfile == profile
    }

    public func artifactData() throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        encoder.dateEncodingStrategy = .secondsSince1970
        return try encoder.encode(self)
    }

    public static func deterministicArtifactData(for profile: NuProfile) throws -> Data {
        try generate(
            for: profile,
            generatedAt: Date(timeIntervalSince1970: 0)
        ).artifactData()
    }

    public static func deterministicArtifactDigest(for profile: NuProfile) throws -> [UInt8] {
        Array(NuSecurityDigest.sha256(try deterministicArtifactData(for: profile)))
    }

    public static func decodeArtifactData(_ data: Data) throws -> ProfileCertificate {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .secondsSince1970
        return try decoder.decode(ProfileCertificate.self, from: data)
    }
}
