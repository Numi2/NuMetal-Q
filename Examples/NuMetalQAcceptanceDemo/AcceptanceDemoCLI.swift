import Foundation

enum AcceptanceDemoCommand {
    case run(AcceptanceDemoOptions)
    case help

    init(arguments: ArraySlice<String>) throws {
        self = try AcceptanceDemoOptions.parse(arguments: arguments)
    }
}

struct AcceptanceDemoOptions {
    enum OutputFormat: String {
        case text
        case json
    }

    let format: OutputFormat
    let outputURL: URL?

    static func parse(arguments: ArraySlice<String>) throws -> AcceptanceDemoCommand {
        var format: OutputFormat = .text
        var outputURL: URL?

        var iterator = arguments.makeIterator()
        while let argument = iterator.next() {
            switch argument {
            case "--format":
                guard let value = iterator.next(), let parsed = OutputFormat(rawValue: value) else {
                    throw AcceptanceDemoCLIError.invalidArguments("--format must be either 'text' or 'json'")
                }
                format = parsed
            case "--output":
                guard let value = iterator.next(), value.isEmpty == false else {
                    throw AcceptanceDemoCLIError.invalidArguments("--output requires a file path")
                }
                outputURL = URL(fileURLWithPath: value)
            case "--help":
                return .help
            default:
                throw AcceptanceDemoCLIError.invalidArguments("unknown argument: \(argument)")
            }
        }

        return .run(AcceptanceDemoOptions(format: format, outputURL: outputURL))
    }

    static let usage = """
    Usage: swift run NuMetalQAcceptanceDemo [--format text|json] [--output FILE]

    Options:
      --format text|json   Render the report as human-readable text or structured JSON.
      --output FILE        Write the rendered report to a file instead of stdout.
      --help               Show this help message.
    """
}

struct AcceptanceDemoSnapshot: Encodable {
    let generatedAt: String
    let profile: ProfileSection
    let shapeCompiler: ShapeCompilerSection
    let metal: MetalSection
    let superNeo: SuperNeoSection
    let sdkFlow: SDKFlowSection
    let cluster: ClusterSection
    let sync: SyncSection
    let summary: String

    struct ProfileSection: Encodable {
        let name: String
        let securityBits: Int
        let parameterPinPrefix: String
        let challengeSetDescription: String
        let irreducibilityVerified: Bool
        let derivedParamsVerified: Bool
        let schedulerMaxArity: Int
        let schedulerQueueDepth: Int
        let schedulerAggressiveSeal: Bool
    }

    struct ShapeCompilerSection: Encodable {
        let shapeName: String
        let shapeDigestPrefix: String
        let laneCount: Int
        let commitmentBits: Int
        let shapePackSignatureBytes: Int
        let kernelConfigurations: [KernelConfiguration]
    }

    struct KernelConfiguration: Encodable {
        let gpuFamilyTag: String
        let threadgroupSize: Int
        let tilesPerThreadgroup: Int
        let foldArity: Int
    }

    struct MetalSection: Encodable {
        let deviceName: String
        let gpuFamilyTag: String
        let maxThreadsPerThreadgroup: Int
        let warmedThreadExecutionWidth: Int
    }

    struct SuperNeoSection: Encodable {
        let stagesExercised: String
        let piDECInput: String
        let piCCSVerified: Bool
        let piCCSMetalMatchesCPU: Bool
        let piCCSSumcheckRounds: Int
        let piRLCVerified: Bool
        let piRLCMetalMatchesCPU: Bool
        let ringChallengeCoefficientZero: [UInt64]
        let crossTermCommitments: Int
        let piDECVerified: Bool
        let piDECMetalMatchesCPU: Bool
        let decompositionLimbs: Int
    }

    struct SDKFlowSection: Encodable {
        let seedHandles: Int
        let logicalStatementCount: Int
        let sealBackendID: String
        let envelopeSignatureValid: Bool
        let verificationResult: Bool
        let resumedChainID: String
        let outerSpartanRounds: Int
        let pcsBatchClasses: Int
        let pcsOpenings: Int
        let matrixCommitments: Int
    }

    struct ClusterSection: Encodable {
        let confinedLaneIndices: [Int]
        let delegatedCommitmentDiffersFromFinal: Bool
        let confinedHandleEligibility: String
        let sessionReturnedToPaired: Bool
        let delegatableHandleEligibility: String
        let clusterSealVerificationResult: Bool
    }

    struct SyncSection: Encodable {
        let messageID: String
        let ciphertextBytes: Int
        let signatureBytes: Int
        let attestationCarriedThroughSync: Bool
        let openedEnvelopeMatchesOriginal: Bool
    }
}

extension NuMetalQAcceptanceDemo {
    static func render(snapshot: AcceptanceDemoSnapshot, format: AcceptanceDemoOptions.OutputFormat) throws -> String {
        switch format {
        case .text:
            return renderText(snapshot: snapshot)
        case .json:
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
            return String(decoding: try encoder.encode(snapshot), as: UTF8.self)
        }
    }

    static func emit(snapshot: AcceptanceDemoSnapshot, options: AcceptanceDemoOptions) throws {
        let rendered = try render(snapshot: snapshot, format: options.format)
        guard let outputURL = options.outputURL else {
            print(rendered)
            return
        }

        let directory = outputURL.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        try rendered.write(to: outputURL, atomically: true, encoding: .utf8)
        print("NuMetalQAcceptanceDemo wrote:")
        print(outputURL.path)
    }

    static func renderText(snapshot: AcceptanceDemoSnapshot) -> String {
        var lines: [String] = []
        lines.append("NuMetalQ Acceptance Demo")
        lines.append("========================")
        lines.append("")

        appendSection("Profile", to: &lines)
        lines.append("profile: \(snapshot.profile.name)")
        lines.append("security bits: \(snapshot.profile.securityBits)")
        lines.append("parameter pin: \(snapshot.profile.parameterPinPrefix)")
        lines.append("challenge set: \(snapshot.profile.challengeSetDescription)")
        lines.append("irreducibility proof: \(snapshot.profile.irreducibilityVerified)")
        lines.append("derived params verify: \(snapshot.profile.derivedParamsVerified)")
        lines.append(
            "scheduler: arity=\(snapshot.profile.schedulerMaxArity) queueDepth=\(snapshot.profile.schedulerQueueDepth) aggressiveSeal=\(snapshot.profile.schedulerAggressiveSeal)"
        )

        appendSection("Shape Compiler", to: &lines)
        lines.append("shape: \(snapshot.shapeCompiler.shapeName)")
        lines.append("shape digest: \(snapshot.shapeCompiler.shapeDigestPrefix)")
        lines.append("lanes: \(snapshot.shapeCompiler.laneCount)")
        lines.append("commitment bits: \(snapshot.shapeCompiler.commitmentBits)")
        lines.append("shape pack signature bytes: \(snapshot.shapeCompiler.shapePackSignatureBytes)")
        for config in snapshot.shapeCompiler.kernelConfigurations {
            lines.append(
                "kernel[\(config.gpuFamilyTag)]: tg=\(config.threadgroupSize) tiles=\(config.tilesPerThreadgroup) foldArity=\(config.foldArity)"
            )
        }

        appendSection("Metal", to: &lines)
        lines.append("device: \(snapshot.metal.deviceName)")
        lines.append("gpu family: \(snapshot.metal.gpuFamilyTag)")
        lines.append("max threads per threadgroup: \(snapshot.metal.maxThreadsPerThreadgroup)")

        appendSection("SuperNeo Folding", to: &lines)
        lines.append("stages exercised: \(snapshot.superNeo.stagesExercised)")
        lines.append("PiDEC input: \(snapshot.superNeo.piDECInput)")
        lines.append("PiCCS verified: \(snapshot.superNeo.piCCSVerified)")
        lines.append("PiCCS metal matches CPU: \(snapshot.superNeo.piCCSMetalMatchesCPU)")
        lines.append("PiCCS sum-check rounds: \(snapshot.superNeo.piCCSSumcheckRounds)")
        lines.append("PiRLC verified: \(snapshot.superNeo.piRLCVerified)")
        lines.append("PiRLC metal matches CPU: \(snapshot.superNeo.piRLCMetalMatchesCPU)")
        lines.append("ring challenge coeff[0]: \(snapshot.superNeo.ringChallengeCoefficientZero)")
        lines.append("cross-term commitments: \(snapshot.superNeo.crossTermCommitments)")
        lines.append("PiDEC verified: \(snapshot.superNeo.piDECVerified)")
        lines.append("PiDEC metal matches CPU: \(snapshot.superNeo.piDECMetalMatchesCPU)")
        lines.append("decomposition limbs: \(snapshot.superNeo.decompositionLimbs)")
        lines.append("warmed thread execution width: \(snapshot.metal.warmedThreadExecutionWidth)")

        appendSection("SDK Flow", to: &lines)
        lines.append("seed handles: \(snapshot.sdkFlow.seedHandles)")
        lines.append("logical statement count: \(snapshot.sdkFlow.logicalStatementCount)")
        lines.append("seal backend: \(snapshot.sdkFlow.sealBackendID)")
        lines.append("envelope signature valid: \(snapshot.sdkFlow.envelopeSignatureValid)")
        lines.append("verify result: \(snapshot.sdkFlow.verificationResult)")
        lines.append("resumed chain: \(snapshot.sdkFlow.resumedChainID)")
        lines.append("sealed logical statements: \(snapshot.sdkFlow.logicalStatementCount)")
        lines.append("outer Spartan rounds: \(snapshot.sdkFlow.outerSpartanRounds)")
        lines.append("PCS batch classes: \(snapshot.sdkFlow.pcsBatchClasses)")
        lines.append("PCS openings: \(snapshot.sdkFlow.pcsOpenings)")
        lines.append("matrix commitments: \(snapshot.sdkFlow.matrixCommitments)")

        appendSection("Cluster", to: &lines)
        lines.append("confined lane indices: \(snapshot.cluster.confinedLaneIndices)")
        lines.append(
            "delegated commitment differs from final: \(snapshot.cluster.delegatedCommitmentDiffersFromFinal)"
        )
        lines.append("confined-handle eligibility: \(snapshot.cluster.confinedHandleEligibility)")
        lines.append("session returned to paired: \(snapshot.cluster.sessionReturnedToPaired)")
        lines.append("delegatable-handle eligibility: \(snapshot.cluster.delegatableHandleEligibility)")
        lines.append("cluster seal verify result: \(snapshot.cluster.clusterSealVerificationResult)")

        appendSection("Sync", to: &lines)
        lines.append("message id: \(snapshot.sync.messageID)")
        lines.append("ciphertext bytes: \(snapshot.sync.ciphertextBytes)")
        lines.append("signature bytes: \(snapshot.sync.signatureBytes)")
        lines.append("attestation carried through sync: \(snapshot.sync.attestationCarriedThroughSync)")
        lines.append("opened envelope matches original: \(snapshot.sync.openedEnvelopeMatchesOriginal)")

        appendSection("Completed", to: &lines)
        lines.append(snapshot.summary)
        return lines.joined(separator: "\n")
    }

    private static func appendSection(_ title: String, to lines: inout [String]) {
        if lines.isEmpty == false, lines.last?.isEmpty == false {
            lines.append("")
        }
        lines.append(title)
        lines.append(String(repeating: "-", count: title.count))
    }
}

private enum AcceptanceDemoCLIError: LocalizedError {
    case invalidArguments(String)

    var errorDescription: String? {
        switch self {
        case .invalidArguments(let message):
            return message
        }
    }
}
