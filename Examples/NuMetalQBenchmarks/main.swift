import Foundation
import CryptoKit
import Darwin
import Metal
import NuMetal_Q

enum NuMetalQBenchmarks {
    static func main() async throws {
        let command = try BenchmarkCommand(arguments: CommandLine.arguments.dropFirst())
        switch command {
        case .help:
            print(Options.usage)
            return
        case .listWorkloads:
            print(Options.workloadListing)
            return
        case .run(let options):
            try await run(options: options)
        }
    }

    private static func run(options: Options) async throws {
        let outputDirectory = options.outputDirectory ?? defaultOutputDirectory()
        try FileManager.default.createDirectory(at: outputDirectory, withIntermediateDirectories: true)

        let metadata = BenchmarkMetadata(
            generatedAt: ISO8601DateFormatter().string(from: Date()),
            hostName: Host.current().localizedName ?? "unknown-host",
            operatingSystemVersion: ProcessInfo.processInfo.operatingSystemVersionString,
            activeProcessorCount: ProcessInfo.processInfo.activeProcessorCount,
            physicalMemoryBytes: ProcessInfo.processInfo.physicalMemory
        )

        let configuration = BenchmarkConfiguration(
            iterations: options.iterations,
            warmups: options.warmups
        )
        let sealScaffolds = options.sealWorkloads.map(makeSealScaffold)
        let artifactWriter = try BenchmarkArtifactWriter(
            outputDirectory: outputDirectory,
            metadata: metadata,
            configuration: configuration,
            initialSealWorkloads: sealScaffolds.map { pendingSealResult(for: $0.workload, configuration: configuration) },
            initialPCSWorkloads: options.pcsWorkloads.map { pendingPCSResult(for: $0, configuration: configuration) },
            initialVerifierWorkloads: options.verifierWorkloads.map {
                pendingVerifierResult(for: $0, configuration: configuration)
            }
        )

        do {
            _ = try await benchmarkSealWorkflows(
                options: options,
                sealScaffolds: sealScaffolds,
                artifactWriter: artifactWriter
            )
            _ = try await benchmarkPCSKernels(options: options, artifactWriter: artifactWriter)
            _ = try await benchmarkVerifierStages(options: options, artifactWriter: artifactWriter)
            let completedReport = try await artifactWriter.markCompleted()

            print("NuMetalQBenchmarks wrote:")
            print(completedReport.jsonPath)
            print(completedReport.markdownPath)
            print(completedReport.dispatchTracePath)
            print(completedReport.comparisonTemplatePath)
            print(completedReport.reviewBundlePath)
        } catch {
            _ = try? await artifactWriter.markFailed(error: error)
            throw error
        }
    }

    private static func benchmarkSealWorkflows(
        options: Options,
        sealScaffolds: [SealWorkloadScaffold],
        artifactWriter: BenchmarkArtifactWriter
    ) async throws -> [SealBenchmarkResult] {
        let metalInfo = try? MetalContext()
        let expectedIterations = options.warmups + options.iterations

        return try await Array(sealScaffolds.enumerated()).mapAsync { workloadIndex, scaffold in
            var seedOneSamples: [Double] = []
            var seedTwoSamples: [Double] = []
            var fuseSamples: [Double] = []
            var sealSamples: [Double] = []
            var cpuVerifySamples: [Double] = []
            var assistedVerifySamples: [Double] = []
            var assistedVerifyGPUSamples: [Double] = []
            var peakRSSBytes: UInt64 = peakResidentSetSizeBytes()
            var publicProofBytes = 0
            var resumeArtifactBytes = 0
            var totalExportBytes = 0
            var fuseFailure: String?
            var verificationParity: HachiVerificationParity = metalInfo == nil ? .unavailable : .matched
            var parityNote: String?

            try await artifactWriter.updateSeal(
                makeSealResult(
                    workload: scaffold.workload,
                    status: .running,
                    completedIterations: 0,
                    expectedIterations: expectedIterations,
                    completedSamples: 0,
                    expectedSamples: options.iterations,
                    gpuFamilyTag: metalInfo?.gpuFamilyTag ?? "unavailable",
                    gpuName: metalInfo?.device.name ?? "unavailable",
                    publicProofBytes: publicProofBytes,
                    resumeArtifactBytes: resumeArtifactBytes,
                    totalExportBytes: totalExportBytes,
                    peakRSSBytes: peakRSSBytes,
                    seedOneSamples: seedOneSamples,
                    seedTwoSamples: seedTwoSamples,
                    fuseSamples: fuseSamples,
                    sealSamples: sealSamples,
                    cpuVerifySamples: cpuVerifySamples,
                    assistedVerifySamples: assistedVerifySamples,
                    assistedVerifyGPUSamples: assistedVerifyGPUSamples,
                    verifyMode: metalInfo == nil ? "cpu-only" : "cpu-only+metal-assisted",
                    verificationParity: verificationParity,
                    dispatchTracePath: await artifactWriter.dispatchTracePath(),
                    parityNote: parityNote,
                    fuseFailure: fuseFailure
                ),
                at: workloadIndex
            )

            let fixture = try makeSealFixture(scaffold: scaffold)
            let engine = try await NuMeQ()
            let hachiVerifier = HachiSealEngine()
            if let metalInfo {
                await hachiVerifier.setMetalContext(metalInfo)
            }

            for iteration in 0..<(options.warmups + options.iterations) {
                let inputs = try makeSealInputs(
                    fixture: fixture,
                    seedOne: 11 + UInt64(iteration * 2),
                    seedTwo: 29 + UInt64(iteration * 2)
                )
                let context = await engine.createContext(
                    compiledShape: fixture.compiledShape,
                    policy: .standard,
                    appID: benchmarkAppID,
                    teamID: benchmarkTeamID,
                    attestationVerifier: attestationVerifier
                )
                let sessionKey = SymmetricKey(data: Data(repeating: 0xA5, count: 32))

                let seedOne = try await timedThrowing {
                    try await context.seed(
                        witness: inputs.firstWitness,
                        publicInputs: inputs.publicInputs,
                        publicHeader: packedPublicHeader(inputs.publicInputs)
                    )
                }
                peakRSSBytes = max(peakRSSBytes, peakResidentSetSizeBytes())

                let seedTwo = try await timedThrowing {
                    try await context.seed(
                        witness: inputs.secondWitness,
                        publicInputs: inputs.publicInputs,
                        publicHeader: packedPublicHeader(inputs.publicInputs)
                    )
                }
                peakRSSBytes = max(peakRSSBytes, peakResidentSetSizeBytes())

                if fuseFailure == nil {
                    do {
                        let fuseContext = await engine.createContext(
                            compiledShape: fixture.compiledShape,
                            policy: .standard,
                            appID: benchmarkAppID,
                            teamID: benchmarkTeamID,
                            attestationVerifier: attestationVerifier
                        )
                        let untimedFuseSeedOne = try await fuseContext.seed(
                            witness: inputs.firstWitness,
                            publicInputs: inputs.publicInputs,
                            publicHeader: packedPublicHeader(inputs.publicInputs)
                        )
                        let untimedFuseSeedTwo = try await fuseContext.seed(
                            witness: inputs.secondWitness,
                            publicInputs: inputs.publicInputs,
                            publicHeader: packedPublicHeader(inputs.publicInputs)
                        )
                        let fused = try await timedThrowing {
                            try await fuseContext.fuse(untimedFuseSeedOne, untimedFuseSeedTwo)
                        }
                        peakRSSBytes = max(peakRSSBytes, peakResidentSetSizeBytes())
                        if iteration >= options.warmups {
                            fuseSamples.append(fused.milliseconds)
                        }
                    } catch {
                        fuseFailure = String(describing: error)
                    }
                }

                let sealedExport = try await timedThrowing {
                    try await context.seal(
                        seedOne.value,
                        sessionKey: sessionKey,
                        signerKeyID: signerKeyID,
                        attestation: Data("bench-attestation".utf8),
                        signEnvelope: signer
                    )
                }
                peakRSSBytes = max(peakRSSBytes, peakResidentSetSizeBytes())

                let cpuVerification = try await timedThrowing {
                    try await engine.verify(
                        envelope: sealedExport.value.proofEnvelope,
                        compiledShape: fixture.compiledShape,
                        verifySignature: envelopeVerifier,
                        expectedAppID: benchmarkAppID,
                        expectedTeamID: benchmarkTeamID,
                        attestationVerifier: attestationVerifier,
                        requireAttestation: true,
                        executionMode: .cpuOnly,
                        traceCollector: nil
                    )
                }
                peakRSSBytes = max(peakRSSBytes, peakResidentSetSizeBytes())
                let decodedProof = try sealedExport.value.proofEnvelope.proof()
                publicProofBytes = sealedExport.value.proofEnvelope.proofBytes.count
                resumeArtifactBytes = sealedExport.value.resumeArtifact.serialize().count
                totalExportBytes =
                    sealedExport.value.proofEnvelope.serialize().count
                    + resumeArtifactBytes

                guard cpuVerification.value.isValid else {
                    let cpuOutcome = await hachiVerifier.verifySemantically(
                        proof: decodedProof,
                        shape: fixture.compiledShape.shape,
                        publicHeader: sealedExport.value.proofEnvelope.publicHeaderBytes,
                        executionMode: .cpuOnly,
                        traceCollector: nil
                    )
                    verificationParity = metalInfo == nil ? .unavailable : .mismatched
                    parityNote = "cpuOnly: \(cpuOutcome.diagnostics.summary)"
                    let failedSnapshot = makeSealResult(
                        workload: fixture.workload,
                        status: .running,
                        completedIterations: iteration + 1,
                        expectedIterations: expectedIterations,
                        completedSamples: max(0, iteration + 1 - options.warmups),
                        expectedSamples: options.iterations,
                        gpuFamilyTag: metalInfo?.gpuFamilyTag ?? "unavailable",
                        gpuName: metalInfo?.device.name ?? "unavailable",
                        publicProofBytes: publicProofBytes,
                        resumeArtifactBytes: resumeArtifactBytes,
                        totalExportBytes: totalExportBytes,
                        peakRSSBytes: peakRSSBytes,
                        seedOneSamples: seedOneSamples,
                        seedTwoSamples: seedTwoSamples,
                        fuseSamples: fuseSamples,
                        sealSamples: sealSamples,
                        cpuVerifySamples: cpuVerifySamples,
                        assistedVerifySamples: assistedVerifySamples,
                        assistedVerifyGPUSamples: assistedVerifyGPUSamples,
                        verifyMode: metalInfo == nil ? "cpu-only" : "cpu-only+metal-assisted",
                        verificationParity: verificationParity,
                        dispatchTracePath: await artifactWriter.dispatchTracePath(),
                        parityNote: parityNote,
                        fuseFailure: fuseFailure
                    )
                    try await artifactWriter.updateSeal(failedSnapshot, at: workloadIndex)
                    throw BenchmarkError.invalidVerification("\(fixture.workload.name): \(cpuOutcome.diagnostics.summary)")
                }

                var assistedVerification: TimedResult<VerificationResult>?
                var assistedTraceSnapshot: [MetalDispatchTraceSample] = []
                if metalInfo != nil {
                    let traceCollector = MetalTraceCollector(iteration: max(0, iteration - options.warmups))
                        let result = try await timedThrowing {
                        try await engine.verify(
                            envelope: sealedExport.value.proofEnvelope,
                            compiledShape: fixture.compiledShape,
                            verifySignature: envelopeVerifier,
                            expectedAppID: benchmarkAppID,
                            expectedTeamID: benchmarkTeamID,
                            attestationVerifier: attestationVerifier,
                            requireAttestation: true,
                            executionMode: .metalAssisted,
                            traceCollector: traceCollector
                        )
                    }
                    peakRSSBytes = max(peakRSSBytes, peakResidentSetSizeBytes())
                    guard result.value.isValid else {
                        let assistedOutcome = await hachiVerifier.verifySemantically(
                            proof: decodedProof,
                            shape: fixture.compiledShape.shape,
                            publicHeader: sealedExport.value.proofEnvelope.publicHeaderBytes,
                            executionMode: .metalAssisted,
                            traceCollector: nil
                        )
                        verificationParity = .mismatched
                        parityNote = "metalAssisted: \(assistedOutcome.diagnostics.summary)"
                        let failedSnapshot = makeSealResult(
                            workload: fixture.workload,
                            status: .running,
                            completedIterations: iteration + 1,
                            expectedIterations: expectedIterations,
                            completedSamples: max(0, iteration + 1 - options.warmups),
                            expectedSamples: options.iterations,
                            gpuFamilyTag: metalInfo?.gpuFamilyTag ?? "unavailable",
                            gpuName: metalInfo?.device.name ?? "unavailable",
                            publicProofBytes: publicProofBytes,
                            resumeArtifactBytes: resumeArtifactBytes,
                            totalExportBytes: totalExportBytes,
                            peakRSSBytes: peakRSSBytes,
                            seedOneSamples: seedOneSamples,
                            seedTwoSamples: seedTwoSamples,
                            fuseSamples: fuseSamples,
                            sealSamples: sealSamples,
                            cpuVerifySamples: cpuVerifySamples,
                            assistedVerifySamples: assistedVerifySamples,
                            assistedVerifyGPUSamples: assistedVerifyGPUSamples,
                            verifyMode: metalInfo == nil ? "cpu-only" : "cpu-only+metal-assisted",
                            verificationParity: verificationParity,
                            dispatchTracePath: await artifactWriter.dispatchTracePath(),
                            parityNote: parityNote,
                            fuseFailure: fuseFailure
                        )
                        try await artifactWriter.updateSeal(failedSnapshot, at: workloadIndex)
                        throw BenchmarkError.invalidVerification("\(fixture.workload.name): \(assistedOutcome.diagnostics.summary)")
                    }
                    assistedVerification = result
                    assistedTraceSnapshot = traceCollector.snapshot()
                    verificationParity = .matched
                    parityNote = nil
                }

                if iteration >= options.warmups {
                    seedOneSamples.append(seedOne.milliseconds)
                    seedTwoSamples.append(seedTwo.milliseconds)
                    sealSamples.append(sealedExport.milliseconds)
                    cpuVerifySamples.append(cpuVerification.milliseconds)
                    if let assistedVerification {
                        assistedVerifySamples.append(assistedVerification.milliseconds)
                        if let gpuMilliseconds = totalGPUMilliseconds(for: assistedTraceSnapshot) {
                            assistedVerifyGPUSamples.append(gpuMilliseconds)
                        }
                        try await artifactWriter.updateSealTrace(
                            workloadName: fixture.workload.name,
                            iteration: iteration - options.warmups,
                            samples: assistedTraceSnapshot
                        )
                    }
                }

                let snapshot = makeSealResult(
                    workload: fixture.workload,
                    status: .running,
                    completedIterations: iteration + 1,
                    expectedIterations: expectedIterations,
                    completedSamples: max(0, iteration + 1 - options.warmups),
                    expectedSamples: options.iterations,
                    gpuFamilyTag: metalInfo?.gpuFamilyTag ?? "unavailable",
                    gpuName: metalInfo?.device.name ?? "unavailable",
                    publicProofBytes: publicProofBytes,
                    resumeArtifactBytes: resumeArtifactBytes,
                    totalExportBytes: totalExportBytes,
                    peakRSSBytes: peakRSSBytes,
                    seedOneSamples: seedOneSamples,
                    seedTwoSamples: seedTwoSamples,
                    fuseSamples: fuseSamples,
                    sealSamples: sealSamples,
                    cpuVerifySamples: cpuVerifySamples,
                    assistedVerifySamples: assistedVerifySamples,
                    assistedVerifyGPUSamples: assistedVerifyGPUSamples,
                    verifyMode: metalInfo == nil ? "cpu-only" : "cpu-only+metal-assisted",
                    verificationParity: verificationParity,
                    dispatchTracePath: await artifactWriter.dispatchTracePath(),
                    parityNote: parityNote,
                    fuseFailure: fuseFailure
                )
                try await artifactWriter.updateSeal(snapshot, at: workloadIndex)
            }

            let finalResult = makeSealResult(
                workload: fixture.workload,
                status: .completed,
                completedIterations: expectedIterations,
                expectedIterations: expectedIterations,
                completedSamples: options.iterations,
                expectedSamples: options.iterations,
                gpuFamilyTag: metalInfo?.gpuFamilyTag ?? "unavailable",
                gpuName: metalInfo?.device.name ?? "unavailable",
                publicProofBytes: publicProofBytes,
                resumeArtifactBytes: resumeArtifactBytes,
                totalExportBytes: totalExportBytes,
                peakRSSBytes: peakRSSBytes,
                seedOneSamples: seedOneSamples,
                seedTwoSamples: seedTwoSamples,
                fuseSamples: fuseSamples,
                sealSamples: sealSamples,
                cpuVerifySamples: cpuVerifySamples,
                assistedVerifySamples: assistedVerifySamples,
                assistedVerifyGPUSamples: assistedVerifyGPUSamples,
                verifyMode: metalInfo == nil ? "cpu-only" : "cpu-only+metal-assisted",
                verificationParity: verificationParity,
                dispatchTracePath: await artifactWriter.dispatchTracePath(),
                parityNote: parityNote,
                fuseFailure: fuseFailure
            )
            try await artifactWriter.updateSeal(finalResult, at: workloadIndex)
            return finalResult
        }
    }

    private static func benchmarkPCSKernels(
        options: Options,
        artifactWriter: BenchmarkArtifactWriter
    ) async throws -> [PCSBenchmarkResult] {
        let metalContext = try? MetalContext()
        let expectedIterations = options.warmups + options.iterations

        return try await Array(options.pcsWorkloads.enumerated()).mapAsync { workloadIndex, workload in
            let evals = samplePCSEvaluations(numVars: workload.numVars)
            let codewordLength = evals.count * 4
            let positions = samplePCSQueryPositions(codewordLength: codewordLength)
            let note = metalContext == nil
                ? "Commit measures codeword extension plus Merkle construction. Open measures codeword query gather. Metal timings unavailable on this host."
                : "Commit measures codeword extension plus Merkle construction. Open measures codeword query gather."

            var cpuCommitSamples: [Double] = []
            var cpuOpenSamples: [Double] = []
            var metalCommitSamples: [Double] = []
            var metalOpenSamples: [Double] = []
            var metalCommitGPUSamples: [Double] = []
            var metalOpenGPUSamples: [Double] = []
            var metalCommitThreadgroupWidths = Set<Int>()
            var metalOpenThreadgroupWidths = Set<Int>()
            var metalCommitCountersCaptured = true
            var metalOpenCountersCaptured = true
            var peakRSSBytes = peakResidentSetSizeBytes()
            let counterSamplingAvailable = metalContext?.dispatchCounterSamplingSupported ?? false

            try await artifactWriter.updatePCS(
                PCSBenchmarkResult(
                    workload: workload,
                    status: .running,
                    completedIterations: 0,
                    expectedIterations: expectedIterations,
                    completedSamples: 0,
                    expectedSamples: options.iterations,
                    peakRSSBytes: peakRSSBytes,
                    cpuCommit: nil,
                    cpuOpen: nil,
                    metalCommit: nil,
                    metalOpen: nil,
                    metalCommitGPU: nil,
                    metalOpenGPU: nil,
                    metalCommitThreadgroupWidths: [],
                    metalOpenThreadgroupWidths: [],
                    counterSamplingAvailable: counterSamplingAvailable,
                    metalCommitCountersCaptured: false,
                    metalOpenCountersCaptured: false,
                    gpuFamilyTag: metalContext?.gpuFamilyTag ?? "unavailable",
                    gpuName: metalContext?.device.name ?? "unavailable",
                    note: note
                ),
                at: workloadIndex
            )

            for iteration in 0..<expectedIterations {
                let cpuCommitStart = DispatchTime.now().uptimeNanoseconds
                let cpuArtifact = buildCPUCommitArtifact(evals: evals, blowup: 4)
                let cpuCommitElapsed = Double(
                    DispatchTime.now().uptimeNanoseconds - cpuCommitStart
                ) / 1_000_000.0

                let cpuOpenStart = DispatchTime.now().uptimeNanoseconds
                _ = gatherCPUQueryValues(codeword: cpuArtifact.codeword, positions: positions)
                let cpuOpenElapsed = Double(
                    DispatchTime.now().uptimeNanoseconds - cpuOpenStart
                ) / 1_000_000.0

                if let metalContext {
                    let metalIteration = try benchmarkMetalPCSIteration(
                        evals: evals,
                        positions: positions,
                        context: metalContext,
                        blowup: 4
                    )
                    if iteration >= options.warmups {
                        metalCommitSamples.append(metalIteration.commitCPU)
                        metalOpenSamples.append(metalIteration.openCPU)
                        if let commitGPU = metalIteration.commitGPU {
                            metalCommitGPUSamples.append(commitGPU)
                        }
                        if let openGPU = metalIteration.openGPU {
                            metalOpenGPUSamples.append(openGPU)
                        }
                    }
                    metalCommitThreadgroupWidths.formUnion(metalIteration.commitThreadgroupWidths)
                    metalOpenThreadgroupWidths.formUnion(metalIteration.openThreadgroupWidths)
                    metalCommitCountersCaptured = metalCommitCountersCaptured && metalIteration.commitCounterSamplesCaptured
                    metalOpenCountersCaptured = metalOpenCountersCaptured && metalIteration.openCounterSamplesCaptured
                }

                peakRSSBytes = max(peakRSSBytes, peakResidentSetSizeBytes())

                if iteration >= options.warmups {
                    cpuCommitSamples.append(cpuCommitElapsed)
                    cpuOpenSamples.append(cpuOpenElapsed)
                }

                try await artifactWriter.updatePCS(
                    makePCSResult(
                        workload: workload,
                        status: .running,
                        completedIterations: iteration + 1,
                        expectedIterations: expectedIterations,
                        completedSamples: max(0, iteration + 1 - options.warmups),
                        expectedSamples: options.iterations,
                        peakRSSBytes: peakRSSBytes,
                        cpuCommitSamples: cpuCommitSamples,
                        cpuOpenSamples: cpuOpenSamples,
                        metalCommitSamples: metalCommitSamples,
                        metalOpenSamples: metalOpenSamples,
                        metalCommitGPUSamples: metalCommitGPUSamples,
                        metalOpenGPUSamples: metalOpenGPUSamples,
                        metalCommitThreadgroupWidths: metalCommitThreadgroupWidths.sorted(),
                        metalOpenThreadgroupWidths: metalOpenThreadgroupWidths.sorted(),
                        counterSamplingAvailable: counterSamplingAvailable,
                        metalCommitCountersCaptured: counterSamplingAvailable && metalCommitCountersCaptured,
                        metalOpenCountersCaptured: counterSamplingAvailable && metalOpenCountersCaptured,
                        gpuFamilyTag: metalContext?.gpuFamilyTag ?? "unavailable",
                        gpuName: metalContext?.device.name ?? "unavailable",
                        note: note
                    ),
                    at: workloadIndex
                )
            }

            let finalResult = makePCSResult(
                workload: workload,
                status: .completed,
                completedIterations: expectedIterations,
                expectedIterations: expectedIterations,
                completedSamples: options.iterations,
                expectedSamples: options.iterations,
                peakRSSBytes: peakRSSBytes,
                cpuCommitSamples: cpuCommitSamples,
                cpuOpenSamples: cpuOpenSamples,
                metalCommitSamples: metalCommitSamples,
                metalOpenSamples: metalOpenSamples,
                metalCommitGPUSamples: metalCommitGPUSamples,
                metalOpenGPUSamples: metalOpenGPUSamples,
                metalCommitThreadgroupWidths: metalCommitThreadgroupWidths.sorted(),
                metalOpenThreadgroupWidths: metalOpenThreadgroupWidths.sorted(),
                counterSamplingAvailable: counterSamplingAvailable,
                metalCommitCountersCaptured: counterSamplingAvailable && metalCommitCountersCaptured,
                metalOpenCountersCaptured: counterSamplingAvailable && metalOpenCountersCaptured,
                gpuFamilyTag: metalContext?.gpuFamilyTag ?? "unavailable",
                gpuName: metalContext?.device.name ?? "unavailable",
                note: note
            )
            try await artifactWriter.updatePCS(finalResult, at: workloadIndex)
            return finalResult
        }
    }

    private static func benchmarkVerifierStages(
        options: Options,
        artifactWriter: BenchmarkArtifactWriter
    ) async throws -> [VerifierBenchmarkResult] {
        let metalContext = try? MetalContext()
        let expectedIterations = options.warmups + options.iterations

        return try await Array(options.verifierWorkloads.enumerated()).mapAsync { workloadIndex, workload in
            let counterSamplingAvailable = metalContext?.dispatchCounterSamplingSupported ?? false
            let note = metalContext == nil
                ? "Metal-assisted verifier unavailable on this host."
                : "Metal-assisted verifier uses the recursive-stage GPU recomputation path."

            var cpuSamples: [Double] = []
            var assistedSamples: [Double] = []
            var assistedGPUSamples: [Double] = []
            var dispatchSamples: [MetalDispatchTraceSample] = []
            var peakRSSBytes = peakResidentSetSizeBytes()

            try await artifactWriter.updateVerifier(
                VerifierBenchmarkResult(
                    workload: workload,
                    status: .running,
                    completedIterations: 0,
                    expectedIterations: expectedIterations,
                    completedSamples: 0,
                    expectedSamples: options.iterations,
                    peakRSSBytes: peakRSSBytes,
                    cpuVerify: nil,
                    assistedVerify: nil,
                    assistedVerifyGPU: nil,
                    assistanceMode: metalContext == nil ? "cpu-only" : "metal-assisted",
                    counterSamplingAvailable: counterSamplingAvailable,
                    dispatchCount: 0,
                    dispatchSummaries: [],
                    dispatchTracePath: await artifactWriter.dispatchTracePath(),
                    gpuFamilyTag: metalContext?.gpuFamilyTag ?? "unavailable",
                    gpuName: metalContext?.device.name ?? "unavailable",
                    note: note
                ),
                at: workloadIndex
            )

            switch workload.stage {
            case .piCCS:
                let input = sampleVerifierPiCCSInput(seed: 17)
                var provingTranscript = NuTranscriptField(domain: "Bench.Verifier.PiCCS")
                let output = PiCCS.prove(input: input, transcript: &provingTranscript)

                for iteration in 0..<expectedIterations {
                    let cpuElapsed = try timedVerifierStage {
                        var transcript = NuTranscriptField(domain: "Bench.Verifier.PiCCS")
                        return PiCCS.verify(input: input, output: output, transcript: &transcript)
                    }
                    guard cpuElapsed.value else {
                        throw BenchmarkError.invalidVerification(workload.name)
                    }

                    if let metalContext {
                        let traceCollector = MetalTraceCollector(iteration: max(0, iteration - options.warmups))
                        let assistedElapsed = try timedVerifierStage {
                            var transcript = NuTranscriptField(domain: "Bench.Verifier.PiCCS")
                            return try PiCCS.verifyMetal(
                                input: input,
                                output: output,
                                transcript: &transcript,
                                context: metalContext,
                                trace: traceCollector
                            )
                        }
                        guard assistedElapsed.value else {
                            throw BenchmarkError.invalidVerification(workload.name)
                        }
                        if iteration >= options.warmups {
                            assistedSamples.append(assistedElapsed.milliseconds)
                            let snapshot = traceCollector.snapshot()
                            dispatchSamples.append(contentsOf: snapshot)
                            if let gpuMilliseconds = totalGPUMilliseconds(for: snapshot) {
                                assistedGPUSamples.append(gpuMilliseconds)
                            }
                            try await artifactWriter.updateVerifierTrace(
                                workloadName: workload.name,
                                iteration: iteration - options.warmups,
                                samples: snapshot
                            )
                        }
                    }

                    if iteration >= options.warmups {
                        cpuSamples.append(cpuElapsed.milliseconds)
                    }
                    peakRSSBytes = max(peakRSSBytes, peakResidentSetSizeBytes())

                    try await artifactWriter.updateVerifier(
                        makeVerifierResult(
                            workload: workload,
                            status: .running,
                            completedIterations: iteration + 1,
                            expectedIterations: expectedIterations,
                            completedSamples: max(0, iteration + 1 - options.warmups),
                            expectedSamples: options.iterations,
                            peakRSSBytes: peakRSSBytes,
                            cpuSamples: cpuSamples,
                            assistedSamples: assistedSamples,
                            assistedGPUSamples: assistedGPUSamples,
                            assistanceMode: metalContext == nil ? "cpu-only" : "metal-assisted",
                            counterSamplingAvailable: counterSamplingAvailable,
                            dispatchSummaries: aggregateDispatchSummaries(dispatchSamples),
                            dispatchTracePath: await artifactWriter.dispatchTracePath(),
                            gpuFamilyTag: metalContext?.gpuFamilyTag ?? "unavailable",
                            gpuName: metalContext?.device.name ?? "unavailable",
                            note: note
                        ),
                        at: workloadIndex
                    )
                }

            case .piRLC:
                let key = NuParams.derive(from: .canonical).fold.commitmentKey
                let inputs = sampleVerifierPiRLCInputs(key: key, seed: 33)
                var provingTranscript = NuTranscriptField(domain: "Bench.Verifier.PiRLC")
                let output = PiRLC.prove(inputs: inputs, key: key, transcript: &provingTranscript)

                for iteration in 0..<expectedIterations {
                    let cpuElapsed = try timedVerifierStage {
                        var transcript = NuTranscriptField(domain: "Bench.Verifier.PiRLC")
                        return PiRLC.verify(
                            inputs: inputs,
                            output: output,
                            key: key,
                            transcript: &transcript
                        )
                    }
                    guard cpuElapsed.value else {
                        throw BenchmarkError.invalidVerification(workload.name)
                    }

                    if let metalContext {
                        let traceCollector = MetalTraceCollector(iteration: max(0, iteration - options.warmups))
                        let assistedElapsed = try timedVerifierStage {
                            var transcript = NuTranscriptField(domain: "Bench.Verifier.PiRLC")
                            return try PiRLC.verifyMetal(
                                inputs: inputs,
                                output: output,
                                key: key,
                                transcript: &transcript,
                                context: metalContext,
                                trace: traceCollector
                            )
                        }
                        guard assistedElapsed.value else {
                            throw BenchmarkError.invalidVerification(workload.name)
                        }
                        if iteration >= options.warmups {
                            assistedSamples.append(assistedElapsed.milliseconds)
                            let snapshot = traceCollector.snapshot()
                            dispatchSamples.append(contentsOf: snapshot)
                            if let gpuMilliseconds = totalGPUMilliseconds(for: snapshot) {
                                assistedGPUSamples.append(gpuMilliseconds)
                            }
                            try await artifactWriter.updateVerifierTrace(
                                workloadName: workload.name,
                                iteration: iteration - options.warmups,
                                samples: snapshot
                            )
                        }
                    }

                    if iteration >= options.warmups {
                        cpuSamples.append(cpuElapsed.milliseconds)
                    }
                    peakRSSBytes = max(peakRSSBytes, peakResidentSetSizeBytes())

                    try await artifactWriter.updateVerifier(
                        makeVerifierResult(
                            workload: workload,
                            status: .running,
                            completedIterations: iteration + 1,
                            expectedIterations: expectedIterations,
                            completedSamples: max(0, iteration + 1 - options.warmups),
                            expectedSamples: options.iterations,
                            peakRSSBytes: peakRSSBytes,
                            cpuSamples: cpuSamples,
                            assistedSamples: assistedSamples,
                            assistedGPUSamples: assistedGPUSamples,
                            assistanceMode: metalContext == nil ? "cpu-only" : "metal-assisted",
                            counterSamplingAvailable: counterSamplingAvailable,
                            dispatchSummaries: aggregateDispatchSummaries(dispatchSamples),
                            dispatchTracePath: await artifactWriter.dispatchTracePath(),
                            gpuFamilyTag: metalContext?.gpuFamilyTag ?? "unavailable",
                            gpuName: metalContext?.device.name ?? "unavailable",
                            note: note
                        ),
                        at: workloadIndex
                    )
                }

            case .piDEC:
                let key = NuParams.derive(from: .canonical).fold.commitmentKey
                let input = sampleVerifierPiDECInput(key: key, seed: 61)
                var provingTranscript = NuTranscriptField(domain: "Bench.Verifier.PiDEC")
                let output = PiDEC.prove(input: input, transcript: &provingTranscript)

                for iteration in 0..<expectedIterations {
                    let cpuElapsed = try timedVerifierStage {
                        var transcript = NuTranscriptField(domain: "Bench.Verifier.PiDEC")
                        return PiDEC.verify(input: input, output: output, transcript: &transcript)
                    }
                    guard cpuElapsed.value else {
                        throw BenchmarkError.invalidVerification(workload.name)
                    }

                    if let metalContext {
                        let traceCollector = MetalTraceCollector(iteration: max(0, iteration - options.warmups))
                        let assistedElapsed = try timedVerifierStage {
                            var transcript = NuTranscriptField(domain: "Bench.Verifier.PiDEC")
                            return try PiDEC.verifyMetal(
                                input: input,
                                output: output,
                                transcript: &transcript,
                                context: metalContext,
                                trace: traceCollector
                            )
                        }
                        guard assistedElapsed.value else {
                            throw BenchmarkError.invalidVerification(workload.name)
                        }
                        if iteration >= options.warmups {
                            assistedSamples.append(assistedElapsed.milliseconds)
                            let snapshot = traceCollector.snapshot()
                            dispatchSamples.append(contentsOf: snapshot)
                            if let gpuMilliseconds = totalGPUMilliseconds(for: snapshot) {
                                assistedGPUSamples.append(gpuMilliseconds)
                            }
                            try await artifactWriter.updateVerifierTrace(
                                workloadName: workload.name,
                                iteration: iteration - options.warmups,
                                samples: snapshot
                            )
                        }
                    }

                    if iteration >= options.warmups {
                        cpuSamples.append(cpuElapsed.milliseconds)
                    }
                    peakRSSBytes = max(peakRSSBytes, peakResidentSetSizeBytes())

                    try await artifactWriter.updateVerifier(
                        makeVerifierResult(
                            workload: workload,
                            status: .running,
                            completedIterations: iteration + 1,
                            expectedIterations: expectedIterations,
                            completedSamples: max(0, iteration + 1 - options.warmups),
                            expectedSamples: options.iterations,
                            peakRSSBytes: peakRSSBytes,
                            cpuSamples: cpuSamples,
                            assistedSamples: assistedSamples,
                            assistedGPUSamples: assistedGPUSamples,
                            assistanceMode: metalContext == nil ? "cpu-only" : "metal-assisted",
                            counterSamplingAvailable: counterSamplingAvailable,
                            dispatchSummaries: aggregateDispatchSummaries(dispatchSamples),
                            dispatchTracePath: await artifactWriter.dispatchTracePath(),
                            gpuFamilyTag: metalContext?.gpuFamilyTag ?? "unavailable",
                            gpuName: metalContext?.device.name ?? "unavailable",
                            note: note
                        ),
                        at: workloadIndex
                    )
                }
            }

            let finalResult = makeVerifierResult(
                workload: workload,
                status: .completed,
                completedIterations: expectedIterations,
                expectedIterations: expectedIterations,
                completedSamples: options.iterations,
                expectedSamples: options.iterations,
                peakRSSBytes: peakRSSBytes,
                cpuSamples: cpuSamples,
                assistedSamples: assistedSamples,
                assistedGPUSamples: assistedGPUSamples,
                assistanceMode: metalContext == nil ? "cpu-only" : "metal-assisted",
                counterSamplingAvailable: counterSamplingAvailable,
                dispatchSummaries: aggregateDispatchSummaries(dispatchSamples),
                dispatchTracePath: await artifactWriter.dispatchTracePath(),
                gpuFamilyTag: metalContext?.gpuFamilyTag ?? "unavailable",
                gpuName: metalContext?.device.name ?? "unavailable",
                note: note
            )
            try await artifactWriter.updateVerifier(finalResult, at: workloadIndex)
            return finalResult
        }
    }

    fileprivate static func renderMarkdown(_ report: BenchmarkReport) -> String {
        var lines: [String] = []
        lines.append("# NuMetalQ Benchmark Report")
        lines.append("")
        lines.append("- Status: \(report.status.rawValue)")
        lines.append("- Generated: \(report.metadata.generatedAt)")
        lines.append("- Last updated: \(report.lastUpdatedAt)")
        if let completedAt = report.completedAt {
            lines.append("- Completed: \(completedAt)")
        }
        if let failure = report.failure {
            lines.append("- Failure: \(failure)")
        }
        lines.append("- Host: \(report.metadata.hostName)")
        lines.append("- OS: \(report.metadata.operatingSystemVersion)")
        lines.append("- CPU cores: \(report.metadata.activeProcessorCount)")
        lines.append("- Memory bytes: \(report.metadata.physicalMemoryBytes)")
        lines.append("- Iterations: \(report.configuration.iterations)")
        lines.append("- Warmups: \(report.configuration.warmups)")
        lines.append("")
        lines.append("## Seal Workflow")
        lines.append("")
        lines.append("| Workload | State | Progress | Family | Scenario | Rows | Witness | Matrices | NNZ | Density | Gate Deg | Peak RSS | GPU | Public Proof Bytes | Resume Artifact Bytes | Total Export Bytes | Seed-1 p50/p95 | Seed-2 p50/p95 | Fuse p50/p95 | Seal p50/p95 | CPU Verify p50/p95 | Assisted Verify p50/p95 | Assisted GPU p50/p95 | Parity | Trace | Verify Note | Fuse Note |")
        lines.append("| --- | --- | --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- | ---: | ---: | ---: | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |")
        for result in report.sealWorkloads {
            lines.append(
                "| \(result.workload.name) | \(result.status.rawValue) | \(result.completedIterations)/\(result.expectedIterations) iters, \(result.completedSamples)/\(result.expectedSamples) samples | \(result.workload.family) | \(result.workload.scenario) | \(result.workload.rowCount) | \(result.workload.witnessLength) | \(result.workload.matrixCount) | \(result.workload.totalNNZ) | \(formatDensity(result.workload.nonZeroDensity)) | \(result.workload.maxGateDegree) | \(result.peakRSSBytes) | \(result.gpuFamilyTag) | \(result.publicProofBytes) | \(result.resumeArtifactBytes) | \(result.totalExportBytes) | \(formatPair(result.seedOne)) | \(formatPair(result.seedTwo)) | \(formatPair(result.fuse)) | \(formatPair(result.seal)) | \(formatPair(result.cpuVerify)) | \(formatPair(result.assistedVerify)) | \(formatPair(result.assistedVerifyGPU)) | \(result.verificationParity.rawValue) | \(result.dispatchTracePath ?? "") | \(result.parityNote ?? "") | \(result.fuseFailure ?? "") |"
            )
        }
        lines.append("")
        lines.append("## PCS Status")
        lines.append("")
        lines.append("| Workload | State | Progress | Vars | Evals | Peak RSS | GPU | CPU Commit p50/p95 | CPU Open p50/p95 | Metal Commit p50/p95 | Metal Open p50/p95 | Metal Commit GPU p50/p95 | Metal Open GPU p50/p95 | Commit TG Widths | Open TG Widths | Counters | Note |")
        lines.append("| --- | --- | --- | ---: | ---: | ---: | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |")
        for result in report.pcsWorkloads {
            lines.append(
                "| \(result.workload.name) | \(result.status.rawValue) | \(result.completedIterations)/\(result.expectedIterations) iters, \(result.completedSamples)/\(result.expectedSamples) samples | \(result.workload.numVars) | \(1 << result.workload.numVars) | \(result.peakRSSBytes) | \(result.gpuFamilyTag) | \(formatPair(result.cpuCommit)) | \(formatPair(result.cpuOpen)) | \(formatPair(result.metalCommit)) | \(formatPair(result.metalOpen)) | \(formatPair(result.metalCommitGPU)) | \(formatPair(result.metalOpenGPU)) | \(formatWidths(result.metalCommitThreadgroupWidths)) | \(formatWidths(result.metalOpenThreadgroupWidths)) | \(formatCounterStatus(available: result.counterSamplingAvailable, captured: result.metalCommitCountersCaptured && result.metalOpenCountersCaptured)) | \(result.note ?? "") |"
            )
        }
        lines.append("")
        lines.append("## Verifier Stages")
        lines.append("")
        lines.append("| Workload | Stage | State | Progress | Peak RSS | GPU | CPU Verify p50/p95 | Assisted Verify p50/p95 | Assisted GPU p50/p95 | Dispatches | Counters | Trace | Note |")
        lines.append("| --- | --- | --- | --- | ---: | --- | --- | --- | --- | ---: | --- | --- | --- |")
        for result in report.verifierWorkloads {
            lines.append(
                "| \(result.workload.name) | \(result.workload.stage.rawValue) | \(result.status.rawValue) | \(result.completedIterations)/\(result.expectedIterations) iters, \(result.completedSamples)/\(result.expectedSamples) samples | \(result.peakRSSBytes) | \(result.gpuFamilyTag) | \(formatPair(result.cpuVerify)) | \(formatPair(result.assistedVerify)) | \(formatPair(result.assistedVerifyGPU)) | \(result.dispatchCount) | \(formatCounterStatus(available: result.counterSamplingAvailable, captured: result.dispatchSummaries.allSatisfy(\.counterSamplesCaptured))) | \(result.dispatchTracePath ?? "") | \(result.note ?? "") |"
            )
        }
        lines.append("")
        lines.append("## Verifier Dispatch Summary")
        lines.append("")
        lines.append("| Workload | Stage | Dispatch | Kernel | Samples | CPU p50/p95 | GPU p50/p95 | Exec Widths | TG Widths | Counters |")
        lines.append("| --- | --- | --- | --- | ---: | --- | --- | --- | --- | --- |")
        for result in report.verifierWorkloads {
            for summary in result.dispatchSummaries {
                lines.append(
                    "| \(result.workload.name) | \(summary.stage) | \(summary.dispatchLabel) | \(summary.kernelFamily) | \(summary.sampleCount) | \(formatPair(summary.cpu)) | \(formatPair(summary.gpu)) | \(formatWidths(summary.threadExecutionWidths)) | \(formatWidths(summary.threadgroupWidths)) | \(formatCounterStatus(available: summary.counterSamplingAvailable, captured: summary.counterSamplesCaptured)) |"
                )
            }
        }
        lines.append("")
        return lines.joined(separator: "\n")
    }

    private static func pendingSealResult(
        for workload: SealWorkload,
        configuration: BenchmarkConfiguration
    ) -> SealBenchmarkResult {
        SealBenchmarkResult(
            workload: workload,
            status: .pending,
            completedIterations: 0,
            expectedIterations: configuration.iterations + configuration.warmups,
            completedSamples: 0,
            expectedSamples: configuration.iterations,
            gpuFamilyTag: "unavailable",
            gpuName: "unavailable",
            publicProofBytes: 0,
            resumeArtifactBytes: 0,
            totalExportBytes: 0,
            peakRSSBytes: 0,
            seedOne: nil,
            seedTwo: nil,
            fuse: nil,
            seal: nil,
            cpuVerify: nil,
            assistedVerify: nil,
            assistedVerifyGPU: nil,
            verifyMode: "cpu-only",
            verificationParity: .unavailable,
            dispatchTracePath: nil,
            parityNote: nil,
            fuseFailure: nil
        )
    }

    private static func pendingPCSResult(
        for workload: PCSWorkload,
        configuration: BenchmarkConfiguration
    ) -> PCSBenchmarkResult {
        PCSBenchmarkResult(
            workload: workload,
            status: .pending,
            completedIterations: 0,
            expectedIterations: configuration.iterations + configuration.warmups,
            completedSamples: 0,
            expectedSamples: configuration.iterations,
            peakRSSBytes: 0,
            cpuCommit: nil,
            cpuOpen: nil,
            metalCommit: nil,
            metalOpen: nil,
            metalCommitGPU: nil,
            metalOpenGPU: nil,
            metalCommitThreadgroupWidths: [],
            metalOpenThreadgroupWidths: [],
            counterSamplingAvailable: false,
            metalCommitCountersCaptured: false,
            metalOpenCountersCaptured: false,
            gpuFamilyTag: "unavailable",
            gpuName: "unavailable",
            note: nil
        )
    }

    private static func pendingVerifierResult(
        for workload: VerifierWorkload,
        configuration: BenchmarkConfiguration
    ) -> VerifierBenchmarkResult {
        VerifierBenchmarkResult(
            workload: workload,
            status: .pending,
            completedIterations: 0,
            expectedIterations: configuration.iterations + configuration.warmups,
            completedSamples: 0,
            expectedSamples: configuration.iterations,
            peakRSSBytes: 0,
            cpuVerify: nil,
            assistedVerify: nil,
            assistedVerifyGPU: nil,
            assistanceMode: "cpu-only",
            counterSamplingAvailable: false,
            dispatchCount: 0,
            dispatchSummaries: [],
            dispatchTracePath: nil,
            gpuFamilyTag: "unavailable",
            gpuName: "unavailable",
            note: nil
        )
    }

    private static func makeSealResult(
        workload: SealWorkload,
        status: BenchmarkEntryStatus,
        completedIterations: Int,
        expectedIterations: Int,
        completedSamples: Int,
        expectedSamples: Int,
        gpuFamilyTag: String,
        gpuName: String,
        publicProofBytes: Int,
        resumeArtifactBytes: Int,
        totalExportBytes: Int,
        peakRSSBytes: UInt64,
        seedOneSamples: [Double],
        seedTwoSamples: [Double],
        fuseSamples: [Double],
        sealSamples: [Double],
        cpuVerifySamples: [Double],
        assistedVerifySamples: [Double],
        assistedVerifyGPUSamples: [Double],
        verifyMode: String,
        verificationParity: HachiVerificationParity,
        dispatchTracePath: String?,
        parityNote: String?,
        fuseFailure: String?
    ) -> SealBenchmarkResult {
        SealBenchmarkResult(
            workload: workload,
            status: status,
            completedIterations: completedIterations,
            expectedIterations: expectedIterations,
            completedSamples: completedSamples,
            expectedSamples: expectedSamples,
            gpuFamilyTag: gpuFamilyTag,
            gpuName: gpuName,
            publicProofBytes: publicProofBytes,
            resumeArtifactBytes: resumeArtifactBytes,
            totalExportBytes: totalExportBytes,
            peakRSSBytes: peakRSSBytes,
            seedOne: seedOneSamples.isEmpty ? nil : summarize(seedOneSamples),
            seedTwo: seedTwoSamples.isEmpty ? nil : summarize(seedTwoSamples),
            fuse: fuseSamples.isEmpty ? nil : summarize(fuseSamples),
            seal: sealSamples.isEmpty ? nil : summarize(sealSamples),
            cpuVerify: cpuVerifySamples.isEmpty ? nil : summarize(cpuVerifySamples),
            assistedVerify: assistedVerifySamples.isEmpty ? nil : summarize(assistedVerifySamples),
            assistedVerifyGPU: assistedVerifyGPUSamples.isEmpty ? nil : summarize(assistedVerifyGPUSamples),
            verifyMode: verifyMode,
            verificationParity: verificationParity,
            dispatchTracePath: dispatchTracePath,
            parityNote: parityNote,
            fuseFailure: fuseFailure
        )
    }

    private static func makePCSResult(
        workload: PCSWorkload,
        status: BenchmarkEntryStatus,
        completedIterations: Int,
        expectedIterations: Int,
        completedSamples: Int,
        expectedSamples: Int,
        peakRSSBytes: UInt64,
        cpuCommitSamples: [Double],
        cpuOpenSamples: [Double],
        metalCommitSamples: [Double],
        metalOpenSamples: [Double],
        metalCommitGPUSamples: [Double],
        metalOpenGPUSamples: [Double],
        metalCommitThreadgroupWidths: [Int],
        metalOpenThreadgroupWidths: [Int],
        counterSamplingAvailable: Bool,
        metalCommitCountersCaptured: Bool,
        metalOpenCountersCaptured: Bool,
        gpuFamilyTag: String,
        gpuName: String,
        note: String?
    ) -> PCSBenchmarkResult {
        PCSBenchmarkResult(
            workload: workload,
            status: status,
            completedIterations: completedIterations,
            expectedIterations: expectedIterations,
            completedSamples: completedSamples,
            expectedSamples: expectedSamples,
            peakRSSBytes: peakRSSBytes,
            cpuCommit: cpuCommitSamples.isEmpty ? nil : summarize(cpuCommitSamples),
            cpuOpen: cpuOpenSamples.isEmpty ? nil : summarize(cpuOpenSamples),
            metalCommit: metalCommitSamples.isEmpty ? nil : summarize(metalCommitSamples),
            metalOpen: metalOpenSamples.isEmpty ? nil : summarize(metalOpenSamples),
            metalCommitGPU: metalCommitGPUSamples.isEmpty ? nil : summarize(metalCommitGPUSamples),
            metalOpenGPU: metalOpenGPUSamples.isEmpty ? nil : summarize(metalOpenGPUSamples),
            metalCommitThreadgroupWidths: metalCommitThreadgroupWidths,
            metalOpenThreadgroupWidths: metalOpenThreadgroupWidths,
            counterSamplingAvailable: counterSamplingAvailable,
            metalCommitCountersCaptured: metalCommitCountersCaptured,
            metalOpenCountersCaptured: metalOpenCountersCaptured,
            gpuFamilyTag: gpuFamilyTag,
            gpuName: gpuName,
            note: note
        )
    }

    private static func makeVerifierResult(
        workload: VerifierWorkload,
        status: BenchmarkEntryStatus,
        completedIterations: Int,
        expectedIterations: Int,
        completedSamples: Int,
        expectedSamples: Int,
        peakRSSBytes: UInt64,
        cpuSamples: [Double],
        assistedSamples: [Double],
        assistedGPUSamples: [Double],
        assistanceMode: String,
        counterSamplingAvailable: Bool,
        dispatchSummaries: [DispatchAggregate],
        dispatchTracePath: String?,
        gpuFamilyTag: String,
        gpuName: String,
        note: String?
    ) -> VerifierBenchmarkResult {
        VerifierBenchmarkResult(
            workload: workload,
            status: status,
            completedIterations: completedIterations,
            expectedIterations: expectedIterations,
            completedSamples: completedSamples,
            expectedSamples: expectedSamples,
            peakRSSBytes: peakRSSBytes,
            cpuVerify: cpuSamples.isEmpty ? nil : summarize(cpuSamples),
            assistedVerify: assistedSamples.isEmpty ? nil : summarize(assistedSamples),
            assistedVerifyGPU: assistedGPUSamples.isEmpty ? nil : summarize(assistedGPUSamples),
            assistanceMode: assistanceMode,
            counterSamplingAvailable: counterSamplingAvailable,
            dispatchCount: dispatchSummaries.reduce(0) { $0 + $1.sampleCount },
            dispatchSummaries: dispatchSummaries,
            dispatchTracePath: dispatchTracePath,
            gpuFamilyTag: gpuFamilyTag,
            gpuName: gpuName,
            note: note
        )
    }

    private static func samplePCSEvaluations(numVars: Int) -> [Fq] {
        let count = 1 << numVars
        var evaluations = [Fq]()
        evaluations.reserveCapacity(count)
        for index in 0..<count {
            let sample = (index * 37 + numVars * 19 + 5) % 65521
            evaluations.append(Fq(UInt64(sample)))
        }
        return evaluations
    }

    private static func samplePCSQueryPositions(codewordLength: Int) -> [UInt32] {
        let queryCount = max(8, min(64, max(1, codewordLength / 8)))
        return (0..<queryCount).map { index in
            UInt32((index * 17 + 3) % max(1, codewordLength))
        }
    }

    private static func buildCPUCommitArtifact(
        evals: [Fq],
        blowup: Int
    ) -> PCSCPUCommitArtifact {
        let base = evals.isEmpty ? [Fq.zero] : evals
        let codeword = (0..<(base.count * blowup)).map { base[$0 % base.count] }
        let merkleLevels = buildCPUMerkleLevels(codeword: codeword)
        return PCSCPUCommitArtifact(codeword: codeword, merkleLevels: merkleLevels)
    }

    private static func buildCPUMerkleLevels(codeword: [Fq]) -> [[[UInt8]]] {
        var levels = [codeword.map(cpuPCSLeafHash)]
        var current = levels[0]
        while current.count > 1 {
            if current.count % 2 != 0, let last = current.last {
                current.append(last)
            }
            current = stride(from: 0, to: current.count, by: 2).map { index in
                cpuPCSParentHash(left: current[index], right: current[index + 1])
            }
            levels.append(current)
        }
        return levels
    }

    private static func cpuPCSLeafHash(_ value: Fq) -> [UInt8] {
        Array(SHA256.hash(data: Data([0x00] + value.toBytes())))
    }

    private static func cpuPCSParentHash(left: [UInt8], right: [UInt8]) -> [UInt8] {
        Array(SHA256.hash(data: Data(left + right)))
    }

    private static func gatherCPUQueryValues(
        codeword: [Fq],
        positions: [UInt32]
    ) -> [Fq] {
        positions.map { codeword[Int($0)] }
    }

    private static func benchmarkMetalPCSIteration(
        evals: [Fq],
        positions: [UInt32],
        context: MetalContext,
        blowup: Int
    ) throws -> PCSMetalIteration {
        try autoreleasepool {
            let codewordLength = max(1, evals.count * blowup)
            guard let evalBuffer = context.uploadFieldElements(evals),
                  let codewordBuffer = context.makeSharedBuffer(
                    length: codewordLength * MemoryLayout<UInt32>.size * 2
                  ),
                  let leafBuffer = context.makeSharedBuffer(length: codewordLength * 32),
                  let positionsBuffer = context.makeSharedBuffer(
                    length: positions.count * MemoryLayout<UInt32>.size
                  ),
                  let outputBuffer = context.makeSharedBuffer(
                    length: positions.count * MemoryLayout<UInt32>.size * 2
                  ) else {
                throw BenchmarkError.invalidWorkload("pcs-metal-allocation")
            }

            let positionsPointer = positionsBuffer.contents().bindMemory(
                to: UInt32.self,
                capacity: positions.count
            )
            for (index, value) in positions.enumerated() {
                positionsPointer[index] = value
            }

            let dispatcher = KernelDispatcher(context: context)
            let encodeTiming = try dispatcher.dispatchSealEncodeTimed(
                evalBuffer: evalBuffer,
                codewordBuffer: codewordBuffer,
                n: evals.count,
                blowup: blowup
            )
            let leafTiming = try dispatcher.dispatchMerkleHashTimed(
                leavesBuffer: codewordBuffer,
                nodesBuffer: leafBuffer,
                numLeaves: codewordLength
            )

            var commitCPU = encodeTiming.cpuMilliseconds + leafTiming.cpuMilliseconds
            var commitGPU = sumGPU(encodeTiming.gpuMilliseconds, leafTiming.gpuMilliseconds)
            var commitThreadgroupWidths = Set([encodeTiming.threadgroupWidth, leafTiming.threadgroupWidth])
            var commitCountersCaptured = encodeTiming.counterSampleCaptured && leafTiming.counterSampleCaptured
            var currentLevel = readPCSHashes(from: leafBuffer, count: codewordLength)
            while currentLevel.count > 1 {
                if currentLevel.count % 2 != 0, let last = currentLevel.last {
                    currentLevel.append(last)
                }
                let parentCount = currentLevel.count / 2
                guard let childBuffer = context.makeSharedBuffer(length: currentLevel.count * 32),
                      let parentBuffer = context.makeSharedBuffer(length: parentCount * 32) else {
                    throw BenchmarkError.invalidWorkload("pcs-metal-merkle-parent")
                }
                writePCSHashes(currentLevel, to: childBuffer)
                let parentTiming = try dispatcher.dispatchMerkleParentTimed(
                    childBuffer: childBuffer,
                    parentBuffer: parentBuffer,
                    numParents: parentCount
                )
                commitCPU += parentTiming.cpuMilliseconds
                commitGPU = sumGPU(commitGPU, parentTiming.gpuMilliseconds)
                commitThreadgroupWidths.insert(parentTiming.threadgroupWidth)
                commitCountersCaptured = commitCountersCaptured && parentTiming.counterSampleCaptured
                currentLevel = readPCSHashes(from: parentBuffer, count: parentCount)
            }

            let queryTiming = try dispatcher.dispatchSealQueryTimed(
                codewordBuffer: codewordBuffer,
                positionsBuffer: positionsBuffer,
                outputBuffer: outputBuffer,
                codewordLength: codewordLength,
                numQueries: positions.count
            )
            let queryPointer = outputBuffer.contents().bindMemory(
                to: UInt32.self,
                capacity: positions.count * 2
            )
            _ = MetalFieldPacking.unpackFieldElementsSoA(
                Array(UnsafeBufferPointer(start: queryPointer, count: positions.count * 2)),
                count: positions.count
            )

            return PCSMetalIteration(
                commitCPU: commitCPU,
                openCPU: queryTiming.cpuMilliseconds,
                commitGPU: commitGPU,
                openGPU: queryTiming.gpuMilliseconds,
                commitThreadgroupWidths: commitThreadgroupWidths.sorted(),
                openThreadgroupWidths: [queryTiming.threadgroupWidth],
                commitCounterSamplesCaptured: commitCountersCaptured,
                openCounterSamplesCaptured: queryTiming.counterSampleCaptured
            )
        }
    }

    private static func readPCSHashes(from buffer: MTLBuffer, count: Int) -> [[UInt8]] {
        let pointer = buffer.contents().bindMemory(to: UInt32.self, capacity: count * 8)
        return (0..<count).map { hashIndex in
            var bytes = [UInt8]()
            bytes.reserveCapacity(32)
            let base = hashIndex * 8
            for wordOffset in 0..<8 {
                let word = pointer[base + wordOffset].bigEndian
                withUnsafeBytes(of: word) { bytes.append(contentsOf: $0) }
            }
            return bytes
        }
    }

    private static func writePCSHashes(_ hashes: [[UInt8]], to buffer: MTLBuffer) {
        let pointer = buffer.contents().bindMemory(to: UInt32.self, capacity: hashes.count * 8)
        for (hashIndex, hash) in hashes.enumerated() {
            precondition(hash.count == 32)
            for wordOffset in 0..<8 {
                let start = wordOffset * 4
                let word = hash[start..<(start + 4)].withUnsafeBytes { raw -> UInt32 in
                    raw.load(as: UInt32.self).bigEndian
                }
                pointer[hashIndex * 8 + wordOffset] = word
            }
        }
    }

    private static func sumGPU(_ lhs: Double?, _ rhs: Double?) -> Double? {
        guard let lhs, let rhs else { return nil }
        return lhs + rhs
    }

    private static func totalGPUMilliseconds(
        for samples: [MetalDispatchTraceSample]
    ) -> Double? {
        let values = samples.compactMap(\.gpuMilliseconds)
        guard values.isEmpty == false else { return nil }
        return values.reduce(0, +)
    }

    private static func aggregateDispatchSummaries(
        _ samples: [MetalDispatchTraceSample]
    ) -> [DispatchAggregate] {
        let grouped = Dictionary(grouping: samples) {
            "\($0.stage)|\($0.dispatchLabel)|\($0.kernelFamily)"
        }
        return grouped.values.compactMap { group in
            guard let first = group.first else { return nil }
            let cpuSamples = group.map(\.cpuMilliseconds)
            let gpuSamples = group.compactMap(\.gpuMilliseconds)
            return DispatchAggregate(
                stage: first.stage,
                dispatchLabel: first.dispatchLabel,
                kernelFamily: first.kernelFamily,
                sampleCount: group.count,
                cpu: summarize(cpuSamples),
                gpu: gpuSamples.isEmpty ? nil : summarize(gpuSamples),
                threadExecutionWidths: Array(Set(group.map(\.threadExecutionWidth))).sorted(),
                threadgroupWidths: Array(Set(group.map(\.threadgroupWidth))).sorted(),
                counterSamplingAvailable: group.contains(where: \.counterSamplingAvailable),
                counterSamplesCaptured: group.allSatisfy(\.counterSampleCaptured)
            )
        }
        .sorted {
            if $0.stage == $1.stage {
                return $0.dispatchLabel < $1.dispatchLabel
            }
            return $0.stage < $1.stage
        }
    }

    private static func summarize(_ samples: [Double]) -> TimingSummary {
        precondition(samples.isEmpty == false, "benchmark produced no samples")
        let sorted = samples.sorted()
        let count = Double(sorted.count)
        let mean = sorted.reduce(0, +) / count
        let median = percentile(sorted, q: 0.50)
        return TimingSummary(
            samples: sorted.count,
            meanMilliseconds: mean,
            medianMilliseconds: median,
            p90Milliseconds: percentile(sorted, q: 0.90),
            p95Milliseconds: percentile(sorted, q: 0.95),
            p99Milliseconds: percentile(sorted, q: 0.99),
            minMilliseconds: sorted.first ?? 0,
            maxMilliseconds: sorted.last ?? 0
        )
    }

    private static func percentile(_ sorted: [Double], q: Double) -> Double {
        guard sorted.isEmpty == false else { return 0 }
        let rank = Int(ceil(q * Double(sorted.count)))
        let index = min(max(rank - 1, 0), sorted.count - 1)
        return sorted[index]
    }

    private static func timed<T>(_ body: () async -> T) async -> TimedResult<T> {
        let start = DispatchTime.now().uptimeNanoseconds
        let value = await body()
        let elapsed = DispatchTime.now().uptimeNanoseconds - start
        return TimedResult(value: value, milliseconds: Double(elapsed) / 1_000_000.0)
    }

    private static func timedThrowing<T>(_ body: () async throws -> T) async throws -> TimedResult<T> {
        let start = DispatchTime.now().uptimeNanoseconds
        let value = try await body()
        let elapsed = DispatchTime.now().uptimeNanoseconds - start
        return TimedResult(value: value, milliseconds: Double(elapsed) / 1_000_000.0)
    }

    private static func timedVerifierStage<T>(_ body: () throws -> T) throws -> TimedResult<T> {
        let start = DispatchTime.now().uptimeNanoseconds
        let value = try body()
        let elapsed = DispatchTime.now().uptimeNanoseconds - start
        return TimedResult(value: value, milliseconds: Double(elapsed) / 1_000_000.0)
    }

    private static func makeSealScaffold(workload: SealWorkload) -> SealWorkloadScaffold {
        let sourceLanes = workload.sourceLanes.enumerated().map { index, lane in
            LaneDescriptor(
                index: UInt32(index),
                name: lane.name,
                width: lane.width,
                length: UInt32(workload.rowCount)
            )
        }
        let derivedLane = LaneDescriptor(
            index: UInt32(sourceLanes.count),
            name: "derivedProducts",
            width: .field,
            length: UInt32(workload.rowCount)
        )
        let allLanes = sourceLanes + [derivedLane]
        let layout = ColumnLayout(publicInputCount: workload.publicInputCount, lanes: allLanes)
        let relation = makeRelation(workload: workload, layout: layout)
        let totalNNZ = relation.matrices.reduce(0) { $0 + $1.nnz }
        let densityDenominator = max(1, relation.m * relation.n * relation.matrices.count)
        let relationDensity = Double(totalNNZ) / Double(densityDenominator)
        let enrichedWorkload = SealWorkload(
            name: workload.name,
            family: workload.family,
            scenario: workload.scenario,
            relationModel: workload.relationModel,
            densityModel: workload.densityModel,
            rowCount: workload.rowCount,
            publicInputCount: workload.publicInputCount,
            sourceLanes: workload.sourceLanes,
            leftTermsPerRow: workload.leftTermsPerRow,
            rightTermsPerRow: workload.rightTermsPerRow,
            witnessLength: allLanes.reduce(0) { $0 + Int($1.length) },
            matrixCount: relation.matrices.count,
            totalNNZ: totalNNZ,
            nonZeroDensity: relationDensity,
            maxGateDegree: relation.gates.map { $0.matrixIndices.count }.max() ?? 0,
            witnessBitWidth: sourceLanes.map { $0.width.bitWidth }.max() ?? 0
        )
        return SealWorkloadScaffold(
            workload: enrichedWorkload,
            relation: relation,
            sourceLanes: sourceLanes,
            derivedLane: derivedLane,
            layout: layout,
            publicInputs: publicInputs(for: enrichedWorkload)
        )
    }

    private static func makeSealFixture(scaffold: SealWorkloadScaffold) throws -> SealWorkloadFixture {
        let compiledShape = try makeCompiledShape(
            workload: scaffold.workload,
            relation: scaffold.relation,
            lanes: scaffold.allLanes
        )
        return SealWorkloadFixture(
            workload: scaffold.workload,
            compiledShape: compiledShape,
            sourceLanes: scaffold.sourceLanes,
            derivedLane: scaffold.derivedLane,
            layout: scaffold.layout,
            publicInputs: scaffold.publicInputs
        )
    }

    private static func makeSealInputs(
        fixture: SealWorkloadFixture,
        seedOne: UInt64,
        seedTwo: UInt64
    ) throws -> SealBenchmarkInputs {
        let firstWitness = try makeWitness(fixture: fixture, seed: seedOne)
        let secondWitness = try makeWitness(fixture: fixture, seed: seedTwo)
        return SealBenchmarkInputs(
            publicInputs: fixture.publicInputs,
            firstWitness: firstWitness,
            secondWitness: secondWitness
        )
    }

    private static func makeCompiledShape(
        workload: SealWorkload,
        relation: CCSRelation,
        lanes: [LaneDescriptor]
    ) throws -> CompiledShape {
        let compiler = ShapeCompiler(
            config: .init(
                signShapePack: signer,
                targetGPUFamilies: ["benchmark"],
                defaultArity: 2
            )
        )
        let pack = try compiler.compile(
            name: workload.name,
            relation: relation,
            lanes: lanes,
            publicHeaderByteCount: UInt32(clamping: workload.publicInputCount * MemoryLayout<UInt64>.size)
        )
        let shape = Shape(
            digest: pack.shapeDigest,
            name: workload.name,
            relation: relation,
            lanes: lanes,
            publicHeaderSize: workload.publicInputCount * MemoryLayout<UInt64>.size,
            defaultArity: 2
        )
        return try CompiledShape(shape: shape, shapePack: pack, verifySignature: verifier)
    }

    private static func makeRelation(workload: SealWorkload, layout: ColumnLayout) -> CCSRelation {
        let leftMatrix = makeOperandMatrix(workload: workload, layout: layout, side: .left)
        let rightMatrix = makeOperandMatrix(workload: workload, layout: layout, side: .right)
        let outputMatrix = makeOutputMatrix(workload: workload, layout: layout)

        return CCSRelation(
            m: workload.rowCount,
            n: layout.totalColumns,
            nPublic: workload.publicInputCount,
            matrices: [leftMatrix, rightMatrix, outputMatrix],
            gates: [
                CCSGate(coefficient: .one, matrixIndices: [0]),
                CCSGate(coefficient: .one, matrixIndices: [1]),
                CCSGate(coefficient: -Fq.one, matrixIndices: [2]),
            ]
        )
    }

    private static func makeOperandMatrix(
        workload: SealWorkload,
        layout: ColumnLayout,
        side: OperandSide
    ) -> SparseMatrix {
        var rowPtr: [UInt32] = [0]
        var colIdx: [UInt32] = []
        var values: [Fq] = []
        var runningNNZ = 0
        let tapCount = side == .left ? workload.leftTermsPerRow : workload.rightTermsPerRow

        for row in 0..<workload.rowCount {
            var rowEntries: [Int: Fq] = [:]
            for tap in 0..<tapCount {
                let coefficient = coefficientFor(row: row, tap: tap, side: side)
                if tap < workload.publicInputCount {
                    let publicIndex = (tap + side.publicOffset) % workload.publicInputCount
                    rowEntries[publicIndex, default: .zero] += coefficient
                    continue
                }

                let sourceTap = tap - workload.publicInputCount
                let laneIndex = selectedSourceLane(
                    row: row,
                    tap: sourceTap,
                    side: side,
                    workload: workload
                )
                let sourceRow = selectedSourceRow(
                    row: row,
                    tap: sourceTap,
                    laneIndex: laneIndex,
                    side: side,
                    workload: workload
                )
                let column = layout.column(forLane: laneIndex, position: sourceRow)
                rowEntries[column, default: .zero] += coefficient
            }

            let sortedEntries = rowEntries
                .filter { !$0.value.isZero }
                .sorted { $0.key < $1.key }
            for (column, value) in sortedEntries {
                colIdx.append(UInt32(column))
                values.append(value)
                runningNNZ += 1
            }
            rowPtr.append(UInt32(runningNNZ))
        }

        return SparseMatrix(
            rows: workload.rowCount,
            cols: layout.totalColumns,
            rowPtr: rowPtr,
            colIdx: colIdx,
            values: values
        )
    }

    private static func makeOutputMatrix(workload: SealWorkload, layout: ColumnLayout) -> SparseMatrix {
        var rowPtr: [UInt32] = [0]
        var colIdx: [UInt32] = []
        var values: [Fq] = []

        for row in 0..<workload.rowCount {
            colIdx.append(UInt32(layout.column(forLane: workload.sourceLanes.count, position: row)))
            values.append(.one)
            rowPtr.append(UInt32(colIdx.count))
        }

        return SparseMatrix(
            rows: workload.rowCount,
            cols: layout.totalColumns,
            rowPtr: rowPtr,
            colIdx: colIdx,
            values: values
        )
    }

    private static func coefficientFor(row: Int, tap: Int, side: OperandSide) -> Fq {
        let sideBias = side == .left ? 17 : 43
        return Fq(UInt64(((row + 1) * (tap + 3) + sideBias) % 97 + 1))
    }

    private static func selectedSourceLane(
        row: Int,
        tap: Int,
        side: OperandSide,
        workload: SealWorkload
    ) -> Int {
        switch workload.densityModel {
        case .sparse:
            return (row + tap + side.publicOffset) % workload.sourceLanes.count
        case .dense:
            return (tap + side.publicOffset) % workload.sourceLanes.count
        }
    }

    private static func selectedSourceRow(
        row: Int,
        tap: Int,
        laneIndex: Int,
        side: OperandSide,
        workload: SealWorkload
    ) -> Int {
        switch workload.densityModel {
        case .sparse:
            let stride = side == .left ? 3 : 5
            return (row + tap * stride + laneIndex * 7) % workload.rowCount
        case .dense:
            let stride = side == .left ? 5 : 9
            let window = max(8, workload.rowCount / 3)
            return (row + (tap * stride + laneIndex * 11) % window) % workload.rowCount
        }
    }

    private static func publicInputs(for workload: SealWorkload) -> [Fq] {
        [
            Fq(UInt64(workload.rowCount * 3 + 11)),
            Fq(UInt64(workload.sourceLanes.count * 19 + workload.leftTermsPerRow + workload.rightTermsPerRow))
        ]
    }

    private static func packedPublicHeader(_ publicInputs: [Fq]) -> Data {
        Data(publicInputs.flatMap { $0.toBytes() })
    }

    private static func makeWitness(
        fixture: SealWorkloadFixture,
        seed: UInt64
    ) throws -> Witness {
        var sourceWitnessLanes: [WitnessLane] = []
        sourceWitnessLanes.reserveCapacity(fixture.sourceLanes.count)

        for (laneIndex, descriptor) in fixture.sourceLanes.enumerated() {
            let values = (0..<fixture.workload.rowCount).map { row in
                sampleLaneValue(
                    seed: seed,
                    laneIndex: laneIndex,
                    row: row,
                    width: descriptor.width
                )
            }
            sourceWitnessLanes.append(WitnessLane(descriptor: descriptor, values: values))
        }

        var partialAssignment = [Fq](repeating: .zero, count: fixture.compiledShape.shape.relation.n)
        for (index, value) in fixture.publicInputs.enumerated() {
            partialAssignment[index] = value
        }
        for (laneIndex, lane) in sourceWitnessLanes.enumerated() {
            for (row, value) in lane.values.enumerated() {
                partialAssignment[fixture.layout.column(forLane: laneIndex, position: row)] = value
            }
        }

        let relation = fixture.compiledShape.shape.relation
        let leftValues = relation.matrices[0].matvec(partialAssignment)
        let rightValues = relation.matrices[1].matvec(partialAssignment)
        let derivedValues = zip(leftValues, rightValues).map(+)
        let derivedWitness = WitnessLane(descriptor: fixture.derivedLane, values: derivedValues)

        let witness = Witness(lanes: sourceWitnessLanes + [derivedWitness])
        let assignment = fixture.publicInputs + witness.flatten()
        guard relation.isSatisfied(by: assignment) else {
            throw BenchmarkError.invalidWorkload(fixture.workload.name)
        }
        return witness
    }

    private static func sampleLaneValue(
        seed: UInt64,
        laneIndex: Int,
        row: Int,
        width: LaneWidth
    ) -> Fq {
        let mixed = seed
            &+ UInt64(laneIndex * 97)
            &+ UInt64(row * 131)
            &+ UInt64((laneIndex + 1) * (row + 3))
        switch width {
        case .bit:
            return Fq(mixed & 1)
        case .u8:
            return Fq(mixed % 127)
        case .u16:
            return Fq(mixed % 127)
        case .u32:
            return Fq(mixed % 127)
        case .u64, .field:
            return Fq(mixed % 127)
        case .bounded:
            return Fq(mixed % 127)
        }
    }

    private static func samplePolynomial(seed: UInt64, numVars: Int) -> MultilinearPoly {
        let evalCount = 1 << numVars
        return MultilinearPoly(
            numVars: numVars,
            evals: (0..<evalCount).map { index in
                Fq((seed &+ UInt64(index * 5) &+ 1) % 4096)
            }
        )
    }

    private static func samplePoint(seed: UInt64, numVars: Int) -> [Fq] {
        (0..<numVars).map { index in
            Fq((seed &+ UInt64(index * 13) &+ 7) % 97)
        }
    }

    private static func sampleVerifierPiCCSInput(seed: UInt64) -> PiCCS.Input {
        let matrix = SparseMatrix(
            rows: 4,
            cols: 4,
            rowPtr: [0, 1, 2, 3, 4],
            colIdx: [0, 1, 2, 3],
            values: (0..<4).map { offset in
                Fq((seed &+ UInt64(offset * 11) &+ 3) % 257)
            }
        )
        let relation = CCSRelation(
            m: 4,
            n: 4,
            nPublic: 0,
            matrices: [matrix],
            gates: [CCSGate(coefficient: .zero, matrixIndices: [0])]
        )
        return PiCCS.Input(
            relation: relation,
            publicInputs: [],
            witness: (0..<4).map { offset in
                Fq((seed &+ UInt64(offset * 7) &+ 5) % 257)
            },
            relaxationFactor: .one
        )
    }

    private static func sampleVerifierPiRLCInputs(key: AjtaiKey, seed: UInt64) -> [PiRLC.Input] {
        (0..<2).map { inputIndex in
            let witness = (0..<4).map { ringIndex in
                sampleVerifierRing(seed: seed &+ UInt64(inputIndex) &* 17, index: UInt64(ringIndex))
            }
            return PiRLC.Input(
                commitment: AjtaiCommitter.commit(key: key, witness: witness),
                witness: witness,
                publicInputs: [
                    Fq(seed &+ UInt64(inputIndex + 1)),
                    Fq(seed &+ UInt64(inputIndex + 9))
                ],
                ccsEvaluations: [
                    Fq(seed &+ UInt64(inputIndex + 11)),
                    Fq(seed &+ UInt64(inputIndex + 21))
                ],
                relaxationFactor: Fq(seed &+ UInt64(inputIndex + 2)),
                errorTerms: [sampleVerifierRing(seed: seed &+ 100 &+ UInt64(inputIndex), index: 0)]
            )
        }
    }

    private static func sampleVerifierPiDECInput(key: AjtaiKey, seed: UInt64) -> PiDEC.Input {
        let witness = (0..<3).map { ringIndex in
            sampleVerifierBoundedRing(
                seed: seed,
                index: UInt64(ringIndex),
                maxCoefficient: 1 << 13
            )
        }
        return PiDEC.Input(
            witness: witness,
            commitment: AjtaiCommitter.commit(key: key, witness: witness),
            key: key,
            decompBase: 2,
            decompLimbs: 13
        )
    }

    private static func sampleVerifierRing(seed: UInt64, index: UInt64) -> RingElement {
        RingElement(coeffs: (0..<RingElement.degree).map { coeff in
            Fq((seed &+ UInt64(coeff) &* 17 &+ index &* 31) % Fq.modulus)
        })
    }

    private static func sampleVerifierBoundedRing(
        seed: UInt64,
        index: UInt64,
        maxCoefficient: UInt64
    ) -> RingElement {
        RingElement(coeffs: (0..<RingElement.degree).map { coeff in
            Fq((seed &+ UInt64(coeff) &* 17 &+ index &* 31) % maxCoefficient)
        })
    }

    private static func peakResidentSetSizeBytes() -> UInt64 {
        var usage = rusage()
        guard getrusage(RUSAGE_SELF, &usage) == 0 else { return 0 }
        return UInt64(usage.ru_maxrss)
    }

    private static func defaultOutputDirectory() -> URL {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        let stamp = formatter.string(from: Date())
            .replacingOccurrences(of: ":", with: "-")
        return packageRootDirectory()
            .appendingPathComponent("artifacts", isDirectory: true)
            .appendingPathComponent("benchmarks", isDirectory: true)
            .appendingPathComponent(stamp, isDirectory: true)
    }

    private static func format(_ value: Double?) -> String {
        guard let value else { return "n/a" }
        return String(format: "%.3f", value)
    }

    private static func formatDensity(_ value: Double) -> String {
        String(format: "%.4f", value)
    }

    private static func formatPair(_ summary: TimingSummary?) -> String {
        guard let summary else { return "n/a" }
        return "\(format(summary.medianMilliseconds)) / \(format(summary.p95Milliseconds))"
    }

    private static func formatWidths(_ widths: [Int]) -> String {
        widths.isEmpty ? "n/a" : widths.map(String.init).joined(separator: ",")
    }

    private static func formatCounterStatus(available: Bool, captured: Bool) -> String {
        if available == false { return "unavailable" }
        return captured ? "captured" : "available"
    }

    private static let signerKey = SymmetricKey(data: Data(repeating: 0x5A, count: 32))
    private static let signerKeyID = Data("bench-signer".utf8)
    private static let benchmarkAppID = "NuMetalQ.Benchmarks"
    private static let benchmarkTeamID = "NuMetalQ.Benchmarks"
    private static let signer: PQSignClosure = { message in
        Data(HMAC<SHA256>.authenticationCode(for: message, using: signerKey))
    }
    private static let verifier: PQVerifyClosure = { message, signature in
        Data(HMAC<SHA256>.authenticationCode(for: message, using: signerKey)) == signature
    }
    private static let envelopeVerifier: PQKeyedVerifyClosure = { message, signature, candidateSignerKeyID in
        guard candidateSignerKeyID == signerKeyID else {
            return false
        }
        return Data(HMAC<SHA256>.authenticationCode(for: message, using: signerKey)) == signature
    }
    private static let attestationVerifier: AttestationVerifier = { attestation, context in
        guard attestation == Data("bench-attestation".utf8) else {
            return false
        }
        return context.appID == benchmarkAppID
            && context.teamID == benchmarkTeamID
            && context.shapeDigest != nil
            && context.signerKeyID == signerKeyID
            && context.payloadDigest.isEmpty == false
    }
}

try await NuMetalQBenchmarks.main()

struct Options {
    let iterations: Int
    let warmups: Int
    let outputDirectory: URL?
    fileprivate let sealWorkloads: [SealWorkload]
    fileprivate let pcsWorkloads: [PCSWorkload]
    fileprivate let verifierWorkloads: [VerifierWorkload]

    fileprivate static let defaultSealWorkloads: [SealWorkload] = [
        SealWorkload(
            name: "auth-policy-sparse",
            family: "pcd-auth",
            scenario: "multi-factor authorization policy",
            relationModel: "sparse local aggregate checks",
            densityModel: .sparse,
            rowCount: 64,
            publicInputCount: 2,
            sourceLanes: [
                SealLaneBlueprint(name: "balances", width: .u16),
                SealLaneBlueprint(name: "riskFlags", width: .bit),
                SealLaneBlueprint(name: "approvals", width: .u8),
            ],
            leftTermsPerRow: 4,
            rightTermsPerRow: 4
        ),
        SealWorkload(
            name: "rollup-settlement-dense",
            family: "pcd-rollup",
            scenario: "batched settlement aggregation",
            relationModel: "dense windowed linear aggregation checks",
            densityModel: .dense,
            rowCount: 64,
            publicInputCount: 2,
            sourceLanes: [
                SealLaneBlueprint(name: "amounts", width: .u16),
                SealLaneBlueprint(name: "fees", width: .u16),
                SealLaneBlueprint(name: "nonces", width: .u32),
                SealLaneBlueprint(name: "accountWeights", width: .u16),
            ],
            leftTermsPerRow: 14,
            rightTermsPerRow: 14
        ),
    ]

    fileprivate static let defaultPCSWorkloads: [PCSWorkload] = [
        PCSWorkload(name: "pcs-8", numVars: 8),
        PCSWorkload(name: "pcs-10", numVars: 10),
        PCSWorkload(name: "pcs-12", numVars: 12),
    ]

    fileprivate static let defaultVerifierWorkloads: [VerifierWorkload] = [
        VerifierWorkload(name: "piccs-verify", stage: .piCCS, arity: 1, witnessRingCount: 1, fieldCount: 4),
        VerifierWorkload(name: "pirlc-verify", stage: .piRLC, arity: 3, witnessRingCount: 4, fieldCount: 2),
        VerifierWorkload(name: "pidec-verify", stage: .piDEC, arity: 1, witnessRingCount: 3, fieldCount: RingElement.degree),
    ]

    static let usage = """
    Usage: swift run NuMetalQBenchmarks [options]

    Options:
      --iterations N             Number of measured iterations per workload. Default: 9.
      --warmups N                Number of warmup iterations per workload. Default: 2.
      --output DIR               Directory to write benchmark artifacts into.
      --seal-workload NAME       Run only the named seal workload. Repeat or comma-separate values.
      --pcs-workload NAME        Run only the named PCS workload. Repeat or comma-separate values.
      --verifier-workload NAME   Run only the named verifier workload. Repeat or comma-separate values.
      --list-workloads           Print the built-in workloads and exit.
      --help                     Show this help message.
    """

    static var workloadListing: String {
        let seal = defaultSealWorkloads.map {
            "  \($0.name) - \($0.family): \($0.scenario)"
        }
        let pcs = defaultPCSWorkloads.map {
            "  \($0.name) - numVars=\($0.numVars)"
        }
        let verifier = defaultVerifierWorkloads.map {
            "  \($0.name) - stage=\($0.stage.rawValue) arity=\($0.arity)"
        }

        return ([
            "Seal workloads:",
        ] + seal + [
            "",
            "PCS workloads:",
        ] + pcs + [
            "",
            "Verifier workloads:",
        ] + verifier).joined(separator: "\n")
    }

    static func parse(arguments: ArraySlice<String>) throws -> BenchmarkCommand {
        var iterations = 9
        var warmups = 2
        var outputDirectory: URL?
        var selectedSealWorkloads: [String] = []
        var selectedPCSWorkloads: [String] = []
        var selectedVerifierWorkloads: [String] = []

        var iterator = arguments.makeIterator()
        while let argument = iterator.next() {
            switch argument {
            case "--iterations":
                guard let value = iterator.next(), let parsed = Int(value), parsed > 0 else {
                    throw BenchmarkError.invalidArguments("--iterations must be a positive integer")
                }
                iterations = parsed
            case "--warmups":
                guard let value = iterator.next(), let parsed = Int(value), parsed >= 0 else {
                    throw BenchmarkError.invalidArguments("--warmups must be a non-negative integer")
                }
                warmups = parsed
            case "--output":
                guard let value = iterator.next() else {
                    throw BenchmarkError.invalidArguments("--output requires a directory path")
                }
                outputDirectory = URL(fileURLWithPath: value, isDirectory: true)
            case "--seal-workload":
                guard let value = iterator.next(), value.isEmpty == false else {
                    throw BenchmarkError.invalidArguments("--seal-workload requires at least one workload name")
                }
                selectedSealWorkloads.append(contentsOf: splitSelectionArgument(value))
            case "--pcs-workload":
                guard let value = iterator.next(), value.isEmpty == false else {
                    throw BenchmarkError.invalidArguments("--pcs-workload requires at least one workload name")
                }
                selectedPCSWorkloads.append(contentsOf: splitSelectionArgument(value))
            case "--verifier-workload":
                guard let value = iterator.next(), value.isEmpty == false else {
                    throw BenchmarkError.invalidArguments("--verifier-workload requires at least one workload name")
                }
                selectedVerifierWorkloads.append(contentsOf: splitSelectionArgument(value))
            case "--list-workloads":
                return .listWorkloads
            case "--help":
                return .help
            default:
                throw BenchmarkError.invalidArguments("unknown argument: \(argument)")
            }
        }

        let sealWorkloads = try selectWorkloads(
            from: defaultSealWorkloads,
            selection: selectedSealWorkloads,
            label: "seal"
        )
        let pcsWorkloads = try selectWorkloads(
            from: defaultPCSWorkloads,
            selection: selectedPCSWorkloads,
            label: "pcs"
        )
        let verifierWorkloads = try selectWorkloads(
            from: defaultVerifierWorkloads,
            selection: selectedVerifierWorkloads,
            label: "verifier"
        )

        return .run(Options(
            iterations: iterations,
            warmups: warmups,
            outputDirectory: outputDirectory,
            sealWorkloads: sealWorkloads,
            pcsWorkloads: pcsWorkloads,
            verifierWorkloads: verifierWorkloads
        ))
    }

    private init(
        iterations: Int,
        warmups: Int,
        outputDirectory: URL?,
        sealWorkloads: [SealWorkload],
        pcsWorkloads: [PCSWorkload],
        verifierWorkloads: [VerifierWorkload]
    ) {
        self.iterations = iterations
        self.warmups = warmups
        self.outputDirectory = outputDirectory
        self.sealWorkloads = sealWorkloads
        self.pcsWorkloads = pcsWorkloads
        self.verifierWorkloads = verifierWorkloads
    }

    private static func splitSelectionArgument(_ argument: String) -> [String] {
        argument
            .split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { $0.isEmpty == false }
    }

    private static func selectWorkloads<T>(
        from workloads: [T],
        selection: [String],
        label: String
    ) throws -> [T] where T: NamedBenchmarkWorkload {
        guard selection.isEmpty == false else {
            return workloads
        }

        let requested = Set(selection)
        let available = Set(workloads.map(\.name))
        let unknown = requested.subtracting(available).sorted()
        guard unknown.isEmpty else {
            let validNames = workloads.map(\.name).joined(separator: ", ")
            throw BenchmarkError.invalidArguments(
                "unknown \(label) workload(s): \(unknown.joined(separator: ", ")). Available: \(validNames)"
            )
        }

        return workloads.filter { requested.contains($0.name) }
    }
}

private struct TimedResult<Value> {
    let value: Value
    let milliseconds: Double
}

private struct SealBenchmarkInputs {
    let publicInputs: [Fq]
    let firstWitness: Witness
    let secondWitness: Witness
}

private struct SealWorkloadFixture {
    let workload: SealWorkload
    let compiledShape: CompiledShape
    let sourceLanes: [LaneDescriptor]
    let derivedLane: LaneDescriptor
    let layout: ColumnLayout
    let publicInputs: [Fq]
}

private struct SealWorkloadScaffold {
    let workload: SealWorkload
    let relation: CCSRelation
    let sourceLanes: [LaneDescriptor]
    let derivedLane: LaneDescriptor
    let layout: ColumnLayout
    let publicInputs: [Fq]

    var allLanes: [LaneDescriptor] {
        sourceLanes + [derivedLane]
    }
}

private struct ColumnLayout {
    let publicInputCount: Int
    let laneRanges: [Range<Int>]
    let totalColumns: Int

    init(publicInputCount: Int, lanes: [LaneDescriptor]) {
        self.publicInputCount = publicInputCount
        var start = publicInputCount
        var ranges: [Range<Int>] = []
        ranges.reserveCapacity(lanes.count)
        for lane in lanes {
            let end = start + Int(lane.length)
            ranges.append(start..<end)
            start = end
        }
        self.laneRanges = ranges
        self.totalColumns = start
    }

    func column(forLane laneIndex: Int, position: Int) -> Int {
        laneRanges[laneIndex].lowerBound + position
    }
}

private struct BenchmarkMetadata: Codable {
    let generatedAt: String
    let hostName: String
    let operatingSystemVersion: String
    let activeProcessorCount: Int
    let physicalMemoryBytes: UInt64
}

private struct BenchmarkConfiguration: Codable {
    let iterations: Int
    let warmups: Int
}

private enum BenchmarkRunStatus: String, Codable {
    case running
    case completed
    case failed
}

private enum BenchmarkEntryStatus: String, Codable {
    case pending
    case running
    case completed
    case failed
}

private enum DensityModel: String, Codable {
    case sparse
    case dense
}

private enum OperandSide {
    case left
    case right

    var publicOffset: Int {
        switch self {
        case .left: return 0
        case .right: return 1
        }
    }
}

private struct SealLaneBlueprint: Codable {
    let name: String
    let width: LaneWidth
}

private struct SealWorkload: Codable {
    let name: String
    let family: String
    let scenario: String
    let relationModel: String
    let densityModel: DensityModel
    let rowCount: Int
    let publicInputCount: Int
    let sourceLanes: [SealLaneBlueprint]
    let leftTermsPerRow: Int
    let rightTermsPerRow: Int
    let witnessLength: Int
    let matrixCount: Int
    let totalNNZ: Int
    let nonZeroDensity: Double
    let maxGateDegree: Int
    let witnessBitWidth: Int

    init(
        name: String,
        family: String,
        scenario: String,
        relationModel: String,
        densityModel: DensityModel,
        rowCount: Int,
        publicInputCount: Int,
        sourceLanes: [SealLaneBlueprint],
        leftTermsPerRow: Int,
        rightTermsPerRow: Int,
        witnessLength: Int = 0,
        matrixCount: Int = 0,
        totalNNZ: Int = 0,
        nonZeroDensity: Double = 0,
        maxGateDegree: Int = 0,
        witnessBitWidth: Int = 0
    ) {
        self.name = name
        self.family = family
        self.scenario = scenario
        self.relationModel = relationModel
        self.densityModel = densityModel
        self.rowCount = rowCount
        self.publicInputCount = publicInputCount
        self.sourceLanes = sourceLanes
        self.leftTermsPerRow = leftTermsPerRow
        self.rightTermsPerRow = rightTermsPerRow
        self.witnessLength = witnessLength
        self.matrixCount = matrixCount
        self.totalNNZ = totalNNZ
        self.nonZeroDensity = nonZeroDensity
        self.maxGateDegree = maxGateDegree
        self.witnessBitWidth = witnessBitWidth
    }
}

private struct PCSWorkload: Codable {
    let name: String
    let numVars: Int
}

private enum VerifierStageKind: String, Codable {
    case piCCS
    case piRLC
    case piDEC
}

private struct VerifierWorkload: Codable {
    let name: String
    let stage: VerifierStageKind
    let arity: Int
    let witnessRingCount: Int
    let fieldCount: Int
}

private protocol NamedBenchmarkWorkload {
    var name: String { get }
}

extension SealWorkload: NamedBenchmarkWorkload {}
extension PCSWorkload: NamedBenchmarkWorkload {}
extension VerifierWorkload: NamedBenchmarkWorkload {}

private struct PCSCPUCommitArtifact {
    let codeword: [Fq]
    let merkleLevels: [[[UInt8]]]
}

private struct PCSMetalIteration {
    let commitCPU: Double
    let openCPU: Double
    let commitGPU: Double?
    let openGPU: Double?
    let commitThreadgroupWidths: [Int]
    let openThreadgroupWidths: [Int]
    let commitCounterSamplesCaptured: Bool
    let openCounterSamplesCaptured: Bool
}

private struct TimingSummary: Codable {
    let samples: Int
    let meanMilliseconds: Double
    let medianMilliseconds: Double
    let p90Milliseconds: Double
    let p95Milliseconds: Double
    let p99Milliseconds: Double
    let minMilliseconds: Double
    let maxMilliseconds: Double
}

private struct SealBenchmarkResult: Codable {
    let workload: SealWorkload
    let status: BenchmarkEntryStatus
    let completedIterations: Int
    let expectedIterations: Int
    let completedSamples: Int
    let expectedSamples: Int
    let gpuFamilyTag: String
    let gpuName: String
    let publicProofBytes: Int
    let resumeArtifactBytes: Int
    let totalExportBytes: Int
    let peakRSSBytes: UInt64
    let seedOne: TimingSummary?
    let seedTwo: TimingSummary?
    let fuse: TimingSummary?
    let seal: TimingSummary?
    let cpuVerify: TimingSummary?
    let assistedVerify: TimingSummary?
    let assistedVerifyGPU: TimingSummary?
    let verifyMode: String
    let verificationParity: HachiVerificationParity
    let dispatchTracePath: String?
    let parityNote: String?
    let fuseFailure: String?
}

private struct PCSBenchmarkResult: Codable {
    let workload: PCSWorkload
    let status: BenchmarkEntryStatus
    let completedIterations: Int
    let expectedIterations: Int
    let completedSamples: Int
    let expectedSamples: Int
    let peakRSSBytes: UInt64
    let cpuCommit: TimingSummary?
    let cpuOpen: TimingSummary?
    let metalCommit: TimingSummary?
    let metalOpen: TimingSummary?
    let metalCommitGPU: TimingSummary?
    let metalOpenGPU: TimingSummary?
    let metalCommitThreadgroupWidths: [Int]
    let metalOpenThreadgroupWidths: [Int]
    let counterSamplingAvailable: Bool
    let metalCommitCountersCaptured: Bool
    let metalOpenCountersCaptured: Bool
    let gpuFamilyTag: String
    let gpuName: String
    let note: String?
}

private struct VerifierBenchmarkResult: Codable {
    let workload: VerifierWorkload
    let status: BenchmarkEntryStatus
    let completedIterations: Int
    let expectedIterations: Int
    let completedSamples: Int
    let expectedSamples: Int
    let peakRSSBytes: UInt64
    let cpuVerify: TimingSummary?
    let assistedVerify: TimingSummary?
    let assistedVerifyGPU: TimingSummary?
    let assistanceMode: String
    let counterSamplingAvailable: Bool
    let dispatchCount: Int
    let dispatchSummaries: [DispatchAggregate]
    let dispatchTracePath: String?
    let gpuFamilyTag: String
    let gpuName: String
    let note: String?
}

private struct DispatchAggregate: Codable {
    let stage: String
    let dispatchLabel: String
    let kernelFamily: String
    let sampleCount: Int
    let cpu: TimingSummary
    let gpu: TimingSummary?
    let threadExecutionWidths: [Int]
    let threadgroupWidths: [Int]
    let counterSamplingAvailable: Bool
    let counterSamplesCaptured: Bool
}

private struct WorkloadDispatchTrace: Codable {
    let suite: String
    let workloadName: String
    let iteration: Int
    let samples: [MetalDispatchTraceSample]
}

private struct BenchmarkDispatchTraceReport: Codable {
    let generatedAt: String
    var seal: [WorkloadDispatchTrace]
    var verifier: [WorkloadDispatchTrace]
}

private struct BenchmarkReport: Codable {
    let metadata: BenchmarkMetadata
    let configuration: BenchmarkConfiguration
    var status: BenchmarkRunStatus
    var lastUpdatedAt: String
    var completedAt: String?
    var failure: String?
    var sealWorkloads: [SealBenchmarkResult]
    var pcsWorkloads: [PCSBenchmarkResult]
    var verifierWorkloads: [VerifierBenchmarkResult]
}

private struct BenchmarkArtifactPaths {
    let jsonPath: String
    let markdownPath: String
    let dispatchTracePath: String
    let comparisonTemplatePath: String
    let reviewBundlePath: String
}

private struct ExternalComparisonTemplate: Codable {
    let generatedAt: String
    let benchmarkArtifactPath: String
    let requiredBaselines: [String]
    let dimensions: [String]
    let entries: [ExternalComparisonEntry]
}

private struct ExternalComparisonEntry: Codable {
    let baselineFamily: String
    let implementation: String
    let workloadName: String
    let proverTimeMilliseconds: Double
    let verifierTimeMilliseconds: Double
    let proofBytes: Int
    let memoryBytes: Int
    let notes: String
}

private struct ReviewBundle: Codable {
    let generatedAt: String
    let canonicalBackendID: String
    let canonicalSealWireMagic: String
    let protocolNotePath: String
    let stateOfTheArtPath: String
    let benchmarkingGuidePath: String
    let benchmarkReportJSONPath: String
    let benchmarkReportMarkdownPath: String
    let benchmarkDispatchTracePath: String
    let comparisonTemplatePath: String
}

private actor BenchmarkArtifactWriter {
    private let encoder: JSONEncoder
    private let jsonURL: URL
    private let markdownURL: URL
    private let dispatchTraceURL: URL
    private let comparisonURL: URL
    private let bundleURL: URL
    private var report: BenchmarkReport
    private var traceReport: BenchmarkDispatchTraceReport

    init(
        outputDirectory: URL,
        metadata: BenchmarkMetadata,
        configuration: BenchmarkConfiguration,
        initialSealWorkloads: [SealBenchmarkResult],
        initialPCSWorkloads: [PCSBenchmarkResult],
        initialVerifierWorkloads: [VerifierBenchmarkResult]
    ) throws {
        self.encoder = JSONEncoder()
        self.encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        self.jsonURL = outputDirectory.appendingPathComponent("benchmark-report.json")
        self.markdownURL = outputDirectory.appendingPathComponent("benchmark-report.md")
        self.dispatchTraceURL = outputDirectory.appendingPathComponent("benchmark-dispatch-trace.json")
        self.comparisonURL = outputDirectory.appendingPathComponent("comparison-template.json")
        self.bundleURL = outputDirectory.appendingPathComponent("review-bundle.json")
        self.report = BenchmarkReport(
            metadata: metadata,
            configuration: configuration,
            status: .running,
            lastUpdatedAt: Self.timestamp(),
            completedAt: nil,
            failure: nil,
            sealWorkloads: initialSealWorkloads,
            pcsWorkloads: initialPCSWorkloads,
            verifierWorkloads: initialVerifierWorkloads
        )
        self.traceReport = BenchmarkDispatchTraceReport(
            generatedAt: metadata.generatedAt,
            seal: [],
            verifier: []
        )

        try Self.writeComparisonTemplate(
            generatedAt: metadata.generatedAt,
            benchmarkArtifactPath: jsonURL.path,
            comparisonURL: comparisonURL,
            encoder: encoder
        )
        try Self.writeReviewBundle(
            generatedAt: metadata.generatedAt,
            benchmarkReportJSONPath: jsonURL.path,
            benchmarkReportMarkdownPath: markdownURL.path,
            benchmarkDispatchTracePath: dispatchTraceURL.path,
            comparisonTemplatePath: comparisonURL.path,
            bundleURL: bundleURL,
            encoder: encoder
        )
        try Self.persist(
            report: report,
            traceReport: traceReport,
            encoder: encoder,
            jsonURL: jsonURL,
            markdownURL: markdownURL,
            dispatchTraceURL: dispatchTraceURL
        )
    }

    func updateSeal(_ result: SealBenchmarkResult, at index: Int) throws {
        var seal = report.sealWorkloads
        seal[index] = result
        report = BenchmarkReport(
            metadata: report.metadata,
            configuration: report.configuration,
            status: report.status,
            lastUpdatedAt: Self.timestamp(),
            completedAt: report.completedAt,
            failure: report.failure,
            sealWorkloads: seal,
            pcsWorkloads: report.pcsWorkloads,
            verifierWorkloads: report.verifierWorkloads
        )
        try Self.persist(
            report: report,
            traceReport: traceReport,
            encoder: encoder,
            jsonURL: jsonURL,
            markdownURL: markdownURL,
            dispatchTraceURL: dispatchTraceURL
        )
    }

    func updatePCS(_ result: PCSBenchmarkResult, at index: Int) throws {
        var pcs = report.pcsWorkloads
        pcs[index] = result
        report = BenchmarkReport(
            metadata: report.metadata,
            configuration: report.configuration,
            status: report.status,
            lastUpdatedAt: Self.timestamp(),
            completedAt: report.completedAt,
            failure: report.failure,
            sealWorkloads: report.sealWorkloads,
            pcsWorkloads: pcs,
            verifierWorkloads: report.verifierWorkloads
        )
        try Self.persist(
            report: report,
            traceReport: traceReport,
            encoder: encoder,
            jsonURL: jsonURL,
            markdownURL: markdownURL,
            dispatchTraceURL: dispatchTraceURL
        )
    }

    func updateVerifier(_ result: VerifierBenchmarkResult, at index: Int) throws {
        var verifier = report.verifierWorkloads
        verifier[index] = result
        report = BenchmarkReport(
            metadata: report.metadata,
            configuration: report.configuration,
            status: report.status,
            lastUpdatedAt: Self.timestamp(),
            completedAt: report.completedAt,
            failure: report.failure,
            sealWorkloads: report.sealWorkloads,
            pcsWorkloads: report.pcsWorkloads,
            verifierWorkloads: verifier
        )
        try Self.persist(
            report: report,
            traceReport: traceReport,
            encoder: encoder,
            jsonURL: jsonURL,
            markdownURL: markdownURL,
            dispatchTraceURL: dispatchTraceURL
        )
    }

    func dispatchTracePath() -> String {
        dispatchTraceURL.path
    }

    func updateSealTrace(workloadName: String, iteration: Int, samples: [MetalDispatchTraceSample]) throws {
        traceReport.seal.removeAll {
            $0.workloadName == workloadName && $0.iteration == iteration
        }
        traceReport.seal.append(
            WorkloadDispatchTrace(
                suite: "seal",
                workloadName: workloadName,
                iteration: iteration,
                samples: samples
            )
        )
        try Self.persist(
            report: report,
            traceReport: traceReport,
            encoder: encoder,
            jsonURL: jsonURL,
            markdownURL: markdownURL,
            dispatchTraceURL: dispatchTraceURL
        )
    }

    func updateVerifierTrace(workloadName: String, iteration: Int, samples: [MetalDispatchTraceSample]) throws {
        traceReport.verifier.removeAll {
            $0.workloadName == workloadName && $0.iteration == iteration
        }
        traceReport.verifier.append(
            WorkloadDispatchTrace(
                suite: "verifier",
                workloadName: workloadName,
                iteration: iteration,
                samples: samples
            )
        )
        try Self.persist(
            report: report,
            traceReport: traceReport,
            encoder: encoder,
            jsonURL: jsonURL,
            markdownURL: markdownURL,
            dispatchTraceURL: dispatchTraceURL
        )
    }

    func markFailed(error: Error) throws -> BenchmarkArtifactPaths {
        report.status = .failed
        report.lastUpdatedAt = Self.timestamp()
        report.completedAt = report.lastUpdatedAt
        report.failure = String(describing: error)
        report.sealWorkloads = report.sealWorkloads.map { result in
            result.status == .completed ? result : SealBenchmarkResult(
                workload: result.workload,
                status: .failed,
                completedIterations: result.completedIterations,
                expectedIterations: result.expectedIterations,
                completedSamples: result.completedSamples,
                expectedSamples: result.expectedSamples,
                gpuFamilyTag: result.gpuFamilyTag,
                gpuName: result.gpuName,
                publicProofBytes: result.publicProofBytes,
                resumeArtifactBytes: result.resumeArtifactBytes,
                totalExportBytes: result.totalExportBytes,
                peakRSSBytes: result.peakRSSBytes,
                seedOne: result.seedOne,
                seedTwo: result.seedTwo,
                fuse: result.fuse,
                seal: result.seal,
                cpuVerify: result.cpuVerify,
                assistedVerify: result.assistedVerify,
                assistedVerifyGPU: result.assistedVerifyGPU,
                verifyMode: result.verifyMode,
                verificationParity: result.verificationParity,
                dispatchTracePath: result.dispatchTracePath,
                parityNote: result.parityNote,
                fuseFailure: result.fuseFailure
            )
        }
        report.pcsWorkloads = report.pcsWorkloads.map { result in
            result.status == .completed ? result : PCSBenchmarkResult(
                workload: result.workload,
                status: .failed,
                completedIterations: result.completedIterations,
                expectedIterations: result.expectedIterations,
                completedSamples: result.completedSamples,
                expectedSamples: result.expectedSamples,
                peakRSSBytes: result.peakRSSBytes,
                cpuCommit: result.cpuCommit,
                cpuOpen: result.cpuOpen,
                metalCommit: result.metalCommit,
                metalOpen: result.metalOpen,
                metalCommitGPU: result.metalCommitGPU,
                metalOpenGPU: result.metalOpenGPU,
                metalCommitThreadgroupWidths: result.metalCommitThreadgroupWidths,
                metalOpenThreadgroupWidths: result.metalOpenThreadgroupWidths,
                counterSamplingAvailable: result.counterSamplingAvailable,
                metalCommitCountersCaptured: result.metalCommitCountersCaptured,
                metalOpenCountersCaptured: result.metalOpenCountersCaptured,
                gpuFamilyTag: result.gpuFamilyTag,
                gpuName: result.gpuName,
                note: result.note
            )
        }
        report.verifierWorkloads = report.verifierWorkloads.map { result in
            result.status == .completed ? result : VerifierBenchmarkResult(
                workload: result.workload,
                status: .failed,
                completedIterations: result.completedIterations,
                expectedIterations: result.expectedIterations,
                completedSamples: result.completedSamples,
                expectedSamples: result.expectedSamples,
                peakRSSBytes: result.peakRSSBytes,
                cpuVerify: result.cpuVerify,
                assistedVerify: result.assistedVerify,
                assistedVerifyGPU: result.assistedVerifyGPU,
                assistanceMode: result.assistanceMode,
                counterSamplingAvailable: result.counterSamplingAvailable,
                dispatchCount: result.dispatchCount,
                dispatchSummaries: result.dispatchSummaries,
                dispatchTracePath: result.dispatchTracePath,
                gpuFamilyTag: result.gpuFamilyTag,
                gpuName: result.gpuName,
                note: result.note
            )
        }
        try Self.persist(
            report: report,
            traceReport: traceReport,
            encoder: encoder,
            jsonURL: jsonURL,
            markdownURL: markdownURL,
            dispatchTraceURL: dispatchTraceURL
        )
        return paths()
    }

    func markCompleted() throws -> BenchmarkArtifactPaths {
        report.status = .completed
        report.lastUpdatedAt = Self.timestamp()
        report.completedAt = report.lastUpdatedAt
        report.failure = nil
        try Self.persist(
            report: report,
            traceReport: traceReport,
            encoder: encoder,
            jsonURL: jsonURL,
            markdownURL: markdownURL,
            dispatchTraceURL: dispatchTraceURL
        )
        return paths()
    }

    private func paths() -> BenchmarkArtifactPaths {
        BenchmarkArtifactPaths(
            jsonPath: jsonURL.path,
            markdownPath: markdownURL.path,
            dispatchTracePath: dispatchTraceURL.path,
            comparisonTemplatePath: comparisonURL.path,
            reviewBundlePath: bundleURL.path
        )
    }

    private static func writeComparisonTemplate(
        generatedAt: String,
        benchmarkArtifactPath: String,
        comparisonURL: URL,
        encoder: JSONEncoder
    ) throws {
        let comparisonTemplate = ExternalComparisonTemplate(
            generatedAt: generatedAt,
            benchmarkArtifactPath: benchmarkArtifactPath,
            requiredBaselines: [
                "Spartan-family",
                "Lattice folding",
                "Multilinear PCS",
            ],
            dimensions: [
                "prover_time_p50_ms",
                "prover_time_p95_ms",
                "cpu_verify_p50_ms",
                "cpu_verify_p95_ms",
                "assisted_verify_p50_ms",
                "assisted_verify_gpu_p50_ms",
                "proof_bytes",
                "peak_rss_bytes",
                "gpu_time_ms",
                "threadgroup_widths",
                "counter_sampling",
                "nnz",
                "max_gate_degree",
            ],
            entries: []
        )
        try encoder.encode(comparisonTemplate).write(to: comparisonURL, options: [.atomic])
    }

    private static func writeReviewBundle(
        generatedAt: String,
        benchmarkReportJSONPath: String,
        benchmarkReportMarkdownPath: String,
        benchmarkDispatchTracePath: String,
        comparisonTemplatePath: String,
        bundleURL: URL,
        encoder: JSONEncoder
    ) throws {
        let documentationPaths = BenchmarkDocumentationPaths.current()
        let bundle = ReviewBundle(
            generatedAt: generatedAt,
            canonicalBackendID: NuSealConstants.productionBackendID,
            canonicalSealWireMagic: "NuSeal",
            protocolNotePath: documentationPaths.protocolNotePath,
            stateOfTheArtPath: documentationPaths.stateOfTheArtPath,
            benchmarkingGuidePath: documentationPaths.benchmarkingGuidePath,
            benchmarkReportJSONPath: benchmarkReportJSONPath,
            benchmarkReportMarkdownPath: benchmarkReportMarkdownPath,
            benchmarkDispatchTracePath: benchmarkDispatchTracePath,
            comparisonTemplatePath: comparisonTemplatePath
        )
        try encoder.encode(bundle).write(to: bundleURL, options: [.atomic])
    }

    private static func persist(
        report: BenchmarkReport,
        traceReport: BenchmarkDispatchTraceReport,
        encoder: JSONEncoder,
        jsonURL: URL,
        markdownURL: URL,
        dispatchTraceURL: URL
    ) throws {
        try encoder.encode(report).write(to: jsonURL, options: [.atomic])
        try encoder.encode(traceReport).write(to: dispatchTraceURL, options: [.atomic])
        try NuMetalQBenchmarks.renderMarkdown(report).write(
            to: markdownURL,
            atomically: true,
            encoding: .utf8
        )
    }

    private static func timestamp() -> String {
        ISO8601DateFormatter().string(from: Date())
    }
}

private enum BenchmarkError: LocalizedError {
    case invalidArguments(String)
    case invalidVerification(String)
    case invalidWorkload(String)
    case metalMismatch(String)

    var errorDescription: String? {
        switch self {
        case .invalidArguments(let message):
            return message
        case .invalidVerification(let message):
            return "verification failed: \(message)"
        case .invalidWorkload(let message):
            return "invalid workload: \(message)"
        case .metalMismatch(let message):
            return "metal mismatch: \(message)"
        }
    }
}

private extension Array {
    func mapAsync<T>(_ transform: (Element) async throws -> T) async rethrows -> [T] {
        var results: [T] = []
        results.reserveCapacity(count)
        for element in self {
            results.append(try await transform(element))
        }
        return results
    }
}
