import Foundation
import Metal

// MARK: - AutoTuner
// Persists per-shape, per-family tuning choices and measures probes with
// Metal counter sample buffers when timestamp counters are available.

public struct TuneProbe: Sendable {
    public let arity: Int
    public let tileSize: Int
    public let queueDepth: Int
    public let decompWindow: Int
    public let elapsedNanoseconds: UInt64
    public let gpuCycles: UInt64
}

public struct TuneResult: Sendable, Codable {
    public let shapeDigest: [UInt8]
    public let gpuFamilyTag: String
    public let bestArity: Int
    public let bestTileSize: Int
    public let bestQueueDepth: Int
    public let bestDecompWindow: Int
    public let timestamp: Date
}

@available(*, unavailable, message: "Runtime autotuning is removed from the production NuMeQ pipeline.")
public actor AutoTuner {
    private let context: MetalContext
    private let cacheURL: URL
    private var cache: [String: TuneResult]

    public init(context: MetalContext, cacheDirectory: URL? = nil) {
        self.context = context
        let baseDirectory = cacheDirectory ?? AutoTuner.defaultCacheDirectory()
        self.cacheURL = baseDirectory
            .appendingPathComponent("NuMeQ-AutoTune-\(context.gpuFamilyTag).json")
        self.cache = AutoTuner.loadCache(from: self.cacheURL)
    }

    public func tune(
        shapeDigest: ShapeDigest,
        defaultConfig: KernelConfig
    ) async -> KernelConfig {
        let cacheKey = Self.cacheKey(shapeDigest: shapeDigest, gpuFamilyTag: context.gpuFamilyTag)
        if let cached = cache[cacheKey] {
            return Self.kernelConfig(from: cached, baselineConfig: defaultConfig)
        }

        let candidateArities = [2, 4, 8, 16].filter { $0 <= max(2, Int(defaultConfig.foldArity) * 2) }
        let candidateTiles = [32, 64, 128, 256].filter { $0 <= context.maxThreadsPerThreadgroupWidth }
        let candidateDepths = [1, Int(defaultConfig.queueDepth), max(2, Int(defaultConfig.queueDepth) + 1)]
        let candidateWindows = [Int(defaultConfig.decompositionWindow), 4, 8].uniqued().sorted()

        var bestProbe: TuneProbe?
        for arity in candidateArities {
            for tileSize in candidateTiles {
                for queueDepth in candidateDepths {
                    for decompWindow in candidateWindows {
                        guard let probe = runProbe(
                            arity: arity,
                            tileSize: tileSize,
                            queueDepth: queueDepth,
                            decompWindow: decompWindow
                        ) else {
                            continue
                        }
                        if bestProbe == nil || probe.elapsedNanoseconds < bestProbe!.elapsedNanoseconds {
                            bestProbe = probe
                        }
                    }
                }
            }
        }

        guard let bestProbe else {
            return defaultConfig
        }

        let result = TuneResult(
            shapeDigest: shapeDigest.bytes,
            gpuFamilyTag: context.gpuFamilyTag,
            bestArity: bestProbe.arity,
            bestTileSize: bestProbe.tileSize,
            bestQueueDepth: bestProbe.queueDepth,
            bestDecompWindow: bestProbe.decompWindow,
            timestamp: Date()
        )
        cache[cacheKey] = result
        persistCache()
        return Self.kernelConfig(from: result, baselineConfig: defaultConfig)
    }

    private func runProbe(
        arity: Int,
        tileSize: Int,
        queueDepth: Int,
        decompWindow: Int
    ) -> TuneProbe? {
        let evalCount = max(256, min(4096, tileSize * max(arity, 1)))
        let blowup = 4
        let codewordLen = evalCount * blowup
        let queryCount = max(8, min(32, queueDepth * 8))
        let sampleEvals = Self.sampleSealEvaluations(
            count: evalCount,
            arity: arity,
            tileSize: tileSize,
            queueDepth: queueDepth,
            decompWindow: decompWindow
        )

        guard let evalBuffer = context.uploadFieldElements(sampleEvals),
              let codewordBuffer = context.makeSharedBuffer(length: codewordLen * MemoryLayout<UInt32>.size * 2),
              let nodesBuffer = context.makeSharedBuffer(length: codewordLen * 32),
              let positionsBuffer = context.makeSharedBuffer(length: queryCount * MemoryLayout<UInt32>.size),
              let outputBuffer = context.makeSharedBuffer(length: queryCount * MemoryLayout<UInt32>.size * 2) else {
            return nil
        }
        let dispatcher = KernelDispatcher(context: context)
        let positions = positionsBuffer.contents().bindMemory(to: UInt32.self, capacity: queryCount)
        let modulus = max(1, codewordLen)
        for index in 0..<queryCount {
            positions[index] = UInt32((index * max(1, arity)) % modulus)
        }

        let cpuStart = DispatchTime.now().uptimeNanoseconds
        do {
            try dispatcher.dispatchSealEncode(
                evalBuffer: evalBuffer,
                codewordBuffer: codewordBuffer,
                n: evalCount,
                blowup: blowup
            )
            try dispatcher.dispatchMerkleHash(
                leavesBuffer: codewordBuffer,
                nodesBuffer: nodesBuffer,
                numLeaves: codewordLen
            )
            try dispatcher.dispatchSealQuery(
                codewordBuffer: codewordBuffer,
                positionsBuffer: positionsBuffer,
                outputBuffer: outputBuffer,
                codewordLength: codewordLen,
                numQueries: queryCount
            )
        } catch {
            return nil
        }

        let cpuElapsed = DispatchTime.now().uptimeNanoseconds - cpuStart

        return TuneProbe(
            arity: arity,
            tileSize: tileSize,
            queueDepth: queueDepth,
            decompWindow: decompWindow,
            elapsedNanoseconds: cpuElapsed,
            gpuCycles: cpuElapsed
        )
    }

    private func persistCache() {
        do {
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.sortedKeys]
            encoder.dateEncodingStrategy = .iso8601
            try FileManager.default.createDirectory(
                at: cacheURL.deletingLastPathComponent(),
                withIntermediateDirectories: true
            )
            let data = try encoder.encode(Array(cache.values))
            try data.write(to: cacheURL, options: [.atomic])
        } catch {
            // Best-effort persistence. Runtime proving must not fail on cache I/O.
        }
    }

    private static func sampleSealEvaluations(
        count: Int,
        arity: Int,
        tileSize: Int,
        queueDepth: Int,
        decompWindow: Int
    ) -> [Fq] {
        (0..<count).map { index in
            let mixed =
                UInt64(index &+ 1) * 0x9E37_79B1
                &+ UInt64(arity &* 17)
                &+ UInt64(tileSize &* 5)
                &+ UInt64(queueDepth &* 29)
                &+ UInt64(decompWindow &* 13)
            return Fq(mixed % Fq.modulus)
        }
    }

    private static func loadCache(from url: URL) -> [String: TuneResult] {
        guard let data = try? Data(contentsOf: url) else {
            return [:]
        }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        guard let entries = try? decoder.decode([TuneResult].self, from: data) else {
            return [:]
        }
        return Dictionary(
            uniqueKeysWithValues: entries.map { result in
                (cacheKey(shapeDigest: ShapeDigest(bytes: result.shapeDigest), gpuFamilyTag: result.gpuFamilyTag), result)
            }
        )
    }

    private static func defaultCacheDirectory() -> URL {
        let caches = FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask).first!
        return caches.appendingPathComponent("NuMeQ/AutoTune", isDirectory: true)
    }

    private static func cacheKey(shapeDigest: ShapeDigest, gpuFamilyTag: String) -> String {
        let digest = shapeDigest.bytes.map { String(format: "%02x", $0) }.joined()
        return "\(gpuFamilyTag):\(digest)"
    }

    private static func kernelConfig(from result: TuneResult, baselineConfig: KernelConfig) -> KernelConfig {
        KernelConfig(
            threadgroupSize: UInt32(result.bestTileSize),
            threadExecutionWidthMultiple: baselineConfig.threadExecutionWidthMultiple,
            tilesPerThreadgroup: baselineConfig.tilesPerThreadgroup,
            laneTile: baselineConfig.laneTile,
            matrixRowTile: baselineConfig.matrixRowTile,
            storageLayoutVersion: baselineConfig.storageLayoutVersion,
            foldArity: UInt8(result.bestArity),
            decompositionWindow: UInt8(result.bestDecompWindow),
            queueDepth: UInt8(result.bestQueueDepth),
            sealChunkSize: baselineConfig.sealChunkSize,
            merkleChunkSize: baselineConfig.merkleChunkSize,
            gpuFamilyTag: result.gpuFamilyTag
        )
    }
}

private extension Array where Element: Hashable {
    func uniqued() -> [Element] {
        var seen = Set<Element>()
        return filter { seen.insert($0).inserted }
    }
}
