import Foundation
import Metal

// MARK: - Metal Context
// Central GPU resource manager for the NuMeQ proving engine.
// Manages device, command queues, heaps, binary archives, and pipeline state.
// Apple silicon shared memory model: shared buffers for CPU-visible staging,
// private heaps for long-lived GPU-only data.

/// Central Metal resource manager.
///
/// Owns the device, command queues, heaps, binary archives, and all
/// compiled pipeline states for the prover kernel families.
public final class MetalContext: @unchecked Sendable {
    public let device: MTLDevice
    public let commandQueue: MTLCommandQueue

    /// Shared heap for CPU-visible buffers (witness staging, transcript inputs).
    public let sharedHeap: MTLHeap

    /// Private heap for GPU-only data (rotation matrices, scratch, codewords).
    public let privateHeap: MTLHeap

    /// Binary archive for persisting compiled pipelines per GPU family.
    public let binaryArchive: MTLBinaryArchive?

    /// On-disk location for the binary archive, when persistence is enabled.
    public let binaryArchiveURL: URL?

    /// Versioned binary archive cache key.
    public let binaryArchiveKey: String

    /// Digest of the canonical Metal artifact bundle loaded by this context.
    public let gpuArtifactDigest: [UInt8]

    /// `maxThreadsPerThreadgroup.width` upper bound (dispatch sizing).
    public let maxThreadsPerThreadgroupWidth: Int

    /// First compute pipeline's `threadExecutionWidth` after warmup (SIMD lane count).
    public private(set) var threadExecutionWidth: Int

    /// GPU family identifier for kernel config lookup.
    public let gpuFamilyTag: String

    /// Compiled pipeline states, keyed by kernel family.
    private var pipelines: [KernelFamily: MTLComputePipelineState] = [:]
    private var indirectComputeGraphs: [IndirectComputeGraphKey: IndirectComputeGraph] = [:]
    private let indirectGraphLock = NSLock()

    private let sharedArena: HeapArena
    private let privateArena: HeapArena
    private let arenaLock = NSLock()

    /// Default Metal library containing NuMeQ compute shaders.
    public let library: MTLLibrary

    /// Timestamp counter set used by the autotuner when available.
    public let timestampCounterSet: MTLCounterSet?

    /// Whether this device supports dispatch-boundary counter sampling.
    public let dispatchCounterSamplingSupported: Bool

    public init() throws {
        #if !arch(arm64)
        throw NuMetalError.unsupportedCPUArchitecture
        #endif
        guard let device = MTLCreateSystemDefaultDevice() else {
            throw NuMetalError.noGPU
        }
        // NuMeQ targets Apple silicon GPUs only (shared-memory prover design).
        guard device.supportsFamily(.apple7) || device.supportsFamily(.apple8) || device.supportsFamily(.apple9) else {
            throw NuMetalError.unsupportedGPUFamily
        }
        self.device = device

        guard let queue = device.makeCommandQueue() else {
            throw NuMetalError.commandQueueFailed
        }
        self.commandQueue = queue

        self.maxThreadsPerThreadgroupWidth = device.maxThreadsPerThreadgroup.width
        self.threadExecutionWidth = 32
        self.gpuFamilyTag = Self.identifyGPUFamily(device)
        self.gpuArtifactDigest = try MetalArtifactBundle.artifactDigest()
        self.binaryArchiveKey = Self.makeBinaryArchiveKey(
            gpuFamilyTag: self.gpuFamilyTag,
            gpuArtifactDigestHex: self.gpuArtifactDigest.prefix(8).map { String(format: "%02x", $0) }.joined(),
            storageLayoutVersion: MetalStorageLayout.currentVersion
        )
        self.binaryArchiveURL = try? Self.prepareBinaryArchiveURL(binaryArchiveKey: self.binaryArchiveKey)
        self.timestampCounterSet = device.counterSets?.first(where: {
            $0.name.localizedCaseInsensitiveContains("timestamp")
        })
        if #available(macOS 11.0, iOS 14.0, *) {
            self.dispatchCounterSamplingSupported = device.supportsCounterSampling(.atDispatchBoundary)
        } else {
            self.dispatchCounterSamplingSupported = false
        }

        // Shared heap: CPU+GPU visible, for staging
        let sharedDesc = MTLHeapDescriptor()
        sharedDesc.storageMode = .shared
        sharedDesc.size = 256 * 1024 * 1024  // 256 MB
        sharedDesc.cpuCacheMode = .writeCombined
        guard let shared = device.makeHeap(descriptor: sharedDesc) else {
            throw NuMetalError.heapCreationFailed
        }
        self.sharedHeap = shared
        self.sharedArena = HeapArena(
            heap: shared,
            device: device,
            options: [.storageModeShared, .cpuCacheModeWriteCombined],
            defaultChunkSize: 8 * 1024 * 1024
        )

        // Private heap: GPU-only, for long-lived compute data
        let privateDesc = MTLHeapDescriptor()
        privateDesc.storageMode = .private
        privateDesc.size = 512 * 1024 * 1024  // 512 MB
        guard let priv = device.makeHeap(descriptor: privateDesc) else {
            throw NuMetalError.heapCreationFailed
        }
        self.privateHeap = priv
        self.privateArena = HeapArena(
            heap: priv,
            device: device,
            options: .storageModePrivate,
            defaultChunkSize: 16 * 1024 * 1024
        )

        // Binary archive for compiled pipelines
        let archiveDesc = MTLBinaryArchiveDescriptor()
        archiveDesc.url = binaryArchiveURL
        self.binaryArchive = try? device.makeBinaryArchive(descriptor: archiveDesc)

        do {
            self.library = try MetalArtifactBundle.makeLibrary(device: device)
        } catch {
            throw NuMetalError.libraryCompilationFailed(error.localizedDescription)
        }

        warmPipelines()
    }

    // MARK: - Pipeline Management

    /// Get or compile a pipeline for the given kernel family.
    public func pipeline(for family: KernelFamily) throws -> MTLComputePipelineState {
        if let cached = pipelines[family] { return cached }

        guard let function = library.makeFunction(name: family.functionName) else {
            throw NuMetalError.functionNotFound(family.functionName)
        }

        let descriptor = MTLComputePipelineDescriptor()
        descriptor.computeFunction = function
        descriptor.threadGroupSizeIsMultipleOfThreadExecutionWidth = true
        if #available(macOS 11.0, iOS 13.0, *) {
            descriptor.supportIndirectCommandBuffers = true
        }

        if let archive = binaryArchive {
            try? archive.addComputePipelineFunctions(descriptor: descriptor)
            if #available(macOS 11.0, iOS 14.0, *) {
                descriptor.binaryArchives = [archive]
            }
        }

        let pso = try device.makeComputePipelineState(
            descriptor: descriptor,
            options: [],
            reflection: nil
        )
        pipelines[family] = pso
        let tw = Int(pso.threadExecutionWidth)
        if tw > threadExecutionWidth {
            threadExecutionWidth = tw
        }
        persistBinaryArchiveIfPossible()
        return pso
    }

    func indirectComputeGraph(
        for family: KernelFamily,
        maxKernelBufferBindCount: Int
    ) throws -> IndirectComputeGraph? {
        guard #available(macOS 11.0, iOS 13.0, *) else {
            return nil
        }

        let key = IndirectComputeGraphKey(
            family: family,
            maxKernelBufferBindCount: maxKernelBufferBindCount
        )

        indirectGraphLock.lock()
        defer { indirectGraphLock.unlock() }

        if let cached = indirectComputeGraphs[key] {
            return cached
        }

        let pipeline = try self.pipeline(for: family)
        let graph = try IndirectComputeGraph(
            device: device,
            pipeline: pipeline,
            maxKernelBufferBindCount: maxKernelBufferBindCount
        )
        indirectComputeGraphs[key] = graph
        return graph
    }

    // MARK: - Buffer Allocation

    /// Allocate a shared buffer for CPU-visible data.
    public func makeSharedBuffer(length: Int) -> MTLBuffer? {
        let aligned = (length + 255) & ~255
        return sharedHeap.makeBuffer(
            length: aligned,
            options: [.storageModeShared, .cpuCacheModeWriteCombined]
        ) ?? device.makeBuffer(
            length: aligned,
            options: [.storageModeShared, .cpuCacheModeWriteCombined]
        )
    }

    /// Allocate a private buffer for GPU-only data.
    public func makePrivateBuffer(length: Int) -> MTLBuffer? {
        let aligned = (length + 255) & ~255
        return privateHeap.makeBuffer(length: aligned, options: .storageModePrivate)
            ?? device.makeBuffer(length: aligned, options: .storageModePrivate)
    }

    /// Upload field elements to a shared buffer.
    public func uploadFieldElements(_ elements: [Fq]) -> MTLBuffer? {
        uploadFieldElementsSoA(elements)
    }

    /// Upload field elements in canonical low-plane/high-plane SoA form.
    public func uploadFieldElementsSoA(_ elements: [Fq], paddedTo count: Int? = nil) -> MTLBuffer? {
        let storage = MetalFieldPacking.packFieldElementsSoA(elements, paddedTo: count)
        let byteCount = storage.count * MemoryLayout<UInt32>.size
        guard let buffer = makeSharedBuffer(length: byteCount) else { return nil }
        let ptr = buffer.contents().bindMemory(to: UInt32.self, capacity: storage.count)
        for (index, value) in storage.enumerated() {
            ptr[index] = value
        }
        return buffer
    }

    /// Dense Ajtai key layout for `nu_sparse_rot_commit`: `keys[i].coeffs[j]` at `i * 64 + j`.
    public func uploadAjtaiKeyRingCoefficients(_ key: AjtaiKey) -> MTLBuffer? {
        let d = RingElement.degree
        let count = key.keys.count * d
        let byteCount = count * MemoryLayout<UInt64>.size
        guard let buffer = makeSharedBuffer(length: byteCount) else { return nil }
        let ptr = buffer.contents().bindMemory(to: UInt64.self, capacity: count)
        for (i, ring) in key.keys.enumerated() {
            for j in 0..<d {
                ptr[i * d + j] = ring.coeffs[j].v
            }
        }
        return buffer
    }

    /// Dense rotation-major SoA layout for the canonical sparse-rotation commitment path.
    public func uploadAjtaiRotationRowsSoA(_ key: AjtaiKey) -> MTLBuffer? {
        let storage = MetalFieldPacking.packDenseRotationRowsSoA(for: key)
        let byteCount = storage.count * MemoryLayout<UInt32>.size
        guard let buffer = makeSharedBuffer(length: byteCount) else { return nil }
        let ptr = buffer.contents().bindMemory(to: UInt32.self, capacity: storage.count)
        for (index, value) in storage.enumerated() {
            ptr[index] = value
        }
        return buffer
    }

    /// Dense ring-element layout: `rings[i].coeffs[j]` at `i * 64 + j`.
    public func uploadRingElements(_ rings: [RingElement], paddedTo count: Int? = nil) -> MTLBuffer? {
        uploadRingElementsSoA(rings, paddedTo: count)
    }

    /// Canonical low-plane/high-plane SoA layout for ring tiles padded to 64-lane tiles.
    public func uploadRingElementsSoA(_ rings: [RingElement], paddedTo count: Int? = nil) -> MTLBuffer? {
        let storage = MetalFieldPacking.packRingElementsSoA(rings, paddedTo: count)
        let byteCount = storage.count * MemoryLayout<UInt32>.size
        guard let buffer = makeSharedBuffer(length: byteCount) else { return nil }
        let ptr = buffer.contents().bindMemory(to: UInt32.self, capacity: storage.count)
        for (index, value) in storage.enumerated() {
            ptr[index] = value
        }
        return buffer
    }

    public func uploadRingBatchSoA(
        _ batches: [[RingElement]],
        paddedInnerCount: Int? = nil
    ) -> MTLBuffer? {
        let storage = MetalFieldPacking.packRingBatchSoA(batches, paddedInnerCount: paddedInnerCount)
        let byteCount = storage.count * MemoryLayout<UInt32>.size
        guard let buffer = makeSharedBuffer(length: byteCount) else { return nil }
        let pointer = buffer.contents().bindMemory(to: UInt32.self, capacity: storage.count)
        for (index, value) in storage.enumerated() {
            pointer[index] = value
        }
        return buffer
    }

    /// Create a shared counter sample buffer for autotuning probes.
    public func makeCounterSampleBuffer(
        sampleCount: Int,
        label: String = "NuMeQ.CounterSamples"
    ) -> MTLCounterSampleBuffer? {
        guard dispatchCounterSamplingSupported,
              let counterSet = timestampCounterSet,
              sampleCount > 0 else {
            return nil
        }

        let descriptor = MTLCounterSampleBufferDescriptor()
        descriptor.counterSet = counterSet
        descriptor.label = label
        descriptor.storageMode = .shared
        descriptor.sampleCount = sampleCount
        return try? device.makeCounterSampleBuffer(descriptor: descriptor)
    }

    /// Run one proving pass with exclusive access to the persistent arenas.
    ///
    /// The arenas reset after the closure returns, so repeated passes reuse the
    /// same heap chunks without accumulating per-round buffer allocations.
    public func withTransientArena<T>(_ body: (MetalTransientArena) throws -> T) rethrows -> T {
        arenaLock.lock()
        defer {
            sharedArena.reset()
            privateArena.reset()
            arenaLock.unlock()
        }
        return try body(MetalTransientArena(sharedArena: sharedArena, privateArena: privateArena))
    }

    public var transientArenaChunkCounts: (shared: Int, private: Int) {
        arenaLock.lock()
        defer { arenaLock.unlock() }
        return (
            shared: sharedArena.allocatedChunkCount,
            private: privateArena.allocatedChunkCount
        )
    }

    public var indirectComputeGraphCount: Int {
        indirectGraphLock.lock()
        defer { indirectGraphLock.unlock() }
        return indirectComputeGraphs.count
    }

    // MARK: - GPU Family Detection

    private static func identifyGPUFamily(_ device: MTLDevice) -> String {
        if device.supportsFamily(.apple9) { return "apple9" }
        if device.supportsFamily(.apple8) { return "apple8" }
        if device.supportsFamily(.apple7) { return "apple7" }
        return "apple_unknown"
    }

    private static func makeBinaryArchiveKey(
        gpuFamilyTag: String,
        gpuArtifactDigestHex: String,
        storageLayoutVersion: UInt16
    ) -> String {
        "\(gpuFamilyTag)-abi\(storageLayoutVersion)-\(gpuArtifactDigestHex)"
    }

    private static func prepareBinaryArchiveURL(binaryArchiveKey: String) throws -> URL {
        let caches = FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask).first!
        let directory = caches.appendingPathComponent("NuMeQ/Metal", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        return directory.appendingPathComponent("\(binaryArchiveKey).metalarc")
    }

    private func persistBinaryArchiveIfPossible() {
        guard let binaryArchive, let binaryArchiveURL else {
            return
        }
        _ = try? binaryArchive.serialize(to: binaryArchiveURL)
    }

    private func warmPipelines() {
        for family in KernelFamily.allCases {
            _ = try? pipeline(for: family)
        }
    }
}

/// Metal kernel family identifiers.
///
/// Each family corresponds to a group of related Metal compute functions.
public enum KernelFamily: String, Sendable, Hashable, CaseIterable {
    case fieldArithmetic = "nu_field"
    case fq2Arithmetic = "nu_fq2"
    case sparseRotationCommit = "nu_sparse_rot_commit"
    case sparseRotationCommitBatch = "nu_sparse_rot_commit_batch"
    case ringMultiplyAG64 = "nu_ring_mul_ag64_d64"
    case ringBindFoldBatch = "nu_ring_bind_fold_batch"
    case matrixLift = "nu_matrix_lift"
    case sumCheckPartial = "nu_sumcheck_partial"
    case piRLCFold = "nu_pirlc_fold"
    case piDECDecompose = "nu_pidec_decompose"

    /// Metal function name for this kernel family.
    var functionName: String { rawValue }
}

/// Errors from the Metal subsystem.
public enum NuMetalError: Error, Sendable {
    case noGPU
    case unsupportedCPUArchitecture
    case unsupportedGPUFamily
    case commandQueueFailed
    case heapCreationFailed
    case libraryNotFound
    case libraryCompilationFailed(String)
    case functionNotFound(String)
    case encodingFailed
    case executionFailed
    case invalidDecompositionBase(UInt8)
    case indirectCommandBufferUnavailable
}
