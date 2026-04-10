import Foundation
import Metal

// MARK: - Kernel Dispatch
// Typed dispatch wrappers for each kernel family.
// Maps high-level proving operations to Metal compute dispatches.

private struct TimestampSamplePair {
    let start: UInt64
    let end: UInt64
}

private struct MatrixLiftDispatchParams {
    var numRows: UInt32
    var valueCount: UInt32
    var xCount: UInt32
}

private struct SumCheckDispatchParams {
    var count: UInt32
    var outputCount: UInt32
}

private struct SealQueryDispatchParams {
    var numQueries: UInt32
    var codewordLength: UInt32
}

public final class KernelDispatcher: @unchecked Sendable {
    private let context: MetalContext
    private let scheduler: ProverScheduler

    public init(context: MetalContext, scheduler: ProverScheduler = ProverScheduler()) {
        self.context = context
        self.scheduler = scheduler
    }

    @discardableResult
    private func commitAndMeasure(
        _ cmdBuffer: MTLCommandBuffer,
        family: KernelFamily,
        threadExecutionWidth: Int,
        threadgroupWidth: Int,
        counterSampleBuffer: MTLCounterSampleBuffer? = nil,
        trace: TimedDispatchTraceContext? = nil
    ) throws -> MetalDispatchTiming {
        let start = DispatchTime.now().uptimeNanoseconds
        cmdBuffer.commit()
        cmdBuffer.waitUntilCompleted()
        let elapsed = Double(DispatchTime.now().uptimeNanoseconds - start) / 1_000_000.0

        if cmdBuffer.status == .error {
            throw NuMetalError.executionFailed
        }

        let counterSamplingAvailable = counterSampleBuffer != nil
        let counterSamples = decodeTimestampSamples(counterSampleBuffer)
        let gpuWindowMilliseconds = gpuDurationMilliseconds(for: cmdBuffer)
        let gpuMilliseconds = gpuDurationMilliseconds(
            from: counterSamples,
            fallback: gpuWindowMilliseconds
        )
        let gpuStartOffsetMicroseconds: Double?
        let gpuEndOffsetMicroseconds: Double?
        if let counterSamples,
           let gpuMilliseconds {
            let offsets = gpuOffsetsMicroseconds(
                from: counterSamples,
                gpuDurationMilliseconds: gpuMilliseconds
            )
            gpuStartOffsetMicroseconds = offsets.start
            gpuEndOffsetMicroseconds = offsets.end
        } else {
            gpuStartOffsetMicroseconds = nil
            gpuEndOffsetMicroseconds = nil
        }

        let counterCaptured = counterSamples != nil

        let timing = MetalDispatchTiming(
            cpuMilliseconds: elapsed,
            gpuMilliseconds: gpuMilliseconds,
            counterSamplingAvailable: counterSamplingAvailable,
            gpuStartOffsetMicroseconds: gpuStartOffsetMicroseconds,
            gpuEndOffsetMicroseconds: gpuEndOffsetMicroseconds,
            threadExecutionWidth: threadExecutionWidth,
            threadgroupWidth: threadgroupWidth,
            counterSampleCaptured: counterCaptured
        )
        if let trace {
            trace.collector.append(
                stage: trace.stage,
                iteration: trace.iteration,
                dispatchLabel: trace.dispatchLabel,
                kernelFamily: family,
                timing: timing
            )
        }
        return timing
    }

    private func canonicalThreadgroupSize(
        requestedWidth: Int,
        pipeline: MTLComputePipelineState
    ) -> MTLSize {
        let executionWidth = max(1, Int(pipeline.threadExecutionWidth))
        let maxWidth = min(context.maxThreadsPerThreadgroupWidth, pipeline.maxTotalThreadsPerThreadgroup)
        let clamped = max(executionWidth, min(requestedWidth, maxWidth))
        let rounded = max(
            executionWidth,
            min(maxWidth, (clamped / executionWidth) * executionWidth)
        )
        return MTLSize(width: rounded, height: 1, depth: 1)
    }

    private func decodeTimestampSamples(
        _ counterSampleBuffer: MTLCounterSampleBuffer?
    ) -> TimestampSamplePair? {
        guard let counterSampleBuffer,
              let data = try? counterSampleBuffer.resolveCounterRange(
                0..<counterSampleBuffer.sampleCount
              ) else {
            return nil
        }

        let stride = MemoryLayout<MTLCounterResultTimestamp>.stride
        guard data.count >= stride * 2 else {
            return nil
        }

        return data.withUnsafeBytes { rawBuffer in
            guard let baseAddress = rawBuffer.baseAddress else {
                return nil
            }
            let start = baseAddress
                .assumingMemoryBound(to: MTLCounterResultTimestamp.self)
                .pointee
                .timestamp
            let end = baseAddress
                .advanced(by: stride)
                .assumingMemoryBound(to: MTLCounterResultTimestamp.self)
                .pointee
                .timestamp
            guard end >= start else {
                return nil
            }
            return TimestampSamplePair(start: start, end: end)
        }
    }

    private func gpuDurationMilliseconds(for cmdBuffer: MTLCommandBuffer) -> Double? {
        guard cmdBuffer.gpuStartTime > 0,
              cmdBuffer.gpuEndTime >= cmdBuffer.gpuStartTime else {
            return nil
        }
        return (cmdBuffer.gpuEndTime - cmdBuffer.gpuStartTime) * 1_000.0
    }

    private func gpuDurationMilliseconds(
        from counterSamples: TimestampSamplePair?,
        fallback: Double?
    ) -> Double? {
        guard let counterSamples,
              counterSamples.end > counterSamples.start else {
            return fallback
        }

        let tickDelta = Double(counterSamples.end - counterSamples.start)
        guard tickDelta > 0 else {
            return fallback
        }
        return tickDelta / 1_000_000.0
    }

    private func gpuOffsetsMicroseconds(
        from counterSamples: TimestampSamplePair,
        gpuDurationMilliseconds: Double
    ) -> (start: Double, end: Double) {
        let tickDelta = Double(counterSamples.end - counterSamples.start)
        guard tickDelta > 0 else {
            let durationUs = gpuDurationMilliseconds * 1_000.0
            return (0, durationUs)
        }

        let durationUs = gpuDurationMilliseconds * 1_000.0
        let start = 0.0
        let end = start + durationUs
        return (start, end)
    }

    private func preconditionThreadgroupWidth(
        _ threadgroupWidth: Int,
        executionWidth: Int
    ) {
        precondition(
            threadgroupWidth % max(1, executionWidth) == 0,
            "Threadgroup width \(threadgroupWidth) must be a multiple of threadExecutionWidth \(executionWidth)"
        )
    }

    private func sampleCountersIfAvailable(
        _ encoder: MTLComputeCommandEncoder,
        sampleBuffer: MTLCounterSampleBuffer?,
        sampleIndex: Int,
        barrier: Bool
    ) {
        guard let sampleBuffer,
              sampleIndex >= 0,
              sampleIndex < sampleBuffer.sampleCount else {
            return
        }
        if #available(macOS 10.15, iOS 14.0, *) {
            encoder.sampleCounters(
                sampleBuffer: sampleBuffer,
                sampleIndex: sampleIndex,
                barrier: barrier
            )
        }
    }

    public func makeStage(label: String? = nil) throws -> MetalStageCommandBuffer {
        try MetalStageCommandBuffer(context: context, label: label)
    }

    // MARK: - Sparse Rotation Commitment

    /// Dispatch the rotation-matrix Ajtai commitment kernel.
    ///
    /// Computes one ring element C = Σᵢ (aᵢ · wᵢ) in Rq with aᵢ,wᵢ ∈ Rq,
    /// using dense key coefficients (`keyCount * 64` limbs) and witness rings
    /// of the same layout. Grid width is `RingElement.degree` (64). No NTTs.
    public func dispatchSparseRotationCommit(
        keyRingCoefficients: MTLBuffer,
        witnessBuffer: MTLBuffer,
        outputBuffer: MTLBuffer,
        keyCount: Int
    ) throws {
        let params = scheduler.productionParams()
        let pso = try context.pipeline(for: .sparseRotationCommit)

        guard let cmdBuffer = context.commandQueue.makeCommandBuffer(),
              let encoder = cmdBuffer.makeComputeCommandEncoder() else {
            throw NuMetalError.encodingFailed
        }

        encoder.setComputePipelineState(pso)
        encoder.setBuffer(keyRingCoefficients, offset: 0, index: 0)
        encoder.setBuffer(witnessBuffer, offset: 0, index: 1)
        encoder.setBuffer(outputBuffer, offset: 0, index: 2)

        var keyCountU32 = UInt32(keyCount)
        encoder.setBytes(&keyCountU32, length: 4, index: 3)

        let threadgroupSize = canonicalThreadgroupSize(
            requestedWidth: params.threadgroupSize,
            pipeline: pso
        )
        let gridSize = MTLSize(width: RingElement.degree, height: 1, depth: 1)
        encoder.dispatchThreads(gridSize, threadsPerThreadgroup: threadgroupSize)

        encoder.endEncoding()
        cmdBuffer.commit()
        cmdBuffer.waitUntilCompleted()

        if cmdBuffer.status == .error {
            throw NuMetalError.executionFailed
        }
    }

    public func dispatchSparseRotationCommitBatch(
        keyRingCoefficients: MTLBuffer,
        witnessBatchBuffer: MTLBuffer,
        outputBuffer: MTLBuffer,
        keyCount: Int,
        batchCount: Int
    ) throws {
        let params = scheduler.productionParams()
        let pso = try context.pipeline(for: .sparseRotationCommitBatch)

        guard let cmdBuffer = context.commandQueue.makeCommandBuffer(),
              let encoder = cmdBuffer.makeComputeCommandEncoder() else {
            throw NuMetalError.encodingFailed
        }

        encoder.setComputePipelineState(pso)
        encoder.setBuffer(keyRingCoefficients, offset: 0, index: 0)
        encoder.setBuffer(witnessBatchBuffer, offset: 0, index: 1)
        encoder.setBuffer(outputBuffer, offset: 0, index: 2)

        var keyCountU32 = UInt32(keyCount)
        var batchCountU32 = UInt32(batchCount)
        encoder.setBytes(&keyCountU32, length: 4, index: 3)
        encoder.setBytes(&batchCountU32, length: 4, index: 4)

        let threadgroupSize = canonicalThreadgroupSize(
            requestedWidth: params.threadgroupSize,
            pipeline: pso
        )
        let gridSize = MTLSize(width: batchCount * RingElement.degree, height: 1, depth: 1)
        encoder.dispatchThreads(gridSize, threadsPerThreadgroup: threadgroupSize)
        encoder.endEncoding()
        cmdBuffer.commit()
        cmdBuffer.waitUntilCompleted()

        if cmdBuffer.status == .error {
            throw NuMetalError.executionFailed
        }
    }

    package func dispatchSparseRotationCommitBatchTimed(
        keyRingCoefficients: MTLBuffer,
        witnessBatchBuffer: MTLBuffer,
        outputBuffer: MTLBuffer,
        keyCount: Int,
        batchCount: Int,
        trace: TimedDispatchTraceContext
    ) throws -> MetalDispatchTiming {
        let params = scheduler.productionParams()
        let pso = try context.pipeline(for: .sparseRotationCommitBatch)

        guard let cmdBuffer = context.commandQueue.makeCommandBuffer(),
              let encoder = cmdBuffer.makeComputeCommandEncoder() else {
            throw NuMetalError.encodingFailed
        }

        encoder.setComputePipelineState(pso)
        encoder.setBuffer(keyRingCoefficients, offset: 0, index: 0)
        encoder.setBuffer(witnessBatchBuffer, offset: 0, index: 1)
        encoder.setBuffer(outputBuffer, offset: 0, index: 2)

        var keyCountU32 = UInt32(keyCount)
        var batchCountU32 = UInt32(batchCount)
        encoder.setBytes(&keyCountU32, length: 4, index: 3)
        encoder.setBytes(&batchCountU32, length: 4, index: 4)

        let threadgroupSize = canonicalThreadgroupSize(
            requestedWidth: params.threadgroupSize,
            pipeline: pso
        )
        preconditionThreadgroupWidth(threadgroupSize.width, executionWidth: Int(pso.threadExecutionWidth))
        let gridSize = MTLSize(width: batchCount * RingElement.degree, height: 1, depth: 1)
        let counterSampleBuffer = context.makeCounterSampleBuffer(
            sampleCount: 2,
            label: "NuMeQ.\(trace.dispatchLabel)"
        )
        sampleCountersIfAvailable(encoder, sampleBuffer: counterSampleBuffer, sampleIndex: 0, barrier: true)
        encoder.dispatchThreads(gridSize, threadsPerThreadgroup: threadgroupSize)
        sampleCountersIfAvailable(encoder, sampleBuffer: counterSampleBuffer, sampleIndex: 1, barrier: true)
        encoder.endEncoding()

        return try commitAndMeasure(
            cmdBuffer,
            family: .sparseRotationCommitBatch,
            threadExecutionWidth: Int(pso.threadExecutionWidth),
            threadgroupWidth: threadgroupSize.width,
            counterSampleBuffer: counterSampleBuffer,
            trace: trace
        )
    }

    public func dispatchSparseRotationCommit(
        keyRingCoefficients: MetalBufferSlice,
        witnessBuffer: MetalBufferSlice,
        outputBuffer: MetalBufferSlice,
        keyCountBuffer: MetalBufferSlice
    ) throws {
        let params = scheduler.productionParams()
        let pipeline = try context.pipeline(for: .sparseRotationCommit)
        let threadgroupSize = canonicalThreadgroupSize(
            requestedWidth: params.threadgroupSize,
            pipeline: pipeline
        )
        let gridSize = MTLSize(width: RingElement.degree, height: 1, depth: 1)
        try executeIndirectCompute(
            family: .sparseRotationCommit,
            buffers: [
                (keyRingCoefficients.buffer, keyRingCoefficients.offset, 0, .read),
                (witnessBuffer.buffer, witnessBuffer.offset, 1, .read),
                (outputBuffer.buffer, outputBuffer.offset, 2, .write),
                (keyCountBuffer.buffer, keyCountBuffer.offset, 3, .read),
            ],
            threadsPerGrid: gridSize,
            threadsPerThreadgroup: threadgroupSize,
            maxKernelBufferBindCount: 4
        )
    }

    // MARK: - Ring Multiplication

    /// Dispatch the AG64 degree-64 negacyclic ring multiplication kernel.
    @available(*, unavailable, message: "Direct AG64 degree-64 multiplication kernels are barred from the canonical Fq4 production path.")
    public func dispatchRingMultiply(
        lhsBuffer: MTLBuffer,
        rhsBuffer: MTLBuffer,
        outputBuffer: MTLBuffer
    ) throws {
        let params = scheduler.productionParams()
        let pso = try context.pipeline(for: .ringMultiplyAG64)

        guard let cmdBuffer = context.commandQueue.makeCommandBuffer(),
              let encoder = cmdBuffer.makeComputeCommandEncoder() else {
            throw NuMetalError.encodingFailed
        }

        encoder.setComputePipelineState(pso)
        encoder.setBuffer(lhsBuffer, offset: 0, index: 0)
        encoder.setBuffer(rhsBuffer, offset: 0, index: 1)
        encoder.setBuffer(outputBuffer, offset: 0, index: 2)
        var ringCount: UInt32 = 1
        encoder.setBytes(&ringCount, length: MemoryLayout<UInt32>.size, index: 3)

        let threadgroupSize = canonicalThreadgroupSize(
            requestedWidth: params.threadgroupSize,
            pipeline: pso
        )
        let gridSize = MTLSize(width: RingElement.degree, height: 1, depth: 1)
        encoder.dispatchThreads(gridSize, threadsPerThreadgroup: threadgroupSize)

        encoder.endEncoding()
        cmdBuffer.commit()
        cmdBuffer.waitUntilCompleted()

        if cmdBuffer.status == .error {
            throw NuMetalError.executionFailed
        }
    }

    public func dispatchRingMultiplyBatch(
        lhsBuffer: MTLBuffer,
        rhsBuffer: MTLBuffer,
        outputBuffer: MTLBuffer,
        ringCount: Int
    ) throws {
        let params = scheduler.productionParams()
        let pso = try context.pipeline(for: .ringMultiplyAG64)

        guard let cmdBuffer = context.commandQueue.makeCommandBuffer(),
              let encoder = cmdBuffer.makeComputeCommandEncoder() else {
            throw NuMetalError.encodingFailed
        }

        encoder.setComputePipelineState(pso)
        encoder.setBuffer(lhsBuffer, offset: 0, index: 0)
        encoder.setBuffer(rhsBuffer, offset: 0, index: 1)
        encoder.setBuffer(outputBuffer, offset: 0, index: 2)
        var ringCountU32 = UInt32(ringCount)
        encoder.setBytes(&ringCountU32, length: MemoryLayout<UInt32>.size, index: 3)

        let threadgroupSize = canonicalThreadgroupSize(
            requestedWidth: params.threadgroupSize,
            pipeline: pso
        )
        let gridSize = MTLSize(width: ringCount * RingElement.degree, height: 1, depth: 1)
        encoder.dispatchThreads(gridSize, threadsPerThreadgroup: threadgroupSize)
        encoder.endEncoding()
        cmdBuffer.commit()
        cmdBuffer.waitUntilCompleted()

        if cmdBuffer.status == .error {
            throw NuMetalError.executionFailed
        }
    }

    package func dispatchRingMultiplyBatchTimed(
        lhsBuffer: MTLBuffer,
        rhsBuffer: MTLBuffer,
        outputBuffer: MTLBuffer,
        ringCount: Int,
        trace: TimedDispatchTraceContext
    ) throws -> MetalDispatchTiming {
        let params = scheduler.productionParams()
        let pso = try context.pipeline(for: .ringMultiplyAG64)

        guard let cmdBuffer = context.commandQueue.makeCommandBuffer(),
              let encoder = cmdBuffer.makeComputeCommandEncoder() else {
            throw NuMetalError.encodingFailed
        }

        encoder.setComputePipelineState(pso)
        encoder.setBuffer(lhsBuffer, offset: 0, index: 0)
        encoder.setBuffer(rhsBuffer, offset: 0, index: 1)
        encoder.setBuffer(outputBuffer, offset: 0, index: 2)
        var ringCountU32 = UInt32(ringCount)
        encoder.setBytes(&ringCountU32, length: MemoryLayout<UInt32>.size, index: 3)

        let threadgroupSize = canonicalThreadgroupSize(
            requestedWidth: params.threadgroupSize,
            pipeline: pso
        )
        preconditionThreadgroupWidth(threadgroupSize.width, executionWidth: Int(pso.threadExecutionWidth))
        let gridSize = MTLSize(width: ringCount * RingElement.degree, height: 1, depth: 1)
        let counterSampleBuffer = context.makeCounterSampleBuffer(
            sampleCount: 2,
            label: "NuMeQ.\(trace.dispatchLabel)"
        )
        sampleCountersIfAvailable(encoder, sampleBuffer: counterSampleBuffer, sampleIndex: 0, barrier: true)
        encoder.dispatchThreads(gridSize, threadsPerThreadgroup: threadgroupSize)
        sampleCountersIfAvailable(encoder, sampleBuffer: counterSampleBuffer, sampleIndex: 1, barrier: true)
        encoder.endEncoding()

        return try commitAndMeasure(
            cmdBuffer,
            family: .ringMultiplyAG64,
            threadExecutionWidth: Int(pso.threadExecutionWidth),
            threadgroupWidth: threadgroupSize.width,
            counterSampleBuffer: counterSampleBuffer,
            trace: trace
        )
    }

    @available(*, unavailable, message: "Direct AG64 degree-64 multiplication kernels are barred from the canonical Fq4 production path.")
    public func dispatchRingMultiply(
        lhsBuffer: MetalBufferSlice,
        rhsBuffer: MetalBufferSlice,
        outputBuffer: MetalBufferSlice,
        ringCountBuffer: MetalBufferSlice
    ) throws {
        let params = scheduler.productionParams()
        let pipeline = try context.pipeline(for: .ringMultiplyAG64)
        let threadgroupSize = canonicalThreadgroupSize(
            requestedWidth: params.threadgroupSize,
            pipeline: pipeline
        )
        let gridSize = MTLSize(width: RingElement.degree, height: 1, depth: 1)
        try executeIndirectCompute(
            family: .ringMultiplyAG64,
            buffers: [
                (lhsBuffer.buffer, lhsBuffer.offset, 0, .read),
                (rhsBuffer.buffer, rhsBuffer.offset, 1, .read),
                (outputBuffer.buffer, outputBuffer.offset, 2, .write),
                (ringCountBuffer.buffer, ringCountBuffer.offset, 3, .read),
            ],
            threadsPerGrid: gridSize,
            threadsPerThreadgroup: threadgroupSize,
            maxKernelBufferBindCount: 4
        )
    }

    public func dispatchRingBindFoldBatch(
        challengeBuffer: MTLBuffer,
        inputBuffer: MTLBuffer,
        outputBuffer: MTLBuffer,
        sourceCount: Int,
        ringCount: Int
    ) throws {
        let params = scheduler.productionParams()
        let pso = try context.pipeline(for: .ringBindFoldBatch)

        guard let cmdBuffer = context.commandQueue.makeCommandBuffer(),
              let encoder = cmdBuffer.makeComputeCommandEncoder() else {
            throw NuMetalError.encodingFailed
        }

        encoder.setComputePipelineState(pso)
        encoder.setBuffer(challengeBuffer, offset: 0, index: 0)
        encoder.setBuffer(inputBuffer, offset: 0, index: 1)
        encoder.setBuffer(outputBuffer, offset: 0, index: 2)
        var sourceCountU32 = UInt32(sourceCount)
        var ringCountU32 = UInt32(ringCount)
        encoder.setBytes(&sourceCountU32, length: MemoryLayout<UInt32>.size, index: 3)
        encoder.setBytes(&ringCountU32, length: MemoryLayout<UInt32>.size, index: 4)

        let threadgroupSize = canonicalThreadgroupSize(
            requestedWidth: params.threadgroupSize,
            pipeline: pso
        )
        let gridSize = MTLSize(width: ringCount * RingElement.degree, height: 1, depth: 1)
        encoder.dispatchThreads(gridSize, threadsPerThreadgroup: threadgroupSize)
        encoder.endEncoding()
        cmdBuffer.commit()
        cmdBuffer.waitUntilCompleted()

        if cmdBuffer.status == .error {
            throw NuMetalError.executionFailed
        }
    }

    package func dispatchRingBindFoldBatchTimed(
        challengeBuffer: MTLBuffer,
        inputBuffer: MTLBuffer,
        outputBuffer: MTLBuffer,
        sourceCount: Int,
        ringCount: Int,
        trace: TimedDispatchTraceContext
    ) throws -> MetalDispatchTiming {
        let params = scheduler.productionParams()
        let pso = try context.pipeline(for: .ringBindFoldBatch)

        guard let cmdBuffer = context.commandQueue.makeCommandBuffer(),
              let encoder = cmdBuffer.makeComputeCommandEncoder() else {
            throw NuMetalError.encodingFailed
        }

        encoder.setComputePipelineState(pso)
        encoder.setBuffer(challengeBuffer, offset: 0, index: 0)
        encoder.setBuffer(inputBuffer, offset: 0, index: 1)
        encoder.setBuffer(outputBuffer, offset: 0, index: 2)
        var sourceCountU32 = UInt32(sourceCount)
        var ringCountU32 = UInt32(ringCount)
        encoder.setBytes(&sourceCountU32, length: MemoryLayout<UInt32>.size, index: 3)
        encoder.setBytes(&ringCountU32, length: MemoryLayout<UInt32>.size, index: 4)

        let threadgroupSize = canonicalThreadgroupSize(
            requestedWidth: params.threadgroupSize,
            pipeline: pso
        )
        preconditionThreadgroupWidth(threadgroupSize.width, executionWidth: Int(pso.threadExecutionWidth))
        let gridSize = MTLSize(width: ringCount * RingElement.degree, height: 1, depth: 1)
        let counterSampleBuffer = context.makeCounterSampleBuffer(
            sampleCount: 2,
            label: "NuMeQ.\(trace.dispatchLabel)"
        )
        sampleCountersIfAvailable(encoder, sampleBuffer: counterSampleBuffer, sampleIndex: 0, barrier: true)
        encoder.dispatchThreads(gridSize, threadsPerThreadgroup: threadgroupSize)
        sampleCountersIfAvailable(encoder, sampleBuffer: counterSampleBuffer, sampleIndex: 1, barrier: true)
        encoder.endEncoding()

        return try commitAndMeasure(
            cmdBuffer,
            family: .ringBindFoldBatch,
            threadExecutionWidth: Int(pso.threadExecutionWidth),
            threadgroupWidth: threadgroupSize.width,
            counterSampleBuffer: counterSampleBuffer,
            trace: trace
        )
    }

    // MARK: - Sum-Check Partial Reduction

    public func dispatchMatrixLift(
        rowPtrBuffer: MTLBuffer,
        colIdxBuffer: MTLBuffer,
        valuesBuffer: MTLBuffer,
        xBuffer: MTLBuffer,
        yBuffer: MTLBuffer,
        numRows: Int,
        valueCount: Int,
        xCount: Int
    ) throws {
        let params = scheduler.productionParams()
        let pso = try context.pipeline(for: .matrixLift)

        guard let cmdBuffer = context.commandQueue.makeCommandBuffer(),
              let encoder = cmdBuffer.makeComputeCommandEncoder() else {
            throw NuMetalError.encodingFailed
        }

        encoder.setComputePipelineState(pso)
        encoder.setBuffer(rowPtrBuffer, offset: 0, index: 0)
        encoder.setBuffer(colIdxBuffer, offset: 0, index: 1)
        encoder.setBuffer(valuesBuffer, offset: 0, index: 2)
        encoder.setBuffer(xBuffer, offset: 0, index: 3)
        encoder.setBuffer(yBuffer, offset: 0, index: 4)

        var dispatchParams = MatrixLiftDispatchParams(
            numRows: UInt32(numRows),
            valueCount: UInt32(valueCount),
            xCount: UInt32(xCount)
        )
        encoder.setBytes(&dispatchParams, length: MemoryLayout<MatrixLiftDispatchParams>.size, index: 5)

        let threadgroupSize = canonicalThreadgroupSize(
            requestedWidth: max(params.threadgroupSize, Int(MetalStorageLayout.matrixRowTile)),
            pipeline: pso
        )
        let gridSize = MTLSize(width: numRows, height: 1, depth: 1)
        encoder.dispatchThreads(gridSize, threadsPerThreadgroup: threadgroupSize)

        encoder.endEncoding()
        cmdBuffer.commit()
        cmdBuffer.waitUntilCompleted()

        if cmdBuffer.status == .error {
            throw NuMetalError.executionFailed
        }
    }

    public func dispatchMatrixLift(
        rowPtrBuffer: MetalBufferSlice,
        colIdxBuffer: MetalBufferSlice,
        valuesBuffer: MetalBufferSlice,
        xBuffer: MetalBufferSlice,
        yBuffer: MetalBufferSlice,
        paramsBuffer: MetalBufferSlice,
        numRows: Int
    ) throws {
        let params = scheduler.productionParams()
        let pipeline = try context.pipeline(for: .matrixLift)
        guard let cmdBuffer = context.commandQueue.makeCommandBuffer(),
              let encoder = cmdBuffer.makeComputeCommandEncoder() else {
            throw NuMetalError.encodingFailed
        }

        encoder.setComputePipelineState(pipeline)
        encoder.setBuffer(rowPtrBuffer.buffer, offset: rowPtrBuffer.offset, index: 0)
        encoder.setBuffer(colIdxBuffer.buffer, offset: colIdxBuffer.offset, index: 1)
        encoder.setBuffer(valuesBuffer.buffer, offset: valuesBuffer.offset, index: 2)
        encoder.setBuffer(xBuffer.buffer, offset: xBuffer.offset, index: 3)
        encoder.setBuffer(yBuffer.buffer, offset: yBuffer.offset, index: 4)
        encoder.setBuffer(paramsBuffer.buffer, offset: paramsBuffer.offset, index: 5)

        let threadgroupSize = canonicalThreadgroupSize(
            requestedWidth: max(params.threadgroupSize, Int(MetalStorageLayout.matrixRowTile)),
            pipeline: pipeline
        )
        let gridSize = MTLSize(width: numRows, height: 1, depth: 1)
        encoder.dispatchThreads(gridSize, threadsPerThreadgroup: threadgroupSize)
        encoder.endEncoding()
        cmdBuffer.commit()
        cmdBuffer.waitUntilCompleted()

        if cmdBuffer.status == .error {
            throw NuMetalError.executionFailed
        }
    }

    package func dispatchMatrixLiftTimed(
        rowPtrBuffer: MetalBufferSlice,
        colIdxBuffer: MetalBufferSlice,
        valuesBuffer: MetalBufferSlice,
        xBuffer: MetalBufferSlice,
        yBuffer: MetalBufferSlice,
        paramsBuffer: MetalBufferSlice,
        numRows: Int,
        trace: TimedDispatchTraceContext
    ) throws -> MetalDispatchTiming {
        let params = scheduler.productionParams()
        let pso = try context.pipeline(for: .matrixLift)
        guard let cmdBuffer = context.commandQueue.makeCommandBuffer(),
              let encoder = cmdBuffer.makeComputeCommandEncoder() else {
            throw NuMetalError.encodingFailed
        }

        encoder.setComputePipelineState(pso)
        encoder.setBuffer(rowPtrBuffer.buffer, offset: rowPtrBuffer.offset, index: 0)
        encoder.setBuffer(colIdxBuffer.buffer, offset: colIdxBuffer.offset, index: 1)
        encoder.setBuffer(valuesBuffer.buffer, offset: valuesBuffer.offset, index: 2)
        encoder.setBuffer(xBuffer.buffer, offset: xBuffer.offset, index: 3)
        encoder.setBuffer(yBuffer.buffer, offset: yBuffer.offset, index: 4)
        encoder.setBuffer(paramsBuffer.buffer, offset: paramsBuffer.offset, index: 5)

        let threadgroupSize = canonicalThreadgroupSize(
            requestedWidth: max(params.threadgroupSize, Int(MetalStorageLayout.matrixRowTile)),
            pipeline: pso
        )
        preconditionThreadgroupWidth(threadgroupSize.width, executionWidth: Int(pso.threadExecutionWidth))
        let gridSize = MTLSize(width: numRows, height: 1, depth: 1)
        let counterSampleBuffer = context.makeCounterSampleBuffer(
            sampleCount: 2,
            label: "NuMeQ.\(trace.dispatchLabel)"
        )
        sampleCountersIfAvailable(encoder, sampleBuffer: counterSampleBuffer, sampleIndex: 0, barrier: true)
        encoder.dispatchThreads(gridSize, threadsPerThreadgroup: threadgroupSize)
        sampleCountersIfAvailable(encoder, sampleBuffer: counterSampleBuffer, sampleIndex: 1, barrier: true)
        encoder.endEncoding()

        return try commitAndMeasure(
            cmdBuffer,
            family: .matrixLift,
            threadExecutionWidth: Int(pso.threadExecutionWidth),
            threadgroupWidth: threadgroupSize.width,
            counterSampleBuffer: counterSampleBuffer,
            trace: trace
        )
    }

    /// Dispatch sum-check partial evaluation kernel.
    ///
    /// For each round of the sum-check, computes partial sums over
    /// the boolean hypercube in parallel.
    public func dispatchSumCheckPartial(
        evalBuffer: MTLBuffer,
        outputBuffer: MTLBuffer,
        numElements: Int,
        outputCount: Int
    ) throws {
        let scheduleParams = scheduler.productionParams()
        let pso = try context.pipeline(for: .sumCheckPartial)

        guard let cmdBuffer = context.commandQueue.makeCommandBuffer(),
              let encoder = cmdBuffer.makeComputeCommandEncoder() else {
            throw NuMetalError.encodingFailed
        }

        encoder.setComputePipelineState(pso)
        encoder.setBuffer(evalBuffer, offset: 0, index: 0)
        encoder.setBuffer(outputBuffer, offset: 0, index: 1)

        var dispatchParams = SumCheckDispatchParams(
            count: UInt32(numElements),
            outputCount: UInt32(outputCount)
        )
        encoder.setBytes(&dispatchParams, length: MemoryLayout<SumCheckDispatchParams>.size, index: 2)

        let threadgroupSize = canonicalThreadgroupSize(
            requestedWidth: scheduleParams.threadgroupSize,
            pipeline: pso
        )
        let gridSize = MTLSize(width: (numElements + 1) / 2, height: 1, depth: 1)
        encoder.dispatchThreads(gridSize, threadsPerThreadgroup: threadgroupSize)

        encoder.endEncoding()
        cmdBuffer.commit()
        cmdBuffer.waitUntilCompleted()

        if cmdBuffer.status == .error {
            throw NuMetalError.executionFailed
        }
    }

    public func dispatchSumCheckPartial(
        evalBuffer: MetalBufferSlice,
        outputBuffer: MetalBufferSlice,
        paramsBuffer: MetalBufferSlice,
        numElements: Int
    ) throws {
        let params = scheduler.productionParams()
        let pipeline = try context.pipeline(for: .sumCheckPartial)
        let threadgroupSize = canonicalThreadgroupSize(
            requestedWidth: params.threadgroupSize,
            pipeline: pipeline
        )
        let gridSize = MTLSize(width: (numElements + 1) / 2, height: 1, depth: 1)
        try executeIndirectCompute(
            family: .sumCheckPartial,
            buffers: [
                (evalBuffer.buffer, evalBuffer.offset, 0, .read),
                (outputBuffer.buffer, outputBuffer.offset, 1, .write),
                (paramsBuffer.buffer, paramsBuffer.offset, 2, .read),
            ],
            threadsPerGrid: gridSize,
            threadsPerThreadgroup: threadgroupSize,
            maxKernelBufferBindCount: 3
        )
    }

    // MARK: - Merkle Hash

    /// Dispatch Merkle tree hashing kernel for seal proofs.
    public func dispatchMerkleHash(
        leavesBuffer: MTLBuffer,
        nodesBuffer: MTLBuffer,
        numLeaves: Int
    ) throws {
        _ = try dispatchMerkleHashTimed(
            leavesBuffer: leavesBuffer,
            nodesBuffer: nodesBuffer,
            numLeaves: numLeaves
        )
    }

    public func dispatchMerkleHashTimed(
        leavesBuffer: MTLBuffer,
        nodesBuffer: MTLBuffer,
        numLeaves: Int
    ) throws -> MetalDispatchTiming {
        let pso = try context.pipeline(for: .merkleHash)

        guard let cmdBuffer = context.commandQueue.makeCommandBuffer(),
              let encoder = cmdBuffer.makeComputeCommandEncoder() else {
            throw NuMetalError.encodingFailed
        }

        encoder.setComputePipelineState(pso)
        encoder.setBuffer(leavesBuffer, offset: 0, index: 0)
        encoder.setBuffer(nodesBuffer, offset: 0, index: 1)

        var count = UInt32(numLeaves)
        encoder.setBytes(&count, length: 4, index: 2)

        let threadgroupSize = canonicalThreadgroupSize(
            requestedWidth: Int(MetalStorageLayout.defaultMerkleChunkSize),
            pipeline: pso
        )
        preconditionThreadgroupWidth(threadgroupSize.width, executionWidth: Int(pso.threadExecutionWidth))
        let gridSize = MTLSize(width: numLeaves, height: 1, depth: 1)
        let counterSampleBuffer = context.makeCounterSampleBuffer(sampleCount: 2, label: "NuMeQ.MerkleHash")
        sampleCountersIfAvailable(encoder, sampleBuffer: counterSampleBuffer, sampleIndex: 0, barrier: true)
        encoder.dispatchThreads(gridSize, threadsPerThreadgroup: threadgroupSize)
        sampleCountersIfAvailable(encoder, sampleBuffer: counterSampleBuffer, sampleIndex: 1, barrier: true)

        encoder.endEncoding()
        return try commitAndMeasure(
            cmdBuffer,
            family: .merkleHash,
            threadExecutionWidth: Int(pso.threadExecutionWidth),
            threadgroupWidth: threadgroupSize.width,
            counterSampleBuffer: counterSampleBuffer
        )
    }

    public func dispatchMerkleParent(
        childBuffer: MTLBuffer,
        parentBuffer: MTLBuffer,
        numParents: Int
    ) throws {
        _ = try dispatchMerkleParentTimed(
            childBuffer: childBuffer,
            parentBuffer: parentBuffer,
            numParents: numParents
        )
    }

    public func dispatchMerkleParentTimed(
        childBuffer: MTLBuffer,
        parentBuffer: MTLBuffer,
        numParents: Int
    ) throws -> MetalDispatchTiming {
        let pso = try context.pipeline(for: .merkleParent)

        guard let cmdBuffer = context.commandQueue.makeCommandBuffer(),
              let encoder = cmdBuffer.makeComputeCommandEncoder() else {
            throw NuMetalError.encodingFailed
        }

        encoder.setComputePipelineState(pso)
        encoder.setBuffer(childBuffer, offset: 0, index: 0)
        encoder.setBuffer(parentBuffer, offset: 0, index: 1)

        var parentCount = UInt32(numParents)
        encoder.setBytes(&parentCount, length: 4, index: 2)

        let threadgroupSize = canonicalThreadgroupSize(
            requestedWidth: Int(MetalStorageLayout.defaultMerkleChunkSize),
            pipeline: pso
        )
        preconditionThreadgroupWidth(threadgroupSize.width, executionWidth: Int(pso.threadExecutionWidth))
        let gridSize = MTLSize(width: numParents, height: 1, depth: 1)
        let counterSampleBuffer = context.makeCounterSampleBuffer(sampleCount: 2, label: "NuMeQ.MerkleParent")
        sampleCountersIfAvailable(encoder, sampleBuffer: counterSampleBuffer, sampleIndex: 0, barrier: true)
        encoder.dispatchThreads(gridSize, threadsPerThreadgroup: threadgroupSize)
        sampleCountersIfAvailable(encoder, sampleBuffer: counterSampleBuffer, sampleIndex: 1, barrier: true)

        encoder.endEncoding()
        return try commitAndMeasure(
            cmdBuffer,
            family: .merkleParent,
            threadExecutionWidth: Int(pso.threadExecutionWidth),
            threadgroupWidth: threadgroupSize.width,
            counterSampleBuffer: counterSampleBuffer
        )
    }

    // MARK: - Seal Opening

    /// Dispatch Lightning PCS codeword extension.
    public func dispatchSealEncode(
        evalBuffer: MTLBuffer,
        codewordBuffer: MTLBuffer,
        n: Int,
        blowup: Int
    ) throws {
        _ = try dispatchSealEncodeTimed(
            evalBuffer: evalBuffer,
            codewordBuffer: codewordBuffer,
            n: n,
            blowup: blowup
        )
    }

    public func dispatchSealEncodeTimed(
        evalBuffer: MTLBuffer,
        codewordBuffer: MTLBuffer,
        n: Int,
        blowup: Int
    ) throws -> MetalDispatchTiming {
        let params = scheduler.productionParams()
        let pso = try context.pipeline(for: .sealEncode)

        guard let cmdBuffer = context.commandQueue.makeCommandBuffer(),
              let encoder = cmdBuffer.makeComputeCommandEncoder() else {
            throw NuMetalError.encodingFailed
        }

        encoder.setComputePipelineState(pso)
        encoder.setBuffer(evalBuffer, offset: 0, index: 0)
        encoder.setBuffer(codewordBuffer, offset: 0, index: 1)

        var nU32 = UInt32(n)
        var blowupU32 = UInt32(blowup)
        encoder.setBytes(&nU32, length: 4, index: 2)
        encoder.setBytes(&blowupU32, length: 4, index: 3)

        let threadgroupSize = canonicalThreadgroupSize(
            requestedWidth: Int(max(params.threadgroupSize, Int(MetalStorageLayout.defaultSealChunkSize))),
            pipeline: pso
        )
        preconditionThreadgroupWidth(threadgroupSize.width, executionWidth: Int(pso.threadExecutionWidth))
        let gridSize = MTLSize(width: n * blowup, height: 1, depth: 1)
        let counterSampleBuffer = context.makeCounterSampleBuffer(sampleCount: 2, label: "NuMeQ.SealEncode")
        sampleCountersIfAvailable(encoder, sampleBuffer: counterSampleBuffer, sampleIndex: 0, barrier: true)
        encoder.dispatchThreads(gridSize, threadsPerThreadgroup: threadgroupSize)
        sampleCountersIfAvailable(encoder, sampleBuffer: counterSampleBuffer, sampleIndex: 1, barrier: true)

        encoder.endEncoding()
        return try commitAndMeasure(
            cmdBuffer,
            family: .sealEncode,
            threadExecutionWidth: Int(pso.threadExecutionWidth),
            threadgroupWidth: threadgroupSize.width,
            counterSampleBuffer: counterSampleBuffer
        )
    }

    /// Dispatch Lightning PCS query extraction.
    public func dispatchSealQuery(
        codewordBuffer: MTLBuffer,
        positionsBuffer: MTLBuffer,
        outputBuffer: MTLBuffer,
        codewordLength: Int,
        numQueries: Int
    ) throws {
        _ = try dispatchSealQueryTimed(
            codewordBuffer: codewordBuffer,
            positionsBuffer: positionsBuffer,
            outputBuffer: outputBuffer,
            codewordLength: codewordLength,
            numQueries: numQueries
        )
    }

    public func dispatchSealQueryTimed(
        codewordBuffer: MTLBuffer,
        positionsBuffer: MTLBuffer,
        outputBuffer: MTLBuffer,
        codewordLength: Int,
        numQueries: Int
    ) throws -> MetalDispatchTiming {
        let params = scheduler.productionParams()
        let pso = try context.pipeline(for: .sealQuery)

        guard let cmdBuffer = context.commandQueue.makeCommandBuffer(),
              let encoder = cmdBuffer.makeComputeCommandEncoder() else {
            throw NuMetalError.encodingFailed
        }

        encoder.setComputePipelineState(pso)
        encoder.setBuffer(codewordBuffer, offset: 0, index: 0)
        encoder.setBuffer(positionsBuffer, offset: 0, index: 1)
        encoder.setBuffer(outputBuffer, offset: 0, index: 2)

        var paramsBlock = SealQueryDispatchParams(
            numQueries: UInt32(numQueries),
            codewordLength: UInt32(codewordLength)
        )
        encoder.setBytes(&paramsBlock, length: MemoryLayout<SealQueryDispatchParams>.size, index: 3)

        let threadgroupSize = canonicalThreadgroupSize(
            requestedWidth: Int(max(params.threadgroupSize, Int(MetalStorageLayout.defaultSealChunkSize))),
            pipeline: pso
        )
        preconditionThreadgroupWidth(threadgroupSize.width, executionWidth: Int(pso.threadExecutionWidth))
        let gridSize = MTLSize(width: numQueries, height: 1, depth: 1)
        let counterSampleBuffer = context.makeCounterSampleBuffer(sampleCount: 2, label: "NuMeQ.SealQuery")
        sampleCountersIfAvailable(encoder, sampleBuffer: counterSampleBuffer, sampleIndex: 0, barrier: true)
        encoder.dispatchThreads(gridSize, threadsPerThreadgroup: threadgroupSize)
        sampleCountersIfAvailable(encoder, sampleBuffer: counterSampleBuffer, sampleIndex: 1, barrier: true)

        encoder.endEncoding()
        return try commitAndMeasure(
            cmdBuffer,
            family: .sealQuery,
            threadExecutionWidth: Int(pso.threadExecutionWidth),
            threadgroupWidth: threadgroupSize.width,
            counterSampleBuffer: counterSampleBuffer
        )
    }

    // MARK: - Decomposition

    /// Dispatch PiDEC decomposition kernel.
    public func dispatchDecompose(
        inputBuffer: MTLBuffer,
        outputBuffer: MTLBuffer,
        numElements: Int,
        decompBase: UInt8,
        numLimbs: UInt8
    ) throws {
        let pso = try context.pipeline(for: .piDECDecompose)
        guard let limbBitWidth = Decomposition.metalLimbBitWidth(forBase: UInt64(decompBase)) else {
            throw NuMetalError.invalidDecompositionBase(decompBase)
        }

        guard let cmdBuffer = context.commandQueue.makeCommandBuffer(),
              let encoder = cmdBuffer.makeComputeCommandEncoder() else {
            throw NuMetalError.encodingFailed
        }

        encoder.setComputePipelineState(pso)
        encoder.setBuffer(inputBuffer, offset: 0, index: 0)
        encoder.setBuffer(outputBuffer, offset: 0, index: 1)

        var params = (UInt32(numElements), UInt32(limbBitWidth), UInt32(numLimbs))
        encoder.setBytes(&params, length: 12, index: 2)

        let threadgroupSize = canonicalThreadgroupSize(
            requestedWidth: 256,
            pipeline: pso
        )
        let gridSize = MTLSize(width: numElements, height: 1, depth: 1)
        encoder.dispatchThreads(gridSize, threadsPerThreadgroup: threadgroupSize)

        encoder.endEncoding()
        cmdBuffer.commit()
        cmdBuffer.waitUntilCompleted()

        if cmdBuffer.status == .error {
            throw NuMetalError.executionFailed
        }
    }

    public func dispatchDecompose(
        inputBuffer: MetalBufferSlice,
        outputBuffer: MetalBufferSlice,
        paramsBuffer: MetalBufferSlice,
        numElements: Int,
        decompBase: UInt8,
        numLimbs: UInt8
    ) throws {
        guard let limbBitWidth = Decomposition.metalLimbBitWidth(forBase: UInt64(decompBase)) else {
            throw NuMetalError.invalidDecompositionBase(decompBase)
        }
        let pipeline = try context.pipeline(for: .piDECDecompose)
        let threadgroupSize = canonicalThreadgroupSize(
            requestedWidth: 256,
            pipeline: pipeline
        )
        let gridSize = MTLSize(width: numElements, height: 1, depth: 1)
        _ = limbBitWidth
        try executeIndirectCompute(
            family: .piDECDecompose,
            buffers: [
                (inputBuffer.buffer, inputBuffer.offset, 0, .read),
                (outputBuffer.buffer, outputBuffer.offset, 1, .write),
                (paramsBuffer.buffer, paramsBuffer.offset, 2, .read),
            ],
            threadsPerGrid: gridSize,
            threadsPerThreadgroup: threadgroupSize,
            maxKernelBufferBindCount: 3
        )
    }

    package func dispatchDecomposeTimed(
        inputBuffer: MetalBufferSlice,
        outputBuffer: MetalBufferSlice,
        paramsBuffer: MetalBufferSlice,
        numElements: Int,
        decompBase: UInt8,
        numLimbs: UInt8,
        trace: TimedDispatchTraceContext
    ) throws -> MetalDispatchTiming {
        guard Decomposition.metalLimbBitWidth(forBase: UInt64(decompBase)) != nil else {
            throw NuMetalError.invalidDecompositionBase(decompBase)
        }

        let pso = try context.pipeline(for: .piDECDecompose)
        guard let cmdBuffer = context.commandQueue.makeCommandBuffer(),
              let encoder = cmdBuffer.makeComputeCommandEncoder() else {
            throw NuMetalError.encodingFailed
        }

        encoder.setComputePipelineState(pso)
        encoder.setBuffer(inputBuffer.buffer, offset: inputBuffer.offset, index: 0)
        encoder.setBuffer(outputBuffer.buffer, offset: outputBuffer.offset, index: 1)
        encoder.setBuffer(paramsBuffer.buffer, offset: paramsBuffer.offset, index: 2)

        let threadgroupSize = canonicalThreadgroupSize(
            requestedWidth: 256,
            pipeline: pso
        )
        preconditionThreadgroupWidth(threadgroupSize.width, executionWidth: Int(pso.threadExecutionWidth))
        let gridSize = MTLSize(width: numElements, height: 1, depth: 1)
        let counterSampleBuffer = context.makeCounterSampleBuffer(
            sampleCount: 2,
            label: "NuMeQ.\(trace.dispatchLabel)"
        )
        sampleCountersIfAvailable(encoder, sampleBuffer: counterSampleBuffer, sampleIndex: 0, barrier: true)
        encoder.dispatchThreads(gridSize, threadsPerThreadgroup: threadgroupSize)
        sampleCountersIfAvailable(encoder, sampleBuffer: counterSampleBuffer, sampleIndex: 1, barrier: true)
        encoder.endEncoding()

        _ = numLimbs
        return try commitAndMeasure(
            cmdBuffer,
            family: .piDECDecompose,
            threadExecutionWidth: Int(pso.threadExecutionWidth),
            threadgroupWidth: threadgroupSize.width,
            counterSampleBuffer: counterSampleBuffer,
            trace: trace
        )
    }

    private func executeIndirectCompute(
        family: KernelFamily,
        buffers: [(buffer: MTLBuffer, offset: Int, index: Int, usage: MTLResourceUsage)],
        threadsPerGrid: MTLSize,
        threadsPerThreadgroup: MTLSize,
        maxKernelBufferBindCount: Int,
        constants: [(String, UInt32, Int)] = []
    ) throws {
        guard let graph = try context.indirectComputeGraph(
            for: family,
            maxKernelBufferBindCount: maxKernelBufferBindCount
        ) else {
            throw NuMetalError.indirectCommandBufferUnavailable
        }

        graph.encode(
            buffers: buffers.map { ($0.buffer, $0.offset, $0.index) },
            threadsPerGrid: threadsPerGrid,
            threadsPerThreadgroup: threadsPerThreadgroup
        )

        guard let cmdBuffer = context.commandQueue.makeCommandBuffer(),
              let encoder = cmdBuffer.makeComputeCommandEncoder() else {
            throw NuMetalError.encodingFailed
        }

        for constant in constants {
            var value = constant.1
            encoder.setBytes(&value, length: MemoryLayout<UInt32>.size, index: constant.2)
        }

        var resourceUsages: [ObjectIdentifier: (buffer: MTLBuffer, usage: MTLResourceUsage)] = [:]
        for entry in buffers {
            let id = ObjectIdentifier(entry.buffer)
            if let existing = resourceUsages[id] {
                resourceUsages[id] = (existing.buffer, existing.usage.union(entry.usage))
            } else {
                resourceUsages[id] = (entry.buffer, entry.usage)
            }
        }
        for resource in resourceUsages.values {
            encoder.useResource(resource.buffer, usage: resource.usage)
        }

        encoder.executeCommandsInBuffer(graph.indirectCommandBuffer, range: graph.executionRange)
        encoder.endEncoding()
        cmdBuffer.commit()
        cmdBuffer.waitUntilCompleted()

        if cmdBuffer.status == .error {
            throw NuMetalError.executionFailed
        }
    }
}
