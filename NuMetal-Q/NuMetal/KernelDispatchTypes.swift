import Foundation
import Metal

/// Dispatcher timing for a single Metal compute submission.
public enum MetalGPUTimingSource: String, Sendable, Codable {
    case unavailable = "unavailable"
    case dispatchBoundaryCounter = "dispatch-boundary-counter"
    case commandBufferTimeline = "command-buffer-timeline"
}

public enum MetalCounterCaptureState: String, Sendable, Codable {
    case unsupported = "unsupported"
    case availableButNotCaptured = "available-but-not-captured"
    case captured = "captured"
}

public struct MetalDispatchTiming: Sendable {
    public let cpuMilliseconds: Double
    public let gpuMilliseconds: Double?
    public let counterSamplingAvailable: Bool
    public let counterCaptureState: MetalCounterCaptureState
    public let gpuTimingSource: MetalGPUTimingSource
    public let counterFallbackReason: String?
    public let gpuStartOffsetMicroseconds: Double?
    public let gpuEndOffsetMicroseconds: Double?
    public let threadExecutionWidth: Int
    public let threadgroupWidth: Int
    public let counterSampleCaptured: Bool

    public init(
        cpuMilliseconds: Double,
        gpuMilliseconds: Double?,
        counterSamplingAvailable: Bool = false,
        counterCaptureState: MetalCounterCaptureState = .unsupported,
        gpuTimingSource: MetalGPUTimingSource = .unavailable,
        counterFallbackReason: String? = nil,
        gpuStartOffsetMicroseconds: Double? = nil,
        gpuEndOffsetMicroseconds: Double? = nil,
        threadExecutionWidth: Int,
        threadgroupWidth: Int,
        counterSampleCaptured: Bool = false
    ) {
        self.cpuMilliseconds = cpuMilliseconds
        self.gpuMilliseconds = gpuMilliseconds
        self.counterSamplingAvailable = counterSamplingAvailable
        self.counterCaptureState = counterCaptureState
        self.gpuTimingSource = gpuTimingSource
        self.counterFallbackReason = counterFallbackReason
        self.gpuStartOffsetMicroseconds = gpuStartOffsetMicroseconds
        self.gpuEndOffsetMicroseconds = gpuEndOffsetMicroseconds
        self.threadExecutionWidth = threadExecutionWidth
        self.threadgroupWidth = threadgroupWidth
        self.counterSampleCaptured = counterSampleCaptured
    }
}

package struct TimedDispatchTraceContext {
    let collector: MetalTraceCollector
    let stage: String
    let iteration: Int
    let dispatchLabel: String
}

public final class MetalStageCommandBuffer: @unchecked Sendable {
    public let commandBuffer: MTLCommandBuffer
    private let context: MetalContext

    init(context: MetalContext, label: String?) throws {
        guard let commandBuffer = context.commandQueue.makeCommandBuffer() else {
            throw NuMetalError.commandQueueFailed
        }
        commandBuffer.label = label
        self.context = context
        self.commandBuffer = commandBuffer
    }

    @discardableResult
    public func encode(
        family: KernelFamily,
        buffers: [(buffer: MTLBuffer, offset: Int, index: Int)],
        bytes: [(UnsafeRawPointer, Int, Int)] = [],
        threadsPerGrid: MTLSize,
        requestedThreadgroupWidth: Int
    ) throws -> MTLComputePipelineState {
        let pipeline = try context.pipeline(for: family)
        guard let encoder = commandBuffer.makeComputeCommandEncoder() else {
            throw NuMetalError.encodingFailed
        }
        encoder.setComputePipelineState(pipeline)
        for entry in buffers {
            encoder.setBuffer(entry.buffer, offset: entry.offset, index: entry.index)
        }
        for byteEntry in bytes {
            encoder.setBytes(byteEntry.0, length: byteEntry.1, index: byteEntry.2)
        }
        let executionWidth = max(1, Int(pipeline.threadExecutionWidth))
        let maxWidth = min(context.maxThreadsPerThreadgroupWidth, pipeline.maxTotalThreadsPerThreadgroup)
        let clamped = max(executionWidth, min(requestedThreadgroupWidth, maxWidth))
        let rounded = max(
            executionWidth,
            min(maxWidth, (clamped / executionWidth) * executionWidth)
        )
        encoder.dispatchThreads(
            threadsPerGrid,
            threadsPerThreadgroup: MTLSize(width: rounded, height: 1, depth: 1)
        )
        encoder.endEncoding()
        return pipeline
    }

    public func commit() {
        commandBuffer.commit()
    }

    public func waitUntilCompleted() throws {
        commandBuffer.waitUntilCompleted()
        if commandBuffer.status == .error {
            throw NuMetalError.executionFailed
        }
    }
}
