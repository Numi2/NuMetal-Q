import Foundation
@preconcurrency import Metal

struct IndirectComputeGraphKey: Hashable {
    let family: KernelFamily
    let maxKernelBufferBindCount: Int
}

final class IndirectComputeGraph: @unchecked Sendable {
    let pipeline: MTLComputePipelineState
    let indirectCommandBuffer: MTLIndirectCommandBuffer
    let executionRange = 0..<1

    init(
        device: MTLDevice,
        pipeline: MTLComputePipelineState,
        maxKernelBufferBindCount: Int
    ) throws {
        let descriptor = MTLIndirectCommandBufferDescriptor()
        descriptor.commandTypes = .concurrentDispatchThreads
        descriptor.inheritPipelineState = false
        descriptor.inheritBuffers = false
        descriptor.maxKernelBufferBindCount = maxKernelBufferBindCount

        guard let indirectCommandBuffer = device.makeIndirectCommandBuffer(
            descriptor: descriptor,
            maxCommandCount: 1,
            options: .storageModePrivate
        ) else {
            throw NuMetalError.indirectCommandBufferUnavailable
        }

        self.pipeline = pipeline
        self.indirectCommandBuffer = indirectCommandBuffer
    }

    func encode(
        buffers: [(buffer: MTLBuffer, offset: Int, index: Int)],
        threadsPerGrid: MTLSize,
        threadsPerThreadgroup: MTLSize
    ) {
        let command = indirectCommandBuffer.indirectComputeCommandAt(0)
        command.reset()
        command.setComputePipelineState(pipeline)
        for entry in buffers {
            command.setKernelBuffer(entry.buffer, offset: entry.offset, at: entry.index)
        }
        command.concurrentDispatchThreads(
            threadsPerGrid,
            threadsPerThreadgroup: threadsPerThreadgroup
        )
    }
}
