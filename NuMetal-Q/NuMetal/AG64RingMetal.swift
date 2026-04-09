import Metal

public enum AG64RingMetal {
    public static func multiply(
        context: MetalContext,
        lhs: RingElement,
        rhs: RingElement
    ) throws -> RingElement {
        try multiplyBatch(context: context, lhs: [lhs], rhs: [rhs])[0]
    }

    static func multiplyBatch(
        context: MetalContext,
        lhs: [RingElement],
        rhs: [RingElement]
    ) throws -> [RingElement] {
        try multiplyBatch(context: context, lhs: lhs, rhs: rhs, trace: nil)
    }

    package static func multiplyBatch(
        context: MetalContext,
        lhs: [RingElement],
        rhs: [RingElement],
        trace: TimedDispatchTraceContext?
    ) throws -> [RingElement] {
        precondition(lhs.count == rhs.count)
        guard lhs.isEmpty == false else { return [] }

        let ringCount = lhs.count
        guard let lhsBuffer = context.uploadRingElementsSoA(lhs, paddedTo: ringCount),
              let rhsBuffer = context.uploadRingElementsSoA(rhs, paddedTo: ringCount),
              let outputBuffer = context.makeSharedBuffer(
                length: ringCount * RingElement.degree * MemoryLayout<UInt32>.size * 2
              ) else {
            throw NuMetalError.heapCreationFailed
        }

        let dispatcher = KernelDispatcher(context: context)
        if let trace {
            _ = try dispatcher.dispatchRingMultiplyBatchTimed(
                lhsBuffer: lhsBuffer,
                rhsBuffer: rhsBuffer,
                outputBuffer: outputBuffer,
                ringCount: ringCount,
                trace: trace
            )
        } else {
            try dispatcher.dispatchRingMultiplyBatch(
                lhsBuffer: lhsBuffer,
                rhsBuffer: rhsBuffer,
                outputBuffer: outputBuffer,
                ringCount: ringCount
            )
        }

        let valueCount = ringCount * RingElement.degree
        let pointer = outputBuffer.contents().bindMemory(to: UInt32.self, capacity: valueCount * 2)
        let packed = Array(UnsafeBufferPointer(start: pointer, count: valueCount * 2))
        return MetalFieldPacking.unpackRingElementsSoA(packed, ringCount: ringCount)
    }

    static func bindFold(
        context: MetalContext,
        challengeRings: [RingElement],
        inputs: [[RingElement]],
        ringCount: Int
    ) throws -> [RingElement] {
        try bindFold(
            context: context,
            challengeRings: challengeRings,
            inputs: inputs,
            ringCount: ringCount,
            trace: nil
        )
    }

    package static func bindFold(
        context: MetalContext,
        challengeRings: [RingElement],
        inputs: [[RingElement]],
        ringCount: Int,
        trace: TimedDispatchTraceContext?
    ) throws -> [RingElement] {
        precondition(inputs.count == challengeRings.count)
        guard challengeRings.isEmpty == false, ringCount > 0 else { return [] }

        let paddedInputs = inputs.map { input in
            input + [RingElement](repeating: .zero, count: max(0, ringCount - input.count))
        }

        guard let challengeBuffer = context.uploadRingElementsSoA(challengeRings, paddedTo: challengeRings.count),
              let inputBuffer = context.uploadRingBatchSoA(paddedInputs, paddedInnerCount: ringCount),
              let outputBuffer = context.makeSharedBuffer(
                length: ringCount * RingElement.degree * MemoryLayout<UInt32>.size * 2
              ) else {
            throw NuMetalError.heapCreationFailed
        }

        let dispatcher = KernelDispatcher(context: context)
        if let trace {
            _ = try dispatcher.dispatchRingBindFoldBatchTimed(
                challengeBuffer: challengeBuffer,
                inputBuffer: inputBuffer,
                outputBuffer: outputBuffer,
                sourceCount: challengeRings.count,
                ringCount: ringCount,
                trace: trace
            )
        } else {
            try dispatcher.dispatchRingBindFoldBatch(
                challengeBuffer: challengeBuffer,
                inputBuffer: inputBuffer,
                outputBuffer: outputBuffer,
                sourceCount: challengeRings.count,
                ringCount: ringCount
            )
        }

        let valueCount = ringCount * RingElement.degree
        let pointer = outputBuffer.contents().bindMemory(to: UInt32.self, capacity: valueCount * 2)
        let packed = Array(UnsafeBufferPointer(start: pointer, count: valueCount * 2))
        return MetalFieldPacking.unpackRingElementsSoA(packed, ringCount: ringCount)
    }
}
