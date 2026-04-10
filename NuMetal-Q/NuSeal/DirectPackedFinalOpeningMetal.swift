import Foundation
import Metal

internal struct DirectPackedMaskSeedMaterial {
    let magnitudeRaw: [UInt64]
    let signRaw: [UInt64]
}

internal struct DirectPackedFinalOpeningPreparation {
    let shortMasks: [RingElement]
    let outerMasks: [RingElement]
    let bindingMaskVector: [RingElement]
    let relationMaskVector: [RingElement]
    let evaluationMask: Fq
    let outerMaskVector: [RingElement]
}

internal struct DirectPackedResponseMetrics: Equatable {
    let maskNorm: UInt64
    let responseNorm: UInt64
    let maxResponseMagnitude: UInt64
    let responseBoundExceeded: Bool
}

internal struct DirectPackedFinalOpeningResponses {
    let shortResponses: [RingElement]
    let outerResponses: [RingElement]
    let metrics: DirectPackedResponseMetrics
}

internal enum DirectPackedFinalOpeningMetal {
    private struct MaskPrepareParams {
        var chunkCount: UInt32
        var sigma: UInt32
        var gaussianTableCount: UInt32
    }

    private struct ResponseFinalizeParams {
        var chunkCount: UInt32
        var maxAcceptedResponseBound: UInt32
        var sigmaChallengeLow: UInt32
        var sigmaChallengeHigh: UInt32
    }

    private struct ResponseMetricsABI {
        var maskNorm: UInt64
        var responseNorm: UInt64
        var maxResponseMagnitude: UInt64
        var responseBoundExceeded: UInt32
    }

    private static let metricsThreadgroupWidth = 128

    static func prepare(
        statement: ShortLinearWitnessStatement,
        shortSeedMaterial: DirectPackedMaskSeedMaterial,
        outerSeedMaterial: DirectPackedMaskSeedMaterial,
        finalBindingCoefficients: [RingElement],
        finalRelationShortCoefficients: [RingElement],
        finalRelationOuterCoefficients: [RingElement],
        finalEvaluationWeights: [RingElement],
        finalOuterCoefficients: [RingElement],
        context: MetalContext,
        gaussianThresholds: [UInt64]
    ) throws -> DirectPackedFinalOpeningPreparation {
        let chunkCount = statement.chunkCount
        let totalCoefficientCount = chunkCount * RingElement.degree
        precondition(shortSeedMaterial.magnitudeRaw.count == totalCoefficientCount)
        precondition(outerSeedMaterial.magnitudeRaw.count == totalCoefficientCount)

        return try context.withTransientArena { arena in
            let params = MaskPrepareParams(
                chunkCount: UInt32(chunkCount),
                sigma: statement.parameters.finalMaskSigma,
                gaussianTableCount: UInt32(gaussianThresholds.count)
            )

            guard let parameterSlice = arena.makeSharedSlice(length: MemoryLayout<MaskPrepareParams>.size),
                  let gaussianThresholdSlice = uploadUInt64Array(gaussianThresholds, arena: arena),
                  let shortMagnitudeSlice = uploadUInt64Array(shortSeedMaterial.magnitudeRaw, arena: arena),
                  let shortSignSlice = uploadUInt64Array(shortSeedMaterial.signRaw, arena: arena),
                  let outerMagnitudeSlice = uploadUInt64Array(outerSeedMaterial.magnitudeRaw, arena: arena),
                  let outerSignSlice = uploadUInt64Array(outerSeedMaterial.signRaw, arena: arena),
                  let bindingCoefficientSlice = arena.uploadRingElementsSoA(finalBindingCoefficients, paddedTo: chunkCount),
                  let relationShortSlice = arena.uploadRingElementsSoA(finalRelationShortCoefficients, paddedTo: chunkCount),
                  let relationOuterSlice = arena.uploadRingElementsSoA(finalRelationOuterCoefficients, paddedTo: chunkCount),
                  let evaluationWeightSlice = arena.uploadRingElementsSoA(finalEvaluationWeights, paddedTo: chunkCount),
                  let outerCoefficientSlice = arena.uploadRingElementsSoA(finalOuterCoefficients, paddedTo: chunkCount),
                  let shortMaskSlice = arena.makeSharedSlice(length: ringBufferLength(ringCount: chunkCount)),
                  let outerMaskSlice = arena.makeSharedSlice(length: ringBufferLength(ringCount: chunkCount)),
                  let bindingMaskVectorSlice = arena.makeSharedSlice(length: ringBufferLength(ringCount: chunkCount)),
                  let relationMaskVectorSlice = arena.makeSharedSlice(length: ringBufferLength(ringCount: chunkCount)),
                  let evaluationPartialSlice = arena.makeSharedSlice(length: ag64BufferLength(count: chunkCount)),
                  let evaluationMaskSlice = arena.makeSharedSlice(length: ringBufferLength(ringCount: 1)),
                  let outerMaskVectorSlice = arena.makeSharedSlice(length: ringBufferLength(ringCount: chunkCount)) else {
                throw NuMetalError.heapCreationFailed
            }

            parameterSlice.typedContents(as: MaskPrepareParams.self, capacity: 1)[0] = params

            let dispatcher = KernelDispatcher(context: context)
            try dispatcher.dispatchDirectPackedMaskDecode(
                parameterBuffer: parameterSlice,
                gaussianThresholdBuffer: gaussianThresholdSlice,
                shortMagnitudeRawBuffer: shortMagnitudeSlice,
                shortSignRawBuffer: shortSignSlice,
                outerMagnitudeRawBuffer: outerMagnitudeSlice,
                outerSignRawBuffer: outerSignSlice,
                shortMaskBuffer: shortMaskSlice,
                outerMaskBuffer: outerMaskSlice,
                totalCoefficientCount: totalCoefficientCount
            )
            try dispatcher.dispatchDirectPackedImagePrepare(
                parameterBuffer: parameterSlice,
                bindingCoefficientBuffer: bindingCoefficientSlice,
                relationShortCoefficientBuffer: relationShortSlice,
                relationOuterCoefficientBuffer: relationOuterSlice,
                outerCoefficientBuffer: outerCoefficientSlice,
                shortMaskBuffer: shortMaskSlice,
                outerMaskBuffer: outerMaskSlice,
                bindingMaskVectorBuffer: bindingMaskVectorSlice,
                relationMaskVectorBuffer: relationMaskVectorSlice,
                outerMaskVectorBuffer: outerMaskVectorSlice,
                totalCoefficientCount: totalCoefficientCount
            )
            try dispatcher.dispatchDirectPackedEvaluationPartialReduce(
                parameterBuffer: parameterSlice,
                shortMaskBuffer: shortMaskSlice,
                evaluationWeightBuffer: evaluationWeightSlice,
                evaluationPartialBuffer: evaluationPartialSlice,
                chunkCount: chunkCount
            )
            try dispatcher.dispatchDirectPackedEvaluationFinalize(
                parameterBuffer: parameterSlice,
                evaluationPartialBuffer: evaluationPartialSlice,
                evaluationMaskBuffer: evaluationMaskSlice,
                chunkCount: chunkCount
            )

            return DirectPackedFinalOpeningPreparation(
                shortMasks: decodeRingBuffer(shortMaskSlice, ringCount: chunkCount),
                outerMasks: decodeRingBuffer(outerMaskSlice, ringCount: chunkCount),
                bindingMaskVector: decodeRingBuffer(bindingMaskVectorSlice, ringCount: chunkCount),
                relationMaskVector: decodeRingBuffer(relationMaskVectorSlice, ringCount: chunkCount),
                evaluationMask: decodeRingBuffer(evaluationMaskSlice, ringCount: 1).first?.coeffs[0] ?? .zero,
                outerMaskVector: decodeRingBuffer(outerMaskVectorSlice, ringCount: chunkCount)
            )
        }
    }

    static func finalizeResponses(
        statement: ShortLinearWitnessStatement,
        sigmaChallenge: Fq,
        shortMasks: [RingElement],
        outerMasks: [RingElement],
        residualShort: [RingElement],
        residualOuter: [RingElement],
        context: MetalContext
    ) throws -> DirectPackedFinalOpeningResponses {
        let chunkCount = statement.chunkCount
        let totalCoefficientCount = chunkCount * RingElement.degree

        return try context.withTransientArena { arena in
            let params = ResponseFinalizeParams(
                chunkCount: UInt32(chunkCount),
                maxAcceptedResponseBound: UInt32(clamping: statement.parameters.maxAcceptedResponseBound),
                sigmaChallengeLow: UInt32(truncatingIfNeeded: sigmaChallenge.v),
                sigmaChallengeHigh: UInt32(truncatingIfNeeded: sigmaChallenge.v >> 32)
            )

            guard let parameterSlice = arena.makeSharedSlice(length: MemoryLayout<ResponseFinalizeParams>.size),
                  let shortMaskSlice = arena.uploadRingElementsSoA(shortMasks, paddedTo: chunkCount),
                  let outerMaskSlice = arena.uploadRingElementsSoA(outerMasks, paddedTo: chunkCount),
                  let residualShortSlice = arena.uploadRingElementsSoA(residualShort, paddedTo: chunkCount),
                  let residualOuterSlice = arena.uploadRingElementsSoA(residualOuter, paddedTo: chunkCount),
                  let shortResponseSlice = arena.makeSharedSlice(length: ringBufferLength(ringCount: chunkCount)),
                  let outerResponseSlice = arena.makeSharedSlice(length: ringBufferLength(ringCount: chunkCount)),
                  let metricsPartialSlice = arena.makeSharedSlice(
                    length: metricsPartialBufferLength(totalCoefficientCount: totalCoefficientCount)
                  ),
                  let metricsSlice = arena.makeSharedSlice(length: MemoryLayout<ResponseMetricsABI>.size) else {
                throw NuMetalError.heapCreationFailed
            }

            parameterSlice.typedContents(as: ResponseFinalizeParams.self, capacity: 1)[0] = params
            metricsSlice.typedContents(as: ResponseMetricsABI.self, capacity: 1)[0] = ResponseMetricsABI(
                maskNorm: 0,
                responseNorm: 0,
                maxResponseMagnitude: 0,
                responseBoundExceeded: 0
            )

            let dispatcher = KernelDispatcher(context: context)
            try dispatcher.dispatchDirectPackedResponseForm(
                parameterBuffer: parameterSlice,
                shortMaskBuffer: shortMaskSlice,
                outerMaskBuffer: outerMaskSlice,
                residualShortBuffer: residualShortSlice,
                residualOuterBuffer: residualOuterSlice,
                shortResponseBuffer: shortResponseSlice,
                outerResponseBuffer: outerResponseSlice,
                totalCoefficientCount: totalCoefficientCount
            )
            zeroFill(metricsPartialSlice)
            try dispatcher.dispatchDirectPackedResponseMetricsPartialReduce(
                parameterBuffer: parameterSlice,
                shortMaskBuffer: shortMaskSlice,
                outerMaskBuffer: outerMaskSlice,
                shortResponseBuffer: shortResponseSlice,
                outerResponseBuffer: outerResponseSlice,
                metricsPartialBuffer: metricsPartialSlice,
                totalCoefficientCount: totalCoefficientCount
            )
            try dispatcher.dispatchDirectPackedResponseMetricsFinalize(
                parameterBuffer: parameterSlice,
                metricsPartialBuffer: metricsPartialSlice,
                metricsBuffer: metricsSlice,
                partialCount: metricsPartialCount(totalCoefficientCount: totalCoefficientCount)
            )

            let metrics = metricsSlice.typedContents(as: ResponseMetricsABI.self, capacity: 1).pointee
            return DirectPackedFinalOpeningResponses(
                shortResponses: decodeRingBuffer(shortResponseSlice, ringCount: chunkCount),
                outerResponses: decodeRingBuffer(outerResponseSlice, ringCount: chunkCount),
                metrics: DirectPackedResponseMetrics(
                    maskNorm: metrics.maskNorm,
                    responseNorm: metrics.responseNorm,
                    maxResponseMagnitude: metrics.maxResponseMagnitude,
                    responseBoundExceeded: metrics.responseBoundExceeded != 0
                )
            )
        }
    }

    private static func uploadUInt64Array(
        _ values: [UInt64],
        arena: MetalTransientArena
    ) -> MetalBufferSlice? {
        guard let slice = arena.makeSharedSlice(length: values.count * MemoryLayout<UInt64>.size) else {
            return nil
        }
        let pointer = slice.typedContents(as: UInt64.self, capacity: values.count)
        for (index, value) in values.enumerated() {
            pointer[index] = value
        }
        return slice
    }

    private static func ringBufferLength(ringCount: Int) -> Int {
        max(1, ringCount) * RingElement.degree * MemoryLayout<UInt32>.size * 2
    }

    private static func ag64BufferLength(count: Int) -> Int {
        max(1, count) * MemoryLayout<UInt32>.size * 2
    }

    private static func metricsPartialCount(totalCoefficientCount: Int) -> Int {
        max(1, (max(1, totalCoefficientCount) + metricsThreadgroupWidth - 1) / metricsThreadgroupWidth)
    }

    private static func metricsPartialBufferLength(totalCoefficientCount: Int) -> Int {
        metricsPartialCount(totalCoefficientCount: totalCoefficientCount) * MemoryLayout<ResponseMetricsABI>.size
    }

    private static func zeroFill(_ slice: MetalBufferSlice) {
        let pointer = slice.buffer.contents().advanced(by: slice.offset)
        pointer.initializeMemory(as: UInt8.self, repeating: 0, count: slice.length)
    }

    private static func decodeRingBuffer(
        _ slice: MetalBufferSlice,
        ringCount: Int
    ) -> [RingElement] {
        let valueCount = max(1, ringCount) * RingElement.degree
        let pointer = slice.typedContents(as: UInt32.self, capacity: valueCount * 2)
        let packed = Array(UnsafeBufferPointer(start: pointer, count: valueCount * 2))
        return Array(MetalFieldPacking.unpackRingElementsSoA(packed, ringCount: max(1, ringCount)).prefix(ringCount))
    }
}
