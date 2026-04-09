import Foundation

package struct MetalDispatchTraceSample: Sendable, Codable, Equatable {
    package let stage: String
    package let dispatchLabel: String
    package let kernelFamily: String
    package let iteration: Int
    package let ordinal: Int
    package let cpuMilliseconds: Double
    package let gpuMilliseconds: Double?
    package let gpuStartOffsetUs: Double?
    package let gpuEndOffsetUs: Double?
    package let threadExecutionWidth: Int
    package let threadgroupWidth: Int
    package let counterSamplingAvailable: Bool
    package let counterSampleCaptured: Bool

    package init(
        stage: String,
        dispatchLabel: String,
        kernelFamily: String,
        iteration: Int,
        ordinal: Int,
        cpuMilliseconds: Double,
        gpuMilliseconds: Double?,
        gpuStartOffsetUs: Double?,
        gpuEndOffsetUs: Double?,
        threadExecutionWidth: Int,
        threadgroupWidth: Int,
        counterSamplingAvailable: Bool,
        counterSampleCaptured: Bool
    ) {
        self.stage = stage
        self.dispatchLabel = dispatchLabel
        self.kernelFamily = kernelFamily
        self.iteration = iteration
        self.ordinal = ordinal
        self.cpuMilliseconds = cpuMilliseconds
        self.gpuMilliseconds = gpuMilliseconds
        self.gpuStartOffsetUs = gpuStartOffsetUs
        self.gpuEndOffsetUs = gpuEndOffsetUs
        self.threadExecutionWidth = threadExecutionWidth
        self.threadgroupWidth = threadgroupWidth
        self.counterSamplingAvailable = counterSamplingAvailable
        self.counterSampleCaptured = counterSampleCaptured
    }
}

package final class MetalTraceCollector: @unchecked Sendable {
    private let lock = NSLock()
    package let defaultIteration: Int
    private var samples: [MetalDispatchTraceSample] = []
    private var nextOrdinalByStage: [String: Int] = [:]
    private var nextGPUOffsetUsByStage: [String: Double] = [:]

    package init(iteration: Int = 0) {
        self.defaultIteration = iteration
    }

    package func append(
        stage: String,
        iteration: Int,
        dispatchLabel: String,
        kernelFamily: KernelFamily,
        timing: MetalDispatchTiming
    ) {
        lock.lock()
        defer { lock.unlock() }

        let ordinal = nextOrdinalByStage[stage, default: 0]
        nextOrdinalByStage[stage] = ordinal + 1

        let startOffsetUs: Double?
        let endOffsetUs: Double?
        if let gpuMilliseconds = timing.gpuMilliseconds {
            let currentOffset = nextGPUOffsetUsByStage[stage, default: 0]
            startOffsetUs = currentOffset
            let nextOffset = currentOffset + (gpuMilliseconds * 1_000.0)
            endOffsetUs = nextOffset
            nextGPUOffsetUsByStage[stage] = nextOffset
        } else {
            startOffsetUs = nil
            endOffsetUs = nil
        }

        samples.append(
            MetalDispatchTraceSample(
                stage: stage,
                dispatchLabel: dispatchLabel,
                kernelFamily: kernelFamily.rawValue,
                iteration: iteration,
                ordinal: ordinal,
                cpuMilliseconds: timing.cpuMilliseconds,
                gpuMilliseconds: timing.gpuMilliseconds,
                gpuStartOffsetUs: startOffsetUs,
                gpuEndOffsetUs: endOffsetUs,
                threadExecutionWidth: timing.threadExecutionWidth,
                threadgroupWidth: timing.threadgroupWidth,
                counterSamplingAvailable: timing.counterSamplingAvailable,
                counterSampleCaptured: timing.counterSampleCaptured
            )
        )
    }

    package func snapshot() -> [MetalDispatchTraceSample] {
        lock.lock()
        defer { lock.unlock() }
        return samples
    }

    package func reset() {
        lock.lock()
        defer { lock.unlock() }
        samples.removeAll(keepingCapacity: true)
        nextOrdinalByStage.removeAll(keepingCapacity: true)
        nextGPUOffsetUsByStage.removeAll(keepingCapacity: true)
    }
}

package enum VerificationExecutionMode: Sendable {
    case automatic
    case cpuOnly
    case metalAssisted
}
