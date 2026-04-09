import Foundation
#if canImport(UIKit)
import UIKit
import BackgroundTasks
#endif
#if os(macOS)
import Darwin
#endif

// MARK: - Per-Device-Class Scheduler
// MacBook: maximize throughput — wide folds, deeper queues, aggressive seal.
// iPhone: maximize interactive latency — smaller k in foreground,
//         larger k while charging/background.
// Driven by ProcessInfo.thermalState.

/// Device classification for scheduler policy.
public enum DeviceClass: Sendable {
    case macDesktop     // Mac Studio, Mac Pro, Mac mini
    case macLaptop      // MacBook Air, MacBook Pro
    case iPhone         // iPhone (foreground)
    case iPhoneBackground  // iPhone in background/charging
    case iPad           // iPad

    /// Detect the current device class.
    public static var current: DeviceClass {
        #if os(macOS)
        var size = 0
        sysctlbyname("hw.model", nil, &size, nil, 0)
        let model: String
        if size > 1 {
            var buf = [CChar](repeating: 0, count: size)
            sysctlbyname("hw.model", &buf, &size, nil, 0)
            model = String(decoding: buf.prefix { $0 != 0 }.map(UInt8.init), as: UTF8.self)
        } else {
            model = ProcessInfo.processInfo.hostName
        }
        if model.contains("MacBook") { return .macLaptop }
        return .macDesktop
        #elseif os(iOS)
        if UIDevice.current.userInterfaceIdiom == .pad { return .iPad }
        return .iPhone
        #else
        return .macDesktop
        #endif
    }
}

/// Scheduler parameters tuned per device class and thermal state.
public struct SchedulerParams: Sendable {
    /// Maximum fold arity to use.
    public let maxArity: Int

    /// Command queue depth (number of concurrent command buffers).
    public let queueDepth: Int

    /// Whether to aggressively prefetch shape packs.
    public let prefetchShapePacks: Bool

    /// Whether to run seal compression eagerly.
    public let aggressiveSeal: Bool

    /// Threadgroup size override (0 = use kernel default).
    public let threadgroupSize: Int

    /// Maximum memory allocation for prover scratch space (bytes).
    public let maxScratchBytes: Int

    public static let production = SchedulerParams(
        maxArity: 8,
        queueDepth: 2,
        prefetchShapePacks: false,
        aggressiveSeal: true,
        threadgroupSize: 64,
        maxScratchBytes: 512 * 1024 * 1024
    )
}

// MARK: - Background Authorization

public enum ProverBackgroundRequirements {
    public static let sealTaskIdentifier = "com.numeq.continued-seal"
    public static let backgroundGPUOptInInfoKey = "NuMeQBackgroundGPUEnabled"
    public static let permittedIdentifiersInfoKey = "BGTaskSchedulerPermittedIdentifiers"
}

public enum ProverBackgroundAuthorizationError: Error, Sendable, Equatable {
    case missingBackgroundGPUOptIn(String)
    case missingPermittedTaskIdentifier(String)
}

/// Explicit authorization for continued background proving.
///
/// Callers must opt in through the documented app configuration path:
/// `NuMeQBackgroundGPUEnabled = true` and `BGTaskSchedulerPermittedIdentifiers`
/// must include the continued-processing task identifier.
public struct ProverBackgroundAuthorization: Sendable, Equatable {
    public let taskIdentifier: String

    public static func validate(
        infoDictionary: [String: Any],
        taskIdentifier: String = ProverBackgroundRequirements.sealTaskIdentifier
    ) throws -> ProverBackgroundAuthorization {
        let backgroundOptIn = infoDictionary[ProverBackgroundRequirements.backgroundGPUOptInInfoKey] as? Bool ?? false
        guard backgroundOptIn else {
            throw ProverBackgroundAuthorizationError.missingBackgroundGPUOptIn(
                ProverBackgroundRequirements.backgroundGPUOptInInfoKey
            )
        }

        let permittedIdentifiers = infoDictionary[ProverBackgroundRequirements.permittedIdentifiersInfoKey] as? [String] ?? []
        guard permittedIdentifiers.contains(taskIdentifier) else {
            throw ProverBackgroundAuthorizationError.missingPermittedTaskIdentifier(taskIdentifier)
        }

        return ProverBackgroundAuthorization(taskIdentifier: taskIdentifier)
    }

    public static func requireConfigured(
        bundle: Bundle = .main,
        taskIdentifier: String = ProverBackgroundRequirements.sealTaskIdentifier
    ) throws -> ProverBackgroundAuthorization {
        try validate(infoDictionary: bundle.infoDictionary ?? [:], taskIdentifier: taskIdentifier)
    }
}

/// The prover scheduler: adapts fold parameters to device and thermal state.
public final class ProverScheduler: Sendable {
    public let deviceClass: DeviceClass

    public init(deviceClass: DeviceClass = .current) {
        self.deviceClass = deviceClass
    }

    /// Runtime heuristic scheduling is removed from the production pipeline.
    @available(*, unavailable, message: "Thermal and device-class heuristics are barred from the canonical production scheduler.")
    public func currentParams() -> SchedulerParams {
        let thermal = ProcessInfo.processInfo.thermalState
        return params(for: deviceClass, thermal: thermal)
    }

    public func productionParams() -> SchedulerParams {
        .production
    }

    func params(for device: DeviceClass, thermal: ProcessInfo.ThermalState) -> SchedulerParams {
        switch device {
        case .macDesktop:
            return macDesktopParams(thermal: thermal)
        case .macLaptop:
            return macLaptopParams(thermal: thermal)
        case .iPhone:
            return iPhoneParams(thermal: thermal)
        case .iPhoneBackground:
            return iPhoneBackgroundParams(thermal: thermal)
        case .iPad:
            return iPadParams(thermal: thermal)
        }
    }

    private func macDesktopParams(thermal: ProcessInfo.ThermalState) -> SchedulerParams {
        SchedulerParams(
            maxArity: thermal == .critical ? 4 : 16,
            queueDepth: thermal == .critical ? 2 : 4,
            prefetchShapePacks: true,
            aggressiveSeal: true,
            threadgroupSize: 256,
            maxScratchBytes: 2 * 1024 * 1024 * 1024
        )
    }

    private func macLaptopParams(thermal: ProcessInfo.ThermalState) -> SchedulerParams {
        switch thermal {
        case .nominal, .fair:
            return SchedulerParams(
                maxArity: 8,
                queueDepth: 3,
                prefetchShapePacks: true,
                aggressiveSeal: true,
                threadgroupSize: 256,
                maxScratchBytes: 1024 * 1024 * 1024
            )
        case .serious:
            return SchedulerParams(
                maxArity: 4,
                queueDepth: 2,
                prefetchShapePacks: true,
                aggressiveSeal: false,
                threadgroupSize: 128,
                maxScratchBytes: 512 * 1024 * 1024
            )
        case .critical:
            return SchedulerParams(
                maxArity: 2,
                queueDepth: 1,
                prefetchShapePacks: false,
                aggressiveSeal: false,
                threadgroupSize: 64,
                maxScratchBytes: 256 * 1024 * 1024
            )
        @unknown default:
            return SchedulerParams(
                maxArity: 4,
                queueDepth: 2,
                prefetchShapePacks: true,
                aggressiveSeal: false,
                threadgroupSize: 128,
                maxScratchBytes: 512 * 1024 * 1024
            )
        }
    }

    private func iPhoneParams(thermal: ProcessInfo.ThermalState) -> SchedulerParams {
        switch thermal {
        case .nominal, .fair:
            return SchedulerParams(
                maxArity: 4,
                queueDepth: 2,
                prefetchShapePacks: false,
                aggressiveSeal: false,
                threadgroupSize: 64,
                maxScratchBytes: 256 * 1024 * 1024
            )
        case .serious:
            return SchedulerParams(
                maxArity: 2,
                queueDepth: 1,
                prefetchShapePacks: false,
                aggressiveSeal: false,
                threadgroupSize: 32,
                maxScratchBytes: 128 * 1024 * 1024
            )
        case .critical:
            return SchedulerParams(
                maxArity: 2,
                queueDepth: 1,
                prefetchShapePacks: false,
                aggressiveSeal: false,
                threadgroupSize: 32,
                maxScratchBytes: 64 * 1024 * 1024
            )
        @unknown default:
            return SchedulerParams(
                maxArity: 2,
                queueDepth: 1,
                prefetchShapePacks: false,
                aggressiveSeal: false,
                threadgroupSize: 32,
                maxScratchBytes: 128 * 1024 * 1024
            )
        }
    }

    private func iPhoneBackgroundParams(thermal: ProcessInfo.ThermalState) -> SchedulerParams {
        SchedulerParams(
            maxArity: thermal == .critical ? 2 : 8,
            queueDepth: thermal == .critical ? 1 : 2,
            prefetchShapePacks: true,
            aggressiveSeal: thermal != .critical,
            threadgroupSize: thermal == .critical ? 32 : 128,
            maxScratchBytes: thermal == .critical ? 128 * 1024 * 1024 : 512 * 1024 * 1024
        )
    }

    private func iPadParams(thermal: ProcessInfo.ThermalState) -> SchedulerParams {
        switch thermal {
        case .nominal, .fair:
            return SchedulerParams(
                maxArity: 8,
                queueDepth: 3,
                prefetchShapePacks: true,
                aggressiveSeal: true,
                threadgroupSize: 128,
                maxScratchBytes: 512 * 1024 * 1024
            )
        case .serious, .critical:
            return SchedulerParams(
                maxArity: 4,
                queueDepth: 1,
                prefetchShapePacks: false,
                aggressiveSeal: false,
                threadgroupSize: 64,
                maxScratchBytes: 256 * 1024 * 1024
            )
        @unknown default:
            return SchedulerParams(
                maxArity: 4,
                queueDepth: 2,
                prefetchShapePacks: true,
                aggressiveSeal: false,
                threadgroupSize: 128,
                maxScratchBytes: 256 * 1024 * 1024
            )
        }
    }
}

// MARK: - Long-running seal work (iOS 26+)

#if canImport(UIKit) && !os(tvOS)
/// Registers NuMeQ seal / wide-fold jobs with `BGContinuedProcessingTaskRequest`
/// so proving can continue after the app backgrounds, subject to system policy.
public enum ProverBackgroundTasks {
    public static let sealTaskIdentifier = ProverBackgroundRequirements.sealTaskIdentifier

    /// Call from app launch to enable continued processing for heavy seal jobs.
    public static func registerContinuedSealHandler(
        authorization: ProverBackgroundAuthorization,
        _ handler: @escaping @Sendable (BGContinuedProcessingTask) -> Void
    ) {
        BGContinuedProcessingTaskRequest.register(
            forTaskWithIdentifier: authorization.taskIdentifier,
            using: nil
        ) { task in
            guard let continued = task as? BGContinuedProcessingTask else { return }
            handler(continued)
        }
    }

    /// Submit a continued-processing request (e.g. from `ProofContext` after user starts seal on iPhone).
    public static func submitContinuedSealRequest(authorization: ProverBackgroundAuthorization) {
        let request = BGContinuedProcessingTaskRequest(identifier: authorization.taskIdentifier)
        try? request.submit()
    }
}
#endif
