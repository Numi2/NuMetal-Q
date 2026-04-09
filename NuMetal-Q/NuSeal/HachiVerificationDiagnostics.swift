import Foundation

package enum HachiVerificationParity: String, Sendable, Codable {
    case matched
    case mismatched
    case unavailable
}

package struct HachiPCSArtifactDiff: Sendable, Codable, Equatable {
    package let oracle: SpartanOracleID
    package let component: String
    package let detail: String

    package init(
        oracle: SpartanOracleID,
        component: String,
        detail: String
    ) {
        self.oracle = oracle
        self.component = component
        self.detail = detail
    }
}

package struct HachiVerificationDiagnostics: Sendable, Codable, Equatable {
    package private(set) var failures: [String]
    package private(set) var artifactDiffs: [HachiPCSArtifactDiff]

    package init(
        failures: [String] = [],
        artifactDiffs: [HachiPCSArtifactDiff] = []
    ) {
        self.failures = failures
        self.artifactDiffs = artifactDiffs
    }

    package mutating func recordFailure(_ message: String) {
        failures.append(message)
    }

    package mutating func recordArtifactDiff(
        oracle: SpartanOracleID,
        component: String,
        detail: String
    ) {
        artifactDiffs.append(
            HachiPCSArtifactDiff(
                oracle: oracle,
                component: component,
                detail: detail
            )
        )
    }

    package var summary: String {
        if let failure = failures.first {
            return failure
        }
        if let diff = artifactDiffs.first {
            return "\(diff.oracle.kind.rawValue):\(diff.oracle.index ?? -1) \(diff.component) \(diff.detail)"
        }
        return "ok"
    }
}

package struct HachiVerificationOutcome: Sendable {
    package let isValid: Bool
    package let diagnostics: HachiVerificationDiagnostics

    package init(isValid: Bool, diagnostics: HachiVerificationDiagnostics) {
        self.isValid = isValid
        self.diagnostics = diagnostics
    }
}
