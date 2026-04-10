import Foundation

enum BenchmarkCommand {
    case run(Options)
    case help
    case listWorkloads

    init(arguments: ArraySlice<String>) throws {
        self = try Options.parse(arguments: arguments)
    }
}

struct BenchmarkDocumentationPaths {
    let protocolNotePath: String
    let stateOfTheArtPath: String
    let benchmarkingGuidePath: String

    static func current() -> BenchmarkDocumentationPaths {
        let root = NuMetalQBenchmarks.packageRootDirectory()
        return BenchmarkDocumentationPaths(
            protocolNotePath: resolve(
                in: root,
                candidates: ["docs/protocol-note.md", "MATH.md"]
            ),
            stateOfTheArtPath: resolve(
                in: root,
                candidates: ["docs/state-of-the-art.md", "METAL_FIRST_VNEXT.md"]
            ),
            benchmarkingGuidePath: resolve(
                in: root,
                candidates: ["docs/benchmarking.md", "README.md"]
            )
        )
    }

    private static func resolve(in root: URL, candidates: [String]) -> String {
        let fileManager = FileManager.default
        for candidate in candidates {
            let url = root.appendingPathComponent(candidate)
            if fileManager.fileExists(atPath: url.path) {
                return url.path
            }
        }
        return root.appendingPathComponent(candidates[0]).path
    }
}

extension NuMetalQBenchmarks {
    static func packageRootDirectory() -> URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
    }
}
