import Foundation
import XCTest
@testable import TunnelKeychainLauncher

// Definition proposal: accepted C-008/C-009 plus scoped owner private-tunnel steering.
// Verification mapping is manual/proposed, not a formal REQ alias or approved gate.
// The injected lookup/exec seams belong to this library's tests. The release CLI
// must hardwire native Security.framework lookup and execve, with no fake mode.
final class LauncherTests: XCTestCase {
    private let fakeKey = "synthetic-runtime-key-DO-NOT-USE"
    private let service = "com.oxiom.whatsapp-connect.openai-tunnel.runtime"
    private let fixedPath = "/usr/bin:/bin:/usr/sbin:/sbin"

    private func configuration(
        organizationID: String = "org-fixture123",
        tunnelID: String = "tunnel_fixture123",
        clientExecutable: String = "/opt/fixture/tunnel-client",
        archiveExecutable: String = "/opt/fixture/whatsapp-connect",
        dataDirectory: String = "/tmp/fixture/Data Directory With Spaces",
        homeDirectory: String = "/tmp/fixture/home",
        temporaryDirectory: String = "/tmp/fixture/tmp",
        healthURLFile: String = "/tmp/fixture/runtime/health.url"
    ) throws -> LauncherConfiguration {
        try LauncherConfiguration(
            organizationID: organizationID, tunnelID: tunnelID,
            clientExecutable: clientExecutable, archiveExecutable: archiveExecutable,
            dataDirectory: dataDirectory, homeDirectory: homeDirectory,
            temporaryDirectory: temporaryDirectory, healthURLFile: healthURLFile
        )
    }

    func testLookupFailuresNeverExecuteOrExposeCredentialBytes() throws {
        // Realistic failures: absent item, native ACL cancellation/denial, locked
        // Keychain, wrong native result type, unusable UTF-8/C-string payload.
        let cases: [(String, KeychainLookupResult, String)] = [
            ("missing", .failure(.missing), "credential-unavailable"),
            ("denied", .failure(.denied), "credential-unavailable"),
            ("locked", .failure(.locked), "credential-unavailable"),
            ("malformed native value", .malformedValue, "invalid-credential"),
            ("empty", .data(Data()), "invalid-credential"),
            ("NUL", .data(Data((fakeKey + "\0suffix").utf8)), "invalid-credential"),
            ("non UTF-8", .data(Data([0xff, 0xfe])), "invalid-credential")
        ]
        for (name, result, expectedDiagnostic) in cases {
            var lookups = 0
            var executions = 0
            XCTAssertThrowsError(try Launcher.run(
                configuration: configuration(), parentEnvironment: [:],
                verifyClient: { .verified(executable: $0) },
                lookup: { query in
                    lookups += 1
                    XCTAssertEqual(query.service, self.service, name)
                    XCTAssertEqual(query.account, "org-fixture123/tunnel_fixture123", name)
                    return result
                },
                execute: { _ in executions += 1 }
            ), name) { error in
                // A fixed public category prevents native error/key payload leaks.
                XCTAssertEqual(String(describing: error), expectedDiagnostic, name)
                XCTAssertFalse(String(describing: error).contains(self.fakeKey), name)
            }
            XCTAssertEqual(lookups, 1, name)
            XCTAssertEqual(executions, 0, name)
        }
    }

    func testSuccessUsesExactItemAndFixedClientBoundaryOnly() throws {
        let ambientCases: [[String: String]] = [[:], [
            "HOME": "/ambient/home", "PATH": "/ambient/bin", "TMPDIR": "/ambient/tmp",
            "CONTROL_PLANE_API_KEY": "wrong-ambient-key", "OPENAI_API_KEY": "ambient-openai",
            "ARCHIVE_MASTER_KEY": "ambient-archive", "CALLBACK_SECRET": "ambient-callback",
            "HTTPS_PROXY": "http://fixture.invalid", "ALL_PROXY": "http://fixture.invalid",
            "NO_PROXY": "*", "DYLD_INSERT_LIBRARIES": "/ambient/inject.dylib",
            "DYLD_LIBRARY_PATH": "/ambient", "TUNNEL_CLIENT_CONFIG": "/ambient/config",
            "LOG_LEVEL": "debug", "OTEL_EXPORTER_OTLP_ENDPOINT": "http://fixture.invalid"
        ]]
        for ambient in ambientCases {
            var lookups = 0
            var requests: [LaunchRequest] = []
            try Launcher.run(
                configuration: configuration(), parentEnvironment: ambient,
                verifyClient: { .verified(executable: $0) },
                lookup: { query in
                    lookups += 1
                    XCTAssertEqual(query.service, self.service)
                    XCTAssertEqual(query.account, "org-fixture123/tunnel_fixture123")
                    return .data(Data(self.fakeKey.utf8))
                }, execute: { requests.append($0) }
            )
            XCTAssertEqual(lookups, 1)
            XCTAssertEqual(requests.count, 1)
            let request = try XCTUnwrap(requests.first)
            XCTAssertEqual(request.executable, "/opt/fixture/tunnel-client")
            XCTAssertEqual(Launcher.pinnedClientSHA256,
                "4a82a4591933241850966ab3484cb39e65fad11b7e83b43891f6599f9638bd7f")
            XCTAssertEqual(request.environment, [
                "HOME": "/tmp/fixture/home", "PATH": fixedPath,
                "TMPDIR": "/tmp/fixture/tmp", "CONTROL_PLANE_API_KEY": fakeKey
            ])
            // argv excludes argv[0]; the native executor supplies the executable.
            XCTAssertEqual(request.arguments, [
                "run", "--control-plane.api-key=env:CONTROL_PLANE_API_KEY",
                "--control-plane.tunnel-id=tunnel_fixture123", "--mcp.stdio-failure-policy=exit",
                "--health.listen-addr=127.0.0.1:0", "--health.url-file=/tmp/fixture/runtime/health.url",
                "--log.level=warn", "--log.format=json", "--log.http-raw-unsafe=false",
                "--tracing.enabled=false", "--allow-remote-ui=false",
                "--mcp.command=channel=main,command=/usr/bin/env -i HOME=/tmp/fixture/home PATH=\(fixedPath) TMPDIR=/tmp/fixture/tmp /opt/fixture/whatsapp-connect serve --transport stdio --data-dir '/tmp/fixture/Data Directory With Spaces' --log-level warn"
            ])
            XCTAssertFalse(request.arguments.joined().contains(fakeKey))
            XCTAssertFalse(request.arguments.contains { $0.contains("ambient") })
        }
    }

    func testConfigurationRejectsInvalidIDsPathsAndCommandInjection() throws {
        // Invalid nonsecret configuration must be rejected before even lookup.
        let invalid: [(String, () throws -> LauncherConfiguration)] = [
            ("organization traversal", { try self.configuration(organizationID: "org-fixture/../other") }),
            ("organization whitespace", { try self.configuration(organizationID: "org fixture") }),
            ("organization control", { try self.configuration(organizationID: "org-fixture\n") }),
            ("tunnel injection", { try self.configuration(tunnelID: "tunnel_fixture --log.level=debug") }),
            ("tunnel shell", { try self.configuration(tunnelID: "tunnel_$(id)") }),
            ("relative client", { try self.configuration(clientExecutable: "tunnel-client") }),
            ("relative archive", { try self.configuration(archiveExecutable: "./whatsapp-connect") }),
            ("relative data", { try self.configuration(dataDirectory: "data") }),
            ("relative home", { try self.configuration(homeDirectory: "home") }),
            ("relative temporary", { try self.configuration(temporaryDirectory: "tmp") }),
            ("relative health", { try self.configuration(healthURLFile: "health.url") }),
            ("client NUL", { try self.configuration(clientExecutable: "/opt/client\0suffix") }),
            ("archive newline", { try self.configuration(archiveExecutable: "/opt/archive\n--debug") }),
            ("data carriage return", { try self.configuration(dataDirectory: "/tmp/data\r") }),
            ("health control", { try self.configuration(healthURLFile: "/tmp/health\u{001b}") }),
            // Client's channel=...,command=... grammar has comma delimiters;
            // reject rather than assume shell quoting protects that outer parser.
            ("outer command delimiter", { try self.configuration(dataDirectory: "/tmp/data,command=evil") })
        ]
        for (name, makeConfiguration) in invalid {
            XCTAssertThrowsError(try makeConfiguration(), name) { error in
                XCTAssertEqual(String(describing: error), "invalid-configuration", name)
            }
        }

        // Quotes, spaces and shell punctuation are path data, never a command API.
        let pathCases: [(String, String)] = [
            ("/tmp/Data With Spaces", "'/tmp/Data With Spaces'"),
            ("/tmp/owner's data", "'/tmp/owner'\\''s data'"),
            ("/tmp/$(touch NEVER);data", "'/tmp/$(touch NEVER);data'")
        ]
        for (dataDirectory, quotedDataDirectory) in pathCases {
            var requests: [LaunchRequest] = []
            try Launcher.run(
                configuration: configuration(dataDirectory: dataDirectory), parentEnvironment: [:],
                verifyClient: { .verified(executable: $0) },
                lookup: { _ in .data(Data(self.fakeKey.utf8)) },
                execute: { requests.append($0) }
            )
            let request = try XCTUnwrap(requests.first)
            let command = try XCTUnwrap(request.arguments.last)
            XCTAssertEqual(command,
                "--mcp.command=channel=main,command=/usr/bin/env -i HOME=/tmp/fixture/home PATH=\(fixedPath) TMPDIR=/tmp/fixture/tmp /opt/fixture/whatsapp-connect serve --transport stdio --data-dir \(quotedDataDirectory) --log-level warn")
            XCTAssertEqual(requests.count, 1)
            XCTAssertFalse(command.contains(fakeKey))
        }
    }

    func testClientIntegrityPrecedesLookupAndHashesActualRegularFileBytes() throws {
        // L-001: a digest constant alone proves neither verification nor order.
        // These failure categories model native digest/open/stat failures; no
        // injected verifier is exposed by the release CLI.
        let target = "/opt/fixture/tunnel-client"
        let cases: [(String, ClientIntegrityResult, Bool)] = [
            ("mismatch", .failure(.digestMismatch), false),
            ("unreadable", .failure(.unreadable), false),
            ("not regular file", .failure(.notRegularFile), false),
            ("different verified target", .verified(executable: "/opt/fixture/other"), false),
            ("valid", .verified(executable: target), true)
        ]
        for (name, integrity, valid) in cases {
            var phases: [String] = []
            let run = {
                try Launcher.run(
                    configuration: self.configuration(), parentEnvironment: [:],
                    verifyClient: { path in
                        phases.append("verify")
                        XCTAssertEqual(path, target, name)
                        return integrity
                    },
                    lookup: { query in
                        phases.append("lookup")
                        XCTAssertEqual(query.service, self.service, name)
                        XCTAssertEqual(query.account, "org-fixture123/tunnel_fixture123", name)
                        return .data(Data(self.fakeKey.utf8))
                    },
                    execute: { request in
                        phases.append("exec")
                        XCTAssertEqual(request.executable, target, name)
                        if case .verified(let verifiedTarget) = integrity {
                            XCTAssertEqual(request.executable, verifiedTarget, name)
                        } else {
                            XCTFail("Execution without verified target", file: #filePath, line: #line)
                        }
                    }
                )
            }
            if valid {
                try run()
                XCTAssertEqual(phases, ["verify", "lookup", "exec"], name)
            } else {
                XCTAssertThrowsError(try run(), name) { error in
                    XCTAssertEqual(String(describing: error), "client-integrity-failed", name)
                }
                XCTAssertEqual(phases, ["verify"], name) // ZERO lookup and exec.
            }
        }

        // Call the future REAL native hashing function, without the seam, on
        // two independently known SHA-256 vectors. Constant-returning hashing
        // cannot satisfy both. These files contain synthetic public bytes only.
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("tunnel-digest-witness-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: directory) }
        for (index, vector) in [
            (Data(), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
            (Data("abc".utf8), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        ].enumerated() {
            let file = directory.appendingPathComponent("vector-\(index)")
            try vector.0.write(to: file)
            XCTAssertEqual(try NativeClientVerifier.sha256(ofRegularFile: file.path), vector.1)
        }
        XCTAssertThrowsError(try NativeClientVerifier.sha256(ofRegularFile: directory.path)) { error in
            XCTAssertEqual(String(describing: error), "client-integrity-failed")
        }
    }

    // Current C-008/C-009 development-file exception; two focused tables only.
    func testDevelopmentCredentialFileSafetyTable() throws {
        let fm = FileManager.default
        // Foundation preserves the /var alias on this macOS; realpath supplies an actual no-symlink fixture.
        let canonicalTemporary = try XCTUnwrap(realpath(fm.temporaryDirectory.path, nil))
        defer { free(canonicalTemporary) }
        let root = URL(fileURLWithPath: String(cString: canonicalTemporary))
            .appendingPathComponent("dev-key-fixtures-" + UUID().uuidString)
        try fm.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? fm.removeItem(at: root) }
        let cases: [(String, Data?, String?)] = [
            ("valid", Data(fakeKey.utf8), nil),
            ("missing", nil, "credential-unavailable"),
            ("empty", Data(), "invalid-credential"),
            ("newline", Data((fakeKey + "\n").utf8), "invalid-credential"),
            ("space", Data("invalid token".utf8), "invalid-credential"),
            ("NUL", Data([65, 0, 66]), "invalid-credential"),
            ("invalidUTF8", Data([0xff]), "invalid-credential"),
            ("oversized", Data(repeating: 65, count: 4097), "invalid-credential"),
            ("publicFile", Data(fakeKey.utf8), "credential-unavailable"),
            ("publicParent", Data(fakeKey.utf8), "credential-unavailable"),
            ("symlinkFile", Data(fakeKey.utf8), "credential-unavailable"),
            ("symlinkParent", Data(fakeKey.utf8), "credential-unavailable"),
            ("directory", nil, "credential-unavailable"),
            ("fifo", nil, "credential-unavailable"),
            ("hardlink", Data(fakeKey.utf8), "credential-unavailable")
        ]
        for (name, bytes, expected) in cases {
            let parent = root.appendingPathComponent(name)
            try fm.createDirectory(at: parent, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
            let file = parent.appendingPathComponent("runtime.key")
            if let bytes { try bytes.write(to: file); try fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path) }
            var selected = file.path
            switch name {
            case "publicFile": try fm.setAttributes([.posixPermissions: 0o644], ofItemAtPath: file.path)
            case "publicParent": try fm.setAttributes([.posixPermissions: 0o755], ofItemAtPath: parent.path)
            case "symlinkFile":
                let link = parent.appendingPathComponent("link"); try fm.createSymbolicLink(atPath: link.path, withDestinationPath: file.path); selected = link.path
            case "symlinkParent":
                let link = root.appendingPathComponent("parent-link"); try fm.createSymbolicLink(atPath: link.path, withDestinationPath: parent.path); selected = link.appendingPathComponent("runtime.key").path
            case "directory": try fm.createDirectory(at: file, withIntermediateDirectories: false)
            case "fifo": XCTAssertEqual(mkfifo(file.path, 0o600), 0)
            case "hardlink": try fm.linkItem(at: file, to: parent.appendingPathComponent("other"))
            default: break
            }
            if let expected {
                XCTAssertThrowsError(try NativeCredentialFile.read(selected), name) {
                    XCTAssertEqual(String(describing: $0), expected, name)
                    XCTAssertFalse(String(describing: $0).contains(self.fakeKey), name)
                    XCTAssertFalse(String(describing: $0).contains(selected), name)
                }
            } else {
                XCTAssertEqual(try NativeCredentialFile.read(selected), Data(fakeKey.utf8), name)
            }
        }
        for path in ["relative.key", root.path + "/../runtime.key", root.path + "/bad\nkey"] {
            XCTAssertThrowsError(try NativeCredentialFile.read(path)) {
                XCTAssertEqual(String(describing: $0), "credential-unavailable")
            }
        }
    }

    func testDevelopmentCredentialRoutingAndPinOrderTable() throws {
        let cases: [(String, String?, Bool, Bool, [String], String?)] = [
            ("file success", "/fixture/runtime.key", true, true, ["verify", "file", "exec"], nil),
            ("file failure", "/fixture/runtime.key", true, false, ["verify", "file"], "credential-unavailable"),
            ("bad pin", "/fixture/runtime.key", false, true, ["verify"], "client-integrity-failed"),
            ("Keychain default", nil, true, true, ["verify", "keychain", "exec"], nil)
        ]
        for (name, path, validPin, validFile, expectedPhases, expectedError) in cases {
            var phases: [String] = []
            let operation = {
                try Launcher.run(configuration: self.configuration(), parentEnvironment: [:],
                    verifyClient: { target in phases.append("verify"); return validPin ? .verified(executable: target) : .failure(.digestMismatch) },
                    lookup: { query in
                        try Launcher.selectCredential(path: path, query: query,
                            file: { selected in
                                phases.append("file"); XCTAssertEqual(selected, path, name)
                                if !validFile { throw LauncherFailure.credentialUnavailable }
                                return Data(self.fakeKey.utf8)
                            }, keychain: { selected in
                                phases.append("keychain")
                                XCTAssertEqual(selected.service, self.service, name)
                                XCTAssertEqual(selected.account, "org-fixture123/tunnel_fixture123", name)
                                return .data(Data(self.fakeKey.utf8))
                            })
                    }, execute: { request in
                        phases.append("exec")
                        XCTAssertEqual(request.environment["CONTROL_PLANE_API_KEY"], self.fakeKey, name)
                        XCTAssertEqual(Set(request.environment.keys), Set(["HOME", "PATH", "TMPDIR", "CONTROL_PLANE_API_KEY"]), name)
                        XCTAssertFalse(request.arguments.joined().contains(self.fakeKey), name)
                        XCTAssertTrue(request.arguments.last!.contains("/usr/bin/env -i"), name)
                    })
            }
            if let expectedError {
                XCTAssertThrowsError(try operation(), name) { XCTAssertEqual(String(describing: $0), expectedError, name) }
            } else { try operation() }
            XCTAssertEqual(phases, expectedPhases, name)
        }
    }
}
