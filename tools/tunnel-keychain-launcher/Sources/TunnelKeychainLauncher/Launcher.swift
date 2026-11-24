import Foundation
import CryptoKit
import Security
import Darwin

// Manual C-008/C-009 mapping: .traceweaver/tunnel-launcher-authority.json.
// Native secrets stay at this boundary; no underlying error text is exported.
enum LauncherFailure: Error, CustomStringConvertible {
    case invalidConfiguration, integrity, credentialUnavailable, invalidCredential, runtime, execution
    var description: String {
        switch self {
        case .invalidConfiguration: return "invalid-configuration"
        case .integrity: return "client-integrity-failed"
        case .credentialUnavailable: return "credential-unavailable"
        case .invalidCredential: return "invalid-credential"
        case .runtime: return "private-runtime-unavailable"
        case .execution: return "execution-failed"
        }
    }
    var exitCode: Int32 {
        switch self {
        case .invalidConfiguration: return 64
        case .integrity: return 65
        case .runtime: return 73
        case .credentialUnavailable: return 77
        case .invalidCredential: return 78
        case .execution: return 126
        }
    }
}

struct LauncherConfiguration {
    let organizationID, tunnelID, clientExecutable, archiveExecutable: String
    let dataDirectory, homeDirectory, temporaryDirectory, healthURLFile: String
    let devRuntimeKeyFile: String?
    init(organizationID: String, tunnelID: String, clientExecutable: String,
         archiveExecutable: String, dataDirectory: String, homeDirectory: String,
         temporaryDirectory: String, healthURLFile: String, devRuntimeKeyFile: String? = nil) throws {
        func identifier(_ value: String, prefix: String) -> Bool {
            value.hasPrefix(prefix) && value.count > prefix.count && value.count <= 256 &&
                value.utf8.allSatisfy { (65...90).contains($0) || (97...122).contains($0) ||
                    (48...57).contains($0) || $0 == 45 || $0 == 95 }
        }
        func path(_ value: String) -> Bool {
            value.hasPrefix("/") && value != "/" && value.utf8.count < Int(PATH_MAX) &&
                !value.unicodeScalars.contains { CharacterSet.controlCharacters.contains($0) } &&
                !value.contains(",") && !value.split(separator: "/").contains { $0 == "." || $0 == ".." }
        }
        guard identifier(organizationID, prefix: "org-"), identifier(tunnelID, prefix: "tunnel_"),
            [clientExecutable, archiveExecutable, dataDirectory, homeDirectory,
             temporaryDirectory, healthURLFile].allSatisfy(path),
            devRuntimeKeyFile.map(path) ?? true else { throw LauncherFailure.invalidConfiguration }
        self.organizationID = organizationID; self.tunnelID = tunnelID
        self.clientExecutable = clientExecutable; self.archiveExecutable = archiveExecutable
        self.dataDirectory = dataDirectory; self.homeDirectory = homeDirectory
        self.temporaryDirectory = temporaryDirectory; self.healthURLFile = healthURLFile
        self.devRuntimeKeyFile = devRuntimeKeyFile
    }
}

struct KeychainQuery { let service, account: String }
enum KeychainFailure { case missing, denied, locked }
enum KeychainLookupResult { case failure(KeychainFailure), malformedValue, data(Data) }
enum ClientIntegrityFailure { case digestMismatch, unreadable, notRegularFile }
enum ClientIntegrityResult { case failure(ClientIntegrityFailure), verified(executable: String) }
struct LaunchRequest { let executable: String; let arguments: [String]; let environment: [String: String] }

enum Launcher {
    static let pinnedClientSHA256 = "4a82a4591933241850966ab3484cb39e65fad11b7e83b43891f6599f9638bd7f"
    static let service = "com.oxiom.whatsapp-connect.openai-tunnel.runtime"
    static let safePath = "/usr/bin:/bin:/usr/sbin:/sbin"

    // Library seam for focused tests; the CLI supplies only the native functions.
    static func run(configuration c: LauncherConfiguration, parentEnvironment: [String: String],
                    verifyClient: (String) -> ClientIntegrityResult,
                    lookup: (KeychainQuery) throws -> KeychainLookupResult,
                    execute: (LaunchRequest) throws -> Void) throws {
        guard case .verified(let verifiedTarget) = verifyClient(c.clientExecutable),
            verifiedTarget == c.clientExecutable else { throw LauncherFailure.integrity }
        let result = try lookup(KeychainQuery(service: service, account: c.organizationID + "/" + c.tunnelID))
        let data: Data
        switch result {
        case .failure: throw LauncherFailure.credentialUnavailable
        case .malformedValue: throw LauncherFailure.invalidCredential
        case .data(let bytes): data = bytes
        }
        guard !data.isEmpty, data.count <= 4096, data.allSatisfy({ (0x21...0x7e).contains($0) }),
            let key = String(data: data, encoding: .ascii) else {
            throw LauncherFailure.invalidCredential
        }
        let nonsecret = ["HOME": c.homeDirectory, "PATH": safePath, "TMPDIR": c.temporaryDirectory]
        let child = ["/usr/bin/env", "-i", "HOME=" + c.homeDirectory, "PATH=" + safePath,
                     "TMPDIR=" + c.temporaryDirectory, c.archiveExecutable,
                     "serve", "--transport", "stdio", "--data-dir", c.dataDirectory, "--log-level", "warn"]
        let arguments = ["run", "--control-plane.api-key=env:CONTROL_PLANE_API_KEY",
            "--control-plane.tunnel-id=" + c.tunnelID, "--mcp.stdio-failure-policy=exit",
            "--health.listen-addr=127.0.0.1:0", "--health.url-file=" + c.healthURLFile,
            "--log.level=warn", "--log.format=json", "--log.http-raw-unsafe=false",
            "--tracing.enabled=false", "--allow-remote-ui=false",
            "--mcp.command=channel=main,command=" + child.map(quote).joined(separator: " ")]
        var environment = nonsecret
        environment["CONTROL_PLANE_API_KEY"] = key
        // parentEnvironment is intentionally ignored, including proxies/config/DYLD.
        try execute(LaunchRequest(executable: verifiedTarget, arguments: arguments, environment: environment))
    }

    // Manual C-008/C-009: presence selects file only; failures never fall back.
    static func selectCredential(path: String?, query: KeychainQuery,
                                 file: (String) throws -> Data,
                                 keychain: (KeychainQuery) -> KeychainLookupResult) throws -> KeychainLookupResult {
        if let path { return .data(try file(path)) }
        return keychain(query)
    }

    private static func quote(_ value: String) -> String {
        let safe = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_@%+=:./-")
        if !value.isEmpty && value.unicodeScalars.allSatisfy({ safe.contains($0) }) { return value }
        return "'" + value.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }
}

// Manual C-008/C-009: descriptor-relative bounded development plaintext reader.
// No path/OS error/credential bytes enter public diagnostics; reading never repairs permissions.
enum NativeCredentialFile {
    private static func noExtendedACL(_ fd: Int32) -> Bool {
        // Darwin reports ENOENT when no extended ACL exists. Other errors fail closed.
        errno = 0
        guard let acl = acl_get_fd_np(fd, ACL_TYPE_EXTENDED) else { return errno == ENOENT }
        defer { acl_free(UnsafeMutableRawPointer(acl)) }
        guard acl_valid(acl) == 0 else { return false }
        var entry: acl_entry_t?
        errno = 0
        // Darwin returns0 for an entry and -1/EINVAL for an empty validated ACL.
        return acl_get_entry(acl, Int32(ACL_FIRST_ENTRY.rawValue), &entry) == -1 && errno == EINVAL
    }

    static func read(_ path: String) throws -> Data {
        let parts = path.split(separator: "/", omittingEmptySubsequences: false)
        guard path.hasPrefix("/"), path != "/", path.utf8.count < Int(PATH_MAX),
            !path.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }),
            parts.dropFirst().allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." }) else {
            throw LauncherFailure.credentialUnavailable
        }
        var directory = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        guard directory >= 0 else { throw LauncherFailure.credentialUnavailable }
        defer { close(directory) }
        for component in parts.dropFirst().dropLast() {
            let next = openat(directory, String(component), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
            guard next >= 0 else { throw LauncherFailure.credentialUnavailable }
            close(directory); directory = next
        }
        var parent = stat()
        guard fstat(directory, &parent) == 0, (parent.st_mode & S_IFMT) == S_IFDIR,
            parent.st_uid == getuid(), parent.st_mode & 0o7777 == 0o700,
            noExtendedACL(directory) else { throw LauncherFailure.credentialUnavailable }
        let fd = openat(directory, String(parts.last!), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK)
        guard fd >= 0 else { throw LauncherFailure.credentialUnavailable }
        defer { close(fd) }
        var before = stat()
        guard fstat(fd, &before) == 0, (before.st_mode & S_IFMT) == S_IFREG,
            before.st_uid == getuid(), before.st_mode & 0o7777 == 0o600,
            before.st_nlink == 1, noExtendedACL(fd) else { throw LauncherFailure.credentialUnavailable }
        var bytes = Data()
        var buffer = [UInt8](repeating: 0, count: 4097)
        while bytes.count < 4097 {
            let count = Darwin.read(fd, &buffer, 4097 - bytes.count)
            if count < 0 {
                if errno == EINTR { continue }
                throw LauncherFailure.credentialUnavailable
            }
            if count == 0 { break }
            bytes.append(contentsOf: buffer.prefix(count))
        }
        var after = stat()
        guard fstat(fd, &after) == 0, before.st_size == after.st_size,
            before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec,
            before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec,
            before.st_ctimespec.tv_sec == after.st_ctimespec.tv_sec,
            before.st_ctimespec.tv_nsec == after.st_ctimespec.tv_nsec else { throw LauncherFailure.credentialUnavailable }
        guard !bytes.isEmpty, bytes.count <= 4096,
            bytes.allSatisfy({ (0x21...0x7e).contains($0) }) else { throw LauncherFailure.invalidCredential }
        return bytes
    }
}

enum NativeClientVerifier {
    // Hash bytes from an opened non-symlink regular file, not metadata or a constant.
    static func sha256(ofRegularFile path: String) throws -> String {
        let fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
        guard fd >= 0 else { throw LauncherFailure.integrity }
        defer { close(fd) }
        var before = stat()
        guard fstat(fd, &before) == 0, (before.st_mode & S_IFMT) == S_IFREG else { throw LauncherFailure.integrity }
        var hash = SHA256()
        var buffer = [UInt8](repeating: 0, count: 65536)
        while true {
            let count = read(fd, &buffer, buffer.count)
            if count < 0 { if errno == EINTR { continue }; throw LauncherFailure.integrity }
            if count == 0 { break }
            hash.update(data: Data(buffer.prefix(count)))
        }
        var after = stat()
        guard fstat(fd, &after) == 0, before.st_size == after.st_size,
            before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec,
            before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec,
            before.st_ctimespec.tv_sec == after.st_ctimespec.tv_sec,
            before.st_ctimespec.tv_nsec == after.st_ctimespec.tv_nsec else { throw LauncherFailure.integrity }
        return hash.finalize().map { String(format: "%02x", $0) }.joined()
    }

    static func verify(_ path: String) -> ClientIntegrityResult {
        var info = stat()
        guard lstat(path, &info) == 0 else { return .failure(.unreadable) }
        guard (info.st_mode & S_IFMT) == S_IFREG else { return .failure(.notRegularFile) }
        guard (info.st_mode & 0o111) != 0, (info.st_mode & 0o022) == 0,
            info.st_uid == getuid() || info.st_uid == 0 else { return .failure(.unreadable) }
        guard let digest = try? sha256(ofRegularFile: path), digest == Launcher.pinnedClientSHA256 else {
            return .failure(.digestMismatch)
        }
        return .verified(executable: path)
    }
}

public enum NativeLauncher {
    public static let help = """
    Usage: tunnel-keychain-launcher --organization-id ID --tunnel-id ID --client ABSOLUTE_PATH --archive ABSOLUTE_PATH --data-dir ABSOLUTE_PATH --home ABSOLUTE_PATH --tmp-dir ABSOLUTE_PATH --health-url-file ABSOLUTE_PATH [--dev-runtime-key-file ABSOLUTE_PATH] [--owner-http-url http://127.0.0.1:PORT/mcp]
    Provision separately: tunnel-keychain-launcher owner-access init --data-dir ABSOLUTE_PATH
    Runs one fixed, pinned tunnel-client with native login-Keychain credentials by default.
    Explicit HTTP mode routes to the existing owner; owner access always uses native Keychain.
    Explicit development file mode reads only the owner-only plaintext token file; no fallback.
    Only nonsecret paths and identifiers are accepted. No credential or pin override exists.
    --help prints this text without Keychain access.
    Exit codes before exec: 64 configuration, 65 integrity, 73 private runtime, 77 unavailable credential, 78 invalid credential, 126 exec failure.
    After exec, status belongs to tunnel-client. No automatic restart or service installation.
    """

    public static func run(arguments: [String]) -> Int32 {
        if arguments == ["--help"] {
            FileHandle.standardOutput.write(Data((help + "\n").utf8)); return 0
        }
        do {
            if arguments.count == 4, arguments[0] == "owner-access", arguments[1] == "init", arguments[2] == "--data-dir" {
                guard arguments[3].hasPrefix("/") else { throw LauncherFailure.invalidConfiguration }
                umask(0o077)
                var core = rlimit(rlim_cur: 0, rlim_max: 0)
                guard setrlimit(RLIMIT_CORE, &core) == 0 else { throw LauncherFailure.runtime }
                try NativeOwnerHTTPAccess.initialize(dataDirectory: arguments[3])
                FileHandle.standardOutput.write(Data("owner-access-initialized\n".utf8))
                return 0
            }
            let (c, ownerURL) = try parse(arguments)
            umask(0o077)
            var core = rlimit(rlim_cur: 0, rlim_max: 0)
            guard setrlimit(RLIMIT_CORE, &core) == 0 else { throw LauncherFailure.runtime }
            // Integrity always precedes runtime filesystem setup and any Keychain API.
            if let ownerURL {
                try Launcher.runOwnerHTTP(configuration: c, serverURL: ownerURL,
                    canonicalDBPath: (c.dataDirectory as NSString).appendingPathComponent("whatsapp.db"),
                    verify: {
                        if case .verified(let target) = NativeClientVerifier.verify(c.clientExecutable) { return target == c.clientExecutable }
                        return false
                    }, runtimeKey: {
                        try prepareRuntime(c)
                        return try credentialBytes(Launcher.selectCredential(path: c.devRuntimeKeyFile,
                            query: KeychainQuery(service: Launcher.service, account: c.organizationID + "/" + c.tunnelID),
                            file: NativeCredentialFile.read, keychain: lookup))
                    }, ownerKey: { service, account in
                        // No file fallback, regardless of runtime development mode.
                        try credentialBytes(lookup(KeychainQuery(service: service, account: account)))
                    }, execute: { try execute($0) })
                throw LauncherFailure.execution
            }
            try Launcher.run(configuration: c, parentEnvironment: [:], verifyClient: NativeClientVerifier.verify,
                lookup: { query in
                    // Only the exact login item is touched; archive/callback stores are absent.
                    try prepareRuntime(c)
                    return try Launcher.selectCredential(path: c.devRuntimeKeyFile, query: query,
                        file: NativeCredentialFile.read, keychain: lookup)
                }, execute: { try execute($0) })
            throw LauncherFailure.execution
        } catch let error as LauncherFailure {
            FileHandle.standardError.write(Data((error.description + "\n").utf8)); return error.exitCode
        } catch {
            FileHandle.standardError.write(Data("execution-failed\n".utf8)); return 126
        }
    }

    private static func parse(_ args: [String]) throws -> (LauncherConfiguration, String?) {
        let required: Set<String> = ["--organization-id", "--tunnel-id", "--client", "--archive",
            "--data-dir", "--home", "--tmp-dir", "--health-url-file"]
        let allowed = required.union(["--dev-runtime-key-file", "--owner-http-url"])
        guard args.count % 2 == 0, args.count >= required.count * 2, args.count <= allowed.count * 2 else { throw LauncherFailure.invalidConfiguration }
        var values: [String: String] = [:]
        for index in stride(from: 0, to: args.count, by: 2) {
            guard allowed.contains(args[index]), values[args[index]] == nil else { throw LauncherFailure.invalidConfiguration }
            values[args[index]] = args[index + 1]
        }
        guard required.isSubset(of: Set(values.keys)) else { throw LauncherFailure.invalidConfiguration }
        if let url = values["--owner-http-url"] { try OwnerHTTPIdentity.validateURL(url) }
        let configuration = try LauncherConfiguration(organizationID: values["--organization-id"]!, tunnelID: values["--tunnel-id"]!,
            clientExecutable: values["--client"]!, archiveExecutable: values["--archive"]!,
            dataDirectory: values["--data-dir"]!, homeDirectory: values["--home"]!,
            temporaryDirectory: values["--tmp-dir"]!, healthURLFile: values["--health-url-file"]!,
            devRuntimeKeyFile: values["--dev-runtime-key-file"])
        return (configuration, values["--owner-http-url"])
    }

    private static func credentialBytes(_ result: KeychainLookupResult) throws -> Data {
        switch result {
        case .failure: throw LauncherFailure.credentialUnavailable
        case .malformedValue: throw LauncherFailure.invalidCredential
        case .data(let bytes): return bytes
        }
    }

    private static func prepareRuntime(_ c: LauncherConfiguration) throws {
        let parent = (c.healthURLFile as NSString).deletingLastPathComponent
        // lstat every component: reject symlink traversal, even a parent symlink.
        var prefix = ""
        for part in parent.split(separator: "/") {
            prefix += "/" + part
            var info = stat()
            if lstat(prefix, &info) != 0 {
                guard prefix == parent, errno == ENOENT, mkdir(prefix, 0o700) == 0 else { throw LauncherFailure.runtime }
                guard lstat(prefix, &info) == 0 else { throw LauncherFailure.runtime }
            }
            guard (info.st_mode & S_IFMT) == S_IFDIR else { throw LauncherFailure.runtime }
            if prefix == parent {
                guard info.st_uid == getuid(), info.st_mode & 0o777 == 0o700 else { throw LauncherFailure.runtime }
            }
        }
        var existing = stat()
        guard lstat(c.healthURLFile, &existing) != 0, errno == ENOENT else { throw LauncherFailure.runtime }
        // These paths are configuration only; do not open the archive/profile.
    }

    private static func lookup(_ query: KeychainQuery) -> KeychainLookupResult {
        var keychain: SecKeychain?
        // Resolve the current local user's login Keychain independently of the
        // configurable, nonsecret HOME given to the client and archive child.
        guard let record = getpwuid(getuid()), let directory = record.pointee.pw_dir else { return .failure(.denied) }
        let home = String(cString: directory)
        let path = home + "/Library/Keychains/login.keychain-db"
        guard SecKeychainOpen(path, &keychain) == errSecSuccess, let login = keychain else { return .failure(.locked) }
        let attributes: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword, kSecAttrService: query.service,
            kSecAttrAccount: query.account, kSecMatchSearchList: [login],
            kSecAttrSynchronizable: false, kSecMatchLimit: kSecMatchLimitOne, kSecReturnData: true
        ]
        var value: CFTypeRef?
        switch SecItemCopyMatching(attributes as CFDictionary, &value) {
        case errSecSuccess:
            guard let data = value as? Data else { return .malformedValue }
            return .data(data)
        case errSecItemNotFound: return .failure(.missing)
        case errSecInteractionNotAllowed: return .failure(.locked)
        default: return .failure(.denied)
        }
    }

    private static func execute(_ request: LaunchRequest) throws {
        // Recheck pinned bytes immediately before exec as well. This does not
        // promise protection against a privileged/same-user concurrent replacement.
        guard case .verified(let target) = NativeClientVerifier.verify(request.executable),
            target == request.executable else { throw LauncherFailure.integrity }
        let argv = ([request.executable] + request.arguments).map { strdup($0) } + [nil]
        let envp = request.environment.keys.sorted().map { strdup($0 + "=" + request.environment[$0]!) } + [nil]
        defer { argv.forEach { free($0) }; envp.forEach { free($0) } }
        guard argv.dropLast().allSatisfy({ $0 != nil }), envp.dropLast().allSatisfy({ $0 != nil }) else {
            throw LauncherFailure.execution
        }
        argv.withUnsafeBufferPointer { a in
            envp.withUnsafeBufferPointer { e in
                _ = execve(request.executable, a.baseAddress!, e.baseAddress!)
            }
        }
        throw LauncherFailure.execution
    }
}
