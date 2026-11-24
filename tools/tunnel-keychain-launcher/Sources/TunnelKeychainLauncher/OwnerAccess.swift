import Foundation
import CryptoKit
import Security
import Darwin

// Manual C-008/C-009: fixed purpose namespace; normal launch reads only.
enum OwnerHTTPIdentity {
    static let service = "com.oxiom.whatsapp-connect.owner-http"
    static func canonicalPath(_ path: String) throws -> String {
        guard !path.utf8.contains(0), let resolved = realpath(path, nil) else {
            throw LauncherFailure.invalidConfiguration
        }
        defer { free(resolved) }
        guard let canonical = String(validatingUTF8: resolved) else { throw LauncherFailure.invalidConfiguration }
        var info = stat()
        guard stat(canonical, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG else {
            throw LauncherFailure.invalidConfiguration
        }
        return canonical
    }
    static func account(forExistingDB path: String) throws -> String {
        let canonical = try canonicalPath(path)
        return SHA256.hash(data: Data(canonical.utf8)).map { String(format: "%02x", $0) }.joined()
    }
    static func validateURL(_ value: String) throws {
        // Exact numeric-loopback origin/path; URLComponents alone normalizes
        // spellings such as empty userinfo, so also require canonical spelling.
        guard let u = URLComponents(string: value), u.scheme == "http", u.host == "127.0.0.1",
            u.user == nil, u.password == nil, u.query == nil, u.fragment == nil,
            u.path == "/mcp", let port = u.port, (1...65535).contains(port),
            value == "http://127.0.0.1:\(port)/mcp" else { throw LauncherFailure.invalidConfiguration }
    }
}

extension Launcher {
    // Native adapters only on the CLI. Test closures never touch real items.
    static func runOwnerHTTP(configuration c: LauncherConfiguration, serverURL: String, canonicalDBPath: String,
                             verify: () -> Bool, runtimeKey: () throws -> Data,
                             ownerKey: (String, String) throws -> Data,
                             execute: (LaunchRequest) throws -> Void) throws {
        try OwnerHTTPIdentity.validateURL(serverURL)
        let derived = try OwnerHTTPIdentity.canonicalPath((c.dataDirectory as NSString).appendingPathComponent("whatsapp.db"))
        guard try OwnerHTTPIdentity.canonicalPath(canonicalDBPath) == derived else { throw LauncherFailure.invalidConfiguration }
        let account = try OwnerHTTPIdentity.account(forExistingDB: derived)
        guard verify() else { throw LauncherFailure.integrity }
        let runtime: Data
        let owner: Data
        do { runtime = try runtimeKey(); owner = try ownerKey(OwnerHTTPIdentity.service, account) }
        catch let failure as LauncherFailure { throw failure }
        catch { throw LauncherFailure.credentialUnavailable }
        guard !runtime.isEmpty, runtime.count <= 4096, runtime.allSatisfy({ (0x21...0x7e).contains($0) }),
            let control = String(data: runtime, encoding: .ascii), owner.count == 32 else {
            throw LauncherFailure.invalidCredential
        }
        let encoded = owner.base64EncodedString().replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
        let arguments = ["run", "--control-plane.api-key=env:CONTROL_PLANE_API_KEY",
            "--control-plane.tunnel-id=" + c.tunnelID,
            "--mcp.server-url=url=" + serverURL + ",channel=main",
            "--mcp.extra-headers=X-WhatsApp-Owner-Authorization: env:WC_OWNER_AUTHORIZATION",
            "--health.listen-addr=127.0.0.1:0", "--health.url-file=" + c.healthURLFile,
            "--log.level=warn", "--log.format=json", "--log.http-raw-unsafe=false",
            "--tracing.enabled=false", "--allow-remote-ui=false"]
        let environment = ["HOME": c.homeDirectory, "PATH": safePath, "TMPDIR": c.temporaryDirectory,
            "CONTROL_PLANE_API_KEY": control, "WC_OWNER_AUTHORIZATION": "Bearer " + encoded]
        try execute(LaunchRequest(executable: c.clientExecutable, arguments: arguments, environment: environment))
    }
}

// This create-only function has no update/delete/export operation. A native
// duplicate-add race fails rather than replacing the original item.
enum OwnerHTTPProvision {
    static func initialize(existing: Data?, random: () throws -> Data, add: (Data) throws -> Void) throws {
        if let existing {
            guard existing.count == 32 else { throw LauncherFailure.invalidCredential }
            return
        }
        let bytes = try random()
        guard bytes.count == 32 else { throw LauncherFailure.invalidCredential }
        try add(bytes)
    }
}

enum NativeOwnerHTTPAccess {
    private static func loginKeychain() throws -> SecKeychain {
        guard let record = getpwuid(getuid()), let directory = record.pointee.pw_dir else {
            throw LauncherFailure.credentialUnavailable
        }
        let path = String(cString: directory) + "/Library/Keychains/login.keychain-db"
        var keychain: SecKeychain?
        guard SecKeychainOpen(path, &keychain) == errSecSuccess, let login = keychain else {
            throw LauncherFailure.credentialUnavailable
        }
        return login
    }
    // Called only by the explicit owner-access init command, never startup.
    static func initialize(dataDirectory: String) throws {
        let account = try OwnerHTTPIdentity.account(forExistingDB: (dataDirectory as NSString).appendingPathComponent("whatsapp.db"))
        let login = try loginKeychain()
        let query: [CFString: Any] = [kSecClass: kSecClassGenericPassword,
            kSecAttrService: OwnerHTTPIdentity.service, kSecAttrAccount: account,
            kSecMatchSearchList: [login], kSecAttrSynchronizable: false,
            kSecMatchLimit: kSecMatchLimitOne, kSecReturnData: true]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        let existing: Data?
        switch status {
        case errSecSuccess:
            guard let data = result as? Data else { throw LauncherFailure.invalidCredential }
            existing = data
        case errSecItemNotFound: existing = nil
        default: throw LauncherFailure.credentialUnavailable
        }
        try OwnerHTTPProvision.initialize(existing: existing, random: {
            var bytes = Data(count: 32)
            let status = bytes.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }
            guard status == errSecSuccess else { throw LauncherFailure.credentialUnavailable }
            return bytes
        }, add: { bytes in
            let item: [CFString: Any] = [kSecClass: kSecClassGenericPassword,
                kSecAttrService: OwnerHTTPIdentity.service, kSecAttrAccount: account,
                kSecUseKeychain: login, kSecAttrSynchronizable: false,
                kSecAttrAccessible: kSecAttrAccessibleWhenUnlockedThisDeviceOnly, kSecValueData: bytes]
            guard SecItemAdd(item as CFDictionary, nil) == errSecSuccess else {
                throw LauncherFailure.credentialUnavailable
            }
        })
    }
}
