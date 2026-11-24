import Foundation
import XCTest
import CryptoKit
import Darwin

private func expectedPOSIXPath(_ path: String) throws -> String {
 guard let raw = Darwin.realpath(path, nil) else { throw NSError(domain: "synthetic-path", code: 1) }
 defer { free(raw) }
 return String(cString: raw)
}
@testable import TunnelKeychainLauncher
// Proposed seams: missing API is not behavioral RED. Native functions never called.
final class OwnerHTTPTests: XCTestCase {
 func testOwnerHTTPHelperBoundaryAndProvisioning() throws {
  let key=Data(repeating:0x42,count:32)
  let fm=FileManager.default
  let fixtureRoot=fm.temporaryDirectory.appendingPathComponent("owner-http-launch-"+UUID().uuidString).resolvingSymlinksInPath()
  try fm.createDirectory(at:fixtureRoot,withIntermediateDirectories:true)
  defer { try? fm.removeItem(at:fixtureRoot) }
  let launchDB=fixtureRoot.appendingPathComponent("whatsapp.db")
  try Data("synthetic-public-fixture".utf8).write(to:launchDB)
  let fixtureConfiguration=try LauncherConfiguration(organizationID:"org-fixture123",tunnelID:"tunnel_fixture123",clientExecutable:"/opt/fixture/tunnel-client",archiveExecutable:"/opt/fixture/whatsapp-connect",dataDirectory:fixtureRoot.path,homeDirectory:fixtureRoot.path,temporaryDirectory:fixtureRoot.path,healthURLFile:fixtureRoot.appendingPathComponent("health.url").path,devRuntimeKeyFile:fixtureRoot.appendingPathComponent("runtime.key").path)

  let expectedLaunchCanonical = try expectedPOSIXPath(launchDB.path)
  for verified in [false,true] {
   var phases:[String]=[];var requests:[LaunchRequest]=[]
   let run={try Launcher.runOwnerHTTP(configuration:fixtureConfiguration,serverURL:"http://127.0.0.1:9812/mcp",canonicalDBPath:launchDB.path,verify:{phases.append("pin");return verified},runtimeKey:{phases.append("runtime-key");return Data("synthetic-control".utf8)},ownerKey:{service,account in phases.append("owner-key");XCTAssertEqual(service,"com.oxiom.whatsapp-connect.owner-http");XCTAssertEqual(account,SHA256.hash(data:Data(expectedLaunchCanonical.utf8)).map{String(format:"%02x",$0)}.joined());return key},execute:{requests.append($0)})}
   if verified {try run();XCTAssertEqual(phases,["pin","runtime-key","owner-key"]);let r=try XCTUnwrap(requests.first);XCTAssertEqual(r.executable,fixtureConfiguration.clientExecutable);XCTAssertTrue(r.arguments.contains("--control-plane.tunnel-id=tunnel_fixture123"));XCTAssertFalse(r.arguments.contains{$0.contains("mcp.command")});XCTAssertTrue(r.arguments.contains("--mcp.server-url=url=http://127.0.0.1:9812/mcp,channel=main"));XCTAssertEqual(r.environment["WC_OWNER_AUTHORIZATION"],"Bearer "+key.base64EncodedString().replacingOccurrences(of:"+",with:"-").replacingOccurrences(of:"/",with:"_").replacingOccurrences(of:"=",with:""));XCTAssertTrue(r.arguments.contains("--mcp.extra-headers=X-WhatsApp-Owner-Authorization: env:WC_OWNER_AUTHORIZATION"));XCTAssertFalse(r.arguments.joined().contains(key.base64EncodedString()));XCTAssertEqual(Set(r.environment.keys),Set(["HOME","PATH","TMPDIR","CONTROL_PLANE_API_KEY","WC_OWNER_AUTHORIZATION"]))}
   else {XCTAssertThrowsError(try run());XCTAssertEqual(phases,["pin"]);XCTAssertTrue(requests.isEmpty)}
  }
  // Create-only API injection: production adapter uses SecItemAdd, never update.
  var adds=0
  for exists in [false,true] {XCTAssertNoThrow(try OwnerHTTPProvision.initialize(existing:exists ? key:nil,random:{Data(repeating:0x43,count:32)},add:{bytes in adds+=1;XCTAssertEqual(bytes.count,32)}))}
  XCTAssertEqual(adds,1)
  for ownerResult in [Data(),Data(repeating:1,count:31),Data(repeating:1,count:33)] {
   var executed=false
   XCTAssertThrowsError(try Launcher.runOwnerHTTP(configuration:fixtureConfiguration,serverURL:"http://127.0.0.1:9812/mcp",canonicalDBPath:launchDB.path,verify:{true},runtimeKey:{Data("synthetic-control".utf8)},ownerKey:{_,_ in ownerResult},execute:{_ in executed=true}))
   XCTAssertFalse(executed) // dev runtime file never substitutes owner native item.
  }
  for failure in ["missing","denied","locked"] {var executed=false
   XCTAssertThrowsError(try Launcher.runOwnerHTTP(configuration:fixtureConfiguration,serverURL:"http://127.0.0.1:9812/mcp",canonicalDBPath:launchDB.path,verify:{true},runtimeKey:{Data("synthetic-control".utf8)},ownerKey:{_,_ in throw NSError(domain:failure,code:1)},execute:{_ in executed=true}))
   XCTAssertFalse(executed)
  }
  for url in ["http://localhost:9812/mcp","http://0.0.0.0:9812/mcp","http://192.0.2.1/mcp","https://127.0.0.1/mcp","http://user:pass@127.0.0.1/mcp","http://127.0.0.1/mcp?secret=x","http://127.0.0.1/mcp#fragment"] {
   var reads=0
   XCTAssertThrowsError(try Launcher.runOwnerHTTP(configuration:fixtureConfiguration,serverURL:url,canonicalDBPath:launchDB.path,verify:{true},runtimeKey:{reads+=1;return Data()},ownerKey:{_,_ in reads+=1;return key},execute:{_ in XCTFail("invalid URL executed")}));XCTAssertEqual(reads,0)
  }
  // Invalid DB path is a separate negative, never a positive launch fixture.
  var invalidPathReads=0
  XCTAssertThrowsError(try Launcher.runOwnerHTTP(configuration:fixtureConfiguration,serverURL:"http://127.0.0.1:9812/mcp",canonicalDBPath:fixtureRoot.appendingPathComponent("absent.db").path,verify:{true},runtimeKey:{invalidPathReads+=1;return Data()},ownerKey:{_,_ in invalidPathReads+=1;return key},execute:{_ in XCTFail("missing DB executed")}))
  XCTAssertEqual(invalidPathReads,0)
  // Existing but unrelated DB must not select an arbitrary owner account.
  let otherDB=fixtureRoot.appendingPathComponent("other.db");try Data("synthetic".utf8).write(to:otherDB)
  var mismatchedPathReads=0
  XCTAssertThrowsError(try Launcher.runOwnerHTTP(configuration:fixtureConfiguration,serverURL:"http://127.0.0.1:9812/mcp",canonicalDBPath:otherDB.path,verify:{true},runtimeKey:{mismatchedPathReads+=1;return Data()},ownerKey:{_,_ in mismatchedPathReads+=1;return key},execute:{_ in XCTFail("unrelated DB executed")}))
  XCTAssertEqual(mismatchedPathReads,0)
  XCTAssertThrowsError(try OwnerHTTPProvision.initialize(existing:Data([1]),random:{XCTFail("malformed existing item generated replacement");return key},add:{_ in XCTFail("malformed existing item overwritten")}))
  for count in [0,31,33] {XCTAssertThrowsError(try OwnerHTTPProvision.initialize(existing:nil,random:{Data(repeating:1,count:count)},add:{_ in XCTFail("short entropy stored")}))}
  let existing=key;var randomCalls=0
  try OwnerHTTPProvision.initialize(existing:existing,random:{randomCalls+=1;return Data()},add:{_ in XCTFail("existing item overwritten")});XCTAssertEqual(randomCalls,0)
  // Duplicate-add race must return failure and preserve prior item (no update seam).
  XCTAssertThrowsError(try OwnerHTTPProvision.initialize(existing:nil,random:{key},add:{_ in throw NSError(domain:"duplicate-item",code:-25299)}))
  let dir=fm.temporaryDirectory.appendingPathComponent(UUID().uuidString);try fm.createDirectory(at:dir,withIntermediateDirectories:true);defer{try? fm.removeItem(at:dir)}
  let parent=dir.appendingPathComponent("Data With Spaces");try fm.createDirectory(at:parent,withIntermediateDirectories:true);let db=parent.appendingPathComponent("whatsapp.db");try Data("synthetic".utf8).write(to:db)
  let canonical=try expectedPOSIXPath(db.path);let expected=SHA256.hash(data:Data(canonical.utf8)).map{String(format:"%02x",$0)}.joined()
  let fileAlias=dir.appendingPathComponent("db-alias");let parentAlias=dir.appendingPathComponent("parent-alias");try fm.createSymbolicLink(at:fileAlias,withDestinationURL:db);try fm.createSymbolicLink(at:parentAlias,withDestinationURL:parent)
  for path in [db.path,fileAlias.path,parentAlias.appendingPathComponent("whatsapp.db").path]{XCTAssertEqual(try OwnerHTTPIdentity.account(forExistingDB:path),expected)}
  let missing=dir.appendingPathComponent("absent");let dangling=dir.appendingPathComponent("dangling");try fm.createSymbolicLink(at:dangling,withDestinationURL:missing);for path in [missing.path,dangling.path]{XCTAssertThrowsError(try OwnerHTTPIdentity.account(forExistingDB:path))}
 }

}
