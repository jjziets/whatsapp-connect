import Darwin
import TunnelKeychainLauncher

// Only the native boundary is reachable from the release executable.
exit(NativeLauncher.run(arguments: Array(CommandLine.arguments.dropFirst())))
