# Early SQLCipher key hook

Source: github.com/mattn/go-sqlite3 v1.14.52, verified Go module cache. MIT license preserved in LICENSE. Only production source and module files are included; upstream tests are not duplicated.

Local change: add SQLiteDriver.PreConnectHook and call it immediately after allocation of SQLiteConn and its error cleanup, before any initialization PRAGMAs can read encrypted pages. Existing ConnectHook semantics remain unchanged. No cryptography is implemented or altered here.

Reason: a native SQLCipher 4.20.0 probe proved the existing late ConnectHook can create an encrypted database but cannot reopen it (file is not a database), because initialization PRAGMAs read pages before the key is applied. The new hook is exercised by the securestore encrypted create/close/reopen, wrong-key, WAL and retained MCP tests. The stock bundled SQLite build is retained solely for the explicit fail-closed negative lane.

Use the project's build script and libsqlite3 tag to link the pinned official SQLCipher static library. Builds with a stock SQLite engine must reject secure opens at runtime. This directory is externally owned source plus a documented minimal adapter patch; matrix provenance replaces injected TraceWeaver comments throughout imported source.
