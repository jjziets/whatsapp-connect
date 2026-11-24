# Imported evaluation baseline

Source: https://github.com/hansen1101/whatsapp-mcp-server
Revision: 275f6b809dfbc888fd20be9d7924ac9cb0691148
License: MIT, preserved in LICENSE.

The six Go source/test files and go.mod/go.sum were initially copied without changes. The untouched upstream suite passed on Go 1.27.0/darwin-arm64 before import. Subsequent local differences will integrate Keychain-backed encrypted storage before account pairing. No real account data is included.

Imported unchanged files are externally owned source and retain upstream attribution; traceability for them is file-level provenance rather than injected comments. Changed runtime entry points and newly authored security code require current REQ/TRACE/VER anchors and review.
