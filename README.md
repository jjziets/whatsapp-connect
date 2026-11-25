# WhatsApp Connect

**A self-hosted WhatsApp connector for Codex and ChatGPT / Dot.** Build it on your Mac and link your own WhatsApp account. It keeps an encrypted archive on your Mac so you can search chats and groups, read the surrounding conversation, and see what history has synced.

## What needs to stay running?

**Your Mac hosts the connector.** Keep it awake and online whenever you need live sync or a scheduled digest. Each person sets up their own copy and client connection. Your configured AI service receives the messages and other results returned by its tool calls.

| How you use it | What runs on your Mac |
| --- | --- |
| **ChatGPT / Dot**, including scheduled digests | Keep the WhatsApp Connect process and its private OpenAI tunnel running. The tunnel starts the connector in the setup below. You can close Codex once setup is complete. |
| **Codex or ChatGPT Work with the local desktop plugin** | Keep the desktop host running for interactive use. It starts the local connector when needed. |
| Claude Desktop and local Cowork | The local client starts the connector over stdio. |

Claude on the web, cloud Cowork, Grok and Grok Bot need a separate authenticated reader endpoint. See the [remote client setup status](docs/setup.md#cloud-cowork-grok-and-grok-bot).

## Get started with ChatGPT and Dot

This is a macOS source build. You can follow the steps in Terminal or open the repo in Codex and ask it to walk you through the setup.

1. [Download the source release](https://github.com/jjziets/whatsapp-connect/releases/latest) and [build it on your Mac](docs/setup.md#build-on-macos).
2. Run `./bin/whatsapp-connect login`. On your phone, go to **WhatsApp → Linked devices → Link a device** and scan the QR code. [Pair your account and check the archive](docs/setup.md#link-your-whatsapp-account).
3. [Register WhatsApp Connect in ChatGPT](docs/setup.md#connect-chatgpt-and-dot-through-a-private-tunnel) with your own Secure MCP Tunnel. Ask Dot to check the connection and find a message you recognise.
4. [Choose your groups and schedule digests in Dot](docs/dot-digests.md). The guide includes prompts for morning and evening digests and an optional Sunday planning edition.

For same-Mac use, see [local desktop plugin setup](docs/setup.md#install-the-local-desktop-plugin) or [Claude Desktop setup](docs/setup.md#claude-desktop-and-cowork-on-the-same-mac). This is a macOS source build. The Claude and Grok paths are documented against their supported MCP interfaces and await testing in those apps.

## What you can do

- Search direct chats and joined groups and read the messages around a match.
- Check sync progress and the available date range. WhatsApp decides which linked-device history is delivered.
- Keep a saved school-group selection for use in scheduled summaries.
- Enable owner-confirmed text and archived attachment forwarding on a compatible host. Review the exact recipient and content before approving the host's permission card.

The archive uses SQLCipher and macOS Keychain. Initial setup requires the WhatsApp phone and a QR scan. Downloads, native events and confirmed writes require additional owner setup. Local AI inference, Windows and Linux are outside the current tested setup.

## Source and notices

Original WhatsApp Connect additions are available under the [MIT Licence](LICENSE). Third-party code retains its own terms and notices.

WhatsApp Connect builds on [hansen1101/whatsapp-mcp-server](https://github.com/hansen1101/whatsapp-mcp-server). See the [pinned upstream revision](server/UPSTREAM.md), [upstream MIT notice](server/LICENSE), [SQLite driver licence](server/third_party/go-sqlite3/LICENSE) and [Whatsmeow patch provenance](server/sdkpatch/manifest.json). The [Whatsmeow patch](server/sdkpatch/cancellable-send.patch) is distributed under [MPL 2.0](server/sdkpatch/LICENSE).
