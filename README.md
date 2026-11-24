# WhatsApp Connect

Search your own WhatsApp history from an AI assistant. WhatsApp Connect is a self-hosted MCP server that keeps an encrypted archive on your Mac. It lets you find messages across chats and groups, read the surrounding conversation, and check what history has synced.

A school-group digest is one use. Save the groups you follow, ask your assistant to find dates and actions, and use the source messages to check the result. The connector supplies search and group context. The assistant manages its own schedule and notifications.

Each person runs their own copy, links their own WhatsApp account, and sets up their own client connection. The Mac needs to be awake and online for live syncing and remote access. Your conversation stays in your local archive until a tool returns relevant content to the AI service you configured.

| Client | How it connects |
| --- | --- |
| Claude Desktop and local Cowork | Local MCP over stdio using the Mac build. |
| ChatGPT / Dot | Local MCP with a compatible desktop plugin host, or a private OpenAI tunnel for a cloud connection. |
| Claude on the web, cloud Cowork, Grok and Grok Bot | Custom remote MCP over HTTPS. A separate authenticated reader endpoint is required for this deployment. |

## Get started with ChatGPT and Dot

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
