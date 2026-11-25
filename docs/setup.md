# Set up WhatsApp Connect

WhatsApp Connect runs on your Mac. Codex can help you build it and set up the client connection. You scan the pairing QR code from your own phone.

Choose the [private tunnel](#connect-chatgpt-and-dot-through-a-private-tunnel) for Dot and scheduled digests. Choose the [local desktop plugin](#install-the-local-desktop-plugin) for interactive use in Codex or ChatGPT Work on the Mac that hosts the connector.

## Build on macOS

Install Go 1.27.0 or a compatible newer version, Xcode command-line tools and Python 3.9 or later. Put the source in a directory whose path has no spaces, then run the following from that directory.

```sh
WC_BUILD_MODCACHE="$PWD/work/go-modules"
mkdir -p "$WC_BUILD_MODCACHE"
(
  cd server
  GOMODCACHE="$WC_BUILD_MODCACHE" GOWORK=off GOTOOLCHAIN=local \
    GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org go mod download all
)
scripts/server.sh build
./bin/whatsapp-connect version
```

Use the build wrapper to verify the SDK overlay and build with the pinned SQLCipher engine. It fetches build dependencies and generates a local executable under `bin/`.

## Link your WhatsApp account

1. Run `./bin/whatsapp-connect login` in Terminal. Keep this window open and the phone online.
2. Open **Linked devices → Link a device** in WhatsApp on your phone, then scan the QR code shown on your Mac.
3. Wait for the link to succeed and the initial sync to finish. The command exits after a quiet period. Run `./bin/whatsapp-connect status` to check the local archive. WhatsApp can deliver additional messages once the connector is running, and archive counts alone do not establish complete history.

Use `login --full-history` on the first link if you want to request more history from the phone. Already linked? Reuse the existing profile. The default is `~/Library/Application Support/WhatsApp Connect`. Pass the same `--data-dir` to the login and server commands if you use a different profile. Store the profile, QR code and media privately.

## Connect ChatGPT and Dot through a private tunnel

Use this path for Dot and scheduled cloud digests. It requires a ChatGPT workspace that allows custom MCP servers and access to an OpenAI Platform Secure MCP Tunnel.

1. Create a tunnel in [OpenAI Platform tunnel settings](https://platform.openai.com/settings/organization/tunnels). Associate the ChatGPT workspace where you want to install the plugin. Use a restricted runtime key with **Tunnels Read + Use**. Download the Mac `tunnel-client` from the [official source](https://github.com/openai/tunnel-client/releases/latest) and put it on your path.
2. Give the tunnel your built connector as its stdio command. Run from the source directory used above. Replace the example tunnel ID. Supply `CONTROL_PLANE_API_KEY` securely to the tunnel client from your credential manager, separate from this configuration. [OpenAI tunnel setup](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels)

   ```sh
   WC_TUNNEL_ID='tunnel_REPLACE_WITH_YOURS'
   tunnel-client init \
     --sample sample_mcp_stdio_local \
     --profile whatsapp-connect \
     --tunnel-id "$WC_TUNNEL_ID" \
     --mcp-command "$PWD/bin/whatsapp-connect serve --transport stdio --log-level warn"
   tunnel-client doctor --profile whatsapp-connect --explain
   tunnel-client run --profile whatsapp-connect
   ```

   The tunnel starts the connector child using the paired profile. For a custom profile, include its absolute path as a quoted `--data-dir` argument in the MCP command. One process owns live sync for each profile. If a local plugin already owns it, the tunnel child may open as a reader. For a new setup, close the local plugin first so the tunnel child can own the profile. If you already have an always-on owner and tunnel, reuse that connection.
3. With the tunnel running, open [ChatGPT Plugins](https://chatgpt.com/plugins), then choose **+ → Add custom MCP server**. Name it **WhatsApp Connect**. Under **Connection**, choose **Tunnel** and select your tunnel or enter its ID. Choose **No authentication** for this stdio server behind your scoped private tunnel. The tunnel client still authenticates to OpenAI with its restricted runtime key. Review the connection, choose **Create as a plugin**, then review the discovered tools and install the plugin in your account. [Register and test a custom MCP server](https://developers.openai.com/plugins/deploy/connect-chatgpt)
4. In a new Dot chat, ask it to call `whatsapp_status`, then search for a message you know is in the archive. Check that the status reports a connected, logged-in owner and that the result comes from the right chat. Review the available history and dates. If tools are stale, refresh the app's tools in ChatGPT and retry in a new chat.

Keep the Mac awake and online and the tunnel client running. If you started the tunnel in a foreground Terminal session, leave it running there. After restarting the Mac, check the tunnel and `whatsapp_status` before the next digest. You can close Codex after setup because Dot connects through the running tunnel. After the search works, [choose groups and schedule the digests](dot-digests.md).

## Install the local desktop plugin

Use this path for local ChatGPT Work or Codex on the Mac. The desktop host launches the connector when you use the plugin, so keep that host open for local use. Stage just the two manifests and the executable from the built source directory.

```sh
mkdir -p work/desktop-plugin/bin
cp plugin.json mcp.json work/desktop-plugin/
install -m 700 bin/whatsapp-connect work/desktop-plugin/bin/whatsapp-connect
```

Add the folder to your local plugin marketplace. With a repo marketplace at `.agents/plugins/marketplace.json`, set the local entry's `source.path` to `./work/desktop-plugin` relative to the repo root. Follow the [manual local install instructions](https://developers.openai.com/plugins/build/plugins#install-a-local-plugin-manually) to add the entry, keeping existing entries. Restart the desktop app, choose the marketplace in **Plugins**, install **WhatsApp Connect**, and check `whatsapp_status` in a new chat. Local desktop access is for interactive use. Use the private tunnel above for cloud schedules.

## Claude Desktop and Cowork on the same Mac

Merge this entry into `~/Library/Application Support/Claude/claude_desktop_config.json` and replace the example command with the absolute path to your built executable. Keep any existing entries. [MCP configuration reference](https://py.sdk.modelcontextprotocol.io/get-started/real-host/)

```json
{
  "mcpServers": {
    "whatsapp-connect": {
      "command": "/absolute/path/to/whatsapp-connect/bin/whatsapp-connect",
      "args": ["serve", "--transport", "stdio", "--log-level", "warn"]
    }
  }
}
```

Fully quit and reopen Claude Desktop. Open **+ → Connectors** in the chat composer to check that WhatsApp Connect is listed. The command uses the same default profile as pairing. If you paired into a different profile, pass `--data-dir` followed by its absolute path. If a service already owns the profile lock, the Claude process opens the archive as a reader. If the lock is free, the Claude process can become the sync owner. Keychain access is required from the process that opens the archive.

Ask Claude to call `whatsapp_status`, then search for a phrase you know is in your archive. Check the source chat and timestamp against the phone. The local server runs on your Mac and Claude can still process returned results through its cloud service. Claude documents desktop extensions and local MCP for Cowork running on your device. A distributable `.mcpb` extension can wrap this binary once that package is built and tested. [Local MCP setup](https://support.claude.com/en/articles/10949351-getting-started-with-local-mcp-servers-on-claude-desktop) · [Cowork and remote connectors](https://support.claude.com/en/articles/11175166-get-started-with-custom-connectors-using-remote-mcp)

## Cloud Cowork, Grok and Grok Bot

These clients can connect to a remote MCP URL. The release design is a dedicated Streamable HTTP reader over HTTPS, authenticated for the individual account. It should expose status, chat listing, message search, context and saved group reads. The server should both list and enforce those allowed tools. The current local owner endpoint serves the owner's permissions and is unsuitable as this reader endpoint. The shared reader endpoint and client sign-in are still development work.

Once the reader is available, add its URL and sign in to the connector:

| Client | Where to add it |
| --- | --- |
| Claude and cloud Cowork | **Customize → Connectors**. [Claude custom connectors](https://support.claude.com/en/articles/11175166-get-started-with-custom-connectors-using-remote-mcp) |
| Grok Bot | **Connect apps → Add a custom connector** in the desktop app. [Grok Bot custom connectors](https://docs.x.ai/grok-bot/computer-and-apps) |
| Grok | **Connectors → New Connector → Custom**. [Grok connectors](https://docs.x.ai/grok/connectors) |
| An app built with xAI's API | Add the MCP URL and a limited credential to the app's server-side tool configuration. [xAI Remote MCP](https://docs.x.ai/developers/tools/remote-mcp) |

Check the connection as the intended user. Confirm it can search known archive content, rejects missing credentials and leaves send, forwarding and monitoring controls unavailable. Each person sets up their own reader URL and access. Grok Bot connectors can be available to multiple Bots on the same account. Check which Bots can access a connector before enabling it for a private archive. For recurring summaries, verify a read request first, then use the client's own schedule or routine against the selected groups. [Grok Bot app access](https://docs.x.ai/grok-bot/computer-and-apps)
