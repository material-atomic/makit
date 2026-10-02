# Notifications

**Command:** `makit notify`

makit can tell you when something happens — a ban, a critical score, a scheduled scan with findings — on Telegram,
Slack, Google Chat, Discord, Microsoft Teams, ntfy, any JSON webhook, or email. Channels live in
`/etc/makit/notify.yaml` (mode 600, because it holds tokens).

```bash
makit notify add telegram --name ops --token 123456:ABC… --chat-id -1001234567890
makit notify add slack --name team --url https://hooks.slack.com/services/… --min-level critical
makit notify add googlechat --url 'https://chat.googleapis.com/v1/spaces/…/messages?key=…&token=…'
makit notify add discord --url https://discord.com/api/webhooks/…
makit notify add teams --url https://…logic.azure.com/workflows/…     # a Teams "Workflows" webhook
makit notify add ntfy --url https://ntfy.sh/my-server-alerts [--token tk_…]
makit notify add webhook --url https://example.com/hook --header 'Authorization=Bearer …'
makit notify add email --smtp smtp.example.com:587 --from makit@example.com --to you@example.com \
  --username makit@example.com --password '…'
makit notify list
makit notify test [NAME]
makit notify remove NAME
```

- **Levels** — each channel has a `min_level` (info, low, medium, high, critical; default high). Send critical alerts to
  the phone and everything else to a team channel.
- **No floods** — an identical message to the same channel is sent once per 10 minutes.
- **Telegram** — create a bot with @BotFather for the token; add it to the group and read the chat id from
  `https://api.telegram.org/bot<TOKEN>/getUpdates`.
- **Email** — port 465 uses TLS from the start; other ports use STARTTLS when the server offers it.
- **Webhook** — receives the message as JSON: `{"title", "text", "level", "source", "host", "time"}`.

Scripts can send their own messages: `echo "disk 92%" | makit notify send --level high --title "disk"`.
