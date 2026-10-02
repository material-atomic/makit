# Bots, crawlers and AI agents

**Rules:** MK-BOTS (known bots), MK-SCORE-BOTS (bot score) · **Command:** `makit shield bots`

Not every bot is an attacker, and not every bot is welcome. Search engines bring visitors; link previews make your
pages look right in Telegram or Slack; AI assistants fetch a page because a person asked about it; AI training
crawlers copy the whole site; scrapers and headless browsers may be your competitor's price checker. Whether each of
these may in is your decision — makit identifies them, checks that they are who they claim to be, and applies your
policy.

## How makit recognises a bot

1. **Known agents** — [`security/bots/agents.yaml`](../../security/bots/agents.yaml) lists bots by User-Agent (or
   by header, for AI agents that sign their requests with *Web Bot Auth*), grouped in categories:

   | Category | Examples | Default |
   | --- | --- | --- |
   | `search` | Googlebot, Bingbot, Applebot, coccocbot, YandexBot | allow |
   | `ai-search` | OAI-SearchBot, Claude-SearchBot, PerplexityBot | allow |
   | `ai-assistant` | ChatGPT-User, Claude-User, Perplexity-User | allow |
   | `ai-crawler` | GPTBot, ClaudeBot, CCBot, Bytespider, meta-externalagent | log |
   | `ai-agent` | ChatGPT agent and other signed agents | log |
   | `seo` | AhrefsBot, SemrushBot, MJ12bot, GoesBot | log |
   | `social` | facebookexternalhit, Twitterbot, TelegramBot, Slackbot | allow |
   | `monitoring` | UptimeRobot, Pingdom, Uptime Kuma | allow |
   | `feed`, `archive` | Feedly, Internet Archive | allow, log |
   | `webhook` | goes.vn webhooks | log |
   | `library` | curl, python-requests, Go-http-client, axios | log |
   | `headless` | HeadlessChrome, PhantomJS | log |
   | `other-bot` | anything else that calls itself a bot | log |

   The catalog favours no one: every crawler, makit's sister product GoesBot included, gets its category's default
   until you decide otherwise (`makit shield bots set goesbot allow`, or `block`).

2. **Verification** — anyone can send `User-Agent: Googlebot`. For operators that make it possible, makit checks:
   - the IP is in the ranges the operator publishes (Google, Bing, Apple, OpenAI, Perplexity, DuckDuckGo,
     Common Crawl), downloaded daily into `/var/lib/makit/shield/bots/`, or
   - forward-confirmed reverse DNS: the IP's name ends in the operator's domain (`googlebot.com`, `search.msn.com`,
     `applebot.apple.com`, `yandex.ru`…) and that name resolves back to the same IP.

   The result is `verified`, `spoofed` (claims to be a verifiable bot and is not), `claimed` (the operator offers no
   way to verify), `pending` (the DNS answer is on its way — requests never wait for it) or `unknown` (DNS failed, or
   ranges not downloaded yet). A spoofed bot gets the `spoofed` policy (block by default).

3. **Bot score** — clients that do not say they are bots are scored by
   [`security/scoring/bots.yaml`](../../security/scoring/bots.yaml): no User-Agent, a User-Agent that is not a
   browser, automation markers, missing `Accept-Language` / `Accept` / `Accept-Encoding`, a Chrome User-Agent without
   the `sec-ch-ua` and `sec-fetch-*` headers Chrome always sends over HTTPS, many requests or 404s in a short window.
   Levels: suspect ≥30, likely ≥50, bot ≥80. All levels only log by default.

## What happens to a request

- A **verified** bot whose policy is `allow` goes straight through: no rules, no attack score. The real Googlebot
  follows every link it finds, including spam links full of `<script>` — it must not be banned for that.
- Any other known bot gets its policy (the agent's own, else its category's), then the normal rules and scoring.
- An unknown client gets the bot score, and its level's action.

Actions: `allow`, `log`, `block`, `ban <duration>` (`ban 24h`, `ban 7d`), `limit <N>/<window>` (`limit 60/1m`).
A limit on an agent counts all its IPs together (GPTBot crawls from many); a limit on a bot score level counts per
IP. Over the limit, the client gets `429 Too Many Requests` with `Retry-After` (in nginx ask mode a 403, because
nginx only passes 401/403 through).

## Your policy

```bash
makit shield bots                          # categories, actions, overrides
makit shield bots agents ai-crawler        # the agents in a category
makit shield bots set ai-crawler block     # no AI training on this site
makit shield bots set gptbot "limit 30/1m" # …but let GPTBot in slowly
makit shield bots set seo "ban 24h"
makit shield bots set score.bot "limit 60/1m"
makit shield bots unset gptbot             # back to the category's action
makit shield bots check --ua "Googlebot/2.1" --ip 66.249.66.1
makit shield bots robots                   # robots.txt lines for what you block
```

The same in `/etc/makit/shield.yaml`:

```yaml
bots:
  policy:
    ai-crawler: block
    gptbot: limit 30/1m
    spoofed: block
  score:
    actions: { likely: log, bot: "limit 60/1m" }
    disable: [robots-txt]        # bot score signals to ignore
  verify: true                   # reverse-DNS checks (off: only published ranges)
  # enabled: false               # no bot handling at all
```

Polite crawlers obey `robots.txt`, so publish what `makit shield bots robots` prints — it saves them the trip, and
makit still blocks the ones that ignore it. `Google-Extended` and `Applebot-Extended` only exist in robots.txt: they
opt your pages out of Gemini and Apple Intelligence training without affecting search.

## Your own IP sources

The operators' published ranges are downloaded for you. Add your own, from a URL refreshed on a schedule or typed by
hand — for a catalog agent (more ranges to verify it), or for a new agent of yours that is then recognised by IP alone,
whatever its User-Agent (a partner's crawler, your uptime monitor, your office):

```bash
makit shield bots source add https://partner.example/crawler-ips.txt --agent partner --category monitoring --every 6h
makit shield bots source add https://example.org/gptbot-extra.json --agent gptbot
makit shield bots ip add office-monitor 203.0.113.10 --category monitoring --name "Office monitor"
makit shield bots ip add gptbot 198.51.100.0/24
makit shield bots sources            # every feed: size, last download, errors
makit shield bots ips
makit shield bots update [AGENT]     # download now
makit shield bots source remove URL
makit shield bots ip remove gptbot 198.51.100.0/24
```

A feed can be JSON (the `{"prefixes":[{"ipv4Prefix":…}]}` shape the big operators use, or any JSON holding IPs and
CIDRs) or text with IPs/CIDRs (comments after `#` or `;`, CSV columns are fine). Each one is cached in
`/var/lib/makit/shield/bots/` and downloaded again when its interval (`--every`, default `bots.refresh: 24h`) is up;
a failed download keeps the previous copy and is retried after an hour. Ranges wider than /8 (IPv4) or /32 (IPv6)
are refused: a broken feed must not turn half the internet into a "verified" bot.

All ranges go into the same kind of set as the block list (a hash table per prefix length), so a lookup costs the
same with a hundred ranges or a few million. In `shield.yaml` this is:

```yaml
bots:
  refresh: 24h
  sources:
    - { agent: partner, category: monitoring, url: https://partner.example/crawler-ips.txt, every: 6h }
    - { agent: office-monitor, name: Office monitor, category: monitoring, ips: [203.0.113.10] }
    - { agent: gptbot, ips: [198.51.100.0/24], by_ip: true }   # by_ip: also recognise it without its User-Agent
```

## Your own lists

```bash
makit shield customize bots     # copies agents.yaml and scoring/bots.yaml to /etc/makit/security
```

Edit the copies: add your partners' crawlers, your own monitoring, a category of your own. They override the bundled
catalog, are never touched by `makit rules update`, and the running gate reloads them within two seconds. Or point to
files kept elsewhere: `bots: { file: /srv/ops/agents.yaml, score_file: /srv/ops/bot-score.yaml }`.

Know the limits: a determined scraper running a real browser from residential IPs looks like a person. The bot score
raises the cost of the cheap ones; rate limits keep the rest from hurting you.
