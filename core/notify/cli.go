package notify

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
)

const usage = `makit notify — alerts to Telegram, Slack, Google Chat, Discord, Microsoft Teams, ntfy, webhooks and email

  list
  add TYPE --name NAME [--min-level high] TYPE OPTIONS
      telegram   --token BOT_TOKEN --chat-id CHAT_ID
      slack | googlechat | discord | teams | ntfy | webhook   --url URL   (ntfy: [--token T]; webhook: [--header K=V]…)
      email      --smtp host:587 --from a@x --to b@y[,c@z] [--username U --password P]
  remove NAME
  test [NAME]                   send a test message (to every channel, or one)
  send --level LEVEL --title TEXT [--source S] (text from stdin)
`

// Main is `makit-core notify …`.
func Main(args []string) int {
	path := os.Getenv("MAKIT_NOTIFY_CONFIG")
	if path == "" {
		path = DefaultConfig
	}
	if len(args) == 0 {
		fmt.Print(usage)
		return 2
	}
	var err error
	switch args[0] {
	case "list":
		err = list(path)
	case "add":
		err = add(path, args[1:])
	case "remove":
		err = removeCh(path, args[1:])
	case "test":
		only := ""
		if len(args) > 1 {
			only = args[1]
		}
		err = send(path, Message{Title: "makit test message", Text: "If you can read this, makit can reach this channel.", Level: "info", Source: "test"}, only, true)
	case "send":
		err = sendCmd(path, args[1:])
	case "help", "--help", "-h":
		fmt.Print(usage)
	default:
		fmt.Fprint(os.Stderr, usage)
		return 2
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "makit notify:", err)
		return 1
	}
	return 0
}

func list(path string) error {
	c, err := Load(path)
	if err != nil {
		return err
	}
	if len(c.Channels) == 0 {
		fmt.Println("no channels (makit notify add …)")
	}
	for _, ch := range c.Channels {
		target := ch.URL
		switch ch.Type {
		case "telegram":
			target = "chat " + ch.ChatID
		case "email":
			target = strings.Join(ch.To, ", ")
		}
		if i := strings.Index(target, "?"); i > 0 {
			target = target[:i] + "?…" // hide webhook keys
		}
		fmt.Printf("  %-18s %-11s %-9s %s\n", ch.Name, ch.Type, firstNonEmpty(ch.MinLevel, "info"), target)
	}
	return nil
}

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

func add(path string, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("add TYPE --name NAME …")
	}
	ch := Channel{Type: args[0]}
	fs := flag.NewFlagSet("add", flag.ContinueOnError)
	fs.StringVar(&ch.Name, "name", args[0], "channel name")
	fs.StringVar(&ch.MinLevel, "min-level", "high", "info, low, medium, high, critical")
	fs.StringVar(&ch.URL, "url", "", "webhook URL")
	fs.StringVar(&ch.Token, "token", "", "bot/access token")
	fs.StringVar(&ch.ChatID, "chat-id", "", "telegram chat id")
	fs.StringVar(&ch.SMTP, "smtp", "", "smtp host:port")
	fs.StringVar(&ch.Username, "username", "", "smtp user")
	fs.StringVar(&ch.Password, "password", "", "smtp password")
	fs.StringVar(&ch.From, "from", "", "sender")
	to := fs.String("to", "", "recipients, comma-separated")
	var hdr multi
	fs.Var(&hdr, "header", "webhook header K=V (repeatable)")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *to != "" {
		ch.To = strings.Split(*to, ",")
	}
	for _, h := range hdr {
		k, v, ok := strings.Cut(h, "=")
		if !ok {
			return fmt.Errorf("--header %q: use K=V", h)
		}
		if ch.Headers == nil {
			ch.Headers = map[string]string{}
		}
		ch.Headers[k] = v
	}
	if err := ch.validate(); err != nil {
		return err
	}
	c, err := Load(path)
	if err != nil {
		return err
	}
	for i, x := range c.Channels {
		if x.Name == ch.Name {
			c.Channels = append(c.Channels[:i], c.Channels[i+1:]...)
			break
		}
	}
	c.Channels = append(c.Channels, ch)
	if err := c.Save(path); err != nil {
		return err
	}
	fmt.Printf("channel %s (%s) saved — try it: makit notify test %s\n", ch.Name, ch.Type, ch.Name)
	return nil
}

func removeCh(path string, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("remove NAME")
	}
	c, err := Load(path)
	if err != nil {
		return err
	}
	for i, x := range c.Channels {
		if x.Name == args[0] {
			c.Channels = append(c.Channels[:i], c.Channels[i+1:]...)
			fmt.Printf("channel %s removed\n", args[0])
			return c.Save(path)
		}
	}
	return fmt.Errorf("no channel named %s", args[0])
}

func send(path string, m Message, only string, verbose bool) error {
	c, err := Load(path)
	if err != nil {
		return err
	}
	if len(c.Channels) == 0 {
		return fmt.Errorf("no channels configured")
	}
	errs := c.Send(m, only)
	for _, e := range errs {
		fmt.Fprintln(os.Stderr, "  ✗", e)
	}
	if verbose && len(errs) == 0 {
		fmt.Println("sent")
	}
	if len(errs) > 0 {
		return fmt.Errorf("%d channel(s) failed", len(errs))
	}
	return nil
}

func sendCmd(path string, args []string) error {
	fs := flag.NewFlagSet("send", flag.ContinueOnError)
	level := fs.String("level", "info", "level")
	title := fs.String("title", "makit", "title")
	source := fs.String("source", "cli", "source")
	if err := fs.Parse(args); err != nil {
		return err
	}
	b, _ := io.ReadAll(bufio.NewReader(os.Stdin))
	return send(path, Message{Title: *title, Text: strings.TrimSpace(string(b)), Level: *level, Source: *source}, "", false)
}
