// Package notify sends makit alerts to chat and mail: Telegram, Slack, Google Chat, Discord, Microsoft Teams, ntfy,
// any JSON webhook, and email. Channels live in /etc/makit/notify.yaml (mode 600: it holds tokens).
package notify

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/smtp"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

var DefaultConfig = "/etc/makit/notify.yaml"

type Channel struct {
	Name     string            `yaml:"name"`
	Type     string            `yaml:"type"` // telegram slack googlechat discord teams ntfy webhook email
	URL      string            `yaml:"url,omitempty"`
	Token    string            `yaml:"token,omitempty"`   // telegram bot token, ntfy access token
	ChatID   string            `yaml:"chat_id,omitempty"` // telegram
	Headers  map[string]string `yaml:"headers,omitempty"` // webhook
	MinLevel string            `yaml:"min_level,omitempty"`
	SMTP     string            `yaml:"smtp,omitempty"` // host:port (465 = implicit TLS, else STARTTLS when offered)
	Username string            `yaml:"username,omitempty"`
	Password string            `yaml:"password,omitempty"`
	From     string            `yaml:"from,omitempty"`
	To       []string          `yaml:"to,omitempty"`
}

type Config struct {
	Channels []Channel `yaml:"channels"`
}

// Message is one alert. Level is info, low, medium, high or critical.
type Message struct {
	Title  string    `json:"title"`
	Text   string    `json:"text"`
	Level  string    `json:"level"`
	Source string    `json:"source"` // shield, scan, analyze, test
	Host   string    `json:"host"`
	Time   time.Time `json:"time"`
}

var levels = map[string]int{"info": 0, "normal": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

var Types = []string{"telegram", "slack", "googlechat", "discord", "teams", "ntfy", "webhook", "email"}

func Load(path string) (*Config, error) {
	c := &Config{}
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return c, nil
	}
	if err != nil {
		return nil, err
	}
	if err := yaml.Unmarshal(b, c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	for _, ch := range c.Channels {
		if err := ch.validate(); err != nil {
			return nil, fmt.Errorf("%s: channel %q: %w", path, ch.Name, err)
		}
	}
	return c, nil
}

func (c *Config) Save(path string) error {
	b, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append([]byte("# makit notifications — holds tokens: keep mode 600. Guide: makit docs notifications\n"), b...), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (ch Channel) validate() error {
	if ch.Name == "" {
		return fmt.Errorf("name required")
	}
	if _, ok := levels[firstNonEmpty(ch.MinLevel, "info")]; !ok {
		return fmt.Errorf("min_level %q: info, low, medium, high or critical", ch.MinLevel)
	}
	switch ch.Type {
	case "telegram":
		if ch.Token == "" || ch.ChatID == "" {
			return fmt.Errorf("telegram needs token and chat_id")
		}
	case "slack", "googlechat", "discord", "teams", "ntfy", "webhook":
		if !strings.HasPrefix(ch.URL, "https://") && !strings.HasPrefix(ch.URL, "http://") {
			return fmt.Errorf("%s needs url", ch.Type)
		}
	case "email":
		if ch.SMTP == "" || ch.From == "" || len(ch.To) == 0 {
			return fmt.Errorf("email needs smtp, from and to")
		}
	default:
		return fmt.Errorf("type %q: one of %s", ch.Type, strings.Join(Types, ", "))
	}
	return nil
}

var client = &http.Client{Timeout: 15 * time.Second}

// dedupe drops an identical message to the same channel within 10 minutes.
var (
	dmu  sync.Mutex
	seen = map[string]time.Time{}
)

func duplicate(ch Channel, m Message) bool {
	h := sha256.Sum256([]byte(ch.Name + "\x00" + m.Title + "\x00" + m.Text))
	k := hex.EncodeToString(h[:8])
	dmu.Lock()
	defer dmu.Unlock()
	if t, ok := seen[k]; ok && time.Since(t) < 10*time.Minute {
		return true
	}
	seen[k] = time.Now()
	for kk, t := range seen {
		if time.Since(t) > time.Hour {
			delete(seen, kk)
		}
	}
	return false
}

// Send delivers m to every channel whose min_level it reaches (or only to the named one). It returns one error per
// failed channel; delivery to the others continues.
func (c *Config) Send(m Message, only string) []error {
	if m.Time.IsZero() {
		m.Time = time.Now()
	}
	if m.Host == "" {
		m.Host, _ = os.Hostname()
	}
	var errs []error
	for _, ch := range c.Channels {
		if only != "" && ch.Name != only {
			continue
		}
		if only == "" && levels[m.Level] < levels[firstNonEmpty(ch.MinLevel, "info")] {
			continue
		}
		if only == "" && duplicate(ch, m) {
			continue
		}
		if err := ch.send(m); err != nil {
			errs = append(errs, fmt.Errorf("%s (%s): %w", ch.Name, ch.Type, err))
		}
	}
	return errs
}

// SendTo is Send restricted to the named channels (all channels when names is empty); levels and duplicate
// suppression apply as for Send.
func (c *Config) SendTo(m Message, names []string) []error {
	if len(names) == 0 {
		return c.Send(m, "")
	}
	want := map[string]bool{}
	for _, n := range names {
		want[n] = true
	}
	sub := &Config{}
	for _, ch := range c.Channels {
		if want[ch.Name] {
			sub.Channels = append(sub.Channels, ch)
		}
	}
	return sub.Send(m, "")
}

var icon = map[string]string{"critical": "🚨", "high": "🔴", "medium": "🟠", "low": "🟡", "info": "ℹ️", "normal": "ℹ️"}

func plain(m Message) string {
	return fmt.Sprintf("%s [%s] %s · %s\n%s", icon[m.Level], strings.ToUpper(m.Level), m.Title, m.Host, m.Text)
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-20] + "\n… (truncated)"
}

func (ch Channel) send(m Message) error {
	switch ch.Type {
	case "telegram":
		return postJSON(fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", ch.Token), nil,
			map[string]any{"chat_id": ch.ChatID, "text": clip(plain(m), 4000), "disable_web_page_preview": true})
	case "slack":
		return postJSON(ch.URL, nil, map[string]any{"text": clip(fmt.Sprintf("%s *[%s] %s* · %s\n```%s```", icon[m.Level], strings.ToUpper(m.Level), m.Title, m.Host, m.Text), 39000)})
	case "googlechat":
		return postJSON(ch.URL, nil, map[string]any{"text": clip(fmt.Sprintf("%s *[%s] %s* · %s\n```\n%s\n```", icon[m.Level], strings.ToUpper(m.Level), m.Title, m.Host, m.Text), 4000)})
	case "discord":
		return postJSON(ch.URL, nil, map[string]any{"content": clip(fmt.Sprintf("%s **[%s] %s** · %s\n```\n%s\n```", icon[m.Level], strings.ToUpper(m.Level), m.Title, m.Host, m.Text), 1990)})
	case "teams": // Teams Workflows ("When a Teams webhook request is received") expects an Adaptive Card message.
		card := map[string]any{"$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "type": "AdaptiveCard", "version": "1.4",
			"body": []any{
				map[string]any{"type": "TextBlock", "weight": "Bolder", "wrap": true, "text": fmt.Sprintf("%s [%s] %s · %s", icon[m.Level], strings.ToUpper(m.Level), m.Title, m.Host)},
				map[string]any{"type": "TextBlock", "wrap": true, "fontType": "Monospace", "text": clip(m.Text, 20000)},
			}}
		return postJSON(ch.URL, nil, map[string]any{"type": "message", "attachments": []any{map[string]any{"contentType": "application/vnd.microsoft.card.adaptive", "content": card}}})
	case "ntfy":
		req, _ := http.NewRequest("POST", ch.URL, strings.NewReader(clip(m.Text, 3900)))
		req.Header.Set("Title", fmt.Sprintf("[%s] %s · %s", strings.ToUpper(m.Level), m.Title, m.Host))
		req.Header.Set("Priority", map[string]string{"critical": "5", "high": "4", "medium": "3"}[m.Level])
		req.Header.Set("Tags", "shield")
		if ch.Token != "" {
			req.Header.Set("Authorization", "Bearer "+ch.Token)
		}
		return do(req)
	case "webhook":
		return postJSON(ch.URL, ch.Headers, m)
	case "email":
		return ch.mail(m)
	}
	return fmt.Errorf("unknown type %s", ch.Type)
}

func postJSON(url string, headers map[string]string, body any) error {
	b, _ := json.Marshal(body)
	req, err := http.NewRequest("POST", url, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return do(req)
}

func do(req *http.Request) error {
	req.Header.Set("User-Agent", "makit-notify")
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(res.Body, 300))
		return fmt.Errorf("%s: %s", res.Status, strings.TrimSpace(string(b)))
	}
	return nil
}

func (ch Channel) mail(m Message) error {
	host, port, err := net.SplitHostPort(ch.SMTP)
	if err != nil {
		return err
	}
	subject := fmt.Sprintf("[makit %s] %s · %s", strings.ToUpper(m.Level), m.Title, m.Host)
	msg := "From: " + ch.From + "\r\nTo: " + strings.Join(ch.To, ", ") + "\r\nSubject: " + subject +
		"\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n" + strings.ReplaceAll(m.Text, "\n", "\r\n") + "\r\n"
	var auth smtp.Auth
	if ch.Username != "" {
		auth = smtp.PlainAuth("", ch.Username, ch.Password, host)
	}
	if port != "465" {
		return smtp.SendMail(ch.SMTP, auth, ch.From, ch.To, []byte(msg)) // STARTTLS when the server offers it
	}
	conn, err := tls.Dial("tcp", ch.SMTP, &tls.Config{ServerName: host})
	if err != nil {
		return err
	}
	c, err := smtp.NewClient(conn, host)
	if err != nil {
		return err
	}
	defer c.Close()
	if auth != nil {
		if err := c.Auth(auth); err != nil {
			return err
		}
	}
	if err := c.Mail(ch.From); err != nil {
		return err
	}
	for _, t := range ch.To {
		if err := c.Rcpt(t); err != nil {
			return err
		}
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write([]byte(msg)); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}
