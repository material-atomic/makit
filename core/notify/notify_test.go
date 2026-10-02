package notify

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestChannelsPayloadsLevelsAndDedupe(t *testing.T) {
	var mu sync.Mutex
	got := map[string]string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		got[r.URL.Path] = string(b) + "|" + r.Header.Get("Title") + "|" + r.Header.Get("X-Key")
		mu.Unlock()
	}))
	defer srv.Close()
	c := &Config{Channels: []Channel{
		{Name: "slack", Type: "slack", URL: srv.URL + "/slack", MinLevel: "high"},
		{Name: "gchat", Type: "googlechat", URL: srv.URL + "/gchat"},
		{Name: "discord", Type: "discord", URL: srv.URL + "/discord"},
		{Name: "teams", Type: "teams", URL: srv.URL + "/teams"},
		{Name: "ntfy", Type: "ntfy", URL: srv.URL + "/ntfy"},
		{Name: "hook", Type: "webhook", URL: srv.URL + "/hook", Headers: map[string]string{"X-Key": "k1"}},
		{Name: "quiet", Type: "slack", URL: srv.URL + "/quiet", MinLevel: "critical"},
	}}
	for _, ch := range c.Channels {
		if err := ch.validate(); err != nil {
			t.Fatal(err)
		}
	}
	m := Message{Title: "203.0.113.5 banned", Text: strings.Repeat("x", 5000), Level: "high", Source: "shield", Host: "web-1"}
	if errs := c.Send(m, ""); len(errs) != 0 {
		t.Fatal(errs)
	}
	if _, ok := got["/quiet"]; ok {
		t.Error("min_level critical channel received a high message")
	}
	if !strings.Contains(got["/slack"], `"text":`) || !strings.Contains(got["/gchat"], `"text":`) {
		t.Errorf("slack/gchat payloads: %s / %s", got["/slack"], got["/gchat"])
	}
	var d struct{ Content string }
	_ = json.Unmarshal([]byte(strings.Split(got["/discord"], "|")[0]), &d)
	if len(d.Content) > 2000 || !strings.Contains(d.Content, "truncated") {
		t.Errorf("discord limit: %d", len(d.Content))
	}
	if !strings.Contains(got["/teams"], "AdaptiveCard") {
		t.Errorf("teams payload: %s", got["/teams"])
	}
	if !strings.Contains(got["/ntfy"], "[HIGH] 203.0.113.5 banned · web-1") {
		t.Errorf("ntfy title: %s", got["/ntfy"])
	}
	if !strings.Contains(got["/hook"], `"source":"shield"`) || !strings.HasSuffix(got["/hook"], "|k1") {
		t.Errorf("webhook: %s", got["/hook"])
	}
	delete(got, "/slack")
	c.Send(m, "")
	if _, ok := got["/slack"]; ok {
		t.Error("duplicate message within 10 minutes was sent again")
	}
}

func TestValidateAndSave(t *testing.T) {
	bad := []Channel{{Name: "a", Type: "telegram"}, {Name: "b", Type: "slack"}, {Name: "c", Type: "email", SMTP: "x:25"},
		{Name: "d", Type: "pager"}, {Name: "e", Type: "slack", URL: "https://x", MinLevel: "urgent"}}
	for _, ch := range bad {
		if ch.validate() == nil {
			t.Errorf("%s accepted", ch.Name)
		}
	}
	p := filepath.Join(t.TempDir(), "notify.yaml")
	c := &Config{Channels: []Channel{{Name: "tg", Type: "telegram", Token: "1:x", ChatID: "-100"}}}
	if err := c.Save(p); err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(p)
	if st.Mode().Perm() != 0o600 {
		t.Errorf("mode %v (holds tokens)", st.Mode().Perm())
	}
	c2, err := Load(p)
	if err != nil || len(c2.Channels) != 1 || c2.Channels[0].ChatID != "-100" {
		t.Fatalf("load: %+v %v", c2, err)
	}
}
