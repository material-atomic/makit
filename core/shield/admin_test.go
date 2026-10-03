package shield

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The admin address is on this machine or its private network: an http_proxy set for downloads must never answer
// in the gate's place (it did — `makit shield status` then failed to parse the proxy's "forbidden").
func TestAdminClientNeverUsesAProxy(t *testing.T) {
	tr, ok := AdminClient(0).Transport.(*http.Transport)
	if !ok || tr.Proxy != nil {
		t.Fatalf("admin client transport %#v: want one with Proxy == nil", AdminClient(0).Transport)
	}
}

func TestAdminURL(t *testing.T) {
	for in, want := range map[string]string{
		"127.0.0.1:9180":  "http://127.0.0.1:9180/status",
		"172.17.0.1:9180": "http://172.17.0.1:9180/status",
		"0.0.0.0:9180":    "http://127.0.0.1:9180/status",
		":9180":           "http://127.0.0.1:9180/status",
		"[::]:9180":       "http://127.0.0.1:9180/status",
	} {
		if got := AdminURL(in, "/status"); got != want {
			t.Errorf("AdminURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPrivateOnlyNamesTheRefusedCaller(t *testing.T) {
	h := privateOnly(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("{}")) }))
	for addr, want := range map[string]int{"127.0.0.1:1": 200, "172.17.0.1:5555": 200, "10.0.3.4:1": 200, "[::1]:1": 200, "203.0.113.5:1234": 403} {
		r := httptest.NewRequest("GET", "/status", nil)
		r.RemoteAddr = addr
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != want {
			t.Errorf("%s: %d, want %d", addr, w.Code, want)
		}
		if want == 403 && !strings.Contains(w.Body.String(), addr) {
			t.Errorf("refusal %q does not name the caller %s", w.Body.String(), addr)
		}
	}
}

// A gate that answers something other than its JSON: the error says the status and the first line, not a JSON
// parse error about the letter 'o'.
func TestStatusSaysWhatAnsweredInstead(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer srv.Close()
	cfg := filepath.Join(t.TempDir(), "shield.yaml")
	if err := os.WriteFile(cfg, []byte("admin: "+strings.TrimPrefix(srv.URL, "http://")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := cmdStatus(cfg, nil)
	if err == nil || !strings.Contains(err.Error(), "403 Forbidden: forbidden") {
		t.Fatalf("cmdStatus error = %v, want it to say 403 Forbidden: forbidden", err)
	}
}
