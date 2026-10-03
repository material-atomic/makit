package shield

import (
	"net/http/httptest"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestKubernetesSnippetsAreValidYAML(t *testing.T) {
	o := snippetOpts{service: "makit-shield", namespace: "makit", port: 9180, gateway: "web", gatewayNS: "apps",
		addr: "makit-shield.makit.svc.cluster.local:9180"}
	for _, kind := range []string{"envoy-gateway", "istio", "envoy", "traefik", "ingress-nginx"} {
		s, ok := k8sSnippet(kind, o)
		if !ok {
			t.Fatalf("%s: no snippet", kind)
		}
		dec := yaml.NewDecoder(strings.NewReader(s))
		docs := 0
		for {
			var v any
			if err := dec.Decode(&v); err != nil {
				if err.Error() != "EOF" {
					t.Errorf("%s: not valid YAML: %v\n%s", kind, err, s)
				}
				break
			}
			docs++
		}
		if docs == 0 {
			t.Errorf("%s: empty", kind)
		}
		// A gateway that sends only listed headers must get every header makit reads.
		if kind == "envoy-gateway" || kind == "istio" || kind == "envoy" {
			for _, h := range askHeaders {
				if !strings.Contains(s, h) {
					t.Errorf("%s: header %s is not passed to makit", kind, h)
				}
			}
		}
	}
}

// What each proxy sends must reach the decision as the visitor's request.
func TestAskedRequestFromEachProxy(t *testing.T) {
	cases := []struct {
		name               string
		target             string
		host               string
		hdr                map[string]string
		method, uri, wantH string
	}{
		{"Caddy/Traefik", "/check", "127.0.0.1:9180", map[string]string{"X-Forwarded-Method": "POST", "X-Forwarded-Uri": "/login?a=1",
			"X-Forwarded-Host": "shop.example"}, "POST", "/login?a=1", "shop.example"},
		{"ingress-nginx", "/check?deny=403", "makit-shield.makit.svc.cluster.local:9180", map[string]string{"X-Original-Method": "GET",
			"X-Original-URL": "https://shop.example/.env?x=1"}, "GET", "/.env?x=1", "shop.example"},
		{"Envoy ext_authz", "/check/wp-login.php?redirect=1", "shop.example", nil, "GET", "/wp-login.php?redirect=1", "shop.example"},
		{"Envoy, root path", "/check", "shop.example", nil, "GET", "/", "shop.example"},
	}
	for _, c := range cases {
		r := httptest.NewRequest("GET", "http://"+c.host+c.target, nil)
		r.Host = c.host
		for k, v := range c.hdr {
			r.Header.Set(k, v)
		}
		m, u, h := askedRequest(r)
		if m != c.method || u != c.uri || h != c.wantH {
			t.Errorf("%s: %s %s %s, want %s %s %s", c.name, m, u, h, c.method, c.uri, c.wantH)
		}
	}
	// End to end through the handler: Envoy asks about a probe on the visitor's path, and it is blocked.
	g := askingGate(t)
	r := httptest.NewRequest("GET", "http://shop.example/check/.git/config", nil)
	r.RemoteAddr = "10.0.3.4:5000"
	r.Header.Set("X-Makit-Peer", "203.0.113.90")
	w := httptest.NewRecorder()
	g.checkHandler().ServeHTTP(w, r)
	if w.Code != 403 {
		t.Errorf("Envoy-style probe: %d", w.Code)
	}
}
