package shield

import (
	"fmt"
	"strings"
)

// Ready-made setups for proxies and gateways in Kubernetes that ask makit before every request (ask mode). Each one
// sends makit the headers its rules and scores read: without them a browser would look like a script.

// askHeaders are the request headers makit reads; a gateway that sends only the headers it is told to must send these.
var askHeaders = []string{"x-forwarded-for", "user-agent", "referer", "accept", "accept-encoding", "accept-language",
	"sec-ch-ua", "sec-fetch-mode", "next-action", "signature", "signature-input", "signature-agent",
	"forwarded", "x-real-ip", "cf-ipcountry", "cf-ray", "x-forwarded-proto"}

type snippetOpts struct {
	addr, service, namespace, gateway, gatewayNS string
	port                                         int
}

func (o snippetOpts) svcHost() string {
	return fmt.Sprintf("%s.%s.svc.cluster.local", o.service, o.namespace)
}

func k8sSnippet(kind string, o snippetOpts) (string, bool) {
	switch kind {
	case "envoy-gateway":
		var hs strings.Builder
		for _, h := range askHeaders {
			fmt.Fprintf(&hs, "        - %s\n", h)
		}
		return fmt.Sprintf(`# Envoy Gateway (Gateway API): every route of the Gateway asks makit first.
# The client IP: makit reads X-Forwarded-For from the right (trusted_proxies: [aws-alb] or your subnets in
# shield.yaml), so a visitor cannot choose its own.
apiVersion: gateway.envoyproxy.io/v1alpha1
kind: SecurityPolicy
metadata:
  name: makit-shield
  namespace: %[5]s
spec:
  targetRefs:
    - group: gateway.networking.k8s.io
      kind: Gateway
      name: %[4]s
  extAuth:
    failOpen: true            # makit unreachable: let traffic through rather than take the site down
    headersToExtAuth:         # by default ext auth only gets Host, Method, Path, Content-Length, Authorization
%[6]s    http:
      path: /check
      backendRefs:
        - name: %[1]s
          namespace: %[2]s
          port: %[3]d
      headersToBackend: [x-makit-client, x-makit-verdict]
---
# Lets the SecurityPolicy in %[5]s reach the makit Service in %[2]s.
apiVersion: gateway.networking.k8s.io/v1beta1
kind: ReferenceGrant
metadata:
  name: makit-shield-ext-auth
  namespace: %[2]s
spec:
  from:
    - group: gateway.envoyproxy.io
      kind: SecurityPolicy
      namespace: %[5]s
  to:
    - group: ""
      kind: Service
      name: %[1]s
`, o.service, o.namespace, o.port, o.gateway, o.gatewayNS, hs.String()), true
	case "istio":
		return fmt.Sprintf(`# Istio: 1) the provider, in the mesh config (istioctl / IstioOperator / the istio ConfigMap):
meshConfig:
  extensionProviders:
    - name: makit-shield
      envoyExtAuthzHttp:
        service: %[1]s
        port: %[2]d
        pathPrefix: /check
        includeRequestHeadersInCheck: [%[3]s]
        headersToUpstreamOnAllow: [x-makit-client, x-makit-verdict]
        failOpen: true
---
# 2) which workloads ask it (here: the ingress gateway).
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: makit-shield
  namespace: istio-system
spec:
  selector:
    matchLabels:
      istio: ingressgateway
  action: CUSTOM
  provider:
    name: makit-shield
  rules:
    - {}
`, o.svcHost(), o.port, strings.Join(askHeaders, ", ")), true
	case "envoy":
		var hs strings.Builder
		for _, h := range askHeaders {
			fmt.Fprintf(&hs, "              - exact: %s\n", h)
		}
		return fmt.Sprintf(`# Envoy: in the HTTP connection manager's http_filters, before envoy.filters.http.router.
- name: envoy.filters.http.ext_authz
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz
    failure_mode_allow: true
    http_service:
      server_uri: { uri: "http://%[1]s", cluster: makit_shield, timeout: 0.25s }
      path_prefix: /check
      authorization_request:
        allowed_headers:
          patterns:
%[2]s      authorization_response:
        allowed_upstream_headers:
          patterns: [{ exact: x-makit-client }, { exact: x-makit-verdict }]
# and a cluster named makit_shield pointing at %[1]s.
`, o.addr, hs.String()), true
	case "traefik":
		return fmt.Sprintf(`# Traefik (Kubernetes CRD): a middleware, then add it to each IngressRoute's middlewares
# (or traefik.ingress.kubernetes.io/router.middlewares: <namespace>-makit-shield@kubernetescrd on an Ingress).
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: makit-shield
spec:
  forwardAuth:
    address: http://%[1]s:%[2]d/check
    trustForwardHeader: true    # pass X-Forwarded-For on: makit reads it from the right
    authResponseHeaders: [X-Makit-Client, X-Makit-Verdict]
# Behind a load balancer, let Traefik keep the chain it appends to (static configuration):
#   entryPoints.websecure.forwardedHeaders.trustedIPs: [<load balancer subnets>]
`, o.svcHost(), o.port), true
	case "ingress-nginx":
		return fmt.Sprintf(`# ingress-nginx: on each Ingress (or in the controller ConfigMap as global-auth-url).
# Note: ingress-nginx is retired (no fixes after March 2026); Envoy Gateway is the Gateway API path.
metadata:
  annotations:
    nginx.ingress.kubernetes.io/auth-url: "http://%[1]s:%[2]d/check?deny=403"   # nginx passes only 401/403 on
    nginx.ingress.kubernetes.io/auth-response-headers: X-Makit-Client, X-Makit-Verdict
# Behind a load balancer, in the controller ConfigMap, so X-Forwarded-For keeps the chain makit reads from the right:
#   use-forwarded-headers: "true"
#   compute-full-forwarded-for: "true"
#   proxy-real-ip-cidr: <load balancer subnets>
`, o.svcHost(), o.port), true
	}
	return "", false
}
