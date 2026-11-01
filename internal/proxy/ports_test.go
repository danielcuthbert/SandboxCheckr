package proxy

import "testing"

// An allowed host is allowed for HTTPS and HTTP, not for every port: a CONNECT
// tunnel carries any protocol, so an open port list turns one allowed name
// into a general relay (SSH on 22, SMTP on 25).
func TestPortsDefaultToWeb(t *testing.T) {
	a, _ := NewAllowList([]string{"example.com"})
	for _, p := range []string{"443", "80"} {
		if !a.PermitsPort(p) {
			t.Errorf("port %s should be permitted by default", p)
		}
	}
	for _, p := range []string{"22", "25", "8080"} {
		if a.PermitsPort(p) {
			t.Errorf("port %s must not be permitted by default", p)
		}
	}
	a.Ports = []string{"22"}
	if !a.PermitsPort("22") || a.PermitsPort("443") {
		t.Error("explicit ports must replace the default set")
	}
}

func TestListenRefusesNonLoopback(t *testing.T) {
	s := NewServer(&AllowList{}, false, nil)
	if _, err := s.ListenOn("tcp", "0.0.0.0:0"); err == nil {
		t.Error("the proxy must refuse to bind a non-loopback address")
	}
}
