package detect

import (
	"testing"

	"github.com/danielcuthbert/sandboxcheckr/internal/model"
)

func TestParseKV(t *testing.T) {
	kv := parseKV("BITLOCKER=On\r\nSECUREBOOT=True\r\nVBS=2\r\nnoise\r\n")
	if kv["BITLOCKER"] != "On" || kv["SECUREBOOT"] != "True" || kv["VBS"] != "2" {
		t.Errorf("unexpected parse: %v", kv)
	}
}

func TestWindowsFindings(t *testing.T) {
	cases := []struct {
		f    model.PostureFinding
		want model.Status
	}{
		{bitLockerFinding("On"), model.StatusPass},
		{bitLockerFinding("Off"), model.StatusFail},
		{bitLockerFinding(""), model.StatusIndeterminate},
		{secureBootFinding("True"), model.StatusPass},
		{secureBootFinding("False"), model.StatusFail},
		{vbsFinding("2", "True"), model.StatusPass},
		{vbsFinding("2", "False"), model.StatusDegraded},
		{defenderFinding("False"), model.StatusFail},
		{cfaFinding("1"), model.StatusPass},
		{cfaFinding("0"), model.StatusDegraded},
		{smartAppControlFinding("1"), model.StatusPass},
		{uacFinding("0"), model.StatusFail},
		{windowsSandboxFinding("Enabled"), model.StatusPass},
	}
	for _, c := range cases {
		if c.f.Status != c.want {
			t.Errorf("%s (%s): got %s, want %s", c.f.ID, c.f.Raw, c.f.Status, c.want)
		}
	}
}
