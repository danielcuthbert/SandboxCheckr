package emit

import (
	"os"
	"testing"
)

// TestRenderDemo prints the sample report so the layout can be eyeballed:
//
//	go test ./internal/emit -run TestRenderDemo -v
func TestRenderDemo(t *testing.T) {
	if os.Getenv("SCR_DEMO") == "" {
		t.Skip("set SCR_DEMO=1 to print the sample report")
	}
	Terminal(os.Stdout, sampleReport(), Options{Color: true})
}
