//go:build !nochromium

package standard

import (
	"testing"

	"github.com/gotenberg/gotenberg/v8/pkg/gotenberg"
)

// TestChromiumModuleRegistered verifies that a default build (no build tags)
// still ships the Chromium module, i.e. that the "nochromium" opt-out did not
// change the upstream behavior.
func TestChromiumModuleRegistered(t *testing.T) {
	for _, desc := range gotenberg.GetModuleDescriptors() {
		if desc.ID == "chromium" {
			return
		}
	}

	t.Fatal("expected the 'chromium' module to be registered in a default build, but it is not")
}
