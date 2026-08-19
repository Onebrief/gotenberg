//go:build nochromium

package standard

import (
	"testing"

	"github.com/gotenberg/gotenberg/v8/pkg/gotenberg"
)

// TestChromiumModuleNotRegistered verifies that a build tagged "nochromium"
// contains no Chromium module at all: no routes, no flags, and no way to spawn
// a browser process.
func TestChromiumModuleNotRegistered(t *testing.T) {
	for _, desc := range gotenberg.GetModuleDescriptors() {
		if desc.ID == "chromium" {
			t.Fatal("expected the 'chromium' module to be absent from a 'nochromium' build, but it is registered")
		}
	}
}

// TestLibreOfficeModulesRegistered verifies that removing Chromium did not take
// the LibreOffice conversion path with it.
func TestLibreOfficeModulesRegistered(t *testing.T) {
	want := map[string]bool{
		"libreoffice":           false,
		"libreoffice-api":       false,
		"libreoffice-pdfengine": false,
	}

	for _, desc := range gotenberg.GetModuleDescriptors() {
		if _, ok := want[desc.ID]; ok {
			want[desc.ID] = true
		}
	}

	for id, found := range want {
		if !found {
			t.Errorf("expected the '%s' module to be registered, but it is not", id)
		}
	}
}
