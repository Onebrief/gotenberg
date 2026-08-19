//go:build !nochromium

package standard

// The Chromium module is imported from its own file so that it may be compiled
// out of the binary entirely.
//
// Building with the "nochromium" build tag (go build -tags nochromium) skips
// this file: the module is then never registered, none of its routes
// (/forms/chromium/*) are mounted, none of its flags exist, and no Chromium
// process can ever be spawned. Building without the tag keeps the upstream
// behavior, so the default build stays identical to Gotenberg's.
//
// This is the mechanism behind the LibreOffice-only image built by
// build/Dockerfile.bc.
import _ "github.com/gotenberg/gotenberg/v8/pkg/modules/chromium"
