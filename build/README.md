# The LibreOffice-only image (`Dockerfile.bc`)

`build/Dockerfile.bc` is the only image this fork ships. It is built by
`.github/workflows/ci.yml` and pushed to `nexus.int.onebrief.tools/ob/gotenberg`.

It is upstream Gotenberg with the Chromium half removed: document conversion via
LibreOffice and the PDF engines still works exactly as before, but the container
holds no browser, fetches nothing from the network, and calls nothing back.

## What changed, and why each piece is there

| Concern                       | Mechanism                                                                                                                   |
| ----------------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| No browser in the binary      | `-tags nochromium` skips `pkg/standard/imports_chromium.go`, so the module is never registered                                |
| No browser in the image       | `build/scrub-chromium.sh` deletes the Chromium package from the extracted root filesystem, then the image is rebuilt `FROM scratch` |
| No Chromium CVEs in the scan  | The same script removes Chromium's package-database entry and its SPDX document, which is what Grype/Syft read                |
| No ingress of remote content  | `API_DISABLE_DOWNLOAD_FROM=true`                                                                                             |
| No egress back to the app     | `WEBHOOK_DISABLE=true`                                                                                                       |

### Why the image is rebuilt `FROM scratch`

Deleting files in a derived layer does not remove them from the image: the base
layer still ships the bytes and an overlay whiteout hides them. Scanners that
read the base layer still report the CVEs, and the image does not shrink. The
only way to actually drop Chromium from a base image we do not build is to
extract the root filesystem, scrub it, and reassemble a single flattened layer.

The cost of flattening is that the final stage inherits no configuration from
the base image. Every `ENV`, plus `USER`, `WORKDIR`, `EXPOSE` and `ENTRYPOINT`,
is therefore declared explicitly in `Dockerfile.bc`, and `scrub-chromium.sh`
fails the build if any path they point at is missing (`REQUIRED_PATHS`). A base
image change that would invalidate them breaks the build rather than producing
an image that starts and then fails on the first conversion.

The runtime user is pinned to `gotenberg` (uid/gid 1001), matching upstream. If
the base image already defines that user at a different uid, the build fails and
names the uid to pass as `--build-arg RUNTIME_UID=`.

Every binary in `REQUIRED_PATHS` except `tini` is one that Gotenberg itself
stats at startup, so the base image must already carry it or the current image
would not boot. `tini` is the exception: it is only referenced by the
`ENTRYPOINT`, and it is required here because that entrypoint is now declared
rather than inherited. If a future base image drops it, the build will say
`MISSING required path: /usr/bin/tini`; the fix is to drop `tini` from both
`REQUIRED_PATHS` and the `ENTRYPOINT`, and to make sure something else reaps the
zombie processes LibreOffice leaves behind (`docker run --init`, or a pod spec
with `shareProcessNamespace`).

## Verifying a build

```sh
IMAGE=nexus.int.onebrief.tools/ob/gotenberg:<tag>

# No Chromium module: no chromium-* flags, no /forms/chromium/* routes.
docker run --rm --entrypoint /usr/bin/gotenberg "$IMAGE" --help | grep -i chromium   # expect no match

# No Chromium on disk.
docker run --rm --entrypoint /usr/bin/gotenberg "$IMAGE" --help >/dev/null           # sanity: image starts
docker save "$IMAGE" | tar -t | grep -i chromium                                     # expect no match

# No Chromium in the SBOM, so no Chromium CVEs in the Anchore scan.
syft "$IMAGE" | grep -i chromium                                                     # expect no match
grype "$IMAGE"

# Conversion still works.
docker run --rm -p 3000:3000 "$IMAGE"
curl -F files=@sample.docx http://localhost:3000/forms/libreoffice/convert -o out.pdf
```

The startup banner lists the registered modules; `chromium` should not be among
them.

### If something misbehaves after a base image bump

Flattening means the base image's own `Config` block is dropped, so an
environment variable the base sets and this Dockerfile does not re-declare would
silently go missing. Compare the two:

```sh
docker inspect --format '{{json .Config.Env}}' \
  nexus.int.onebrief.tools/cgr.dev/onebrief.com/gotenberg:8.36.0 | tr ',' '\n'
docker inspect --format '{{json .Config.Env}}' \
  nexus.int.onebrief.tools/ob/gotenberg:<tag> | tr ',' '\n'
```

Anything present on the left and absent on the right belongs in the `ENV` block
of `Dockerfile.bc`. The same check on `.Config.Entrypoint`, `.Config.User` and
`.Config.WorkingDir` is worth doing once per base image bump.

## Reverting or relaxing parts of it

Each piece is independently reversible.

- Chromium back in the binary: `--build-arg GO_BUILD_TAGS=` (empty). The default
  `go build` with no tags is byte-for-byte upstream behavior, which is why
  `pkg/standard/imports.go` opts *out* with a tag rather than opting in.
- Webhook callbacks back on: set `WEBHOOK_DISABLE=false` in the deployment.
- Remote input fetching back on: set `API_DISABLE_DOWNLOAD_FROM=false`.

The last two are upstream flags, so they remain per-deployment overrides rather
than compile-time decisions.

## What this deliberately does not decide

Removing Chromium is an operational change: it shrinks the image and takes the
browser CVE stream off the board without changing what the service is for.
Whether Office previews stay in the product at all - that is, whether this
component is deleted outright rather than slimmed - is a separate, product-owned
call. Nothing here forecloses it, and nothing here makes it.
