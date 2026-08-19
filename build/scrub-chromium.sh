#!/bin/sh
#
# scrub-chromium.sh - remove Chromium from an extracted Gotenberg root
# filesystem, and prepare that root filesystem for a flattened, LibreOffice-only
# image.
#
# This runs inside a BusyBox build stage, against a copy of the base image's
# root filesystem (see build/Dockerfile.bc). It deliberately does *not* run
# inside the base image itself: the Chainguard base is distroless, so it has no
# shell, and the final image is rebuilt "FROM scratch" from the scrubbed tree.
# That is what makes the removal an actual size reduction rather than an overlay
# whiteout - deleting files in a derived layer hides them but still ships them.
#
# The package manager database is the source of truth for what belongs to
# Chromium: we delete exactly the files the database attributes to the matched
# packages, then drop their entries from the database and from the per-package
# SBOM directory. Removing the database entries is what stops Grype/Syft from
# reporting Chromium CVEs - and because the files are gone too, that is an
# accurate report rather than a suppressed one.
#
# Environment variables (all optional, defaults shown in the assignments below):
#
#   ROOTFS            Directory holding the extracted root filesystem.
#   PKG_REGEX         POSIX ERE matching the package names to remove.
#   SWEEP_PATHS       Extra paths removed unconditionally, whether or not a
#                     package database claims them.
#   REQUIRED_PATHS    Paths that must still exist afterwards; the build fails if
#                     any is missing. This is the runtime contract of the image.
#   RUNTIME_USER      Name of the unprivileged user the image runs as.
#   RUNTIME_UID/GID   Numeric ids for that user, created if absent.
#   RUNTIME_HOME      Home directory for that user, created if absent.
#   ALLOW_REVERSE_DEPS
#                     Set to "true" to continue even if a surviving package
#                     declares a dependency on a removed one.

set -eu

ROOTFS="${ROOTFS:-/rootfs}"
PKG_REGEX="${PKG_REGEX:-^chromium(-.*)?$}"
SWEEP_PATHS="${SWEEP_PATHS:-/usr/bin/chromium /usr/bin/chromium-browser /usr/bin/chrome /usr/lib/chromium /usr/lib/chromium-browser /usr/lib64/chromium /usr/share/chromium /opt/chromium /opt/gotenberg/chromium-hyphen-data}"
REQUIRED_PATHS="${REQUIRED_PATHS:-}"
RUNTIME_USER="${RUNTIME_USER:-gotenberg}"
RUNTIME_UID="${RUNTIME_UID:-1001}"
RUNTIME_GID="${RUNTIME_GID:-1001}"
RUNTIME_HOME="${RUNTIME_HOME:-/home/gotenberg}"
ALLOW_REVERSE_DEPS="${ALLOW_REVERSE_DEPS:-false}"

WORK="$(mktemp -d)"

log() { echo "[scrub] $*"; }
die() {
	echo "[scrub] FATAL: $*" >&2
	exit 1
}

[ -d "$ROOTFS" ] || die "root filesystem '$ROOTFS' does not exist"

log "root filesystem size before: $(du -sh "$ROOTFS" | cut -f1)"

# ----------------------------------------------
# Locate the package databases.
# ----------------------------------------------
# Wolfi/Alpine (the Chainguard base) uses apk; the dpkg branch exists so that the
# same script also works if BASE_IMAGE is ever pointed at the Debian-based
# upstream Gotenberg image.

APK_DB=""
for candidate in "$ROOTFS/lib/apk/db/installed" "$ROOTFS/usr/lib/apk/db/installed"; do
	if [ -f "$candidate" ]; then
		APK_DB="$candidate"
		break
	fi
done

DPKG_DB=""
if [ -f "$ROOTFS/var/lib/dpkg/status" ]; then
	DPKG_DB="$ROOTFS/var/lib/dpkg/status"
fi

[ -n "$APK_DB" ] || [ -n "$DPKG_DB" ] ||
	die "found no apk or dpkg database under '$ROOTFS'; refusing to guess what Chromium owns"

# ----------------------------------------------
# Collect the packages to remove and the files they own.
# ----------------------------------------------

: >"$WORK/packages"
: >"$WORK/files"
: >"$WORK/dirs"

if [ -n "$APK_DB" ]; then
	log "reading apk database: ${APK_DB#"$ROOTFS"}"

	# An apk "installed" database is a sequence of blank-line separated stanzas
	# of "K:value" lines. P: is the package name, V: its version, F: a directory
	# and R: a file inside the directory named by the most recent F:.
	awk -v re="$PKG_REGEX" '
		{ k = substr($0, 1, 1); v = substr($0, 3) }
		k == "P" { sel = (v ~ re); if (sel) print "PKG\t" v }
		k == "F" { dir = v; if (sel) print "DIR\t/" v }
		k == "R" && sel { print "FILE\t/" dir "/" v }
		NF == 0 { sel = 0 }
	' "$APK_DB" >"$WORK/apk-entries"

	awk -F '\t' '$1 == "PKG" { print $2 }' "$WORK/apk-entries" >>"$WORK/packages"
	awk -F '\t' '$1 == "FILE" { print $2 }' "$WORK/apk-entries" >>"$WORK/files"
	awk -F '\t' '$1 == "DIR" { print $2 }' "$WORK/apk-entries" >>"$WORK/dirs"

	# A surviving package that depends on a removed one would be left broken.
	awk -v re="$PKG_REGEX" '
		{ k = substr($0, 1, 1); v = substr($0, 3) }
		k == "P" { cur = v; skip = (v ~ re) }
		k == "D" && !skip {
			n = split(v, deps, " ")
			for (i = 1; i <= n; i++) {
				d = deps[i]
				sub(/[<>=~].*$/, "", d)
				if (d ~ re) print cur " depends on " d
			}
		}
		NF == 0 { skip = 0 }
	' "$APK_DB" | sort -u >"$WORK/reverse-deps"
fi

if [ -n "$DPKG_DB" ]; then
	log "reading dpkg database: ${DPKG_DB#"$ROOTFS"}"

	awk -v re="$PKG_REGEX" '$1 == "Package:" && $2 ~ re { print $2 }' "$DPKG_DB" |
		sort -u >"$WORK/dpkg-packages"

	while read -r pkg; do
		[ -n "$pkg" ] || continue
		echo "$pkg" >>"$WORK/packages"
		for list in "$ROOTFS/var/lib/dpkg/info/$pkg.list" "$ROOTFS/var/lib/dpkg/info/$pkg:"*".list"; do
			[ -f "$list" ] || continue
			while read -r path; do
				[ -n "$path" ] || continue
				if [ -d "$ROOTFS$path" ] && [ ! -L "$ROOTFS$path" ]; then
					echo "$path" >>"$WORK/dirs"
				else
					echo "$path" >>"$WORK/files"
				fi
			done <"$list"
		done
	done <"$WORK/dpkg-packages"

	awk -v re="$PKG_REGEX" '
		$1 == "Package:" { cur = $2; skip = ($2 ~ re) }
		($1 == "Depends:" || $1 == "Pre-Depends:") && !skip {
			line = $0
			sub(/^[^:]*: */, "", line)
			n = split(line, deps, /, */)
			for (i = 1; i <= n; i++) {
				d = deps[i]
				sub(/ *\(.*$/, "", d)
				sub(/^ +| +$/, "", d)
				if (d ~ re) print cur " depends on " d
			}
		}
	' "$DPKG_DB" | sort -u >>"$WORK/reverse-deps"
fi

sort -u "$WORK/packages" -o "$WORK/packages"
sort -u "$WORK/files" -o "$WORK/files"
sort -u "$WORK/dirs" -o "$WORK/dirs"
[ -f "$WORK/reverse-deps" ] || : >"$WORK/reverse-deps"

if [ ! -s "$WORK/packages" ]; then
	log "WARNING: no package matched '$PKG_REGEX'"
	log "WARNING: either the base image already ships without Chromium, or it names the package differently"
else
	log "packages to remove:"
	sed 's/^/[scrub]   - /' "$WORK/packages"
	log "files owned by those packages: $(wc -l <"$WORK/files")"
fi

if [ -s "$WORK/reverse-deps" ]; then
	log "surviving packages declare a dependency on a package being removed:"
	sed 's/^/[scrub]   ! /' "$WORK/reverse-deps"
	if [ "$ALLOW_REVERSE_DEPS" != "true" ]; then
		die "refusing to break those packages; rebuild with ALLOW_REVERSE_DEPS=true if this is expected"
	fi
	log "WARNING: continuing anyway because ALLOW_REVERSE_DEPS=true"
fi

# ----------------------------------------------
# Delete the files, then the directories left empty.
# ----------------------------------------------

while read -r path; do
	[ -n "$path" ] || continue
	rm -f "$ROOTFS$path"
done <"$WORK/files"

# Deepest first, so that nested directories can drain. rmdir only removes empty
# directories, which keeps shared ones such as /usr/bin intact.
awk '{ print gsub("/", "/") "\t" $0 }' "$WORK/dirs" | sort -rn | cut -f2- |
	while read -r path; do
		[ -n "$path" ] || continue
		rmdir "$ROOTFS$path" 2>/dev/null || true
	done

for path in $SWEEP_PATHS; do
	if [ -e "$ROOTFS$path" ] || [ -L "$ROOTFS$path" ]; then
		log "sweeping leftover path: $path"
		rm -rf "$ROOTFS$path"
	fi
done

# ----------------------------------------------
# Drop the packages from the databases and the SBOM.
# ----------------------------------------------
# Anything left behind here would keep vulnerability scanners reporting Chromium
# CVEs against an image that no longer contains Chromium.

if [ -n "$APK_DB" ] && [ -s "$WORK/packages" ]; then
	awk -v re="$PKG_REGEX" '
		BEGIN { RS = ""; ORS = "\n\n" }
		{
			name = ""
			n = split($0, lines, "\n")
			for (i = 1; i <= n; i++) {
				if (substr(lines[i], 1, 2) == "P:") {
					name = substr(lines[i], 3)
					break
				}
			}
			if (name == "" || name !~ re) print
		}
	' "$APK_DB" >"$WORK/installed.new"
	cat "$WORK/installed.new" >"$APK_DB"
	log "pruned apk database"
fi

if [ -n "$DPKG_DB" ] && [ -s "$WORK/packages" ]; then
	awk -v re="$PKG_REGEX" '
		BEGIN { RS = ""; ORS = "\n\n" }
		{
			name = ""
			n = split($0, lines, "\n")
			for (i = 1; i <= n; i++) {
				if (lines[i] ~ /^Package: /) {
					name = lines[i]
					sub(/^Package: */, "", name)
					break
				}
			}
			if (name == "" || name !~ re) print
		}
	' "$DPKG_DB" >"$WORK/status.new"
	cat "$WORK/status.new" >"$DPKG_DB"

	while read -r pkg; do
		[ -n "$pkg" ] || continue
		rm -f "$ROOTFS/var/lib/dpkg/info/$pkg."* 2>/dev/null || true
	done <"$WORK/packages"
	log "pruned dpkg database"
fi

# Chainguard/Wolfi images ship a per-package SPDX document that scanners read
# directly.
while read -r pkg; do
	[ -n "$pkg" ] || continue
	for sbom in "$ROOTFS/var/lib/db/sbom/$pkg-"*.spdx.json "$ROOTFS/var/lib/db/sbom/$pkg.spdx.json"; do
		if [ -f "$sbom" ]; then
			log "removing SBOM document: ${sbom#"$ROOTFS"}"
			rm -f "$sbom"
		fi
	done
done <"$WORK/packages"

# ----------------------------------------------
# Prepare the runtime user.
# ----------------------------------------------
# The final image is rebuilt FROM scratch, so it inherits no USER from the base
# and we cannot read the base's configuration from the root filesystem. Pin the
# unprivileged user here instead, matching upstream Gotenberg's uid/gid.

PASSWD="$ROOTFS/etc/passwd"
GROUP="$ROOTFS/etc/group"

if [ -f "$PASSWD" ] && grep -q "^$RUNTIME_USER:" "$PASSWD"; then
	existing_uid="$(awk -F: -v u="$RUNTIME_USER" '$1 == u { print $3 }' "$PASSWD")"
	log "runtime user '$RUNTIME_USER' already exists in the base image (uid $existing_uid)"
	if [ "$existing_uid" != "$RUNTIME_UID" ]; then
		die "base image has '$RUNTIME_USER' at uid $existing_uid but the build expects $RUNTIME_UID; rebuild with --build-arg RUNTIME_UID=$existing_uid"
	fi
else
	log "creating runtime user '$RUNTIME_USER' ($RUNTIME_UID:$RUNTIME_GID)"
	if [ -f "$PASSWD" ] && awk -F: -v id="$RUNTIME_UID" '$3 == id { found = 1 } END { exit !found }' "$PASSWD"; then
		die "uid $RUNTIME_UID is already taken in the base image; rebuild with a free --build-arg RUNTIME_UID"
	fi
	if ! grep -q "^$RUNTIME_USER:" "$GROUP" 2>/dev/null; then
		echo "$RUNTIME_USER:x:$RUNTIME_GID:" >>"$GROUP"
	fi
	echo "$RUNTIME_USER:x:$RUNTIME_UID:$RUNTIME_GID:$RUNTIME_USER:$RUNTIME_HOME:/sbin/nologin" >>"$PASSWD"
fi

# LibreOffice writes its user profile - including lock files - into this
# directory, so it has to be owned by the runtime user before the image drops
# privileges. Creating it here also means the COPY that lands the CVE-2012-5639
# registrymodifications.xcu file does not create root-owned parents.
mkdir -p "$ROOTFS$RUNTIME_HOME/.config/libreoffice/4/user"
chown -R "$RUNTIME_UID:$RUNTIME_GID" "$ROOTFS$RUNTIME_HOME"
# Support for arbitrary user ids (OpenShift), as upstream does.
chmod -R g=u "$ROOTFS$RUNTIME_HOME"
chgrp -R 0 "$ROOTFS$RUNTIME_HOME"

mkdir -p "$ROOTFS/tmp"
chmod 1777 "$ROOTFS/tmp"

# ----------------------------------------------
# Verify.
# ----------------------------------------------

failures=0

for path in $REQUIRED_PATHS; do
	if [ ! -e "$ROOTFS$path" ]; then
		log "MISSING required path: $path"
		failures=$((failures + 1))
	fi
done

if [ -n "$APK_DB" ] && awk -v re="$PKG_REGEX" '
	{ k = substr($0, 1, 1); v = substr($0, 3) }
	k == "P" && v ~ re { found = 1 }
	END { exit !found }
' "$APK_DB"; then
	log "apk database still lists a package matching '$PKG_REGEX'"
	failures=$((failures + 1))
fi

if [ -n "$DPKG_DB" ] && awk -v re="$PKG_REGEX" '$1 == "Package:" && $2 ~ re { found = 1 } END { exit !found }' "$DPKG_DB"; then
	log "dpkg database still lists a package matching '$PKG_REGEX'"
	failures=$((failures + 1))
fi

for path in $SWEEP_PATHS; do
	if [ -e "$ROOTFS$path" ] || [ -L "$ROOTFS$path" ]; then
		log "path still present after sweep: $path"
		failures=$((failures + 1))
	fi
done

# Anything else carrying the name is reported but not fatal: documentation,
# fontconfig entries and the like are harmless, and failing on them would make
# the build brittle against unrelated base image changes.
leftovers="$(find "$ROOTFS" -iname '*chromium*' -o -iname 'chrome-sandbox' 2>/dev/null | sed "s|^$ROOTFS||" | head -n 40)"
if [ -n "$leftovers" ]; then
	log "paths still mentioning Chromium (informational):"
	echo "$leftovers" | sed 's/^/[scrub]   ? /'
fi

if [ "$failures" -ne 0 ]; then
	die "$failures verification check(s) failed"
fi

rm -rf "$WORK"

log "root filesystem size after: $(du -sh "$ROOTFS" | cut -f1)"
log "done"
