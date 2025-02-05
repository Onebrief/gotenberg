#!/bin/bash

set -e

DOCKER_REPO_GH="ghcr.io/onebrief"

# Args.
GOLANG_VERSION="$1"
GOTENBERG_VERSION="$2"
GOTENBERG_USER_GID="$3"
GOTENBERG_USER_UID="$4"
NOTO_COLOR_EMOJI_VERSION="$5"
PDFTK_VERSION="$6"
PDFCPU_VERSION="$7"
DOCKER_REGISTRY="$8"
DOCKER_REPOSITORY="$9"
LINUX_AMD64_RELEASE="${10}"

# Find out if given version is "semver".
GOTENBERG_VERSION="${GOTENBERG_VERSION//v}"
IFS='.' read -ra SEMVER <<< "$GOTENBERG_VERSION"
VERSION_LENGTH=${#SEMVER[@]}
TAGS=()
TAGS_CLOUD_RUN=()

if [ "$VERSION_LENGTH" -eq 3 ]; then
  MAJOR="${SEMVER[0]}"
  MINOR="${SEMVER[1]}"
  PATCH="${SEMVER[2]}"

  TAGS+=("-t" "$DOCKER_REGISTRY/$DOCKER_REPOSITORY:latest")
  TAGS+=("-t" "$DOCKER_REGISTRY/$DOCKER_REPOSITORY:$MAJOR")
  TAGS+=("-t" "$DOCKER_REGISTRY/$DOCKER_REPOSITORY:$MAJOR.$MINOR")
  TAGS+=("-t" "$DOCKER_REGISTRY/$DOCKER_REPOSITORY:$MAJOR.$MINOR.$PATCH")

  TAGS_CLOUD_RUN+=("-t" "$DOCKER_REGISTRY/$DOCKER_REPOSITORY:latest-cloudrun")
  TAGS_CLOUD_RUN+=("-t" "$DOCKER_REGISTRY/$DOCKER_REPOSITORY:$MAJOR-cloudrun")
  TAGS_CLOUD_RUN+=("-t" "$DOCKER_REGISTRY/$DOCKER_REPOSITORY:$MAJOR.$MINOR-cloudrun")
  TAGS_CLOUD_RUN+=("-t" "$DOCKER_REGISTRY/$DOCKER_REPOSITORY:$MAJOR.$MINOR.$PATCH-cloudrun")
else
    # Normalizes version.
    GOTENBERG_VERSION="${GOTENBERG_VERSION// /-}"
    GOTENBERG_VERSION="$(echo "$GOTENBERG_VERSION" | tr -cd '[:alnum:]._\-')"

    if [[ "$GOTENBERG_VERSION" =~ ^[\.\-] ]]; then
      GOTENBERG_VERSION="_${GOTENBERG_VERSION#?}"
    fi

    if [ "${#GOTENBERG_VERSION}" -gt 128 ]; then
      GOTENBERG_VERSION="${GOTENBERG_VERSION:0:128}"
    fi

  TAGS+=("-t" "$DOCKER_REGISTRY/$DOCKER_REPOSITORY:$GOTENBERG_VERSION")
  TAGS_CLOUD_RUN+=("-t" "$DOCKER_REGISTRY/$DOCKER_REPOSITORY:$GOTENBERG_VERSION-cloudrun")
fi

# Multi-arch build takes a lot of time.
if [ "$LINUX_AMD64_RELEASE" = true ]; then
    PLATFORM_FLAG="--platform linux/amd64"
else
    PLATFORM_FLAG="--platform linux/amd64,linux/arm64,linux/386,linux/arm/v7"
fi

docker buildx build \
  --build-arg GOLANG_VERSION="$GOLANG_VERSION" \
  --build-arg GOTENBERG_VERSION="$GOTENBERG_VERSION" \
  --platform linux/amd64 \
  -t "$DOCKER_REPO_GH/gotenberg:latest" \
  -t "$DOCKER_REPO_GH/gotenberg:${SEMVER[0]}" \
  -t "$DOCKER_REPO_GH/gotenberg:${SEMVER[0]}.${SEMVER[1]}" \
  -t "$DOCKER_REPO_GH/gotenberg:${SEMVER[0]}.${SEMVER[1]}.${SEMVER[2]}" \
  --push \
  -f build/Dockerfile.bc .

