#!/usr/bin/env bash
# A shields.io endpoint badge: ci/badge.sh <file> <label> <message>
# <color>.
set -euo pipefail

printf '{"schemaVersion":1,"label":"%s","message":"%s","color":"%s"}\n' \
  "$2" "$3" "$4" >"$1"
