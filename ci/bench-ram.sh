#!/usr/bin/env bash
# Peak memory (VmHWM, KiB) of host-agent running a configuration for a
# while against ci/sink.py, printed last; samples on the way. Run as
# root, as the agent runs: the journal, Docker and /proc need it.
# Usage: ci/bench-ram.sh <binary> <config.alloy> [seconds]
set -euo pipefail

binary=$1
config=$2
seconds=${3:-60}
here=$(dirname "$0")
storage=$(mktemp -d)

python3 "$here/sink.py" 19099 &
sink=$!
trap 'kill "$sink" 2>/dev/null; rm -rf "$storage"' EXIT
sleep 1

"$binary" run --storage.path="$storage" "$config" &
agent=$!
for second in $(seq "$seconds"); do
  sleep 1
  if ! kill -0 "$agent" 2>/dev/null; then
    echo "host-agent ended early" >&2
    exit 1
  fi
  logger -n 127.0.0.1 -P 5514 -d "bench line $second" 2>/dev/null || :
  if [ $((second % 10)) -eq 0 ]; then
    grep -E '^Vm(RSS|HWM)' "/proc/$agent/status" \
      | tr '\n' ' ' | sed "s/^/${second}s: /"
    echo
  fi
done
peak=$(awk '/^VmHWM/ { print $2 }' "/proc/$agent/status")
kill -TERM "$agent"
wait "$agent"
echo "$peak"
