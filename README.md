# host-agent

Pushes a Linux host's metrics to Prometheus (remote write) and its logs
to Loki: the part of Grafana Alloy that the homelab's configuration
used, in about 1 MiB of memory instead of about 100.

- Metrics under node_exporter's and cAdvisor's names and labels, the
  same series Alloy's unix exporter and cAdvisor give: CPU, memory,
  disks, file systems, network, hwmon, systemd, ZFS, btrfs, XFS, NFS,
  DMI and the rest of Alloy's collectors; `*.prom` files; Docker
  containers from cgroup v2 or v1, with `container_label_*`, `spec` and
  `machine_*`. Exporters on the host are scraped and passed on, each
  with `up`. Its own numbers come as Alloy's (job `alloy`).
- Logs: the systemd journal (through `journalctl --output=export`),
  every running Docker container's output, files named in `log` lines
  and in file_sd JSON files (`__path__` may be a glob, `**` included).
  A `level` label comes from the journal's priority or from a line's
  first level word.
- One thread around poll(2). Metrics Prometheus does not take wait on
  disk (`state_dir/spool`, up to 2 hours and `spool_max_mb`) and are
  sent oldest first when it is back. An outage of Loki pauses the log
  sources, which resume from saved positions (journal cursor, Docker
  timestamp, file offset) once the lines are sent.

## Build

```bash
cargo build --release --locked --target x86_64-unknown-linux-musl
cargo test
```

Static with musl, so the binary runs on any Linux of its architecture;
the homelab's Ansible role builds it with `RUSTFLAGS=-C linker=rust-lld`
for each host's architecture.

## Run

```bash
host-agent /etc/host-agent/config          # the agent
host-agent --print /etc/host-agent/config  # one round of metrics, sent nowhere
```

The configuration format, with an example, is at the top of
[src/config.rs](src/config.rs); `HOST_AGENT_CONFIG`, when set, holds its
text instead of the file. Positions are kept in `state_dir/positions`.
It runs as root: the journal, Docker's socket and the containers'
`/proc` need it.

## Docker

The [Dockerfile](Dockerfile) compiles it in a build stage on Alpine's
Rust and copies the binary alone into an image `FROM scratch` (1.4 MB):

```bash
docker build -t host-agent:local .
docker run -d --name host-agent --restart unless-stopped \
  --pid host --network host --cgroupns host \
  -v /:/host/root:ro -v /var/run/docker.sock:/var/run/docker.sock \
  -v host-agent-data:/var/lib/host-agent \
  -e HOST_AGENT_CONFIG="$(cat config)" host-agent:local
```

The configuration says `root /host/root`: every host path (`/proc`,
`/sys`, `/run`, `/etc`, log files) is read under it, as node_exporter's
`--path.rootfs`; in an LXC that keeps lxcfs's `/proc`. It needs no
privileges. There is no journal reader in it (no `journalctl`): a host
without systemd names its syslog file in a `log` line.
