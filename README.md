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
  with `up`. Network devices over SNMP v2c, with snmp_exporter's
  `system`, `if_mib` and UCD modules. Its own numbers come as Alloy's
  (job `alloy`).
- Logs: the systemd journal (read from its files, or through
  `journalctl --output=export` without feature `journal-files`),
  every running Docker container's output, files from static targets
  and from file_sd JSON files (`__path__` may be a glob, `**` included),
  syslog over UDP or TCP (RFC 5424 or 3164).
  Labels from the journal's fields and syslog's header, for
  `loki.relabel` and `loki.process` to shape.
- Alloy's configuration: it reads `config.alloy` and does what its
  components say (below), so either can run from the same file.
- An OTLP/HTTP receiver that passes each request on unchanged to its
  signal's backend (Loki and Prometheus take OTLP themselves).
- Alloy's HTTP server on `127.0.0.1:12345`: a status
  page, `/metrics`, `/-/ready`, `/-/healthy`, `/-/reload`, and live
  views of each sample and log line sent (`/debug/metrics`,
  `/debug/logs`).
- One thread around poll(2), and SNMP devices polled apart from it, so
  a dead one holds nothing up. Metrics Prometheus does not take wait on
  disk (`<storage>/prometheus.remote_write.<name>`, up to 2 hours and
  256 MiB) and are
  sent oldest first when it is back. An outage of Loki pauses the log
  sources, which resume from saved positions (journal cursor, Docker
  timestamp, file offset) once the lines are sent.

## Build

```bash
cargo build --release --locked --target x86_64-unknown-linux-musl
cargo test
```

Each part a host may lack is a cargo feature, all on by default:
`docker` (containers' metrics and logs), `journal` (through
journalctl), `journal-files` (from the files, without journalctl),
`filesystems` (btrfs, XFS, ZFS), `snmp`, `syslog`, `otlp`, `server`.
Off by default: `journal-xz` (fields journald compressed with xz,
before systemd 246), `tokio` (SNMP devices polled by tasks on one
thread instead of a thread each), `tls` (syslog over TLS, rustls on
ring: +0.9 MB, and a C compiler for the target). A smaller build:
`--no-default-features --features journal,filesystems`. A
configuration that needs a part the build lacks is refused.

Static with musl, so the binary runs on any Linux of its architecture;
the homelab's Ansible role builds it with `RUSTFLAGS=-C linker=rust-lld`
for each host's architecture.

## Run

Alloy's command line, for the flags it shares:

```bash
host-agent run /etc/host-agent/config.alloy   # the agent
host-agent run --server.http.listen-addr=127.0.0.1:12345 \
  --storage.path=/var/lib/host-agent config.d/   # a directory of *.alloy
host-agent --print config.alloy   # one round of metrics, sent nowhere
kill -HUP <pid>                   # read the configuration again
```

Alloy's other flags are warned of and ignored. `HOST_AGENT_CONFIG`,
when set, holds the configuration's text instead of the file. Positions
are kept in `<storage>/positions`. It runs as root: the journal,
Docker's socket and the containers' `/proc` need it.

## Configuration

Alloy's syntax: blocks, attributes, references between components
(`prometheus.remote_write.default.receiver`), `sys.env`, `constants.*`,
`string.format`, `string.join`, `coalesce`, `array.concat`. Components:

- `prometheus.exporter.unix`, `.self`, `.cadvisor`, `.snmp`;
  `prometheus.scrape`, `prometheus.relabel`, `prometheus.remote_write`;
- `discovery.docker`, `discovery.file`, `discovery.relabel`,
  `local.file_match`;
- `loki.source.journal` (with `path` and `matches`), `.file`,
  `.docker` (Docker's or Podman's socket), `.syslog` (UDP, TCP or
  TLS, RFC 5424 or 3164); `loki.relabel`, `loki.write`, `loki.process`
  with the stages `regex`, `template`, `replace`, `labels`,
  `static_labels`, `label_drop`, `label_keep`, `drop`, `json`,
  `logfmt`, `timestamp` (zones from the host's tz database),
  `output`, `match`;
- `otelcol.receiver.otlp` into `otelcol.exporter.otlphttp` (passed on
  unchanged, to every exporter a signal reaches;
  `otelcol.processor.batch` in between is let through).

What it cannot do as Alloy would (another component, attribute or
block, such as `loki.source.kafka` or syslog's `raw` format) is refused
with its position in the file, never ignored. `logging`,
`livedebugging` and `tracing` are accepted and ignored.

## Docker

The [Dockerfile](Dockerfile) compiles it in a build stage on Alpine's
Rust, cross-compiling for the target platform, and copies the binary
alone into an image `FROM scratch` (about 1 MB). `FEATURES` picks the
parts:

```bash
docker buildx build --platform linux/arm64 \
  --build-arg FEATURES=docker,filesystems -t host-agent:local --load .
docker run -d --name host-agent --restart unless-stopped \
  --pid host --network host --cgroupns host \
  -v /:/host/root:ro -v /var/run/docker.sock:/var/run/docker.sock \
  -v host-agent-data:/var/lib/host-agent \
  -e HOST_AGENT_CONFIG="$(cat config)" host-agent:local
```

`prometheus.exporter.unix` says `rootfs_path = "/host/root"`: every
host path (`/proc`,
`/sys`, `/run`, `/etc`, log files) is read under it, as node_exporter's
`--path.rootfs`; in an LXC that keeps lxcfs's `/proc`. It needs no
privileges. The journal is read from the host's files under it; a
host without systemd reads its syslog file by `loki.source.file`.
