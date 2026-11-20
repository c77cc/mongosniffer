# MongoSniffer

MongoSniffer is a passive MongoDB traffic analyzer. It reassembles TCP streams, decodes the MongoDB Wire Protocol, and aggregates calls, errors, result sizes, and client-observed latency by redacted BSON command fingerprint. It does not connect to MongoDB, proxy requests, or require changes to database configuration.

[中文](README_CN.md)

## Table of contents

- [Features](#features)
- [Install](#install)
- [Quick start](#quick-start)
- [Replica sets and sharded clusters](#replica-sets-and-sharded-clusters)
- [Command-line options](#command-line-options)
- [Long-running observability](#long-running-observability)
  - [Runtime status and diagnostics](#runtime-status-and-diagnostics)
  - [PromQL examples](#promql-examples)
- [Output](#output)
- [Timing semantics](#timing-semantics)
- [BSON fingerprint semantics](#bson-fingerprint-semantics)
- [Protocol scope](#protocol-scope)
- [Limitations and security](#limitations-and-security)
- [Build from source](#build-from-source)
- [License](#license)

## Features

- Analyzes live traffic and offline PCAP/PCAPNG using capture timestamps.
- Handles IPv4/IPv6, IPv4 fragmentation, VLAN/QinQ, TCP segmentation, coalescing, reordering, and concurrent connections.
- Decodes `OP_MSG` kind 0/kind 1, checksums, and noop, snappy, zlib, and zstd `OP_COMPRESSED` messages.
- Correlates concurrent requests, ordinary responses, and exhaust response chains through `requestID`/`responseTo`.
- Recognizes find, aggregate, count, distinct, writes, bulk writes, cursor/getMore, transaction, and control commands.
- Reports calls, errors, incomplete requests, w:0 operations, returned/affected/modified documents, upserts, write errors, protocol bytes, and compression.
- Reports average, minimum, p95, p99, maximum, and total latency, plus first-response, response-transfer, and incomplete observed durations.
- Groups by command, database, collection, application, driver, client, server, transaction, retryable-write, and cursor dimensions.
- Redacts BSON business values by default and always removes authentication material, sessions, transaction numbers, and security tokens.
- Detects and counts TLS sessions without attempting decryption.
- Exposes JSON, periodic JSONL, `/healthz`, `/report`, and Prometheus `/metrics` with HELP/TYPE metadata.

## Install

Tagged versions are configured to publish archives and SHA-256 checksum files through [GitHub Releases](https://github.com/c77cc/mongosniffer/releases) for:

- Linux AMD64
- Linux ARM64
- macOS Intel
- macOS Apple Silicon
- Windows x64

Linux packages use AF_PACKET/TPACKET_V3 and have no libpcap runtime dependency. macOS uses the system libpcap/BPF stack. Windows live capture and interface enumeration require [Npcap](https://npcap.com/#download); offline PCAP/PCAPNG analysis does not.

Extract the archive and place `mongosniffer` (`mongosniffer.exe` on Windows) in `PATH`. Validate downloads with the release `checksums.txt` or the matching `.sha256` file.

## Quick start

List capture interfaces:

```bash
mongosniffer --list-interfaces
```

Capture MongoDB server traffic until `Ctrl-C`, writing the final JSON report to a file:

```bash
sudo mongosniffer \
  --interface eth0 \
  --server 10.0.0.8:27017 \
  > report.json
```

Analyze an existing PCAP/PCAPNG without elevated privileges:

```bash
mongosniffer \
  --read-pcap traffic.pcap \
  --server 10.0.0.8:27017 \
  > report.json
```

`--server` is required. It accepts one or more comma-separated IP-literal endpoints, with a maximum of 64 after splitting; duplicate endpoints are ignored. Use brackets for IPv6. Do not repeat the flag:

```bash
sudo mongosniffer \
  --interface eth0 \
  --server '10.0.0.8:27017,10.0.0.9:27017,[2001:db8::10]:27017' \
  > report.json
```

On Windows, run `--list-interfaces` and copy the Npcap Device value. To capture local MongoDB traffic, use the loopback device, for example:

```powershell
.\mongosniffer.exe --interface '\Device\NPF_Loopback' --server 127.0.0.1:27017
```

Reports use redacted BSON fingerprints by default. The following options retain permitted business values and may expose sensitive data:

```bash
# Stream commands with mandatory security fields removed to stderr.
sudo mongosniffer --interface eth0 --server 10.0.0.8:27017 --log-commands

# Group the final report by mandatory-redacted raw commands.
sudo mongosniffer --interface eth0 --server 10.0.0.8:27017 --group-by raw-command
```

Even in raw mode, authentication payloads, `lsid`, `txnNumber`, cluster-time signatures, security tokens, passwords, and credentials are never emitted.

## Replica sets and sharded clusters

MongoSniffer does not connect to MongoDB or discover topology. Supply the actual endpoints whose traffic is visible on the selected interface:

- For a replica set, list every member that clients may contact, for example `--server '10.0.0.8:27017,10.0.0.9:27017,10.0.0.10:27017'`. Primary changes then remain observable without restarting MongoSniffer.
- For a sharded cluster, list the client-facing `mongos` endpoints, for example `--server '10.0.1.8:27017,10.0.1.9:27017'`.
- Do not mix `mongos` endpoints with config-server or shard-member endpoints in one process. Traffic between two configured endpoints is direction-ambiguous and is deliberately excluded. Run a separate MongoSniffer process when backend shard traffic also needs analysis.
- Use the addresses as they appear at the capture point. With NAT, containers, Kubernetes, or a service/load balancer, those addresses may differ from the MongoDB connection string.

Operations are split by the actual matched endpoint in JSON `dimensions.server_address` and Prometheus `server`. Aggregate without that label when a cluster-wide view is desired.

## Command-line options

| Option | Description |
| --- | --- |
| `--server IP:PORT[,IP:PORT...]` | Comma-separated MongoDB endpoints; required for live capture and replay. IP literals only, maximum 64; repeat use is rejected. |
| `--interface INTERFACE` | Interface for live capture; defaults to `lo` on Linux and `lo0` on macOS, and must be selected on Windows. |
| `--list-interfaces` | List available capture interfaces and exit. |
| `--read-pcap FILE` | Analyze a PCAP/PCAPNG file instead of capturing live traffic. |
| `--group-by MODE` | `fingerprint` or `raw-command`; default: `fingerprint`. |
| `--log-commands` | Write mandatory-redacted original commands to stderr; business values may be sensitive. |
| `--include-system-commands` | Include safely processed hello, authentication, session, and other control commands in operations; control counters are always retained. |
| `--max-groups COUNT` | Maximum operation groups in reports, ordered by maximum completed-request latency; default: 50, 0 means all. |
| `--listen ADDRESS` | Serve `/healthz`, `/report`, and `/metrics`, for example `127.0.0.1:9108`. |
| `--report-interval DURATION` | Periodic JSONL interval such as `1m`; requires `--report-file`. |
| `--report-file FILE` | Periodic JSONL destination, created with mode 0600; requires `--report-interval`. |
| `--version` | Print the version and exit. |
| `-h`, `--help` | Show command-line help and exit. |

## Long-running observability

Enable a loopback-only HTTP server and periodic JSONL snapshots:

```bash
sudo mongosniffer \
  --interface eth0 \
  --server 10.0.0.8:27017 \
  --listen 127.0.0.1:9108 \
  --report-interval 1m \
  --report-file /var/log/mongosniffer/reports.jsonl
```

HTTP endpoints:

- `GET /healthz`: liveness check.
- `GET /report`: current cumulative JSON report, subject to `--max-groups`.
- `GET /metrics`: Prometheus text exposition for all bounded operation aggregates, without `--max-groups` truncation.

### Runtime status and diagnostics

Status and diagnostics go to stderr while JSON goes to stdout, so redirecting stdout produces a clean report. A healthy live capture normally prints:

```text
mongosniffer: capture started interface="eth0" servers="10.0.0.8:27017,10.0.0.9:27017" filter="(host 10.0.0.8 and tcp port 27017) or (host 10.0.0.9 and tcp port 27017)"
mongosniffer: waiting for MongoDB traffic; press Ctrl+C to stop and print the report
mongosniffer: MongoDB traffic detected
mongosniffer: MongoDB command capture is working
```

After ten seconds without matching live traffic, MongoSniffer suggests checking the interface, endpoint, and container or VM routing. If traffic is present but no complete command is decoded, it points to midstream capture, TLS, or unsupported protocol boundaries. TLS detection immediately explains that commands cannot be decoded. The stop summary includes packets, matched packets, operations, incomplete and unacknowledged operations, encrypted sessions, and capture drops.

### PromQL examples

Top ten command fingerprints by call rate over five minutes:

```promql
topk(10,
  sum by (server, fingerprint_id, fingerprint, command, database, collection) (
    rate(mongosniffer_operation_calls_total[5m])
  )
)
```

Mean observed duration of completed acknowledged operations over five minutes:

```promql
sum by (command, database) (
  rate(mongosniffer_operation_duration_seconds_total[5m])
)
/
clamp_min(
  sum by (command, database) (
    rate(mongosniffer_operation_duration_observations_total[5m])
  ),
  1e-9
)
```

Mean first-response duration over five minutes:

```promql
sum by (command, database) (
  rate(mongosniffer_operation_first_response_seconds_total[5m])
)
/
clamp_min(
  sum by (command, database) (
    rate(mongosniffer_operation_first_response_observations_total[5m])
  ),
  1e-9
)
```

Error percentage over five minutes:

```promql
100 * sum(rate(mongosniffer_operation_errors_total[5m]))
/
clamp_min(sum(rate(mongosniffer_operation_calls_total[5m])), 1e-9)
```

Capture-quality problems over ten minutes:

```promql
sum(increase(mongosniffer_tcp_gap_events_total[10m]))
+ sum(increase(mongosniffer_tcp_sequence_discontinuities_total[10m]))
+ sum(increase(mongosniffer_capture_kernel_drops_total[10m]))
```

Protocol issues by reason over ten minutes:

```promql
sum by (issue) (
  increase(mongosniffer_protocol_issues_total[10m])
)
```

MongoSniffer is up but has observed no completed operation for ten minutes:

```promql
up{job="mongosniffer"} == 1
and on()
(
  sum(rate(mongosniffer_completed_operations_total[10m])) or vector(0)
) == 0
```

Duration metrics with `quantile="0.95"`/`"0.99"` and max metrics are cumulative gauges since process start, not sliding-window histograms. Use the rate of a seconds total divided by the rate of its observations total for windowed means.

All operation metrics include the actual endpoint in the `server` label. Add `server` to `sum by (...)` for per-member analysis, or omit it to aggregate a replica set or `mongos` pool.

## Output

All durations are in milliseconds. Abbreviated example:

```json
{
  "schema_version": 1,
  "build": {"version": "v0.1.0", "revision": "abcdef123456"},
  "generated_at": "2026-11-20T12:00:00+08:00",
  "operations": [
    {
      "fingerprint_id": "ba383643e98d8123",
      "fingerprint": "find shop.orders where status = ? sort(created_at: ?) limit ? project(_id, status, total)",
      "dimensions": {
        "command": "find",
        "database": "shop",
        "collection": "orders",
        "application_name": "order-api",
        "driver_name": "mongo-go-driver",
        "client_address": "10.0.1.24",
        "server_address": "10.0.0.8:27017",
        "transactional": false,
        "retryable_write": false,
        "cursor_kind": "normal"
      },
      "dimension_status": {"handshake_observed": true},
      "calls": 57,
      "acknowledged": 57,
      "unacknowledged": 0,
      "errors": 1,
      "incomplete": 0,
      "returned_documents": 1280,
      "affected_documents": 0,
      "modified_documents": 0,
      "upserts": 0,
      "write_errors": 1,
      "write_concern_errors": 0,
      "request_protocol_bytes": 18240,
      "response_protocol_bytes": 1048576,
      "error_codes": {"50": 1},
      "compression": {"zstd": 57},
      "latency_ms": {
        "observations": 57,
        "average": 11.643,
        "min": 1.433,
        "p95": 65.535,
        "p99": 156.734,
        "max": 156.734,
        "total": 663.65,
        "first_response": {
          "observations": 57,
          "average": 10.8,
          "min": 1.2,
          "p95": 64,
          "p99": 155,
          "max": 155,
          "total": 615.6
        },
        "response_transfer": {
          "observations": 57,
          "average": 0.843,
          "min": 0.1,
          "p95": 1.535,
          "p99": 1.734,
          "max": 1.734,
          "total": 48.05
        }
      }
    }
  ],
  "capture": {
    "packets_seen": 920,
    "packets_matched": 920,
    "bytes_captured": 184320,
    "truncated_packets": 0,
    "kernel_packets_dropped": 0,
    "interface_packets_dropped": 0,
    "tcp_gap_events": 0,
    "tcp_bytes_skipped": 0,
    "tcp_sequence_discontinuities": 0,
    "connections_observed": 10,
    "handshake_observed_connections": 9,
    "midstream_connections": 1,
    "protocol_state_loss_connections": 0
  },
  "data_quality": {
    "completed_operations": 57,
    "unacknowledged_operations": 0,
    "excluded_operations": 0,
    "excluded_percentage": 0,
    "metadata_missing_operations": 0
  },
  "encrypted_sessions": 0,
  "decode_errors": 0,
  "protocol_issues": {},
  "fingerprint_truncations": 0,
  "dropped_operation_keys": 0
}
```

Top-level fields:

| Field | Meaning |
| --- | --- |
| `schema_version` | Report format version; currently 1. |
| `build` / `generated_at` | Binary version, source revision, and snapshot generation time. |
| `operations` | Operation aggregates after grouping, sorting, and `--max-groups`. |
| `control_counters` | Counts for control commands excluded from operations by default. |
| `capture` | Capture, TCP reassembly, and connection-integrity counters. |
| `data_quality` | Global completed, w:0, excluded, and metadata-missing counts before `--max-groups`. |
| `encrypted_sessions` | TLS sessions identified but not decoded. |
| `decode_errors` / `protocol_issues` | Decode failures and bounded protocol issue counters. |
| `fingerprint_truncations` | Fingerprints truncated at configured safety limits. |
| `dropped_operation_keys` | New operation keys rejected after the bounded aggregation capacity is full. |

Primary fields in each operation:

| Field | Meaning |
| --- | --- |
| `fingerprint_id` | Stable short ID derived from the complete bounded canonical shape; useful in dashboards and joins. |
| `fingerprint` | Human-readable redacted command summary; mandatory-redacted command in raw-command mode. |
| `dimensions` | Command, database, collection, application, driver, client, matched server endpoint, transaction, retryable-write, and cursor dimensions. |
| `dimension_status` | Whether the connection handshake was observed and which application/driver dimensions are missing. |
| `calls` / `acknowledged` / `unacknowledged` | Total calls, response-bearing requests, and w:0 requests. |
| `errors` / `incomplete` | Requests with command/write/write-concern errors and requests without a complete terminal response. |
| `returned_documents` | Documents in cursor firstBatch/nextBatch responses. |
| `affected_documents` / `modified_documents` / `upserts` | Aggregated write results. |
| `write_errors` / `write_concern_errors` | Bulk-write and write-concern error counts. |
| `request_protocol_bytes` / `response_protocol_bytes` | MongoDB wire-frame bytes, not total TCP/IP bytes. |
| `error_codes` / `error_code_names` / `write_error_codes` | MongoDB error classifications; error text is not a grouping dimension. |
| `incomplete_reasons` / `compression` | Incomplete causes and observed compression algorithms. |
| `latency_ms` | Observed duration distribution for complete acknowledged requests. |
| `incomplete_observed_duration_ms` | Optional observed duration for incomplete requests; diagnostic only, not database execution time. |

Non-zero `capture.tcp_gap_events`, `truncated_packets`, capture drops, or `protocol_state_loss_connections` indicate that a report may be incomplete. `midstream_connections` means capture began after a connection was established; self-describing OP_MSG frames may still be decoded, but application and driver metadata can be missing.

## Timing semantics

- `latency_ms`: complete client request frame to complete terminal response frame.
- `first_response`: complete request frame to the start of the first attributable response.
- `response_transfer`: first attributable response to the complete terminal response; exhaust includes waits within the response chain.
- `incomplete_observed_duration_ms`: complete request frame to the last available timestamp at connection close, capture end, TCP gap, or protocol error.
- A `find` and each following `getMore` are separate round trips; getMore retains an origin fingerprint hash and cursor kind.
- w:0 contributes to calls/unacknowledged but not normal latency and is not reported as a timeout solely because it has no response.

These are capture-point observations that include network, queuing, server execution, serialization, and transfer. They are not equivalent to server-only MongoDB profiler duration.

## BSON fingerprint semantics

- Business scalar values become `?`; field names, query/update operators, logical structure, and aggregation-stage order remain.
- Nested `$and`/`$or` clauses are rendered completely within the safety limits. Nested operators of the same kind are flattened and commutative clauses are sorted for stability.
- Common operators use readable notation such as `=`, `!=`, `<`, `<=`, `>`, `>=`, `in`, and `not in`.
- Transport boilerplate such as `$db`, `batchSize`, and `$readPreference` is omitted from the readable summary but remains part of the internal canonical grouping shape when relevant.
- Projection lists field names as `project(field, ...)`; sort retains ordered fields as `sort(field: ?)`.
- Pure-value `$in`, `$nin`, `$all`, and similar arrays collapse to stable shapes so batch length does not split fingerprints.
- Generic non-query document arrays retain the first shape and mark heterogeneous structures with `...mixed`; logical query arrays never use `...mixed`.
- Regex patterns, JavaScript, binary values, UUIDs, ObjectIds, and authentication payloads do not expose original content.
- `lsid`, `txnNumber`, cluster-time signatures, and security tokens are removed before general shaping.
- `fingerprint_id` is calculated from the complete bounded canonical shape used for grouping, not only from the readable summary.
- Depth, element count, sequence shapes, and total fingerprint length are bounded; explicit truncation markers and counters expose limit hits.

`--group-by raw-command` and `--log-commands` retain permitted business values while still removing mandatory security fields and bounding binary or long-string output. Raw mode is not a byte-for-byte BSON reconstruction.

## Protocol scope

- Fully decodes OP_MSG and OP_COMPRESSED used by ordinary MongoDB 5.1+ clients.
- Supports kind 0 bodies, kind 1 document sequences, checksums, `moreToCome`, and exhaust response chains.
- Legacy opcodes are identified, counted, and safely skipped for that frame; no operation is emitted for the frame, and later supported frames can still be decoded.
- OP_MSG kind 2/3, unknown required flags, malformed BSON, checksum failures, and decompression failures are non-recoverable attribution boundaries: MongoSniffer records an issue and stops business attribution for that connection rather than risk false results.

## Limitations and security

- Passive capture cannot decrypt TLS; MongoSniffer only detects and counts encrypted sessions.
- Unix Domain Socket traffic does not traverse IP networking and is not visible.
- MongoSniffer does not connect to MongoDB, execute commands, or modify database configuration.
- MongoSniffer does not resolve hostnames, SRV records, connection strings, replica-set membership, or sharded-cluster topology; `--server` requires the observed IP endpoints.
- Authenticated users cannot be recovered reliably from all MongoDB wire traffic and are not a grouping dimension.
- Execution plans, index hits, cache state, and server lock waits are not present in ordinary wire traffic; use the profiler, `explain`, or monitoring systems.
- Live capture usually requires root or administrator privileges. Linux can instead grant `CAP_NET_RAW` and `CAP_NET_ADMIN` to the binary.
- Raw commands, logs, and PCAP files may contain sensitive data; restrict access and retention.
- Aggregation is bounded to 10,000 operation keys; `dropped_operation_keys` reports overflow explicitly.

## Build from source

Go 1.26.x is required:

```bash
make build
make test
make check
```

Static Linux build:

```bash
CGO_ENABLED=0 go build -trimpath -o bin/mongosniffer ./cmd/mongosniffer
```

The real MongoDB Docker E2E suite requires Docker and tcpdump:

```bash
make e2e
make e2e-full
```

The base suite covers standalone MongoDB, live/PCAP replay, snappy/zlib/zstd, TLS, and server interruption. The full Linux suite adds replica sets, transactions, change streams, and PyMongo, Node.js, Java, and .NET drivers. See [tests/e2e/README.md](tests/e2e/README.md) for environment variables.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the design and [docs/SPEC.md](docs/SPEC.md) for protocol, output, and acceptance requirements.

## License

MongoSniffer is available under the [MIT License](LICENSE).

Capture, packet-filtering, TCP-reassembly, and packaging code is adapted from the validated [PgSniffer](https://github.com/c77cc/pgsniffer) implementation. MongoDB Wire Protocol and BSON analysis code is specific to this project. See [NOTICE](NOTICE) for details.
