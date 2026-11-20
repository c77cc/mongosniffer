# MongoSniffer Docker E2E

These tests start real MongoDB containers, generate traffic with official
drivers, capture the traffic through MongoSniffer and tcpdump, then compare the
live report with a replay of the captured PCAP.

Every live/replay invocation passes the active MongoDB endpoint together with
an unused endpoint in one comma-separated `--server` value. This keeps the real
suite exercising multi-endpoint parsing, filtering, direction detection, and
the JSON `dimensions.server_address` field.

Run the base suite:

```bash
MONGOSNIFFER_E2E_REQUIRED=1 \
MONGOSNIFFER_MONGO_IMAGE=mongo:7.0 \
go test -tags=e2e ./tests/e2e -run TestDockerEndToEnd -v -count=1
```

On Linux CI, grant capture capabilities first or set
`MONGOSNIFFER_E2E_SETCAP=1`. For local environments where capabilities cannot
be set, `MONGOSNIFFER_E2E_SUDO=1` runs the capture processes through sudo.

Additional suites:

```bash
MONGOSNIFFER_E2E_REPLICA=1          # transaction and change-stream coverage
MONGOSNIFFER_E2E_REAL_CLIENTS=1     # PyMongo, Node.js, Java, and .NET drivers
MONGOSNIFFER_E2E_ARTIFACTS=PATH     # retain JSON, PCAP, and tcpdump logs
```

Without `MONGOSNIFFER_E2E_REQUIRED=1`, the suite skips when Docker is not
available. CI always enables the required mode.
