# MongoSniffer

MongoSniffer 是一个旁路 MongoDB 流量分析工具。它重组 TCP 流，解析 MongoDB Wire Protocol，并按默认脱敏的 BSON 命令指纹统计调用量、错误、结果规模和客户端观察耗时，无需连接数据库、代理请求或修改 MongoDB 配置。

[English](README.md)

## 目录

- [主要能力](#主要能力)
- [安装](#安装)
- [快速使用](#快速使用)
- [副本集与分片集群](#副本集与分片集群)
- [命令行参数](#命令行参数)
- [长期运行与实时观测](#长期运行与实时观测)
  - [运行状态与诊断](#运行状态与诊断)
  - [PromQL 示例](#promql-示例)
- [输出](#输出)
- [耗时语义](#耗时语义)
- [BSON 指纹语义](#bson-指纹语义)
- [协议范围](#协议范围)
- [限制与安全](#限制与安全)
- [从源码构建](#从源码构建)
- [License](#license)

## 主要能力

- 使用抓包时间戳分析实时网络流量和离线 PCAP/PCAPNG。
- 支持 IPv4/IPv6、IPv4 分片、VLAN/QinQ、TCP 拆包、粘包、乱序和并发连接。
- 解析 `OP_MSG` kind 0/kind 1、checksum，以及 noop、snappy、zlib、zstd `OP_COMPRESSED`。
- 使用 `requestID`/`responseTo` 关联并发请求、普通响应和 exhaust response chain。
- 识别 `find`、`aggregate`、`count`、`distinct`、写入、bulk write、cursor/getMore、事务和控制命令。
- 统计调用、错误、未完成请求、w:0、返回/影响/修改文档、upsert、写错误、协议字节和压缩算法。
- 输出平均、最小、p95、p99、最大、总耗时，以及 first response、response transfer 和未完成观察时长。
- 按 command、database、collection、application、driver、client、server、事务、retryable write 和 cursor 类型分组。
- 默认删除 BSON 业务值，并对认证载荷、session、事务号和安全 token 执行强制脱敏。
- 检测 TLS 会话并单独计数；不尝试解密。
- 提供 JSON、周期 JSONL、`/healthz`、`/report` 和带 HELP/TYPE 的 Prometheus `/metrics`。

## 安装

版本 tag 发布后，[GitHub Releases](https://github.com/c77cc/mongosniffer/releases) 会提供以下平台的压缩包和 SHA-256 校验文件：

- Linux AMD64
- Linux ARM64
- macOS Intel
- macOS Apple Silicon
- Windows x64

Linux 包使用 AF_PACKET/TPACKET_V3，不依赖 libpcap。macOS 使用系统 libpcap/BPF。Windows 实时抓包和网卡枚举需要安装 [Npcap](https://npcap.com/#download)；离线 PCAP/PCAPNG 分析不需要 Npcap。

下载后解压，将 `mongosniffer`（Windows 为 `mongosniffer.exe`）放入 `PATH`。可使用发布页的 `checksums.txt` 或同名 `.sha256` 文件校验包内容。

## 快速使用

列出抓包网卡：

```bash
mongosniffer --list-interfaces
```

持续抓取 MongoDB 服务端流量，按 `Ctrl-C` 后将最终 JSON 写入文件：

```bash
sudo mongosniffer \
  --interface eth0 \
  --server 10.0.0.8:27017 \
  > report.json
```

分析已有 PCAP/PCAPNG，不需要管理员权限：

```bash
mongosniffer \
  --read-pcap traffic.pcap \
  --server 10.0.0.8:27017 \
  > report.json
```

`--server` 为必填参数，接受一个或多个以逗号分隔的 IP 字面量端点；拆分后最多 64 个，重复端点会被忽略。IPv6 地址必须使用方括号。不要重复传递该参数：

```bash
sudo mongosniffer \
  --interface eth0 \
  --server '10.0.0.8:27017,10.0.0.9:27017,[2001:db8::10]:27017' \
  > report.json
```

Windows 抓取本机 MongoDB 流量时，先执行 `--list-interfaces`，再复制输出中的 Npcap Device 名称，例如：

```powershell
.\mongosniffer.exe --interface '\Device\NPF_Loopback' --server 127.0.0.1:27017
```

默认报告按脱敏 BSON 指纹聚合。以下两个选项会保留允许输出的业务值，可能包含敏感数据：

```bash
# 在 stderr 实时输出经过强制安全字段删除的命令。
sudo mongosniffer --interface eth0 --server 10.0.0.8:27017 --log-commands

# 最终报告按经过强制脱敏的 raw command 分组。
sudo mongosniffer --interface eth0 --server 10.0.0.8:27017 --group-by raw-command
```

即使启用 raw 模式，认证载荷、`lsid`、`txnNumber`、cluster time signature、安全 token、密码和凭据仍不会输出。

## 副本集与分片集群

MongoSniffer 不会连接 MongoDB，也不会主动发现拓扑。需要填写在所选网卡上实际可见的服务端端点：

- 副本集：列出客户端可能连接的所有成员，例如 `--server '10.0.0.8:27017,10.0.0.9:27017,10.0.0.10:27017'`。主节点切换后无需重启 MongoSniffer。
- 分片集群：列出面向客户端的所有 `mongos`，例如 `--server '10.0.1.8:27017,10.0.1.9:27017'`。
- 不要在同一进程中混填 `mongos` 与 config server 或 shard member。两个已配置端点之间的流量无法可靠判断客户端方向，因此会被主动排除。如需分析后端分片流量，应另启一个 MongoSniffer 进程。
- 应填写抓包点看到的地址。存在 NAT、容器、Kubernetes、Service 或负载均衡时，它可能与 MongoDB 连接串中的地址不同。

JSON 通过 `dimensions.server_address`、Prometheus 通过 `server` 标识实际命中的端点。需要集群整体视图时，应在聚合中去掉该 label。

## 命令行参数

| 参数 | 说明 |
| --- | --- |
| `--server IP:PORT[,IP:PORT...]` | 逗号分隔的 MongoDB 服务端地址；实时抓包和回放时必填。仅支持 IP 字面量，最多 64 个；重复传参会报错。 |
| `--interface INTERFACE` | 实时抓包网卡；Linux 默认 `lo`，macOS 默认 `lo0`，Windows 需显式选择。 |
| `--list-interfaces` | 列出可用抓包网卡并退出。 |
| `--read-pcap FILE` | 分析 PCAP/PCAPNG 文件，不进行实时抓包。 |
| `--group-by MODE` | `fingerprint` 或 `raw-command`，默认 `fingerprint`。 |
| `--log-commands` | 将经过强制脱敏的原始命令写入 stderr，可能暴露业务值。 |
| `--include-system-commands` | 将安全处理后的 hello、认证、session 等控制命令加入 operations；控制计数始终保留。 |
| `--max-groups COUNT` | 最终报告最多输出的 operation 分组数，按最大完整请求耗时排序；默认 50，0 表示全部。 |
| `--listen ADDRESS` | 提供 `/healthz`、`/report` 和 `/metrics`，例如 `127.0.0.1:9108`。 |
| `--report-interval DURATION` | 周期 JSONL 间隔，例如 `1m`；必须同时设置 `--report-file`。 |
| `--report-file FILE` | 周期 JSONL 文件；以 0600 权限创建，必须同时设置 `--report-interval`。 |
| `--version` | 输出版本并退出。 |
| `-h`、`--help` | 显示帮助并退出。 |

## 长期运行与实时观测

启用只监听本机的 HTTP 服务和周期 JSONL：

```bash
sudo mongosniffer \
  --interface eth0 \
  --server 10.0.0.8:27017 \
  --listen 127.0.0.1:9108 \
  --report-interval 1m \
  --report-file /var/log/mongosniffer/reports.jsonl
```

HTTP 端点：

- `GET /healthz`：存活检查。
- `GET /report`：当前累计 JSON 报告，遵循 `--max-groups`。
- `GET /metrics`：Prometheus 文本指标，包含全部有界 operation 聚合，不受 `--max-groups` 截断。

### 运行状态与诊断

状态和诊断写入 stderr，JSON 报告写入 stdout，因此重定向 stdout 不会混入日志。正常实时抓包依次输出：

```text
mongosniffer: capture started interface="eth0" servers="10.0.0.8:27017,10.0.0.9:27017" filter="(host 10.0.0.8 and tcp port 27017) or (host 10.0.0.9 and tcp port 27017)"
mongosniffer: waiting for MongoDB traffic; press Ctrl+C to stop and print the report
mongosniffer: MongoDB traffic detected
mongosniffer: MongoDB command capture is working
```

实时抓包 10 秒后没有匹配流量时，会提示检查网卡、服务地址和容器/虚拟机路由。检测到流量但没有完整命令时，会提示 midstream、TLS 或不支持协议等可能原因。检测到 TLS 会立即说明无法解码命令。停止时输出 packets、matched、operations、incomplete、unacknowledged、encrypted sessions 和 capture drops 摘要。

### PromQL 示例

最近 5 分钟调用量最高的 10 个命令指纹：

```promql
topk(10,
  sum by (server, fingerprint_id, fingerprint, command, database, collection) (
    rate(mongosniffer_operation_calls_total[5m])
  )
)
```

最近 5 分钟完整 acknowledged 操作的平均观察耗时：

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

最近 5 分钟平均 first response：

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

最近 5 分钟错误率百分比：

```promql
100 * sum(rate(mongosniffer_operation_errors_total[5m]))
/
clamp_min(sum(rate(mongosniffer_operation_calls_total[5m])), 1e-9)
```

最近 10 分钟抓包质量异常：

```promql
sum(increase(mongosniffer_tcp_gap_events_total[10m]))
+ sum(increase(mongosniffer_tcp_sequence_discontinuities_total[10m]))
+ sum(increase(mongosniffer_capture_kernel_drops_total[10m]))
```

按原因统计最近 10 分钟协议问题：

```promql
sum by (issue) (
  increase(mongosniffer_protocol_issues_total[10m])
)
```

服务存活但最近 10 分钟没有完整 operation：

```promql
up{job="mongosniffer"} == 1
and on()
(
  sum(rate(mongosniffer_completed_operations_total[10m])) or vector(0)
) == 0
```

带 `quantile="0.95"`/`"0.99"` 的耗时指标和 max 指标是进程启动以来的累计 gauge，不是滑动窗口直方图。窗口平均值应使用 seconds total 的 rate 除以 observations total 的 rate。

所有 operation 指标都使用 `server` label 标识实际端点。按成员分析时将 `server` 加入 `sum by (...)`；查看整个副本集或 `mongos` 池时省略它。

## 输出

所有耗时单位均为毫秒。简化示例：

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

顶层字段：

| 字段 | 含义 |
| --- | --- |
| `schema_version` | 报告格式版本；当前为 1。 |
| `build` / `generated_at` | 二进制版本、源码 revision 和快照生成时间。 |
| `operations` | 应用分组、排序和 `--max-groups` 后的 operation 汇总。 |
| `control_counters` | 默认不进入 operations 的控制命令计数。 |
| `capture` | 抓包、TCP 重组和连接完整性计数。 |
| `data_quality` | 全局完整、w:0、排除和元数据缺失计数，不受 `--max-groups` 影响。 |
| `encrypted_sessions` | 识别但无法解码的 TLS 会话数。 |
| `decode_errors` / `protocol_issues` | 解码失败和有界协议问题计数。 |
| `fingerprint_truncations` | 指纹达到安全上限后被截断的次数。 |
| `dropped_operation_keys` | 有界聚合容量已满时无法接纳的新 operation key 数量。 |

每个 operation 的主要字段：

| 字段 | 含义 |
| --- | --- |
| `fingerprint_id` | 由完整、有界 canonical shape 生成的稳定短 ID，适合 dashboard 查询和关联。 |
| `fingerprint` | 便于阅读的脱敏命令摘要；raw-command 模式下为强制脱敏后的命令。 |
| `dimensions` | command、database、collection、application、driver、client、实际命中的 server、事务、retryable write 和 cursor 类型。 |
| `dimension_status` | 是否观察到握手；缺失时明确列出 application/driver。 |
| `calls` / `acknowledged` / `unacknowledged` | 调用总数、需响应请求和 w:0 请求。 |
| `errors` / `incomplete` | 有 command/write/write-concern 错误的请求，以及没有完整终止响应的请求。 |
| `returned_documents` | cursor firstBatch/nextBatch 中返回的文档数。 |
| `affected_documents` / `modified_documents` / `upserts` | 写入结果汇总。 |
| `write_errors` / `write_concern_errors` | 批量写错误和 write concern 错误数量。 |
| `request_protocol_bytes` / `response_protocol_bytes` | MongoDB wire frame 字节数，不是 TCP/IP 总字节数。 |
| `error_codes` / `error_code_names` / `write_error_codes` | MongoDB 错误分类；错误文本不作为维度。 |
| `incomplete_reasons` / `compression` | 未完成原因和实际观察到的压缩算法计数。 |
| `latency_ms` | 完整 acknowledged 请求的观察耗时分布。 |
| `incomplete_observed_duration_ms` | 可选的未完成请求观察时长，仅用于诊断，不是数据库执行耗时。 |

`capture.tcp_gap_events`、`truncated_packets`、capture drops 或 `protocol_state_loss_connections` 非零时，报告可能不完整。`midstream_connections` 表示抓包从已经建立的连接中途开始；这类连接仍可解析自描述的 OP_MSG，但 application 和 driver 元数据可能缺失。

## 耗时语义

- `latency_ms`：从完整客户端请求帧结束到最终响应帧完整结束。
- `first_response`：从完整请求帧结束到首个归属响应开始。
- `response_transfer`：从首个响应开始到终止响应完整结束；exhaust 包含响应链之间的等待。
- `incomplete_observed_duration_ms`：从完整请求帧结束到连接关闭、抓包结束、TCP gap 或协议错误的最后可用时间戳。
- `find` 和后续 `getMore` 是独立往返；getMore 会保留来源指纹 hash 和 cursor 类型。
- w:0 计入 calls/unacknowledged，但不进入正常 latency，也不会因没有响应被标记 timeout。

这些值是抓包点观察耗时，包含网络、排队、服务端执行、序列化和传输，不等同于 MongoDB profiler 的纯服务端耗时。

## BSON 指纹语义

- 默认将所有业务 scalar 替换为 `?`，保留字段名、query/update operator、逻辑结构和 aggregation stage 顺序。
- 在安全上限内完整展示 `$and`/`$or` 条件；同类嵌套逻辑会被扁平化，可交换的条件会排序以保持稳定。
- 常用操作符显示为 `=`、`!=`、`<`、`<=`、`>`、`>=`、`in` 和 `not in`。
- 可读摘要省略 `$db`、`batchSize`、`$readPreference` 等传输噪声；需要区分时它们仍保留在内部 canonical 聚合 shape 中。
- projection 使用 `project(field, ...)` 展示字段名；sort 使用 `sort(field: ?)` 保留有语义的字段顺序。
- `$in`、`$nin`、`$all` 等纯值数组折叠为稳定 shape，批量大小不会产生新的指纹。
- 普通非查询 document 数组仍保留首个 shape，并以 `...mixed` 标记混合结构；逻辑查询数组不再使用 `...mixed`。
- regex pattern、JavaScript、binary、UUID、ObjectId 和认证载荷不会输出原始内容。
- `lsid`、`txnNumber`、cluster time signature 和安全 token 在进入通用 shape 前删除。
- `fingerprint_id` 基于实际用于聚合的完整、有界 canonical shape 计算，不只依赖可读摘要。
- 深度、元素数、sequence shape 数和总指纹长度都有上限；超限使用明确截断标记并增加计数。

`--group-by raw-command` 和 `--log-commands` 保留允许的业务值，但仍强制删除安全字段并截断 binary/超长字符串。这不是逐字节 BSON 还原模式。

## 协议范围

- 完整解析 MongoDB 5.1+ 普通客户端使用的 OP_MSG 和 OP_COMPRESSED。
- 支持 kind 0 body、kind 1 document sequence、checksum、`moreToCome` 和 exhaust response chain。
- legacy opcode 会被识别、计数并安全跳过该 frame；不会为该 frame 生成业务统计，后续支持的 frame 仍可继续解析。
- OP_MSG kind 2/3、未知 required flag、畸形 BSON、checksum 或解压失败等无法安全恢复的边界会记录协议问题，并停止该连接的业务归属，避免错误统计。

## 限制与安全

- 普通抓包无法解密 TLS；只能识别并统计 encrypted session。
- Unix Domain Socket 流量不经过 IP 网络，无法被抓取。
- 工具不主动连接 MongoDB，不执行命令，也不修改数据库配置。
- 工具不解析 hostname、SRV、连接串，也不发现副本集成员或分片拓扑；`--server` 必须填写抓包点可见的 IP 端点。
- 认证用户无法从所有 MongoDB wire 流量中可靠恢复，因此不作为分组维度。
- 执行计划、索引命中、缓存状态和服务端锁等待不在普通 wire protocol 中；应结合 profiler、`explain` 或监控系统。
- 实时抓包通常需要 root/管理员权限；Linux 可为二进制授予 `CAP_NET_RAW` 和 `CAP_NET_ADMIN`。
- raw command、日志和 PCAP 可能包含敏感数据，应限制访问和保留时间。
- 有界聚合最多保留 10000 个 operation key；溢出通过 `dropped_operation_keys` 显式报告。

## 从源码构建

需要 Go 1.26.x：

```bash
make build
make test
make check
```

Linux 静态构建：

```bash
CGO_ENABLED=0 go build -trimpath -o bin/mongosniffer ./cmd/mongosniffer
```

真实 MongoDB Docker E2E 需要 Docker 和 tcpdump：

```bash
make e2e
make e2e-full
```

基础套件覆盖 standalone、live/PCAP replay、snappy/zlib/zstd、TLS 和服务中断。完整 Linux 套件额外覆盖副本集、事务、change stream、PyMongo、Node.js、Java 和 .NET Driver。环境变量见 [tests/e2e/README.md](tests/e2e/README.md)。

总体方案见 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)，协议、输出与验收要求见 [docs/SPEC.md](docs/SPEC.md)。

## License

MongoSniffer 使用 [MIT License](LICENSE)。

抓包、包过滤、TCP 重组和打包代码基于 [PgSniffer](https://github.com/c77cc/pgsniffer) 的已验证实现适配；MongoDB Wire Protocol 和 BSON 分析代码由本项目实现。详情见 [NOTICE](NOTICE)。
