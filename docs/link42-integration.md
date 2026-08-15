# Link42 集成契约

Punt 应在 Link42 中作为 WireGuard 的 `punt` middleware，而不是独立连接后端。
一条受管 WireGuard 点对点链路对应两个 Punt systemd 实例，每端一个；当前
Punt 的单活动对端约束与 Link42 的单 peer 受管接口约束一致。

## 交付物

Link42 Agent 应安装以下文件：

```text
/usr/local/sbin/punt
/etc/systemd/system/punt@.service
/etc/link42/middleware/punt/<instance>.json
/etc/link42/middleware/punt/<instance>.key
```

服务模板位于 [deploy/link42/punt@.service](../deploy/link42/punt@.service)，
配置示例位于 [deploy/link42/punt.json.example](../deploy/link42/punt.json.example)。
通用四层 relay 示例位于
[punt-relay-client.json.example](../deploy/link42/punt-relay-client.json.example) 和
[punt-relay-server.json.example](../deploy/link42/punt-relay-server.json.example)。
Agent 创建 `link42-punt` 系统用户，配置和密钥目录权限为 `0750`，每个 key
文件权限必须为 `0600`。Punt 会拒绝 group 或 other 可读的 key 文件。

构建发布资产时使用：

```sh
make linux-amd64 VERSION=<release-version>
```

Agent 通过 `punt --version` 验证下载资产版本。首版只应声明
`middleware.punt` capability 给 Linux/systemd/IPv4 节点；OpenWrt、IPv6 和
一实例多 peer 都必须在 Link42 API 层拒绝。

## 配置模式

Punt 受管启动使用严格 JSON。未知字段会使启动失败，避免 Agent/API 版本不匹配
时静默忽略配置。

| 字段 | 必填 | 说明 |
| --- | --- | --- |
| `mode` | 是 | `client` 或 `server` |
| `network` | 是 | 本机真实 IPv4 地址和真实 UDP control port |
| `peer` | client | 客户端可连接的服务端公网 IPv4/UDP 地址 |
| `local` | 否 | wrapper loopback 地址，默认 `127.0.0.1:51821` |
| `wireguard` | 否 | 本机 WireGuard loopback ListenPort，默认 `127.0.0.1:51820` |
| `relay` | 否 | 通用 TCP/UDP relay；与 `local`、`wireguard` 互斥 |
| `carrier` | 否 | 双向数据载体；省略时双向均为 `icmp` |
| `key_file` | 是 | 包含 32 位十六进制密钥的 `0600` 常规文件 |
| `status_socket` | 否 | 绝对 Unix socket 路径，例如 `/run/link42-punt/<instance>.sock` |
| `keepalive` | 否 | Go duration，默认 `5s` |
| `dead_timeout` | 否 | Go duration，默认 `15s` |
| `max_payload` | 否 | 最大认证数据 payload，默认 `1400` |
| `max_pps` | 否 | 数据载体 PPS 上限，默认 `10000` |
| `max_mbps` | 否 | 数据载体速率上限，默认 `100` |

`network` 不是“用户从公网访问的地址”。例如服务端位于 DNAT/EIP 后时，
`network` 必须使用服务端网卡实际拥有的内网地址；客户端的 `peer` 才使用公网
DNAT/EIP 地址。Link42 必须分别保存和校验这两个地址，不能从 `Node.public_ip`
推断本机 bind 地址。

`relay` 内部字段为 `protocol`（`tcp` 或 `udp`）、`listen_side`（默认
`client`）、listener side 的 `listen`、target side 的 `target`、可选
`idle_timeout` 和 `tcp_nocwnd`。Link42 API 必须让连接两端共享
protocol/listen_side/tcp_nocwnd，并按
应用角色只下发 listen 或 target；target 不得来自运行时网络报文。通用 relay
是另一种 Punt 使用方式，不改变下述 WireGuard middleware 的现有配置映射。

`carrier` 内部字段为 `client_to_server` 和 `server_to_client`，取值只能为
`icmp` 或 `udp`。两端必须下发完全相同的对象。方向由 Punt underlay role
确定，不得根据 relay `listen_side` 或应用流量方向交换。非默认组合会在数据
probe 中校验一致性，不匹配的实例不会进入 `ESTABLISHED`。

## Link42 middleware 映射

建议在 Link42 增加 `PuntMiddlewareConfig`，包含：

```text
server_side
server_public_ipv4, server_public_udp_port
server_bind_ipv4, server_bind_udp_port
client_bind_ipv4, client_bind_udp_port
local_wrapper_port, peer_wrapper_port
client_to_server_carrier, server_to_client_carrier
keepalive, dead_timeout, max_payload, max_pps, max_mbps
generated_punt_key
```

`server_side` 确定哪一端运行 Punt server。client 的 `peer` 使用
`server_public_ipv4:server_public_udp_port`；server 的 `network` 使用
`server_bind_ipv4:server_bind_udp_port`。服务端会动态学习客户端 NAT 后端口，
Link42 不得配置或持久化该端口为静态对端地址。

启用 Punt 时，**双方** WireGuard peer endpoint 都必须改为各自本机的 wrapper：

```text
node A WireGuard peer endpoint = 127.0.0.1:<A wrapper port>
node B WireGuard peer endpoint = 127.0.0.1:<B wrapper port>
```

公网地址只提供给 Punt 控制面和 raw ICMP quoted tuple，不能继续留在
WireGuard Endpoint 字段。两个 WireGuard ListenPort、两个 wrapper port 和
两个 control port 都必须进行同机端口冲突校验；推荐 WireGuard MTU 为 1340。

## 生命周期与状态

Link42 必须编排跨节点顺序，不能只同时下发 middleware 与 WireGuard 启动：

```text
install Punt on both nodes
-> write key/config on both nodes
-> start both punt@ instances
-> apply WireGuard configs with localhost endpoints
-> start both WireGuard interfaces
-> require Punt ESTABLISHED and a WireGuard handshake
```

停止顺序相反：先停 WireGuard，再停 Punt，最后删除 Punt 配置和密钥。修改
角色、端口、绑定地址或密钥时应作为 Change Plan 执行完整重建，而不是原地
并行重启。

Agent 状态任务执行：

```sh
punt status -socket /run/link42-punt/<instance>.sock
```

返回 JSON 中的 `state`、`client_to_server`、`server_to_client`、
`learned_remote`、`last_ack_at`、`raw_in/out`、`udp_data_in/out`、
`wireguard_in/out`、`dropped` 和 `invalid` 应写入 Link42 运行状态。只有
`ESTABLISHED` 且 WireGuard 最新握手存在时，面板才能将连接标识为可用。
通用 relay 还返回 `transport`、`listen_side`、`listen`、`target`、
`active_flows`、`queued_raw`、`queued_udp` 与 `tcp_nocwnd`；这些字段
用于展示本地转发状态，不能代替端到端应用健康检查。

## 安全与限制

- systemd 服务仅授予 `CAP_NET_RAW`，不需要 `CAP_NET_ADMIN`。
- 不在 Agent task payload、systemd 参数、日志或进程参数中传递明文 key。
- Link42 应保留端口、NAT、IP 协议和 ICMP policer 风险确认，并先执行低速
  capability probe。
- Punt 当前只支持一个活动 remote tuple；对每条 Link42 虚拟网线单独创建
  一个实例，不要合并多个 peer。
