# 部署指南

## 前置条件

- Linux IPv4 主机；当前 raw socket 实现在 Linux 上构建。
- Go 1.22+ 用于本机构建。发布到相同架构的 Linux 可使用静态产物。
- 使用 WireGuard 兼容模式时，WireGuard 已安装并能创建接口；通用 TCP/UDP
  relay 不依赖 WireGuard。
- 只要任一方向使用 ICMP，运行用户就具有 `CAP_NET_RAW`。双向 UDP 模式不
  需要此能力。开发测试可直接以 root 运行，部署时优先：

  ```sh
  sudo setcap cap_net_raw=ep /usr/local/sbin/punt
  ```

- 服务端入口 UDP 端口必须可被 NAT/DNAT 转发。客户端和服务端都必须先允许
  真实 UDP 双向通过。

## 构建与安装

```sh
make test vet build
make linux-amd64
sudo install -Dm0755 bin/punt /usr/local/sbin/punt
sudo setcap cap_net_raw=ep /usr/local/sbin/punt
```

生成一把随机 16 字节预共享密钥：

```sh
openssl rand -hex 16
```

密钥不能通过 shell history、进程列表、日志或版本库泄漏。生产部署和 Link42
集成应使用 `-config` 指定 JSON 配置、使用配置中的 `key_file` 指向 `0600`
密钥文件。`-key` 仅保留给开发和受控调试环境。

## Link42 受管启动

Punt 为 Link42 提供 JSON 配置、版本输出与本地状态 socket。安装模板与完整
字段说明见 [Link42 集成契约](link42-integration.md)。核心操作为：

```sh
punt --version
systemctl start punt@<link-instance>
punt status -socket /run/link42-punt/<link-instance>.sock
```

状态命令输出 JSON，包括 `UDP_PROBING`、`ICMP_PROBING` 或 `ESTABLISHED`，
以及方向 carrier、控制面、raw ICMP、UDP data、WireGuard 和丢包计数。
`ICMP_PROBING` 为兼容保留的状态名，也用于非 ICMP carrier probe。socket 权限
固定为 `0600`，不包含共享密钥或承载数据。

## 部署决策顺序

在编写命令或 JSON 前，先按以下顺序确定每个参数。这样可以避免把应用入口、
服务端公网地址和 NAT 学到的客户端地址混为一谈：

1. 选定 underlay server。该端使用 `mode=server` 和本机实际拥有的 `network`
   地址；client 的 `peer` 使用该端从公网可访问的 IP/UDP 端口。
2. 选定应用 listener side。默认是 client：client 配置 `listen`，server 配置
   `target`。若应用要从 server 侧发起，只把两端 `listen_side` 改为 `server`，
   不交换 underlay mode。
3. 确定每个 underlay 方向的 carrier。默认双向 ICMP；只有确认某一方向受
   ICMP policer 影响时才改为 UDP。两端的 `carrier` 必须完全一致。
4. 为每个 Punt 实例分配独立的 control port、应用 listen/target port、状态
   socket 和密钥文件；不要复用已有 WireGuard ListenPort 或生产入口。
5. 先启动两端 Punt，检查 `ESTABLISHED`、carrier 计数和 queue 为正常值，
   再启动或切换应用/WireGuard。停止时反向执行。

`network` 是本机 bind 地址，`peer` 是 client 发起 HELLO 的公网地址，server
日志中的 `learned_remote` 才是实际的客户端 NAT tuple。它是运行时结果，不是
用户配置字段，也不应持久化为 peer。

## 通用 UDP/TCP Relay

完整的 TCP、UDP 和 WireGuard 两端命令见[快速上手](quickstart.md)。本节说明
参数关系与部署约束。

应用只连接客户端 Punt 的 `listen` 地址。公网 control port 是 Punt underlay，
不需要也不应该出现在应用配置中。以下示例把客户端本机 `127.0.0.1:8080`
转发到服务端本机应用 `127.0.0.1:80`。

服务端：

```sh
punt \
  -mode server \
  -network 192.0.2.10:23087 \
  -relay tcp \
  -target 127.0.0.1:80 \
  -key-file /etc/punt/example.key
```

客户端：

```sh
punt \
  -mode client \
  -network 192.0.2.20:42488 \
  -peer 198.51.100.10:23087 \
  -relay tcp \
  -listen 127.0.0.1:8080 \
  -key-file /etc/punt/example.key
```

将两端的 `tcp` 同时改为 `udp` 即为逐 datagram UDP relay。TCP/UDP 不能在同一
实例混用；需要多个协议、监听端口或目标时，为每条规则启动独立 Punt 实例和
独立 control port。客户端可以把 `listen` 绑定到非 loopback IPv4 地址，但这
会把入口开放给对应网络，应配合主机防火墙和访问控制；默认推荐 loopback。

`mode` 只决定 UDP control/NAT underlay 角色，不等于应用方向。若希望应用从
underlay server 侧发起，保持原有 client/server 和公网端口不变，两端都设置：

```sh
-listen-side server
```

然后 server 使用 `-listen`，client 使用 `-target`。不要为了反向应用流量交换
underlay 角色，否则可能进入不同的 NAT/ICMP 策略路径。

## 上下行载体分离

两端必须配置相同的双向 carrier。方向只按 underlay 角色定义，不受
`listen_side` 影响：

```text
-client-tx icmp|udp  # underlay client -> server
-server-tx icmp|udp  # underlay server -> client
```

默认均为 `icmp`。例如客户端所在 CGNAT 只限制上行 ICMP，而服务端下行 ICMP
正常时，两端都配置：

```sh
-client-tx udp -server-tx icmp
```

UDP carrier 复用真实 control socket 和 NAT mapping，但数据仍由 Punt session
和 HMAC 认证。它不是应用 UDP 直通，也不把 underlay 端口暴露给应用。JSON
中的等价配置为：

```json
{
  "carrier": {
    "client_to_server": "udp",
    "server_to_client": "icmp"
  }
}
```

严格 JSON 配置中的 relay 字段如下，且与 `local`、`wireguard` 互斥：

```json
{
  "relay": {
    "protocol": "tcp",
    "listen_side": "client",
    "listen": "127.0.0.1:8080",
    "tcp_nocwnd": false,
    "idle_timeout": "5m"
  }
}
```

服务端把 `listen` 换成 `target`。这是配置片段，仍需提供 `mode`、`network`、
客户端 `peer`、`key_file` 等公共字段。`idle_timeout` 默认 `5m`；到期会关闭
相应 TCP 连接或 UDP flow，以限制失联客户端留下的资源。

`tcp_nocwnd` 默认 `false`。设为 `true` 会关闭 KCP 自身拥塞窗口，可提高低丢包
专用链路吞吐，但必须同时设置合理的 `max_mbps`/`max_pps`，并观察
`queued_raw`、`queued_udp` 与 `dropped`；出现持续 queue 或 drop 时应恢复为
`false`。

## WireGuard 配置

设 WireGuard ListenPort 为 `51820`，包装器监听 `127.0.0.1:51821`。将
WireGuard peer endpoint 配置为 `127.0.0.1:51821`，不要配置公网 peer。

```sh
REMOTE_WG_PUBLIC_KEY='replace-with-remote-public-key'
REMOTE_TUNNEL_PREFIX='replace-with-remote-tunnel-prefix'
wg set wg-punt peer "$REMOTE_WG_PUBLIC_KEY" \
  endpoint 127.0.0.1:51821 \
  persistent-keepalive 25 \
  allowed-ips "$REMOTE_TUNNEL_PREFIX"
ip link set dev wg-punt mtu 1340 up
```

WireGuard `PersistentKeepalive` 有助于维持 WireGuard 自身状态，但不能替代
Punt 的真实 UDP HELLO。

## 启动包装器

服务端绑定其 DNAT 后可见的本地地址和端口：

```sh
punt \
  -mode server \
  -network 192.0.2.10:23087 \
  -local 127.0.0.1:51821 \
  -wireguard 127.0.0.1:51820 \
  -key-file /etc/punt/example.key
```

客户端绑定希望保持稳定的本地 UDP 源端口，并将 peer 设为服务端公网地址：

```sh
punt \
  -mode client \
  -network 192.0.2.20:42488 \
  -peer 198.51.100.10:23087 \
  -local 127.0.0.1:51821 \
  -wireguard 127.0.0.1:51820 \
  -key-file /etc/punt/example.key
```

服务端日志中的 `learned UDP NAT tuple` 才是它实际用于 ICMP 外层和 quoted
UDP 的客户端地址/端口。不要把客户端本地端口或预期公网映射端口写死。

## 参数基线

| 参数 | 默认值 | 说明 |
| --- | ---: | --- |
| `-keepalive` | `5s` | 真实 UDP HELLO 周期，不宜超过已测 NAT timeout |
| `-dead-timeout` | `15s` | UDP ACK/HELLO 超时后重建 session |
| `-tcp-fallback` | `3s` | UDP control 尚未建连时回落 TCP control 的等待时间；`0` 禁用 |
| `-max-payload` | `1400` | 最大认证数据 payload；relay 另占 16 字节帧头 |
| `-client-tx` | `icmp` | client -> server carrier，`icmp` 或 `udp` |
| `-server-tx` | `icmp` | server -> client carrier，`icmp` 或 `udp` |
| `-max-pps` | `10000` | 当前发送方向数据 carrier PPS 上限 |
| `-max-mbps` | `100` | 当前发送方向数据 carrier 速率上限 |
| `-icmp-pacing-pps` | `0` | WireGuard 经本机 ICMP 发送方向的可选节奏目标；`0` 保持直发 |

先从低速率开始。若运营商对 ICMP 限速或丢包，应下调应用发送速率并观察
`dropped`、WireGuard transfer 和端到端丢包，不要仅提高速率上限。对于
WireGuard 下行突发导致高重传的路径，可仅在发送端设置
`-icmp-pacing-pps`，其值必须不高于 `-max-pps`；建议从 `8000` 开始逐步测量。
该选项只影响本机发出的 ICMP WireGuard 数据，控制和探测报文仍立即发送。

TCP 回落只替代 control HELLO/ACK，不传输 WireGuard 数据。客户端会继续从
`network` 指定的 UDP 端口向服务端发送 HELLO，以维持 NAT 映射；TCP 也从这个
端口建立连接，服务端据此构造 ICMP quoted UDP tuple。因此它适用于服务端 UDP
入站被阻断、但 TCP 可达且 NAT 保持端口的场景。若 NAT 重映射 UDP 端口，Punt 不会
错误建立会话，应改为开放 UDP control 端口。

## 运行检查与故障处理

- 期望状态顺序为 `UDP_PROBING -> ICMP_PROBING -> ESTABLISHED`。
- 停留在 `UDP_PROBING`：检查端口 DNAT、安全组、防火墙和控制密钥。
- 停留在 `ICMP_PROBING`：先确认两端 carrier 配置完全一致；ICMP 方向再检查
  NAT 是否转换 Type 3/Code 3 RELATED 流量以及外层/quoted tuple 是否匹配，
  UDP 方向检查回包 tuple 是否等于 HELLO 学习结果。
- 频繁回到 `UDP_PROBING`：缩短 keepalive，检查 NAT 重映射或控制 ACK 丢失。
- WireGuard 无握手但包装器已建立：检查 WireGuard endpoint 是否为 wrapper
  loopback 端口、ListenPort 是否与 `-wireguard` 一致，以及 allowed IP/密钥。
- relay 已建立但应用连接失败：确认客户端只配置 `listen`、服务端只配置
  `target`，目标应用确实监听该 IPv4/端口，且两端 `relay` 协议一致。

不要在未隔离的生产接口、已有 WireGuard ListenPort、已有 DNAT 端口或全局
防火墙规则上进行首次调试。
