# 架构与会话状态机

## 控制面与应用数据面

Punt 由一个进程维护控制面和可选方向的数据载体：

```text
TCP/UDP application or WireGuard
        |
        | TCP or UDP listener
        v
punt
  - UDP control plane and authenticated UDP data carrier
  - raw ICMP data carrier
  - NAT tuple learner
  - session state machine
        |
        | ICMP Type 3 / Code 3 or UDP
        v
remote punt
```

控制面必须发送真实 UDP；ICMP RELATED 流量不能假定会刷新 UDP conntrack。
数据面通过 endpoint adapter 接入应用：UDP 保留 datagram 边界；TCP 用每流
KCP 子会话在 ICMP 路径上恢复可靠、有序字节流；WireGuard 兼容入口仍接受
固定 loopback UDP datagram。三者复用同一个控制面、认证数据封装、NAT tuple
学习和限速器；配置为 ICMP 的方向再经过 raw ICMP 编解码。

`client_to_server` 与 `server_to_client` 独立选择 `icmp` 或 `udp`，方向由
underlay client/server 固定定义，与 relay 的 `listen_side` 无关。UDP 数据
载体复用 control socket 和已学习的 remote tuple，但仍使用完整 `PUWG`
session/MAC 封装，不会把应用 datagram 原样暴露到公网。

## 显式端口转发

通用 relay 是定向的单目标转发：

```text
application -> listener-side Punt -> ICMP or UDP carrier -> target-side Punt -> configured target
```

默认由 underlay client 配置 `listen`、server 配置 `target`。`listen_side`
也可设为 `server`，此时两者交换应用职责，但 UDP 控制面、NAT tuple 学习和
公网角色保持不变。目标地址不在网络帧中传递，target side 不会按网络输入
选择目的地，因此 Punt 不会成为 SOCKS 或开放转发代理。
UDP 可以同时维护多个本地来源 flow；TCP 可以同时维护多条本地连接。Punt
underlay 的 `network` 与 `peer` 仅用于控制面和 ICMP quoted tuple，不属于
应用的连接参数。

## UDP 控制面

客户端把 UDP socket 绑定到 `-network` 指定的 IPv4 地址和端口，每个
`-keepalive` 周期（默认 5 秒）向 `-peer` 发送 `HELLO`。服务端以
`recvfrom` 的实际来源地址和端口作为当前 remote tuple，并返回
`HELLO_ACK`。因此服务端不会写死客户端 CGNAT 映射后的端口。

控制 socket 必须保持 unconnected。Linux 可以把关联的 ICMP Port
Unreachable 作为 UDP 异步错误呈现，单次错误不能销毁控制会话或停止接收。

服务端在相同 client session 的来源 IP 或端口变化时创建新的 server session；
客户端在 `-dead-timeout`（默认 15 秒）未收到 ACK 时回到 UDP 探测状态。

## 端到端处理路径

以默认 `listen_side=client` 的 TCP relay 为例，应用 TCP 连接、Punt 会话和
carrier 包不是同一层的连接。一个应用连接会成为一个 relay flow；每个 flow
拥有自己的 KCP 子会话，而同一 Punt 实例的所有 flow 共用当前 Punt session：

```text
local TCP client
  -> client Punt listen accepts a TCP connection
  -> client Punt allocates a non-zero flow ID and sends TCP_OPEN
  -> server Punt connects only to its configured target
  -> server Punt replies TCP_OPEN_ACK or TCP_REJECT
  -> both sides exchange TCP_PACKET frames for that flow
  -> each frame is wrapped in a PUWG Packet with the current server session
  -> selected carrier sends the complete PUWG message
  -> remote Punt validates it, then delivers it to KCP or the fixed target
```

UDP relay 没有 KCP 和连接握手：listener side 将每个 datagram 绑定到一个随机
flow ID；target side 只向配置的 target 发送；回包使用该 flow ID 映射回原始
listener 地址。WireGuard 兼容模式不使用 relay frame，直接把经过验证的
`PUWG Packet` payload 注入本机固定的 WireGuard loopback endpoint。

在所有模式下，Punt 先完成以下边界检查，才允许数据离开本机：

1. 对 UDP carrier，来源必须等于 client 配置的 `peer` 或 server 从 `HELLO`
   学到的 remote tuple，且该方向必须配置为 UDP。
2. 对 ICMP carrier，外层 IPv4、ICMP Type/Code、quoted IPv4/UDP 的正反
   tuple 都必须符合当前 session 的控制流。
3. 两个 carrier 都必须通过 `PUWG` magic/version/length、server session 和
   HMAC 校验。
4. relay payload 必须是合法的 `PRLY` frame；WireGuard payload 只能交给配置的
   loopback port，目标地址绝不来自远端报文。

因此 `network`、`peer` 和 carrier 均为 Punt 的 underlay 参数。应用只能看见
`listen`，target application 只能看见来自本机 Punt 的连接或 datagram。

### 方向与载体选择

两个 carrier 字段使用 underlay 方向而非应用方向。下图的箭头无论是 TCP
请求、TCP 响应、UDP datagram 还是 WireGuard datagram，都遵循相同规则：

```text
underlay client -- client_to_server --> underlay server
underlay client <-- server_to_client -- underlay server
```

`listen_side` 只决定谁接受应用连接或 datagram。它改变时，以上两条 underlay
箭头不变，也不应交换 `mode`、`network`、`peer` 或 carrier 配置。

## ICMP 元组方向

ICMP 的方向与被引用 UDP 包的方向相反。以客户端本地端口 `C`、NAT 后
端口 `N`、服务端 UDP 端口 `S` 为例：

| 数据方向 | 本地构造的外层 ICMP | quoted UDP |
| --- | --- | --- |
| client -> server | client -> server public address | server:`S` -> client:`C` |
| server -> client | server -> learned NAT tuple:`N` | learned NAT tuple:`N` -> server:`S` |

NAT 会在 RELATED 流量中同时转换外层地址与 quoted IPv4/UDP 元组。只有
`HELLO` 和 `HELLO_ACK` 都成功后，这两个引用方向才可用。

## 状态机

```text
UDP_PROBING
  -> ICMP_PROBING
  -> ESTABLISHED
  -> UDP_PROBING
```

1. `UDP_PROBING`：客户端发送 HELLO；服务端学习 NAT tuple 并发送 ACK。
2. `ICMP_PROBING`：这是为兼容既有状态接口保留的名称，实际表示数据载体
   probe。客户端按 `client_to_server` 发送 `PROBE`，服务端按
   `server_to_client` 返回 `PROBE_ACK`，客户端再发送 `PROBE_CONFIRM`。
   非默认 carrier 组合会在 probe payload 中带版本标记和双向配置，配置不一致
   的两端不会建立会话。
3. `ESTABLISHED`：服务端收到确认后，两端允许 endpoint adapter 数据进入
   配置的数据载体。客户端继续发送真实 UDP HELLO，并周期性发送 carrier probe。
4. UDP ACK 超时、服务端 HELLO 超时或 NAT tuple 变化时，现有 session 被废弃
   并重新探测。

当客户端在 `tcp_fallback` 时间内收不到 UDP ACK 时，会从与 `network` 相同的
本地端口建立 TCP control 连接，并在 TCP 上交换同样经过认证的 HELLO/ACK。客户端
仍持续发送 UDP HELLO 创建映射；服务端使用 TCP 观察到的公网 IP 和 HELLO 声明的
UDP 端口构造 ICMP tuple。TCP control 不承载数据，UDP 恢复后优先切回 UDP control。

## WireGuard 接入

兼容模式监听 `-local`，并用同一个 UDP socket 向 `-wireguard` 注入解出的
datagram。两者必须为 loopback 地址；收到本地数据时还会校验来源端口必须
等于 `-wireguard`。这避免 WireGuard 因包装器临时端口而错误 roaming。

推荐初始 WireGuard MTU 为 1340。外层 IPv4、ICMP、quoted IPv4/UDP 共占
56 字节，另有 32 字节包装头和约 32 字节 WireGuard data message 开销。程序
设置 DF，超过 1,400 字节的 WireGuard datagram 被丢弃并计数，绝不截断。

当前版本只维护一个活动 remote tuple。多个同时在线的 WireGuard peer 应使用
独立的 `punt` 进程、network/control port 和 localhost wrapper port。

WireGuard 从架构上仍是一个固定 UDP endpoint：其公网 underlay 完全由 Punt
管理，WireGuard 两端 endpoint 都配置为 `127.0.0.1:<punt-port>`。保留专用
兼容入口是为了维持既有协议和双向 endpoint roaming 行为，而不是维护第二套
ICMP 数据面。

## TCP 吞吐路径

TCP relay 每次把本地读取拆成单个 KCP MSS 大小的消息，避免一个丢包阻塞整块
32 KiB 读取。KCP 使用 512 segment 收发窗口、10 ms update 和 fast resend；
默认保留 KCP 拥塞窗口。显式启用 `tcp_nocwnd` 后，由 Punt 的全局 Mbit/s/PPS
limiter 负责实例级速率边界，适合经过测量的专用链路，不应作为未知路径默认值。
可靠 TCP relay packet 在 token bucket 暂时无额度时进入对应 carrier 最多
256 包的有界 pacing queue，而不是立即制造一次需要 KCP 重传的本地丢包。
