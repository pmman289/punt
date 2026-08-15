# 协议与报文校验

## 密钥与字节序

`-key` 是恰好 16 字节、32 个十六进制字符的预共享密钥。控制面和数据面都
使用 HMAC-SHA-256，取前 8 字节作为 tag。所有整数采用网络字节序。

计算 MAC 时先将 tag 字段清零；收到报文后以常数时间比较 tag。该 MAC 保护
包装器的控制与注入边界，但不提供内容加密。WireGuard 兼容模式由 WireGuard
加密；通用 relay 应由 TLS、SSH 等应用协议提供所需的机密性。

## 控制面消息

控制消息固定为 56 字节，magic 为 `PUWC`：

| 偏移 | 长度 | 字段 |
| ---: | ---: | --- |
| 0 | 4 | magic `PUWC` |
| 4 | 1 | protocol version（当前为 1） |
| 5 | 1 | type：`HELLO=1`、`HELLO_ACK=2` |
| 6 | 2 | 固定长度 56 |
| 8 | 8 | client session ID |
| 16 | 8 | server session ID |
| 24 | 8 | nonce |
| 32 | 8 | Unix timestamp |
| 40 | 2 | 服务端观察到的客户端来源端口 |
| 42 | 6 | 保留，必须为零 |
| 48 | 8 | 截断 HMAC tag |

客户端只接受来自配置 `-peer`、client session 和最新 nonce 都匹配且带非零
server session/observed port 的 ACK。

## 数据面消息

数据消息固定头为 32 字节，magic 为 `PUWG`：

| 偏移 | 长度 | 字段 |
| ---: | ---: | --- |
| 0 | 4 | magic `PUWG` |
| 4 | 1 | protocol version |
| 5 | 1 | type：`PROBE=1`、`PROBE_ACK=2`、`PROBE_CONFIRM=3`、`PACKET=4` |
| 6 | 2 | header length，固定 32 |
| 8 | 8 | server session ID |
| 16 | 4 | packet sequence |
| 20 | 2 | payload length |
| 22 | 2 | 保留，必须为零 |
| 24 | 8 | 截断 HMAC tag |
| 32 | variable | probe、WireGuard datagram 或 relay frame |

payload 最大 1,400 字节。`PACKET` 仅在 `ESTABLISHED` 状态下被投递给
配置的 endpoint adapter；WireGuard 兼容模式保持版本 1 的原始 datagram
格式，relay 模式则解析下面的 `PRLY` 帧。

每个方向可把完整 `PUWG` message 放入 ICMP quoted UDP payload，或直接作为
真实 UDP datagram 通过 control socket 发送。UDP carrier 不省略 session、
sequence 或 MAC。接收端还必须确认来源等于 client 配置的 peer 或 server
从 HELLO 学到的 remote tuple，并确认该方向配置为 UDP。

默认双向 ICMP 的 probe payload 保持 8 字节随机值以兼容既有版本。只要任一
方向为 UDP，probe payload 为 16 字节：`PUC1` 标记、client carrier code、
server carrier code、2 个零保留字节和 8 个随机字节。`icmp=1`、`udp=2`；
两端配置不一致时不得回复或确认 probe。

## Relay 帧

Relay 帧位于已认证的 `PACKET` payload 内，本身不重复计算 MAC：

| 偏移 | 长度 | 字段 |
| ---: | ---: | --- |
| 0 | 4 | magic `PRLY` |
| 4 | 1 | relay version，当前为 1 |
| 5 | 1 | type：`UDP=1`、`TCP_OPEN=2`、`TCP_OPEN_ACK=3`、`TCP_PACKET=4`、`TCP_REJECT=5` |
| 6 | 2 | header length，固定 16 |
| 8 | 4 | 非零 flow ID |
| 12 | 2 | payload length |
| 14 | 2 | 保留，必须为零 |
| 16 | variable | UDP datagram 或 KCP packet |

UDP flow ID 由客户端 Punt 随机生成，用于把服务端回包映射到原始本地来源
地址。服务端不会接受帧中携带目标地址，目标只能来自本地配置。

TCP 每条本地连接使用独立 flow ID。`TCP_OPEN` 可重发，target side 成功连接固定
目标后返回 `TCP_OPEN_ACK`，连接失败则返回 `TCP_REJECT` 并关闭 listener
side 本地
连接；后续 `TCP_PACKET` 承载 KCP packet，提供有序
交付、确认、重传和拥塞控制。TCP half-close 作为 KCP 有序消息传递，避免 FIN
越过尚未送达的数据。Punt 不把应用 TCP header 放进 underlay，也不声称外层
是 TCP；外层由方向配置决定，是 ICMP Type 3/Code 3 或真实 UDP。

`TCP_OPEN` 的发送方由本地配置的 `listen_side` 决定，不由 underlay
client/server 角色写死。两端必须配置相同的 `listen_side`，否则 OPEN 会在
错误一侧被拒绝。

## ICMP 封装

每个发送包的结构为：

```text
outer IPv4 header, DF=1, protocol=ICMP
ICMP header, Type=3, Code=3
quoted IPv4 header, protocol=UDP
quoted UDP header, checksum=0
PUWG data message
```

程序生成 quoted IPv4 header checksum 和 ICMP checksum。IPv4 quoted UDP
checksum 设置为零，这是 IPv4 中有效的选择，也避免 NAT 重写 quoted tuple
时需要增量更新伪首部校验和。

## 接收边界

接收 raw ICMP 后必须依次验证：

1. 外层 IPv4 version、IHL、总长度、ICMP protocol、源/目的地址。
2. ICMP 必须为 Type 3 Code 3。
3. quoted IPv4 version、IHL、总长度、UDP protocol、源/目的地址。
4. quoted UDP 源/目的端口、长度以及完整的 payload 边界。
5. `PUWG` magic、版本、固定头长度、消息类型、session、payload length 与
   MAC。

未知 session、畸形长度、错误元组或 MAC 失败的包都只计入 invalid 统计，
绝不回显或转发，从而避免成为反射器。

接收 UDP carrier 时依次验证 UDP 来源 tuple、方向 carrier、`PUWG` envelope、
session、payload length 和 MAC，然后进入与 ICMP 完全相同的数据消息处理器。
