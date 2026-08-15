# Punt

Punt（Port Unreachable Network Transport）是一个 Linux IPv4 四层定向
转发器。应用只连接本机的 Punt 监听地址；Punt 使用真实 UDP 建立并维持
NAT/conntrack 状态，然后在每个方向把已认证的数据放入 ICMP Destination
Unreachable / Port Unreachable（IPv4 Type 3、Code 3）的 quoted UDP payload，
或放入同一条真实 UDP flow。目标端只会转发到本地配置的单个地址和端口，
因此 Punt 不是开放代理。

## 为什么不是普通 ICMP 隧道

Punt 面向一类传统 ICMP 隧道难以正常建立双向通信的网络：server 只有经过
EIP/DNAT 暴露的 UDP 入口，本机网卡并不持有公网地址；client 又位于 CGNAT
之后，公网 IP 和来源端口由运营商动态映射。仅发送 ICMP Echo 或自定义裸 ICMP
的隧道没有一条真实传输流用于打洞和维持 conntrack，也无法让 server 可靠学习
client 的实际 NAT 后地址与端口。中间 NAT 因而可能无法关联、反向转换外层
ICMP 与其 quoted tuple，表现为单向可达、回包丢失或完全无法建链。

Punt 不直接从裸 ICMP 开始。client 先通过真实 UDP `HELLO` 访问 server，建立
NAT/conntrack 状态；server 从收到的 UDP 包学习 client 的实际公网 tuple，再
按该控制流的正反 tuple 构造 ICMP Port Unreachable。对支持 RELATED ICMP 的
NAT，这些 ICMP 包可以沿已建立的 UDP 映射被正确转换和送达。Punt 继续发送
UDP keepalive，在 NAT remap 后重新学习 tuple，并用认证 probe 确认双向 carrier
确实可用后才转发应用流量。

这使 Punt 区别于一般的“IP over ICMP”：它是由真实 UDP 控制面驱动的 NAT
打洞与四层定向转发器。若运营商只限制某一个 ICMP 方向，还可以将该方向切换
为认证 UDP，另一方向继续使用 ICMP，无需交换 client/server 角色。Punt 仍
依赖 NAT 对 RELATED ICMP 的支持，因此不是对所有 NAT 类型都有效的通用穿透
协议。

UDP relay 保持 datagram 语义；TCP relay 使用 KCP 子会话处理 carrier 路径上
的丢包、乱序和重传。Punt 的 HMAC 用于隧道认证而不是内容加密；需要内容保密
时仍应使用 TLS、SSH、WireGuard 等上层协议。

## 工作原理

Punt 把“应用流量”和“公网 underlay”明确分开。应用不感知公网地址、NAT
映射或 carrier；它只连接一个本地 TCP/UDP 端口。`mode=client` 与
`mode=server` 描述的是公网控制面角色，不代表应用必定从哪一端发起。

| 名称 | 作用 | 应用是否使用 |
| --- | --- | --- |
| `listen` | listener side 的本地应用入口 | 是 |
| `target` | target side 的固定本地应用地址 | 否，Punt 使用 |
| `network` | 本机真实 UDP control socket 的绑定地址 | 否 |
| `peer` | client 到 server 的公网 UDP 地址 | 否 |
| `carrier` | 每个 underlay 方向的 `icmp` 或 `udp` 选择 | 否 |

默认 TCP relay 路径如下；UDP relay 保留 datagram 边界，WireGuard 模式把左、
右两侧替换为各自的 loopback WireGuard endpoint：

```text
application
    | TCP connection or UDP datagram
    v
listener-side Punt (listen)
    | authenticated PUWG data message
    | client_to_server: ICMP or UDP
    v
target-side Punt
    | configured local connection or datagram
    v
target application (target)
```

返回流量走相同会话的反向路径，但 carrier 独立取 `server_to_client`。因此，
`client_to_server=udp`、`server_to_client=icmp` 的含义是：所有从 underlay
client 发到 server 的已认证 Punt 数据走真实 UDP，反向数据走 ICMP；它不随
`listen_side` 或应用 TCP 连接的建立方向改变。

### 会话与转发流程

1. client 将 UDP socket 绑定到 `network`，周期性向 `peer` 发送认证 `HELLO`。
2. server 从 `HELLO` 的真实来源地址和端口学习 NAT 映射，创建 server session，
   并返回 `HELLO_ACK`。不需要预先知道客户端的公网映射端口。
3. client 依次发送 `PROBE`、接收 `PROBE_ACK`、发送 `PROBE_CONFIRM`。probe
   使用相同的双向 carrier；非默认 carrier 组合携带配置标记，配置不一致的
   两端不会进入 `ESTABLISHED`。
4. 会话建立后，listener side 从应用读取数据，封装为带 session、sequence 和
   HMAC 的 `PUWG` message，再按发送方向选择 carrier。target side 验证来源
   tuple、carrier、session、长度和 MAC 后才投递给固定目标。
5. client 继续发送真实 UDP `HELLO` 维持 NAT 映射；若 ACK 超时、NAT tuple
   改变或 session 失效，Punt 丢弃旧 flow 并重新从第 1 步探测。

ICMP carrier 不是伪造应用 TCP/UDP header：它的外层固定为 ICMP Type 3/Code 3，
内部 quoted UDP 仅用于保持与控制流匹配的 tuple。UDP carrier 也不是应用 UDP
直通，仍承载完整的 `PUWG` 认证封装。

### 两种使用方式

- **通用 relay**：把任意本地 TCP 或 UDP 应用的 `listen` 定向转发到远端
  `target`。TCP relay 在 Punt 内使用每流 KCP，以应对有丢包和乱序的 carrier。
- **WireGuard 兼容模式**：不配置 `relay`，而是让两端 WireGuard peer endpoint
  都指向本机 `127.0.0.1:<punt wrapper port>`；Punt 在两个 loopback UDP
  endpoint 之间搬运 WireGuard datagram，公网 underlay 仍完全由 Punt 管理。

## 当前范围

- Linux、IPv4、单个活动对端。
- 已实现 UDP 控制面、NAT 后端口学习、认证会话、ICMP 探测和数据转发。
- 支持显式 TCP/UDP `listen -> target` relay，以及原有 WireGuard 兼容模式。
- relay 的 `listen_side` 与 NAT underlay 的 client/server 角色相互独立；默认
  `client`，也可让 underlay server 接受本地应用连接而不交换公网角色。
- `client_to_server` 与 `server_to_client` 可分别选择 `icmp` 或 `udp`；默认
  双向 `icmp`。这两个方向只由 underlay 角色定义，不随 `listen_side` 改变。
- WireGuard 只是固定 loopback UDP relay 的一个用例，只与 `127.0.0.1` 上的
  Punt 端口通信；公网 underlay 地址不能配置为 WireGuard endpoint。
- 需要 NAT 设备能将匹配既有 UDP 流的 ICMP Type 3/Code 3 作为 RELATED
  流量转换；这不是通用 NAT 穿透方案。

## 快速开始

前置条件：Linux、Go 1.22+；任一方向使用 ICMP 时还需要 `CAP_NET_RAW`
（测试可直接以 root 运行）。只有使用 WireGuard 兼容模式时才需要安装
WireGuard。

```sh
make test vet build
sudo setcap cap_net_raw=ep bin/punt
```

三种完整的两端配置可直接参照[快速上手](docs/quickstart.md)：

- [普通 TCP relay](docs/quickstart.md#普通-tcp-relay)
- [普通 UDP relay](docs/quickstart.md#普通-udp-relay)
- [WireGuard 兼容模式](docs/quickstart.md#wireguard-兼容模式)

应用只访问本地 `listen` 或本机 WireGuard endpoint；`network`、`peer` 和真实
UDP control port 只属于 Punt underlay，不暴露给应用。

反向应用流量不应交换 Punt 的 NAT 角色。两端同时增加
`-listen-side server`，然后由 server 配置 `-listen`、client 配置 `-target`。

使用受限 CGNAT 路径时，两端可以保持相同角色，只切换受限的 carrier 方向：

```sh
-client-tx udp -server-tx icmp
```

这会让本机 underlay client 的上行载荷使用认证 UDP，而将服务端返回数据保留
为 ICMP；完整适用条件和实测结果见[上下行载体分离](docs/deployment.md#上下行载体分离)。

## 文档

- [架构与会话状态机](docs/architecture.md)
- [部署前概念与流量路径](docs/architecture.md#端到端处理路径)
- [TCP、UDP 与 WireGuard 快速上手](docs/quickstart.md)
- [协议与报文校验](docs/protocol.md)
- [部署指南](docs/deployment.md)
- [Link42 集成契约](docs/link42-integration.md)
- [测试规范与已验证结果](docs/testing.md)
- [开发规范](docs/development.md)

## 常用命令

```sh
make test
make vet
go test -race ./...
make build
make linux-amd64
```

## 发布构建

当前初始发布版本为 `0.0.1a`，根目录 [VERSION](VERSION) 是唯一版本来源。
每次发布前运行 `./scripts/bump-version.sh`，它会按
`0.0.1a -> ... -> 0.0.9a -> 0.1.0a` 自动提升版本；然后执行：

```sh
make test vet
go test -race ./...
make release
```

`make release` 生成 Linux `amd64`、`arm64`、`armv7` 的静态发布包、source
tarball 和 `SHA256SUMS`，输出在 `dist/v<VERSION>/`。release 只能从已提交且
干净的 Git 工作区构建。发布规范见
[开发规范](docs/development.md#版本与发布)。

默认数据载体为双向 ICMP，上限为 10,000 PPS、100 Mbit/s，最大认证数据
payload 为 1,400 字节。运营商限制某一方向的 ICMP 时，可只把该方向设为
UDP，例如 `-client-tx udp -server-tx icmp`。高频 Type 3 流量可被观察、
限速或拦截，不能视为隐蔽或安全。

## 已验证路径

隔离测试已验证两条独立公网测试路径以及一条 CGNAT 上行路径的包装器会话和
WireGuard 传输。详细测试条件、吞吐和限制见
[测试规范与已验证结果](docs/testing.md)。测试所创建的临时接口、密钥、
进程和远端二进制均已清理。

## 致谢
- 感谢[Session Hu](https://github.com/SessionHu)提供的在 NAT 环境下基于 ICMP Port Unreachable 穿透的思路，以及免费提供的token用于vibe coding
