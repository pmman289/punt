# 快速上手

本页给出三种可直接套用的最小拓扑：普通 TCP relay、普通 UDP relay 和
WireGuard 兼容模式。所有 IPv4 地址都来自 RFC 5737 文档网段，必须替换为
实际地址；所有端口都必须与已有服务、WireGuard 接口和其他 Punt 实例隔离。

```text
underlay server local bind = 192.0.2.10
underlay server public peer = 198.51.100.10
underlay client local bind = 192.0.2.20
```

`network` 总是本机实际 bind 地址，`peer` 只在 client 上配置，且使用 server
的公网可达地址。若 server 位于 DNAT/EIP 后，`network` 仍填写 server 网卡的
实际地址，不能填写 EIP。

## 共同准备

在两个节点上安装相同版本的 `punt`。只要任一方向使用 ICMP，进程需要
`CAP_NET_RAW`；以下命令使用 `sudo`，因此不要求事先设置 file capability。

只在任一节点生成一份 Punt 预共享密钥，再通过受控渠道把**相同内容**放到
另一端。这个密钥只认证 Punt 控制和数据封装，不替代 TLS、SSH 或 WireGuard
自己的密钥。

```sh
sudo install -d -m 0700 /etc/punt
openssl rand -hex 16 | sudo tee /etc/punt/example.key >/dev/null
sudo chmod 0600 /etc/punt/example.key
```

下文所有命令都使用 `/etc/punt/example.key`。生产环境应改为独立实例目录、
独立 key 文件和受管 `-config` JSON；不要把密钥放到命令行、版本库或日志中。

默认 carrier 是双向 ICMP。若已确认只有 client 上行受到 ICMP 限速，则在**两端
Punt 命令中同时**追加：

```sh
-client-tx udp -server-tx icmp
```

方向按 underlay role 定义，和应用由哪一端发起无关。详细理由见
[架构文档](architecture.md#方向与载体选择)。

## 普通 TCP Relay

本例把 client 本机的 `127.0.0.1:8080` 定向转发到 server 本机已经监听的
`127.0.0.1:8080`。TCP relay 内部使用每 flow KCP；应用仍然只看到普通 TCP。

没有现成目标应用时，可在 server 的独立终端启动临时 HTTP 服务：

```sh
python3 -m http.server 8080 --bind 127.0.0.1
```

先在 **server** 启动 Punt：

```sh
sudo punt \
  -mode server \
  -network 192.0.2.10:23086 \
  -relay tcp \
  -target 127.0.0.1:8080 \
  -key-file /etc/punt/example.key \
  -status-socket /run/punt-tcp.sock
```

再在 **client** 启动 Punt：

```sh
sudo punt \
  -mode client \
  -network 192.0.2.20:42487 \
  -peer 198.51.100.10:23086 \
  -relay tcp \
  -listen 127.0.0.1:8080 \
  -key-file /etc/punt/example.key \
  -status-socket /run/punt-tcp.sock
```

两端先检查状态；只有 `ESTABLISHED` 后才启动或使用应用连接：

```sh
punt status -socket /run/punt-tcp.sock
```

在 client 上访问 `127.0.0.1:8080`，例如 `curl http://127.0.0.1:8080/`。
该地址是 Punt 本地入口，不是 server 的公网地址。需要让 server 侧接受应用
连接时，两端都增加 `-listen-side server`，并将 server 改为 `-listen`、client
改为 `-target`；不要交换 `mode` 或 `peer`。

## 普通 UDP Relay

UDP relay 保留每个应用 datagram 的边界。本例将 client 的
`127.0.0.1:9000` 转发到 server 本机的 `127.0.0.1:9000`。它与 TCP relay
必须使用不同的 control/listen/target 端口和独立 Punt 实例。

没有现成目标应用时，可在 server 使用 `socat` 启动临时 UDP echo：

```sh
socat UDP4-RECVFROM:9000,bind=127.0.0.1,fork EXEC:/bin/cat
```

**server**：

```sh
sudo punt \
  -mode server \
  -network 192.0.2.10:23087 \
  -relay udp \
  -target 127.0.0.1:9000 \
  -key-file /etc/punt/example.key \
  -status-socket /run/punt-udp.sock
```

**client**：

```sh
sudo punt \
  -mode client \
  -network 192.0.2.20:42488 \
  -peer 198.51.100.10:23087 \
  -relay udp \
  -listen 127.0.0.1:9000 \
  -key-file /etc/punt/example.key \
  -status-socket /run/punt-udp.sock
```

确认两端 `ESTABLISHED` 后，client 应用把 UDP datagram 发往
`127.0.0.1:9000`。可先使用 UDP echo 服务验证，不要用 TCP 客户端连接此端口。
server 不会从远端报文读取目标地址，所有收到的合法 datagram 都只会被送到
配置的 `127.0.0.1:9000`。

```sh
printf 'hello through punt\n' | socat -T2 - UDP4:127.0.0.1:9000
```

## WireGuard 兼容模式

WireGuard 模式不配置 `relay`。Punt 的 `local` 是 WireGuard 发包时连接的
wrapper 端口，`wireguard` 是本机 WireGuard 的实际 ListenPort。两端 WireGuard
peer endpoint 都必须指向**本机** Punt wrapper，不能填写公网地址。

先启动 Punt。**server**：

```sh
sudo punt \
  -mode server \
  -network 192.0.2.10:23088 \
  -local 127.0.0.1:51821 \
  -wireguard 127.0.0.1:51820 \
  -key-file /etc/punt/example.key \
  -status-socket /run/punt-wg.sock
```

**client**：

```sh
sudo punt \
  -mode client \
  -network 192.0.2.20:42489 \
  -peer 198.51.100.10:23088 \
  -local 127.0.0.1:51821 \
  -wireguard 127.0.0.1:51820 \
  -key-file /etc/punt/example.key \
  -status-socket /run/punt-wg.sock
```

确认两端 Punt 均为 `ESTABLISHED` 后，创建 WireGuard 接口。以下是最小 /30
示例；`<...>` 必须替换为各端真实 WireGuard 密钥，不是 Punt 密钥。

**server WireGuard**：

```sh
CLIENT_WG_PUBLIC_KEY='replace-with-client-public-key'
sudo ip link add wg-punt type wireguard
sudo wg set wg-punt listen-port 51820 private-key /etc/wireguard/server.key \
  peer "$CLIENT_WG_PUBLIC_KEY" \
  allowed-ips 10.66.0.2/32 \
  endpoint 127.0.0.1:51821
sudo ip address add 10.66.0.1/30 dev wg-punt
sudo ip link set wg-punt mtu 1340 up
```

**client WireGuard**：

```sh
SERVER_WG_PUBLIC_KEY='replace-with-server-public-key'
sudo ip link add wg-punt type wireguard
sudo wg set wg-punt listen-port 51820 private-key /etc/wireguard/client.key \
  peer "$SERVER_WG_PUBLIC_KEY" \
  allowed-ips 10.66.0.1/32 \
  endpoint 127.0.0.1:51821 persistent-keepalive 25
sudo ip address add 10.66.0.2/30 dev wg-punt
sudo ip link set wg-punt mtu 1340 up
```

从 client 执行 `ping 10.66.0.1`，然后在两端检查：

```sh
punt status -socket /run/punt-wg.sock
sudo wg show wg-punt
```

Punt 必须保持 `ESTABLISHED`，`wg show` 必须出现最新握手和 transfer。若 Punt
已建立但 WireGuard 没有握手，优先检查 WireGuard peer endpoint 是否是
`127.0.0.1:51821`、ListenPort 是否为 `51820`，以及双方 public key、allowed IP
和本地防火墙。

## 停止与清理

先停止应用或 WireGuard，再停止 Punt，最后删除临时接口、状态 socket、密钥和
测试端口。不要在首次验证时改动已有生产 WireGuard peer、路由、DNAT、安全组
或全局防火墙规则。
