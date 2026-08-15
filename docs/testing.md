# 测试规范与已验证结果

## 本地质量门槛

每次协议、解析、状态机或 raw socket 变更后必须执行：

```sh
make test
make vet
go test -race ./...
make build
```

单元测试必须至少覆盖：消息 round trip、MAC 篡改、截断包、ICMP quoted
tuple 方向和边界检查。TCP relay 必须覆盖至少一次 KCP 数据帧丢失后的重传与
有序回显。修复缺陷时先增加能复现缺陷的测试，再修改实现。

## 跨主机测试隔离要求

- 使用未占用的 UDP、WireGuard ListenPort 和 localhost wrapper port。
- 创建带 `punt-test-` 前缀的临时 WireGuard 接口，使用独立测试网段和新密钥。
- 不修改生产 WireGuard peer、DNAT、安全组、路由、全局防火墙或 sysctl。
- 每次测试都记录启动参数、包装器状态转换、WireGuard transfer 和吞吐结果。
- 无论成功或失败都删除临时接口、进程、二进制、私钥、日志和监听端口。

推荐先做控制面/ICMP 探测，再创建临时 WireGuard peer。确认 peer endpoint
为 `127.0.0.1:<wrapper-port>`，才能证明流量经由包装器而非直连。

## 建议验证顺序

1. 启动服务端与客户端，确认双方进入 `ESTABLISHED`。
2. 用临时 WireGuard /30 或 /31 地址连续 ping，记录发送、接收、丢包和 RTT。
3. 使用 `iperf3` 验证 TCP 与限速 UDP。UDP 要指定速率，例如：

   ```sh
   iperf3 -s -1 -B <server-tunnel-ip>
   iperf3 -c <server-tunnel-ip> -B <client-tunnel-ip> -u -b 1M -t 30
   ```

4. 对照 `wg show <interface>` transfer、包装器 `wg in/out` 与 `raw in/out`
   统计。仅连接成功不足以证明实际经 ICMP 转发。
5. 进行至少一次 NAT remap/重连测试，并验证服务端日志重新学习 tuple。

## 已验证结果

2026-08-15 还在本机 loopback 上使用独立 control/listen/target 端口进行了
真实 raw ICMP relay 联调：普通 UDP 客户端经 Punt 到 UDP echo 成功，普通
TCP 客户端经 Punt/KCP 到 TCP echo 成功。应用仅访问本地绑定端口；测试没有
修改路由、防火墙或现有接口，所有临时进程和端口均已清理。单元层额外故意
丢弃首个 TCP relay packet，连接仍通过 KCP 重传完成回显。

## TCP Relay 优化对照

2026-08-15 在两台隔离测试节点使用固定 underlay 角色
`node-a=client`、`node-b=server` 复测通用 TCP relay。优化包括 MSS 级 KCP
message、512 segment 窗口、10 ms update、有界 raw pacing queue，以及将
应用 `listen_side` 与 underlay mode 解耦。测试上限为 300 Mbit/s / 30,000
PPS，结果均取 iperf3 接收端。

| 应用方向 | 模式 | 并发 | 优化前 | 优化后 |
| --- | --- | ---: | ---: | ---: |
| `node-a -> node-b` | `tcp_nocwnd=true` | 1 | 18.1 Mbit/s | 47.1 Mbit/s |
| `node-a -> node-b` | `tcp_nocwnd=true` | 4 | 60.9 Mbit/s | 81.9 Mbit/s |
| `node-b -> node-a` | `listen_side=server,tcp_nocwnd=true` | 1 | 417 Kbit/s | 75.3 Mbit/s |
| `node-b -> node-a` | `listen_side=server,tcp_nocwnd=true` | 4 | 1.14 Mbit/s | 104 Mbit/s |

反向优化前为了改变应用方向交换了 underlay client/server，进入了高丢包 ICMP
路径；优化后只改变 `listen_side`，继续使用已验证的 NAT tuple，提升主要来自
角色解耦而不是窗口参数。正向默认拥塞控制的 4 流结果为 63.9 Mbit/s，raw
发送/接收约 95,656/94,328，`dropped=0`；开启 `tcp_nocwnd` 可提高到 81.9
Mbit/s，但会显著增加路径 policer 丢包。生产默认应保持 `false`，只对已测、
有明确 `max_mbps`/`max_pps` 的链路启用。

2026-08-15 的隔离测试均使用独立 UDP 端口、临时 WireGuard 接口、loopback
endpoint 和一次性密钥。测试结束后已清理所有资产。

| 路径 | 检查 | 结果 |
| --- | --- | --- |
| `node-a -> node-b` | 20 个 WireGuard ping | 20/20 收到，0% 丢包 |
| `node-a -> node-b` | 单流 TCP `iperf3`，30 秒，包装器 300 Mbit/s / 30,000 PPS | 接收端 132 Mbit/s |
| `node-a -> node-b` | 4 并发 TCP `iperf3`，30 秒，同一上限 | 接收端合计 124 Mbit/s |
| `node-b -> node-a` | 单流 TCP `iperf3`，30 秒，包装器 300 Mbit/s / 30,000 PPS | 接收端 138 Mbit/s |
| `node-b -> node-a` | 4 并发 TCP `iperf3`，30 秒，同一上限 | 接收端合计 124 Mbit/s |
| CGNAT client `-> node-b` | 30 个 WireGuard ping | 30/30 收到，0% 丢包，平均 RTT 28.4 ms |
| CGNAT client `-> node-b` | UDP `iperf3 -b 1M`，30 秒 | 999 Kbit/s，0/2,912 datagram 丢失 |
| CGNAT client `-> node-b` | 单流 TCP `iperf3`，30 秒，包装器 300 Mbit/s / 30,000 PPS | 接收端 1.22 Mbit/s |
| CGNAT client `-> node-b` | 4 并发 TCP `iperf3`，30 秒，同一上限 | 接收端合计 1.19 Mbit/s，大量重传 |
| `node-b ->` CGNAT client | 单流 TCP `iperf3`，30 秒，包装器 300 Mbit/s / 30,000 PPS | 接收端 71.7 Mbit/s，稳定区间约 75-82 Mbit/s |

CGNAT client 上行的高突发 TCP 测试出现约 20% ICMP 丢包和明显重传；该路径
当前的已验证稳定速率为 1 Mbit/s。将包装器上限提高到 300 Mbit/s / 30,000
PPS 或增加 TCP 并发数均未提高该路径的实际吞吐，说明限制位于 CGNAT 上行或
中间网络的 ICMP 策略，而不是默认包装器限速。不要将其它路径的短时高吞吐
结论外推到该 CGNAT 或其它运营商网络。

反向的 `node-b ->` CGNAT client 下行使用相同的包装器上限和隔离方式，30 秒
单流 TCP 达到 71.7 Mbit/s，且包装器未发生自身限速丢弃。该差异表明本机
CGNAT 路径的主要限制在上行方向，不应把上行约 1 Mbit/s 的结果套用到下行。

## UDP Carrier 对照

2026-08-15 为验证 CGNAT client 上行 ICMP policer 的规避方式，在不改动路由、
防火墙、DNAT 或既有服务的前提下，使用独立端口从 CGNAT client 到 `node-b`
进行了 TCP relay 测试。两端运行 Punt `0.4.0-carrier`，应用端口为各自独立的
loopback 端口，Punt 上限为 300 Mbit/s/30,000 PPS，carrier 为：

```json
{
  "client_to_server": "udp",
  "server_to_client": "icmp"
}
```

客户端与服务端均进入 `ESTABLISHED`。接收端 `iperf3` 结果如下：

| CGNAT client -> node-b TCP relay | 时长 | 接收端吞吐 | 旧双向 ICMP 对照 | 改善 |
| --- | ---: | ---: | ---: | ---: |
| 单流 | 15 秒 | 32.7 Mbit/s | 1.25 Mbit/s | 26.2 倍 |
| 4 并发流 | 15 秒 | 42.1 Mbit/s | 731 Kbit/s | 约 57.6 倍 |

单流有 16 次、4 流合计有 22 次应用 TCP retransmit；Punt `dropped=0`，两条
carrier queue 均为 0。测试结束时本机累计 `udp_data_out=132,938`、
`raw_in=132,930`，远端日志累计 `udp data in=132,938`、`raw out=132,930`。
这些互补计数证明本机受限的 client->server 载荷已经走 UDP，而服务端返回的
KCP ACK/控制数据仍走 ICMP。结果说明该 CGNAT 上行限速位于 ICMP 策略，且在
本次时段可由方向分离绕过；它不构成其他 NAT、运营商或长期可用性的保证。

`node-a <-> node-b` 的双向极限测试中，单流均优于 4 并发流。以本次 30 秒
测试的接收端平均值计，已验证极限为 `node-a -> node-b` 132 Mbit/s、
`node-b -> node-a` 138 Mbit/s。包装器设置为 300 Mbit/s / 30,000 PPS，未
发生自身限速丢弃；这些数值反映当前链路和测试时段，不构成长期带宽保证。

## 裸 WireGuard 对照

为区分 ICMP 包装开销与基础网络限制，额外在 `node-a <-> node-b` 上创建了
不启动 Punt 的临时 WireGuard 接口。裸 WireGuard 客户端直接指向服务端
公网 UDP 端口，MTU 仍为 1340，使用相同 /30 地址和 30 秒单流 TCP 方法。

| 方向 | Punt 接收端 | 裸 WireGuard 接收端 | 包装链路相对下降 |
| --- | ---: | ---: | ---: |
| `node-a -> node-b` | 132 Mbit/s | 196 Mbit/s | 32.7% |
| `node-b -> node-a` | 138 Mbit/s | 196 Mbit/s | 29.6% |

裸 WireGuard 的两个方向均为完整 30.03 秒测试。该对照说明当前 Port
Unreachable 包装层加上路径对 ICMP 的处理会带来约 30% 的有效 TCP 吞吐
下降；其数值会随线路、NAT、ICMP 策略和主机负载变化，不能外推为固定开销。
