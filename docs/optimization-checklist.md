# 性能审计改进 Checklist

本文逐项对应 `punt-传输性能优化报告.md` 的问题清单。状态只在代码、测试和
文档都能提供证据时标记为“已完成”。

| 编号 | 改进点 | 状态 | 实现与验证证据 |
| --- | --- | --- | --- |
| P0-1 | 默认限速过低、令牌桶仅 100 ms | 已完成 | `Burst` 可配置，保留 100 ms 兼容默认；CLI/JSON 暴露 `burst`、`max_pps`、`max_mbps`；`go test ./...`。100 Mbit/s 是安全保底，不宣称性能推荐值。 |
| P0-2 | 热路径分配和载荷复制 | 已完成 | `protocol.Verifier`、`SealData`、`ParseDataInPlace`、`EncodeRelayFrame`、ICMP 原地组包、收发 `sync.Pool`；协议线格式兼容测试覆盖。 |
| P0-3 | 单事件循环中的阻塞 TCP 写 | 已完成 | TCP relay 每流使用有界写队列和 writer goroutine；满队列通过 KCP 窗口背压；TCP 回显/丢包重传测试和 `go test -race ./...` 通过。 |
| P0-4 | UDP/raw 到达缓冲不足 | 已完成 | `tuneUDPBuffers` 应用于 control、WireGuard、UDP relay listener/target 和 raw socket；支持 FORCE 选项并记录实际缓冲。 |
| P0-5 | 可靠队列小于 KCP 窗口、把整形变成丢包 | 已完成 | 环形 `packetQueue`，默认 4096，可配置；可靠包在令牌不足时排队，不可靠包单独计数；TCP relay 高水位暂停 KCP 更新。 |
| P1-5 | raw socket 无 BPF | 已完成 | Linux raw socket 安装 Type 3/Code 3 BPF，并在学习 remote 后增加源地址过滤；用户态仍保留完整校验。 |
| P1-6 | KCP 参数固化 | 已完成 | `KCPWindow`、`KCPInterval`、`KCPFastResend` 增加配置与边界校验，CLI/JSON 可用；默认值保持兼容。 |
| P1-7 | UDP 超大 datagram 与普通丢包混计 | 已完成 | `MSG_TRUNC`/超预算走 `relay_oversize` 独立事件和计数，接收缓冲复用。 |
| P2-8 | limiter 浮点开销、缺少字节观测 | 已处理（保留浮点） | 按报告结论保留浮点令牌桶以避免语义变化；增加 `tx_bytes`、`rx_bytes`、`limiter_queued`、`limiter_drops`、`queue_drops`、`relay_oversize`，浮点路径后续需以 profile 决定是否改整数实现。 |
| P2-9 | `string()` 地址/魔数比较 | 已完成 | 魔数和 IPv4 地址改用定长字节比较；probe 比较使用 `bytes.Equal`。 |
| P2-10 | 16 位 checksum 循环 | 已完成 | RFC 1071 checksum 使用 32 位字累加和 64 位折叠，增加 ICMP 回归测试。 |
| P2-11 | relay 帧头冗余 | 不改线格式 | 报告明确收益约 0.55%，且 v1 混跑兼容优先；保留当前头部并用兼容测试锁定。 |
| P2-12 | 单 goroutine 约 700 Mbit/s 上限 | 部分完成 | 收发缓冲池、原地封装和 TCP 写路径已并行；`sendmmsg/recvmmsg` 和多实例 `SO_REUSEPORT` 属于后续架构变更，未伪称完成。 |

## 质量门槛

每次修改至少执行：

```sh
gofmt -w ./cmd ./internal
go test ./...
go vet ./...
go test -race ./...
```

跨主机吞吐、ICMP policer、NAT remap 和 WireGuard 联调仍需按
[`docs/testing.md`](testing.md) 的隔离要求执行；单元测试不能替代真实网络验收。
