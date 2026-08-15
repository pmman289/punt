# 开发规范

## 代码与依赖

- 使用 Go 1.22，优先标准库；增加外部依赖前必须说明无法用标准库解决的
  原因、许可证、维护状态和交叉编译影响。
- TCP relay 固定使用 `github.com/xtaci/kcp-go/v5 v5.5.16` 的 KCP 核心。该
  版本兼容 Go 1.22、采用 MIT 许可证；引入它是为了使用经过验证的有序重传和
  拥塞控制实现，不在 Punt 内手写一套不完整的可靠传输协议。升级时必须重新
  执行丢包恢复、race、静态构建和跨主机吞吐测试。
- TCP application read 必须拆成不超过一个 KCP MSS 的 message；不要恢复为
  由 KCP 分片的 32 KiB message，否则任一 segment 丢失都会阻塞整块交付。
- `listen_side` 与 underlay `mode` 是独立维度。修改 flow 状态机时必须覆盖
  client-listen 和 server-listen 两种组合，不能重新写死 OPEN 的发送方向。
- 运行时代码位于 `internal/`，CLI 仅位于 `cmd/punt/`；不要把协议、raw
  socket 或状态机逻辑塞进 `main`。
- 协议常量、序列化和认证集中在 `internal/protocol`；IPv4/ICMP 编解码集中
  在 `internal/tunnel/icmp.go`；Linux syscall 封装集中在 `raw_linux.go`。
- 运行 `gofmt`，避免无关重排。提交前必须通过 `make test`、`make vet`，并对
  并发或网络路径改动运行 `go test -race ./...`。

## 协议兼容性

- 修改字段、长度、字节序、magic、版本或 MAC 范围前，先更新
  [协议文档](protocol.md)，再增加兼容性或拒绝性测试。
- 版本 1 的固定长度字段不得复用。新增可选字段必须引入新版本或明确的
  header length 协商，不能让旧解析器猜测。
- 新的控制或数据消息类型必须有完整的状态机入口、来源验证、长度限制、
  未知类型处理和测试。
- 不要降低 `MaxPayload`、endpoint MTU 或速率上限之间的边界检查；超长包
  必须丢弃并计数，绝不能静默截断。

## 安全与健壮性

- 将 raw ICMP、UDP 控制/数据面和 loopback UDP 都视为不可信输入。每次读取后先
  校验长度，再访问字段；禁止按未经验证的 IHL、总长度或 payload length
  切片。
- 必须同时验证外层和 quoted IPv4/UDP tuple，以及 magic、版本、session 和
  MAC，才能向 endpoint adapter 投递数据。
- MAC 比较使用常数时间函数；session ID、nonce 和 probe payload 使用
  `crypto/rand`，不使用时间、PID 或递增计数器替代随机值。
- 对无效包只计数和有限日志，不能回显任意内容，不能成为反射器。
- 保持控制 UDP socket unconnected；关联 ICMP 可能表现为异步 UDP 错误，
  不能因此停止控制面。
- 最小化权限。运行时只需要 `CAP_NET_RAW`；除非新增隔离所必需的功能，
  不要引入 `CAP_NET_ADMIN`、防火墙变更或策略路由。

## 并发与性能

- 状态机只在 `engine` 事件循环中改变；读 goroutine 只生产事件，不能直接
  修改 session、remote tuple 或统计。
- 不要每个报文创建 goroutine。高 PPS 优化应优先使用有界队列、buffer pool
  和批量 I/O，并以 profile 和跨主机测试证明收益。
- 限速必须覆盖所有 ICMP 和 UDP data 发送，包括 probe；`PUWC` 控制消息不
  纳入该限速，因为它负责维持 NAT 状态。
- 性能优化不能绕过 MAC、长度、tuple 或 session 校验。先保护边界，再减少
  分配和 syscall 开销。

## 变更流程

1. 先阅读相关代码和 [架构文档](architecture.md)、[协议文档](protocol.md)。
2. 写出行为变化、兼容性影响、风险和验证方式；范围不明确时先澄清。
3. 实现最小范围变更，并添加针对新行为或回归的单元测试。
4. 执行本地质量门槛；涉及 NAT、raw socket、会话或 WireGuard 时按
   [测试规范](testing.md) 做隔离联调。
5. 更新 README 和受影响的文档，记录已知限制，不把未验证的网络行为写成
   保证。
