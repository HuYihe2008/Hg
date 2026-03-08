# TCP 30000 登录抓包分析报告

## 1. 分析对象

- 抓包文件：`tcp==30000.pcap`
- 目标流：`tcp.stream == 137`
- 客户端：`192.168.5.18:6548`
- 服务端：`47.117.245.217:30000`
- 现象：自建 TCP 发包服务收到错误码 **41**

仓库内 `endfield/tcp/tcp.py:26` 已定义错误码：

- `41 = ErrLoginMsgFormatInvalid`

这说明服务器判定：**登录消息格式不合法**。

---

## 2. 正常登录首包（抓包证据）

正常客户端登录时，第一组关键发送包是：

### 2.1 首个请求头包

- 帧号：`3507`
- 长度：`11` 字节
- 十六进制：

```text
08 20 05 08 0d 38 eb ac ba cc 01
```

按协议拆分：

```text
08                -> head_len = 8
20 05             -> body_len = 0x0520 = 1312 (小端)
08 0d             -> field 1 = msgid = 13
38 eb ac ba cc 01 -> field 7 = checksum = 428775019
```

结论：**正常登录首包头部只包含两个字段：**

- `field 1 = msgid = 13`
- `field 7 = checksum = 428775019`

也就是说，正常 `CSHead` 为：

```text
08 0d 38 eb ac ba cc 01
```

### 2.2 紧随其后的登录 body

- 帧号：`3508`
- 长度：`1312` 字节
- 开头：

```text
05 0f 09 0c ...
```

该前缀与仓库中的 `SRSA_MAGIC = 05 0f 09 0c` 一致，说明：

- 登录 body 是 **SRSA 加密数据**
- 前面的 `body_len = 1312` 与实际 body 长度一致

因此，**正常登录格式是：先发 3+8 字节头，再发 1312 字节 SRSA body**。

---

## 3. 当前代码实际构包方式

当前实现位于：`endfield/tcp/tcp.py:696`

登录时调用：

- `build_tcp_packet(..., seq_id=1, checksum=428775019, force_emit_checksum=True, body_len_override=len(cs_body))`

而 `build_tcp_packet` 会进入：

- `endfield/tcp/tcp.py:502`
- `_build_cs_head` 位于 `endfield/tcp/tcp.py:476`

其中 `_build_cs_head` 默认会写入：

- `field 1 = msgid`
- `field 2 = up_seqid`
- `field 4 = total_pack_count`
- `field 7 = checksum`

也就是说，当前代码生成的首包头为：

```text
0c 20 05 08 0d 10 01 20 01 38 eb ac ba cc 01
```

拆分如下：

```text
0c                -> head_len = 12
20 05             -> body_len = 1312
08 0d             -> field 1 = msgid = 13
10 01             -> field 2 = up_seqid = 1
20 01             -> field 4 = total_pack_count = 1
38 eb ac ba cc 01 -> field 7 = checksum = 428775019
```

---

## 4. 正常包 vs 当前代码构包 对比

### 4.1 正常首包

```text
08 20 05 08 0d 38 eb ac ba cc 01
```

### 4.2 当前代码首包

```text
0c 20 05 08 0d 10 01 20 01 38 eb ac ba cc 01
```

### 4.3 差异点

当前代码 **多发了两个字段**：

- `field 2 = up_seqid = 1`
- `field 4 = total_pack_count = 1`

并导致：

- `head_len` 从正常的 `8` 变成了 `12`

这和抓包中的正常登录包 **不一致**。

---

## 5. 为什么这会触发错误 41

错误 `41 = ErrLoginMsgFormatInvalid`，语义非常直接：

- 不是 token 错误
- 不是平台错误
- 而是 **登录消息格式错误**

从抓包来看：

1. `msgid=13` 是对的
2. `checksum=428775019` 是对的
3. `body_len=1312` 和 body 分离发送方式是对的
4. `body` 开头是 `SRSA_MAGIC`，这一点也对

目前最明确、最可证实的格式错误点就是：

> **登录首包的 CSHead 发多了字段 2 和字段 4，导致头结构与官方客户端不一致。**

这正符合服务器返回 `41` 的原因。

---

## 6. 已确认正确的部分

以下内容从抓包和代码对比看，暂时没有发现问题：

- TCP 目标端口：`30000`
- 登录消息号：`msgid = 13`
- 头部长度字段使用 `1 + 2` 字节布局
- `body_len` 使用小端序
- 登录 body 为独立发送的 SRSA 密文
- `checksum = 428775019`

因此，当前问题不是出在：

- TCP 拆包方式
- body_len 字节序
- checksum 常量
- SRSA magic 前缀

---

## 7. 高概率根因

高概率根因是：

> 当前代码复用了“通用业务包头”生成逻辑，把 `up_seqid` / `total_pack_count` 也带进了“登录首包头”。

但从实际抓包看，**登录首包并不是这个格式**，它是一个更瘦的头：

- 只保留 `msgid`
- 再附带 `checksum`

所以当前登录流程应该使用 **专门的登录头构建逻辑**，而不是直接复用通用 `_build_cs_head()`。

---

## 8. 建议修正方向

建议修改 `endfield/tcp/tcp.py:705` 附近的登录构包逻辑：

### 方案 A：为登录专门构建头（推荐）

登录首包只编码：

- `field 1 = msgid`
- `field 7 = checksum`

不要带：

- `field 2 = up_seqid`
- `field 4 = total_pack_count`

### 方案 B：让 `_build_cs_head()` 支持“登录模式”

增加参数，控制以下字段默认不发送：

- `up_seqid`
- `total_pack_count`

但从可维护性看，登录包和会话包建议分开处理，更清晰。

---

## 9. 目前无法仅凭此抓包确认的部分

由于登录 body 是 SRSA 加密数据，仅凭当前这份正常抓包，**还不能 100% 证明** 下列字段是否也存在差异：

- `CsLogin` 明文字段顺序是否完全一致
- `client_public_key` 是否完全一致
- `device_info` 是否完全一致
- 某些可选字段是否应省略

但是：

- 这些属于“下一层”的问题
- **首包头格式错误已经足够解释错误 41**

所以排查优先级应先修正 `CSHead`，再看是否还有后续字段差异。

---

## 10. 最终结论

### 结论一句话

你的 TCP 登录包最明显的问题不是 body，而是 **登录首包头构建错了**。

### 具体错误点

正常客户端首包头只有：

- `msgid=13`
- `checksum=428775019`

而你当前代码额外发送了：

- `up_seqid=1`
- `total_pack_count=1`

导致：

- `head_len` 从 `8` 变成 `12`
- 包头结构与正常游戏客户端不一致
- 服务器返回 `41 = ErrLoginMsgFormatInvalid`

---

## 11. 可直接对照的位置

- 正常错误码定义：`endfield/tcp/tcp.py:26`
- 登录入口：`endfield/tcp/tcp.py:642`
- 当前登录构包调用：`endfield/tcp/tcp.py:705`
- 通用头构建：`endfield/tcp/tcp.py:476`
- TCP 包拼装：`endfield/tcp/tcp.py:502`
- 本报告依据抓包中的关键帧：`3507`、`3508`

