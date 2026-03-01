"""
集成总结与架构说明
"""

# Campofinale 生产服务器客户端 - 集成架构

## 项目结构

```
Hg/
├── Campofinale/                    # 【服务器】核心游戏服务器
│   ├── Http/                       # HTTP分发服务
│   │   ├── SDK.cs                 # ✗ 已替换为 Client/login/
│   │   ├── Dispatch.cs            # ✗ 已被 Client 代替
│   │   └── ...
│   ├── Network/                    # 网络协议
│   ├── Packets/                    # 数据包处理
│   │   └── Cs/HandleCsLogin.cs    # ← 客户端登录包在此处理
│   └── ...
│
└── Client/                         # 【客户端】新增 - 生产环境客户端实现
    ├── config/                     # 配置获取与解密
    │   ├── get_config.py          # ✅ 自动拉取launcher/game-config
    │   │                          # ✅ AES-CBC解密（支持CN/Oversea）
    │   └── __init__.py
    │
    ├── login/                      # HTTP认证流程
    │   ├── login.py               # ✅ 完整登录流程
    │   │                          # ✅ 鹰角通行证扫码 (as.hypergryph.com)
    │   │                          # ✅ Unity用户认证 (u8.hypergryph.com)
    │   │                          # ✅ 服务器选择与grant授权码
    │   └── __init__.py
    │
    ├── tcp/                        # TCP通信与加密
    │   ├── tcp.py                 # ✅ TCP客户端实现
    │   │                          # ✅ 数据包编码/解码
    │   │                          # ✅ XXE1会话加密支持
    │   │
    │   ├── srsa_bridge.py         # ✅ SRSA加密桥接
    │   │                          # ✅ GameAssembly.dll交互
    │   │                          # ✅ 登录消息体加密/解密
    │   │
    │   ├── xxe1.py                # ✅ XXE1会话加密算法
    │   │                          # ✅ AES-CTR加密 + HMAC-SHA256认证
    │   │                          # ✅ 收发计数器管理
    │   └── __init__.py
    │
    ├── main.py                     # ✅ 主入口 - 三阶段登录流程
    ├── requirements.txt            # ✅ 依赖清单
    └── README.md                   # ✅ 使用文档
```

## 工作流程图

```
┌─────────────────────────────────────────────────────────────────┐
│                     完整客户端登录流程                             │
└─────────────────────────────────────────────────────────────────┘

    第1阶段：配置获取
    ─────────────────
    
    launcher.hypergryph.com
        ↓
    /api/game/get_latest
        ↓
    版本信息 + 文件路径
        ↓
    CDN下载 u8ExtraConfig.bin
        ↓
    AES-CBC解密 (密钥固定)
        ↓
    game-config.hypergryph.com
        ↓
    /remote_config/*/engine_config
    /remote_config/*/network_config (AES-CBC加密)
    /remote_config/*/game_config    (AES-CBC加密)
        ↓
    本地保存 → config_cache/
        
    ┌─────────────────────────────────┐
    │  输出：engine/network/game配置  │
    └─────────────────────────────────┘


    第2阶段：HTTP鉴权
    ─────────────────
    
    ┌────────────────────────────────┐
    │ 2.1 鹰角通行证 (as.hypergryph) │
    └────────────────────────────────┘
    
    /general/v1/gen_scan/login
        ↓ 获取二维码ID
    用户扫码确认
        ↓
    /general/v1/scan_status (轮询)
        ↓ 获取scanCode
    /user/auth/v1/token_by_scan_code
        ↓ 获取 {token, hgId, deviceToken}
    /user/oauth2/v2/grant
        ↓ 获取 {uid, oauth_code}
    
    构造 channelToken = {"type":1, "code":"oauth_code"}
    
    ┌──────────────────────────────┐
    │ 2.2 Unity认证 (u8.hypergryph) │
    └──────────────────────────────┘
    
    /u8/user/auth/v2/token_by_channel_token
        ↓ 获取 {u8_token, u8_uid}
    /game/server/v1/server_list
        ↓ 获取 {serverId, serverName, host:port, roleId, nickname}
    /u8/user/auth/v2/grant
        ↓ 获取 {grant_code} ← 关键！用于TCP登录
    /game/role/v1/confirm_server (可选)
    
    ┌─────────────────────────────────┐
    │ 输出：LoginSession（所有凭证）   │
    └─────────────────────────────────┘


    第3阶段：TCP连接与加密
    ──────────────────────
    
    建立Socket连接到 server_host:server_port
        ↓
    
    ┌──────────────────────────────────────────┐
    │ Step 1: 登录消息加密 (SRSA)              │
    ├──────────────────────────────────────────┤
    │ 构建 CsLogin 消息体                       │
    │   - uid: u8_uid                          │
    │   - token: grant_code                    │
    │   - client_version: "0.5.5"              │
    │   - platform_id: Windows(3)              │
    │   - area: Oversea(0)                     │
    │   - env: Prod(2)                         │
    │                                          │
    │ 序列化为Protobuf二进制                    │
    │   ↓                                       │
    │ SRSA加密 (GameAssembly.dll)              │
    │   ↓                                       │
    │ TCP发送 CsLogin (msgId=50001)            │
    └──────────────────────────────────────────┘
        ↓
    
    ┌──────────────────────────────────────────┐
    │ Step 2: 接收登录响应 (ScLogin - SRSA)    │
    ├──────────────────────────────────────────┤
    │ TCP接收数据包                             │
    │   ↓ 识别SRSA头                           │
    │ SRSA解密 (GameAssembly.dll)              │
    │   ↓                                       │
    │ 解析 ScLogin 消息体                       │
    │   - server_public_key                    │
    │   - server_encryp_nonce                  │
    │   - uid                                  │
    │   - server_time                          │
    └──────────────────────────────────────────┘
        ↓
    
    ┌──────────────────────────────────────────┐
    │ Step 3: 初始化会话加密 (XXE1)            │
    ├──────────────────────────────────────────┤
    │ 从ScLogin提取会话参数                     │
    │   - server_public_key                    │
    │   - server_encryp_nonce                  │
    │   ↓                                       │
    │ 派生会话密钥 (SHA256)                     │
    │   ↓                                       │
    │ 初始化XXE1密码器                          │
    │   - 加密：AES-CTR                        │
    │   - 认证：HMAC-SHA256                    │
    │   - 计数器：0                            │
    │                                          │
    │ ← 从此刻开始，所有TCP消息都经过加密      │
    └──────────────────────────────────────────┘
        ↓
    
    ┌──────────────────────────────────────────┐
    │ Step 4: 会话通信 (XXE1每包)              │
    ├──────────────────────────────────────────┤
    │ 发送流程：                                │
    │   明文消息体                              │
    │   ↓                                       │
    │   计数器++                                │
    │   ↓                                       │
    │   派生加密密钥: HMAC(mainkey, counter||enc) │
    │   派生认证密钥: HMAC(mainkey, counter||auth)│
    │   ↓                                       │
    │   AES-CTR加密                            │
    │   ↓                                       │
    │   HMAC-SHA256（密文 + 计数器）            │
    │   ↓                                       │
    │   发送: [3字节长度头] + [计数器||密文||标签]│
    │                                          │
    │ 接收流程：                                │
    │   TCP接收数据                             │
    │   ↓                                       │
    │   读3字节长度头                           │
    │   ↓                                       │
    │   读body (计数器||密文||标签)             │
    │   ↓                                       │
    │   验证HMAC标签                            │
    │   ↓                                       │
    │   派生密钥 + AES-CTR解密                 │
    │   ↓                                       │
    │   明文消息体                              │
    │   ↓                                       │
    │   计数器++                                │
    └──────────────────────────────────────────┘
        ↓
    
    ✅ 全程通信已加密，游戏进程启动
```

## 关键改进点

### 1. HTTP认证 → 生产系统

| 维度 | 原始 | 改进 |
|------|------|------|
| **认证源** | SDK.cs (本地123) | 鹰角通行证 + Unity (官方认证) |
| **配置** | 硬编码 | 动态拉取 + 解密缓存 |
| **服务发现** | 固定IP | 动态获取服务器列表 |
| **安全性** | 明文token | OAuth2授权码 + grant校验 |

### 2. TCP加密

| 维度 | 登录阶段 | 会话阶段 |
|------|---------|---------|
| **加密算法** | SRSA (RSA + 对称) | XXE1 (AES-CTR + HMAC) |
| **密钥来源** | GameAssembly.dll | ScLogin响应 |
| **计数器** | 单次 | 每包递增 |
| **认证** | SRSA内置 | HMAC-SHA256 |

### 3. 会话管理

```python
# 会话保存
client.save_session("session.json")
↓
# 后续复用（跳过HTTP鉴权）
python main.py --load-session session.json
```

## 开发要点

### 必需依赖

- `httpx`: 异步HTTP客户端
- `cryptography`: AES/HMAC算法
- `GameAssembly.dll`: SRSA加密桥接

### 异步架构

```python
# 所有网络操作均为异步
async def complete_login_flow():
    passport = PassportLogin()
    passport_data = await passport.login()  # 鹰角登录
    
    u8 = U8Login()
    u8_data = await u8.token_by_channel_token(...)  # Unity认证
    
    # TCP连接和心跳可并行运行
    tcp_client = await tcp_login_flow(...)
    asyncio.ensure_future(tcp_client.keep_alive())  # 后台心跳
```

### 日志系统

```python
import logging
logger = logging.getLogger(__name__)

# 分级日志
logger.info("[Client] 登录完成")          # 关键事件
logger.debug("[TCP] 发送包...")           # 调试信息
logger.error("[SRSA] 加密失败")           # 错误
```

## 生产部署

### 环境检查清单

- ✅ Python 3.9+
- ✅ 网络可访问生产API (as.hypergryph.com, u8.hypergryph.com等)
- ✅ GameAssembly.dll位于 `--dll-dir`
- ✅ 配置缓存目录可写
- ✅ 服务器地址可访问

### 配置建议

```bash
# 开发环境
python main.py --dll-dir . --skip-config --oversea

# 生产环境（CN）
python main.py --dll-dir "/path/to/game" --config-dir "/var/cache/game"

# 生产环境（Oversea）
python main.py --dll-dir "/path/to/game" --config-dir "/var/cache/game" --oversea
```

## 扩展点

### 1. 自定义加密实现

在 `tcp/srsa_bridge.py` 中替换SRSA实现为其他加密方法

### 2. 消息处理

在 `tcp/tcp.py` 中添加消息类型处理器

### 3. 会话持久化

实现数据库或文件系统会话存储

## 相关文件映射

| 源文件 | 客户端实现 | 功能 |
|--------|----------|------|
| example/get_config.py | Client/config/get_config.py | ✅ 配置拉取与解密 |
| example/666.md | Client/login/login.py | ✅ 登录流程 |
| example/srsa_bridge.py | Client/tcp/srsa_bridge.py | ✅ SRSA加密 |
| 无 | Client/tcp/xxe1.py | ✅ 会话加密 |
| 无 | Client/tcp/tcp.py | ✅ TCP通信 |

## 下一步计划

- [ ] Protobuf消息完整实现（使用protobuf库）
- [ ] 心跳包完整处理
- [ ] 角色数据同步（ScSyncBaseData等）
- [ ] 地图加载和移动指令
- [ ] 战斗系统集成
- [ ] 插件系统接口

---

**最后更新**: 2026年2月22日
**维护者**: Campofinale项目
**许可证**: MIT
