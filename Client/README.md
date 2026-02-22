# Campofinale 生产服务器客户端

完整的Python游戏客户端实现，支持：
- ✅ 配置自动拉取与解密（AES-CBC）
- ✅ 鹰角通行证扫码登录
- ✅ Unity用户认证
- ✅ TCP加密通信
  - SRSA登录数据加密
  - XXE1会话加密（AES-CTR + HMAC-SHA256）
- ✅ 服务器选择与角色管理

## 目录结构

```
Client/
├── config/              # 配置模块
│   ├── get_config.py   # 配置获取与解密
│   └── __init__.py
├── login/               # 登录模块
│   ├── login.py        # HTTP鉴权流程
│   └── __init__.py
├── tcp/                 # TCP通信模块
│   ├── tcp.py          # TCP客户端
│   ├── srsa_bridge.py  # SRSA加密桥接
│   ├── xxe1.py         # XXE1会话加密
│   └── __init__.py
├── main.py             # 主入口
├── requirements.txt    # Python依赖
└── README.md           # 本文件
```

## 环境要求

- Python 3.9+
- Windows (用于GameAssembly.dll支持)
- 游戏客户端文件（用于SRSA加密）

## 安装

```bash
# 安装依赖
pip install -r requirements.txt
```

### requirements.txt

```
httpx==0.24.0
cryptography==41.0.0
```

## 使用方法

### 完整流程（配置获取 → 登录 → TCP连接）

```bash
python main.py --dll-dir . --config-dir ./config_cache
```

### 跳过配置获取（仅登录）

```bash
python main.py --dll-dir . --skip-config
```

### 加载已保存的会话

```bash
python main.py --dll-dir . --load-session session.json
```

### 并保存会话

```bash
python main.py --dll-dir . --save-session session.json
```

### 海外版本

```bash
python main.py --dll-dir . --oversea
```

## 工作流程

### 阶段1：配置获取

1. 从 `launcher.hypergryph.com` 获取启动器版本
2. 从CDN下载U8配置并解密（AES-CBC）
3. 从 `game-config.hypergryph.com` 获取：
   - 引擎配置 (engine_config)
   - 网络配置 (network_config) - AES-CBC解密
   - 游戏配置 (game_config) - AES-CBC解密

**输出**: `config_cache/` 下的JSON文件

### 阶段2：HTTP鉴权

#### 2.1 鹰角通行证登录 (as.hypergryph.com)
- `POST /general/v1/gen_scan/login` → 获取二维码ID
- `GET /general/v1/scan_status` → 轮询扫码状态
- `POST /user/auth/v1/token_by_scan_code` → 获取token
- `POST /user/oauth2/v2/grant` → OAuth2授权

**输出**: passport_token, passport_uid, oauth_code

#### 2.2 Unity用户认证 (u8.hypergryph.com)
- `POST /u8/user/auth/v2/token_by_channel_token` → Unity鉴权
- `POST /game/server/v1/server_list` → 获取服务器列表
- `POST /u8/user/auth/v2/grant` → 获取grant授权码

**输出**: u8_token, u8_uid, u8_grant_code, server_info

### 阶段3：TCP连接

1. **连接**: 建立TCP连接到服务器
2. **SRSA加密登录**: 使用GameAssembly.dll加密登录消息体
3. **会话加密初始化**: 从ScLogin响应中提取密钥建立XXE1会话
4. **心跳保活**: 定期发送心跳包

## 关键加密流程

### SRSA加密（登录）

```
明文消息体
    ↓
[SRSA Bridge] bridge.encrypt_login_body()
    ↓
加密二进制数据
    ↓
TCP发送 (cmd=50001)
```

### XXE1加密（会话）

```
明文数据包
    ↓
计数器递增
    ↓
派生加密密钥: HMAC-SHA256(mainkey, counter || "enc")
派生认证密钥: HMAC-SHA256(mainkey, counter || "auth")
    ↓
AES-CTR加密
    ↓
HMAC-SHA256认证标签
    ↓
发送: [计数器] + [密文] + [标签]
```

## 会话数据格式

```json
{
  "passport": {
    "token": "鹰角通行证token",
    "hg_id": "鹰角通行证ID",
    "device_token": "设备token",
    "uid": "鹰角通行证UID"
  },
  "u8": {
    "token": "Unity token",
    "uid": "游戏UID",
    "grant_code": "TCP登录授权码"
  },
  "server": {
    "id": "服务器ID",
    "host": "服务器主机",
    "port": 30000,
    "role_id": "角色ID",
    "nickname": "角色昵称"
  }
}
```

## API端点

### 生产环境

| 服务 | 地址 | 用途 |
|------|------|------|
| 启动器 | https://launcher.hypergryph.com | 版本检查 |
| 游戏配置 | https://game-config.hypergryph.com | 配置下载 |
| 鹰角通行证 | https://as.hypergryph.com | 扫码登录 |
| Unity认证 | https://u8.hypergryph.com | 用户鉴权 |

## 消息ID (CsMsgId / ScMsgId)

| ID | 类型 | 用途 |
|----|------|------|
| 50001 | CS/SC | 登录消息 |
| 50010 | SC | 错误通知 |
| 50100 | CS | 心跳包 |

## 故障排查

### 问题：GameAssembly.dll不存在

**解决**: 将游戏客户端的GameAssembly.dll复制到 `--dll-dir` 目录，或使用 `--skip-dll` 使用模拟加密

### 问题：OAuth授权失败

**原因**: 扫码二维码时未确认登录
**解决**: 在弹出的二维码界面完成认证

### 问题：TCP连接超时

**原因**: 网络问题或服务器离线
**解决**: 检查网络连接和服务器地址

## 高级功能

### 自定义加密实现

可以替换 `srsa_bridge.py` 中的SRSA实现：

```python
from tcp.srsa_bridge import SRSABridge

class CustomSRSA(SRSABridge):
    def encrypt_login_body(self, plain: bytes) -> bytes:
        # 自定义加密逻辑
        pass
```

### 会话管理

```python
# 保存会话
client.save_session("my_session.json")

# 加载会话（跳过HTTP鉴权）
python main.py --load-session my_session.json
```

## 许可证

MIT License

## 相关资源

- [Campofinale 服务器项目](https://git.teamstardust.org/Campofinale/Campofinale)
- [游戏资源包](https://git.teamstardust.org/Campofinale/EndfieldData)
- [Discord社区](https://discord.gg/HdXZY2Q9vs)
