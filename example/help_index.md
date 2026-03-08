# 总览

## 入口流程

config 拉配置 → login 走 HTTP 鉴权/选服 → tcp 建立长连 → 插件启动，代码入口在 endfield/endfield.py:23、endfield/endfield.py:32。
配置阶段会请求 launcher/game-config，并做本地解密与缓存，见 endfield/config/get_config.py:149、endfield/config/get_config.py:58、endfield/config/get_config.py:72。
登录阶段是 HTTPS 接口链（as.hypergrpyh + u8），最终拿到 server_select.servers 供 TCP 连接，见 endfield/login/tcp/login.py:15、endfield/login/login/login.py:573、endfield/login/tcp/login.py:640。

## 加密调用时机（重点）

配置解密（HTTP配置层）：network_config/game_config 文本按 AES-CBC 解密在 endfield/config/get_config.py:58；bridge.encrypt_login_body（endfield/tcp/tcp.py:1236，实现见 endfield/tcp/srsa_bridge.py:56），最后封包发送 cmd=13（endfield/tcp/tcp.py:1240）。
ScLogin 接收后（TCP登录回包）：首包先按明文帧读取（endfield/tcp/tcp.py:1245），若识别 SRSA 头则拼包并解密 bridge.decrypt_login_body（endfield/tcp/tcp.py:1268、endfield/tcp/tcp.py:1334，实现见 endfield/tcp/srsa_bridge.py:81）。
登录成功后（会话流加密）：从 ScLogin.server_public_key/server_encryp_nonce 导出会话参数，初始化 XXE1 收发器（endfield/tcp/tcp.py:663、endfield/tcp/tcp.py:691；算法在 endfield/tcp/xxe1.py:29）。
会话期每包时机：发送时仅加密 Packet 的 payload（前3字节长度头不加密），见 endfield/tcp/tcp.py:813、endfield/tcp/tcp.py:825；接收时先按3字节头切包，再解密 payload，见 endfield/tcp/tcp.py:852、endfield/tcp/tcp.py:857。
校验/压缩时机：CRC32 在解密后校验（endfield/tcp/tcp.py:1117）；is_compress 为真时在解密后再做 LZ4 解压（endfield/tcp/tcp.py:696、endfield/tcp/tcp.py:736）。

## 插件网络层（本地 HTTP 与游戏 TCP 的关系）

插件系统强制 http_api 优先加载，供其它插件注册路由，见 endfield/plugin_system.py:103、endfield/plugin_system.py:115。
本地 HTTP 统一由 http_api 承担，含 Bearer 校验与访问日志分桶，见 endfield/plugins/http_api/http_api.py:219、endfield/plugins/http_api/http_api.py:247、endfield/plugins/http_api/http_api.py:199。
friend_api/blueprint_api 只注册路由，实际通过 runtime 在同一条 TCP 长连上发 Cs*、等 Sc*，见 endfield/plugins/friend_api/friend_api.py:105、endfield/plugins/friend_api/friend_api.py:3888、endfield/plugins/blueprint_api/blueprint_api.py:125、endfield/plugins/blueprint_api/blueprint_api.py:182。
