"""
TCP登录流程（已对齐 makeback 版本）

关键点：
- 使用 Hg 协议包格式：HeadLen(1) + BodyLen(2, 小端) + CSHead + CsLogin
- 登录消息 msgId=13
- CsLogin 字段布局与 makeback 一致
"""

from __future__ import annotations

import asyncio
import logging
import struct
from typing import Any, Iterator, Optional

from .srsa_bridge import SRSABridge

logger = logging.getLogger(__name__)

SRSA_MAGIC = b"\x05\x0f\x09\x0c"

ERROR_CODES = {
    -1: "ErrUnknown",
    0: "ErrSuccess",
    40: "ErrLoginTokenInvalid",
    41: "ErrLoginMsgFormatInvalid",
    42: "ErrLoginProcessLogin",
    44: "ErrCommonPlatformInvalid",
}


def encode_varint(value: int) -> bytes:
    if value < 0:
        raise ValueError("varint value must be >= 0")
    out = bytearray()
    while value > 0x7F:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def encode_tag(field_number: int, wire_type: int) -> bytes:
    return encode_varint((field_number << 3) | wire_type)


def encode_string(field_number: int, value: str | bytes) -> bytes:
    if isinstance(value, str):
        raw = value.encode("utf-8")
    else:
        raw = value  # bytes
    return encode_tag(field_number, 2) + encode_varint(len(raw)) + raw


def encode_bool(field_number: int, value: bool) -> bytes:
    return encode_tag(field_number, 0) + encode_varint(1 if value else 0)


def encode_uint32(field_number: int, value: int) -> bytes:
    return encode_tag(field_number, 0) + encode_varint(value & 0xFFFFFFFF)


def encode_uint64(field_number: int, value: int) -> bytes:
    return encode_tag(field_number, 0) + encode_varint(value & 0xFFFFFFFFFFFFFFFF)


def decode_varint(data: bytes, offset: int = 0) -> tuple[int, int]:
    value = 0
    shift = 0
    i = offset
    while i < len(data):
        b = data[i]
        i += 1
        value |= (b & 0x7F) << shift
        if (b & 0x80) == 0:
            return value, i
        shift += 7
        if shift > 63:
            raise ValueError("varint too long")
    raise ValueError("incomplete varint")


def iter_fields(data: bytes) -> Iterator[tuple[int, int, bytes | int]]:
    i = 0
    while i < len(data):
        tag, i = decode_varint(data, i)
        field_no = tag >> 3
        wire = tag & 0x7
        if wire == 0:
            value, i = decode_varint(data, i)
            yield field_no, wire, value
        elif wire == 2:
            n, i = decode_varint(data, i)
            end = i + n
            if end > len(data):
                raise ValueError("field length overflow")
            yield field_no, wire, data[i:end]
            i = end
        elif wire == 5:
            end = i + 4
            if end > len(data):
                raise ValueError("fixed32 overflow")
            yield field_no, wire, data[i:end]
            i = end
        elif wire == 1:
            end = i + 8
            if end > len(data):
                raise ValueError("fixed64 overflow")
            yield field_no, wire, data[i:end]
            i = end
        else:
            raise ValueError(f"unsupported wire type: {wire}")


def _resolve_launcher_version(ctx: dict[str, Any]) -> str:
    return str(ctx.get("client_version") or ctx.get("launcher_version") or "1.0.13")


def _resolve_online_res_version(ctx: dict[str, Any]) -> str:
    return str(ctx.get("res_version") or _resolve_launcher_version(ctx))


def generate_rsa_keypair() -> tuple[bytes, bytes]:
    """
    生成 RSA 密钥对
    
    Returns:
        (公钥 PEM, 私钥 PEM) 字节串
    """
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.backends import default_backend
    
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    public_key = private_key.public_key()
    
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    return public_pem, private_pem


def build_device_info(ctx: dict[str, Any]) -> bytes:
    """
    构建 DEVICE_INFO 消息 (field 17)
    根据 Il2CppInspector 解析的 DEVICE_INFO 结构
    """
    device_info = ctx.get("device_info", {})
    
    # 从上下文或配置中获取设备信息
    device_id = str(device_info.get("device_id", "5be137815cd88139ea5afa89d3e3c913"))
    os = str(device_info.get("os", "Windows"))
    os_ver = str(device_info.get("os_ver", "10.0.19045"))
    brand = str(device_info.get("brand", "Microsoft"))
    model = str(device_info.get("model", "PC"))
    simulator = str(device_info.get("simulator", ""))
    network = str(device_info.get("network", "Ethernet"))
    carrier = str(device_info.get("carrier", ""))
    language = str(device_info.get("language", "zh-CN"))
    country_iso_code = str(device_info.get("country_iso_code", "CN"))
    ipv4 = int(device_info.get("ipv4", 0))
    client_res_version = str(device_info.get("client_res_version", ctx.get("res_version", "1.0.14")))
    
    msg = b""
    msg += encode_string(1, device_id)
    msg += encode_string(2, os)
    msg += encode_string(3, os_ver)
    msg += encode_string(4, brand)
    msg += encode_string(5, model)
    if simulator:
        msg += encode_string(6, simulator)
    if network:
        msg += encode_string(7, network)
    if carrier:
        msg += encode_string(8, carrier)
    if language:
        msg += encode_string(9, language)
    if country_iso_code:
        msg += encode_string(10, country_iso_code)
    if ipv4 != 0:
        msg += encode_uint64(11, ipv4)
    msg += encode_string(12, client_res_version)
    
    return msg


def build_cs_login_body(ctx: dict[str, Any]) -> tuple[bytes, dict[str, Any]]:
    launcher_version = _resolve_launcher_version(ctx)
    online_res_version = _resolve_online_res_version(ctx)

    uid = str(ctx.get("uid") or "")
    token = str(ctx.get("token") or ctx.get("grant_code") or "")
    platform_id = int(ctx.get("platform_id", 3))
    area = int(ctx.get("area", 2))
    env = int(ctx.get("env", 2))
    client_language = int(ctx.get("client_language", 0))
    channel = str(ctx.get("channel") or "official")
    
    # 获取或生成 RSA 密钥对
    client_public_key = ctx.get("client_public_key")
    client_private_key = ctx.get("client_private_key")
    
    if client_public_key is None:
        client_public_key, client_private_key = generate_rsa_keypair()
        ctx["client_public_key"] = client_public_key
        ctx["client_private_key"] = client_private_key

    msg = b""
    # 按字段号顺序编码（protobuf 标准要求）
    # field 1: A14 (string) - channel 渠道
    msg += encode_string(1, channel)
    # field 2: A7 (string) - online_res_version 资源版本
    msg += encode_string(2, online_res_version)
    # field 3: A6 (string) - launcher_version 包体版本
    msg += encode_string(3, launcher_version)
    # field 4: A13 (string) - 未知字符串
    msg += encode_string(4, "")
    # field 5: A1 (string) - uid
    msg += encode_string(5, uid)
    # field 6: A2 (string) - token
    msg += encode_string(6, token)
    # field 7: A8 (ByteString) - client_public_key RSA 公钥
    public_key_str = client_public_key.decode('utf-8')
    logger.info(f"[SRSA] RSA 公钥长度：{len(public_key_str)}")
    msg += encode_string(7, public_key_str)
    # field 8: A9 (CLIENT_PLATFORM_TYPE) - platform_id
    msg += encode_uint32(8, platform_id)
    # field 9: A10 (AREA_TYPE) - area
    msg += encode_uint32(9, area)
    # field 10: A12 (int) - 未知整数
    msg += encode_uint32(10, 0)
    # field 11: A5 (ulong) - 未知
    msg += encode_uint64(11, 0)
    # field 12: A11 (ENV_TYPE) - env
    msg += encode_uint32(12, env)
    # field 13: A21 (int) - channel_id
    msg += encode_uint32(13, 1)
    # field 14: A22 (int) - sub_channel
    msg += encode_uint32(14, 0)
    # field 15: A4 (int) - 未知整数
    msg += encode_uint32(15, 0)
    # field 16: ClientLanguage (int) - 客户端语言
    msg += encode_uint32(16, client_language)
    # field 17: A23 (DEVICE_INFO) - 设备信息
    device_info_bytes = build_device_info(ctx)
    msg += encode_string(17, device_info_bytes)

    meta = {
        "channel": channel,
        "client_res_version": online_res_version,
        "client_version": launcher_version,
        "uid": uid,
        "token_len": len(token),
        "platform_id": platform_id,
        "area": area,
        "env": env,
        "client_language": client_language,
        "public_key_len": len(public_key_str),
        "device_info_len": len(device_info_bytes),
        "body_len": len(msg),
    }
    return msg, meta


def build_cs_head(msgid: int, up_seqid: int, down_seqid: int = 0) -> bytes:
    msg = b""
    msg += encode_uint32(1, msgid)
    msg += encode_uint64(2, up_seqid)
    if down_seqid != 0:
        msg += encode_uint64(3, down_seqid)
    msg += encode_uint32(4, 1)
    msg += encode_uint32(5, 0)
    msg += encode_bool(6, False)
    return msg


def build_tcp_packet(msgid: int, body: bytes, seq_id: int) -> bytes:
    cs_head = build_cs_head(msgid, seq_id)
    head_len = len(cs_head)
    body_len = len(body)

    packet = bytearray()
    packet.append(head_len)
    packet.extend(struct.pack("<H", body_len))
    packet.extend(cs_head)
    packet.extend(body)
    return bytes(packet)


def _is_srsa_encrypted(data: bytes) -> bool:
    # 避免仅靠4字节魔数误判，增加最小长度约束
    return len(data) >= 12 and data[:4] == SRSA_MAGIC


def _parse_sc_login(data: bytes) -> dict[str, Any]:
    out: dict[str, Any] = {}
    try:
        for field_no, wire, value in iter_fields(data):
            if wire == 2 and isinstance(value, bytes):
                if field_no == 1:
                    out["uid"] = value.decode("utf-8", errors="replace")
                elif field_no == 2:
                    out["login_token"] = value.decode("utf-8", errors="replace")
                elif field_no == 3:
                    out["server_public_key"] = value.hex()
                elif field_no == 4:
                    out["server_encryp_nonce"] = value.hex()
            elif wire == 0 and isinstance(value, int):
                if field_no == 5:
                    out["is_client_reconnect"] = bool(value)
                elif field_no == 6:
                    out["is_first_login"] = bool(value)
                elif field_no == 7:
                    out["is_reconnect"] = bool(value)
                elif field_no == 8:
                    out["server_time"] = value
    except Exception as exc:
        out["parse_error"] = str(exc)
    return out


def _parse_error_response(data: bytes) -> dict[str, Any]:
    out: dict[str, Any] = {}
    try:
        for field_no, wire, value in iter_fields(data):
            if wire == 0 and isinstance(value, int) and field_no == 1:
                out["error_code"] = value
            elif wire == 2 and isinstance(value, bytes) and field_no == 2:
                out["details"] = value.decode("utf-8", errors="replace")
    except Exception:
        pass
    return out


class TCPClient:
    """TCP客户端（对齐 makeback 登录流程）"""

    def __init__(
        self,
        host: str,
        port: int,
        grant_code: str,
        srsa_bridge: Optional[SRSABridge] = None,
        timeout: float = 30.0,
        config_ctx: Optional[dict] = None,
    ):
        self.host = host
        self.port = port
        self.grant_code = grant_code
        self.srsa_bridge = srsa_bridge
        self.timeout = timeout
        self.config_ctx = config_ctx or {}

        self.reader: Optional[asyncio.StreamReader] = None
        self.writer: Optional[asyncio.StreamWriter] = None
        self._seq_id = 1
        self.login_parsed: dict[str, Any] = {}

    async def connect(self) -> bool:
        try:
            self.reader, self.writer = await asyncio.wait_for(
                asyncio.open_connection(self.host, self.port),
                timeout=self.timeout,
            )
            logger.info(f"[TCP] 连接成功: {self.host}:{self.port}")
            return True
        except Exception as e:
            logger.error(f"[TCP] 连接失败: {e}")
            return False

    def disconnect(self) -> None:
        if self.writer:
            self.writer.close()
        logger.info("[TCP] 已断开连接")

    async def _read_exact(self, n: int) -> bytes:
        if not self.reader:
            raise RuntimeError("未连接")
        return await self.reader.readexactly(n)

    async def _write(self, data: bytes) -> None:
        if not self.writer:
            raise RuntimeError("未连接")
        self.writer.write(data)
        await self.writer.drain()

    async def send_login_request(self) -> dict[str, Any]:
        # 尝试使用不同的 token 格式
        # 根据 HandleCsLogin.cs，服务器使用 req.Token 查找账户
        # 可能需要使用 U8 token 而不是 grant_code
        ctx = {
            "uid": "",
            "token": self.grant_code,  # 先尝试使用 grant_code
            "grant_code": self.grant_code,
            "platform_id": 3,
            "area": 2,
            "env": 2,
        }
        # 合并配置上下文
        ctx.update(self.config_ctx)
        
        logger.info(f"[TCP] 使用 grant_code 作为 token (长度：{len(self.grant_code)})")
        cs_body, body_meta = build_cs_login_body(ctx)

        msgid = 13
        seq_id = self._seq_id
        self._seq_id += 1
        packet = build_tcp_packet(msgid, cs_body, seq_id)

        parsed: dict[str, Any] = {
            "send_mode": "hg_protocol",
            "cs_login_meta": body_meta,
            "packet_len": len(packet),
            "packet_hex_head": packet[:32].hex(),
            "msgid": msgid,
            "seq_id": seq_id,
        }

        logger.info(f"[TCP] 发送登录包：msgid={msgid}, seq={seq_id}, len={len(packet)}")
        logger.info(f"[TCP] CsLogin 字段：{body_meta}")
        logger.info(f"[TCP] CsBody 完整十六进制：{cs_body.hex()}")
        
        # 详细解析并打印每个字段
        logger.info("[TCP] CsLogin 字段详细解析：")
        try:
            for field_no, wire, value in iter_fields(cs_body):
                if wire == 2 and isinstance(value, bytes):
                    # 尝试解码为字符串
                    try:
                        str_val = value.decode('utf-8')
                        if len(str_val) > 100:
                            str_val = str_val[:100] + "..."
                        logger.info(f"  Field {field_no} (string/bytes, len={len(value)}): {str_val}")
                    except:
                        logger.info(f"  Field {field_no} (bytes, len={len(value)}): {value[:32].hex()}...")
                elif wire == 0:
                    logger.info(f"  Field {field_no} (varint): {value}")
        except Exception as e:
            logger.warning(f"[TCP] 字段解析失败: {e}")
        
        await self._write(packet)

        header = await self._read_exact(3)
        head_len = header[0]
        body_len = struct.unpack("<H", header[1:3])[0]
        remaining = await self._read_exact(head_len + body_len)
        resp = header + remaining

        parsed["resp_len"] = len(resp)
        parsed["resp_hex_head"] = resp[:32].hex()
        parsed["resp_hex_full"] = resp.hex()
        parsed["resp_head_len"] = head_len
        parsed["resp_body_len"] = body_len

        if len(resp) >= 3 + head_len + body_len:
            resp_body = resp[3 + head_len:3 + head_len + body_len]
            parsed["resp_body_hex_head"] = resp_body[:32].hex()
            parsed["resp_body_hex_full"] = resp_body.hex()

            if _is_srsa_encrypted(resp_body) and self.srsa_bridge is not None:
                parsed["response_encrypted"] = True
                try:
                    resp_body = self.srsa_bridge.decrypt_login_body(resp_body)
                    parsed["decrypted_len"] = len(resp_body)
                    parsed["decrypted_hex_head"] = resp_body[:48].hex()
                except Exception as e:
                    parsed["decrypt_error"] = str(e)

            # 先尝试解析错误响应
            error_info = _parse_error_response(resp_body)
            logger.info(f"[TCP] 响应解析结果：error_info={error_info}")
            logger.info(f"[TCP] 响应完整十六进制：{resp_body.hex()}")
            
            if error_info.get("error_code") is not None:
                err_code = int(error_info["error_code"])
                parsed["error_code"] = err_code
                parsed["error_name"] = ERROR_CODES.get(err_code, f"Unknown({err_code})")
                parsed["error_details"] = error_info.get("details", "")
            else:
                sc_login = _parse_sc_login(resp_body)
                if sc_login:
                    parsed["sc_login"] = sc_login
                else:
                    logger.warning(f"[TCP] 无法解析响应：{resp_body.hex()}")

        self.login_parsed = parsed
        return parsed

    async def send_message(self, msg_id: int, body_data: bytes, encrypt: bool = True) -> None:
        _ = encrypt
        packet = build_tcp_packet(msg_id, body_data, self._seq_id)
        self._seq_id += 1
        await self._write(packet)


async def tcp_login_flow(
    host: str,
    port: int,
    grant_code: str,
    srsa_bridge: Optional[SRSABridge] = None,
    config_ctx: Optional[dict] = None,
) -> Optional[TCPClient]:
    client = TCPClient(host, port, grant_code, srsa_bridge, config_ctx=config_ctx)

    if not await client.connect():
        return None

    try:
        parsed = await client.send_login_request()
        if parsed.get("error_code") is not None:
            logger.error(
                f"[TCP] 登录失败: {parsed.get('error_name')}({parsed.get('error_code')}), "
                f"details={parsed.get('error_details', '')}"
            )
            return None

        if parsed.get("sc_login"):
            logger.info("[TCP] 登录成功（收到ScLogin）")
            return client

        logger.error("[TCP] 未识别的登录响应")
        return None
    except Exception as e:
        logger.error(f"[TCP] 登录流程异常: {e}")
        client.disconnect()
        return None
