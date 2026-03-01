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

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

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


def encode_string(field_number: int, value: str) -> bytes:
    raw = value.encode("utf-8")
    return encode_tag(field_number, 2) + encode_varint(len(raw)) + raw


def encode_bytes(field_number: int, value: bytes) -> bytes:
    return encode_tag(field_number, 2) + encode_varint(len(value)) + value


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


def _resolve_branch_tag(ctx: dict[str, Any], launcher_version: str) -> str:
    _ = launcher_version
    return str(ctx.get("branch_tag") or ctx.get("a14") or "prod-obt-official")


def _resolve_login_a1_a2(ctx: dict[str, Any]) -> tuple[str, str]:
    if "a1" in ctx or "a2" in ctx:
        return str(ctx.get("a1") or ""), str(ctx.get("a2") or "")

    uid = str(ctx.get("uid") or "")
    token = str(ctx.get("token") or ctx.get("grant_code") or "")
    return uid, token


def generate_rsa_keypair() -> tuple[str, str]:
    """生成登录使用的RSA密钥对（PEM字符串）"""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    return public_pem, private_pem


def build_cs_login_body(ctx: dict[str, Any]) -> tuple[bytes, dict[str, Any]]:
    launcher_version = _resolve_launcher_version(ctx)
    online_res_version = _resolve_online_res_version(ctx)
    branch_tag = _resolve_branch_tag(ctx, launcher_version)

    a13_value = str(ctx.get("a13") or "")
    a1_value, a2_value = _resolve_login_a1_a2(ctx)

    uid = str(ctx.get("uid") or a1_value or "")
    token = str(ctx.get("token") or ctx.get("grant_code") or a2_value or "")
    platform_id = int(ctx.get("platform_id", 3))
    area = int(ctx.get("area", 2))
    env = int(ctx.get("env", 2))
    a12_value = int(ctx.get("a12", 2))
    a5_value = int(ctx.get("a5", 0))
    a21_value = int(ctx.get("a21", 1))
    a22_value = int(ctx.get("a22", 1))
    a4_value = int(ctx.get("a4", 0))
    client_language = int(ctx.get("client_language", 0))

    client_public_key_bytes = ctx.get("client_public_key_bytes")
    if not isinstance(client_public_key_bytes, (bytes, bytearray)):
        client_public_key_str = str(ctx.get("client_public_key") or "")
        client_public_key_bytes = client_public_key_str.encode("utf-8") if client_public_key_str else b""
    client_public_key_bytes = bytes(client_public_key_bytes)

    msg = b""
    # 对齐生产服 MSG_A1 字段（Campofinale.proto.new）
    if branch_tag:
        msg += encode_string(1, branch_tag)
    if online_res_version:
        msg += encode_string(2, online_res_version)
    if launcher_version:
        msg += encode_string(3, launcher_version)
    if a13_value:
        msg += encode_string(4, a13_value)
    if a1_value:
        msg += encode_string(5, a1_value)
    if a2_value:
        msg += encode_string(6, a2_value)
    if client_public_key_bytes:
        msg += encode_bytes(7, client_public_key_bytes)

    msg += encode_uint32(8, platform_id)
    if area != 0:
        msg += encode_uint32(9, area)
    msg += encode_uint32(10, a12_value)
    if a5_value != 0:
        msg += encode_uint64(11, a5_value)
    msg += encode_uint32(12, env)
    msg += encode_uint32(13, a21_value)
    msg += encode_uint32(14, a22_value)
    if a4_value != 0:
        msg += encode_uint32(15, a4_value)
    msg += encode_uint32(16, client_language)

    meta = {
        "a14": branch_tag,
        "client_res_version": online_res_version,
        "client_version": launcher_version,
        "a13": a13_value,
        "a1_len": len(a1_value),
        "a2_len": len(a2_value),
        "uid": uid,
        "token_len": len(token),
        "platform_id": platform_id,
        "area": area,
        "a12": a12_value,
        "a5": a5_value,
        "env": env,
        "a21": a21_value,
        "a22": a22_value,
        "a4": a4_value,
        "client_language": client_language,
        "client_public_key_len": len(client_public_key_bytes),
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
        uid: str = "",
        srsa_bridge: Optional[SRSABridge] = None,
        config_ctx: Optional[dict[str, Any]] = None,
        timeout: float = 30.0,
    ):
        self.host = host
        self.port = port
        self.grant_code = grant_code
        self.uid = uid
        self.srsa_bridge = srsa_bridge
        self.config_ctx = dict(config_ctx or {})
        self.timeout = timeout

        # 生产服通常会携带 client_public_key，未提供时自动生成
        if not self.config_ctx.get("client_public_key"):
            try:
                public_key, private_key = generate_rsa_keypair()
                self.config_ctx["client_public_key"] = public_key
                self.config_ctx.setdefault("client_public_key_bytes", public_key.encode("utf-8"))
                self.config_ctx.setdefault("client_private_key", private_key)
            except Exception as exc:
                logger.warning(f"[TCP] RSA密钥生成失败，继续不带client_public_key: {exc}")

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
        ctx = dict(self.config_ctx)
        ctx.setdefault("uid", self.uid)
        ctx.setdefault("token", self.grant_code)
        ctx.setdefault("grant_code", self.grant_code)
        ctx.setdefault("platform_id", 3)
        ctx.setdefault("area", 1)
        ctx.setdefault("env", 2)

        cs_body_plain, body_meta = build_cs_login_body(ctx)
        cs_body = cs_body_plain
        encrypted = False
        encrypt_error = None

        if self.srsa_bridge is not None:
            try:
                cs_body = self.srsa_bridge.encrypt_login_body(cs_body_plain)
                encrypted = True
            except Exception as exc:
                encrypt_error = str(exc)
                logger.error(f"[TCP] SRSA加密失败，将回退明文发送: {exc}")

        msgid = 13
        seq_id = self._seq_id
        self._seq_id += 1
        packet = build_tcp_packet(msgid, cs_body, seq_id)

        parsed: dict[str, Any] = {
            "send_mode": "hg_protocol",
            "cs_login_meta": body_meta,
            "request_encrypted": encrypted,
            "request_plain_len": len(cs_body_plain),
            "request_body_len": len(cs_body),
            "packet_len": len(packet),
            "packet_hex_head": packet[:32].hex(),
            "msgid": msgid,
            "seq_id": seq_id,
        }
        if encrypt_error:
            parsed["encrypt_error"] = encrypt_error

        logger.info(f"[TCP] 发送登录包: msgid={msgid}, seq={seq_id}, len={len(packet)}")
        await self._write(packet)

        header = await self._read_exact(3)
        head_len = header[0]
        body_len = struct.unpack("<H", header[1:3])[0]
        remaining = await self._read_exact(head_len + body_len)
        resp = header + remaining

        parsed["resp_len"] = len(resp)
        parsed["resp_hex_head"] = resp[:32].hex()
        parsed["resp_head_len"] = head_len
        parsed["resp_body_len"] = body_len

        if len(resp) >= 3 + head_len + body_len:
            resp_body = resp[3 + head_len:3 + head_len + body_len]
            parsed["resp_body_hex_head"] = resp_body[:32].hex()

            if _is_srsa_encrypted(resp_body) and self.srsa_bridge is not None:
                parsed["response_encrypted"] = True
                try:
                    resp_body = self.srsa_bridge.decrypt_login_body(resp_body)
                    parsed["decrypted_len"] = len(resp_body)
                    parsed["decrypted_hex_head"] = resp_body[:48].hex()
                except Exception as e:
                    parsed["decrypt_error"] = str(e)

            error_info = _parse_error_response(resp_body)
            if error_info.get("error_code") is not None:
                err_code = int(error_info["error_code"])
                parsed["error_code"] = err_code
                parsed["error_name"] = ERROR_CODES.get(err_code, f"Unknown({err_code})")
                parsed["error_details"] = error_info.get("details", "")
            else:
                sc_login = _parse_sc_login(resp_body)
                if sc_login:
                    parsed["sc_login"] = sc_login

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
    uid: str = "",
    srsa_bridge: Optional[SRSABridge] = None,
    config_ctx: Optional[dict[str, Any]] = None,
) -> Optional[TCPClient]:
    client = TCPClient(
        host=host,
        port=port,
        grant_code=grant_code,
        uid=uid,
        srsa_bridge=srsa_bridge,
        config_ctx=config_ctx,
    )

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
