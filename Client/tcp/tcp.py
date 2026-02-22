"""
TCP通信模块
处理与游戏服务器的TCP连接、数据包编码/解码、加密通信
"""

import asyncio
import socket
import struct
import zlib
import logging
from typing import Optional, Callable, Any
from pathlib import Path

from .xxe1 import XXE1Cipher, derive_session_keys
from .srsa_bridge import get_srsa_bridge, SRSABridge

logger = logging.getLogger(__name__)


class TCPPacket:
    """TCP数据包格式"""
    
    # 包头格式：[1字节HeadLen] + [2字节BodyLen] + [HeadLen字节CsHead] + [BodyLen字节Body]
    HEADER_SIZE = 3  # HeadLen(1) + BodyLen(2)
    
    def __init__(self):
        self.head_len = 0
        self.body_len = 0
        self.head_data = b""
        self.body_data = b""
    
    @staticmethod
    def parse_header(data: bytes) -> tuple[int, int]:
        """
        解析包头长度
        
        Args:
            data: 至少3字节的数据
        
        Returns:
            (head_len, body_len)
        """
        head_len = data[0]
        body_len = struct.unpack(">H", data[1:3])[0]
        return head_len, body_len
    
    @staticmethod
    def encode(head_data: bytes, body_data: bytes) -> bytes:
        """
        编码数据包
        
        Args:
            head_data: 包头数据（Protobuf格式）
            body_data: 包体数据
        
        Returns:
            完整的TCP包
        """
        head_len = len(head_data)
        body_len = len(body_data)
        
        packet = bytearray()
        packet.append(head_len)
        packet.extend(struct.pack(">H", body_len))
        packet.extend(head_data)
        packet.extend(body_data)
        
        return bytes(packet)


class TCPClient:
    """游戏TCP客户端"""
    
    def __init__(
        self,
        host: str,
        port: int,
        grant_code: str,
        srsa_bridge: Optional[SRSABridge] = None,
        timeout: float = 30.0
    ):
        """
        初始化TCP客户端
        
        Args:
            host: 服务器主机名
            port: 服务器端口
            grant_code: 登录授权码（来自Unity认证）
            srsa_bridge: SRSA加密桥接（可选）
            timeout: 连接超时时间
        """
        self.host = host
        self.port = port
        self.grant_code = grant_code
        self.srsa_bridge = srsa_bridge or get_srsa_bridge(use_mock=True)
        self.timeout = timeout
        
        self.reader: Optional[asyncio.StreamReader] = None
        self.writer: Optional[asyncio.StreamWriter] = None
        self.xxe1: Optional[XXE1Cipher] = None
        
        self._connected = False
        self._recv_counter = 0
        self._send_counter = 0
    
    async def connect(self) -> bool:
        """
        连接到服务器
        
        Returns:
            连接是否成功
        """
        try:
            logger.info(f"[TCP] 连接到服务器: {self.host}:{self.port}")
            self.reader, self.writer = await asyncio.wait_for(
                asyncio.open_connection(self.host, self.port),
                timeout=self.timeout
            )
            self._connected = True
            logger.info(f"[TCP] 连接成功")
            return True
        
        except asyncio.TimeoutError:
            logger.error(f"[TCP] 连接超时")
            return False
        except Exception as e:
            logger.error(f"[TCP] 连接失败: {e}")
            return False
    
    def disconnect(self) -> None:
        """断开连接"""
        if self.writer:
            self.writer.close()
        self._connected = False
        logger.info(f"[TCP] 已断开连接")
    
    async def _read_exact(self, n: int) -> bytes:
        """读取指定字节数"""
        if not self.reader:
            raise RuntimeError("未连接")
        
        data = await self.reader.readexactly(n)
        if not data:
            raise RuntimeError("连接已关闭")
        return data
    
    async def _write(self, data: bytes) -> None:
        """发送数据"""
        if not self.writer:
            raise RuntimeError("未连接")
        
        self.writer.write(data)
        await self.writer.drain()
    
    async def send_login_request(self) -> Optional[dict]:
        """
        发送登录请求（CsLogin消息）
        
        Returns:
            登录响应数据或None
        """
        # 这里需要构建CsLogin消息体
        # 消息体需要用SRSA加密
        
        login_body = self._build_login_body()
        encrypted_body = self.srsa_bridge.encrypt_login_body(login_body)
        
        # 构建数据包
        # msgId = 50001 (CsLogin)
        # 格式: [4字节msgId] + [加密的消息体]
        
        packet_data = struct.pack(">I", 50001) + encrypted_body
        
        logger.info(f"[TCP] 发送登录请求...")
        await self._write(packet_data)
        
        # 等待登录响应
        response = await self.recv_message()
        return response
    
    def _build_login_body(self) -> bytes:
        """
        构建登录消息体（使用grant_code）
        
        Returns:
            Protobuf编码的CsLogin消息体
        """
        # 这里应该使用实际的Protobuf库来构建消息
        # 简化版本：直接包含grant_code
        
        # 实际实现需要：
        # CsLogin {
        #   uid: grant_code
        #   token: grant_code
        #   client_version: "0.5.5"
        #   platform_id: 3  # Windows
        #   area: 0         # Oversea
        #   env: 2          # Prod
        # }
        
        # 这里使用placeholder实现
        return b"login_placeholder_" + self.grant_code.encode()[:20]
    
    async def send_message(
        self,
        msg_id: int,
        body_data: bytes,
        encrypt: bool = True
    ) -> None:
        """
        发送消息
        
        Args:
            msg_id: 消息ID
            body_data: 消息体数据
            encrypt: 是否加密（使用XXE1）
        """
        # 消息头：msgId(4字节)
        head = struct.pack(">I", msg_id)
        
        # 加密消息体（如果已建立会话）
        if encrypt and self.xxe1:
            body_data = self.xxe1.encrypt(body_data)
        
        # 构建完整数据包
        packet = TCPPacket.encode(head, body_data)
        
        logger.debug(f"[TCP] 发送消息: msgId={msg_id}, 长度={len(body_data)}")
        await self._write(packet)
    
    async def recv_message(self) -> Optional[dict]:
        """
        接收消息
        
        Returns:
            解析后的消息内容
        """
        try:
            # 读取包头（3字节）
            header = await self._read_exact(3)
            head_len, body_len = TCPPacket.parse_header(header)
            
            # 读取包头和包体
            total_len = head_len + body_len
            data = await self._read_exact(total_len)
            
            head_data = data[:head_len]
            body_data = data[head_len:]
            
            # 解密（如果已建立会话）
            if self.xxe1:
                try:
                    body_data = self.xxe1.decrypt(body_data)
                except Exception as e:
                    logger.warning(f"[TCP] 解密失败: {e}")
            
            # 解析消息ID
            msg_id = struct.unpack(">I", head_data[:4])[0]
            
            logger.debug(f"[TCP] 接收消息: msgId={msg_id}, 长度={len(body_data)}")
            
            return {
                "msg_id": msg_id,
                "body": body_data,
                "head": head_data
            }
        
        except asyncio.TimeoutError:
            logger.error(f"[TCP] 接收超时")
            return None
        except Exception as e:
            logger.error(f"[TCP] 接收失败: {e}")
            return None
    
    async def init_session_encryption(
        self,
        server_public_key: bytes,
        server_nonce: bytes
    ) -> bool:
        """
        初始化会话加密（从ScLogin响应中提取密钥）
        
        Args:
            server_public_key: 服务器公钥
            server_nonce: 服务器随机数
        
        Returns:
            初始化是否成功
        """
        try:
            # 派生会话密钥
            session_key, session_nonce = derive_session_keys(server_public_key, server_nonce)
            
            # 初始化XXE1加密器
            self.xxe1 = XXE1Cipher(session_key, session_nonce)
            
            logger.info(f"[TCP] 会话加密已初始化")
            return True
        
        except Exception as e:
            logger.error(f"[TCP] 会话加密初始化失败: {e}")
            return False
    
    async def keep_alive(self, interval: float = 30.0) -> None:
        """
        保持连接活跃（定期发送心跳）
        
        Args:
            interval: 心跳间隔（秒）
        """
        while self._connected:
            try:
                await asyncio.sleep(interval)
                # 发送ping消息
                # msgId = 50100 (CsPing)
                await self.send_message(50100, b"", encrypt=True)
            except Exception as e:
                logger.error(f"[TCP] 心跳失败: {e}")
                break


async def tcp_login_flow(
    host: str,
    port: int,
    grant_code: str,
    srsa_bridge: Optional[SRSABridge] = None
) -> Optional[TCPClient]:
    """
    执行TCP登录流程
    
    Args:
        host: 服务器主机名
        port: 服务器端口
        grant_code: 登录授权码
        srsa_bridge: SRSA加密桥接
    
    Returns:
        已连接的TCPClient或None
    """
    client = TCPClient(host, port, grant_code, srsa_bridge)
    
    # 连接到服务器
    if not await client.connect():
        return None
    
    try:
        # 发送登录请求
        response = await client.send_login_request()
        
        if not response:
            logger.error("登录请求失败")
            return None
        
        msg_id = response["msg_id"]
        logger.info(f"[TCP] 登录响应: msgId={msg_id}")
        
        # 如果收到ScLogin (msgId=50001)
        if msg_id == 50001:
            # 初始化会话加密
            # 从响应体中提取server_public_key和server_nonce
            # 这里需要Protobuf解析
            
            logger.info(f"[TCP] TCP登录成功")
            return client
        else:
            logger.error(f"[TCP] 意外的响应消息: {msg_id}")
            return None
    
    except Exception as e:
        logger.error(f"[TCP] 登录流程失败: {e}")
        client.disconnect()
        return None


if __name__ == "__main__":
    # 配置日志
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )
    
    # 测试（需要实际服务器）
    # client = asyncio.run(tcp_login_flow(
    #     "127.0.0.1",
    #     30000,
    #     "test_grant_code"
    # ))
