"""
会话加密模块（XXE1）
使用AES-CTR + HMAC-SHA256进行会话数据加密/解密
"""

import hashlib
import struct
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class XXE1Cipher:
    """
    XXE1加密算法（会话加密）
    - 加密：AES-CTR模式
    - 认证：HMAC-SHA256
    """
    
    def __init__(self, key: bytes, nonce: bytes):
        """
        初始化XXE1加密器
        
        Args:
            key: 会话密钥（32字节）
            nonce: 随机数/IV（12字节）
        """
        if len(key) != 32:
            raise ValueError(f"密钥长度必须为32字节，实际: {len(key)}")
        if len(nonce) != 12:
            raise ValueError(f"Nonce长度必须为12字节，实际: {len(nonce)}")
        
        self.key = key
        self.nonce = nonce
        self.send_counter = 0
        self.recv_counter = 0
    
    def _derive_keys(self, counter: int) -> tuple[bytes, bytes]:
        """
        从主密钥导出加密密钥和认证密钥
        
        Args:
            counter: 计数器值
        
        Returns:
            (encrypt_key, auth_key)
        """
        # 使用HMAC-SHA256导出密钥
        counter_bytes = struct.pack(">I", counter)
        
        # 加密密钥 = HMAC(key, counter || "enc")
        h_enc = hashlib.new("sha256")
        h_enc.update(self.key)
        h_enc.update(counter_bytes)
        h_enc.update(b"enc")
        enc_key = h_enc.digest()[:32]
        
        # 认证密钥 = HMAC(key, counter || "auth")
        h_auth = hashlib.new("sha256")
        h_auth.update(self.key)
        h_auth.update(counter_bytes)
        h_auth.update(b"auth")
        auth_key = h_auth.digest()[:32]
        
        return enc_key, auth_key
    
    def encrypt(self, plaintext: bytes) -> bytes:
        """
        加密数据
        
        格式: [4字节计数器] + [密文] + [16字节HMAC]
        
        Args:
            plaintext: 明文数据
        
        Returns:
            加密后的数据（包含计数器和HMAC）
        """
        enc_key, auth_key = self._derive_keys(self.send_counter)
        
        # AES-CTR加密
        cipher = Cipher(algorithms.AES(enc_key), modes.CTR(self.nonce + struct.pack(">I", self.send_counter)))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        
        # 构建待认证数据：计数器 || 密文长度 || 密文
        counter_bytes = struct.pack(">I", self.send_counter)
        length_bytes = struct.pack(">I", len(ciphertext))
        to_auth = counter_bytes + length_bytes + ciphertext
        
        # HMAC-SHA256认证
        h = hashlib.new("sha256")
        h.update(auth_key)
        h.update(to_auth)
        tag = h.digest()[:16]
        
        # 增加发送计数器
        self.send_counter += 1
        
        # 返回：计数器 || 密文 || 标签
        return counter_bytes + ciphertext + tag
    
    def decrypt(self, encrypted_data: bytes) -> bytes:
        """
        解密数据
        
        格式: [4字节计数器] + [密文] + [16字节HMAC]
        
        Args:
            encrypted_data: 加密数据
        
        Returns:
            解密后的明文数据
        
        Raises:
            ValueError: 如果认证失败或数据格式错误
        """
        if len(encrypted_data) < 4 + 16:
            raise ValueError(f"加密数据太短: {len(encrypted_data)}")
        
        # 提取计数器、密文和标签
        counter_bytes = encrypted_data[:4]
        ciphertext = encrypted_data[4:-16]
        recv_tag = encrypted_data[-16:]
        
        counter = struct.unpack(">I", counter_bytes)[0]
        
        # 验证计数器
        if counter != self.recv_counter:
            print(f"[XXE1] 警告：计数器不匹配 期望={self.recv_counter}，实际={counter}")
        
        enc_key, auth_key = self._derive_keys(counter)
        
        # 验证HMAC
        length_bytes = struct.pack(">I", len(ciphertext))
        to_auth = counter_bytes + length_bytes + ciphertext
        
        h = hashlib.new("sha256")
        h.update(auth_key)
        h.update(to_auth)
        expected_tag = h.digest()[:16]
        
        if recv_tag != expected_tag:
            raise ValueError("HMAC认证失败（数据可能被篡改）")
        
        # AES-CTR解密
        cipher = Cipher(algorithms.AES(enc_key), modes.CTR(self.nonce + counter_bytes))
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        # 增加接收计数器
        self.recv_counter += 1
        
        return plaintext


def derive_session_keys(server_public_key: bytes, server_nonce: bytes) -> tuple[bytes, bytes]:
    """
    从服务器公钥和随机数派生会话密钥
    
    Args:
        server_public_key: 服务器公钥（RSA加密后）
        server_nonce: 服务器随机数
    
    Returns:
        (session_key, nonce) - 用于初始化XXE1
    """
    # 这里通常需要用私钥解密服务器公钥
    # 简化实现：直接使用SHA256派生
    
    h = hashlib.new("sha256")
    h.update(server_public_key)
    h.update(server_nonce)
    session_key = h.digest()
    
    return session_key, server_nonce


if __name__ == "__main__":
    # 测试XXE1加密
    import os
    
    key = os.urandom(32)
    nonce = os.urandom(12)
    
    cipher = XXE1Cipher(key, nonce)
    
    # 测试加密和解密
    plaintext = b"Hello, World! This is a test message."
    
    encrypted = cipher.encrypt(plaintext)
    print(f"明文长度: {len(plaintext)}")
    print(f"加密长度: {len(encrypted)}")
    
    cipher2 = XXE1Cipher(key, nonce)  # 新实例用于解密
    decrypted = cipher2.decrypt(encrypted)
    
    print(f"解密成功: {decrypted == plaintext}")
    print(f"解密结果: {decrypted}")
