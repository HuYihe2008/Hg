"""
SRSA加密桥接模块（生产环境）
使用DLL与游戏引擎进行SRSA加密/解密操作
"""

import ctypes
import os
from pathlib import Path
from typing import Optional

# 常量
C_GET = 0x12345678
C_SET = 0x87654321
C_RET = 0x11223344
HANDLE_MIN = 0x10000000
MAX_LEN = 0x10000000  # 256MB上限


class SRSABridgeError(Exception):
    """SRSA桥接错误"""
    pass


class SRSABridge:
    """
    SRSA加密桥接（与GameAssembly.dll交互）
    用于加密登录消息体
    """
    
    def __init__(self, dll_dir: Optional[Path] = None):
        """
        初始化SRSA桥接
        
        Args:
            dll_dir: GameAssembly.dll所在目录（如None则自动查找）
        """
        if dll_dir is None:
            dll_dir = Path(".").resolve()
        
        self.dll_dir = dll_dir
        self._dll = None
        self._initialized = False
        self._init_dll()
    
    def _init_dll(self) -> None:
        """初始化DLL"""
        dll_path = self.dll_dir / "GameAssembly.dll"
        
        if not dll_path.exists():
            raise SRSABridgeError(f"GameAssembly.dll不存在: {dll_path}")
        
        try:
            os.add_dll_directory(str(self.dll_dir))
            self._dll = ctypes.WinDLL(str(dll_path))
            
            # 配置加密方法
            self._get_ver = self._dll.mono_method_h_get_ver
            self._get_ver.argtypes = []
            self._get_ver.restype = ctypes.c_uint64
            
            self._get_code = self._dll.mono_method_h_get_code
            self._get_code.argtypes = [ctypes.c_uint64, ctypes.c_uint32]
            self._get_code.restype = ctypes.c_uint64
            
            self._set_code = self._dll.mono_method_h_set_code
            self._set_code.argtypes = [ctypes.c_uint64]
            self._set_code.restype = ctypes.c_uint64
            
            self._remove_code = self._dll.mono_method_h_remove_code
            self._remove_code.argtypes = [ctypes.c_uint64]
            self._remove_code.restype = None
            
            self._initialized = True
            print(f"[SRSA] DLL初始化成功: {dll_path}")
            print(f"[SRSA] DLL版本: {self.version}")
        
        except Exception as e:
            raise SRSABridgeError(f"DLL初始化失败: {e}")
    
    @property
    def version(self) -> int:
        """获取DLL版本"""
        if not self._initialized:
            raise SRSABridgeError("SRSA Bridge未初始化")
        return int(self._get_ver())
    
    def encrypt_login_body(self, plain: bytes) -> bytes:
        """
        加密登录消息体
        
        Args:
            plain: 明文消息体
        
        Returns:
            加密后的消息体
        """
        if not self._initialized:
            raise SRSABridgeError("SRSA Bridge未初始化")
        
        src = (ctypes.c_ubyte * len(plain)).from_buffer_copy(plain)
        ptr = ctypes.cast(src, ctypes.c_void_p).value
        
        if ptr is None:
            raise SRSABridgeError("encrypt_login_body: ptr is null")
        
        try:
            handle = self._get_code(ptr ^ C_GET, len(plain))
            
            if handle < HANDLE_MIN:
                raise SRSABridgeError(f"mono_method_h_get_code failed: handle={handle}")
            
            try:
                decoded_ptr = handle ^ C_RET
                out_len = ctypes.c_int32.from_address(decoded_ptr + 4).value
                
                if out_len <= 0 or out_len > MAX_LEN:
                    raise SRSABridgeError(f"invalid encrypted output length: {out_len}")
                
                encrypted = ctypes.string_at(decoded_ptr, out_len)
                print(f"[SRSA] 加密完成: {len(plain)} -> {out_len}")
                return encrypted
            
            finally:
                self._remove_code(handle)
        
        except Exception as e:
            print(f"[SRSA] 加密失败: {e}")
            raise
    
    def decrypt_login_body(self, encrypted_body: bytes) -> bytes:
        """
        解密登录响应消息体
        
        Args:
            encrypted_body: 加密的消息体
        
        Returns:
            解密后的明文消息体
        """
        if not self._initialized:
            raise SRSABridgeError("SRSA Bridge未初始化")
        
        src = (ctypes.c_ubyte * len(encrypted_body)).from_buffer_copy(encrypted_body)
        ptr = ctypes.cast(src, ctypes.c_void_p).value
        
        if ptr is None:
            raise SRSABridgeError("decrypt_login_body: ptr is null")
        
        try:
            handle = self._set_code(ptr ^ C_SET)
            
            if handle < HANDLE_MIN:
                raise SRSABridgeError(f"mono_method_h_set_code failed: handle={handle}")
            
            try:
                decoded_ptr = handle ^ C_RET
                out_len = ctypes.c_int32.from_address(decoded_ptr).value
                
                if out_len < 0 or out_len > MAX_LEN:
                    raise SRSABridgeError(f"invalid decrypted output length: {out_len}")
                
                decrypted = ctypes.string_at(decoded_ptr + 4, out_len)
                print(f"[SRSA] 解密完成: {len(encrypted_body)} -> {out_len}")
                return decrypted
            
            finally:
                self._remove_code(handle)
        
        except Exception as e:
            print(f"[SRSA] 解密失败: {e}")
            raise
    
    def try_decrypt_login_body(self, encrypted_body: bytes) -> Optional[bytes]:
        """尝试解密（忽略错误）"""
        try:
            return self.decrypt_login_body(encrypted_body)
        except Exception:
            return None


class MockSRSABridge:
    """
    模拟SRSA桥接（用于不需要加密的测试环境）
    """
    
    def encrypt_login_body(self, plain: bytes) -> bytes:
        """返回原文（不加密）"""
        print(f"[SRSA-Mock] 模拟加密: {len(plain)} bytes")
        return plain
    
    def decrypt_login_body(self, encrypted_body: bytes) -> bytes:
        """返回原文（不解密）"""
        print(f"[SRSA-Mock] 模拟解密: {len(encrypted_body)} bytes")
        return encrypted_body
    
    def try_decrypt_login_body(self, encrypted_body: bytes) -> Optional[bytes]:
        """尝试解密（模拟）"""
        return encrypted_body


def get_srsa_bridge(dll_dir: Optional[Path] = None, use_mock: bool = False) -> SRSABridge:
    """
    获取SRSA桥接实例
    
    Args:
        dll_dir: GameAssembly.dll目录
        use_mock: 是否使用模拟桥接
    
    Returns:
        SRSA桥接实例
    """
    if use_mock:
        print("[SRSA] 使用模拟SRSA桥接")
        return MockSRSABridge()
    
    try:
        return SRSABridge(dll_dir)
    except SRSABridgeError as e:
        print(f"[SRSA] 初始化失败: {e}，回退到模拟模式")
        return MockSRSABridge()


if __name__ == "__main__":
    import sys
    
    try:
        # 从当前目录查找DLL
        bridge = SRSABridge(Path("."))
        
        # 测试加密
        test_data = b"Hello, World!"
        encrypted = bridge.encrypt_login_body(test_data)
        print(f"加密结果: {encrypted[:20]}...")
        
        # 测试解密
        decrypted = bridge.decrypt_login_body(encrypted)
        print(f"解密结果: {decrypted}")
        
    except SRSABridgeError as e:
        print(f"错误: {e}")
        sys.exit(1)
