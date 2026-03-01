"""
SRSA加密桥接模块（生产环境）
使用GameAssembly.dll与游戏引擎进行SRSA加密/解密操作

DLL路径: ../Data/GameAssembly.dll
"""

from __future__ import annotations

import ctypes
import os
from pathlib import Path
from typing import Optional

# 与 makeback 对齐的常量
C_GET = 0x8F6650A485
C_SET = 0x971AB5C8FF
C_RET = 0x0F91A4399A0
HANDLE_MIN = 0x1000
MAX_LEN = 16 * 1024 * 1024

# 默认DLL路径（相对于Client目录）
DEFAULT_DLL_DIR = Path("../Data")


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
            dll_dir: GameAssembly.dll所在目录（默认: ../Data）
        """
        if dll_dir is None:
            dll_dir = DEFAULT_DLL_DIR.resolve()
        
        self.dll_dir = dll_dir
        self._dll = None
        self._init_dll()
    
    def _init_dll(self) -> None:
        """初始化DLL"""
        dll_path = self.dll_dir / "GameAssembly.dll"
        
        if not dll_path.exists():
            raise SRSABridgeError(f"GameAssembly.dll不存在: {dll_path}")
        
        try:
            if hasattr(os, 'add_dll_directory'):
                os.add_dll_directory(str(self.dll_dir))
            else:
                try:
                    kernel32 = ctypes.windll.kernel32
                    kernel32.SetDllDirectoryW.argtypes = [ctypes.c_wchar_p]
                    kernel32.SetDllDirectoryW.restype = ctypes.c_bool
                    kernel32.SetDllDirectoryW(str(self.dll_dir))
                except Exception as e:
                    print(f"[SRSA] 警告: SetDllDirectory失败: {e}")
            
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
            
            print(f"[SRSA] DLL初始化成功: {dll_path}")
            print(f"[SRSA] DLL版本: {self.version}")
        
        except Exception as e:
            raise SRSABridgeError(f"DLL初始化失败: {e}")
    
    @property
    def version(self) -> int:
        """获取DLL版本"""
        return int(self._get_ver())
    
    def encrypt_login_body(self, plain: bytes) -> bytes:
        """
        加密登录消息体

        Args:
            plain: 明文消息体

        Returns:
            加密后的消息体
        """
        src = (ctypes.c_ubyte * len(plain)).from_buffer_copy(plain)
        ptr = ctypes.cast(src, ctypes.c_void_p).value
        if ptr is None:
            raise SRSABridgeError("encrypt_login_body: ptr is null")

        handle = self._get_code(ptr ^ C_GET, len(plain))
        if handle < HANDLE_MIN:
            raise SRSABridgeError(f"mono_method_h_get_code failed code={handle}")

        try:
            decoded_ptr = handle ^ C_RET
            out_len = ctypes.c_int32.from_address(decoded_ptr + 4).value
            if out_len <= 0 or out_len > MAX_LEN:
                raise SRSABridgeError(f"encrypt out_len invalid: {out_len}")
            # 复制数据后再释放handle
            result = bytes(ctypes.string_at(decoded_ptr, out_len))
            return result
        finally:
            self._remove_code(handle)
    
    def decrypt_login_body(self, encrypted_body: bytes) -> bytes:
        """
        解密登录响应消息体

        Args:
            encrypted_body: 加密的消息体

        Returns:
            解密后的明文消息体
        """
        src = (ctypes.c_ubyte * len(encrypted_body)).from_buffer_copy(encrypted_body)
        ptr = ctypes.cast(src, ctypes.c_void_p).value
        if ptr is None:
            raise SRSABridgeError("decrypt_login_body: ptr is null")

        handle = self._set_code(ptr ^ C_SET)
        if handle < HANDLE_MIN:
            raise SRSABridgeError(f"mono_method_h_set_code failed code={handle}")

        try:
            decoded_ptr = handle ^ C_RET
            out_len = ctypes.c_int32.from_address(decoded_ptr).value
            if out_len < 0 or out_len > MAX_LEN:
                raise SRSABridgeError(f"decrypt out_len invalid: {out_len}")
            # 复制数据后再释放handle
            result = bytes(ctypes.string_at(decoded_ptr + 4, out_len))
            return result
        finally:
            self._remove_code(handle)
    
    def try_decrypt_login_body(self, encrypted_body: bytes) -> Optional[bytes]:
        """尝试解密（忽略错误）"""
        try:
            return self.decrypt_login_body(encrypted_body)
        except Exception:
            return None


def get_srsa_bridge(dll_dir: Optional[Path] = None):
    """
    获取SRSA桥接实例
    
    Args:
        dll_dir: GameAssembly.dll目录（默认: ../Data）
    
    Returns:
        SRSA桥接实例
    
    Raises:
        SRSABridgeError: DLL初始化失败时抛出
    """
    return SRSABridge(dll_dir)


if __name__ == "__main__":
    import sys
    
    try:
        # 从默认路径查找DLL
        bridge = SRSABridge()
        
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
