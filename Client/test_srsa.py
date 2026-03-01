"""
测试SRSA加密功能
"""
import sys
from pathlib import Path

# 添加当前目录到路径
sys.path.insert(0, str(Path(__file__).parent))

from tcp.srsa_bridge import get_srsa_bridge, SRSABridgeError

def test_srsa():
    """测试SRSA加密/解密"""
    try:
        # 初始化桥接（使用默认路径 ../Data）
        print("[测试] 初始化SRSA桥接...")
        bridge = get_srsa_bridge()
        print(f"[测试] SRSA桥接初始化成功，版本: {bridge.version}")
        
        # 测试数据
        test_data = b"Hello, World! This is a test message."
        print(f"[测试] 原始数据: {test_data}")
        print(f"[测试] 原始数据长度: {len(test_data)}")
        
        # 加密
        print("[测试] 加密数据...")
        encrypted = bridge.encrypt_login_body(test_data)
        print(f"[测试] 加密后数据长度: {len(encrypted)}")
        print(f"[测试] 加密后数据前32字节: {encrypted[:32].hex()}")
        
        # 检查加密后的数据是否有SRSA魔数
        if encrypted[:4] == b"\x05\x0f\x09\x0c":
            print("[测试] ✓ 加密数据包含SRSA魔数")
        else:
            print(f"[测试] ✗ 加密数据缺少SRSA魔数，前4字节: {encrypted[:4].hex()}")
        
        # 解密
        print("[测试] 解密数据...")
        decrypted = bridge.decrypt_login_body(encrypted)
        print(f"[测试] 解密后数据: {decrypted}")
        
        # 验证
        if decrypted == test_data:
            print("[测试] ✓ 加密/解密验证成功")
        else:
            print("[测试] ✗ 加密/解密验证失败")
            print(f"  期望: {test_data}")
            print(f"  实际: {decrypted}")
        
        return True
        
    except SRSABridgeError as e:
        print(f"[测试] ✗ SRSA桥接错误: {e}")
        return False
    except Exception as e:
        print(f"[测试] ✗ 未知错误: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = test_srsa()
    sys.exit(0 if success else 1)
