#!/usr/bin/env python3
"""
二维码功能测试脚本
演示qrcode库集成效果
"""

import sys
import os

# 添加当前目录到路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from login.login import PassportLogin

async def test_qrcode_display():
    """测试二维码生成和显示功能"""
    
    print("=" * 60)
    print("测试二维码生成功能")
    print("=" * 60)
    print()
    
    # 创建PassportLogin实例
    passport = PassportLogin()
    
    # 示例URL（模拟servers返回的scanUrl）
    test_urls = [
        "https://as.hypergryph.com/user/login?scanId=test123",
        "https://example.com/auth?code=abc123"
    ]
    
    for i, test_url in enumerate(test_urls, 1):
        print(f"\n测试用例 {i}:")
        print(f"URL: {test_url}")
        print("-" * 60)
        passport._generate_qrcode_display(test_url)
        print()
    
    print("=" * 60)
    print("✓ 二维码测试完成")
    print("=" * 60)

if __name__ == "__main__":
    import asyncio
    asyncio.run(test_qrcode_display())
