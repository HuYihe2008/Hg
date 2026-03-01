"""
调试 CsLogin 消息体编码
"""

import sys
sys.path.insert(0, '.')

from tcp.tcp import build_cs_login_body, generate_rsa_keypair, iter_fields

# 构建测试上下文
ctx = {
    "uid": "",
    "token": "test_token_123",
    "grant_code": "test_token_123",
    "platform_id": 3,
    "area": 2,
    "env": 2,
    "client_version": "1.0.14",
    "res_version": "1.0.14",
}

# 生成 RSA 密钥对
public_key, private_key = generate_rsa_keypair()
ctx["client_public_key"] = public_key
ctx["client_private_key"] = private_key

# 构建消息体
body, meta = build_cs_login_body(ctx)

print("=" * 60)
print("CsLogin 消息体分析")
print("=" * 60)
print(f"\n元数据：{meta}")
print(f"\n消息体长度：{len(body)} 字节")
print(f"消息体十六进制（前 200 字节）: {body[:200].hex()}")

print("\n" + "=" * 60)
print("解析 protobuf 字段")
print("=" * 60)

field_names = {
    1: "channel",
    2: "client_res_version",
    3: "client_version",
    5: "uid",
    6: "token",
    7: "client_public_key",
    8: "platform_id",
    9: "area",
    12: "env",
    16: "client_language",
}

for field_no, wire, value in iter_fields(body):
    field_name = field_names.get(field_no, f"unknown_{field_no}")
    if wire == 2:  # 字符串
        if isinstance(value, bytes):
            try:
                decoded = value.decode('utf-8')
                if len(decoded) > 50:
                    decoded = decoded[:50] + "..."
                print(f"Field {field_no} ({field_name}): STRING '{decoded}' ({len(value)} bytes)")
            except:
                print(f"Field {field_no} ({field_name}): STRING (binary, {len(value)} bytes)")
        else:
            print(f"Field {field_no} ({field_name}): STRING {value}")
    elif wire == 0:  # Varint
        print(f"Field {field_no} ({field_name}): VARINT {value}")
    else:
        print(f"Field {field_no} ({field_name}): WIRE{wire} {value}")

print("\n" + "=" * 60)
print("验证字段顺序")
print("=" * 60)

expected_order = [1, 2, 3, 5, 6, 7, 8, 9, 12, 16]
actual_order = [field_no for field_no, _, _ in iter_fields(body)]

print(f"期望顺序：{expected_order}")
print(f"实际顺序：{actual_order}")
print(f"顺序正确：{expected_order == actual_order}")
