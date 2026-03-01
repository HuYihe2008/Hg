"""
测试 CsLogin 响应解析
"""

from tcp.tcp import _parse_error_response, _parse_sc_login, iter_fields

# 从日志中复制的响应（需要实际运行后获取）
# 这里先放一个示例错误响应
test_response_hex = "08291200"  # error_code=41, details=""

test_response = bytes.fromhex(test_response_hex)

print("测试响应解析:")
print(f"十六进制：{test_response.hex()}")

error_info = _parse_error_response(test_response)
print(f"错误信息：{error_info}")

sc_login = _parse_sc_login(test_response)
print(f"ScLogin: {sc_login}")

print("\n字段级解析:")
for field_no, wire, value in iter_fields(test_response):
    print(f"  Field {field_no}, Wire {wire}, Value: {value}")
