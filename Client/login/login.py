"""
生产服务器登录模块
包含鹰角通行证扫码、Unity认证、服务器选择等完整流程
"""

import asyncio
import json
import time
from typing import Optional, Dict, Any
from dataclasses import dataclass
import httpx


# 常量定义
PASSPORT_APP_CODE = "dd7b852d5f1dd9da"  # 鹰角通行证AppCode
U8_APP_CODE = "4df8f5a7c2ad711b497a"   # Unity U8 AppCode
CHANNEL_MASTER_ID = "1"

# API端点
PASSPORT_DOMAIN = "https://as.hypergryph.com"
U8_DOMAIN = "https://u8.hypergryph.com"

SCAN_LOGIN_URL = f"{PASSPORT_DOMAIN}/general/v1/gen_scan/login"
SCAN_STATUS_URL = f"{PASSPORT_DOMAIN}/general/v1/scan_status"
TOKEN_BY_SCAN_URL = f"{PASSPORT_DOMAIN}/user/auth/v1/token_by_scan_code"
OAUTH2_GRANT_URL = f"{PASSPORT_DOMAIN}/user/oauth2/v2/grant"

U8_TOKEN_URL = f"{U8_DOMAIN}/u8/user/auth/v2/token_by_channel_token"
SERVER_LIST_URL = f"{U8_DOMAIN}/game/server/v1/server_list"
U8_GRANT_URL = f"{U8_DOMAIN}/u8/user/auth/v2/grant"
CONFIRM_SERVER_URL = f"{U8_DOMAIN}/game/role/v1/confirm_server"

# 标准请求头
HEADERS = {
    "User-Agent": "Endfield/1 CFNetwork/3860.200.71 Darwin/25.1.0",
    "Content-Type": "application/json"
}


@dataclass
class LoginSession:
    """登录会话数据"""
    # 鹰角通行证
    passport_token: str
    passport_hg_id: str
    passport_device_token: str
    passport_uid: str
    
    # Unity
    u8_token: str
    u8_uid: str
    u8_grant_code: str
    
    # 服务器
    server_id: str
    server_host: str
    server_port: int
    role_id: str
    nickname: str
    
    def as_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "passport": {
                "token": self.passport_token,
                "hg_id": self.passport_hg_id,
                "device_token": self.passport_device_token,
                "uid": self.passport_uid,
            },
            "u8": {
                "token": self.u8_token,
                "uid": self.u8_uid,
                "grant_code": self.u8_grant_code,
            },
            "server": {
                "id": self.server_id,
                "host": self.server_host,
                "port": self.server_port,
                "role_id": self.role_id,
                "nickname": self.nickname,
            }
        }


class PassportLogin:
    """鹰角通行证登录处理"""
    
    def __init__(self, timeout: float = 30.0):
        self.timeout = timeout
    
    async def gen_scan_login(self) -> str:
        """
        第1步：生成扫码登录二维码
        返回 scanId
        """
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(
                SCAN_LOGIN_URL,
                json={"appCode": PASSPORT_APP_CODE},
                headers=HEADERS
            )
            resp.raise_for_status()
            data = resp.json()
            
            if data.get("status") != 0:
                raise RuntimeError(f"生成登录二维码失败: {data.get('msg')}")
            
            scan_id = data["data"]["scanId"]
            print(f"[Passport] 已生成二维码，scanId: {scan_id}")
            return scan_id
    
    async def poll_scan_status(self, scan_id: str, max_wait: int = 300) -> str:
        """
        第2步：轮询扫码状态
        返回 scanCode
        """
        start_time = time.time()
        
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            while time.time() - start_time < max_wait:
                resp = await client.get(
                    SCAN_STATUS_URL,
                    params={"scanId": scan_id},
                    headers=HEADERS
                )
                resp.raise_for_status()
                data = resp.json()
                
                status = data.get("status", -1)
                
                if status == 0:  # 扫码成功
                    scan_code = data["data"]["scanCode"]
                    print(f"[Passport] 扫码完成")
                    return scan_code
                elif status == 100:
                    print(f"[Passport] 等待扫码...")
                elif status == 101:
                    print(f"[Passport] 已扫码，等待确认...")
                else:
                    print(f"[Passport] 等待中... (status: {status})")
                
                await asyncio.sleep(2)
        
        raise TimeoutError(f"扫码超时 ({max_wait}s)")
    
    async def token_by_scan_code(self, scan_code: str) -> Dict[str, str]:
        """
        第3步：使用scanCode获取token
        返回 {token, hgId, deviceToken}
        """
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(
                TOKEN_BY_SCAN_URL,
                json={
                    "appCode": PASSPORT_APP_CODE,
                    "scanCode": scan_code,
                    "from": 1
                },
                headers=HEADERS
            )
            resp.raise_for_status()
            data = resp.json()
            
            if data.get("status") != 0:
                raise RuntimeError(f"获取token失败: {data.get('msg')}")
            
            result = data["data"]
            print(f"[Passport] 已获取token, hgId: {result['hgId']}")
            
            return {
                "token": result["token"],
                "hg_id": result["hgId"],
                "device_token": result["deviceToken"]
            }
    
    async def oauth2_grant(self, token: str, device_token: str) -> Dict[str, str]:
        """
        第4步：OAuth2鉴权获取授权码
        返回 {uid, code}
        """
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(
                OAUTH2_GRANT_URL,
                json={
                    "deviceToken": device_token,
                    "type": 0,
                    "token": token,
                    "appCode": PASSPORT_APP_CODE
                },
                headers=HEADERS
            )
            resp.raise_for_status()
            data = resp.json()
            
            if data.get("status") != 0:
                raise RuntimeError(f"OAuth2鉴权失败: {data.get('msg')}")
            
            result = data["data"]
            print(f"[Passport] OAuth2鉴权完成, uid: {result['uid']}")
            
            return {
                "uid": result["uid"],
                "code": result["code"]
            }
    
    async def login(self) -> Dict[str, Any]:
        """
        执行完整的鹰角通行证登录流程
        返回 {token, hg_id, device_token, uid, oauth_code}
        """
        print("[Passport] 开始鹰角通行证登录流程...")
        
        scan_id = await self.gen_scan_login()
        scan_code = await self.poll_scan_status(scan_id)
        
        token_data = await self.token_by_scan_code(scan_code)
        oauth_data = await self.oauth2_grant(token_data["token"], token_data["device_token"])
        
        return {
            "token": token_data["token"],
            "hg_id": token_data["hg_id"],
            "device_token": token_data["device_token"],
            "passport_uid": oauth_data["uid"],
            "oauth_code": oauth_data["code"]
        }


class U8Login:
    """Unity U8登录处理"""
    
    def __init__(self, timeout: float = 30.0):
        self.timeout = timeout
    
    async def token_by_channel_token(self, channel_token: str) -> Dict[str, str]:
        """
        第1步：Unity用户鉴权
        返回 {token, uid}
        """
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(
                U8_TOKEN_URL,
                json={
                    "appCode": U8_APP_CODE,
                    "channelMasterId": CHANNEL_MASTER_ID,
                    "channelToken": channel_token,
                    "type": 0,
                    "platform": 0
                },
                headers=HEADERS
            )
            resp.raise_for_status()
            data = resp.json()
            
            if data.get("status") != 0:
                raise RuntimeError(f"Unity鉴权失败: {data.get('msg')}")
            
            result = data["data"]
            print(f"[U8] Unity鉴权完成, 游戏UID: {result['uid']}")
            
            return {
                "token": result["token"],
                "uid": result["uid"]
            }
    
    async def get_server_list(self, token: str) -> list:
        """
        第2步：获取服务器列表
        """
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(
                SERVER_LIST_URL,
                json={"token": token},
                headers=HEADERS
            )
            resp.raise_for_status()
            data = resp.json()
            
            if data.get("status") != 0:
                raise RuntimeError(f"获取服务器列表失败: {data.get('msg')}")
            
            servers = data["data"]["serverList"]
            print(f"[U8] 获取服务器列表: {len(servers)}个服务器")
            
            for srv in servers:
                print(f"  - {srv['serverId']}: {srv['serverName']}")
            
            return servers
    
    async def grant(self, token: str) -> Dict[str, str]:
        """
        第3步：获取grant授权码（用于TCP登录）
        返回 {uid, grant_code}
        """
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(
                U8_GRANT_URL,
                json={
                    "token": token,
                    "type": 0,
                    "platform": 0
                },
                headers=HEADERS
            )
            resp.raise_for_status()
            data = resp.json()
            
            if data.get("status") != 0:
                raise RuntimeError(f"获取grant授权码失败: {data.get('msg')}")
            
            result = data["data"]
            print(f"[U8] Grant授权码已获取")
            
            return {
                "uid": result["uid"],
                "grant_code": result["code"]
            }
    
    async def confirm_server(self, token: str, server_id: str) -> None:
        """
        第4步（可选）：确认登录服务器
        """
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(
                CONFIRM_SERVER_URL,
                json={
                    "token": token,
                    "serverId": server_id
                },
                headers=HEADERS
            )
            resp.raise_for_status()
            data = resp.json()
            
            if data.get("status") != 0:
                raise RuntimeError(f"确认服务器失败: {data.get('msg')}")
            
            print(f"[U8] 服务器确认完成: {server_id}")


async def complete_login_flow(auto_select_server: int = 0) -> LoginSession:
    """
    执行完整的登录流程
    
    Args:
        auto_select_server: 自动选择服务器的索引（0=选择第一个）
    """
    print("=" * 60)
    print("开始完整登录流程")
    print("=" * 60)
    
    # 阶段1：鹰角通行证登录
    passport = PassportLogin()
    passport_data = await passport.login()
    
    # 阶段2：构建channelToken
    oauth_code = passport_data["oauth_code"]
    channel_token = json.dumps({
        "type": 1,
        "isSuc": True,
        "code": oauth_code
    }, ensure_ascii=False, separators=(",", ":"))
    
    # 阶段3：Unity鉴权
    u8 = U8Login()
    u8_token_data = await u8.token_by_channel_token(channel_token)
    
    # 阶段4：获取服务器列表
    servers = await u8.get_server_list(u8_token_data["token"])
    
    # 阶段5：获取grant授权码
    grant_data = await u8.grant(u8_token_data["token"])
    
    # 阶段6：选择服务器
    if auto_select_server < len(servers):
        selected_server = servers[auto_select_server]
    else:
        raise ValueError(f"服务器索引超出范围: {auto_select_server}")
    
    server_id = selected_server["serverId"]
    print(f"\n[Login] 已选择服务器: {selected_server['serverName']} (ID: {server_id})")
    
    # 阶段7：确认服务器
    await u8.confirm_server(u8_token_data["token"], server_id)
    
    # 解析服务器地址
    server_domains = json.loads(selected_server["serverDomain"])
    server_host = server_domains[0]["host"]
    server_port = server_domains[0]["port"]
    
    print(f"\n[Login] 服务器地址: {server_host}:{server_port}")
    
    # 构建登录会话
    session = LoginSession(
        passport_token=passport_data["token"],
        passport_hg_id=passport_data["hg_id"],
        passport_device_token=passport_data["device_token"],
        passport_uid=passport_data["passport_uid"],
        u8_token=u8_token_data["token"],
        u8_uid=u8_token_data["uid"],
        u8_grant_code=grant_data["grant_code"],
        server_id=server_id,
        server_host=server_host,
        server_port=server_port,
        role_id=selected_server.get("roleId", ""),
        nickname=selected_server.get("nickname", "")
    )
    
    print("\n" + "=" * 60)
    print("登录流程完成")
    print("=" * 60)
    print(json.dumps(session.as_dict(), indent=2, ensure_ascii=False))
    
    return session


if __name__ == "__main__":
    # 测试登录流程
    try:
        session = asyncio.run(complete_login_flow())
    except Exception as e:
        print(f"[Error] 登录失败: {e}")
        import traceback
        traceback.print_exc()
