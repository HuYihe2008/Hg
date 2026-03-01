"""
Campofinale 生产服务器客户端
完整的登录流程：配置获取 → HTTP鉴权 → TCP连接 → 加密通信
"""

import asyncio
import json
import logging
import argparse
from pathlib import Path
from typing import Optional

from config.get_config import EndfieldConfigFetcher, save_config_to_file
from login.login import complete_login_flow, LoginSession
from tcp.tcp import tcp_login_flow
from tcp.srsa_bridge import get_srsa_bridge

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger(__name__)


class GameClient:
    """游戏客户端主类"""
    
    def __init__(
        self,
        config_dir: Optional[str] = None,
        dll_dir: Optional[str] = None,
        oversea: bool = False
    ):
        """
        初始化客户端

        Args:
            config_dir: 配置缓存目录
            dll_dir: GameAssembly.dll所在目录（优先使用，默认: ../Data）
            oversea: 是否为海外版本
        """
        self.config_dir = Path(config_dir) if config_dir else Path("./config_cache")
        self.dll_dir = Path(dll_dir) if dll_dir else None
        self.oversea = oversea

        self.config_result = None
        self.login_session: Optional[LoginSession] = None
        self.tcp_client = None
        self.srsa_bridge = None
    
    async def phase_1_fetch_config(self) -> bool:
        """
        第1阶段：获取游戏配置
        
        Returns:
            是否成功
        """
        print("\n" + "=" * 60)
        print("第1阶段：获取游戏配置")
        print("=" * 60)
        
        try:
            fetcher = EndfieldConfigFetcher(is_oversea=self.oversea)
            self.config_result = fetcher.fetch_all("Windows")
            
            # 保存配置到文件
            save_config_to_file(self.config_result, str(self.config_dir))
            
            return True
        
        except Exception as e:
            logger.error(f"配置获取失败: {e}")
            return False
    
    async def phase_2_http_login(self) -> bool:
        """
        第2阶段：HTTP鉴权
        
        Returns:
            是否成功
        """
        print("\n" + "=" * 60)
        print("第2阶段：HTTP鉴权与服务器选择")
        print("=" * 60)
        
        try:
            self.login_session = await complete_login_flow(auto_select_server=0)
            return True
        
        except Exception as e:
            logger.error(f"HTTP鉴权失败: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    async def phase_3_tcp_login(self) -> bool:
        """
        第3阶段：TCP登录与参会话建立
        
        Returns:
            是否成功
        """
        print("\n" + "=" * 60)
        print("第3阶段：TCP连接与加密会话")
        print("=" * 60)
        
        if not self.login_session:
            logger.error("未执行HTTP鉴权")
            return False
        
        try:
            # 初始化SRSA桥接
            logger.info("[Client] 初始化SRSA加密桥接...")
            # 如果指定了dll_dir则优先使用，否则使用默认路径 ../Data
            self.srsa_bridge = get_srsa_bridge(self.dll_dir)
            
            # 准备配置上下文
            config_ctx = {}
            if self.config_result:
                # 从配置结果中获取版本信息
                if self.config_result.launcher_version:
                    config_ctx["client_version"] = self.config_result.launcher_version.get("version", "1.0.14")
                if self.config_result.res_version:
                    config_ctx["res_version"] = self.config_result.res_version.get("resourceVersion", "1.0.14")
            
            # 建立 TCP 连接并登录
            logger.info(f"[Client] 连接到 TCP 服务器...")
            self.tcp_client = await tcp_login_flow(
                host=self.login_session.server_host,
                port=self.login_session.server_port,
                grant_code=self.login_session.u8_grant_code,
                srsa_bridge=self.srsa_bridge,
                config_ctx=config_ctx
            )
            
            if not self.tcp_client:
                logger.error("TCP登录失败")
                return False
            
            logger.info("[Client] TCP登录成功")
            return True
        
        except Exception as e:
            logger.error(f"TCP登录失败: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    async def run_full_login(self) -> bool:
        """
        执行完整登录流程
        
        Returns:
            是否成功
        """
        print("\n")
        print("╔" + "=" * 58 + "╗")
        print("║" + " " * 12 + "Campofinale 生产服务器客户端" + " " * 16 + "║")
        print("║" + " " * 58 + "║")
        print("║  1. 获取游戏配置（launcher/resource/configs）" + " " * 12 + "║")
        print("║  2. HTTP鉴权（鹰角通行证 + Unity认证）" + " " * 16 + "║")
        print("║  3. TCP登录（SRSA加密 + XXE1会话加密）" + " " * 16 + "║")
        print("╚" + "=" * 58 + "╝")
        print()
        
        # 第1阶段
        if not await self.phase_1_fetch_config():
            logger.error("[Client] 配置获取失败，中止")
            return False
        
        # 第2阶段
        if not await self.phase_2_http_login():
            logger.error("[Client] HTTP鉴权失败，中止")
            return False
        
        # 第3阶段
        if not await self.phase_3_tcp_login():
            logger.error("[Client] TCP连接失败，中止")
            return False
        
        return True
    
    async def interactive_session(self) -> None:
        """交互式会话"""
        if not self.tcp_client:
            logger.error("未建立TCP连接")
            return
        
        print("\n" + "=" * 60)
        print("交互式会话（输入'exit'退出）")
        print("=" * 60)
        
        while True:
            try:
                cmd = input("\n> ").strip()
                
                if cmd.lower() == "exit":
                    break
                
                elif cmd.lower() == "info":
                    print("\n登录会话信息：")
                    print(json.dumps(self.login_session.as_dict(), indent=2, ensure_ascii=False))
                
                elif cmd.lower().startswith("send"):
                    # 示例：send 50010 "test"
                    parts = cmd.split(" ", 2)
                    if len(parts) < 2:
                        print("用法: send <msgId> [data]")
                        continue
                    
                    msg_id = int(parts[1])
                    data = parts[2].encode() if len(parts) > 2 else b""
                    
                    await self.tcp_client.send_message(msg_id, data)
                    print(f"已发送 msgId={msg_id}")
                
                else:
                    print("未知命令")
            
            except Exception as e:
                logger.error(f"命令执行失败: {e}")
    
    def save_session(self, path: str) -> None:
        """保存登录会话"""
        if self.login_session:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(self.login_session.as_dict(), f, indent=2, ensure_ascii=False)
            logger.info(f"会话已保存: {path}")
    
    def load_session(self, path: str) -> bool:
        """加载登录会话"""
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            
            self.login_session = LoginSession(
                passport_token=data["passport"]["token"],
                passport_hg_id=data["passport"]["hg_id"],
                passport_device_token=data["passport"]["device_token"],
                passport_uid=data["passport"]["uid"],
                u8_token=data["u8"]["token"],
                u8_uid=data["u8"]["uid"],
                u8_grant_code=data["u8"]["grant_code"],
                server_id=data["server"]["id"],
                server_host=data["server"]["host"],
                server_port=data["server"]["port"],
                role_id=data["server"]["role_id"],
                nickname=data["server"]["nickname"]
            )
            logger.info(f"会话已加载: {path}")
            return True
        
        except Exception as e:
            logger.error(f"会话加载失败: {e}")
            return False


async def main():
    """主函数"""
    parser = argparse.ArgumentParser(
        description="Campofinale 生产服务器客户端",
        epilog="示例：python main.py --config-dir ./config_cache"
    )

    parser.add_argument(
        "--dll-dir",
        default=None,
        help="GameAssembly.dll所在目录（优先使用，默认: ../Data）"
    )
    parser.add_argument(
        "--config-dir",
        default="./config_cache",
        help="配置缓存目录"
    )
    parser.add_argument(
        "--oversea",
        action="store_true",
        help="使用海外版本配置"
    )
    parser.add_argument(
        "--skip-config",
        action="store_true",
        help="跳过配置获取（仅进行登录和TCP连接）"
    )
    parser.add_argument(
        "--load-session",
        type=str,
        help="加载已保存的会话（跳过HTTP鉴权）"
    )
    parser.add_argument(
        "--save-session",
        type=str,
        help="保存会话到指定文件"
    )
    
    args = parser.parse_args()
    
    client = GameClient(
        config_dir=args.config_dir,
        dll_dir=args.dll_dir,
        oversea=args.oversea
    )
    
    # 登录流程
    success = False
    
    if args.load_session:
        # 加载已保存的会话
        if client.load_session(args.load_session):
            logger.info("[Client] 使用已保存的会话，跳过HTTP鉴权")
            # 直接进行TCP连接
            if await client.phase_3_tcp_login():
                success = True
    
    else:
        # 执行完整登录流程
        skip_phases = []
        
        if args.skip_config:
            skip_phases.append(1)
            logger.info("[Client] 跳过第1阶段（配置获取）")
        
        success = True
        
        if 1 not in skip_phases:
            success = success and await client.phase_1_fetch_config()
        
        success = success and await client.phase_2_http_login()
        success = success and await client.phase_3_tcp_login()
    
    if success:
        logger.info("[Client] ✓ 所有阶段完成")
        
        # 保存会话
        if args.save_session:
            client.save_session(args.save_session)
        
        # 进入交互式会话
        await client.interactive_session()
    
    else:
        logger.error("[Client] ✗ 登录流程失败")
    
    # 清理
    if client.tcp_client:
        client.tcp_client.disconnect()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\n中断...")
    except Exception as e:
        logger.error(f"致命错误: {e}")
        import traceback
        traceback.print_exc()
