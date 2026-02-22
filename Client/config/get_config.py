"""
游戏配置获取与解密模块
处理launcher版本获取、资源版本和远程配置（AES-CBC解密）
"""

import argparse
import base64
import json
import os
from dataclasses import dataclass
from typing import Any
import httpx
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# 配置加密密钥
ENDFIELD_RC_KEY_B64_OVERSEA = "cZm86UfDp/kgJ3agKx+HZA=="
ENDFIELD_RC_KEY_B64_CN = "Wgxugl5qVirx7r3km6nXtA=="

# U8配置加密密钥和IV（固定）
ENDFIELD_U8_AES_KEY_HEX = "C0F30E1CE763BBC21CC355A34303AC50399444BFF68C4A22AF398C0A166EE143"
ENDFIELD_U8_AES_IV_HEX = "33467861192750649501937264608400"

# 官方API端点
LAUNCHER_VERSION_URL = (
    "https://launcher.hypergryph.com/api/game/get_latest"
    "?appcode=6LL0KJuqHBVz33WK&channel=1&platform={device}&sub_channel=1&source=game"
)
RES_VERSION_URL = (
    "https://launcher.hypergryph.com/api/game/get_latest_resources"
    "?appcode=6LL0KJuqHBVz33WK&platform={device}&game_version=1.0&version={version}&rand_str={rand_str}"
)

ENGINE_CONFIG_URL = "https://game-config.hypergryph.com/api/remote_config/3/prod-engine/default/{device}/engine_config"
NETWORK_CONFIG_URL = "https://game-config.hypergryph.com/api/remote_config/v2/3/prod-obt/default/{device}/network_config"
GAME_CONFIG_URL = "https://game-config.hypergryph.com/api/remote_config/v2/3/prod-obt/default/{device}/game_config"


def _pkcs7_unpad(data: bytes) -> bytes:
    """移除PKCS7填充"""
    if not data:
        return data
    pad_len = data[-1]
    if pad_len <= 0 or pad_len > 16:
        return data
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        return data
    return data[:-pad_len]


def _aes_cbc_decrypt(cipher: bytes, key: bytes, iv: bytes) -> bytes:
    """AES-CBC解密"""
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    return decryptor.update(cipher) + decryptor.finalize()


def _decrypt_remote_config_text(ciphertext_b64: str, *, is_oversea: bool) -> str:
    """
    解密远程配置文本
    格式: [16字节IV] + [加密数据]，使用base64编码
    """
    key_b64 = ENDFIELD_RC_KEY_B64_OVERSEA if is_oversea else ENDFIELD_RC_KEY_B64_CN
    if not key_b64:
        raise RuntimeError("Missing encryption key for remote config")

    raw = base64.b64decode(ciphertext_b64)
    iv, cipher = raw[:16], raw[16:]
    key = base64.b64decode(key_b64)

    pt = _aes_cbc_decrypt(cipher, key, iv)
    pt = _pkcs7_unpad(pt)
    return pt.decode("utf-8")


def _decrypt_u8_extra_config_bin(cipher: bytes) -> bytes:
    """解密U8额外配置二进制"""
    key_hex = ENDFIELD_U8_AES_KEY_HEX
    iv_hex = ENDFIELD_U8_AES_IV_HEX

    key = bytes.fromhex(key_hex)
    iv = bytes.fromhex(iv_hex)

    pt = _aes_cbc_decrypt(cipher, key, iv)
    return _pkcs7_unpad(pt)


@dataclass
class ConfigResult:
    """配置结果集合"""
    launcher_version: dict[str, Any]
    res_version: dict[str, Any]
    engine_config: dict[str, Any]
    network_config: dict[str, Any]
    game_config: dict[str, Any]


class EndfieldConfigFetcher:
    """游戏配置获取器"""
    
    def __init__(self, *, timeout: float = 20.0, is_oversea: bool = False):
        self._timeout = timeout
        self._is_oversea = is_oversea

    def _get_text(self, url: str) -> str:
        """获取HTTP文本响应"""
        with httpx.Client(timeout=self._timeout, follow_redirects=True) as client:
            r = client.get(url)
            r.raise_for_status()
            return r.text

    def _get_json(self, url: str) -> dict[str, Any]:
        """获取HTTP JSON响应"""
        with httpx.Client(timeout=self._timeout, follow_redirects=True) as client:
            r = client.get(url)
            r.raise_for_status()
            return r.json()

    def get_launcher_version(self, device: str) -> dict[str, Any]:
        """获取启动器版本信息"""
        return self._get_json(LAUNCHER_VERSION_URL.format(device=device))

    def get_u8_extra_config(self, file_path: str) -> dict[str, Any]:
        """获取U8额外配置"""
        url = file_path.rstrip("/") + "/U8Data/config/u8ExtraConfig.bin"
        with httpx.Client(timeout=self._timeout, follow_redirects=True) as client:
            r = client.get(url)
            r.raise_for_status()
            raw = r.content

        # 尝试直接解析为JSON，否则解密
        try:
            return json.loads(raw.decode("utf-8"))
        except Exception:
            pt = _decrypt_u8_extra_config_bin(raw)
            return json.loads(pt.decode("utf-8"))

    def get_res_version(self, device: str, version: str, rand_str: str) -> dict[str, Any]:
        """获取资源版本"""
        url = RES_VERSION_URL.format(device=device, version=version, rand_str=rand_str)
        return self._get_json(url)

    def _get_remote_config(self, url: str) -> dict[str, Any]:
        """获取远程配置（支持解密）"""
        text = self._get_text(url)

        # 尝试直接JSON解析，否则按密文解密
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            decrypted = _decrypt_remote_config_text(text, is_oversea=self._is_oversea)
            return json.loads(decrypted)

    def get_engine_config(self, device: str) -> dict[str, Any]:
        """获取引擎配置"""
        return self._get_json(ENGINE_CONFIG_URL.format(device="default"))

    def get_network_config(self, device: str) -> dict[str, Any]:
        """获取网络配置"""
        return self._get_remote_config(NETWORK_CONFIG_URL.format(device="default"))

    def get_game_config(self, device: str) -> dict[str, Any]:
        """获取游戏配置"""
        return self._get_remote_config(GAME_CONFIG_URL.format(device=device))

    def fetch_all(self, device: str) -> ConfigResult:
        """获取所有配置"""
        print(f"[Config] 获取启动器版本... (device: {device})")
        launcher = self.get_launcher_version(device)

        version = launcher.get("version", "")
        pkg = launcher.get("pkg") or {}
        file_path = pkg.get("file_path") or ""
        if not version or not file_path:
            raise RuntimeError(
                f"启动器版本缺少版本/文件路径: version={version!r} file_path={file_path!r}"
            )

        print(f"[Config] 游戏版本: {version}")
        print(f"[Config] 获取U8配置...")
        u8_cfg = self.get_u8_extra_config(file_path)
        rand_str = u8_cfg.get("randStr") or u8_cfg.get("rand_str") or ""
        if not rand_str:
            raise RuntimeError("U8配置缺少randStr")

        print(f"[Config] 获取资源版本...")
        res_version = self.get_res_version(device, version, rand_str)
        
        print(f"[Config] 获取引擎配置...")
        engine = self.get_engine_config(device)
        
        print(f"[Config] 获取网络配置...")
        network = self.get_network_config(device)
        
        print(f"[Config] 获取游戏配置...")
        game = self.get_game_config(device)

        print(f"[Config] 所有配置获取完成")
        
        return ConfigResult(
            launcher_version=launcher,
            res_version=res_version,
            engine_config=engine,
            network_config=network,
            game_config=game,
        )


def save_config_to_file(config_result: ConfigResult, out_dir: str) -> None:
    """保存配置到文件"""
    os.makedirs(out_dir, exist_ok=True)
    
    configs = {
        "launcher_version": config_result.launcher_version,
        "res_version": config_result.res_version,
        "engine_config": config_result.engine_config,
        "network_config": config_result.network_config,
        "game_config": config_result.game_config,
    }
    
    for name, obj in configs.items():
        path = os.path.join(out_dir, f"{name}.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(obj, f, ensure_ascii=False, indent=2)
        print(f"[Config] 已保存: {path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="游戏配置获取工具")
    parser.add_argument("--device", default="Windows", help="设备类型 (Windows/Android/IOS)")
    parser.add_argument("--oversea", action="store_true", help="是否为海外版本")
    parser.add_argument("--output", default="", help="输出目录（留空则不保存）")
    
    args = parser.parse_args()
    
    fetcher = EndfieldConfigFetcher(is_oversea=args.oversea)
    result = fetcher.fetch_all(args.device)
    
    print(f"\n启动器版本: {result.launcher_version.get('version')}")
    print(f"网络配置键数: {len(result.network_config)}")
    print(f"游戏配置键数: {len(result.game_config)}")
    
    if args.output:
        save_config_to_file(result, args.output)
