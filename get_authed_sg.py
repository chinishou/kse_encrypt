# get_authed_sg.py
import os, json, base64
from pathlib import Path
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from get_hardware_fingerprint import get_hardware_fingerprint

CONFIG_PATH = "config.json"


def load_config():
    with open(CONFIG_PATH, "r") as f:
        cfg = json.load(f)
    cfg["local_dir"] = os.path.expanduser(cfg["local_dir"])
    cfg["nfs_dir"] = os.path.expanduser(cfg["nfs_dir"])
    return cfg


def derive_key(secret: bytes, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=32, n=2 ** 14, r=8, p=1)
    return kdf.derive(secret)


def get_api_key():
    cfg = load_config()

    # Step 1: 用當前硬體指紋解密本地的 Part 2 -> 得到 "123456"
    local_key_path = Path(cfg["local_dir"]) / "local_key.json"
    if not local_key_path.exists():
        raise FileNotFoundError("local_key.json not found; please run keygen.py first.")

    with open(local_key_path, "r") as f:
        local_data = json.load(f)

    salt_local = base64.b64decode(local_data["salt"])
    nonce_local = base64.b64decode(local_data["nonce"])
    ct_local = base64.b64decode(local_data["ct"])

    hw_bytes = get_hardware_fingerprint(cfg["bind_attrs"], cfg["os_type"])
    key_from_hw = derive_key(hw_bytes, salt_local)
    aes_gcm_hw = AESGCM(key_from_hw)

    try:
        part2_plaintext = aes_gcm_hw.decrypt(nonce_local, ct_local, None)
    except Exception as e:
        raise PermissionError(f"Failed to decrypt local key. Hardware fingerprint may have changed. Error: {e}")

    # Step 2: 用 "123456" 解密 NFS 的 Part 1 -> 得到 "abcdef"
    nfs_dir = Path(cfg["nfs_dir"])
    part1_path = nfs_dir / "api_part1.json"
    if not part1_path.exists():
        raise FileNotFoundError(f"'{part1_path}' not found on NFS. Please run admin_init.py.")

    with open(part1_path, "r") as f:
        part1_data = json.load(f)

    salt_nfs = base64.b64decode(part1_data["salt"])
    nonce_nfs = base64.b64decode(part1_data["nonce"])
    ct_nfs = base64.b64decode(part1_data["ct"])

    # 使用解密出的 part2_plaintext 來衍生金鑰
    key_from_part2 = derive_key(part2_plaintext, salt_nfs)
    aes_gcm_nfs = AESGCM(key_from_part2)
    part1_plaintext = aes_gcm_nfs.decrypt(nonce_nfs, ct_nfs, None)

    # Step 3: 組合 "abcdef" + "123456"
    full_api_key = (part1_plaintext + part2_plaintext).decode('utf-8')

    return full_api_key


def get_authed_session() -> object:
    api_key = get_api_key()
    try:
        # 假設您有一個名為 shotgun_api3 的庫
        from shotgun_api3 import Shotgun
        # 請替換為您的 ShotGrid URL
        sg = Shotgun("https://my-site.shotgrid.autodesk.com",
                     script_name="my_script",
                     api_key=api_key)
        print("Successfully created Shotgun object.")
        return sg
    except ImportError:
        print("Warning: shotgun_api3 library not found. Returning raw API key.")
        return api_key
    except Exception as e:
        raise RuntimeError("Failed to create Shotgun object") from e


if __name__ == '__main__':
    try:
        retrieved_key = get_api_key()
        print("Successfully retrieved API key:", retrieved_key)
        # sg_instance = get_authed_sg_obj()
    except Exception as e:
        print(f"An error occurred: {e}")