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


def generate_local_key():
    cfg = load_config()
    local_dir = Path(cfg["local_dir"])
    local_dir.mkdir(parents=True, exist_ok=True)
    local_key_path = local_dir / "local_key.json"

    if local_key_path.exists():
        print(f"Local key already exists at '{local_key_path}'. Aborting.")
        return

    # Step 1: 用 build_secret 解密 NFS 的 Part 2 -> 得到 "123456"
    nfs_dir = Path(cfg["nfs_dir"])
    part2_path = nfs_dir / "api_part2.json"
    if not part2_path.exists():
        print(f"Error: '{part2_path}' not found. Please run admin_init first.")
        return

    with open(part2_path, "r") as f:
        part2_data = json.load(f)

    build_secret = bytes.fromhex(cfg["build_secret_hex"])
    salt_from_nfs = base64.b64decode(part2_data["salt"])
    nonce_from_nfs = base64.b64decode(part2_data["nonce"])
    ct_from_nfs = base64.b64decode(part2_data["ct"])

    key_for_part2 = derive_key(build_secret, salt_from_nfs)
    aes_gcm = AESGCM(key_for_part2)

    try:
        part2_plaintext = aes_gcm.decrypt(nonce_from_nfs, ct_from_nfs, None)
    except Exception as e:
        print(f"Failed to decrypt Part 2 from NFS. Check your build_secret. Error: {e}")
        return

    # Step 2: 取得硬體指紋 hw_bytes
    hw_bytes = get_hardware_fingerprint(cfg["bind_attrs"], cfg["os_type"])

    # Step 3: 用 hw_bytes 加密 "123456", 保存到本地: local_key.json
    salt_for_local = os.urandom(16)
    key_for_local = derive_key(hw_bytes, salt_for_local)
    aes_gcm_local = AESGCM(key_for_local)
    nonce_for_local = os.urandom(12)
    ct_for_local = aes_gcm_local.encrypt(nonce_for_local, part2_plaintext, None)

    with open(local_key_path, "w") as f:
        json.dump({
            "salt": base64.b64encode(salt_for_local).decode(),
            "nonce": base64.b64encode(nonce_for_local).decode(),
            "ct": base64.b64encode(ct_for_local).decode()
        }, f)

    os.chmod(local_key_path, 0o600)  # 設定檔案權限為僅擁有者可讀寫
    print(f"Generated local key at '{local_key_path}'")


if __name__ == "__main__":
    generate_local_key()