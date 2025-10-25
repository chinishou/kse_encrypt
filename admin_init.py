import os, json, base64
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

CONFIG_PATH = "config.json"


def load_config():
    with open(CONFIG_PATH, "r") as f:
        cfg = json.load(f)
    cfg["nfs_dir"] = os.path.expanduser(cfg["nfs_dir"])
    return cfg


def derive_key(secret: bytes, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=32, n=2 ** 14, r=8, p=1)
    return kdf.derive(secret)


def encrypt_data(key: bytes, plaintext: bytes) -> dict:
    aes = AESGCM(key)
    nonce = os.urandom(12)
    ct = aes.encrypt(nonce, plaintext, None)
    return {
        "nonce": base64.b64encode(nonce).decode(),
        "ct": base64.b64encode(ct).decode()
    }


def admin_init(api_key_plaintext: str):
    cfg = load_config()
    nfs_dir = Path(cfg["nfs_dir"])
    nfs_dir.mkdir(parents=True, exist_ok=True)

    # 將 API Key 分為 Part 1 和 Part 2
    # 為了簡單起見，我們對半分
    split_point = len(api_key_plaintext) // 2
    part1_str = api_key_plaintext[:split_point]
    part2_str = api_key_plaintext[split_point:]

    part1 = part1_str.encode('utf-8')
    part2 = part2_str.encode('utf-8')

    print(f"API Key split into: Part1='{part1_str}', Part2='{part2_str}'")

    # Step 1: Part 2 "123456" -> 用 build_secret 加密, 保存到 NFS: api_part2.json
    build_secret = bytes.fromhex(cfg["build_secret_hex"])
    salt_for_part2 = os.urandom(16)
    key_for_part2 = derive_key(build_secret, salt_for_part2)
    encrypted_part2_data = encrypt_data(key_for_part2, part2)
    encrypted_part2_data["salt"] = base64.b64encode(salt_for_part2).decode()

    with open(nfs_dir / "api_part2.json", "w") as f:
        json.dump(encrypted_part2_data, f, indent=2)
    print(f"Encrypted Part 2 saved to {nfs_dir / 'api_part2.json'}")

    # Step 2: Part 1 "abcdef" -> 用 Part 2 "123456" 加密, 保存到 NFS: api_part1.json
    salt_for_part1 = os.urandom(16)
    # 這裡直接用 Part 2 的明文作為密碼來衍生金鑰
    key_for_part1 = derive_key(part2, salt_for_part1)
    encrypted_part1_data = encrypt_data(key_for_part1, part1)
    encrypted_part1_data["salt"] = base64.b64encode(salt_for_part1).decode()

    with open(nfs_dir / "api_part1.json", "w") as f:
        json.dump(encrypted_part1_data, f, indent=2)
    print(f"Encrypted Part 1 saved to {nfs_dir / 'api_part1.json'}")

    print(f"\nAdmin init finished. Files written to {nfs_dir}")


if __name__ == "__main__":
    api_key_input = input("Enter the full API key: ").strip()
    if not api_key_input:
        print("API key cannot be empty.")
    else:
        admin_init(api_key_input)