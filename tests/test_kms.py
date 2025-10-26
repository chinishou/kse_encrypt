# test_kms.py
import os
import json
import shutil
import tempfile
import pytest
import platform  # <-- Import the platform module

# 匯入您需要測試的模組
import admin_init
import keygen
import get_authed_sg

# 測試用的假 API Key
FAKE_API_KEY = "abcdef1234567890"


@pytest.fixture
def temp_dirs():
    """建立一個 pytest fixture 來生成暫時的 NFS 和 local 目錄"""
    tmp_nfs = tempfile.mkdtemp(prefix="kms_test_nfs_")
    tmp_local = tempfile.mkdtemp(prefix="kms_test_local_")
    yield tmp_nfs, tmp_local
    # 測試結束後清理目錄
    shutil.rmtree(tmp_nfs)
    shutil.rmtree(tmp_local)


@pytest.fixture
def config_file(temp_dirs):
    """建立一個 fixture 來生成暫時的 config.json 檔案"""
    tmp_nfs, tmp_local = temp_dirs
    # 定義測試用的設定
    cfg = {
        "nfs_dir": tmp_nfs,
        "local_dir": tmp_local,
        "build_secret_hex": "yoooooooooyooooo",  # 測試用的 secret
        "bind_attrs": ["mac", "hostname"],  # 選擇穩定的屬性進行測試
        "os_type": "linux"  # 根據您的測試環境調整
    }
    # 將設定寫入一個暫存的 config.json
    config_path = os.path.join(tmp_local, "config.json")
    with open(config_path, "w") as f:
        json.dump(cfg, f)

    # 返回 config 檔案路徑，供 monkeypatch 使用
    return config_path


def test_full_workflow(config_file, monkeypatch):
    """
    完整的端到端測試，模擬從初始化到取得金鑰的整個流程。
    """
    # 1. 設定環境: 使用 monkeypatch 將所有腳本的 CONFIG_PATH 指向我們暫時的設定檔
    monkeypatch.setattr(admin_init, "CONFIG_PATH", config_file)
    monkeypatch.setattr(keygen, "CONFIG_PATH", config_file)
    monkeypatch.setattr(get_authed_sg, "CONFIG_PATH", config_file)

    # 讀取設定以供後續驗證
    with open(config_file, 'r') as f:
        cfg = json.load(f)
    nfs_dir = cfg['nfs_dir']
    local_dir = cfg['local_dir']

    # 2. 執行 admin_init
    admin_init.admin_init(FAKE_API_KEY)

    # 驗證 admin_init 的產出
    api_part1_path = os.path.join(nfs_dir, "api_part1.json")
    api_part2_path = os.path.join(nfs_dir, "api_part2.json")
    assert os.path.exists(api_part1_path), "api_part1.json should be created by admin_init"
    assert os.path.exists(api_part2_path), "api_part2.json should be created by admin_init"

    with open(api_part1_path) as f:
        part1_data = json.load(f)
    assert all(k in part1_data for k in ["nonce", "ct", "salt"])

    # 3. 執行 keygen
    keygen.generate_local_key()

    # 驗證 keygen 的產出
    local_key_path = os.path.join(local_dir, "local_key.json")
    assert os.path.exists(local_key_path), "local_key.json should be created by keygen"

    with open(local_key_path) as f:
        local_data = json.load(f)
    assert all(k in local_data for k in ["nonce", "ct", "salt"])

    # === MODIFICATION START ===
    # 驗證檔案權限是否設定正確
    # 只在非 Windows 系統上檢查 POSIX 權限
    if platform.system() != "Windows":
        assert oct(os.stat(local_key_path).st_mode)[-3:] == "600"
    # === MODIFICATION END ===

    # 4. 執行 get_api_key 並驗證結果
    retrieved_key = get_authed_sg.get_api_key()
    assert retrieved_key == FAKE_API_KEY, "The retrieved API key must match the original fake key"
    print(f"\nTest successful! Retrieved key: '{retrieved_key}'")


def test_keygen_aborts_if_key_exists(config_file, monkeypatch):
    """測試如果 local_key.json 已存在，keygen 是否會中止"""
    monkeypatch.setattr(keygen, "CONFIG_PATH", config_file)

    # 第一次執行，應該會成功
    keygen.generate_local_key()

    # 第二次執行，應該會直接返回
    # 我們可以透過擷取 stdout 來驗證，但為了簡單起見，這裡只確認它不會拋出錯誤
    try:
        keygen.generate_local_key()
    except Exception as e:
        pytest.fail(f"Keygen should not raise an error on second run, but got: {e}")


def test_get_api_key_fails_without_local_key(config_file, monkeypatch):
    """測試在沒有執行 keygen 的情況下，get_api_key 是否會拋出預期的錯誤"""
    monkeypatch.setattr(get_authed_sg, "CONFIG_PATH", config_file)

    # 不執行 keygen，直接呼叫 get_api_key
    with pytest.raises(FileNotFoundError, match="local_key.json not found"):
        get_authed_sg.get_api_key()