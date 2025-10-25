import uuid, platform, subprocess, os
import hashlib


def get_mac():
    return uuid.getnode().to_bytes(6, 'big')


def get_cpu():
    return platform.processor().encode()


def get_hostname():
    return platform.node().encode()


def get_bios(os_type):
    try:
        if os_type == "windows":
            sn = subprocess.check_output("wmic bios get serialnumber", shell=True)
            return sn.strip()
        elif os_type == "linux":
            with open("/sys/class/dmi/id/bios_version", "rb") as f:
                return f.read().strip()
    except Exception:
        return b"none"


def get_baseboard(os_type):
    try:
        if os_type == "windows":
            sn = subprocess.check_output("wmic baseboard get serialnumber", shell=True)
            return sn.strip()
        elif os_type == "linux":
            with open("/sys/class/dmi/id/board_serial", "rb") as f:
                return f.read().strip()
    except Exception:
        return b"none"


def get_uuid(os_type):
    try:
        if os_type == "windows":
            sn = subprocess.check_output("wmic csproduct get UUID", shell=True)
            return sn.strip()
        elif os_type == "linux":
            with open("/sys/class/dmi/id/product_uuid", "rb") as f:
                return f.read().strip()
    except Exception:
        return b"none"


def get_tpm(os_type):
    try:
        if os_type == "linux" and os.path.exists("/sys/class/tpm/tpm0"):
            with open("/sys/class/tpm/tpm0/device/description", "rb") as f:
                return f.read().strip()
        else:
            return b"none"
    except Exception:
        return b"none"


HARDWARE_GETTERS = {
    "mac": get_mac,
    "cpu": get_cpu,
    "hostname": get_hostname,
    "bios": get_bios,
    "baseboard": get_baseboard,
    "uuid": get_uuid,
    "tpm": get_tpm,
}


def get_hardware_fingerprint(attrs, os_type):
    parts = []
    for attr in attrs:
        if attr in ("bios", "baseboard", "uuid", "tpm"):
            val = HARDWARE_GETTERS[attr](os_type)
        else:
            val = HARDWARE_GETTERS[attr]()
        parts.append(val)
    return hashlib.sha256(b"|".join(parts)).digest()
