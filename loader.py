import requests
import os
import sys
import subprocess
import hashlib
import platform
import uuid
import time
import warnings
import urllib3
import threading
import re
from colorama import Fore, Style, init

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
init(autoreset=True)

ASHH = "https://ochoxash.onrender.com/ocho.py?device_id={device_id}&user_name={user_name}"
ASH = "ash_checker.py"
TEMP_DIR = os.path.join(os.path.expanduser("~"), ".darkxstorms_loader")
ID_DIR = os.path.expanduser("~/.darkxstorms_loader_id")
ID_FILE = os.path.join(ID_DIR, "loader_id.txt")
ASH = "KUPAL"

def print_status(message, status_type="info"):
    if status_type == "success":
        print(f"{Fore.GREEN}[SUCCESS]{Style.RESET_ALL} {message}")
    elif status_type == "warning":
        print(f"{Fore.YELLOW}[WARNING]{Style.RESET_ALL} {message}")
    elif status_type == "error":
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} {message}")
    
    else:
        print(f"{message}")

def get_permanent_manual_id():
    os.makedirs(ID_DIR, exist_ok=True)
    
    if os.path.exists(ID_FILE):
        try:
            with open(ID_FILE, 'r') as file:
                device_id = file.read().strip()
                if device_id and '_' in device_id:
                    user_name = device_id.split('_', 1)[0]
                    if 3 <= len(user_name) <= 20 and len(device_id.split('_', 1)[1]) == 4:
                        print_status(f"Loaded permanent ID: {device_id} (:User  {user_name})", "success")
                        return device_id, user_name
        except IOError:
            pass
        print_status("Invalid saved ID file. Will prompt for new permanent inputs.", "warning")
    
    while True:
        user_name = input(f"{Fore.YELLOW}Enter your permanent user_name (3-20 alphanumeric characters): {Style.RESET_ALL}").strip()
        if 3 <= len(user_name) <= 20 and re.match(r'^[a-zA-Z0-9]+$', user_name):
            break
        print_status("Invalid: Must be 3-20 alphanumeric characters.", "error")
    
    while True:
        device_id = input(f"{Fore.YELLOW}Enter your permanent device_id (format: {user_name}_XXXX where XXXX is 4 alphanumeric characters): {Style.RESET_ALL}").strip()
        if device_id.startswith(f"{user_name}_"):
            code = device_id[len(user_name) + 1:]
            if len(code) == 4 and re.match(r'^[a-zA-Z0-9]+$', code):
                full_device_id = f"{user_name}_{code}"
                try:
                    with open(ID_FILE, 'w') as file:
                        file.write(full_device_id)
                    print_status(f"Saved permanent ID: {full_device_id} (:User  {user_name})", "success")
                    return full_device_id, user_name
                except IOError:
                    print_status("Failed to save permanent ID file.", "error")
                    return full_device_id, user_name
            else:
                print_status("Invalid code: Must be exactly 4 alphanumeric characters after '_' (e.g., abcd or 1234).", "error")
        else:
            print_status(f"Invalid format: Must start with '{user_name}_'.", "error")

def check_loader_subscription(device_id, user_name):
    SUBSCRIPTION_API = "https://darkxdeath.onrender.com/api.php"
    url = f"{SUBSCRIPTION_API}?device_id={device_id}&user_name={user_name}&loader_check=true"
    try:
        response = requests.get(url, verify=False, timeout=15)
        response.raise_for_status()
        response_json = response.json()
        return response_json
    except requests.exceptions.RequestException:
        return {"status": "error", "message": "Loader subscription server request failed."}

def download_and_execute_checker(device_id, user_name):
    ash_url = ASHH.format(device_id=device_id, user_name=user_name)
    
    os.makedirs(TEMP_DIR, exist_ok=True)
    local_checker_path = os.path.join(TEMP_DIR, ASH)
    done = False
    error_occurred = False

    headers = {
        'X-Loader-Request': ASH,
        'User-Agent': 'DARKxStorms-Loader/1.0'
    }

    def download_func():
        nonlocal done, error_occurred
        try:
            response = requests.get(ash_url, stream=True, timeout=30, headers=headers)
            response.raise_for_status() 
            block_size = 1024
            with open(local_checker_path, 'wb') as f:
                for data in response.iter_content(block_size):
                    f.write(data)
            done = True
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 403:
                print_status(f"Access denied kupal")
            else:
                print_status(f"HTTP Error during download:")
            error_occurred = True
        except Exception as e:
            print_status(f"Error during download:")
            error_occurred = True

    thread = threading.Thread(target=download_func)
    thread.start()

    bar_width = 50
    for progress in range(1, 101):
        filled = int(bar_width * progress / 100)
        bar = f"{Fore.GREEN}{'-' * filled}{Fore.WHITE}{'-' * (bar_width - filled)}{Style.RESET_ALL}"
        sys.stdout.write(f"\r{Fore.WHITE}Loading: [{bar}] {progress}%")
        sys.stdout.flush()
        time.sleep(0.03)
        if done:
            while progress < 100:
                progress += 1
                filled = int(bar_width * progress / 100)
                bar = f"{Fore.GREEN}{'-' * filled}{Fore.WHITE}{'-' * (bar_width - filled)}{Style.RESET_ALL}"
                sys.stdout.write(f"\r{Fore.WHITE}Loading: [{bar}] {progress}%")
                sys.stdout.flush()
                time.sleep(0.01)
            break

    thread.join()
    sys.stdout.write("\n")

    if error_occurred or not done:
        print_status("Failed to download checker. Please check your internet connection, permanent ID, ")
        sys.exit(1)

    try:
        subprocess.run([sys.executable, local_checker_path] + sys.argv[1:])
    except Exception:
        pass

if __name__ == "__main__":
    print(f"{Fore.WHITE}@DARKxStorms Loader...{Style.RESET_ALL}")
    device_id, user_name = get_permanent_manual_id()
    
    subscription_response = check_loader_subscription(device_id, user_name)
    status = subscription_response.get("status")

    if status == "active":
        download_and_execute_checker(device_id, user_name)
    elif status in ["pending", "registered_pending"]:
        print_status(f"Loader Subscription Status: Pending Approval.", "warning")
        print_status(f"Your Permanent Device ID: {device_id}", "info")
        sys.exit(0)
    elif status == "expired":
        print_status(f"Loader Subscription Status: Expired.", "error")
        print_status(f"Your Permanent Device ID: {device_id}", "info")
        sys.exit(0)
    else:
        print_status(f"Loader Subscription Status Unknown: {status}.", "error")
        print_status(f"Your Permanent Device ID: {device_id}", "info")
        sys.exit(0)