from flask import Flask, send_file, Response, redirect, url_for, request, abort
import os
import sys
import logging
import requests # Import requests for making HTTP calls to your backend API
import json # For parsing JSON responses from your API

# Import necessary components from ocho.py
# We still need _check_integrity, ColoredFormatter, and colorama
from ocho import (
    _check_integrity,
    logger as ocho_logger, # Rename to avoid conflict with app.logger
    ColoredFormatter,
    colorama
)

app = Flask(__name__)

# --- Configure Logging for app.py ---
app_handler = logging.StreamHandler()
app_handler.setFormatter(ColoredFormatter())
app.logger.addHandler(app_handler)
app.logger.setLevel(logging.INFO)

# Initialize colorama for app.py's own console output
colorama.init(autoreset=True)

# --- Your Backend API URL for Device Verification ---
SUBSCRIPTION_API_URL = "https://darkxdeath.onrender.com/api.php"

# --- New function to verify device with your backend API ---
def verify_device_with_backend(device_id, user_name):
    try:
        # Construct the URL for your API
        # Assuming your api.php expects device_id and user_name as query parameters
        api_url = f"{SUBSCRIPTION_API_URL}?device_id={device_id}&user_name={user_name}"
        
        app.logger.info(f"{colorama.Fore.BLUE}Calling backend API for verification: {api_url}{colorama.Style.RESET_ALL}")
        
        # Make the HTTP GET request to your backend API
        response = requests.get(api_url, timeout=10) # Add a timeout to prevent hanging
        response.raise_for_status() # Raise an exception for HTTP errors (4xx or 5xx)
        
        response_json = response.json()
        
        # Assuming your API returns a JSON with a 'status' field, e.g., {"status": "active"}
        # Adjust this logic based on the actual response format of your api.php
        status = response_json.get("status")
        message = response_json.get("message", "No message from backend.")

        if status == "active":
            return True, message
        else:
            return False, message

    except requests.exceptions.RequestException as e:
        app.logger.error(f"{colorama.Fore.RED}Error communicating with backend API ({SUBSCRIPTION_API_URL}): {e}{colorama.Style.RESET_ALL}")
        return False, f"Backend API communication error: {e}"
    except json.JSONDecodeError:
        app.logger.error(f"{colorama.Fore.RED}Backend API returned invalid JSON: {response.text}{colorama.Style.RESET_ALL}")
        return False, "Backend API returned invalid response."
    except Exception as e:
        app.logger.error(f"{colorama.Fore.RED}An unexpected error occurred during backend verification: {e}{colorama.Style.RESET_ALL}")
        return False, f"Unexpected verification error: {e}"


@app.route('/')
def index():
    return '''
    <h1>OCHOxDARK Server</h1>
    '''

@app.route('/ocho.py')
def serve_ocho():
    # Get device_id and user_name from query parameters
    device_id = request.args.get('device_id')
    user_name = request.args.get('user_name')

    if not device_id or not user_name:
        app.logger.warning(f"{colorama.Fore.YELLOW}Access attempt to /ocho.py without required 'device_id' or 'user_name' query parameters. IP: {request.remote_addr}{colorama.Style.RESET_ALL}")
        return redirect(url_for('index'))

    app.logger.info(f"{colorama.Fore.CYAN}Attempting to serve ocho.py for Device ID: {device_id} (User: {user_name}) from IP: {request.remote_addr}{colorama.Style.RESET_ALL}")

    # --- Verify device using your backend API ---
    is_verified, message = verify_device_with_backend(device_id, user_name)

    if is_verified:
        app.logger.info(f"{colorama.Fore.GREEN}Device ID: {device_id} (User: {user_name}) verified by backend. Access granted! Message: {message}{colorama.Style.RESET_ALL}")
        
        # Perform an integrity check from ocho.py just before serving the file
        if not _check_integrity():
            app.logger.error(f"{colorama.Fore.RED}Integrity check failed during ocho.py access for {device_id}. Potential tampering detected.{colorama.Style.RESET_ALL}")
            return "Access Denied: Integrity check failed.", 403

        if os.path.exists('ocho.py'):
            with open('ocho.py', 'r') as f:
                content = f.read()
            return Response(content, mimetype='text/plain')
        else:
            app.logger.error(f"{colorama.Fore.RED}ocho.py file not found on server for {device_id}.{colorama.Style.RESET_ALL}")
            return "File not found", 404
    else:
        app.logger.warning(f"{colorama.Fore.YELLOW}Device ID: {device_id} (User: {user_name}) verification failed by backend. Message: {message}{colorama.Style.RESET_ALL}")
        return f"Access Denied: Device verification failed. {message}", 403

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
