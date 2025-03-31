import os
import re
import requests
from bitcoinlib.keys import Key
from binascii import unhexlify
import time
import logging

# Set up logging
logging.basicConfig(
    level=logging.INFO,  # Log level (INFO, DEBUG, ERROR, etc.)
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),  # Print logs to console
        logging.FileHandler("bitcoin_scan.log")  # Also log to a file
    ]
)

# File extensions to exclude
EXCLUDED_EXTENSIONS = {".exe", ".dll", ".bin", ".iso"}  # Add more if needed

# Regular expressions for different Bitcoin private key formats, refined for less false positives
PATTERNS = {
    "Raw Hex (64 characters)": re.compile(r'[\s\n][0-9a-fA-F]{64}[\s\n]'),
    "WIF (51/52 chars, starts with 5, K, or L)": re.compile(r'[\s\n][5KL][1-9A-HJ-NP-Za-km-z]{50,51}[\s\n]'),
    "Mini Private Key (starts with S, 22-30 chars)": re.compile(r'[\s\n]S[1-9A-HJ-NP-Za-km-z]{21,29}[\s\n]'),
    "BIP38 Encrypted Key (starts with 6P, 58 chars)": re.compile(r'[\s\n]6P[1-9A-HJ-NP-Za-km-z]{56}[\s\n]')
}

# Blockchair API URL to check balance
BLOCKCHAIR_API_URL = "https://api.blockchair.com/bitcoin/dashboards/address/"

# Configure the delay between requests to avoid rate limits (can be adjusted)
REQUEST_DELAY = 3

# Set to store addresses already checked
checked_addresses = set()

def get_balance(address, retries=3, backoff_time=30):
    """Check the balance of a Bitcoin address using Blockchair API."""
    if address in checked_addresses:
        return 0  # Skip if already checked

    logging.info(f"Checking balance for Bitcoin address: {address}")
    try:
        response = requests.get(f"{BLOCKCHAIR_API_URL}{address}", timeout=10)  # Set timeout for request
        if response.status_code == 429:  # Rate limit exceeded
            if retries > 0:
                logging.warning(f"Rate limit exceeded. Retrying after {backoff_time} seconds...")
                time.sleep(backoff_time)
                return get_balance(address, retries - 1, backoff_time * 2)  # Increase backoff time
            else:
                logging.error("Maximum retries reached. Skipping address.")
                return 0

        data = response.json()
        if "data" in data and address in data["data"]:
            balance = data["data"][address]["address"]["balance"]
            if balance > 0:
                logging.info(f"Found BTC!!! Bitcoin address: {address} balance: {balance}")
                return balance
        return 0
    except requests.exceptions.Timeout as e:
        logging.warning(f"Timeout error for {address}: {e}")
        if retries > 0:
            logging.info(f"Retrying after {backoff_time} seconds...")
            time.sleep(backoff_time)
            return get_balance(address, retries - 1, backoff_time * 2)  # Increase backoff time
        else:
            logging.error(f"Timeout error: Maximum retries reached. Skipping address.")
            return 0
    except requests.exceptions.RequestException as e:
        logging.error(f"Error checking balance for {address}: {e}")
        return -1
    finally:
        checked_addresses.add(address)  # Add address to the set of checked addresses
        time.sleep(REQUEST_DELAY)  # Adding delay to avoid rate limit issues

def private_key_to_address(private_key):
    """Convert a private key to a Bitcoin address."""
    try:
        if private_key.startswith("5") or private_key.startswith("K") or private_key.startswith("L"):
            # WIF format, use the correct method for WIF private keys
            key = Key.from_wif(private_key)
        elif len(private_key) == 64 and all(c in "0123456789abcdefABCDEF" for c in private_key):
            # Raw hex format (64 characters), convert hex to bytes
            key_bytes = unhexlify(private_key)
            key = Key(key_bytes)  # Directly use the Key constructor with the byte data
        else:
            # Invalid private key format
            return None

        address = key.address()
        return address
    except Exception as e:
        logging.error(f"Error converting private key to address: {e}")
        return None


def scan_file(file_path):
    """Scans a file for Bitcoin private keys."""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            # Read file in chunks for better memory management
            while chunk := f.read(1024):
                for key_type, pattern in PATTERNS.items():
                    matches = pattern.findall(chunk)
                    if matches:
                        for match in matches:
                            match_cleaned = match.strip()

                            # Convert private key to address and check balance
                            address = private_key_to_address(match_cleaned)
                            if address:
                                balance = get_balance(address)
                                if balance > 0:
                                    logging.info(f"    -> Address {address} has a balance: {balance} satoshis")
                                else:
                                    logging.info(f"    -> Address {address} has no balance.")
    except (FileNotFoundError, PermissionError) as e:
        logging.error(f"Error opening file {file_path}: {e}")
    except Exception as e:
        logging.error(f"Error reading file {file_path}: {e}")


def scan_directory(directory):
    """Recursively scans all files in a directory, skipping specific file types."""
    for root, _, files in os.walk(directory):
        for file in files:
            if any(file.lower().endswith(ext) for ext in EXCLUDED_EXTENSIONS):
                continue  # Skip excluded file types

            scan_file(os.path.join(root, file))


# Set the target directory to scan
TARGET_DIR = "C:/"

if __name__ == "__main__":
    logging.info(f"Scanning directory: {TARGET_DIR}...\n")
    scan_directory(TARGET_DIR)
    logging.info("\n[✔] Scan complete.")
