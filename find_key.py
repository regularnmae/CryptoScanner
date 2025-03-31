import os
import time
import requests
import logging
import re
from bitcoinlib.keys import Key
from binascii import unhexlify


# Set up logging
logging.basicConfig(
    level=logging.INFO,  # Log level (INFO, DEBUG, ERROR, etc.)
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),  # Print logs to console
        logging.FileHandler("bitcoin_scan.log")  # Also log to a file
    ]
)

# Configurable parameters
MAX_RETRIES = 5  # Maximum number of retries for API requests
RETRY_DELAY = 5  # Initial delay before retrying (in seconds)
MAX_RETRY_DELAY = 60  # Maximum delay between retries (in seconds)
EXCLUDED_EXTENSIONS = {".exe", ".dll", ".bin", ".iso"}  # File extensions to skip

# Regular expressions for different Bitcoin private key formats
PATTERNS = {
    "Raw Hex (64 characters)": re.compile(r'[\s\n][0-9a-fA-F]{64}[\s\n]'),
    "WIF (51/52 chars, starts with 5, K, or L)": re.compile(r'[\s\n][5KL][1-9A-HJ-NP-Za-km-z]{50,51}[\s\n]'),
    "Mini Private Key (starts with S, 22-30 chars)": re.compile(r'[\s\n]S[1-9A-HJ-NP-Za-km-z]{21,29}[\s\n]'),
    "BIP38 Encrypted Key (starts with 6P, 58 chars)": re.compile(r'[\s\n]6P[1-9A-HJ-NP-Za-km-z]{56}[\s\n]')
}

def get_balance_blockchain(address):
    """Check Bitcoin balance using Blockchain.com API with rate limiting."""
    url = f"https://blockchain.info/rawaddr/{address}"

    retries = 0
    while retries < MAX_RETRIES:
        try:
            response = requests.get(url, timeout=10)

            if response.status_code == 200:
                result = response.json()
                balance = result.get("final_balance", 0)
                logging.info(f"Bitcoin address {address} balance: {balance} satoshis")
                return balance
            elif response.status_code == 429:
                # If rate-limited, apply exponential backoff
                wait_time = min(RETRY_DELAY * (2 ** retries), MAX_RETRY_DELAY)
                logging.warning(f"Rate limit exceeded. Retrying after {wait_time} seconds...")
                time.sleep(wait_time)
                retries += 1
            else:
                logging.error(f"Blockchain.com API request failed with status code {response.status_code}")
                return -1

        except requests.exceptions.RequestException as e:
            logging.error(f"Error connecting to Blockchain.com API: {e}")
            retries += 1
            wait_time = min(RETRY_DELAY * (2 ** retries), MAX_RETRY_DELAY)
            logging.warning(f"Retrying after {wait_time} seconds...")
            time.sleep(wait_time)

    logging.error(f"Max retries reached. Could not fetch balance for address {address}")
    return -1

def private_key_to_address(private_key):
    """Convert a private key to a Bitcoin address."""
    try:
        if private_key.startswith("5") or private_key.startswith("K") or private_key.startswith("L"):
            # WIF format
            key = Key.from_wif(private_key)
        elif len(private_key) == 64 and all(c in "0123456789abcdefABCDEF" for c in private_key):
            # Raw hex format (64 characters)
            key_bytes = unhexlify(private_key)
            key = Key(key_bytes)
        else:
            logging.error(f"Invalid private key format: {private_key}")
            return None

        return key.address()
    except Exception as e:
        logging.error(f"Error converting private key to address: {e}")
        return None

def scan_file(file_path):
    """Scans a file for Bitcoin private keys."""
    if not os.path.exists(file_path):
        logging.error(f"File does not exist: {file_path}")
        return

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            # Read file in chunks for better memory management
            while chunk := f.read(1024):
                for key_type, pattern in PATTERNS.items():
                    matches = pattern.findall(chunk)
                    if matches:
                        for match in matches:
                            match_cleaned = match.strip()
                            address = private_key_to_address(match_cleaned)
                            if address:
                                balance = get_balance_blockchain(address)
                                if balance > 0:
                                    logging.info(f"    -> Address {address} has a balance: {balance} satoshis")
                                else:
                                    logging.info(f"    -> Address {address} has no balance.")
                            else:
                                logging.debug(f"Invalid private key found: {match_cleaned}")
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
