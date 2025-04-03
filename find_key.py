import os
import time
import requests
import logging
import re
from bitcoinlib.keys import Key
import json
import random
import asyncio

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("bitcoin_scan.log")
    ]
)

# Configurable parameters
MAX_RETRIES = 5
RETRY_DELAY = 5
MAX_RETRY_DELAY = 60
EXCLUDED_EXTENSIONS = {".exe", ".dll", ".bin", ".iso"}
session = requests.Session()

# Regular expression patterns for Bitcoin keys
PATTERNS = {
    "WIF (51/52 chars, starts with 5, K, or L)": re.compile(r'(^|\s|\n)([5KL][1-9A-HJ-NP-Za-km-z]{50,51})(\s|\n|$)')
}

# Set to store already processed addresses
PROCESSED_FILE = "processed_addresses.json"
sem = asyncio.Semaphore(100)  # Limit concurrent scans

def load_processed_addresses():
    """Load already processed addresses from JSON."""
    try:
        with open(PROCESSED_FILE, 'r') as f:
            return set(json.load(f))
    except (FileNotFoundError, json.JSONDecodeError):
        return set()

def save_processed_addresses():
    """Save processed addresses to JSON."""
    with open(PROCESSED_FILE, 'w') as f:
        json.dump(list(processed_addresses), f)

processed_addresses = load_processed_addresses()

async def read_file_async(file_path):
    """Asynchronously read a file for scanning."""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            return await asyncio.to_thread(f.read)
    except (FileNotFoundError, PermissionError) as e:
        logging.debug(f"Error opening file {file_path}: {e}")
        return None

def retry_request(url, retries=0):
    """Handles retry logic with exponential backoff + jitter."""
    try:
        response = session.get(url, timeout=10)
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 429:  # Rate limit exceeded
            wait_time = min(RETRY_DELAY * (2 ** retries) + random.uniform(0, 3), MAX_RETRY_DELAY)
            logging.warning(f"Rate limit exceeded. Retrying after {wait_time:.2f} seconds...")
            time.sleep(wait_time)
            return retry_request(url, retries + 1)
        else:
            logging.error(f"Request failed with status code {response.status_code}")
            return None
    except requests.exceptions.RequestException as e:
        logging.error(f"Error making request: {e}")
        return None

def get_balance_btc_explorer(address):
    """Check Bitcoin balance using local Bitcoin Explorer API."""
    url = f"https://btc-explorer.privatedns.org/api/address/{address}"
    result = retry_request(url)
    if result:
        balance = result.get("balance", 0)
        logging.info(f"Bitcoin address {address} balance: {balance} satoshis")
        return balance
    return -1

def private_key_to_address(private_key):
    """Convert a private key to a Bitcoin address."""
    try:
        if private_key.startswith(("5", "K", "L")):
            key = Key.from_wif(private_key)
            return key.address()
    except Exception as e:
        logging.debug(f"Error converting private key to address: {e}")
    return None

async def scan_file(file_path):
    """Scan a file asynchronously with concurrency limit."""
    async with sem:
        chunk = await read_file_async(file_path)
        if chunk is None:
            return
        for key_type, pattern in PATTERNS.items():
            matches = pattern.findall(chunk)
            for match in matches:
                match_cleaned = match[1].strip()
                address = private_key_to_address(match_cleaned)
                if address and address not in processed_addresses:
                    processed_addresses.add(address)
                    balance = get_balance_btc_explorer(address)
                    logging.info(f"Bitcoin address {address} balance: {balance} satoshis")

async def scan_directory(directory):
    """Recursively scan files asynchronously with a concurrency limit."""
    tasks = []
    for root, _, files in os.walk(directory):
        for file in files:
            if not any(file.lower().endswith(ext) for ext in EXCLUDED_EXTENSIONS):
                file_path = os.path.join(root, file)
                tasks.append(scan_file(file_path))
    await asyncio.gather(*tasks)

# Set the target directory to scan
TARGET_DIR = input("Enter the directory to scan (e.g., C:/Users/YourName/Documents): ").strip()
if not os.path.exists(TARGET_DIR):
    logging.error("Invalid directory. Exiting.")
    exit(1)

if __name__ == "__main__":
    logging.info(f"Scanning directory: {TARGET_DIR}...\n")
    asyncio.run(scan_directory(TARGET_DIR))
    save_processed_addresses()  # Save addresses after scan
    logging.info("Scan complete.")
