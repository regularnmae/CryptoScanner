import argparse
import os
import time
import requests
import logging
import re
import json
import random
import asyncio
from bitcoinlib.keys import Key
from bitcoinlib.wallets import Wallet

# Set up logging
logging.basicConfig(
    level=logging.DEBUG,
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

# Regular expression patterns for Bitcoin keys & addresses
PATTERNS = {
    "WIF (51/52 chars, starts with 5, K, or L)": re.compile(r'\b([5KL][1-9A-HJ-NP-Za-km-z]{50,51})\b'),
    "Legacy Address (P2PKH)": re.compile(r'\b(1[a-km-zA-HJ-NP-Z1-9]{25,34})\b'),
    "SegWit Address (P2SH)": re.compile(r'\b(3[a-km-zA-HJ-NP-Z1-9]{25,34})\b'),
    "Bech32 Address (P2WPKH/P2WSH)": re.compile(r'\b(bc1[a-zA-HJ-NP-Z0-9]{25,62})\b')
}

# File to store processed addresses, private keys, and balances
PROCESSED_FILE = "processed_addresses.json"
sem = asyncio.Semaphore(100)  # Limit concurrent scans
SAVE_INTERVAL = 100  # Save progress every 100 addresses

def load_processed_addresses():
    """Load already processed addresses with private keys and balances."""
    try:
        with open(PROCESSED_FILE, 'r') as f:
            return json.load(f)  # Should be a dict {address: {"private_key": key, "balance": balance}}
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

def save_processed_addresses():
    """Save processed addresses with private keys and balances to JSON."""
    with open(PROCESSED_FILE, 'w') as f:
        json.dump(processed_addresses, f, indent=4)

processed_addresses = load_processed_addresses()

async def read_file_async(file_path):
    """Asynchronously read a file for scanning in chunks."""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            while chunk := await asyncio.to_thread(f.read, 4096):  # Read in 4KB chunks
                yield chunk
    except (FileNotFoundError, PermissionError) as e:
        logging.debug(f"Error opening file {file_path}: {e}")

def retry_request(url, retries=0):
    """Handles retry logic with exponential backoff + jitter."""
    try:
        response = session.get(url, timeout=10)
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 429:
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
    """Check Bitcoin balance using BTC-RPC-Explorer API."""
    API_BASE_URL = "https://btc-explorer.privatedns.org/api"  # Replace with your actual BTC-RPC-Explorer URL
    url = f"{API_BASE_URL}/address/{address}"

    result = retry_request(url)
    if not result:
        logging.error(f"Failed to fetch balance for {address}")
        return -1  # Indicate failure

    balance_satoshis = result.get("txHistory", {}).get("balanceSat", -1)
    balance_btc = balance_satoshis / 1e8  # Convert satoshis to BTC
    logging.info(f"Bitcoin address {address} balance: {balance_btc} BTC ({balance_satoshis} satoshis)")
    return balance_btc

def bip32_private_key_to_address(xprv):
    """Convert a BIP-32 xprv to a Bitcoin address."""
    try:
        wallet = Wallet.create("temp_wallet", keys=xprv, network='bitcoin', db_uri=':memory:')
        return wallet.get_key().address
    except Exception as e:
        logging.debug(f"Error converting xprv to address: {e}")
        return None

def private_key_to_address(private_key):
    """Convert a private key (WIF or extended) to a Bitcoin address."""
    try:
        if private_key.startswith(("5", "K", "L")):  # WIF format
            key = Key(private_key)
            return key.address()
        elif private_key.startswith(("xprv", "yprv", "zprv")):  # BIP32/44
            return bip32_private_key_to_address(private_key)
    except Exception as e:
        logging.debug(f"Error converting private key to address: {e}")
    return None

def extract_keys(chunk):
    for key_type, pattern in PATTERNS.items():
        yield from pattern.findall(chunk)

async def scan_file(file_path):
    """Scan a file asynchronously with concurrency limit."""
    found_lines = []
    async with sem:
        async for chunk in read_file_async(file_path):
            for match in extract_keys(chunk):
                match_cleaned = match.strip()
                address = private_key_to_address(match_cleaned)

                # Process the address if it hasn't been processed already
                if address and address not in processed_addresses:
                    balance = get_balance_btc_explorer(address)
                    processed_addresses[address] = {
                        "private_key": match_cleaned,  # Store the private key
                        "balance": balance  # Store the balance
                    }

                    if balance > 0:
                        logging.info(f"🎯 FOUND BTC! Address: {address} - Balance: {balance} BTC")
                        with open("found.log", "a") as found:
                            found.write(f"{address} : {balance} BTC : {match_cleaned}\n")
                        found_lines.append(f"{address} : {balance} BTC : {match_cleaned}\n")

                    if len(processed_addresses) % SAVE_INTERVAL == 0:
                        save_processed_addresses()

            if found_lines:
                with open("found.log", "a") as found:
                    found.writelines(found_lines)

async def scan_directory(directory):
    """Recursively scan files asynchronously with a concurrency limit."""
    tasks = []
    for root, _, files in os.walk(directory):
        for file in files:
            if not any(file.lower().endswith(ext) for ext in EXCLUDED_EXTENSIONS):
                file_path = os.path.join(root, file)
                tasks.append(scan_file(file_path))
    await asyncio.gather(*tasks)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", nargs="?", default=os.getcwd(), help="Directory to scan")
    args = parser.parse_args()
    TARGET_DIR = args.directory

    if not os.path.exists(TARGET_DIR):
        logging.error("Invalid directory. Exiting.")
        exit(1)

    logging.info(f"Scanning directory: {TARGET_DIR}...\n")
    asyncio.run(scan_directory(TARGET_DIR))
    save_processed_addresses()
    logging.info("Scan complete.")
