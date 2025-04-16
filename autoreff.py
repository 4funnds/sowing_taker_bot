import aiohttp
import asyncio
from eth_account import Account
from eth_account.messages import encode_defunct
import logging
import time
from typing import Dict, List, Optional, Any
import sys
import random

if sys.platform == 'win32':
	asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Constants
API_BASE_URL = "https://sowing-api.taker.xyz"
HEADERS = {
    'accept': 'application/json, text/plain, */*',
    'accept-language': 'en-US,en;q=0.9',
    'content-type': 'application/json',
    'sec-ch-ua': '"Microsoft Edge";v="135", "Not-A.Brand";v="8", "Chromium";v="135"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'sec-fetch-dest': 'empty',
    'sec-fetch-mode': 'cors',
    'sec-fetch-site': 'same-site',
    'Referer': 'https://sowing.taker.xyz/',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
}

class Wallet:
    def __init__(self, private_key: str):
        self.private_key = private_key
        account = Account.from_key(private_key)
        self.address = account.address
        self.token = None

async def api_request(url: str, method: str, data: Dict = None, headers: Dict = None) -> Dict:
    """Make an API request with the specified parameters."""
    if headers is None:
        headers = {}
    
    async with aiohttp.ClientSession() as session:
        try:
            if method.upper() == 'GET':
                async with session.get(url, headers=headers) as response:
                    return await response.json()
            elif method.upper() == 'POST':
                async with session.post(url, json=data, headers=headers) as response:
                    return await response.json()
            else:
                raise ValueError(f"Unsupported HTTP method: {method}")
        except aiohttp.ClientError as e:
            logger.error(f"API request failed: {e}")
            return {"code": 500, "message": str(e)}

async def generate_nonce(wallet: Wallet) -> str:
    """Generate a nonce for wallet authentication."""
    response = await api_request(
        f"{API_BASE_URL}/wallet/generateNonce",
        'POST',
        {"walletAddress": wallet.address},
        HEADERS
    )
    
    if response.get("code") == 200:
        result = response.get("result", {})
        if isinstance(result, dict) and "nonce" in result:
            return result["nonce"]
        elif isinstance(result, str):
            import re
            nonce_match = re.search(r"Nonce: (.*)$", result, re.MULTILINE)
            if nonce_match and nonce_match.group(1):
                return nonce_match.group(1)
    
    raise Exception(f"Failed to generate nonce: {response.get('message', 'Unknown error')}")

async def login(wallet: Wallet, nonce: str) -> str:
    """Login and return authentication token."""
    message = f"Taker quest needs to verify your identity to prevent unauthorized access. Please confirm your sign-in details below:\n\naddress: {wallet.address}\n\nNonce: {nonce}"
    
    signed_message = Account.sign_message(
        encode_defunct(text=message),
        private_key=wallet.private_key
    )
    signature = signed_message.signature.hex()
    
    response = await api_request(
        f"{API_BASE_URL}/wallet/login",
        'POST',
        {"address": wallet.address, "signature": signature, "message": message, "invitationCode": "MKMVBRMT"},
        HEADERS
    )
    
    if response.get("code") == 200:
        return response["result"]["token"]
    
    raise Exception(f"Login failed: {response.get('message', 'Unknown error')}")

async def authenticate_wallet(wallet: Wallet) -> None:
    """Complete the wallet authentication process."""
    try:
        nonce = await generate_nonce(wallet)
        token = await login(wallet, nonce)
        wallet.token = token
        logger.info(f"Wallet {wallet.address} authenticated successfully")
    except Exception as e:
        logger.error(f"Authentication failed for wallet {wallet.address}: {e}")
        raise

async def process_wallets_sequentially(wallets: List[Wallet]) -> None:
    """Process wallets one by one."""
    for wallet in wallets:
        await authenticate_wallet(wallet)
        await asyncio.sleep(random.uniform(2, 7))  # Random delay between 2 and 7 seconds

def load_private_keys(filename: str = "pvkey.txt") -> List[str]:
    """Load private keys from a text file."""
    private_keys = []
    try:
        with open(filename, 'r') as file:
            for line in file:
                # Strip whitespace and ignore empty lines or comments
                key = line.strip()
                if key and not key.startswith('#'):
                    private_keys.append(key)
        logger.info(f"Loaded {len(private_keys)} private keys from {filename}")
        return private_keys
    except FileNotFoundError:
        logger.error(f"File {filename} not found")
        return []
    except Exception as e:
        logger.error(f"Error loading private keys: {e}")
        return []

async def main():
    # Load private keys from file
    private_keys = load_private_keys()
    if not private_keys:
        logger.error("No private keys loaded. Exiting.")
        return
    
    # Create wallet objects from private keys
    wallets = [Wallet(pk) for pk in private_keys]
    logger.info(f"Created {len(wallets)} wallet objects")
    
    # First process wallets sequentially
    logger.info("Processing wallets sequentially")
    await process_wallets_sequentially(wallets)

if __name__ == "__main__":
    asyncio.run(main())
