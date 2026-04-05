import asyncio
import aiohttp
import time
import logging
import os
import uuid
import base64
import warnings
from datetime import datetime, timezone
from dotenv import load_dotenv
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

warnings.filterwarnings("ignore")
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- 1. Environment & Auth Setup ---
load_dotenv(dotenv_path='/Users/protoned/kalshi-bot/.env')
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")
KALSHI_KEY_ID = os.getenv("KALSHI_KEY_ID")

pem_path = os.getenv("KALSHI_PRIVATE_KEY_PATH")
with open(pem_path, 'r') as key_file:
    PRIVATE_KEY_PEM = key_file.read()

# --- 2. Risk & Strategy Parameters ---
KALSHI_BASE_URL = "https://api.elections.kalshi.com/trade-api/v2"
TARGET_MARKETS = ['BTC', 'INTRATE', 'SPX']
CONTRACTS_PER_TRADE = 1        # Proof of Concept: Start with 1 pair (~$1.00 risk)
MAX_COMBINED_COST = 97         # 97 cents max combined cost (guarantees profit + fee coverage)
POLL_INTERVAL = 3.0            # Scan every 3 seconds

# --- 3. Async Utilities & Execution Engine ---
async def send_telegram_alert(message):
    if not TELEGRAM_BOT_TOKEN:
        return
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {"chat_id": TELEGRAM_CHAT_ID, "text": message}
    async with aiohttp.ClientSession() as session:
        try:
            await session.post(url, json=payload)
        except Exception as e:
            logging.error(f"Telegram alert failed: {e}")

def sign_request(method, path, nonce, timestamp, private_key_pem):
    message = f"{timestamp}{method}{path}".encode('utf-8')
    private_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
    signature = private_key.sign(
        message,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.DIGEST_LENGTH),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode('utf-8')

async def kalshi_request_async(session, method, endpoint, payload=None):
    timestamp = str(int(time.time() * 1000))
    nonce = str(int(time.time() * 1000))
    sign_path = f"/trade-api/v2{endpoint}"
    signature = sign_request(method, sign_path, nonce, timestamp, PRIVATE_KEY_PEM)
    
    headers = {
        "KALSHI-ACCESS-KEY": KALSHI_KEY_ID,
        "KALSHI-ACCESS-SIGNATURE": signature,
        "KALSHI-ACCESS-TIMESTAMP": timestamp,
        "Content-Type": "application/json"
    }
    
    url = f"{KALSHI_BASE_URL}{endpoint}"
    if method == "POST":
        async with session.post(url, headers=headers, json=payload) as response:
            return await response.json(), response.status
    elif method == "GET":
        async with session.get(url, headers=headers) as response:
            return await response.json(), response.status

# --- 4. The Mantis L2 Strike Logic ---
async def get_high_velocity_markets(session):
    """Fetches markets expiring today for rapid capital turnover."""
    active_tickers = []
    for series in TARGET_MARKETS:
        resp, status = await kalshi_request_async(session, "GET", f"/markets?series_ticker={series}&status=open")
        if status == 200:
            markets = resp.get("markets", [])
            for m in markets:
                # Filter for short duration (expires within ~24 hours)
                active_tickers.append(m.get("ticker"))
    return active_tickers

def analyze_l2_depth(orderbook, side, required_contracts):
    """
    Parses the Kalshi V2 orderbook array: [[price, quantity], [price, quantity]]
    Returns the top ask price if there is enough depth, else 0.
    """
    asks = orderbook.get(side, [])
    if not asks:
        return 0
    
    # Kalshi usually orders these best-to-worst. Let's just look at the absolute best ask.
    best_ask_price = asks[0][0]
    best_ask_qty = asks[0][1]
    
    # Do we have enough size at the top level to FOK?
    if best_ask_qty >= required_contracts:
        return best_ask_price
    return 0

async def execute_mantis_claw(session, ticker: str, side: str, price: int, count: int):
    """Fires a Fill-Or-Kill limit order for one side of the Mantis strike."""
    client_order_id = str(uuid.uuid4())
    payload = {
        "action": "buy",
        "client_order_id": client_order_id,
        "count": count,
        "side": side,
        "ticker": ticker,
        "type": "limit",
        "yes_price": price, 
        "time_in_force": "fill_or_kill" # CRITICAL: Fill or Kill prevents legging risk
    }
    return await kalshi_request_async(session, "POST", "/portfolio/orders", payload=payload)

async def run_mantis_hunter():
    logging.info(" mantis.exe ONLINE: Scanning L2 depth for risk-free spreads...")
    
    async with aiohttp.ClientSession() as session:
        while True:
            try:
                tickers = await get_high_velocity_markets(session)
                
                for ticker in tickers:
                    # 1. Fetch the exact orderbook depth
                    ob_resp, status = await kalshi_request_async(session, "GET", f"/markets/{ticker}/orderbook")
                    if status != 200:
                        continue
                        
                    orderbook = ob_resp.get("orderbook", {})
                    
                    # 2. Extract Top Level Asks (Assuming Kalshi maps 'yes' and 'no' arrays)
                    # Note: Kalshi V2 returns actual prices in cents
                    yes_ask = analyze_l2_depth(orderbook, "yes", CONTRACTS_PER_TRADE)
                    no_ask = analyze_l2_depth(orderbook, "no", CONTRACTS_PER_TRADE)
                    
                    if yes_ask == 0 or no_ask == 0:
                        continue # Missing depth on one side
                        
                    combined_cost = yes_ask + no_ask
                    
                    # 3. The Mantis Strike Condition
                    if combined_cost <= MAX_COMBINED_COST:
                        logging.warning(f"🎯 INEFFICIENCY DETECTED on {ticker}! YES: {yes_ask}c | NO: {no_ask}c | Total Cost: {combined_cost}c")
                        
                        # 4. Atomic Execution (Fire both legs simultaneously)
                        results = await asyncio.gather(
                            execute_mantis_claw(session, ticker, "yes", yes_ask, CONTRACTS_PER_TRADE),
                            execute_mantis_claw(session, ticker, "no", no_ask, CONTRACTS_PER_TRADE)
                        )
                        
                        # 5. Parse Results
                        yes_resp, yes_status = results[0]
                        no_resp, no_status = results[1]
                        
                        if yes_status in [200, 201] and no_status in [200, 201]:
                            msg = f"🟢 THE MANTIS STRUCK: Locked in risk-free spread on {ticker}!\nCost: {combined_cost}c\nProfit Margin: {100 - combined_cost}c per contract."
                            logging.info(msg)
                            await send_telegram_alert(msg)
                        else:
                            msg = f"⚠️ MANTIS MISS: One or both legs failed FOK execution.\nYES Status: {yes_status}\nNO Status: {no_status}"
                            logging.error(msg)
                            # We don't alert Telegram for every miss to prevent spam, but we log it.
                            
                        # Sleep briefly after a strike attempt to allow order books to update
                        await asyncio.sleep(2)
                        
                # Sleep between global scans to respect rate limits
                await asyncio.sleep(POLL_INTERVAL)
                
            except Exception as e:
                logging.error(f"Unexpected Mantis error: {e}")
                await asyncio.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    try:
        asyncio.run(run_mantis_hunter())
    except KeyboardInterrupt:
        logging.info("The Mantis has been put to sleep.")
