import os
import json
import time
import uuid
import requests
import base64
import re
import warnings
from datetime import datetime
from dotenv import load_dotenv
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

warnings.filterwarnings("ignore")

# Load Environment
load_dotenv(dotenv_path='/Users/protoned/kalshi-bot/.env')
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")
KALSHI_KEY_ID = os.getenv("KALSHI_KEY_ID")

pem_path = os.getenv("KALSHI_PRIVATE_KEY_PATH")
with open(pem_path, 'r') as key_file:
    PRIVATE_KEY_PEM = key_file.read()

# ---------------------------------------------------------
# THE FALCON PARAMS
# ---------------------------------------------------------
BALANCE_FLOOR = 50.00        
MAX_DAILY_SPEND = 100.00     
MAX_TRADE_CAP = 10.00        

# The Edge: How far past the strike price must spot BTC be to guarantee a win?
BUFFER_USD = 150.00 
# If we have the buffer, what is the max price we are willing to pay for the contract?
MAX_PURCHASE_CENTS = 88 

KALSHI_BASE_URL = "https://api.elections.kalshi.com/trade-api/v2"

def send_telegram(message):
    if not TELEGRAM_BOT_TOKEN:
        return
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    requests.post(url, json={"chat_id": TELEGRAM_CHAT_ID, "text": message})

def sign_request(method, path, nonce, timestamp, private_key_pem):
    message = f"{timestamp}{method}{path}".encode('utf-8')
    private_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
    signature = private_key.sign(
        message,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.DIGEST_LENGTH),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode('utf-8')

def kalshi_request(method, endpoint, payload=None):
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
    if method == "GET":
        return requests.get(url, headers=headers)
    else:
        return requests.post(url, headers=headers, json=payload)

def get_coinbase_spot():
    """Fetches the real-time spot price of BTC from Coinbase."""
    try:
        resp = requests.get("https://api.coinbase.com/v2/prices/BTC-USD/spot")
        if resp.status_code == 200:
            return float(resp.json()['data']['amount'])
    except Exception as e:
        print(f"Failed to fetch Coinbase Spot: {e}")
    return 0.0

def check_daily_spend(cost):
    log_file = '/Users/protoned/kalshi-bot/falcon_state.json'
    today = datetime.now().strftime('%Y-%m-%d')
    
    if os.path.exists(log_file):
        with open(log_file, 'r') as f:
            state = json.load(f)
    else:
        state = {"date": today, "spend": 0.0}

    if state["date"] != today:
        state = {"date": today, "spend": 0.0}

    if state["spend"] + cost > MAX_DAILY_SPEND:
        return False
        
    state["spend"] += cost
    with open(log_file, 'w') as f:
        json.dump(state, f)
    return True

def run_falcon():
    print("🦅 KALSHI FALCON ONLINE: Cross-referencing real-world spot prices.")
    
    # 1. Get Real-World Truth
    spot_btc = get_coinbase_spot()
    if spot_btc == 0:
        return
    print(f"Real-Time Spot BTC: ${spot_btc:.2f}")

    # 2. Check Kalshi Balance
    bal_resp = kalshi_request("GET", "/portfolio/balance")
    if bal_resp.status_code not in [200, 201]: return
    balance_dollars = bal_resp.json().get('balance', 0) / 100.0
    if balance_dollars < BALANCE_FLOOR: return

    # 3. Pull Kalshi BTC Markets
    markets_resp = kalshi_request("GET", "/markets?series_ticker=KXBTC&limit=15&status=open")
    if markets_resp.status_code != 200: return
        
    markets = markets_resp.json().get('markets', [])
    
    for m in markets:
        ticker = m['ticker']
        
        # Extract the strike price from the ticker (e.g. KXBTC-26MAR04-T68000.99 -> 68000.99)
        match = re.search(r'-T([0-9.]+)', ticker)
        if not match: continue
        
        strike_price = float(match.group(1))
        
        ob_resp = kalshi_request("GET", f"/markets/{ticker}/orderbook")
        if ob_resp.status_code != 200: continue
            
        ob = ob_resp.json().get('orderbook', {})
        yes_ask = ob.get('yes_ask', 0)
        no_ask = ob.get('no_ask', 0)
        
        target_side = None
        execution_price = 0
        
        # --- THE CROSS-ASSET ARBITRAGE LOGIC ---
        # Scenario A: Spot is way ABOVE strike, but YES is suspiciously cheap
        if spot_btc > (strike_price + BUFFER_USD) and 0 < yes_ask <= MAX_PURCHASE_CENTS:
            target_side = "yes"
            execution_price = yes_ask
            
        # Scenario B: Spot is way BELOW strike, but NO is suspiciously cheap
        elif spot_btc < (strike_price - BUFFER_USD) and 0 < no_ask <= MAX_PURCHASE_CENTS:
            target_side = "no"
            execution_price = no_ask
            
        # --- EXECUTION ---
        if target_side:
            shares_to_buy = int((MAX_TRADE_CAP * 100) / execution_price)
            shares_to_buy = min(5, shares_to_buy) # Cap at 5 contracts to avoid slippage
            
            cost_dollars = (shares_to_buy * execution_price) / 100.0
            
            if not check_daily_spend(cost_dollars):
                print("Daily spend limit reached.")
                return

            payload = {
                "action": "buy",
                "client_order_id": str(uuid.uuid4()),
                "count": shares_to_buy,
                "side": target_side,
                "ticker": ticker,
                "type": "limit",
                f"{target_side}_price": execution_price
            }
            
            order_resp = kalshi_request("POST", "/portfolio/orders", payload=payload)
            
            if order_resp.status_code in [200, 201]:
                profit_margin = 100 - execution_price
                alert = f"🦅 FALCON ARB LOCKED: {ticker}\nSpot BTC: ${spot_btc:.2f} | Strike: ${strike_price:.2f}\nBought {shares_to_buy} {target_side.upper()} @ {execution_price}c.\nTarget Profit: {profit_margin}c per contract."
                print(alert)
                send_telegram(alert)

if __name__ == "__main__":
    run_falcon()
