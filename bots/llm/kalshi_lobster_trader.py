import os
import warnings

# Muzzle the Apple SSL warnings BEFORE importing requests
warnings.filterwarnings("ignore")

import json
import time
import uuid
import requests
import base64
import ollama
import re
from datetime import datetime
from dotenv import load_dotenv
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

# Load Environment
load_dotenv(dotenv_path='/Users/protoned/kalshi-bot/.env')
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")

# Securely load the PEM file
pem_path = os.getenv("KALSHI_PRIVATE_KEY_PATH")
with open(pem_path, 'r') as key_file:
    PRIVATE_KEY_PEM = key_file.read()

# ---------------------------------------------------------
# 1. THE IRONCLAD CIRCUIT BREAKERS (HARDCODED PARAMS)
# ---------------------------------------------------------
BALANCE_FLOOR = 50.00        
MAX_DAILY_SPEND = 100.00      
MAX_TRADE_CAP = 10.00         
MINIMUM_EDGE_REQUIREMENT = 10
TARGET_MARKETS = ['INTRATE', 'BTC', 'SPX'] 

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
        "KALSHI-ACCESS-KEY": os.getenv("KALSHI_KEY_ID"),
        "KALSHI-ACCESS-SIGNATURE": signature,
        "KALSHI-ACCESS-TIMESTAMP": timestamp,
        "Content-Type": "application/json"
    }

    url = f"{KALSHI_BASE_URL}{endpoint}"
    if method == "GET":
        return requests.get(url, headers=headers)
    else:
        return requests.post(url, headers=headers, json=payload)

def check_daily_spend(cost):
    log_file = '/Users/protoned/kalshi-bot/lobster_state.json'
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

def run_lobster():
    print("🦞 KALSHI LOBSTER V1 ONLINE: The 10% Sniper.")
    
    bal_resp = kalshi_request("GET", "/portfolio/balance")
    if bal_resp.status_code not in [200, 201]:
        print("Failed to fetch balance.")
        return
   
    balance_dollars = bal_resp.json().get('balance', 0) / 100.0
    
    if balance_dollars < BALANCE_FLOOR:
        msg = f"🚨 LOBSTER SHUTDOWN: Balance (${balance_dollars}) dropped below floor."
        print(msg)
        send_telegram(msg)
        return

    for series in TARGET_MARKETS:
        markets_resp = kalshi_request("GET", f"/markets?series_ticker={series}&limit=5")
        if markets_resp.status_code != 200:
            continue
            
        markets = markets_resp.json().get('markets', [])
        
        for m in markets:
            ticker = m['ticker']
            ob_resp = kalshi_request("GET", f"/markets/{ticker}/orderbook")
            if ob_resp.status_code != 200: continue
                
            ob = ob_resp.json().get('orderbook', {})
            yes_bid = ob.get('yes_bid', 0)
            yes_ask = ob.get('yes_ask', 0)
            
            if yes_bid == 0 or yes_ask == 0: continue 
                
            yes_mid_cents = int((yes_bid + yes_ask) / 2)

            # 1. READ THE MACRO SENTIMENT
            sentiment_file = '/Users/protoned/kalshi-bot/market_sentiment.txt'
            sentiment_context = "No recent macro data available."
            if os.path.exists(sentiment_file):
                with open(sentiment_file, 'r') as f:
                    sentiment_context = f.read()

            # 2. INJECT MACRO INTO PROMPT
            system_prompt = "You are a probability oracle. Analyze the market title and macro context. Return a SINGLE integer from 0 to 100 representing the percentage chance of 'Yes' occurring."
            user_msg = f"Market: {m['title']}\n\nMACRO CONTEXT:\n{sentiment_context}"

            try:
                resp = ollama.chat(model='llama3.2:latest', messages=[
                    {'role': 'system', 'content': system_prompt},
                    {'role': 'user', 'content': user_msg}
                ])
                
                llm_prob_raw = resp['message']['content'].strip()
                
                # 3. THE REGEX SAFETY NET
                match = re.search(r'\b(?:100|[1-9]?[0-9])\b', llm_prob_raw)
                if match:
                    llm_prob = int(match.group(0))
                else:
                    print(f"LLM hallucinated non-numbers for {ticker}. Skipping.")
                    continue
                
            except Exception as e:
                continue

            edge_cents = llm_prob - yes_mid_cents
            
            if edge_cents >= MINIMUM_EDGE_REQUIREMENT:
                max_shares_allowed = int((MAX_TRADE_CAP * 100) / yes_mid_cents)
                shares_to_buy = min(5, max_shares_allowed) 
                
                cost_dollars = (shares_to_buy * yes_mid_cents) / 100.0
                
                if not check_daily_spend(cost_dollars):
                    print("Daily spend limit reached. Halting.")
                    return

                payload = {
                    "action": "buy",
                    "client_order_id": str(uuid.uuid4()),
                    "count": shares_to_buy,
                    "side": "yes",
                    "ticker": ticker,
                    "type": "limit",
                    "yes_price": yes_mid_cents
                }
                
                order_resp = kalshi_request("POST", "/portfolio/orders", payload=payload)
                
                if order_resp.status_code in [200, 201]:
                    alert = f"🦞 EXECUTED: Bought {shares_to_buy} YES on {ticker} @ {yes_mid_cents}c. (LLM: {llm_prob}%)"
                    print(alert)
                    send_telegram(alert)
                    
                    with open('/Users/protoned/kalshi-bot/lobster_decisions.log', 'a') as log:
                        log.write(f"{datetime.now().isoformat()} | {ticker} | LLM:{llm_prob}% | MID:{yes_mid_cents}c | BOUGHT {shares_to_buy}\n")

if __name__ == "__main__":
    run_lobster()
