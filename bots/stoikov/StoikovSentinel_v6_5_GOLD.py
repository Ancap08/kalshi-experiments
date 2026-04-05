import os
import time
import json
import logging
import base64
import datetime
import math
import statistics
import requests
import uuid
import asyncio
import websockets
from dotenv import load_dotenv
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# Load Env
load_dotenv()

# Configuration
KALSHI_KEY_ID = os.getenv("KALSHI_KEY_ID")
KALSHI_PRIVATE_KEY_PATH = os.getenv("KALSHI_PRIVATE_KEY_PATH")
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")

# Trading Parameters
GAMMA = 0.05                  
KAPPA = 40.0                  
BASE_VOLATILITY = 0.2     
VOLATILITY_WINDOW = 12        
MAX_INVENTORY_CONTRACTS = 5   
TICK_INTERVAL = 12 
BASE_URL = "https://api.elections.kalshi.com/trade-api/v2"
WS_URL = "wss://api.elections.kalshi.com/trade-api/ws/v2"

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] StoikovSentinel: %(message)s',
    handlers=[
        logging.FileHandler("sentinel.log"),
        logging.StreamHandler()
    ]
)

class TelegramAlerts:    
    @staticmethod
    async def send(message):
        if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID: return
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        payload = {"chat_id": TELEGRAM_CHAT_ID, "text": f"🤖 StoikovSentinel_Predator\n{message}"}
        loop = asyncio.get_running_loop()
        try:
            await loop.run_in_executor(None, lambda: requests.post(url, json=payload, timeout=5))
        except Exception as e:
            logging.error(f"Telegram failed: {e}")

class AsyncKalshiClient:
    def __init__(self, key_id, key_path, base_url):
        self.key_id = key_id
        self.base_url = base_url
        with open(key_path, "rb") as key_file:
            self.private_key = serialization.load_pem_private_key(
                key_file.read(), password=None, backend=default_backend()
            )

    def _sign_request(self, method, path):
        path_without_query = path.split('?')[0]
        timestamp = str(int(datetime.datetime.now().timestamp() * 1000))
        message = timestamp + method + path_without_query
        
        signature = self.private_key.sign(
            message.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return {
            "KALSHI-ACCESS-KEY": self.key_id,
            "KALSHI-ACCESS-SIGNATURE": base64.b64encode(signature).decode('utf-8'),
            "KALSHI-ACCESS-TIMESTAMP": timestamp,
            "Content-Type": "application/json"
        }

    async def request(self, method, endpoint, body=None):
        path = f"/trade-api/v2{endpoint}"
        headers = self._sign_request(method, path)
        url = self.base_url + endpoint
        
        loop = asyncio.get_running_loop()
        try:
            response = await loop.run_in_executor(
                None,
                lambda: requests.request(method, url, headers=headers, json=body, timeout=5)
            )
            if response.status_code >= 400:
                if response.status_code not in [404, 409]:
                    logging.error(f"API Error {response.status_code} on {method}: {response.text}")
                try:
                    return response.json()
                except json.decoder.JSONDecodeError:
                    return {}
            return response.json()
        except Exception as e:
            logging.error(f"API Request failed: {e}")
            return {}

class AsyncStoikovSentinel:
    def __init__(self):
        self.api = AsyncKalshiClient(KALSHI_KEY_ID, KALSHI_PRIVATE_KEY_PATH, BASE_URL)
        
        self.inventory = 0
        self.position_cost = 0.0 
        self.last_taker_time = 0 
        
        self.daily_pnl_cents = 0.0 
        self.load_daily_pnl() 
        
        self.current_market = None
        self.market_close_time = None
        self.price_history = [] 
        self.last_price_history_update = 0  
        self.seen_trade_ids = set() 
        
        self.live_exchange_bid = None 
        self.live_exchange_ask = None
        
        self.quote_lock = asyncio.Lock()
        self.is_running = False
        
        self.resting_bid = None
        self.resting_ask = None
        self.resting_exit_price = None  
        self.active_order_ids = set() 
        
        self.last_quote_time = 0.0
        self.last_sl_time = 0.0
        self.last_pnl_telegram_time = 0.0
        self.last_fill_time = 0.0
        self.last_exit_reason = None

        self.live_btc_price = None
        self.btc_price_history = []

    def load_daily_pnl(self):
        today = datetime.date.today().isoformat()
        try:
            if os.path.exists("pnl_tracker_btc.txt"):
                with open("pnl_tracker_btc.txt", "r") as f:
                    data = f.read().strip().split("|")
                    if len(data) == 2 and data[0] == today:
                        self.daily_pnl_cents = float(data[1])
                        return
            self.daily_pnl_cents = 0.0
            self.save_daily_pnl()
        except Exception as e:
            logging.error(f"Could not load PnL tracker: {e}")

    def save_daily_pnl(self):
        today = datetime.date.today().isoformat()
        try:
            with open("pnl_tracker_btc.txt", "w") as f:
                f.write(f"{today}|{self.daily_pnl_cents}")
        except Exception as e:
            logging.error(f"Could not save PnL tracker: {e}")

    def _apply_fill_to_inventory(self, action, side, count, price):
        if price is None:
            if self.resting_exit_price is not None:
                price = self.resting_exit_price
            elif action == "buy" and side == "yes" and self.resting_bid:
                price = self.resting_bid
            elif action == "sell" and side == "no" and self.resting_bid:
                price = 100.0 - self.resting_bid
            elif action == "buy" and side == "no" and self.resting_ask:
                price = 100.0 - self.resting_ask
            elif action == "sell" and side == "yes" and self.resting_ask:
                price = self.resting_ask
            elif self.price_history:
                price = self.price_history[-1] * 100.0
            else:
                price = 50.0 
            
        trade_qty = count if action == "buy" else -count
        if side == "no":
            trade_qty = -trade_qty

        # === PHANTOM PROFIT BUG ERADICATED — correct NO cost basis ===
        raw_price = price if price is not None else 0
        # Bulletproof normalizer: ensure price is in cents (e.g., 0.29 becomes 29.0)
        fill_price_cents = raw_price * 100.0 if raw_price > 0 and raw_price < 1.0 else float(raw_price)

        trade_price = fill_price_cents if side == "yes" else float(100 - fill_price_cents)
        new_inventory = self.inventory + trade_qty

        if self.inventory > 0 and trade_qty < 0:
            contracts_closed = min(abs(self.inventory), abs(trade_qty))
            trade_pnl = contracts_closed * (trade_price - self.position_cost)
            self.daily_pnl_cents += trade_pnl
        elif self.inventory < 0 and trade_qty > 0:
            contracts_closed = min(abs(self.inventory), abs(trade_qty))
            trade_pnl = contracts_closed * (self.position_cost - trade_price)
            self.daily_pnl_cents += trade_pnl

        if new_inventory == 0:
            self.position_cost = 0.0
        elif side.upper() == "NO" or (self.inventory < 0 and trade_qty < 0):
            # NO contract cost basis: always 100 - fill price (in cents)
            true_cost = 100.0 - fill_price_cents
            if self.inventory == 0:
                self.position_cost = true_cost
            else:
                total_cost = (abs(self.inventory) * self.position_cost) + (abs(trade_qty) * true_cost)
                self.position_cost = total_cost / abs(new_inventory)
            logging.info(f"✅ NO COST INVERTED: fill={fill_price_cents:.1f}¢ → true_cost={true_cost:.1f}¢")
        elif (self.inventory > 0 and new_inventory < 0) or (self.inventory < 0 and new_inventory > 0):
            self.position_cost = trade_price
        elif self.inventory == 0:
            self.position_cost = trade_price
        else:
            total_cost = (abs(self.inventory) * self.position_cost) + (abs(trade_qty) * trade_price)
            self.position_cost = total_cost / abs(new_inventory)
        
        self.inventory = new_inventory
        self.last_fill_time = time.time()

    async def find_active_btc_market(self):
        res = await self.api.request("GET", "/markets?series_ticker=KXBTC15M&status=open")
        markets = res.get("markets", [])
        if not markets: return None
        
        valid_markets = []
        for m in markets:
            close_time = datetime.datetime.fromisoformat(m["close_time"].replace("Z", "+00:00"))
            time_left = (close_time - datetime.datetime.now(datetime.timezone.utc)).total_seconds()
            
            if 60 < time_left <= 1000: 
                valid_markets.append((time_left, m["ticker"], close_time))
        
        if valid_markets:
            valid_markets.sort()
            if valid_markets[0][1] != self.current_market:
                self.price_history = []
                self.seen_trade_ids.clear() 
            return valid_markets[0]
        return None

    def get_dynamic_volatility(self):
        if len(self.price_history) < 2:
            return BASE_VOLATILITY
        std_dev = statistics.stdev(self.price_history)
        return max(std_dev, 0.05)

    def calculate_avellaneda_stoikov(self, mid_price, time_left, current_vol, current_kappa):
        T = max(0.001, time_left / 900.0) 
        effective_gamma = GAMMA * 15.0 
        
        r = mid_price - (self.inventory * effective_gamma * (current_vol**2) * T)
        delta = (effective_gamma * (current_vol**2) * T / 2.0) + (1.0 / effective_gamma) * math.log(1.0 + (effective_gamma / current_kappa))
        
        min_spread = 0.04    
        actual_delta = max(delta, min_spread / 2.0)
        
        bid_cents = round((r - actual_delta) * 100)
        ask_cents = round((r + actual_delta) * 100)
        
        PANIC_MULTIPLIER = 1.0 
        inventory_skew_cents = int(self.inventory * PANIC_MULTIPLIER)
        
        bid_cents -= inventory_skew_cents
        ask_cents -= inventory_skew_cents
        
        bid = max(1, min(98, bid_cents))
        ask = max(2, min(99, ask_cents))            

        if bid >= ask:
            if self.inventory > 0:
                bid = max(1, ask - 1)
            elif self.inventory < 0:
                ask = min(99, bid + 1)
            else:
                ask = min(99, bid + 1)
                bid = max(1, ask - 1)
            
        return bid, ask, actual_delta 

    # --- CURSOR FIX: Robust Cancel Handling ---
    async def cancel_active_orders(self):
        if not self.active_order_ids:
            return
            
        ids_to_cancel = list(self.active_order_ids)
        cancel_tasks = [self.api.request("DELETE", f"/portfolio/orders/{oid}") for oid in ids_to_cancel]
        
        results = await asyncio.gather(*cancel_tasks, return_exceptions=True)
        
        for oid, res in zip(ids_to_cancel, results):
            if isinstance(res, Exception):
                continue
            if isinstance(res, dict):
                if "order" in res:
                    self.active_order_ids.discard(oid)
                elif "error" in res:
                    err_code = res["error"].get("code", "")
                    if err_code == "not_found":
                        self.active_order_ids.discard(oid)
                elif res.get("code") == "not_found":
                    self.active_order_ids.discard(oid)
                else:
                    self.active_order_ids.discard(oid)
        
        # Only wipe resting memory if we successfully killed all orders
        if not self.active_order_ids:
            self.resting_bid = None
            self.resting_ask = None
            self.resting_exit_price = None  

    async def reconcile_ghost_orders(self):
        """Cancel resting orders on Kalshi that we don't track (e.g. from order-creation timeouts)."""
        if not self.current_market:
            return
        try:
            res = await self.api.request("GET", f"/portfolio/orders?ticker={self.current_market}&status=resting")
            live_orders = res.get("orders", [])
            live_ids = {o.get("order_id") or o.get("id") for o in live_orders if (o.get("order_id") or o.get("id"))}

            ghost_ids = live_ids - self.active_order_ids
            if ghost_ids:
                logging.warning(f"👻 Found {len(ghost_ids)} untracked ghost orders. Nuking...")
                cancel_tasks = [self.api.request("DELETE", f"/portfolio/orders/{oid}") for oid in ghost_ids]
                await asyncio.gather(*cancel_tasks)
        except Exception as e:
            logging.error(f"Ghost order sweep failed: {e}")

    async def active_taker_exit(self, pnl, reason, side, limit_price):
        self.last_taker_time = time.time()
        self.last_exit_reason = reason
        if reason == "TAKE PROFIT":
            self.last_tp_side = side
            self.last_tp_price = limit_price  # Store the exit price in cents
        if reason == "STOP LOSS":
            self.last_sl_time = time.time()
        logging.warning(f"🚨 ACTIVE EXIT | Reason: {reason} | Target PnL: {pnl:+.1f}¢ | Sniping Limit @ {limit_price}¢")
        await self.cancel_active_orders()
        
        self.resting_exit_price = limit_price 
        
        if side == "yes":
            order = {"action": "sell", "side": "yes", "count": abs(self.inventory), "type": "limit", "yes_price": limit_price, "ticker": self.current_market, "client_order_id": str(uuid.uuid4())}
        elif side == "no":
            order = {"action": "sell", "side": "no", "count": abs(self.inventory), "type": "limit", "no_price": limit_price, "ticker": self.current_market, "client_order_id": str(uuid.uuid4())}
            
        res = await self.api.request("POST", "/portfolio/orders", body=order)
        if isinstance(res, dict) and "order" in res and "order_id" in res["order"]:
            self.active_order_ids.add(res["order"]["order_id"])

    async def flatten_position(self):
        logging.info("⏳ 3-MINUTE DEAD ZONE REACHED. Flattening position & Killing Quotes.")
        self.last_taker_time = time.time()
        await self.cancel_active_orders()
        
        if self.inventory > 0:
            if self.live_exchange_bid is not None:
                exit_price = max(1, int(self.live_exchange_bid) - 3)
            else:
                exit_price = 1  # Absolute fallback if WS is completely dead
                
            order = {"action": "sell", "side": "yes", "count": abs(self.inventory), "type": "limit", "yes_price": exit_price, "ticker": self.current_market, "client_order_id": str(uuid.uuid4())}
            await self.api.request("POST", "/portfolio/orders", body=order)
            
        elif self.inventory < 0:
            if self.live_exchange_ask is not None:
                exit_price = max(1, int(100 - self.live_exchange_ask) - 3)
            else:
                exit_price = 1  # Absolute fallback if WS is completely dead
                
            order = {"action": "sell", "side": "no", "count": abs(self.inventory), "type": "limit", "no_price": exit_price, "ticker": self.current_market, "client_order_id": str(uuid.uuid4())}
            await self.api.request("POST", "/portfolio/orders", body=order)

    async def update_inventory_and_fills(self):
        res_fills = await self.api.request("GET", f"/portfolio/fills?ticker={self.current_market}")
        fills = res_fills.get("fills", [])
        got_new_fill = False
        
        for fill in fills:
            trade_id = fill.get("trade_id")
            if trade_id and trade_id not in self.seen_trade_ids:
                self.seen_trade_ids.add(trade_id)
                action = fill.get("action") 
                side = fill.get("side") 
                price = fill.get("price")
                count = fill.get("count")
                
                self._apply_fill_to_inventory(action, side, count, price)
                
                msg = f"✅ REST FILL ALERT: {action.upper()} {count} {side.upper()} @ {price}¢ | Net Inv: {self.inventory} | Cost: {self.position_cost:.1f}¢"
                logging.info(msg)
                got_new_fill = True

        if got_new_fill:
            await self.cancel_active_orders()
            asyncio.create_task(self.evaluate_and_quote(self.current_market))

    async def evaluate_and_quote(self, ticker):
        if self.quote_lock.locked():
            return

        async with self.quote_lock:
            try:
                # SMART COOLDOWN v6.5 — full cooldown only after TAKE PROFIT wins
                # Keeps momentum guard + ramp cap reactive on reversals
                if time.time() - self.last_fill_time < 8.0 and getattr(self, 'last_exit_reason', None) == "TAKE PROFIT":
                    logging.info(f"🛡️ Smart NO TP cooldown active ({int(time.time() - self.last_fill_time)}s since win)")
                    return
                elif time.time() - self.last_fill_time < 3.0:  # short cooldown on entries/reversals
                    logging.info(f"🛡️ Light cooldown active ({int(time.time() - self.last_fill_time)}s)")
                    return

                pnl = 0.0
                time_left = (self.market_close_time - datetime.datetime.now(datetime.timezone.utc)).total_seconds()

                # --- 3-MINUTE KILL SWITCH: no new quotes in last 3 minutes ---
                if time_left < 180:
                    if self.resting_bid is not None or self.resting_ask is not None:
                        await self.cancel_active_orders()
                    return

                best_bid = self.live_exchange_bid / 100.0 if self.live_exchange_bid else None
                best_ask = self.live_exchange_ask / 100.0 if self.live_exchange_ask else None

                if best_bid is not None and best_ask is not None:
                    pure_mid = (best_bid + best_ask) / 2.0
                elif best_bid is not None:
                    pure_mid = min(0.99, best_bid + 0.02)
                elif best_ask is not None:
                    pure_mid = max(0.01, best_ask - 0.02)
                elif self.price_history:
                    pure_mid = self.price_history[-1]
                else:
                    return

                if time.time() - self.last_price_history_update > 5.0:
                    self.price_history.append(pure_mid)
                    if len(self.price_history) > VOLATILITY_WINDOW:
                        self.price_history.pop(0)
                    self.last_price_history_update = time.time()

                # --- TP/SL: MUST run before throttle so panic exits are never delayed ---
                if self.inventory != 0 and (time.time() - self.last_taker_time) > 2.0:
                    if time.time() - self.last_fill_time < 5.0:  # 5-second cooldown after any new fill
                        return
                    TAKE_PROFIT = 10.0
                    STOP_LOSS = -28.0 if self.inventory > 0 else -35.0

                    if self.inventory > 0:
                        exit_price_cents = best_bid * 100.0 if best_bid else 0.0
                        pnl = exit_price_cents - self.position_cost
                        if pnl >= TAKE_PROFIT:
                            target = int(exit_price_cents)
                            if self.resting_exit_price == target:
                                return
                            await self.active_taker_exit(pnl, "TAKE PROFIT", "yes", target)
                            return
                        elif pnl <= STOP_LOSS:
                            target = max(1, int(exit_price_cents) - 2)
                            if self.resting_exit_price == target:
                                return
                            await self.active_taker_exit(pnl, "STOP LOSS", "yes", target)
                            return
                    else:
                        exit_price_cents = 100.0 - (best_ask * 100.0) if best_ask else 0.0
                        pnl = exit_price_cents - self.position_cost
                        logging.info(f"DEBUG NO PnL: cost={self.position_cost:.1f} | current_exit={exit_price_cents:.1f} | pnl={pnl:.1f}")
                        live_spread = (self.live_exchange_ask - self.live_exchange_bid) if (self.live_exchange_ask and self.live_exchange_bid) else 0
                        effective_tp = 15.0 if (self.inventory < 0 and live_spread > 8) else TAKE_PROFIT
                        if pnl >= effective_tp:
                            target = int(exit_price_cents)
                            if self.resting_exit_price == target:
                                return
                            await self.active_taker_exit(pnl, "TAKE PROFIT", "no", target)
                            return
                        elif pnl <= STOP_LOSS:
                            target = max(1, int(exit_price_cents) - 2)
                            if self.resting_exit_price == target:
                                return
                            await self.active_taker_exit(pnl, "STOP LOSS", "no", target)
                            return

                # V5 Anti-Whipsaw Cooldown - prevent death spiral re-entries
                if (time.time() - self.last_sl_time) < 45:
                    logging.info("🛡️ SL Cooldown active (45s) — Waiting for market to stabilize")
                    return

                # --- 1.5s throttle strictly below TP/SL ---
                if time.time() - self.last_quote_time < 1.5:
                    return
                self.last_quote_time = time.time()

                allow_buy_yes = True
                allow_buy_no = True
                spot_skew = 0.0
                price_delta = 0.0
                if self.live_btc_price and len(self.btc_price_history) > 10:
                    past_price = self.btc_price_history[0]
                    price_delta = self.live_btc_price - past_price
                    if price_delta >= 15:
                        allow_buy_no = False
                        spot_skew = 0.03
                        if price_delta >= 40:
                            spot_skew = 0.06
                    elif price_delta <= -15:
                        allow_buy_yes = False
                        spot_skew = -0.03
                        if price_delta <= -40:
                            spot_skew = -0.06

                if time_left < 300 and price_delta < -20:  # final 5 minutes + strong BTC dump
                    allow_buy_no = False

                # === NO ADD TO LOSER + MOMENTUM REVERSAL GUARD (delta=20) ===
                if self.inventory != 0:
                    if (self.inventory > 0 and price_delta < -20) or (self.inventory < 0 and price_delta > 20):
                        logging.info(f"🚫 NO ADD TO LOSER: momentum reversal against position (Inv={self.inventory}, delta={price_delta:.1f})")
                        if self.inventory > 0:
                            allow_buy_yes = False
                        else:
                            allow_buy_no = False

                if self.inventory >= MAX_INVENTORY_CONTRACTS:
                    allow_buy_yes = False
                if self.inventory <= -MAX_INVENTORY_CONTRACTS:
                    allow_buy_no = False

                # === BULLETPROOF DEAD ZONE FILTER (Upgraded 44-56¢) ===
                # Kills stupid side picking and prevents adding to positions if market chops back into the zone
                mid_price = (self.live_exchange_bid + self.live_exchange_ask) / 2.0 if (self.live_exchange_bid and self.live_exchange_ask) else 50.0

                # Catches both cents (50.0) and decimal (0.50) formats
                if (44.0 <= mid_price <= 56.0) or (0.44 <= mid_price <= 0.56):
                    if self.inventory == 0:
                        allow_buy_yes = False
                        allow_buy_no = False
                        logging.info(f"🛑 DEAD ZONE: mid={mid_price:.2f} — no new entries in 44-56¢ chop")
                    else:
                        # If we have a position, DO NOT add to it while in the chop zone
                        if self.inventory > 0:
                            allow_buy_yes = False
                        if self.inventory < 0:
                            allow_buy_no = False
                        logging.info(f"🛑 DEAD ZONE: mid={mid_price:.2f} — blocking adds in chop (Inv={self.inventory})")

                # === STRICT BINANCE MOMENTUM CONVICTION FILTER v3 — NO CHASE (mandatory for entries) ===
                # Only enter if Binance delta strongly confirms + price not over-extended
                if self.inventory == 0:
                    # Bulletproof price format handling
                    ask_val = self.live_exchange_ask if self.live_exchange_ask < 1.0 else self.live_exchange_ask / 100.0
                    bid_val = self.live_exchange_bid if self.live_exchange_bid < 1.0 else self.live_exchange_bid / 100.0
                    strong_bull = (price_delta > 25) and (ask_val > 0.56) and (ask_val < 0.85)
                    strong_bear = (price_delta < -25) and (bid_val < 0.44) and (bid_val > 0.15)
                    if strong_bull:
                        allow_buy_yes = True
                        allow_buy_no = False
                        logging.info(f"🎯 STRONG BULL CONVICTION (NO CHASE): delta={price_delta:.1f}, ask={ask_val:.2f} — entry authorized")
                    elif strong_bear:
                        allow_buy_yes = False
                        allow_buy_no = True
                        logging.info(f"🎯 STRONG BEAR CONVICTION (NO CHASE): delta={price_delta:.1f}, bid={bid_val:.2f} — entry authorized")
                    else:
                        allow_buy_yes = False
                        allow_buy_no = False
                        logging.debug(f"🚫 WEAK MOMENTUM or CHASE: delta={price_delta:.1f} — no entry")

                # === POST-TP EXHAUSTION LOCKOUT ===
                # Prevent re-entering the same side at a higher price than our last Take Profit
                if getattr(self, 'last_exit_reason', None) == "TAKE PROFIT":
                    last_side = getattr(self, 'last_tp_side', None)
                    last_price = getattr(self, 'last_tp_price', 0)

                    # Require the market to cool off by at least 5 cents before re-entering the same direction
                    if last_side == "yes" and allow_buy_yes:
                        if (ask_val * 100) >= (last_price - 5):
                            allow_buy_yes = False
                            logging.info(f"🛑 EXHAUSTION LOCKOUT: Refusing to buy YES at {ask_val * 100:.1f}¢ (Last TP was {last_price}¢). Waiting for dip.")

                    elif last_side == "no" and allow_buy_no:
                        if (bid_val * 100) >= (last_price - 5):
                            allow_buy_no = False
                            logging.info(f"🛑 EXHAUSTION LOCKOUT: Refusing to buy NO at {bid_val * 100:.1f}¢ (Last TP was {last_price}¢). Waiting for dip.")

                execution_mid = min(0.99, max(0.01, pure_mid + spot_skew))
                if execution_mid > 0.90 or execution_mid < 0.10:
                    if self.resting_bid is not None or self.resting_ask is not None:
                        await self.cancel_active_orders()
                    return

                dynamic_kappa = 50.0
                current_vol = self.get_dynamic_volatility()
                my_bid_cents, my_ask_cents, actual_delta = self.calculate_avellaneda_stoikov(execution_mid, time_left, current_vol, dynamic_kappa)

                # Dynamic sizing: size 2 when inv=0 and spread wide, else 1; respect MAX_INVENTORY
                quote_size = 2 if (self.inventory == 0 and actual_delta > 0.06) else 1

                # === HARD RAMP CAP — actually prevents adds beyond ±3 (kills -5 bug) ===
                if abs(self.inventory) >= 3:
                    quote_size = 1
                    if self.inventory >= 3:
                        allow_buy_yes = False
                    if self.inventory <= -3:
                        allow_buy_no = False
                    logging.info(f"📉 HARD RAMP CAP HIT: |Inv|={abs(self.inventory)} → blocked new adds + size=1")
                bid_count = min(quote_size, MAX_INVENTORY_CONTRACTS - self.inventory) if self.inventory >= 0 else 1
                ask_count = min(quote_size, MAX_INVENTORY_CONTRACTS + self.inventory) if self.inventory <= 0 else 1
                bid_count = max(1, bid_count)
                ask_count = max(1, ask_count)

                intended_bid = None if (not allow_buy_yes and self.inventory >= 0) else my_bid_cents
                intended_ask = None if (not allow_buy_no and self.inventory <= 0) else my_ask_cents
                if intended_bid == self.resting_bid and intended_ask == self.resting_ask:
                    return

                await self.cancel_active_orders()
                orders_to_send = []

                if self.inventory < 0:
                    bid_order = {"action": "sell", "side": "no", "count": bid_count, "type": "limit", "no_price": 100 - my_bid_cents, "ticker": ticker, "client_order_id": str(uuid.uuid4())}
                    orders_to_send.append(self.api.request("POST", "/portfolio/orders", body=bid_order))
                    self.resting_bid = my_bid_cents
                else:
                    if allow_buy_yes:
                        bid_order = {"action": "buy", "side": "yes", "count": bid_count, "type": "limit", "yes_price": my_bid_cents, "ticker": ticker, "client_order_id": str(uuid.uuid4())}
                        orders_to_send.append(self.api.request("POST", "/portfolio/orders", body=bid_order))
                        self.resting_bid = my_bid_cents
                    else:
                        self.resting_bid = None

                if self.inventory > 0:
                    ask_order = {"action": "sell", "side": "yes", "count": ask_count, "type": "limit", "yes_price": my_ask_cents, "ticker": ticker, "client_order_id": str(uuid.uuid4())}
                    orders_to_send.append(self.api.request("POST", "/portfolio/orders", body=ask_order))
                    self.resting_ask = my_ask_cents
                else:
                    if allow_buy_no:
                        ask_order = {"action": "buy", "side": "no", "count": ask_count, "type": "limit", "no_price": 100 - my_ask_cents, "ticker": ticker, "client_order_id": str(uuid.uuid4())}
                        orders_to_send.append(self.api.request("POST", "/portfolio/orders", body=ask_order))
                        self.resting_ask = my_ask_cents
                    else:
                        self.resting_ask = None

                if orders_to_send:
                    results = await asyncio.gather(*orders_to_send)
                    for res in results:
                        if isinstance(res, dict) and "order" in res and "order_id" in res["order"]:
                            self.active_order_ids.add(res["order"]["order_id"])

                bid_str = str(my_bid_cents) + "¢" if self.resting_bid else "PULLED"
                ask_str = str(my_ask_cents) + "¢" if self.resting_ask else "PULLED"
                logging.info(f"WS Reaction | Mid: {execution_mid:.2f} | PnL: {pnl:+.1f}¢ | Cost: {self.position_cost:.1f}¢ | Bid: {bid_str} | Ask: {ask_str}")
            except Exception as e:
                logging.error(f"Silent Crash caught in WS quoting logic: {e}")

    async def listen_to_binance_ws(self):
        uri = "wss://stream.binance.us:9443/ws/btcusdt@ticker"
        logging.info("Connecting to Binance Public Spot WS...")
        
        while True:
            try:
                async with websockets.connect(uri) as ws:
                    logging.info("✅ Connected to Binance Live BTC Spot feed.")
                    while True:
                        message = await ws.recv()
                        data = json.loads(message)
                        self.live_btc_price = float(data['c'])
                        
                        self.btc_price_history.append(self.live_btc_price)
                        if len(self.btc_price_history) > 60:
                            self.btc_price_history.pop(0)
                            
            except Exception as e:
                logging.error(f"Binance WS disconnected: {e}. Reconnecting in 5s...")
                await asyncio.sleep(5)

    async def listen_to_market_data(self, ticker):
        ws_path = "/trade-api/ws/v2"
        while self.is_running:
            try:
                auth_headers = self.api._sign_request("GET", ws_path)
                async with websockets.connect(WS_URL, additional_headers=auth_headers) as ws:
                    subscribe_msg = {
                        "id": 1,
                        "cmd": "subscribe",
                        "params": {
                            "channels": ["ticker", "fill"], 
                            "market_tickers": [ticker]
                        }
                    }
                    await ws.send(json.dumps(subscribe_msg))
                    logging.info(f"Subscribed to WebSockets for {ticker}")

                    while self.is_running:
                        try:
                            message = await asyncio.wait_for(ws.recv(), timeout=1.0)
                            data = json.loads(message)
                            msg_type = data.get("type")

                            if msg_type == "fill":
                                fill_data = data.get("msg", {})
                                trade_id = fill_data.get("trade_id")
                                
                                if trade_id and trade_id not in self.seen_trade_ids:
                                    self.seen_trade_ids.add(trade_id)
                                    action = fill_data.get("action")
                                    side = fill_data.get("side")
                                    count = fill_data.get("count")
                                    price = fill_data.get("price")
                                    
                                    self._apply_fill_to_inventory(action, side, count, price)
                                    self.last_fill_time = time.time()
                                    if abs(self.inventory) != 0:  # new entry or add (not a flattening exit)
                                        self.last_exit_reason = None
                                    
                                    cost_display = f"{self.position_cost:.1f}¢" if self.position_cost > 0 else "0.0¢"
                                    logging.info(f"⚡ WS FILL ALERT: {action.upper()} {count} {side.upper()} @ {price if price else 'None'}¢ | Net Inv: {self.inventory} | Cost: {cost_display}")
                                    
                                    await self.cancel_active_orders()
                                    asyncio.create_task(self.evaluate_and_quote(ticker))
                                    continue

                            elif msg_type == "ticker":
                                msg_data = data.get("msg", {})
                                self.live_exchange_bid = msg_data.get("yes_bid")
                                self.live_exchange_ask = msg_data.get("yes_ask")
                                asyncio.create_task(self.evaluate_and_quote(ticker))
                                    
                        except asyncio.TimeoutError:
                            continue
                        except websockets.exceptions.ConnectionClosed:
                            logging.warning("Kalshi WS connection dropped. Forcing reconnect...")
                            break 
            except Exception as e:
                if self.is_running:
                    logging.error(f"Kalshi WS Connection Error: {e}. Retrying in 2s...")
                    await asyncio.sleep(2)

    async def inventory_manager(self):
        loop_counter = 0
        while self.is_running:
            await self.update_inventory_and_fills()

            # Ghost order sweep every ~36s (every 3 ticks; TICK_INTERVAL=12)
            loop_counter += 1
            if loop_counter % 3 == 0:
                await self.reconcile_ghost_orders()

            time_left = (self.market_close_time - datetime.datetime.now(datetime.timezone.utc)).total_seconds()

            # 3-minute kill switch: flatten if position open, else cancel quotes; then tear down
            if time_left < 180:
                if self.inventory != 0:
                    await self.flatten_position()
                    await asyncio.sleep(3)
                else:
                    await self.cancel_active_orders()
                logging.info(f"⏳ 3-MINUTE DEAD ZONE. Flattened and tearing down WS.")
                self.is_running = False
                break

            await asyncio.sleep(TICK_INTERVAL)

    async def run(self):
        await TelegramAlerts.send("Bot initialized. PREDATOR SCALPING ACTIVE.")
        binance_task = asyncio.create_task(self.listen_to_binance_ws()) 
        
        try:
            while True:
                market_data = await self.find_active_btc_market()
                if not market_data:
                    logging.info("No active 15-min BTC markets found. Sleeping...")
                    await asyncio.sleep(TICK_INTERVAL)
                    continue

                time_left, ticker, close_time = market_data
                self.current_market = ticker
                self.market_close_time = close_time
                self.is_running = True
                
                self.live_exchange_bid = None
                self.live_exchange_ask = None
                
                self.resting_bid = None
                self.resting_ask = None
                self.active_order_ids.clear()
                
                # --- Position restore: average_price_cents if present, else market_exposure, else proxy (mid or 50) ---
                try:
                    pos_res = await self.api.request("GET", f"/portfolio/positions?ticker={ticker}")
                    positions = pos_res.get("market_positions", [])
                    if positions:
                        p = positions[0]
                        qty = p.get("position", 0)
                        exposure = p.get("market_exposure", 0)
                        self.inventory = int(qty)
                        if self.inventory != 0:
                            if p.get("average_price_cents") is not None:
                                self.position_cost = float(p["average_price_cents"])
                                logging.info(f"🔄 Restored existing Kalshi position: {self.inventory} contracts @ {self.position_cost:.1f}¢")
                            elif exposure:
                                self.position_cost = float(exposure) / abs(self.inventory)
                                logging.info(f"🔄 Restored existing Kalshi position: {self.inventory} contracts @ {self.position_cost:.1f}¢")
                            else:
                                if self.inventory > 0 and self.live_exchange_bid is not None:
                                    self.position_cost = float(self.live_exchange_bid)
                                elif self.inventory < 0 and self.live_exchange_ask is not None:
                                    self.position_cost = 100.0 - float(self.live_exchange_ask)
                                else:
                                    self.position_cost = 50.0
                                logging.info(f"🔄 Restored position with proxy cost basis: {self.inventory} contracts @ {self.position_cost:.1f}¢")
                        else:
                            self.position_cost = 0.0
                    else:
                        self.inventory = 0
                        self.position_cost = 0.0
                except Exception as e:
                    logging.error(f"Failed to fetch initial position: {e}")
                    self.inventory = 0
                    self.position_cost = 0.0

                logging.info(f"=== Spinning up Event-Driven Engine for {ticker} ===")
                ws_task = asyncio.create_task(self.listen_to_market_data(ticker))
                inv_task = asyncio.create_task(self.inventory_manager())
                
                await asyncio.gather(ws_task, inv_task)
                
                daily_pnl_dollars = self.daily_pnl_cents / 100.0
                pnl_msg = f"📊 Market Closed: {ticker}\n💰 Cumulative Daily PnL: {daily_pnl_dollars:+.2f}$"
                logging.info(pnl_msg)
                current_time = time.time()
                if current_time - self.last_pnl_telegram_time >= 900:  # 15 minutes
                    await TelegramAlerts.send(pnl_msg)
                    self.last_pnl_telegram_time = current_time
                    logging.info("📨 Daily PnL Telegram sent")
                else:
                    logging.info(f"📨 Telegram PnL throttled ({int(current_time - self.last_pnl_telegram_time)}s since last send)")
                self.save_daily_pnl()
                
                await asyncio.sleep(TICK_INTERVAL)

        except asyncio.CancelledError:
            logging.info("Task cancelled. Graceful shutdown initiated...")
            await self.cancel_active_orders()
            binance_task.cancel()
            await TelegramAlerts.send("Bot shut down gracefully via Cancellation.")
        except KeyboardInterrupt:
            logging.info("Keyboard interrupt caught. Graceful shutdown initiated...")
            await self.cancel_active_orders()
            binance_task.cancel()
            await TelegramAlerts.send("Bot shut down gracefully. Open orders canceled.")

if __name__ == "__main__":
    bot = AsyncStoikovSentinel()
    try:
        asyncio.run(bot.run())
    except KeyboardInterrupt:
        pass
    except RuntimeError:
        pass
