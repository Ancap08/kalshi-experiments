import os
import sys
import yaml
import time
import logging
import logging.handlers
try:
    import orjson as json
    _orjson_dumps = json.dumps
    def _json_dumps_str(obj) -> str:
        return _orjson_dumps(obj).decode('utf-8')
except ImportError:
    import json

from datetime import datetime
    _json_dumps_str = json.dumps
    logging.warning("orjson not installed — falling back to stdlib json. Run: pip install orjson")
import base64
import datetime
from zoneinfo import ZoneInfo
import math
import statistics
import aiohttp
import uuid
import asyncio
import websockets
from dotenv import load_dotenv
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import concurrent.futures
_SIGN_EXECUTOR = concurrent.futures.ThreadPoolExecutor(max_workers=2, thread_name_prefix="kalshi_signer")

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
# FIXED: Expanded from 12 to 60 to capture adequate market history before spread compression.
VOLATILITY_WINDOW = 60
MAX_INVENTORY_CONTRACTS = 5   
TICK_INTERVAL = 12 
BASE_URL = "https://api.elections.kalshi.com/trade-api/v2"
WS_URL = "wss://api.elections.kalshi.com/trade-api/ws/v2"

from logging.handlers import RotatingFileHandler

log_formatter = logging.Formatter('%(asctime)s | %(levelname)s | %(message)s')

file_handler = RotatingFileHandler("StoikovSentinel.log", maxBytes=10*1024*1024, backupCount=5)
file_handler.setFormatter(log_formatter)
file_handler.setLevel(logging.DEBUG)

console_handler = logging.StreamHandler()
console_handler.setFormatter(log_formatter)
console_handler.setLevel(logging.INFO)

root_logger = logging.getLogger()
root_logger.handlers = []
root_logger.addHandler(file_handler)
root_logger.addHandler(console_handler)
root_logger.setLevel(logging.DEBUG)
logging.getLogger("websockets").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)
logging.getLogger("aiohttp").setLevel(logging.WARNING)


class CriticalDrawdownException(BaseException):
    """Raised when global drawdown limit is hit. Inherits from BaseException so it
    is not swallowed by except Exception. Handled in run() to stop the event loop."""
    pass


class TelegramAlerts:    
    @staticmethod
    async def send(message):
        if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
            return
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        payload = {
            "chat_id": TELEGRAM_CHAT_ID,
            "text": f"🤖 StoikovSentinel_Predator\n{message}"
        }
        try:
            async with aiohttp.ClientSession() as session:
                await session.post(
                    url,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=5)
                )
        except Exception as e:
            logging.error(f"Telegram failed: {e}")

class AsyncKalshiClient:
    def __init__(self, key_id, key_path, base_url):
        self.key_id = key_id
        self.base_url = base_url
        self.session: aiohttp.ClientSession | None = None
        with open(key_path, "rb") as key_file:
            self.private_key = serialization.load_pem_private_key(
                key_file.read(), password=None, backend=default_backend()
            )

    async def start_session(self):
        """Create aiohttp session in async context. Call before first request."""
        if self.session is None or self.session.closed:
            self.session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=5)
            )

    async def close_session(self):
        """Close aiohttp session gracefully. Call on shutdown."""
        if self.session and not self.session.closed:
            await self.session.close()

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

    async def _sign_request_async(self, method: str, path: str) -> dict:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(_SIGN_EXECUTOR, self._sign_request, method, path)

    # FIXED: Migrated to native aiohttp to prevent thread-pool exhaustion under high-frequency load.
    async def request(self, method, endpoint, body=None):
        if self.session is None or self.session.closed:
            await self.start_session()
        path = f"/trade-api/v2{endpoint}"
        headers = await self._sign_request_async(method, path)
        url = self.base_url + endpoint
        max_retries = 4
        for attempt in range(max_retries):
            try:
                async with self.session.request(method, url, headers=headers, json=body) as response:
                    if response.status == 429:
                        backoff = 2 ** attempt
                        logging.warning(f"🛑 API 429 Rate Limit hit. Backing off for {backoff}s...")
                        await response.read()  # Consume body before retry
                        await asyncio.sleep(backoff)
                        continue

                    text_resp = await response.text()
                    if response.status >= 400:
                        if response.status not in [404, 409]:
                            logging.error(f"API Error {response.status} on {method}: {text_resp}")
                        try:
                            return json.loads(text_resp)
                        except json.JSONDecodeError:
                            return {}
                    try:
                        return json.loads(text_resp)
                    except json.JSONDecodeError:
                        return {}
            except Exception as e:
                logging.error(f"API Request failed: {e}")
                return {}
        logging.error("❌ Max retries hit for 429 rate limit. Request failed.")
        return {}

class AsyncStoikovSentinel:
    """v7 Aggressive + Pre-emption (Binance Shadow + OBI + relaxed cushion 3.0)"""

    MAKER_FEE_CENTS = 0.44
    TAKER_FEE_CENTS = 1.75

    # Pull quotes on large ETH spot moves. Uses 0.60% threshold (tuned for ETH).
    def should_preemptive_pull(self, current_price: float) -> bool:
        """Pull quotes only on large ETH price moves. Uses previous tick (not oldest)
        so the velocity shield acts as fast-twitch defense against adverse selection."""
        if len(self.eth_price_history) < 2:
            return False
        past_price = self.eth_price_history[-2]  # immediate last tick, not oldest in buffer
        delta_pct = abs(current_price - past_price) / past_price * 100
        should_pull = delta_pct > 0.60   # 0.60% threshold - tuned for ETH
        if should_pull:
            logging.info(f"PRE-EMPTIVE PULL triggered: {delta_pct:.2f}% ETH move")
        return should_pull

    def should_requote(self, new_bid: float, new_ask: float) -> bool:
        """
        Returns True if the price move is large enough to justify losing queue priority.
        Always returns True if we currently have no active orders.
        """
        HYSTERESIS_THRESHOLD = 1.0  # Minimum 1 cent move to justify a requote

        # If we don't have orders, we MUST quote. No hysteresis.
        if not self.active_order_ids:
            return True

        # Get last quoted prices
        old_bid = getattr(self, 'last_quoted_bid', 0.0)
        old_ask = getattr(self, 'last_quoted_ask', 0.0)

        # Check if either side moved significantly
        bid_move = abs(new_bid - old_bid)
        ask_move = abs(new_ask - old_ask)

        if bid_move >= HYSTERESIS_THRESHOLD or ask_move >= HYSTERESIS_THRESHOLD:
            return True

        return False

    def _load_config(self):
        """Load config.yaml (flat key/value) from the same directory as this script.
        Falls back to hardcoded defaults if the file is missing or malformed.
        Loaded keys overwrite defaults; any key absent from the file keeps its default."""
        defaults = {
            # Core risk
            "daily_profit_target":          15.00,
            "max_inventory":                5,
            "minimum_spread_cents":         7.0,
            "risk_aversion_gamma":          0.1,
            "max_capital_exposure_pct":     0.05,
            "pair_lock_threshold":          0.98,
            "PURE_ARB_THRESHOLD_CENTS":     98.0,
            "max_locked_pairs":             2,
            "max_unbalanced_pct":           0.05,
            # Alpha engine
            "STOIKOV_GAMMA_SCALE":          0.003,
            "basis_velocity_shield":        15.0,
            "delta_volatility_shield":      80.0,
            "base_skew_multiplier":         1.5,
            "alpha_skew":                   2.4,
            # Exit / guard matrix
            "no_chase_ceiling_cents":       92.0,
            "cushion_guard_min_pnl_cents":  5.0,
            "STOP_LOSS":                    -30.0,
            "trailing_stop_cents":          4.0,
            "ripcord_minutes":              3,
            "light_cooldown_seconds":       5,
            # Capital / infra
            "kalshi_balance_cache_minutes":      15,
            "minimum_account_balance_dollars":   20.0,
        }
        config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.yaml")
        try:
            with open(config_path, "r") as f:
                loaded = yaml.safe_load(f)
            if not isinstance(loaded, dict):
                raise ValueError("config.yaml is empty or not a valid YAML mapping.")
            # Flat merge — loaded values overwrite defaults key-by-key
            defaults.update(loaded)
            # logging.debug(f"✅ config.yaml loaded (flat): {config_path}")
            return defaults
        except FileNotFoundError:
            logging.warning(f"⚠️  config.yaml not found at {config_path}. Using hardcoded defaults.")
            return defaults
        except Exception as e:
            logging.error(f"⚠️  config.yaml failed to parse ({e}). Using hardcoded defaults.")
            return defaults

    def __init__(self):
        self.config = self._load_config()
        self.api = AsyncKalshiClient(KALSHI_KEY_ID, KALSHI_PRIVATE_KEY_PATH, BASE_URL)

        self.quote_lock = None
        self.state_changed = None

        # === PER-EVENT PAIR-LOCK INVENTORY ARCHITECTURE ===
        self.event_id = None
        self.yes_inventory  = {}   # {event_id: int}  — strictly positive counts
        self.no_inventory   = {}   # {event_id: int}  — strictly positive counts
        self.yes_cost_basis = {}   # {event_id: float} — VWAP in YES-space cents
        self.no_cost_basis  = {}   # {event_id: float} — VWAP in NO-space cents
        self.no_chase_ceiling_cents = float(self.config.get("no_chase_ceiling_cents", 92.0))
        self.pair_lock_threshold = float(self.config.get("pair_lock_threshold", 0.98))
        self.max_locked_pairs = int(self.config.get("max_locked_pairs", 2))

        self.last_taker_time = 0

        self.daily_pnl_cents = 0.0
        # === PnL DECOMPOSITION BUCKETS ===
        self.maker_spread_pnl     = 0.0   # resting limit fills: bid/ask round-trips
        self.arb_settlement_pnl   = 0.0   # locked pair $1.00 settlements
        self.directional_taker_pnl = 0.0  # aggressive exits: SL, TP, pulls
        self.load_daily_pnl()
        self.daily_profit_target = self.config["daily_profit_target"]
        self.done_for_day = False
        self.GAMMA = GAMMA
        self.kappa = KAPPA
        self.max_inventory = int(self.config.get("max_inventory", 5))
        self.spread_ema: float = 6.0

        self.flight_log_file = f"flight_record_{datetime.now().strftime('%Y-%m-%d')}.jsonl"

        self.current_market = None
        self.market_close_time = None
        self.price_history = []
        self.last_price_history_update = 0
        self.seen_trade_ids = set()

        self.live_exchange_bid = None
        self.live_exchange_ask = None

        self.prev_mid         = None   # previous kalshi mid in fractional (0-1)
        self.velocity_ema     = 0.0    # EMA of tick-to-tick mid velocity in cents
        self.reservation_price = None  # Stoikov reservation price for House-Money sizing

        self.is_running = False

        self.resting_bid = None
        self.resting_ask = None
        self.resting_exit_price = None
        self.active_order_ids = set()
        self.pending_orders = 0  # async leak guard: in-flight order requests

        self.last_quote_time = 0.0
        self.last_sl_time = 0.0
        self.last_pnl_telegram_time = 0.0
        self.last_fill_time = 0.0
        self.last_exit_reason = None
        self.last_ws_msg_time = time.time()

        self.live_eth_price = None
        self.eth_price_history = []
        self.live_eth_futures_price = None
        self.futures_price = None
        self.perp_basis = 0.0
        self.previous_basis_shift = 0.0
        self.basis_velocity = 0.0

        self.current_balance = 100.0  # safe fallback in dollars; updated each market cycle

        self.binance_delta     = 0.0   # for pre-emptive pull
        self.instant_velocity  = 0.0   # for inlined high-vol naked ban
        self.kalshi_book       = {'bids': [], 'asks': []}
        self.state_changed     = asyncio.Event()
        self.latest_ticker     = None
        self.quote_consumer_task: asyncio.Task | None = None
        self.last_quoted_bid   = 0.0   # for hysteresis guard
        self.last_quoted_ask   = 0.0   # for hysteresis guard
        self.last_lock_time    = 0.0   # for Lock & Walk 60s cooldown
        self.last_dislocation_time = 0.0 # for Basis Dislocation Ejector 30s cooldown
        self.current_orderbook = {}    # WS-cached book for OBI (no REST)

        # === BBO OFI STATE (bookTicker stream) ===
        self.ofi_prev_bid_price: float | None = None
        self.ofi_prev_bid_qty:   float        = 0.0
        self.ofi_prev_ask_price: float | None = None
        self.ofi_prev_ask_qty:   float        = 0.0
        self.ofi_ema:            float        = 0.0
        self.ofi_scalar:         float        = 0.0   # [-1.0, 1.0] — used by dynamic_q0

        # === ORACLE CORRELATION ENGINE ===
        self.basis_shift_history:  list  = []
        self.kalshi_vel_history:   list  = []
        self.oracle_correlation:   float = 0.0

        # === FILL RATE MODEL (Queue Position State) ===
        self.live_yes_bid_size: int = 0
        self.live_yes_ask_size: int = 0

        # === PAIR-LOCK QUARANTINE ===
        # Locked arb pairs are isolated here at kill-shot time so subsequent naked
        # scalps cannot contaminate their cost basis via VWAP blending.
        self.locked_pairs: list = []  # [{'ticker': str, 'qty': int, 'yes_cost': float, 'no_cost': float}]

    def load_daily_pnl(self):
        today = datetime.date.today().isoformat()
        try:
            if os.path.exists("pnl_tracker_eth.txt"):
                with open("pnl_tracker_eth.txt", "r") as f:
                    data = f.read().strip().split("|")
                if data[0] == today:
                    self.daily_pnl_cents = float(data[1])
                    if len(data) >= 5:
                        self.maker_spread_pnl      = float(data[2])
                        self.arb_settlement_pnl    = float(data[3])
                        self.directional_taker_pnl = float(data[4])
                    else:
                        self.maker_spread_pnl      = 0.0
                        self.arb_settlement_pnl    = 0.0
                        self.directional_taker_pnl = 0.0
                        logging.info("📊 Legacy PnL file detected — migrating to decomposed format.")
                    return
            self.daily_pnl_cents       = 0.0
            self.maker_spread_pnl      = 0.0
            self.arb_settlement_pnl    = 0.0
            self.directional_taker_pnl = 0.0
            self.save_daily_pnl()
        except Exception as e:
            logging.error(f"Could not load PnL tracker: {e}")

    def save_daily_pnl(self):
        today = datetime.date.today().isoformat()
        try:
            with open("pnl_tracker_eth.txt", "w") as f:
                f.write(
                    f"{today}"
                    f"|{self.daily_pnl_cents:.4f}"
                    f"|{self.maker_spread_pnl:.4f}"
                    f"|{self.arb_settlement_pnl:.4f}"
                    f"|{self.directional_taker_pnl:.4f}"
                )
        except Exception as e:
            logging.error(f"Could not save PnL tracker: {e}")

    def _record_flight_log(self, event_type: str, details: dict = None):
        """Silently appends the current internal state to the JSONL flight recorder."""
        try:
            payload = {
                "timestamp": time.time(),
                "time_iso": datetime.now().isoformat(),
                "event": event_type,
                "market_mid": getattr(self, 'current_mid', 0.0) or 0.0,
                "market_spread": getattr(self, 'current_spread', 0.0) or 0.0,
                "oracle_delta": getattr(self, 'last_binance_delta', 0.0) or 0.0,
                "oracle_basis": getattr(self, 'basis_ema', 0.0) or 0.0,
                "q0_offset": getattr(self, 'dynamic_q0', 0.0) or 0.0,
                "inv_yes": getattr(self, 'live_yes_inventory', 0) or 0,
                "inv_no": getattr(self, 'live_no_inventory', 0) or 0,
                "pnl_total": getattr(self, 'daily_pnl_cents', 0.0) or 0.0
            }
            if details:
                payload.update(details)

            with open(self.flight_log_file, "a") as f:
                f.write(json.dumps(payload) + "\n")
        except Exception as e:
            pass  # Never block or crash the trading loop if I/O fails

    def _log_pnl_breakdown(self):
        """Emit a single structured log line with the full PnL decomposition."""
        total_d   = self.daily_pnl_cents       / 100.0
        maker_d   = self.maker_spread_pnl      / 100.0
        arb_d     = self.arb_settlement_pnl    / 100.0
        direc_d   = self.directional_taker_pnl / 100.0
        residual  = total_d - (maker_d + arb_d + direc_d)
        logging.info(
            f"📊 PnL BREAKDOWN | "
            f"Total: {total_d:+.2f}$ | "
            f"🏭 Maker: {maker_d:+.2f}$ | "
            f"🔐 Arb: {arb_d:+.2f}$ | "
            f"🎯 Directional: {direc_d:+.2f}$ | "
            f"Δ Residual: {residual:+.4f}$"
        )
        self._record_flight_log("HEARTBEAT")

    # ── Pair-Lock Helpers ──────────────────────────────────────────────────────

    def get_locked_pairs(self, event_id=None):
        """Return the number of fully-hedged YES+NO pairs for *event_id*."""
        eid = event_id or self.event_id
        if not eid:
            return 0
        return min(self.yes_inventory.get(eid, 0), self.no_inventory.get(eid, 0))

    def get_unbalanced_leg(self, event_id=None):
        """Return (qty, side) for the naked (unprotected) leg, or (0, None)."""
        eid = event_id or self.event_id
        if not eid:
            return 0, None
        yes = self.yes_inventory.get(eid, 0)
        no  = self.no_inventory.get(eid, 0)
        locked    = min(yes, no)
        naked_yes = yes - locked
        naked_no  = no  - locked
        if naked_yes > 0:
            return naked_yes, "yes"
        if naked_no > 0:
            return naked_no, "no"
        return 0, None

    def settle_locked_pairs(self, event_id):
        """Realize PnL on locked pairs at the guaranteed $1.00 settlement payout.
        Quarantined pairs in self.locked_pairs settle at their exact recorded costs.
        Any residual VWAP-tracked pairs (legacy path) settle at blended cost."""
        SETTLEMENT_FEE = 1.0  # cents per contract

        # — Path A: quarantined pairs with exact isolated costs —
        quarantined = [p for p in self.locked_pairs if p['ticker'] == event_id]
        for p in quarantined:
            combined = p['yes_cost'] + p['no_cost']
            gross    = 100.0 - combined
            net      = gross - (2 * SETTLEMENT_FEE)
            total    = p['qty'] * net
            self.daily_pnl_cents += total
            self.arb_settlement_pnl += total
            logging.info(
                f"🏆 QUARANTINE SETTLEMENT: {p['qty']} pair(s) | "
                f"YES {p['yes_cost']:.1f}¢ + NO {p['no_cost']:.1f}¢ = {combined:.1f}¢ | "
                f"Net PnL: {total:+.1f}¢ (${total / 100:.2f})"
            )
        self.locked_pairs = [p for p in self.locked_pairs if p['ticker'] != event_id]

        # — Path B: any residual legacy-tracked locked pairs (blended VWAP) —
        yes    = self.yes_inventory.get(event_id, 0)
        no     = self.no_inventory.get(event_id, 0)
        locked = min(yes, no)
        if locked > 0:
            yes_cost = self.yes_cost_basis.get(event_id, 0.0)
            no_cost  = self.no_cost_basis.get(event_id, 0.0)
            combined_cost_cents = yes_cost + no_cost
            gross_pnl_per_pair  = 100.0 - combined_cost_cents
            net_pnl_per_pair    = gross_pnl_per_pair - (2 * SETTLEMENT_FEE)
            total_pnl           = locked * net_pnl_per_pair
            self.daily_pnl_cents += total_pnl
            self.arb_settlement_pnl += total_pnl
            logging.info(
                f"🏆 LEGACY SETTLEMENT: {locked} pair(s) → $1.00 payout each. "
                f"Combined cost: {combined_cost_cents:.1f}¢/pair. "
                f"Net PnL: {total_pnl:+.1f}¢ (${total_pnl / 100:.2f})"
            )
        # Wipe all rolling inventory state for this event
        for d in (self.yes_inventory, self.no_inventory,
                  self.yes_cost_basis, self.no_cost_basis):
            d.pop(event_id, None)
        self.save_daily_pnl()
        self._log_pnl_breakdown()

    # ── Market Viability & Session Warm-Up ────────────────────────────────────

    def _is_market_viable(self, mid_cents: float, time_left: float, spread_cents: float) -> tuple[bool, str]:
        min_spread  = float(self.config.get("minimum_spread_cents", 7.0))
        mid_lo      = float(self.config.get("viability_mid_floor",  20.0))
        mid_hi      = float(self.config.get("viability_mid_ceiling", 80.0))
        spread_ratio = float(self.config.get("viability_spread_ratio", 0.5))
        min_time    = float(self.config.get("viability_min_seconds", 210.0))

        if mid_cents > mid_hi:
            return False, f"mid {mid_cents:.1f}¢ > {mid_hi:.0f}¢ ceiling (directional trap)"
        if mid_cents < mid_lo:
            return False, f"mid {mid_cents:.1f}¢ < {mid_lo:.0f}¢ floor (directional trap)"

        viable_spread_floor = min_spread * spread_ratio
        if spread_cents < viable_spread_floor:
            return False, f"BBO spread {spread_cents:.1f}¢ < viability floor {viable_spread_floor:.1f}¢"

        if time_left < min_time:
            return False, f"only {time_left:.0f}s remaining (floor={min_time:.0f}s)"

        return True, "OK"

    def _get_warmup_spread_mult(self) -> float:
        target     = int(self.config.get("warmup_ticks_target", 30))
        confidence = min(1.0, len(self.price_history) / max(1, target))
        mult = 2.0 - confidence
        if confidence < 1.0:
            logging.debug(f"🌡️ WARMUP: {len(self.price_history)}/{target} ticks (conf={confidence:.2f}) → spread mult {mult:.2f}×")
        return mult

    # ── Terminal Taker Aggression ──────────────────────────────────────────────

    def _get_terminal_aggression_cents(self, time_left: float) -> int:
        window   = float(self.config.get("terminal_window_seconds",       300.0))
        max_agg  = int(self.config.get("terminal_aggression_max_cents",   3))

        if time_left >= window or max_agg <= 0:
            return 0

        t_clamped = max(0.0, min(time_left, window))
        fraction  = 1.0 - (t_clamped / window)
        offset    = round(fraction * max_agg)
        return int(min(max_agg, max(0, offset)))

    # ── End Terminal Taker Aggression ─────────────────────────────────────────

    @staticmethod
    def _pearson_correlation(x: list, y: list) -> float:
        n = len(x)
        if n < 3: return 0.0
        mean_x, mean_y = sum(x) / n, sum(y) / n
        num = sum((xi - mean_x) * (yi - mean_y) for xi, yi in zip(x, y))
        den_x = math.sqrt(sum((xi - mean_x) ** 2 for xi in x))
        den_y = math.sqrt(sum((yi - mean_y) ** 2 for yi in y))
        if den_x < 1e-9 or den_y < 1e-9: return 0.0
        return max(-1.0, min(1.0, num / (den_x * den_y)))

    def _update_oracle_correlation(self, kalshi_vel_cents: float) -> None:
        window = int(self.config.get("correlation_window", 20))
        basis_val = getattr(self, 'basis_shift', 0.0)
        self.basis_shift_history.append(basis_val)
        self.kalshi_vel_history.append(kalshi_vel_cents)

        if len(self.basis_shift_history) > window: self.basis_shift_history.pop(0)
        if len(self.kalshi_vel_history) > window: self.kalshi_vel_history.pop(0)

        if len(self.basis_shift_history) >= 5:
            self.oracle_correlation = self._pearson_correlation(self.basis_shift_history, self.kalshi_vel_history)

    def _get_correlation_spread_mult(self) -> float:
        r = self.oracle_correlation
        if r >= float(self.config.get("corr_thresh_high", 0.70)): return float(self.config.get("corr_mult_high", 0.85))
        elif r >= float(self.config.get("corr_thresh_mid", 0.30)): return float(self.config.get("corr_mult_mid", 1.00))
        elif r >= float(self.config.get("corr_thresh_low", 0.00)): return float(self.config.get("corr_mult_low", 1.20))
        else: return float(self.config.get("corr_mult_neg", 1.40))

    def _active_yes_cost(self, eid: str) -> float:
        """Cost basis for NAKED (non-quarantined) YES contracts only.
        Back-calculates from blended VWAP by subtracting the quarantined
        locked_pairs contribution, leaving only the active directional leg."""
        total_yes   = self.yes_inventory.get(eid, 0)
        blended     = self.yes_cost_basis.get(eid, 50.0)
        if not eid or total_yes <= 0:
            return 50.0
        q_qty      = sum(p['qty']            for p in self.locked_pairs if p['ticker'] == eid)
        q_cost_sum = sum(p['yes_cost'] * p['qty'] for p in self.locked_pairs if p['ticker'] == eid)
        naked_qty  = total_yes - q_qty
        if naked_qty <= 0:
            return 50.0
        return (blended * total_yes - q_cost_sum) / naked_qty

    def _active_no_cost(self, eid: str) -> float:
        """Cost basis for NAKED (non-quarantined) NO contracts only."""
        total_no    = self.no_inventory.get(eid, 0)
        blended     = self.no_cost_basis.get(eid, 50.0)
        if not eid or total_no <= 0:
            return 50.0
        q_qty      = sum(p['qty']           for p in self.locked_pairs if p['ticker'] == eid)
        q_cost_sum = sum(p['no_cost'] * p['qty'] for p in self.locked_pairs if p['ticker'] == eid)
        naked_qty  = total_no - q_qty
        if naked_qty <= 0:
            return 50.0
        return (blended * total_no - q_cost_sum) / naked_qty

    def _process_arb_fill_confirmation(
        self,
        eid: str,
        side: str,
        fill_price_cents: float,
        locked_before: int,
        active_yes_before: float,
        active_no_before: float,
    ) -> None:
        """Unified quarantine ledger for both Pure Arb Scanner and Kill Shot.
        Call only after inventory has been updated with the fill. Computes how many
        new locked pairs this fill completed and appends them to self.locked_pairs
        with exact costs; then runs cost-update for any existing entries if fill
        was better than limit."""
        locked_after = min(
            self.yes_inventory.get(eid, 0),
            self.no_inventory.get(eid, 0),
        )
        new_locked = locked_after - locked_before
        if new_locked > 0 and side == "no":
            self.locked_pairs.append({
                "ticker": eid,
                "qty": new_locked,
                "yes_cost": active_yes_before,
                "no_cost": fill_price_cents,
            })
            logging.info(
                f"🔐 QUARANTINED {new_locked} pair(s) on FILL @ "
                f"YES {active_yes_before:.1f}¢ + NO {fill_price_cents:.1f}¢"
            )
        elif new_locked > 0 and side == "yes":
            self.locked_pairs.append({
                "ticker": eid,
                "qty": new_locked,
                "yes_cost": fill_price_cents,
                "no_cost": active_no_before,
            })
            logging.info(
                f"🔐 QUARANTINED {new_locked} pair(s) on FILL @ "
                f"YES {fill_price_cents:.1f}¢ + NO {active_no_before:.1f}¢"
            )
        new_pairs = self.locked_pairs[-new_locked:] if new_locked > 0 else []
        for p in new_pairs:
            if p["ticker"] == eid:
                if side == "no" and fill_price_cents < p["no_cost"]:
                    p["no_cost"] = fill_price_cents
                    logging.debug(
                        f"🔐 QUARANTINE UPDATE: NO cost improved "
                        f"{p['no_cost']:.1f}¢ → {fill_price_cents:.1f}¢"
                    )
                elif side == "yes" and fill_price_cents < p["yes_cost"]:
                    p["yes_cost"] = fill_price_cents
                    logging.debug(
                        f"🔐 QUARANTINE UPDATE: YES cost improved "
                        f"{p['yes_cost']:.1f}¢ → {fill_price_cents:.1f}¢"
                    )

    # ── End Pair-Lock Helpers ──────────────────────────────────────────────────

    async def update_kalshi_balance(self):
        """Fetches Kalshi balance once per market cycle to avoid rate limits."""
        try:
            res = await self.api.request("GET", "/portfolio/balance")
            if isinstance(res, dict) and "balance" in res:
                self.current_balance = float(res["balance"]) / 100.0  # Kalshi returns cents → dollars
                logging.info(f"🏦 Bankroll updated: ${self.current_balance:.2f}")
            else:
                logging.warning("⚠️ Could not parse balance response, using previous/fallback value.")
        except Exception as e:
            logging.warning(f"⚠️ Balance fetch failed: {e}. Using fallback ${self.current_balance:.2f}")

    def _apply_fill_to_inventory(self, eid: str, count: int, fill_price_cents: float, is_buy: bool, is_taker: bool):
        fee_cents = self.TAKER_FEE_CENTS if is_taker else self.MAKER_FEE_CENTS
        if is_buy:
            cur_qty = self.yes_inventory.get(eid, 0)
            cur_cost = self.yes_cost_basis.get(eid, 0.0)
            new_qty = cur_qty + count
            self.yes_cost_basis[eid] = (cur_qty * cur_cost + count * (fill_price_cents + fee_cents)) / new_qty
            self.yes_inventory[eid] = new_qty
        else:
            cur_qty = self.yes_inventory.get(eid, 0)
            cur_cost = self.yes_cost_basis.get(eid, 0.0)
            realized = count * (fill_price_cents - fee_cents - cur_cost)
            self.daily_pnl_cents += realized
            # === PnL BUCKET ROUTING ===
            if is_taker:
                self.directional_taker_pnl += realized
            else:
                self.maker_spread_pnl += realized
            self.save_daily_pnl()
            self.yes_inventory[eid] = cur_qty - count
            if self.yes_inventory[eid] <= 0:
                self.yes_inventory.pop(eid, None)
                self.yes_cost_basis.pop(eid, None)

    def _apply_no_fill_to_inventory(self, eid: str, count: int, fill_price_cents: float, is_buy: bool, is_taker: bool):
        fee_cents = self.TAKER_FEE_CENTS if is_taker else self.MAKER_FEE_CENTS
        if is_buy:
            cur_qty = self.no_inventory.get(eid, 0)
            cur_cost = self.no_cost_basis.get(eid, 0.0)
            new_qty = cur_qty + count
            self.no_cost_basis[eid] = (cur_qty * cur_cost + count * (fill_price_cents + fee_cents)) / new_qty
            self.no_inventory[eid] = new_qty
        else:
            cur_qty = self.no_inventory.get(eid, 0)
            cur_cost = self.no_cost_basis.get(eid, 0.0)
            realized = count * (fill_price_cents - fee_cents - cur_cost)
            self.daily_pnl_cents += realized
            # === PnL BUCKET ROUTING ===
            if is_taker:
                self.directional_taker_pnl += realized
            else:
                self.maker_spread_pnl += realized
            self.save_daily_pnl()
            self.no_inventory[eid] = cur_qty - count
            if self.no_inventory[eid] <= 0:
                self.no_inventory.pop(eid, None)
                self.no_cost_basis.pop(eid, None)

    async def find_active_eth_market(self):
        res = await self.api.request("GET", "/markets?series_ticker=KXETH15M&status=open")
        markets = res.get("markets", [])
        if not markets: return None

        valid_markets = []
        for m in markets:
            close_time = datetime.datetime.fromisoformat(m["close_time"].replace("Z", "+00:00"))
            time_left = (close_time - datetime.datetime.now(datetime.timezone.utc)).total_seconds()

            # Ignore markets with < 3.5 minutes (210s) remaining — prevents 3-min ripcord spin-up loop
            if 210 < time_left <= 1000:
                valid_markets.append((time_left, m["ticker"], close_time))
            elif time_left <= 210:
                logging.info(f"⏭️ SKIP MARKET: {m['ticker']} has only {int(time_left)}s left — below 3.5-min entry floor.")

        if valid_markets:
            valid_markets.sort()
            new_ticker = valid_markets[0][1]
            # BANK THE PROFITS: settle the old market before subscribing to a new one
            if self.current_market and self.current_market != new_ticker:
                logging.info(
                    f"🏦 Market change detected. Settling {self.current_market} "
                    f"before moving to {new_ticker}."
                )
                self.settle_locked_pairs(self.event_id)
                self.price_history = []
                self.seen_trade_ids.clear()
                self.prev_mid      = None
                self.velocity_ema  = 0.0
                # FIXED: Prevents new markets from inheriting the trailing stop state of the previous market.
                self.peak_pnl = 0.0
                self.trailing_stop_active = False
            self.current_market = new_ticker
            return valid_markets[0]
        return None

    def get_dynamic_volatility(self):
        if len(self.price_history) < 2:
            return BASE_VOLATILITY
        std_dev = statistics.stdev(self.price_history)
        return max(std_dev, 0.05)

    def get_adaptive_kappa(self, current_spread_cents: float) -> float:
        self.spread_ema = (0.3 * current_spread_cents) + (0.7 * self.spread_ema)
        BASE_SPREAD  = float(self.config.get("adaptive_kappa_base_spread", 6.0))
        KAPPA_SCALE  = float(self.config.get("adaptive_kappa_scale", 1.0))
        KAPPA_MIN    = self.kappa * 0.4
        KAPPA_MAX    = self.kappa * 2.5
        ratio    = self.spread_ema / BASE_SPREAD if BASE_SPREAD > 0 else 1.0
        adjusted = (self.kappa / ratio) * KAPPA_SCALE
        return max(KAPPA_MIN, min(KAPPA_MAX, adjusted))

    def get_time_scaled_gamma(self, T_normalised: float) -> float:
        base_gamma = self.GAMMA * self.config.get("STOIKOV_GAMMA_SCALE", 0.003)
        alpha = float(self.config.get("gamma_time_alpha", 3.0))
        beta  = float(self.config.get("gamma_time_beta",  2.5))
        time_multiplier = 1.0 + alpha * ((1.0 - T_normalised) ** beta)
        return base_gamma * time_multiplier

    def calculate_avellaneda_stoikov(self, execution_mid: float, inventory: int, current_vol: float, T: float,
                                     kappa_override: float | None = None,
                                     gamma_yes_mult: float = 1.0, gamma_no_mult: float = 1.0,
                                     min_spread_override: float | None = None):
        """Stoikov reservation price + spread with optional asymmetric gamma.

        gamma_yes_mult / gamma_no_mult scale the time-adjusted gamma independently
        for the bid (YES) and ask (NO) sides.  Default 1.0 → symmetric behaviour.
        Bullish regime: narrow YES spread (attract fills), widen NO spread.
        Bearish regime: narrow NO spread (attract fills), widen YES spread.

        *inventory* is the NET NAKED position (positive=YES, negative=NO).
        Locked pairs are excluded — they are not exposed to quote risk.
        execution_mid and outputs stay in fractional space (0-1).
        """
        T = max(0.001, T)
        effective_gamma = self.get_time_scaled_gamma(T)
        inventory_norm = inventory / self.max_inventory if self.max_inventory > 0 else inventory

        # Asymmetric per-side gammas; guard against div-by-zero on extreme multipliers
        g_yes  = max(effective_gamma * gamma_yes_mult, 1e-9)
        g_no   = max(effective_gamma * gamma_no_mult,  1e-9)

        # Separate reservation prices: each side responds to its own risk aversion
        r_yes = execution_mid - (inventory_norm * g_yes * (current_vol ** 2) * T)
        r_no  = execution_mid - (inventory_norm * g_no  * (current_vol ** 2) * T)

        _kappa = kappa_override if kappa_override is not None else self.kappa

        # Per-side half-spreads using the standard A-S formula
        _min_spread_cents = min_spread_override if min_spread_override is not None else float(self.config["minimum_spread_cents"])
        min_spread = _min_spread_cents / 100.0
        hs_yes = max(
            g_yes * (current_vol ** 2) * T + (1.0 / g_yes) * math.log(1.0 + g_yes / _kappa),
            min_spread / 2.0
        )
        hs_no = max(
            g_no  * (current_vol ** 2) * T + (1.0 / g_no)  * math.log(1.0 + g_no  / _kappa),
            min_spread / 2.0
        )
        actual_delta = (hs_yes + hs_no) / 2.0  # averaged for logging / downstream use

        logging.debug(
            f"Stoikov r_yes={r_yes:.4f} r_no={r_no:.4f} "
            f"g×yes={gamma_yes_mult:.2f} g×no={gamma_no_mult:.2f} inv_norm={inventory_norm:.4f}"
        )

        bid_cents = round((r_yes - hs_yes) * 100)
        ask_cents = round((r_no  + hs_no)  * 100)

        bid = max(1, min(98, bid_cents))
        ask = max(2, min(99, ask_cents))

        if bid >= ask:
            if inventory > 0:
                bid = max(1, ask - 1)
            elif inventory < 0:
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
                logging.warning(
                    f"Cancel timeout for {oid} - keeping in active tracker to prevent ghost doubling."
                )
                continue
            if isinstance(res, dict):
                if "order" in res:
                    self.active_order_ids.discard(oid)
                elif "error" in res:
                    err_code = res["error"].get("code", "")
                    if err_code == "not_found":
                        self.active_order_ids.discard(oid)
                    else:
                        logging.warning(
                            f"Cancel timeout for {oid} - keeping in active tracker to prevent ghost doubling."
                        )
                elif res.get("code") == "not_found":
                    self.active_order_ids.discard(oid)
                else:
                    # Empty dict (timeout/network) or unknown response - do NOT discard
                    logging.warning(
                        f"Cancel timeout for {oid} - keeping in active tracker to prevent ghost doubling."
                    )
            else:
                logging.warning(
                    f"Cancel timeout for {oid} - keeping in active tracker to prevent ghost doubling."
                )
        
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
                # FIXED: return_exceptions=True ensures a single 404 doesn't halt the entire ghost order sweep.
                await asyncio.gather(*cancel_tasks, return_exceptions=True)
        except Exception as e:
            logging.error(f"Ghost order sweep failed: {e}")

    async def execute_hybrid_exit(self, trigger: str):
        """Dual-routing exit on the NAKED (unbalanced) leg only.

        Locked pairs are SHIELDED — they will never be exited here; they settle
        at $1.00 payout via settle_locked_pairs() when the market closes.

        Defensive triggers → aggressive taker limit (inside spread).
        Offensive triggers → passive maker limit (at mid).
        """
        eid = self.event_id
        _, exit_side = self.get_unbalanced_leg(eid)
        locked = self.get_locked_pairs(eid)

        # === VAULT LOCK: recompute naked qty from raw inventory to prevent
        # exiting contracts that belong to locked guaranteed-arb pairs ===
        if exit_side == "yes":
            naked_qty = self.yes_inventory.get(eid, 0) - locked
        else:
            naked_qty = self.no_inventory.get(eid, 0) - locked

        if naked_qty <= 0:
            logging.warning(
                f"🛡️ VAULT LOCK: Attempted to exit {exit_side} but all contracts are locked "
                f"({locked} pair(s)). Aborting."
            )
            return

        if locked > 0:
            logging.info(
                f"[HOLD-TO-SETTLEMENT] Shield active on {locked} pair(s). "
                f"Only the naked {exit_side} leg ({naked_qty} contract(s)) is exposed."
            )

        # Cap the order quantity to the naked leg only
        qty = naked_qty

        # ANTI-SNIPE: purge resting quotes before routing the exit
        logging.info("🛡️ ANTI-SNIPE: Canceling all resting orders before hybrid exit.")
        try:
            await self.cancel_active_orders()
        except Exception as e:
            logging.error(f"Anti-Snipe cancellation failed: {e}")

        defensive_triggers = ["NO_ADD_TO_LOSER", "VOLATILITY_SHIELD",
                              "3_MIN_RIPCORD", "DEFENSIVE_VELOCITY",
                              "STOP_LOSS", "WS_BLACKOUT", "DISLOCATION_EJECT"]
        offensive_triggers = ["TRAILING_STOP", "CUSHION_GUARD", "TAKE_PROFIT"]

        self.last_taker_time = time.time()
        self.last_exit_reason = trigger

        raw_bid = float(self.live_exchange_bid or 0.0)
        raw_ask = float(self.live_exchange_ask or 0.0)
        bid_c   = raw_bid * 100.0 if raw_bid < 1.0 else raw_bid
        ask_c   = raw_ask * 100.0 if raw_ask < 1.0 else raw_ask

        if trigger in defensive_triggers:
            if exit_side == "yes":
                limit_price = max(1, math.floor(bid_c) - 2)
                order = {"action": "sell", "side": "yes", "count": int(qty), "type": "limit",
                         "yes_price": int(limit_price), "ticker": self.current_market,
                         "client_order_id": str(uuid.uuid4())}
            else:
                limit_price = max(1, math.floor(100.0 - bid_c) - 1)
                order = {"action": "sell", "side": "no", "count": int(qty), "type": "limit",
                         "no_price": int(limit_price), "ticker": self.current_market,
                         "client_order_id": str(uuid.uuid4())}
            logging.warning(
                f"🚨 DEFENSIVE EXIT ({trigger}): aggressive taker @ {limit_price}¢ "
                f"on {exit_side.upper()} naked leg ({qty} contract(s))."
            )

        elif trigger in offensive_triggers:
            mid_c = (bid_c + ask_c) / 2.0 if (bid_c > 0 and ask_c > 0) else (
                self.yes_cost_basis.get(eid, 50.0) if exit_side == "yes"
                else self.no_cost_basis.get(eid, 50.0)
            )
            if exit_side == "yes":
                limit_price = max(1, math.floor(mid_c))
                order = {"action": "sell", "side": "yes", "count": int(qty), "type": "limit",
                         "yes_price": int(limit_price), "ticker": self.current_market,
                         "client_order_id": str(uuid.uuid4())}
            else:
                limit_price = max(1, math.ceil(100.0 - mid_c))
                order = {"action": "sell", "side": "no", "count": int(qty), "type": "limit",
                         "no_price": int(limit_price), "ticker": self.current_market,
                         "client_order_id": str(uuid.uuid4())}
            logging.info(
                f"📈 OFFENSIVE EXIT ({trigger}): maker limit @ {limit_price}¢ "
                f"on {exit_side.upper()} naked leg ({qty} contract(s))."
            )

        else:
            logging.warning(f"execute_hybrid_exit: unknown trigger '{trigger}' — defensive fallback.")
            if exit_side == "yes":
                limit_price = max(1, math.floor(bid_c) - 2)
                order = {"action": "sell", "side": "yes", "count": int(qty), "type": "limit",
                         "yes_price": int(limit_price), "ticker": self.current_market,
                         "client_order_id": str(uuid.uuid4())}
            else:
                limit_price = max(1, math.floor(100.0 - bid_c) - 1)
                order = {"action": "sell", "side": "no", "count": int(qty), "type": "limit",
                         "no_price": int(limit_price), "ticker": self.current_market,
                         "client_order_id": str(uuid.uuid4())}
            self.pending_orders += 1
            try:
                res = await self.api.request("POST", "/portfolio/orders", body=order)
                if isinstance(res, dict) and "order" in res and "order_id" in res["order"]:
                    self.active_order_ids.add(res["order"]["order_id"])
                    self.resting_exit_price = limit_price
            finally:
                self.pending_orders -= 1
            return

        self.pending_orders += 1
        try:
            res = await self.api.request("POST", "/portfolio/orders", body=order)
            if isinstance(res, dict) and "order" in res and "order_id" in res["order"]:
                self.active_order_ids.add(res["order"]["order_id"])
                self.resting_exit_price = limit_price
        finally:
            self.pending_orders -= 1

    async def update_inventory_and_fills(self):
        res_fills = await self.api.request("GET", f"/portfolio/fills?ticker={self.current_market}")
        fills     = res_fills.get("fills", [])
        got_new_fill = False

        for fill in fills:
            trade_id = fill.get("trade_id")
            if trade_id and trade_id not in self.seen_trade_ids:
                self.seen_trade_ids.add(trade_id)
                action = fill.get("action")
                side   = fill.get("side")
                price  = fill.get("price")
                count  = int(float(fill.get("count") or fill.get("count_fp") or 1.0))

                eid = self.event_id
                if eid:
                    raw = price if price is not None else 50.0
                    fill_price_cents = raw * 100.0 if 0 < raw < 1.0 else float(raw)
                    is_buy = action == "buy"
                    is_taker = fill.get("is_taker", False)
                    invert_no = self.config.get('no_price_inversion', True)
                    if side == "no" and invert_no:
                        raw_fill = fill_price_cents
                        fill_price_cents = 100.0 - raw_fill
                        logging.info(
                            f"🔄 REST INVERSION: raw NO fill {raw_fill:.1f}¢ "
                            f"-> True Cost {fill_price_cents:.1f}¢"
                        )
                    # Snapshot BEFORE inventory mutation (mirrors WebSocket fill path for quarantine)
                    _locked_before = min(
                        self.yes_inventory.get(eid, 0),
                        self.no_inventory.get(eid, 0),
                    )
                    _active_yes_before = self._active_yes_cost(eid)
                    _active_no_before = self._active_no_cost(eid)
                    if side == "yes":
                        self._apply_fill_to_inventory(eid, count, fill_price_cents, is_buy, is_taker)
                    elif side == "no":
                        self._apply_no_fill_to_inventory(eid, count, fill_price_cents, is_buy, is_taker)
                    self._record_flight_log("FILL", {"side": side, "price": fill_price_cents, "qty": count})
                    if side in ("yes", "no"):
                        self._process_arb_fill_confirmation(
                            eid,
                            side,
                            fill_price_cents,
                            _locked_before,
                            _active_yes_before,
                            _active_no_before,
                        )
                    self.last_fill_time = time.time()

                eid      = self.event_id
                yes_inv  = self.yes_inventory.get(eid, 0) if eid else 0
                no_inv   = self.no_inventory.get(eid, 0)  if eid else 0
                locked   = min(yes_inv, no_inv)
                p_raw    = price or 0.0
                p_c      = p_raw * 100.0 if 0 < p_raw < 1.0 else float(p_raw)
                logging.info(
                    f"✅ REST FILL: {action.upper()} {count} {side.upper()} @ {p_c:.1f}¢ | "
                    f"Yes Inv: {yes_inv} | No Inv: {no_inv} | Locked: {locked}"
                )
                got_new_fill = True

        if got_new_fill:
            await self.cancel_active_orders()
            self.latest_ticker = self.current_market
            self.state_changed.set()

    async def _quote_consumer(self):
        """Consumes the latest state without blocking the WebSocket feed."""
        while self.is_running:
            await self.state_changed.wait()

            ticker_to_process = self.latest_ticker
            if not ticker_to_process:
                self.state_changed.clear()
                continue

            try:
                async with self.quote_lock:
                    self.state_changed.clear()
                    await self.evaluate_and_quote(ticker_to_process)
            except Exception as e:
                logging.error(f"Quote consumer error: {e}")

    async def evaluate_and_quote(self, ticker):
        # FIXED: Guard clause prevents the WS ticker from placing new quotes if the bot is shutting down.
        if not getattr(self, 'is_running', True):
            return

        # === 🔒 VAULT LOCK GUARD — no quoting or entries after daily target is hit ===
        if self.done_for_day:
            return

        try:
            # === CONFIG HOT-RELOAD ===
            # Re-reads config.yaml on every tick so hard_stop_naked_cents and other
            # thresholds can be tuned live without restarting the process.
            self.config = self._load_config()

            # === LOCAL INVENTORY SNAPSHOT (rebuilt every tick) ===
            eid       = self.event_id
            yes_inv   = self.yes_inventory.get(eid, 0) if eid else 0
            no_inv    = self.no_inventory.get(eid, 0)  if eid else 0
            locked    = min(yes_inv, no_inv)
            naked_yes = yes_inv - locked
            naked_no  = no_inv  - locked
            # net_inventory: positive = net YES naked, negative = net NO naked
            net_inventory = naked_yes - naked_no
            # canonical naked leg (used by Velocity Guillotine and VIX Filter)
            naked_qty, naked_side = self.get_unbalanced_leg(eid)

            # === 💀 GLOBAL DRAWDOWN KILL-SWITCH 💀 ===
            # If session PnL drops below -$20.00, flatten and terminate immediately.
            if self.daily_pnl_cents <= -2000:
                logging.critical(f"💀 GLOBAL DRAWDOWN LIMIT HIT! Daily PnL: ${self.daily_pnl_cents / 100:.2f}. Pulling the plug.")

                self.is_running = False
                naked_qty, _ = self.get_unbalanced_leg(eid)
                if naked_qty > 0:
                    logging.critical(f"🚨 KILL-SWITCH DUMP: Flattening naked leg ({naked_qty} contract(s)).")
                    try:
                        await self.execute_hybrid_exit("DEFENSIVE_VELOCITY")
                    except Exception as e:
                        logging.error(f"Kill-switch exit failed, dying anyway: {e}")

                # FIXED: Ensure PnL ledger is flushed to disk before emergency shutdown.
                self.save_daily_pnl()
                if getattr(self, 'quote_consumer_task', None) and not self.quote_consumer_task.done():
                    self.quote_consumer_task.cancel()
                raise CriticalDrawdownException(
                    f"Global drawdown limit hit. Daily PnL: ${self.daily_pnl_cents / 100:.2f}"
                )

            # === 💰 HIGH-WATER-MARK PROFIT LOCK 💰 ===
            # Once cumulative daily PnL crosses the daily target, lock the vault for the rest of the day.
            if not self.done_for_day and (self.daily_pnl_cents / 100.0) >= self.daily_profit_target:
                self.done_for_day = True
                banner = (
                    "\n" + "=" * 70 + "\n"
                    f"  💰💰💰  TARGET REACHED: +${self.daily_profit_target:.2f}  💰💰💰\n"
                    f"  Daily PnL: +${self.daily_pnl_cents / 100.0:.2f} — Locking vault and sleeping for the day.\n"
                    "=" * 70
                )
                print(banner)
                logging.info(banner)
                self.save_daily_pnl()
                await TelegramAlerts.send(
                    f"💰 TARGET REACHED: +${self.daily_pnl_cents / 100.0:.2f}\n"
                    f"Daily goal of ${self.daily_profit_target:.2f} achieved. Vault locked. No new trades today."
                )
                await self.cancel_active_orders()
                if net_inventory != 0:
                    logging.info(
                        f"🧹 VAULT FLATTEN: Exiting naked leg ({abs(net_inventory)} contract(s)) before locking."
                    )
                    await self.execute_hybrid_exit("DEFENSIVE_VELOCITY")
                return

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

            # current_mid / spread in fractional for velocity math
            raw_bid_f = float(self.live_exchange_bid or 0.0)
            raw_ask_f = float(self.live_exchange_ask or 0.0)
            if raw_bid_f == 0.0 or raw_ask_f == 0.0:
                return
            current_mid    = (raw_bid_f + raw_ask_f) / 2.0
            current_spread = raw_ask_f - raw_bid_f

            # === STATE READINESS GUARD (Cold-Start Protection) ===
            # If the cycle just reset, we must wait for the first WebSocket ticks 
            # to populate our baseline variables before attempting any velocity math.
            if self.prev_mid is None or self.live_exchange_bid is None or self.live_exchange_ask is None:
                self.prev_mid = current_mid  # Seed the baseline for the next tick
                logging.debug("⏳ Waiting for Oracle/Ticker synchronization on new cycle...")
                return

            if time.time() - self.last_price_history_update > 5.0:
                self.price_history.append(pure_mid)
                if len(self.price_history) > VOLATILITY_WINDOW:
                    self.price_history.pop(0)
                self.last_price_history_update = time.time()

            # === VELOCITY GUILLOTINE ===
            # Thresholds are night_mode-aware and hot-loaded from config.yaml.
            _night_mode   = bool(self.config.get('night_mode', False))
            _axe_ema      = float(self.config.get('axe_ema_night'   if _night_mode else 'axe_ema_day',    5.0 if _night_mode else 8.0))
            _axe_instant  = _axe_ema * 1.5   # instant threshold = 1.5× EMA threshold (5→7.5¢ / 8→12¢)
            _vix_base     = float(self.config.get('vix_night_threshold' if _night_mode else 'vix_day_threshold', 2.5 if _night_mode else 4.0))
            _max_spread   = float(self.config.get('max_spread_night' if _night_mode else 'max_spread_day',  0.12 if _night_mode else 0.08))
            # VIX threshold widens by 1.5¢ once a pair is locked (guaranteed settlement cushion)
            vix_threshold = _vix_base + (1.5 if locked >= 1 else 0.0)

            instant_vel = 0.0
            if self.prev_mid is not None:
                instant_vel      = (current_mid - self.prev_mid)
                self.velocity_ema = (0.85 * instant_vel) + (0.15 * self.velocity_ema)

                if naked_qty > 0:
                    is_adverse = (
                        (naked_side == 'yes' and (self.velocity_ema < -_axe_ema     or instant_vel < -_axe_instant)) or
                        (naked_side == 'no'  and (self.velocity_ema >  _axe_ema     or instant_vel >  _axe_instant))
                    )
                    if is_adverse:
                        logging.critical(
                            f"🪓 VELOCITY GUILLOTINE ({'NIGHT' if _night_mode else 'DAY'}): "
                            f"EMA {self.velocity_ema:.1f}¢ / Instant {instant_vel:.1f}¢ "
                            f"(threshold EMA={_axe_ema}¢ / instant={_axe_instant}¢). "
                            f"AXING {naked_side.upper()} leg."
                        )
                        self._record_flight_log("GUILLOTINE_DROP", {"reason": "velocity_or_gap_stop"})
                        self.prev_mid = current_mid
                        await self.execute_hybrid_exit("DEFENSIVE_VELOCITY")
                        return
            self.prev_mid = current_mid
            self.instant_velocity = instant_vel
            self._update_oracle_correlation(instant_vel)

            sniper_mode = (abs(instant_vel) > vix_threshold) or (current_spread > (_max_spread * 100.0))

## --- TP/SL: MUST run before throttle so panic exits are never delayed ---
            # Only the NAKED leg is evaluated. Locked pairs are SHIELDED.
            if (naked_yes > 0 or naked_no > 0) and (time.time() - self.last_taker_time) > 2.0:
                # === INSTANT GAP STOP-LOSS (pre-cooldown) ===
                # Fires before the 5s fill cooldown so a gap that opens immediately
                # after a fill is not suppressed. EMA Guillotine cannot catch this.
                _instant_gap_threshold = float(self.config.get('instant_gap_stop_cents', -15.0))
                if net_inventory > 0 and best_bid is not None:
                    _gap_pnl = (best_bid * 100.0) - self._active_yes_cost(eid)
                    if _gap_pnl <= _instant_gap_threshold:
                        logging.critical(
                            f"⚡ INSTANT GAP STOP: YES PnL {_gap_pnl:.1f}¢ <= {_instant_gap_threshold:.1f}¢. "
                            f"Bypassing fill cooldown. DEFENSIVE exit. "
                            f"[Yes Inv: {yes_inv} | No Inv: {no_inv} | Locked: {locked}]"
                        )
                        self._record_flight_log("GUILLOTINE_DROP", {"reason": "velocity_or_gap_stop"})
                        await self.execute_hybrid_exit("STOP_LOSS")
                        return
                elif net_inventory < 0 and best_ask is not None:
                    _gap_pnl = (100.0 - best_ask * 100.0) - self._active_no_cost(eid)
                    if _gap_pnl <= _instant_gap_threshold:
                        logging.critical(
                            f"⚡ INSTANT GAP STOP: NO PnL {_gap_pnl:.1f}¢ <= {_instant_gap_threshold:.1f}¢. "
                            f"Bypassing fill cooldown. DEFENSIVE exit. "
                            f"[Yes Inv: {yes_inv} | No Inv: {no_inv} | Locked: {locked}]"
                        )
                        self._record_flight_log("GUILLOTINE_DROP", {"reason": "velocity_or_gap_stop"})
                        await self.execute_hybrid_exit("STOP_LOSS")
                        return

                if time.time() - self.last_fill_time < 5.0:
                    return

                TAKE_PROFIT = 80.0
                stop_loss   = float(self.config.get("STOP_LOSS", -30.0))
                if naked_yes > 0:
                    exit_price_cents = best_bid * 100.0 if best_bid else 0.0
                    yes_cost = self._active_yes_cost(eid)
                    unrealized_pnl_cents = exit_price_cents - yes_cost
                else:  # naked_no > 0
                    current_yes_exit      = best_ask * 100.0 if best_ask else 0.0
                    current_no_exit_price = 100.0 - current_yes_exit
                    no_cost = self._active_no_cost(eid)
                    unrealized_pnl_cents = current_no_exit_price - no_cost
                    logging.debug(
                        f"DEBUG NO PnL: no_cost={no_cost:.1f}¢ | "
                        f"yes_ask={current_yes_exit:.1f}¢ | "
                        f"no_exit={current_no_exit_price:.1f}¢ | "
                        f"true_pnl={unrealized_pnl_cents:.1f}¢ | "
                        f"Yes Inv: {yes_inv} | No Inv: {no_inv} | Locked: {locked}"
                    )


                pnl = unrealized_pnl_cents

                # === 5-MINUTE HOUSE MONEY RULE (LOCKED PAIRS ONLY) ===
                # Inside the final 5 minutes, locked pairs are held to $1.00 settlement.
                # Naked legs are NEVER suppressed here — they flow through to Dynamic
                # Scalp, Dislocation Ejector, and Trailing Stop as normal.
                if time_left <= 300.0:
                    if locked > 0:
                        logging.info(
                            f"🏠 HOUSE MONEY MODE: {time_left:.0f}s to expiry. "
                            f"Holding {locked} locked pair(s) to settlement. "
                            f"Naked legs still active. "
                            f"[Yes Inv: {yes_inv} | No Inv: {no_inv} | Locked: {locked}]"
                        )
                        # Do NOT return — naked legs must continue to Dynamic Scalp /
                        # Dislocation Ejector / Trailing Stop logic below.
                    else:
                        # No locked pairs — full active management for naked legs.
                        pass
                    # Naked legs always flow through to the rest of TP/SL logic.

                # === BASIS DISLOCATION EJECTOR ===
                # Fires after House Money (so settlement-holders are protected) and
                # before the fill cooldown. Exits the naked leg when the perp basis
                # dislocates hard against our position — a leading indicator of
                # adverse flow that the Kalshi price hasn't fully repriced yet.
                _basis_shift = getattr(self, 'basis_shift', 0.0)
                DISLOCATION_THRESHOLD = float(self.config.get('dislocation_threshold_cents', 2.5))
                _dislocation_cd = max(30.0, float(self.config.get('light_cooldown_seconds', 5)))
                if (time.time() - getattr(self, 'last_dislocation_time', 0.0)) > _dislocation_cd:
                    if naked_yes > 0 and _basis_shift < -DISLOCATION_THRESHOLD:
                        logging.warning(
                            f"🪂 BASIS DISLOCATION EJECTOR: Basis Shift {_basis_shift:.2f} "
                            f"against YES leg. Bailing early. "
                            f"[Yes Inv: {yes_inv} | No Inv: {no_inv} | Locked: {locked}]"
                        )
                        self.last_dislocation_time = time.time()
                        await self.execute_hybrid_exit("DISLOCATION_EJECT")
                        return
                    elif naked_no > 0 and _basis_shift > DISLOCATION_THRESHOLD:
                        logging.warning(
                            f"🪂 BASIS DISLOCATION EJECTOR: Basis Shift {_basis_shift:.2f} "
                            f"against NO leg. Bailing early. "
                            f"[Yes Inv: {yes_inv} | No Inv: {no_inv} | Locked: {locked}]"
                        )
                        self.last_dislocation_time = time.time()
                        await self.execute_hybrid_exit("DISLOCATION_EJECT")
                        return

                # === RESET TRACKERS WHEN NAKED LEG IS FLAT ===
                if net_inventory == 0:
                    self.peak_pnl = -999.0
                    self.trailing_stop_active = False

                # === DYNAMIC TRAILING STOP (The Ratchet) v7.5 ===
                if net_inventory != 0:
                    if not hasattr(self, 'peak_pnl'):
                        self.peak_pnl = -999.0
                        self.trailing_stop_active = False

                    if unrealized_pnl_cents > self.peak_pnl:
                        self.peak_pnl = unrealized_pnl_cents

                    if not self.trailing_stop_active and self.peak_pnl >= 15.0:
                        self.trailing_stop_active = True
                        logging.info(
                            f"🚀 TRAIL ACTIVATED: Peak PnL +{self.peak_pnl:.1f}¢. Breakeven+ locked. "
                            f"[Yes Inv: {yes_inv} | No Inv: {no_inv} | Locked: {locked}]"
                        )

                    if self.trailing_stop_active:
                        trail_floor = max(2.0, self.peak_pnl - 8.0)
                        if unrealized_pnl_cents <= trail_floor:
                            # Fee-aware: block micro-scalp exits (< 2¢ gross)
                            MIN_PROFIT_CENTS = 2.0
                            if 0 < unrealized_pnl_cents < MIN_PROFIT_CENTS:
                                logging.debug(
                                    f"🛑 Blocking micro-scalp. Gross PnL {unrealized_pnl_cents:.1f}¢ < {MIN_PROFIT_CENTS}¢ fee floor."
                                )
                            else:
                                logging.warning(
                                    f"🚨 TRAILING STOP | PnL: {unrealized_pnl_cents:.1f}¢ | "
                                    f"Peak: +{self.peak_pnl:.1f}¢ | "
                                    f"Yes Inv: {yes_inv} | No Inv: {no_inv} | Locked: {locked}"
                                )
                                self.peak_pnl = -999.0
                                self.trailing_stop_active = False
                                await self.execute_hybrid_exit("TRAILING_STOP")
                                return

                naked_qty = abs(net_inventory)
                # === +4.0¢ PARTIAL SCALP ===
                # Fires before the full TP/SL check. If PnL >= scalp threshold and we
                # hold > 1 naked contract, exit exactly ceil(naked/2) contracts via an
                # aggressive taker limit (1¢ inside best bid/ask).
                # Locks in gains while keeping a runner for further upside.
                # 30s cooldown prevents re-firing on the same price level.
                # === DYNAMIC SCALP THRESHOLD (Pillar 3) ===
                # When Oracle confirms we are holding WITH the trend, let runners run
                # by doubling the scalp threshold. In flat/ranging markets, default
                # back to the config value so we still harvest spread edge.
                _scalp_thresh_base = float(self.config.get('partial_scalp_cents', 4.0))
                _trend_scalp_cents = float(self.config.get('trend_scalp_cents', 8.0))
                _basis_ema_safe    = getattr(self, 'basis_ema', 0.0)

                _holding_with_bull = (naked_yes > 0 and _basis_ema_safe > 0.8)
                _holding_with_bear = (naked_no  > 0 and _basis_ema_safe < -0.8)

                if _holding_with_bull or _holding_with_bear:
                    _scalp_thresh = _trend_scalp_cents
                    logging.debug(
                        f"🏃 DYNAMIC SCALP: Trend confirmed (basis_ema={_basis_ema_safe:.2f}). "
                        f"Scalp threshold raised to {_scalp_thresh:.1f}¢."
                    )
                else:
                    _scalp_thresh = _scalp_thresh_base

                _scalp_cooldown = float(self.config.get('partial_scalp_cooldown_seconds', 30.0))
                _last_scalp     = getattr(self, 'last_partial_scalp_time', 0.0)
                if (pnl >= _scalp_thresh
                        and naked_qty > 1
                        and (time.time() - _last_scalp) > _scalp_cooldown):
                    _sc_exit_count = math.ceil(naked_qty / 2)
                    _sc_bid_c = best_bid * 100.0 if best_bid else 0.0
                    _sc_ask_c = best_ask * 100.0 if best_ask else 0.0
                    if naked_yes > 0:
                        _sc_price = max(1, math.floor(_sc_bid_c) - 1)
                        _sc_order = {
                            "action": "sell", "side": "yes",
                            "count": int(_sc_exit_count), "type": "limit",
                            "yes_price": int(_sc_price),
                            "ticker": self.current_market,
                            "client_order_id": str(uuid.uuid4())
                        }
                    else:  # naked_no
                        _sc_no_bid = 100.0 - _sc_ask_c
                        _sc_price  = max(1, math.floor(_sc_no_bid) - 1)
                        _sc_order  = {
                            "action": "sell", "side": "no",
                            "count": int(_sc_exit_count), "type": "limit",
                            "no_price": int(_sc_price),
                            "ticker": self.current_market,
                            "client_order_id": str(uuid.uuid4())
                        }
                    logging.info(
                        f"✂️ PARTIAL SCALP: PnL +{pnl:.1f}¢ >= +{_scalp_thresh:.1f}¢. "
                        f"Taker-exiting {_sc_exit_count}/{naked_qty} contract(s) @ {_sc_price}¢. "
                        f"[Yes Inv: {yes_inv} | No Inv: {no_inv} | Locked: {locked}]"
                    )
                    self.last_partial_scalp_time = time.time()
                    self.last_taker_time = time.time()
                    await self.cancel_active_orders()
                    self.pending_orders += 1
                    try:
                        _sc_res = await self.api.request("POST", "/portfolio/orders", body=_sc_order)
                        if isinstance(_sc_res, dict) and "order" in _sc_res and "order_id" in _sc_res["order"]:
                            self.active_order_ids.add(_sc_res["order"]["order_id"])
                    finally:
                        self.pending_orders -= 1
                    return

                if naked_yes > 0:
                    MIN_PROFIT_CENTS = 2.0
                    if 0 < pnl < MIN_PROFIT_CENTS:
                        logging.debug(
                            f"🛑 Blocking micro-scalp. Gross PnL {pnl:.1f}¢ < {MIN_PROFIT_CENTS}¢ fee floor."
                        )
                    elif pnl >= TAKE_PROFIT:
                        await self.execute_hybrid_exit("TAKE_PROFIT")
                        return
                    elif pnl <= stop_loss:
                        await self.execute_hybrid_exit("STOP_LOSS")
                        return
                else:  # naked_no > 0
                    live_spread = (
                        (self.live_exchange_ask - self.live_exchange_bid)
                        if (self.live_exchange_ask and self.live_exchange_bid) else 0
                    )
                    effective_tp = 15.0 if live_spread > 8 else TAKE_PROFIT
                    MIN_PROFIT_CENTS = 2.0
                    if 0 < pnl < MIN_PROFIT_CENTS:
                        logging.debug(
                            f"🛑 Blocking micro-scalp. Gross PnL {pnl:.1f}¢ < {MIN_PROFIT_CENTS}¢ fee floor."
                        )
                    elif pnl >= effective_tp:
                        await self.execute_hybrid_exit("TAKE_PROFIT")
                        return
                    elif pnl <= stop_loss:
                        await self.execute_hybrid_exit("STOP_LOSS")
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
            allow_buy_no  = True
            alpha_skew    = 0.0

            # === MARKET VIABILITY GATE ===
            _raw_ask = float(self.live_exchange_ask or 0.0)
            _raw_bid = float(self.live_exchange_bid or 0.0)
            _safe_ask_cents = _raw_ask * 100.0 if _raw_ask < 1.0 else _raw_ask
            _safe_bid_cents = _raw_bid * 100.0 if _raw_bid < 1.0 else _raw_bid
            _mid_c = (_safe_ask_cents + _safe_bid_cents) / 2.0 if (_safe_ask_cents and _safe_bid_cents) else pure_mid * 100.0
            _spread_c = _safe_ask_cents - _safe_bid_cents if (_safe_ask_cents and _safe_bid_cents) else 0.0
            _viable, _viability_reason = self._is_market_viable(_mid_c, time_left, _spread_c)
            if not _viable and naked_qty == 0:
                logging.debug(f"🚫 MARKET NOT VIABLE: {_viability_reason}. Skipping entry.")
                if self.resting_bid is not None or self.resting_ask is not None:
                    await self.cancel_active_orders()
                return
            elif not _viable and naked_qty > 0:
                allow_buy_yes = False
                allow_buy_no  = False
                logging.debug(f"🚫 MARKET NOT VIABLE: {_viability_reason}. Blocking new entries, managing existing.")

            # === 90-SECOND BLINDFOLD (Pillar 5) ===
            # The first 90s of a 15-min contract (>810s remaining) is toxic price
            # discovery. Block all NEW naked directional entries until the market
            # stabilises. Arb Kill Shots (pair-locking) are explicitly exempt and
            # will still fire normally further down this function.
            if time_left > 810.0:
                allow_buy_yes = False
                allow_buy_no  = False
                logging.debug(
                    f"🙈 BLINDFOLD ACTIVE: {time_left:.0f}s remaining (> 810s). "
                    f"Blocking new naked entries during toxic discovery window."
                )

            # === VIX FILTER (SNIPER MODE) ===
            # Block NEW naked entries during high-velocity spikes or wide spreads.
            # Existing naked positions continue — they proceed to quote the exit.
            if sniper_mode and naked_qty == 0:
                logging.warning(
                    f"🎯 SNIPER MODE ({'NIGHT' if _night_mode else 'DAY'}): "
                    f"Instant vel {instant_vel:.1f}¢ / spread {current_spread:.3f} "
                    f"(vix_thresh={vix_threshold:.1f}¢, max_spread={_max_spread:.2f}). "
                    f"Banning naked entry."
                )
                return

            # Fetch live alpha metrics
            price_delta = 0.0
            if self.live_eth_price and len(self.eth_price_history) > 10:
                # INTENTIONAL: Uses [0] (oldest tick) to measure slow-trend directional momentum over the full 60-tick window. Do not change to [-2].
                past_price  = self.eth_price_history[0]
                price_delta = self.live_eth_price - past_price

            # Update state
            self.binance_delta = price_delta

            # Use cached WS book (no REST calls)
            if hasattr(self, 'current_orderbook') and self.current_orderbook:
                bids = self.current_orderbook.get('bids', [])
                asks = self.current_orderbook.get('asks', [])
                self.kalshi_book = {'bids': bids[:3], 'asks': asks[:3]}
            else:
                self.kalshi_book = {'bids': [], 'asks': []}

            # === PRE-EMPTIVE PULL ===
            pull = self.should_preemptive_pull(self.live_eth_price)
            if pull and self.active_order_ids:
                logging.warning("🚨 PRE-EMPTIVE PULL")
                await self.cancel_active_orders()
                return

            current_delta = self.binance_delta
            current_shift = getattr(self, 'basis_shift', 0.0)

            # === ASYMMETRIC MAKER PROTECTION v8.0 ===
            if current_delta > 20 and current_shift > 2.0:
                allow_buy_no = False
                alpha_skew   = 0.03
                logging.info("📈 MAKER SKEW: Bull Squeeze detected. Pulled NO quote, pushing YES Bid.")
            elif current_delta < -20 and current_shift < -2.0:
                allow_buy_yes = False
                alpha_skew    = -0.03
                logging.info("📉 MAKER SKEW: Bear Squeeze detected. Pulled YES quote, pushing NO Ask.")
            elif abs(current_delta) > self.config["delta_volatility_shield"]:
                allow_buy_yes = False
                allow_buy_no  = False
                logging.warning(f"☢️ VOLATILITY SHIELD: Delta {current_delta:.1f} too violent. Pausing Maker quotes.")

            if time_left < 300 and current_delta < -20:
                allow_buy_no = False

            # === CONDITIONAL ORACLE SUPPRESSION (Pillar 4) ===
            # When Oracle signals strongly agree on trend direction, suppress the
            # opposing quote entirely. Posting both sides hands a free ATM option
            # to any informed flow. Existing q0 choke is preserved — this only
            # affects whether we post a resting limit on the losing side.
            _suppress_threshold_delta = float(self.config.get('suppress_delta_threshold', 1.5))
            _suppress_threshold_basis = float(self.config.get('suppress_basis_threshold', 0.20))

            suppress_yes_ask = (
                current_delta > _suppress_threshold_delta
                and current_shift > _suppress_threshold_basis
            )
            suppress_no_ask = (
                current_delta < -_suppress_threshold_delta
                and current_shift < -_suppress_threshold_basis
            )

            if suppress_yes_ask:
                allow_buy_no = False
                if allow_buy_no:
                    logging.debug(
                        f"🔇 ORACLE SUPPRESS: Strong bull signal (Δ={current_delta:.2f}, "
                        f"basis={current_shift:.2f}) — suppressing NO ask to avoid ATM gift."
                    )
            if suppress_no_ask:
                allow_buy_yes = False
                if allow_buy_yes:
                    logging.debug(
                        f"🔇 ORACLE SUPPRESS: Strong bear signal (Δ={current_delta:.2f}, "
                        f"basis={current_shift:.2f}) — suppressing YES bid to avoid ATM gift."
                    )

            # === NO ADD TO LOSER — acts on the naked leg only (binance_delta = source of truth) ===
            if net_inventory != 0:
                if naked_yes > 0 and self.binance_delta < -20:
                    logging.info(
                        f"🚫 NO ADD TO LOSER: bearish momentum vs naked YES "
                        f"(Yes Inv: {yes_inv} | No Inv: {no_inv} | Locked: {locked} | delta={self.binance_delta:.1f})"
                    )
                    allow_buy_yes = False
                elif naked_no > 0 and self.binance_delta > 20:
                    logging.info(
                        f"🚫 NO ADD TO LOSER: bullish momentum vs naked NO "
                        f"(Yes Inv: {yes_inv} | No Inv: {no_inv} | Locked: {locked} | delta={self.binance_delta:.1f})"
                    )
                    allow_buy_no = False

            # Cap total YES / NO inventory — respects per-tick vacuum choke
            effective_max_naked = getattr(self, '_tick_max_naked', getattr(self, 'max_inventory', 10))
            if yes_inv >= effective_max_naked:
                allow_buy_yes = False
            if no_inv >= effective_max_naked:
                allow_buy_no = False

            # === PRICE-BASED DEAD ZONE REMOVED (v7.6) ===
            # Risk/Reward Ceiling + Cushion Guard + Trailing Stop handle over-extension.

            # === PERP BASIS CALCULATION ===
            safe_futures = float(getattr(self, 'futures_price', 0.0) or 0.0)
            safe_spot = float(self.live_eth_price or 0.0)

            if safe_futures > 0 and safe_spot > 0:
                self.perp_basis = safe_futures - safe_spot
            else:
                self.perp_basis = 0.0

            # === PREDICTIVE ALPHA: EMA SHIFT v7.8 ===
            # Initialize EMA if missing
            if not hasattr(self, 'basis_ema'):
                self.basis_ema = self.perp_basis
            else:
                # Fast EMA (alpha=0.2) to track the moving baseline
                self.basis_ema = (self.perp_basis * 0.2) + (self.basis_ema * 0.8)

            # Calculate how violently the Basis is breaking away from its baseline
            self.basis_shift = self.perp_basis - self.basis_ema

            # === BASIS-SHIFT VELOCITY PRE-SHIELD ===
            self.basis_velocity = abs(self.basis_shift - self.previous_basis_shift)
            self.previous_basis_shift = self.basis_shift

            if self.basis_velocity > self.config["basis_velocity_shield"]:
                logging.warning(f"☢️ PRE-SHIELD ACTIVATED: Basis Velocity {self.basis_velocity:.2f} too violent. Pausing entries.")
                allow_buy_yes = False
                allow_buy_no = False
                if net_inventory != 0:
                    await self.execute_hybrid_exit("DEFENSIVE_VELOCITY")
                    return

            # === SYSTEM HEARTBEAT ===
            _hb_now = time.time()
            if _hb_now - getattr(self, 'last_heartbeat_time', 0) >= 10.0:
                pull = self.should_preemptive_pull(self.live_eth_price)
                if pull and self.active_order_ids:
                    logging.warning("🚨 PRE-EMPTIVE PULL (heartbeat)")
                    await self.cancel_active_orders()
                    return
                _hb_ask = self.live_exchange_ask if self.live_exchange_ask is not None else 0.0
                _hb_bid = self.live_exchange_bid if self.live_exchange_bid is not None else 0.0
                _hb_ask_c = (_hb_ask * 100.0) if _hb_ask < 1.0 else _hb_ask
                _hb_bid_c = (_hb_bid * 100.0) if _hb_bid < 1.0 else _hb_bid
                _hb_mid = (_hb_bid_c + _hb_ask_c) / 2.0 if (_hb_ask_c > 0 and _hb_bid_c > 0) else getattr(self, 'current_mid_price', 0.0) * 100.0
                logging.info(
                    f"📡 HEARTBEAT | Mid: {_hb_mid:.1f}¢ | "
                    f"Binance Delta: {self.binance_delta:.1f} | "
                    f"Basis Shift: {getattr(self, 'basis_shift', 0.0):+.2f} | "
                    f"Yes Inv: {yes_inv} | No Inv: {no_inv} | Locked: {locked}"
                )
                self.last_heartbeat_time = _hb_now
                self._log_pnl_breakdown()

            # === PURE ARB SCANNER ===
            # Fires BEFORE the single-leg Kill Shot / Guillotine / Cushion Guard.
            # Buys both YES and NO simultaneously when the spread collapses below
            # pure_arb_threshold, locking an instant guaranteed-settlement pair.
            if eid:
                _pa_raw_ask = float(self.live_exchange_ask or 0.0)
                _pa_raw_bid = float(self.live_exchange_bid or 0.0)
                _pa_ask_c   = _pa_raw_ask * 100.0 if _pa_raw_ask < 1.0 else _pa_raw_ask
                _pa_bid_c   = _pa_raw_bid * 100.0 if _pa_raw_bid < 1.0 else _pa_raw_bid

                if _pa_ask_c > 0 and _pa_bid_c > 0:
                    pure_arb_threshold = float(self.config.get("PURE_ARB_THRESHOLD_CENTS", self.config.get("pure_arb_threshold_cents", 98.0)))
                    max_locked         = int(self.config.get('max_locked_pairs', 5))
                    total_pure_cost    = _pa_ask_c + (100.0 - _pa_bid_c)

                    if total_pure_cost <= pure_arb_threshold and locked + 2 <= max_locked:
                        _pa_yes_price = max(1, min(99, int(round(_pa_ask_c))))
                        _pa_no_price  = max(1, min(99, int(round(100.0 - _pa_bid_c))))
                        logging.warning(
                            f"🚀 PURE ARB SCANNER: Double-leg lock detected at "
                            f"{total_pure_cost:.1f}¢ (YES@{_pa_yes_price}¢ + NO@{_pa_no_price}¢ = {_pa_yes_price + _pa_no_price}¢). "
                            f"Firing 2x simultaneous sweep. "
                            f"[Yes Inv: {yes_inv} | No Inv: {no_inv} | Locked: {locked}]"
                        )
                        _pa_yes_order = {
                            "action": "buy", "side": "yes", "count": int(2),
                            "type": "limit", "yes_price": int(_pa_yes_price),
                            "ticker": self.current_market,
                            "client_order_id": str(uuid.uuid4())
                        }
                        _pa_no_order = {
                            "action": "buy", "side": "no", "count": int(2),
                            "type": "limit", "no_price": int(_pa_no_price),
                            "ticker": self.current_market,
                            "client_order_id": str(uuid.uuid4())
                        }
                        self.pending_orders += 2
                        try:
                            _pa_yes_res, _pa_no_res = await asyncio.gather(
                                self.api.request("POST", "/portfolio/orders", body=_pa_yes_order),
                                self.api.request("POST", "/portfolio/orders", body=_pa_no_order),
                                return_exceptions=True
                            )
                        finally:
                            self.pending_orders -= 2
                        for _pa_res in (_pa_yes_res, _pa_no_res):
                            if isinstance(_pa_res, dict) and "order" in _pa_res and "order_id" in _pa_res["order"]:
                                self.active_order_ids.add(_pa_res["order"]["order_id"])
                        self.last_lock_time = time.time()
                        logging.info("🔒 VAULT LOCK SECURED. Initiating 60s Lock & Walk naked ban.")
                        return  # Fill handler re-triggers quoting; pair routes to settlement

            # === SMART SECOND-LEG TRIGGER (THE KILL SHOT) ===
            # When holding a naked leg, aggressively buy the opposite side if the
            # combined pair cost ≤ pair_lock_threshold AND momentum confirms the trade.
            if eid and locked < self.max_locked_pairs:
                raw_ask_ks = float(self.live_exchange_ask or 0.0)
                raw_bid_ks = float(self.live_exchange_bid or 0.0)
                ask_c_ks   = raw_ask_ks * 100.0 if raw_ask_ks < 1.0 else raw_ask_ks
                bid_c_ks   = raw_bid_ks * 100.0 if raw_bid_ks < 1.0 else raw_bid_ks

                if naked_yes > 0:
                    # Holding naked YES — try to buy NO to lock
                    no_ask_c = 100.0 - bid_c_ks  # NO ask = 100 - YES bid
                    yes_cost = self.yes_cost_basis.get(eid, 0.0)
                    pair_cost_frac = (yes_cost + no_ask_c) / 100.0
                    # Momentum must be bullish (confirms our YES position)
                    if (pair_cost_frac <= self.pair_lock_threshold
                            and no_ask_c > 0
                            and current_delta > 0):
                        lock_qty = min(naked_yes, self.max_locked_pairs - locked)
                        if lock_qty > 0:
                            # Marketable limit: max we will pay for NO so the pair still clears threshold
                            max_price_cents = int((self.pair_lock_threshold * 100.0) - yes_cost)
                            no_price = max(1, min(99, max_price_cents))
                            logging.info(f"⚡ MARKETABLE LIMIT KILL SHOT: Sweeping book up to {no_price}¢ to lock pair.")
                            ks_order = {
                                "action": "buy", "side": "no", "count": int(lock_qty),
                                "type": "limit", "no_price": int(no_price),
                                "ticker": self.current_market,
                                "client_order_id": str(uuid.uuid4())
                            }
                            self.pending_orders += 1
                            try:
                                ks_res = await self.api.request("POST", "/portfolio/orders", body=ks_order)
                                if isinstance(ks_res, dict) and "order" in ks_res and "order_id" in ks_res["order"]:
                                    self.active_order_ids.add(ks_res["order"]["order_id"])
                                logging.info(
                                    f"🎯 KILL SHOT: Locking {lock_qty} pair(s) | "
                                    f"YES cost: {yes_cost:.1f}¢ + NO limit: {no_price}¢ "
                                    f"= {yes_cost + no_price:.1f}¢ "
                                    f"(≤{self.pair_lock_threshold*100:.0f}¢) | "
                                    f"Delta: {current_delta:.1f} | "
                                    f"Yes Inv: {yes_inv} | No Inv: {no_inv} | Locked: {locked}"
                                )
                                self.last_lock_time = time.time()
                                logging.info("🔒 VAULT LOCK SECURED. Initiating 60s Lock & Walk naked ban.")
                            finally:
                                self.pending_orders -= 1
                            return  # Let fill handler re-trigger quoting

                elif naked_no > 0:
                    # Holding naked NO — try to buy YES to lock
                    yes_ask_c = ask_c_ks
                    no_cost   = self.no_cost_basis.get(eid, 0.0)
                    pair_cost_frac = (no_cost + yes_ask_c) / 100.0
                    # Momentum must be bearish (confirms our NO position)
                    if (pair_cost_frac <= self.pair_lock_threshold
                            and yes_ask_c > 0
                            and current_delta < 0):
                        lock_qty = min(naked_no, self.max_locked_pairs - locked)
                        if lock_qty > 0:
                            # Marketable limit: max we will pay for YES so the pair still clears threshold
                            max_price_cents = int((self.pair_lock_threshold * 100.0) - no_cost)
                            yes_price = max(1, min(99, max_price_cents))
                            logging.info(f"⚡ MARKETABLE LIMIT KILL SHOT: Sweeping book up to {yes_price}¢ to lock pair.")
                            ks_order = {
                                "action": "buy", "side": "yes", "count": int(lock_qty),
                                "type": "limit", "yes_price": int(yes_price),
                                "ticker": self.current_market,
                                "client_order_id": str(uuid.uuid4())
                            }
                            self.pending_orders += 1
                            try:
                                ks_res = await self.api.request("POST", "/portfolio/orders", body=ks_order)
                                if isinstance(ks_res, dict) and "order" in ks_res and "order_id" in ks_res["order"]:
                                    self.active_order_ids.add(ks_res["order"]["order_id"])
                                logging.info(
                                    f"🎯 KILL SHOT: Locking {lock_qty} pair(s) | "
                                    f"NO cost: {no_cost:.1f}¢ + YES limit: {yes_price}¢ "
                                    f"= {no_cost + yes_price:.1f}¢ "
                                    f"(≤{self.pair_lock_threshold*100:.0f}¢) | "
                                    f"Delta: {current_delta:.1f} | "
                                    f"Yes Inv: {yes_inv} | No Inv: {no_inv} | Locked: {locked}"
                                )
                                self.last_lock_time = time.time()
                                logging.info("🔒 VAULT LOCK SECURED. Initiating 60s Lock & Walk naked ban.")
                            finally:
                                self.pending_orders -= 1
                            return  # Let fill handler re-trigger quoting

            # === TAKER CONVICTION FILTER REMOVED (v8.0) ===
            # Maker Skew + Dynamic Ceiling handle all entry gating natively.

            # Define ask_val / bid_val for downstream blocks that reference them (POST-TP LOCKOUT)
            ask_val = float(self.live_exchange_ask or 0.0)
            bid_val = float(self.live_exchange_bid or 0.0)
            if ask_val >= 1.0: ask_val /= 100.0
            if bid_val >= 1.0: bid_val /= 100.0

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

            # === DYNAMIC RISK/REWARD CEILING v7.7.1 (Bugfix) ===
            # binance_delta is source of truth for all entry/ceiling logic
            abs_momentum = abs(self.binance_delta)
            base_ceiling = getattr(self, 'no_chase_ceiling_cents', 92.0)

            if abs_momentum > 115:
                max_premium = min(99.0, base_ceiling + 8.0)
            elif abs_momentum > 80:
                max_premium = min(99.0, base_ceiling + 4.0)
            else:
                max_premium = base_ceiling

            # Precision-safe cents extraction (Strictly Floats, NO int truncation)
            raw_ask = float(self.live_exchange_ask or 0.0)
            raw_bid = float(self.live_exchange_bid or 0.0)

            safe_ask_cents = raw_ask * 100.0 if raw_ask < 1.0 else raw_ask
            safe_bid_cents = raw_bid * 100.0 if raw_bid < 1.0 else raw_bid

            if allow_buy_yes and safe_ask_cents > max_premium:
                allow_buy_yes = False
                logging.info(f"🛑 NO CHASE GUARD: YES costs {safe_ask_cents:.1f}¢ (Ceiling: {max_premium}¢ @ {abs_momentum:.1f} delta). Risk/Reward too poor.")

            if allow_buy_no:
                no_cost_cents = 100.0 - safe_bid_cents
                if no_cost_cents > max_premium:
                    allow_buy_no = False
                    logging.info(f"🛑 NO CHASE GUARD: NO costs {no_cost_cents:.1f}¢ (Ceiling: {max_premium}¢ @ {abs_momentum:.1f} delta). Risk/Reward too poor.")

            # === DYNAMIC SKEW SCALING (A-S Parameters) ===
            # Scale skew aggression using Avellaneda-Stoikov γ and σ²
            _current_vol = self.get_dynamic_volatility()
            _sigma_sq = _current_vol ** 2
            _dynamic_skew_aggression = (
                self.config["base_skew_multiplier"]
                * (1 + (self.basis_velocity / 10.0))
                * self.config["risk_aversion_gamma"]
                * _sigma_sq
            )

            _bull_squeeze = current_delta > 20 and current_shift > 2.0
            _bear_squeeze = current_delta < -20 and current_shift < -2.0

            if _bull_squeeze:
                alpha_skew += _dynamic_skew_aggression
            elif _bear_squeeze:
                alpha_skew -= _dynamic_skew_aggression

            # Apply Alpha Skew to the pure mid to shift the Stoikov reservation price
            execution_mid = min(0.99, max(0.01, pure_mid + alpha_skew))
            if execution_mid > 0.90 or execution_mid < 0.10:
                if self.resting_bid is not None or self.resting_ask is not None:
                    await self.cancel_active_orders()
                return

            current_vol = self.get_dynamic_volatility()
            T = max(0.001, time_left / 900.0)

            _basis_ema_safe    = getattr(self, 'basis_ema', 0.0)
            _ofi_q0_influence  = float(self.config.get('ofi_q0_influence', 1.0))
            dynamic_q0 = (
                0 if time_left < 180
                else max(-2, min(2, int(
                    (_basis_ema_safe / 2.0) + (self.ofi_scalar * _ofi_q0_influence)
                )))
            )

            # === ORACLE-Q0 ALIGNMENT GATE ===
            # Prevents dynamic_q0 from pulling inventory targets against the Oracle
            # Suppression direction, which would cause noisy conflicting quotes.
            # If Oracle is suppressing NO (bullish), q0 must not go bearish (< 0).
            # If Oracle is suppressing YES (bearish), q0 must not go bullish (> 0).
            if not allow_buy_no:
                dynamic_q0 = max(0, dynamic_q0)
            if not allow_buy_yes:
                dynamic_q0 = min(0, dynamic_q0)

            _q0_adjusted_inventory = max(
                -self.max_inventory,
                min(self.max_inventory, net_inventory - dynamic_q0)
            )

            current_spread_cents = safe_ask_cents - safe_bid_cents
            dynamic_kappa = self.get_adaptive_kappa(current_spread_cents)
            # === MOMENTUM-AUGMENTED ASYMMETRIC STOIKOV ===
            # 🐺 SENIOR QUANT OVERRIDE: FULLY WIRED ORACLE VACUUM
            momentum_factor = 1.0
            gamma_yes_m = 1.0
            gamma_no_m = 1.0

            # 1. Zero-lag instant delta (Isolated state variable)
            current_mid = execution_mid
            if not hasattr(self, 'last_mid_vacuum'):
                self.last_mid_vacuum = current_mid

            _instant_delta = current_mid - self.last_mid_vacuum
            self.last_mid_vacuum = current_mid  # isolated update
            _delta_cents = _instant_delta * 100 if current_mid <= 1.0 else _instant_delta

            # 2. Oracle Feeds
            _vel_ema = getattr(self, 'velocity_ema', 0.0)
            _binance_delta = getattr(self, 'binance_delta', 0.0)
            _basis_shift = getattr(self, 'basis_shift', 0.0)

            # 3. Local tick-level inventory limit (Defaults to global setting)
            tick_max_naked = getattr(self, 'max_naked_qty', getattr(self, 'max_inventory', 10))

            # BULLISH RIP (God-Candle on Binance OR Kalshi)
            if (_basis_ema_safe > 0.8 and self.ofi_scalar > 0.05) or (_vel_ema > 8.0) or (_delta_cents > 12.0) or (_binance_delta > 1.5) or (_basis_shift > 0.40):
                momentum_factor = 3.0
                gamma_yes_m = 0.6
                gamma_no_m = momentum_factor
                if _delta_cents > 12.0 or _binance_delta > 1.5 or _basis_shift > 0.40:
                    logging.warning(f"🚨 ORACLE BULL TELEPORT (Binance Δ: {_binance_delta:.2f} | Basis: {_basis_shift:.2f} | Kalshi: {_delta_cents:.2f}¢) → VACUUM ENGAGED")
                    tick_max_naked = 0  # Choke inventory to ZERO for this specific tick

            # BEARISH DUMP (God-Candle on Binance OR Kalshi)
            elif (_basis_ema_safe < -0.8 and self.ofi_scalar < -0.05) or (_vel_ema < -8.0) or (_delta_cents < -12.0) or (_binance_delta < -1.5) or (_basis_shift < -0.40):
                momentum_factor = 3.0
                gamma_yes_m = momentum_factor
                gamma_no_m = 0.6
                if _delta_cents < -12.0 or _binance_delta < -1.5 or _basis_shift < -0.40:
                    logging.warning(f"🚨 ORACLE BEAR TELEPORT (Binance Δ: {_binance_delta:.2f} | Basis: {_basis_shift:.2f} | Kalshi: {_delta_cents:.2f}¢) → VACUUM ENGAGED")
                    tick_max_naked = 0  # Choke inventory to ZERO for this specific tick

            # 4. EXECUTE STOIKOV WITH MULTIPLIERS (composite min-spread: base × warmup × oracle correlation)
            _base_min_spread = float(self.config.get("minimum_spread_cents", 7.0))
            _effective_min_spread = max(3.0, min(30.0, _base_min_spread * self._get_warmup_spread_mult() * self._get_correlation_spread_mult()))

            my_bid_cents, my_ask_cents, actual_delta = self.calculate_avellaneda_stoikov(
                execution_mid, _q0_adjusted_inventory, current_vol, T,
                kappa_override=dynamic_kappa,
                gamma_yes_mult=gamma_yes_m,
                gamma_no_mult=gamma_no_m,
                min_spread_override=_effective_min_spread
            )

            # 5. OVERRIDE GLOBAL INVENTORY CAP FOR THIS TICK
            # Downstream order generation uses tick_max_naked for this iteration (stored for guards/sizing).
            self._tick_max_naked = tick_max_naked

            max_naked_cost = float(self.config.get('max_naked_entry_cost', 65.0))
            
            # Block YES opening if too expensive
            if net_inventory == 0 and my_bid_cents > max_naked_cost:
                logging.info(f"🛑 BAD ODDS GUARD: Blocking YES entry. Cost {my_bid_cents:.1f}¢ > {max_naked_cost}¢ ceiling.")
                my_bid_cents = 0
                intended_bid = None
                
            # Block NO opening if too expensive (100 - ask is the NO cost)
            if net_inventory == 0 and (100.0 - my_ask_cents) > max_naked_cost:
                logging.info(f"🛑 BAD ODDS GUARD: Blocking NO entry. Cost {100.0 - my_ask_cents:.1f}¢ > {max_naked_cost}¢ ceiling.")
                my_ask_cents = 0.0

            if dynamic_q0 != 0 or self.ofi_scalar != 0.0:
                logging.debug(
                    f"📐 q0={dynamic_q0:+d} | basis_ema={_basis_ema_safe:.2f} | "
                    f"ofi_scalar={self.ofi_scalar:+.3f} (influence={_ofi_q0_influence:.1f}) | "
                    f"raw_inv={net_inventory} → adj_inv={_q0_adjusted_inventory}"
                )

            # === HOUSE-MONEY DYNAMIC SIZING (Sentinel V2) ===
            # Default to base size
            quote_size = 1

            # 1. Calculate the Edge (Stoikov Reservation vs. Market Mid)
            res_price = (my_bid_cents + my_ask_cents) / 2.0
            self.reservation_price = res_price  # store for logging
            edge = abs(self.reservation_price - current_mid)

            # 2. Check for "Cushion + Edge"
            # If we have 2+ locked pairs (guaranteed $2.00+ payout) AND edge > 12¢
            if locked >= 2 and edge >= 12.0:
                quote_size = 2
                logging.info(
                    f"💰 HOUSE MONEY: Pressing size to {quote_size} "
                    f"(Edge: {edge:.1f}¢, Locked: {locked})"
                )

            # === ASYNC LEAK GUARD ===
            if self.pending_orders > 0:
                allow_buy_yes = False
                allow_buy_no  = False
                logging.info("🛡️ ASYNC LOCK: Pending fill detected → blocking new quotes")

            # === HARD RAMP CAP v7.3 (applied to naked leg) ===
            if abs(net_inventory) >= 6:
                quote_size = 1
                if net_inventory >= 6:
                    allow_buy_yes = False
                if net_inventory <= -6:
                    allow_buy_no = False
                logging.info(
                    f"📉 HARD RAMP CAP HIT: naked net={net_inventory} → blocked new adds "
                    f"[Yes Inv: {yes_inv} | No Inv: {no_inv} | Locked: {locked}]"
                )

            # === KILL SHOT ARB BYPASS ===
            # If a guaranteed arbitrage lock is mathematically available, skip the cushion
            # guard entirely — risk-free settlement doesn't require a PnL cushion.
            if eid and locked < self.max_locked_pairs:
                raw_ask_arb = float(self.live_exchange_ask or 0.0)
                raw_bid_arb = float(self.live_exchange_bid or 0.0)
                ask_c_arb   = raw_ask_arb * 100.0 if raw_ask_arb < 1.0 else raw_ask_arb
                bid_c_arb   = raw_bid_arb * 100.0 if raw_bid_arb < 1.0 else raw_bid_arb
                arb_ceiling = self.pair_lock_threshold * 100.0

                if naked_yes > 0:
                    yes_cost_arb = self.yes_cost_basis.get(eid, 0.0)
                    no_ask_arb   = 100.0 - bid_c_arb   # NO ask implied from YES bid
                    total_cost   = yes_cost_arb + no_ask_arb
                    if total_cost <= arb_ceiling and no_ask_arb > 0:
                        lock_qty = min(naked_yes, self.max_locked_pairs - locked)
                        if lock_qty > 0:
                            # 1. Snapshot the current inventory state
                            pre_cancel_yes = yes_inv
                            pre_cancel_no = no_inv
                            # 2. Kill all resting limit orders that could get filled concurrently
                            logging.info("🔒 KILL SHOT INIT: Canceling resting orders to prevent legging race condition.")
                            await self.cancel_active_orders()
                            await asyncio.sleep(0.05)  # 50ms buffer for exchange matching engine
                            # 3. Verify our naked leg wasn't sniped during the 50ms window
                            if (self.yes_inventory.get(eid, 0) != pre_cancel_yes or
                                self.no_inventory.get(eid, 0) != pre_cancel_no or
                                self.event_id != eid):
                                logging.warning("⚠️ RACE CONDITION AVERTED: Inventory or Market State mutated during cancel. Aborting kill shot.")
                                return
                            # (Existing kill-shot taker order code proceeds below here)
                            max_price_cents = int(arb_ceiling - yes_cost_arb)
                            no_price = max(1, min(99, max_price_cents))
                            logging.info(
                                f"⚡ ARB BYPASS: Guaranteed lock — "
                                f"total cost {total_cost:.1f}¢ ≤ {arb_ceiling:.0f}¢. "
                                f"Overriding cushion guard. Sweeping NO up to {no_price}¢."
                            )
                            arb_order = {
                                "action": "buy", "side": "no", "count": int(lock_qty),
                                "type": "limit", "no_price": int(no_price),
                                "ticker": self.current_market,
                                "client_order_id": str(uuid.uuid4())
                            }
                            self.pending_orders += 1
                            try:
                                arb_res = await self.api.request("POST", "/portfolio/orders", body=arb_order)
                                if isinstance(arb_res, dict) and "order" in arb_res and "order_id" in arb_res["order"]:
                                    self.active_order_ids.add(arb_res["order"]["order_id"])
                                logging.info(
                                    f"🎯 ARB KILL SHOT: Locking {lock_qty} pair(s) | "
                                    f"YES cost: {yes_cost_arb:.1f}¢ + NO limit: {no_price}¢ "
                                    f"= {yes_cost_arb + no_price:.1f}¢ "
                                    f"(≤{arb_ceiling:.0f}¢) | "
                                    f"Yes Inv: {yes_inv} | No Inv: {no_inv} | Locked: {locked}"
                                )
                            finally:
                                self.pending_orders -= 1
                            return

                elif naked_no > 0:
                    no_cost_arb  = self.no_cost_basis.get(eid, 0.0)
                    yes_ask_arb  = ask_c_arb
                    total_cost   = no_cost_arb + yes_ask_arb
                    if total_cost <= arb_ceiling and yes_ask_arb > 0:
                        lock_qty = min(naked_no, self.max_locked_pairs - locked)
                        if lock_qty > 0:
                            # 1. Snapshot the current inventory state
                            pre_cancel_yes = yes_inv
                            pre_cancel_no = no_inv
                            # 2. Kill all resting limit orders that could get filled concurrently
                            logging.info("🔒 KILL SHOT INIT: Canceling resting orders to prevent legging race condition.")
                            await self.cancel_active_orders()
                            await asyncio.sleep(0.05)  # 50ms buffer for exchange matching engine
                            # 3. Verify our naked leg wasn't sniped during the 50ms window
                            if (self.yes_inventory.get(eid, 0) != pre_cancel_yes or
                                self.no_inventory.get(eid, 0) != pre_cancel_no or
                                self.event_id != eid):
                                logging.warning("⚠️ RACE CONDITION AVERTED: Inventory or Market State mutated during cancel. Aborting kill shot.")
                                return
                            # (Existing kill-shot taker order code proceeds below here)
                            max_price_cents = int(arb_ceiling - no_cost_arb)
                            yes_price = max(1, min(99, max_price_cents))
                            logging.info(
                                f"⚡ ARB BYPASS: Guaranteed lock — "
                                f"total cost {total_cost:.1f}¢ ≤ {arb_ceiling:.0f}¢. "
                                f"Overriding cushion guard. Sweeping YES up to {yes_price}¢."
                            )
                            arb_order = {
                                "action": "buy", "side": "yes", "count": int(lock_qty),
                                "type": "limit", "yes_price": int(yes_price),
                                "ticker": self.current_market,
                                "client_order_id": str(uuid.uuid4())
                            }
                            self.pending_orders += 1
                            try:
                                arb_res = await self.api.request("POST", "/portfolio/orders", body=arb_order)
                                if isinstance(arb_res, dict) and "order" in arb_res and "order_id" in arb_res["order"]:
                                    self.active_order_ids.add(arb_res["order"]["order_id"])
                                logging.info(
                                    f"🎯 ARB KILL SHOT: Locking {lock_qty} pair(s) | "
                                    f"NO cost: {no_cost_arb:.1f}¢ + YES limit: {yes_price}¢ "
                                    f"= {no_cost_arb + yes_price:.1f}¢ "
                                    f"(≤{arb_ceiling:.0f}¢) | "
                                    f"Yes Inv: {yes_inv} | No Inv: {no_inv} | Locked: {locked}"
                                )
                            finally:
                                self.pending_orders -= 1
                            return

            # === THE GUILLOTINE: UNCONDITIONAL NAKED-LEG STOP LOSS ===
            # Runs AFTER the Kill Shot (which locks guaranteed-arb profits first) but
            # BEFORE the Cushion Guard and all momentum/delta checks.
            # hard_stop_naked_cents and toxic_asset_floor_cents are hot-loaded from config.
            if naked_yes > 0 or naked_no > 0:
                hard_stop   = float(self.config.get('hard_stop_naked_cents', -15.0))
                toxic_floor = float(self.config.get('toxic_asset_floor_cents', 3.0))
                _g_bid = float(self.live_exchange_bid or 0.0)
                _g_ask = float(self.live_exchange_ask or 0.0)
                _g_bid_c = _g_bid * 100.0 if _g_bid < 1.0 else _g_bid
                _g_ask_c = _g_ask * 100.0 if _g_ask < 1.0 else _g_ask

                if naked_yes > 0:
                    yes_cost_g        = self._active_yes_cost(eid)
                    current_exit_price = _g_bid_c
                    true_pnl          = current_exit_price - yes_cost_g
                else:  # naked_no > 0
                    no_cost_g         = self._active_no_cost(eid)
                    current_exit_price = 100.0 - _g_ask_c
                    true_pnl          = current_exit_price - no_cost_g

                _sl_triggered    = true_pnl <= hard_stop
                _toxic_triggered = current_exit_price <= toxic_floor

                if _sl_triggered or _toxic_triggered:
                    if _sl_triggered:
                        _reason = (
                            f"Stop Loss — PnL {true_pnl:.1f}¢ <= hard_stop {hard_stop:.1f}¢"
                        )
                    else:
                        _reason = (
                            f"Toxic Floor — exit price {current_exit_price:.1f}¢ "
                            f"<= toxic_floor {toxic_floor:.1f}¢ (PnL {true_pnl:.1f}¢)"
                        )
                    logging.warning(
                        f"🔪 GUILLOTINE TRIGGERED ({_reason}). Forcing hybrid exit NOW. "
                        f"[Yes Inv: {yes_inv} | No Inv: {no_inv} | Locked: {locked}]"
                    )
                    await self.execute_hybrid_exit("STOP_LOSS")
                    return

            # === RELAXED CUSHION + HARD NAKED BAN (inlined) ===
            raw_b = self.live_exchange_bid or 0.0
            raw_a = self.live_exchange_ask or 0.0
            _bid_c = raw_b * 100.0 if raw_b < 1.0 else float(raw_b)
            _ask_c = raw_a * 100.0 if raw_a < 1.0 else float(raw_a)
            _no_exit = 100.0 - _ask_c
            yes_cost = self._active_yes_cost(eid)
            no_cost  = self._active_no_cost(eid)
            current_pnl = (_bid_c - yes_cost) if naked_yes > 0 else ((_no_exit - no_cost) if naked_no > 0 else 0.0)
            PYRAMID_THRESHOLD = float(self.config.get('cushion_guard_min_pnl_cents', 3.0))

            if naked_qty > 0:
                if time.time() - getattr(self, 'last_lock_time', 0.0) < 60.0:
                    return  # Lock & Walk: no new naked entries for 60s after a lock
                ref_price = self.live_eth_price if self.live_eth_price else 1.0
                delta_pct = abs(self.binance_delta) / ref_price * 100
                if delta_pct > 0.60 or getattr(self, 'instant_velocity', 0) > 5.0:
                    return  # Hard ban in trending vol
            if not (naked_qty > 0) and current_pnl >= PYRAMID_THRESHOLD:
                pass  # allow pyramiding — don't apply cushion guard
            else:
                if naked_yes > 0 and allow_buy_yes and (_bid_c - yes_cost) < PYRAMID_THRESHOLD:
                    allow_buy_yes = False
                    logging.info(
                        f"🛑 CUSHION GUARD: YES PnL {_bid_c - yes_cost:.1f}¢ < +{PYRAMID_THRESHOLD:.1f}¢ to pyramid "
                        f"[Yes Inv: {yes_inv} | No Inv: {no_inv} | Locked: {locked}]"
                    )
                if naked_no > 0 and allow_buy_no and (_no_exit - no_cost) < PYRAMID_THRESHOLD:
                    allow_buy_no = False
                    logging.info(
                        f"🛑 CUSHION GUARD: NO PnL {_no_exit - no_cost:.1f}¢ < +{PYRAMID_THRESHOLD:.1f}¢ to pyramid "
                        f"[Yes Inv: {yes_inv} | No Inv: {no_inv} | Locked: {locked}]"
                    )
            # === CAPITAL EXPOSURE CAP ===
            # Use cents for both terms to avoid scale mismatch (balance in $, execution_mid fractional 0-1).
            max_allowed_spend     = self.current_balance * self.config["max_capital_exposure_pct"]
            max_allowed_spend_cents = int(max_allowed_spend * 100)
            price_per_contract_cents = max(1, int(round(execution_mid * 100)))
            max_contracts_allowed = max_allowed_spend_cents // price_per_contract_cents
            logging.debug(f"Cap check: Max spend={max_allowed_spend}, Mid={execution_mid}, Allowed Contracts={max_contracts_allowed}")
            # Ensure effective_max_naked is locally available if out of scope from above
            _local_effective_max = getattr(self, '_tick_max_naked', getattr(self, 'max_inventory', 10))
            max_bid_qty = min(_local_effective_max, max_contracts_allowed)
            max_ask_qty = min(_local_effective_max, max_contracts_allowed)

            # Sizing is driven by the naked (unbalanced) leg count
            bid_count = min(quote_size, max_bid_qty - naked_yes) if naked_yes >= 0 else 1
            ask_count = min(quote_size, max_ask_qty - naked_no)  if naked_no  >= 0 else 1
            bid_count = max(1, bid_count)
            ask_count = max(1, ask_count)

            # =========================================================
            # === FINAL QUOTE ADJUSTMENT LAYER (Upgrades 4 & 5) ===
            # =========================================================

            # --- Upgrade 4: Terminal Taker Aggression ---
            _term_agg = self._get_terminal_aggression_cents(time_left)
            if _term_agg > 0:
                if naked_yes > 0:
                    _old_ask = my_ask_cents
                    my_ask_cents = max(1, min(99, my_ask_cents - _term_agg))
                    if my_ask_cents != _old_ask:
                        logging.info(f"⏳ TERMINAL AGGRESSION ({time_left:.0f}s left): YES ask {_old_ask}¢ → {my_ask_cents}¢ (-{_term_agg}¢)")
                elif naked_no > 0:
                    _old_bid = my_bid_cents
                    my_bid_cents = max(1, min(99, my_bid_cents + _term_agg))
                    if my_bid_cents != _old_bid:
                        logging.info(f"⏳ TERMINAL AGGRESSION ({time_left:.0f}s left): NO bid {_old_bid}¢ → {my_bid_cents}¢ (+{_term_agg}¢)")

            # --- Upgrade 5: Queue Position Jumper ---
            _queue_threshold = int(self.config.get("queue_jump_threshold", 500))

            if (naked_no == 0 and my_bid_cents > 0 and allow_buy_yes
                    and int(round(my_bid_cents)) == int(round(safe_bid_cents))
                    and self.live_yes_bid_size > _queue_threshold):
                _old_bid = my_bid_cents
                my_bid_cents = max(1, min(99, my_bid_cents + 1))
                logging.info(f"🏃 QUEUE JUMP BID: {_old_bid}¢ → {my_bid_cents}¢ (BBO size {self.live_yes_bid_size} > {_queue_threshold})")

            if (naked_yes == 0 and my_ask_cents > 0 and allow_buy_no
                    and int(round(my_ask_cents)) == int(round(safe_ask_cents))
                    and self.live_yes_ask_size > _queue_threshold):
                _old_ask = my_ask_cents
                my_ask_cents = max(1, min(99, my_ask_cents - 1))
                logging.info(f"🏃 QUEUE JUMP ASK: {_old_ask}¢ → {my_ask_cents}¢ (BBO size {self.live_yes_ask_size} > {_queue_threshold})")

            # =========================================================
            intended_bid = None if (not allow_buy_yes and net_inventory >= 0) else my_bid_cents
            intended_ask = None if (not allow_buy_no  and net_inventory <= 0) else my_ask_cents

            # Maker exit: Kalshi maker fees 0¢ — take any positive spread. Taker fee floor (2¢) applied only on taker exits elsewhere.
            MIN_PROFIT_CENTS_MAKER = 0.0
            if naked_yes > 0 and intended_ask is not None:
                exit_profit = my_ask_cents - yes_cost
                if 0 < exit_profit < MIN_PROFIT_CENTS_MAKER:
                    logging.debug(
                        f"🛑 Blocking micro-scalp. Gross PnL {exit_profit:.1f}¢ < {MIN_PROFIT_CENTS_MAKER}¢ fee floor."
                    )
                    intended_ask = None
            if naked_no > 0 and intended_bid is not None:
                exit_profit = (100.0 - my_bid_cents) - no_cost
                if 0 < exit_profit < MIN_PROFIT_CENTS_MAKER:
                    logging.debug(
                        f"🛑 Blocking micro-scalp. Gross PnL {exit_profit:.1f}¢ < {MIN_PROFIT_CENTS_MAKER}¢ fee floor."
                    )
                    intended_bid = None

            if intended_bid == self.resting_bid and intended_ask == self.resting_ask:
                return

            # === HYSTERESIS GUARD ===
            # Structural change (add/remove side) always requotes
            if (intended_bid is None and self.resting_bid is not None) or (intended_ask is None and self.resting_ask is not None):
                pass  # bypass hysteresis, must requote
            elif not self.should_requote(my_bid_cents, my_ask_cents):
                self.iteration_count = getattr(self, 'iteration_count', 0) + 1
                if self.iteration_count % 10 == 0:
                    logging.info("⏳ Hysteresis: Price move < 1c. Maintaining queue priority.")
                return

            await self.cancel_active_orders()
            orders_to_send = []

            # BID side
            if my_bid_cents > 0:
                if naked_no > 0:
                    # Exit the naked NO position via a sell-NO order
                    bid_order = {
                        "action": "sell", "side": "no", "count": int(bid_count),
                        "type": "limit", "no_price": int(100 - my_bid_cents),
                        "ticker": ticker, "client_order_id": str(uuid.uuid4())
                    }
                    orders_to_send.append(self.api.request("POST", "/portfolio/orders", body=bid_order))
                    self.resting_bid = my_bid_cents
                else:
                    if allow_buy_yes:
                        bid_order = {
                            "action": "buy", "side": "yes", "count": int(bid_count),
                            "type": "limit", "yes_price": int(my_bid_cents),
                            "ticker": ticker, "client_order_id": str(uuid.uuid4())
                        }
                        orders_to_send.append(self.api.request("POST", "/portfolio/orders", body=bid_order))
                        self.resting_bid = my_bid_cents
                    else:
                        self.resting_bid = None
            else:
                self.resting_bid = None

            # ASK side
            if my_ask_cents > 0:
                if naked_yes > 0:
                    # Exit the naked YES position via a sell-YES order
                    ask_order = {
                        "action": "sell", "side": "yes", "count": int(ask_count),
                        "type": "limit", "yes_price": int(my_ask_cents),
                        "ticker": ticker, "client_order_id": str(uuid.uuid4())
                    }
                    orders_to_send.append(self.api.request("POST", "/portfolio/orders", body=ask_order))
                    self.resting_ask = my_ask_cents
                else:
                    if allow_buy_no:
                        ask_order = {
                            "action": "buy", "side": "no", "count": int(ask_count),
                            "type": "limit", "no_price": int(100 - my_ask_cents),
                            "ticker": ticker, "client_order_id": str(uuid.uuid4())
                        }
                        orders_to_send.append(self.api.request("POST", "/portfolio/orders", body=ask_order))
                        self.resting_ask = my_ask_cents
                    else:
                        self.resting_ask = None
            else:
                self.resting_ask = None

            if orders_to_send:
                self.pending_orders += 1
                try:
                    results = await asyncio.gather(*orders_to_send, return_exceptions=True)
                    any_success = False
                    for res in results:
                        if isinstance(res, dict) and "order" in res and "order_id" in res["order"]:
                            self.active_order_ids.add(res["order"]["order_id"])
                            any_success = True
                    if any_success:
                        if self.resting_bid is not None:
                            self.last_quoted_bid = self.resting_bid
                        if self.resting_ask is not None:
                            self.last_quoted_ask = self.resting_ask
                        new_bid = self.resting_bid or 0.0
                        new_ask = self.resting_ask or 0.0
                        self.current_mid = execution_mid * 100.0
                        self.current_spread = current_spread
                        self._record_flight_log("QUOTE_POSTED", {"bid": new_bid, "ask": new_ask})
                finally:
                    self.pending_orders -= 1

            bid_str  = f"{my_bid_cents}¢" if self.resting_bid else "PULLED"
            ask_str  = f"{my_ask_cents}¢" if self.resting_ask else "PULLED"
            yes_cost_display = f"{self.yes_cost_basis.get(eid, 0.0):.1f}¢" if yes_inv > 0 else "—"
            no_cost_display  = f"{self.no_cost_basis.get(eid, 0.0):.1f}¢"  if no_inv  > 0 else "—"
            logging.info(
                f"WS Reaction | Mid: {execution_mid:.2f} | PnL: {pnl:+.1f}¢ | "
                f"YES cost: {yes_cost_display} | NO cost: {no_cost_display} | "
                f"Yes Inv: {yes_inv} | No Inv: {no_inv} | Locked: {locked} | "
                f"Bid: {bid_str} | Ask: {ask_str}"
            )
        except Exception as e:
            logging.error(f"Silent Crash caught in WS quoting logic: {e}")

    def _update_ofi(self, bid_price: float, bid_qty: float,
                    ask_price: float, ask_qty: float) -> None:
        if self.ofi_prev_bid_price is None:
            self.ofi_prev_bid_price = bid_price
            self.ofi_prev_bid_qty   = bid_qty
            self.ofi_prev_ask_price = ask_price
            self.ofi_prev_ask_qty   = ask_qty
            return

        if bid_price > self.ofi_prev_bid_price:
            e =  bid_qty
        elif bid_price == self.ofi_prev_bid_price:
            e =  bid_qty - self.ofi_prev_bid_qty
        else:
            e = -self.ofi_prev_bid_qty

        if ask_price < self.ofi_prev_ask_price:
            f = -ask_qty
        elif ask_price == self.ofi_prev_ask_price:
            f =  ask_qty - self.ofi_prev_ask_qty
        else:
            f =  self.ofi_prev_ask_qty

        raw_ofi = e - f

        alpha       = float(self.config.get('ofi_alpha', 0.3))
        self.ofi_ema = (alpha * raw_ofi) + ((1.0 - alpha) * self.ofi_ema)

        normalizer   = float(self.config.get('ofi_normalizer', 50.0))
        if normalizer > 0.0:
            self.ofi_scalar = max(-1.0, min(1.0, self.ofi_ema / normalizer))

        self.ofi_prev_bid_price = bid_price
        self.ofi_prev_bid_qty   = bid_qty
        self.ofi_prev_ask_price = ask_price
        self.ofi_prev_ask_qty   = ask_qty

    async def listen_to_binance_ws(self):
        uri = "wss://stream.binance.us:9443/stream?streams=ethusdt@ticker/ethusdt@bookTicker"
        logging.info("Connecting to Binance Combined Spot WS (ticker + bookTicker)...")
        reconnect_delay = 5

        while True:
            try:
                async with websockets.connect(uri) as ws:
                    reconnect_delay = 5
                    logging.info("✅ Connected to Binance Combined ETH Spot feed (OFI active).")
                    while True:
                        message = await ws.recv()
                        envelope = json.loads(message)
                        self.last_ws_msg_time = time.time()

                        stream_name = envelope.get("stream", "")
                        msg_data    = envelope.get("data", envelope)

                        if stream_name.endswith("@ticker"):
                            last_price = msg_data.get('c') or msg_data.get('lastPrice') or msg_data.get('last')
                            if not last_price:
                                continue
                            self.live_eth_price = float(last_price)
                            self.eth_price_history.append(self.live_eth_price)
                            if len(self.eth_price_history) > 60:
                                self.eth_price_history.pop(0)

                        elif stream_name.endswith("@bookTicker"):
                            try:
                                bp = float(msg_data['b'])
                                bq = float(msg_data['B'])
                                ap = float(msg_data['a'])
                                aq = float(msg_data['A'])
                                if bp > 0.0 and ap > 0.0:
                                    self._update_ofi(bp, bq, ap, aq)
                            except (KeyError, ValueError, TypeError):
                                pass
            except Exception as e:
                logging.warning(f"Binance WS dropped. Reconnecting in {reconnect_delay}s...")
                await asyncio.sleep(reconnect_delay)
                reconnect_delay = min(60, reconnect_delay * 2)

    async def listen_to_binance_futures_ws(self):
        uri = "wss://fstream.binance.com/ws/ethusdt@ticker"
        logging.info("Connecting to Binance Futures WS (Perp Basis feed)...")
        reconnect_delay = 5

        while True:
            try:
                async with websockets.connect(uri) as ws:
                    reconnect_delay = 5  # Reset on successful connection
                    logging.info("✅ Connected to Binance Futures ETH Perp feed.")
                    while True:
                        message = await ws.recv()
                        data = json.loads(message)
                        self.last_ws_msg_time = time.time()
                        last_price = float(data.get('c', 0))
                        if last_price > 0:
                            self.live_eth_futures_price = last_price
                            self.futures_price = last_price
            except Exception as e:
                # FIXED: Implemented exponential backoff to prevent Binance IP bans.
                logging.warning(f"Binance WS dropped. Reconnecting in {reconnect_delay}s...")
                await asyncio.sleep(reconnect_delay)
                reconnect_delay = min(60, reconnect_delay * 2)

    async def listen_to_market_data(self, ticker):
        ws_path = "/trade-api/ws/v2"
        while self.is_running:
            try:
                auth_headers = self.api._sign_request("GET", ws_path)
                async with websockets.connect(WS_URL, additional_headers=auth_headers) as ws:
                    # Do NOT clear. seen_trade_ids accumulates all session fills to prevent double-processing between REST and WS after a reconnect.
                    subscribe_msg = {
                        "id": 1,
                        "cmd": "subscribe",
                        "params": {
                            "channels": ["ticker", "fill"], 
                            "market_tickers": [ticker]
                        }
                    }
                    await ws.send(_json_dumps_str(subscribe_msg))
                    logging.info(f"Subscribed to WebSockets for {ticker}")

                    while self.is_running:
                        try:
                            message = await asyncio.wait_for(ws.recv(), timeout=1.0)
                            data = json.loads(message)
                            msg_type = data.get("type")

                            if msg_type == "fill":
                                self.last_ws_msg_time = time.time()
                                fill_data = data.get("msg", {})
                                trade_id = fill_data.get("trade_id")
                                
                                if trade_id and trade_id not in self.seen_trade_ids:
                                    self.seen_trade_ids.add(trade_id)
                                    logging.debug(f"RAW WS FILL DATA: {fill_data}")
                                    action = fill_data.get("action")
                                    side   = fill_data.get("side")
                                    count  = int(float(fill_data.get("count") or fill_data.get("count_fp") or 1.0))
                                    purchased_side = fill_data.get("purchased_side")

                                    price = None
                                    if purchased_side == "yes" or side == "yes":
                                        price = (fill_data.get("yes_price_dollars") or fill_data.get("yes_price") or (fill_data.get("order") or {}).get("yes_price_dollars") or (fill_data.get("trade") or {}).get("yes_price_dollars") or fill_data.get("price"))
                                    elif purchased_side == "no" or side == "no":
                                        price = (fill_data.get("no_price_dollars") or fill_data.get("no_price") or (fill_data.get("order") or {}).get("no_price_dollars") or (fill_data.get("trade") or {}).get("no_price_dollars") or fill_data.get("price") or fill_data.get("yes_price_dollars") or fill_data.get("yes_price"))

                                    if price is not None:
                                        try:
                                            price = float(price)
                                            if price < 1.0: price *= 100.0
                                        except (ValueError, TypeError):
                                            price = None

                                    if price is None:
                                        logging.warning(f"🚨 MISSING PRICE IN FILL — Keys: {list(fill_data.keys())}")
                                        price = 50.0

                                    # === NO-LEG INVERSION ===
                                    # Kalshi V2 WebSocket unconditionally reports NO fills in YES-space.
                                    # Invert to true cost so VWAP / PnL math is correct.
                                    # Toggle via no_price_inversion in config.yaml.
                                    invert_no = self.config.get('no_price_inversion', True)
                                    if side == "no" and invert_no:
                                        raw_fill = price
                                        price = 100.0 - raw_fill
                                        logging.info(
                                            f"🔄 INVERSION: Kalshi raw NO fill {raw_fill:.1f}¢ "
                                            f"-> True Cost {price:.1f}¢"
                                        )

                                    # Snapshot relevant cost basis BEFORE inventory mutation
                                    _fill_eid = self.event_id
                                    _pre_yes_cost  = self.yes_cost_basis.get(_fill_eid, 0.0) if _fill_eid else 0.0
                                    _pre_no_cost   = self.no_cost_basis.get(_fill_eid, 0.0)  if _fill_eid else 0.0
                                    _pre_fill_cost = _pre_yes_cost if side in ("yes", None) else _pre_no_cost
                                    _cost_display_pre = f"{_pre_fill_cost:.1f}¢" if _pre_fill_cost > 0 else "0.0¢"

                                    # price is already normalized to cents by the parser above
                                    _display_price = price

                                    if _fill_eid:
                                        fill_price_cents = price
                                        is_buy = action == "buy"
                                        is_taker = fill_data.get("is_taker", False)
                                        # Snapshot locked count and naked cost basis BEFORE inventory mutation
                                        _locked_before = min(
                                            self.yes_inventory.get(_fill_eid, 0),
                                            self.no_inventory.get(_fill_eid, 0),
                                        )
                                        _active_yes_before = self._active_yes_cost(_fill_eid)
                                        _active_no_before = self._active_no_cost(_fill_eid)
                                        if side == "yes":
                                            self._apply_fill_to_inventory(_fill_eid, count, fill_price_cents, is_buy, is_taker)
                                        elif side == "no":
                                            self._apply_no_fill_to_inventory(_fill_eid, count, fill_price_cents, is_buy, is_taker)
                                        # Single ledger path for Pure Arb and Kill Shot (fill-confirmed quarantine)
                                        self._process_arb_fill_confirmation(
                                            _fill_eid,
                                            side,
                                            fill_price_cents,
                                            _locked_before,
                                            _active_yes_before,
                                            _active_no_before,
                                        )
                                    self.last_fill_time = time.time()

                                    _eid     = self.event_id
                                    _yes_inv = self.yes_inventory.get(_eid, 0) if _eid else 0
                                    _no_inv  = self.no_inventory.get(_eid, 0)  if _eid else 0
                                    _locked  = min(_yes_inv, _no_inv)

                                    _nq, _ns = self.get_unbalanced_leg(_eid)
                                    if _nq > 0:  # still holding a naked leg
                                        self.last_exit_reason = None

                                    _yes_cost_d = f"{self.yes_cost_basis.get(_eid, 0.0):.1f}¢" if _yes_inv > 0 else "—"
                                    _no_cost_d  = f"{self.no_cost_basis.get(_eid, 0.0):.1f}¢"  if _no_inv  > 0 else "—"
                                    logging.info(
                                        f"⚡ WS FILL: {action.upper()} {count} {side.upper()} "
                                        f"@ {_display_price:.1f}¢ | "
                                        f"Yes Inv: {_yes_inv} | No Inv: {_no_inv} | Locked: {_locked} | "
                                        f"YES cost: {_yes_cost_d} | NO cost: {_no_cost_d}"
                                    )
                                    
                                    await self.cancel_active_orders()
                                    self.latest_ticker = ticker
                                    self.state_changed.set()
                                    continue

                            elif msg_type == "market_result":
                                self.last_ws_msg_time = time.time()
                                # Market has settled — realize locked-pair PnL at $1.00 payout
                                logging.info(f"🏁 MARKET RESULT received for {ticker}. Running settlement protocol.")
                                if self.event_id:
                                    self.settle_locked_pairs(self.event_id)
                                # Flatten any residual naked leg that wasn't exited in time
                                _nq_settle, _ = self.get_unbalanced_leg(self.event_id)
                                if _nq_settle > 0:
                                    logging.warning(
                                        f"⚠️ {_nq_settle} naked contract(s) remain at settlement — "
                                        f"marking as zero-value loss."
                                    )
                                    if self.event_id:
                                        self.yes_inventory.pop(self.event_id, None)
                                        self.no_inventory.pop(self.event_id, None)
                                        self.yes_cost_basis.pop(self.event_id, None)
                                        self.no_cost_basis.pop(self.event_id, None)
                                self.save_daily_pnl()
                                self.is_running = False

                            elif msg_type == "ticker":
                                self.last_ws_msg_time = time.time()
                                msg_data = data.get("msg", {})

                                raw_bid_str = msg_data.get('yes_bid_dollars')
                                raw_ask_str = msg_data.get('yes_ask_dollars')

                                self.live_exchange_bid = float(raw_bid_str) * 100.0 if raw_bid_str else 0.0
                                self.live_exchange_ask = float(raw_ask_str) * 100.0 if raw_ask_str else 0.0

                                try:
                                    raw_bid_sz = msg_data.get('yes_bid_size')
                                    raw_ask_sz = msg_data.get('yes_ask_size')
                                    self.live_yes_bid_size = int(raw_bid_sz) if raw_bid_sz is not None else 0
                                    self.live_yes_ask_size = int(raw_ask_sz) if raw_ask_sz is not None else 0
                                except (ValueError, TypeError):
                                    pass

                                bid_c = self.live_exchange_bid
                                ask_c = self.live_exchange_ask
                                self.current_orderbook = {
                                    'bids': [(bid_c, self.live_yes_bid_size)] if bid_c else [],
                                    'asks': [(ask_c, self.live_yes_ask_size)] if ask_c else [],
                                }

                                self.latest_ticker = ticker
                                self.state_changed.set()
                                    
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

            # FIXED: Dead-man's switch for WS disconnects while holding naked risk.
            if time.time() - self.last_ws_msg_time > 30.0:
                eid = self.event_id
                naked_qty, naked_side = self.get_unbalanced_leg(eid) if eid else (0, None)
                if naked_qty > 0:
                    logging.critical(
                        "WS BLACKOUT DETECTED (>30s) WITH OPEN POSITION. TRIGGERING EMERGENCY EXIT."
                    )
                    await self.execute_hybrid_exit("WS_BLACKOUT")
                    self.last_ws_msg_time = time.time()  # Reset to prevent spamming while exiting

            # Ghost order sweep every ~36s (every 3 ticks; TICK_INTERVAL=12)
            loop_counter += 1
            if loop_counter % 3 == 0:
                await self.reconcile_ghost_orders()

            time_left = (self.market_close_time - datetime.datetime.now(datetime.timezone.utc)).total_seconds()

            if time_left < -60:
                logging.warning("⚠️ Market expired. No settlement event received. Forcing WS teardown to roll over.")
                self.is_running = False
                break

            # 3-minute ripcord: flatten excess risk only; hold small naked into settlement (house money)
            ripcord_seconds = self.config.get("ripcord_minutes", 3) * 60
            if time_left < ripcord_seconds:
                eid = self.event_id
                naked_qty, exit_side = self.get_unbalanced_leg(eid) if eid else (0, None)

                if naked_qty > 2:
                    logging.info("⏳ 3-MINUTE DEAD ZONE. Naked leg > 2. Flattening excess risk.")
                    await self.execute_hybrid_exit("3_MIN_RIPCORD")
                elif naked_qty == 1 and time_left < 180:
                    # Single-leg ripcord: flatten persistent loser before expiry zero (only if salvage value > 2¢ to avoid taker fee deficit)
                    bid_cents = (self.live_exchange_bid * 100.0) if self.live_exchange_bid else 0.0
                    ask_cents = (self.live_exchange_ask * 100.0) if self.live_exchange_ask else 0.0
                    yes_pnl_cents = bid_cents - self.yes_cost_basis.get(eid, 50.0) if eid else 0.0
                    no_pnl_cents = (100.0 - ask_cents) - self.no_cost_basis.get(eid, 50.0) if eid else 0.0
                    if exit_side == "yes" and yes_pnl_cents < -12.0:
                        if bid_cents <= 2.0:
                            logging.info("💀 SALVAGE VALUE TOO LOW: Bid <= 2¢. Letting naked leg die at settlement to avoid Taker fee deficit.")
                        else:
                            logging.warning("⚡ SINGLE-LEG RIPCORD: Flattening persistent YES loser before expiry zero.")
                            await self.execute_hybrid_exit("3_MIN_RIPCORD")
                    elif exit_side == "no" and no_pnl_cents < -12.0:
                        no_bid_cents = 100.0 - ask_cents
                        if no_bid_cents <= 2.0:
                            logging.info("💀 SALVAGE VALUE TOO LOW: Bid <= 2¢. Letting naked leg die at settlement to avoid Taker fee deficit.")
                        else:
                            logging.warning("⚡ SINGLE-LEG RIPCORD: Flattening persistent NO loser before expiry zero.")
                            await self.execute_hybrid_exit("3_MIN_RIPCORD")
                    else:
                        logging.info(f"🎰 HOLDING 1 naked {exit_side.upper()} leg into settlement — house money play.")
                elif naked_qty > 0:
                    logging.info(f"🎰 HOLDING {naked_qty} naked leg(s) into settlement — house money play.")

                await asyncio.sleep(TICK_INTERVAL)  # Throttle REST polling; prevent 429 spam
                continue  # Keep the engine alive for the next 15-min market. DO NOT shut down.

            await asyncio.sleep(TICK_INTERVAL)

    def _reset_cycle_state(self, expired_ticker: str | None = None) -> None:
        logging.info(f"🔄 CYCLE RESET: Clearing per-market state (prev={expired_ticker})")

        self.is_running   = False
        self.done_for_day = getattr(self, 'done_for_day', False)

        self.current_market    = None
        self.market_close_time = None
        self.event_id          = None

        self.live_exchange_bid  = 0.0
        self.live_exchange_ask  = 0.0
        self.live_yes_bid_size  = 0
        self.live_yes_ask_size  = 0
        self.current_orderbook  = {}
        self.kalshi_book        = {'bids': [], 'asks': []}

        self.resting_bid        = 0.0
        self.resting_ask        = 0.0
        self.resting_exit_price = 0.0
        self.active_order_ids.clear()
        self.pending_orders     = 0

        self.price_history             = []
        self.last_price_history_update = 0
        self.prev_mid                  = None
        self.velocity_ema              = 0.0
        self.instant_velocity          = 0.0
        self.last_mid_vacuum           = 0.0

        self.seen_trade_ids.clear()

        self.last_ws_msg_time      = time.time()
        self.last_quote_time       = 0.0
        self.last_sl_time          = 0.0
        self.last_fill_time        = 0.0
        self.last_taker_time       = 0
        self.last_lock_time        = 0.0
        self.last_dislocation_time = 0.0
        self.last_exit_reason      = None
        self.last_quoted_bid       = 0.0
        self.last_quoted_ask       = 0.0
        self.latest_ticker         = None

        self.peak_pnl             = 0.0
        self.trailing_stop_active = False

        if getattr(self, 'state_changed', None) is not None:
            self.state_changed.clear()

        self.quote_consumer_task = None

        if expired_ticker:
            for d in (self.yes_inventory, self.no_inventory,
                      self.yes_cost_basis, self.no_cost_basis):
                d.pop(expired_ticker, None)
            self.locked_pairs = [
                p for p in getattr(self, 'locked_pairs', []) if p.get('ticker') != expired_ticker
            ]

    async def run(self):
        await self.api.start_session()
        await TelegramAlerts.send("🐺 StoikovSentinel initialized. PREDATOR SCALPING ACTIVE.")
        self.quote_lock  = asyncio.Lock()
        self.state_changed = asyncio.Event()

        binance_task         = asyncio.create_task(self.listen_to_binance_ws())
        binance_futures_task = asyncio.create_task(self.listen_to_binance_futures_ws())

        try:
            while True:  
                self.config = self._load_config()
                if not self.config.get('force_run', False):
                    from zoneinfo import ZoneInfo
                    now_et = datetime.datetime.now(datetime.timezone.utc).astimezone(ZoneInfo("America/New_York"))
                    if now_et.hour < 8 or now_et.hour >= 12:
                        logging.info(f"⏰ Outside trading hours (8 AM–12 PM ET). Current ET: {now_et.strftime('%H:%M')}. Sleeping 60s...")
                        await asyncio.sleep(60)
                        continue
                else:
                    logging.warning("🚀 FORCE RUN OVERRIDE — trading outside golden hours!")

                if getattr(self, 'done_for_day', False):
                    logging.info("🔒 VAULT LOCKED — daily target hit. Sleeping 60s.")
                    await asyncio.sleep(60)
                    continue

                market_data = await self.find_active_eth_market()
                if not market_data:
                    logging.info("No active 15-min ETH markets found. Sleeping...")
                    await asyncio.sleep(12)
                    continue

                time_left, ticker, close_time = market_data

                self._reset_cycle_state(expired_ticker=None)   

                self.current_market    = ticker
                self.market_close_time = close_time
                self.event_id          = ticker
                self.is_running        = True

                try:
                    pos_res   = await self.api.request("GET", f"/portfolio/positions?ticker={ticker}")
                    positions = pos_res.get("market_positions", [])
                    if positions:
                        p   = positions[0]
                        qty = int(p.get("position", 0))
                        if qty != 0:
                            exposure = p.get("market_exposure", 0)
                            if p.get("average_price_cents") is not None:
                                cost = float(p["average_price_cents"])
                            elif exposure:
                                cost = float(exposure) / abs(qty)
                            else:
                                cost = 50.0

                            if qty > 0:
                                self.yes_inventory[ticker]  = qty
                                self.yes_cost_basis[ticker] = cost
                                logging.info(f"🔄 Restored YES position: {qty} @ {cost:.1f}¢")
                            else:
                                abs_qty = abs(qty)
                                invert_no = self.config.get('no_price_inversion', True)
                                no_cost = (100.0 - cost) if invert_no else cost
                                self.no_inventory[ticker]  = abs_qty
                                self.no_cost_basis[ticker] = no_cost
                                logging.info(f"🔄 Restored NO position: {abs_qty} @ {no_cost:.1f}¢ NO-space")
                except Exception as e:
                    logging.error(f"Position restore failed: {e}. Starting flat.")
                    for d in (self.yes_inventory, self.no_inventory, self.yes_cost_basis, self.no_cost_basis):
                        d.pop(ticker, None)

                await self.update_kalshi_balance()
                logging.info(f"=== Spinning up Event-Driven Engine for {ticker} ===")

                ws_task              = asyncio.create_task(self.listen_to_market_data(ticker))
                inv_task             = asyncio.create_task(self.inventory_manager())
                self.quote_consumer_task = asyncio.create_task(self._quote_consumer())

                completed_tasks = set()
                all_tasks       = {ws_task, inv_task, self.quote_consumer_task}

                while all_tasks:
                    done, pending = await asyncio.wait(all_tasks, return_when=asyncio.FIRST_COMPLETED)
                    completed_tasks |= done

                    for t in done:
                        if t.done() and not t.cancelled():
                            exc = t.exception()
                            if isinstance(exc, CriticalDrawdownException):
                                raise exc

                    all_tasks = pending

                    if ws_task in completed_tasks and inv_task in completed_tasks:
                        self.state_changed.set()
                        for t in list(all_tasks):
                            t.cancel()
                        for t in list(all_tasks):
                            try: await t
                            except (asyncio.CancelledError, Exception): pass
                        break

                if self.quote_consumer_task and not self.quote_consumer_task.done():
                    self.state_changed.set()
                    self.quote_consumer_task.cancel()
                    try: await self.quote_consumer_task
                    except (asyncio.CancelledError, Exception): pass

                _expired = self.event_id   
                if _expired and (_expired in self.yes_inventory or _expired in self.no_inventory):
                    locked_remaining = self.get_locked_pairs(_expired)
                    if locked_remaining > 0:
                        logging.info(f"🏁 FALLBACK SETTLEMENT: {locked_remaining} pair(s) for {_expired}.")
                        self.settle_locked_pairs(_expired)

                    nq, ns = self.get_unbalanced_leg(_expired)
                    if nq > 0:
                        logging.warning(f"💀 {nq} naked {ns} contract(s) expired worthless. Marking as zero-value.")
                        cost_per = self._active_yes_cost(_expired) if ns == "yes" else self._active_no_cost(_expired)
                        loss = -cost_per * nq
                        self.daily_pnl_cents       += loss
                        self.directional_taker_pnl += loss   

                daily_pnl_dollars = getattr(self, 'daily_pnl_cents', 0) / 100.0
                pnl_msg = f"📊 Market Closed: {_expired}\n💰 Cumulative Daily PnL: {daily_pnl_dollars:+.2f}$"
                logging.info(pnl_msg)
                self._log_pnl_breakdown()
                self.save_daily_pnl()

                now = time.time()
                if getattr(self, 'last_pnl_telegram_time', 0) == 0 or now - self.last_pnl_telegram_time >= 900:
                    await TelegramAlerts.send(pnl_msg)
                    self.last_pnl_telegram_time = now

                self._reset_cycle_state(expired_ticker=_expired)
                await asyncio.sleep(12)

        except CriticalDrawdownException as e:
            logging.critical(f"💀 CRITICAL DRAWDOWN: {e}. Stopping event loop.")
            await self.cancel_active_orders()
            _nq, _ = self.get_unbalanced_leg(self.event_id)
            if _nq > 0:
                try: await self.execute_hybrid_exit("DEFENSIVE_VELOCITY")
                except Exception as ex: logging.error(f"Drawdown exit failed: {ex}")
            if self.quote_consumer_task and not self.quote_consumer_task.done():
                self.state_changed.set()
                self.quote_consumer_task.cancel()
                try: await self.quote_consumer_task
                except (asyncio.CancelledError, Exception): pass
            binance_task.cancel()
            binance_futures_task.cancel()
            await TelegramAlerts.send(f"🛑 CRITICAL DRAWDOWN: Bot stopped. {e}")
            asyncio.get_running_loop().stop()

        except asyncio.CancelledError:
            logging.info("Task cancelled. Graceful shutdown initiated...")
            await self.cancel_active_orders()
            if self.quote_consumer_task and not self.quote_consumer_task.done():
                self.state_changed.set()
                self.quote_consumer_task.cancel()
                try: await self.quote_consumer_task
                except (asyncio.CancelledError, Exception): pass
            binance_task.cancel()
            binance_futures_task.cancel()
            await TelegramAlerts.send("Bot shut down gracefully via Cancellation.")

        except KeyboardInterrupt:
            logging.info("Keyboard interrupt. Graceful shutdown initiated...")
            await self.cancel_active_orders()
            if self.quote_consumer_task and not self.quote_consumer_task.done():
                self.state_changed.set()
                self.quote_consumer_task.cancel()
                try: await self.quote_consumer_task
                except (asyncio.CancelledError, Exception): pass
            binance_task.cancel()
            binance_futures_task.cancel()
            await TelegramAlerts.send("Bot shut down gracefully. Open orders canceled.")

        finally:
            await self.api.close_session()

if __name__ == "__main__":
    bot = AsyncStoikovSentinel()
    try:
        asyncio.run(bot.run())
    except KeyboardInterrupt:
        pass
    except RuntimeError:
        pass
