"""
MomentumWolf_BTC.py
Sentinel connection layer (verbatim) + Wolf directional strategy.

Plumbing source:  StoikovSentinel_v7_Aggressive.py
  - AsyncKalshiClient  (aiohttp, ThreadPoolExecutor signing, PSS.MAX_LENGTH)
  - TelegramAlerts     (aiohttp static)
  - listen_to_binance_ws         (.us stream, while-True exponential backoff)
  - listen_to_binance_futures_ws (fstream.binance.com, same pattern)
  - listen_to_market_data        (auth headers on HTTP upgrade, Sentinel field names)
  - _update_ofi                  (full BBO OFI with prev-state tracking)

Strategy source:  MomentumWolf_v1.py
  - calculate_momentum_score / execute_pyramid_strike / manage_wolf_exits
  - Nuclear risk hierarchy (6 guards)
  - AuditorV3 async I/O (asyncio.to_thread)
  - YAML config room
"""

import os
import math
import time
import base64
import uuid
import asyncio
import logging
import logging.handlers
import concurrent.futures
import yaml
import datetime
from collections import deque

try:
    import orjson as json
    def _json_str(obj) -> str:
        return json.dumps(obj).decode("utf-8")
except ImportError:
    import json
    _json_str = json.dumps
    logging.warning("orjson not installed — stdlib json fallback.")

import aiohttp
import websockets
from dataclasses import dataclass, field
from dotenv import load_dotenv
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

load_dotenv()

KALSHI_KEY_ID           = os.getenv("KALSHI_KEY_ID")
KALSHI_PRIVATE_KEY_PATH = os.getenv("KALSHI_PRIVATE_KEY_PATH")
TELEGRAM_BOT_TOKEN      = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID        = os.getenv("TELEGRAM_CHAT_ID")

BASE_URL = "https://api.elections.kalshi.com/trade-api/v2"
WS_URL   = "wss://api.elections.kalshi.com/trade-api/ws/v2"

# ThreadPoolExecutor for async RSA signing — verbatim Sentinel
_SIGN_EXECUTOR = concurrent.futures.ThreadPoolExecutor(
    max_workers=2, thread_name_prefix="kalshi_signer"
)

# ── Logging (verbatim Sentinel) ───────────────────────────────────────────────
from logging.handlers import RotatingFileHandler
_fmt = logging.Formatter("%(asctime)s | %(levelname)s | %(message)s")
_fh  = RotatingFileHandler("ChopWolf_BTC.log", maxBytes=10*1024*1024, backupCount=5)
_fh.setFormatter(_fmt);  _fh.setLevel(logging.DEBUG)
_ch  = logging.StreamHandler()
_ch.setFormatter(_fmt);  _ch.setLevel(logging.INFO)
_root = logging.getLogger()
_root.handlers = []
_root.addHandler(_fh)
_root.addHandler(_ch)
_root.setLevel(logging.DEBUG)
logging.getLogger("websockets").setLevel(logging.WARNING)
logging.getLogger("aiohttp").setLevel(logging.WARNING)

# ─────────────────────────────────────────────────────────────────────────────
# EXCEPTIONS
# ─────────────────────────────────────────────────────────────────────────────

class CriticalDrawdownException(BaseException):
    """Inherits BaseException so it is never swallowed by except Exception."""
    pass

class GuillotineException(Exception):
    pass

class DislocationEjectorException(Exception):
    pass

# ─────────────────────────────────────────────────────────────────────────────
# FILE I/O HELPER  (asyncio.to_thread dispatch target — never called inline)
# ─────────────────────────────────────────────────────────────────────────────

def _append_line(path: str, line: str) -> None:
    with open(path, "a") as fh:
        fh.write(line)

# ─────────────────────────────────────────────────────────────────────────────
# TELEGRAM ALERTS  (verbatim Sentinel — static aiohttp pattern)
# ─────────────────────────────────────────────────────────────────────────────

class TelegramAlerts:
    _session: aiohttp.ClientSession | None = None

    @classmethod
    async def start(cls):
        if cls._session is None or cls._session.closed:
            cls._session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=5))

    @classmethod
    async def close(cls):
        if cls._session and not cls._session.closed:
            await cls._session.close()

    @classmethod
    async def send(cls, message: str):
        if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID or cls._session is None or cls._session.closed:
            return
        url     = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        payload = {"chat_id": TELEGRAM_CHAT_ID, "text": f"🐺 CHOPWOLF\n{message}"}
        try:
            await cls._session.post(url, json=payload)
        except Exception as e:
            logging.error(f"Telegram failed: {e}")

# ─────────────────────────────────────────────────────────────────────────────
# ASYNC KALSHI CLIENT  (verbatim Sentinel)
#   - aiohttp session with start/close lifecycle
#   - _sign_request: PSS.MAX_LENGTH, strips query params, returns full headers dict
#   - _sign_request_async: offloads to ThreadPoolExecutor
#   - request: 4-attempt retry with 429 exponential backoff
# ─────────────────────────────────────────────────────────────────────────────

class AsyncKalshiClient:
    def __init__(self, key_id: str, key_path: str, base_url: str):
        self.key_id   = key_id
        self.base_url = base_url
        self.session: aiohttp.ClientSession | None = None
        with open(key_path, "rb") as key_file:
            self.private_key = serialization.load_pem_private_key(
                key_file.read(), password=None, backend=default_backend()
            )

    async def start_session(self):
        if self.session is None or self.session.closed:
            self.session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=5)
            )

    async def close_session(self):
        if self.session and not self.session.closed:
            await self.session.close()

    def _sign_request(self, method: str, path: str) -> dict:
        path_without_query = path.split("?")[0]
        timestamp = str(int(datetime.datetime.now().timestamp() * 1000))
        message   = timestamp + method + path_without_query
        signature = self.private_key.sign(
            message.encode("utf-8"),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return {
            "KALSHI-ACCESS-KEY":       self.key_id,
            "KALSHI-ACCESS-SIGNATURE": base64.b64encode(signature).decode("utf-8"),
            "KALSHI-ACCESS-TIMESTAMP": timestamp,
            "Content-Type":            "application/json",
        }

    async def _sign_request_async(self, method: str, path: str) -> dict:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(_SIGN_EXECUTOR, self._sign_request, method, path)

    async def request(self, method: str, endpoint: str, body=None) -> dict:
        if self.session is None or self.session.closed:
            await self.start_session()
        path = f"/trade-api/v2{endpoint}"
        url  = self.base_url + endpoint
        for attempt in range(4):
            headers = await self._sign_request_async(method, path)
            try:
                async with self.session.request(
                    method, url, headers=headers, json=body
                ) as r:
                    if r.status == 429:
                        await r.read()
                        backoff = [0.2, 0.5, 1.0, 2.0][attempt] if attempt < 4 else 2.0
                        logging.warning(f"🛑 429 rate limit. Backoff {backoff}s...")
                        await asyncio.sleep(backoff)
                        continue
                    text = await r.text()
                    if r.status >= 400 and r.status not in (404, 409):
                        logging.error(f"API {r.status} on {method} {endpoint}: {text[:200]}")
                    try:
                        return json.loads(text)
                    except Exception:
                        return {}
            except Exception as e:
                logging.error(f"API request failed: {e}")
                return {}
        logging.error("❌ Max retries exhausted.")
        return {}

# ─────────────────────────────────────────────────────────────────────────────
# AUDITOR V3  (async I/O — asyncio.to_thread, event loop never blocks)
# ─────────────────────────────────────────────────────────────────────────────

class AuditorV3:
    def __init__(self, jsonl_path: str, pnl_path: str):
        self.jsonl_path = jsonl_path
        self.pnl_path   = pnl_path
        self.log        = logging.getLogger("ChopWolf")

    async def record(self, event: str, data: dict):
        entry = {
            "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "event": event,
            **data,
        }
        line = _json_str(entry) + "\n"
        self.log.info("[%s] %s", event, data)
        await asyncio.to_thread(_append_line, self.jsonl_path, line)

    async def pnl_snapshot(self, realized_cents: float, unrealized_cents: float):
        line = (
            f"{datetime.datetime.now(datetime.timezone.utc).isoformat()} | "
            f"realized={realized_cents:.2f}c | unrealized={unrealized_cents:.2f}c\n"
        )
        await asyncio.to_thread(_append_line, self.pnl_path, line)

# ─────────────────────────────────────────────────────────────────────────────
# INVENTORY MANAGER  (single-leg directional)
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class InventoryManager:
    yes_qty:        int   = 0
    no_qty:         int   = 0
    yes_cost_cents: float = 0.0   # total accumulated YES cost in YES-space cents
    no_cost_cents:  float = 0.0   # total accumulated NO cost in NO-space cents
    realized_cents: float = 0.0

    def _active_yes_cost(self) -> float:
        """Average cost per YES contract in YES-space cents."""
        if self.yes_qty == 0:
            return 0.0
        return self.yes_cost_cents / self.yes_qty

    def _active_no_cost(self) -> float:
        """Average cost per NO contract in NO-space cents."""
        if self.no_qty == 0:
            return 0.0
        return self.no_cost_cents / self.no_qty

    def _apply_fill_to_inventory(
        self, side: str, qty: int, price_cents: float, action: str
    ):
        """
        price_cents must be in the side's own space:
          YES fills → YES-space cents
          NO fills  → NO-space cents (already inverted from YES-space by fill handler)
        """
        TAKER_FEE_CENTS = 0.0  # Resting grid legs are maker fills (0 fee)
        if side == "yes":
            if action == "buy":
                self.yes_qty        += qty
                self.yes_cost_cents += qty * price_cents
            else:
                avg_cost             = self._active_yes_cost()
                self.realized_cents += (qty * (price_cents - avg_cost)) - (TAKER_FEE_CENTS * qty)
                self.yes_qty        -= qty
                self.yes_cost_cents -= qty * avg_cost
                if self.yes_qty < 0:
                    # ALLOW NEGATIVE INVENTORY: Kalshi allows shorting (selling YES you don't own = NO pos).
                    # Do NOT clamp to 0. Allowing it to track negatively ensures subsequent buys
                    # mathematically reconcile with Kalshi's backend.
                    logging.critical(f"🚨 GHOST FILL (SHORT POS): yes_qty dropped to {self.yes_qty}. Tracking natively.")
                    self.yes_cost_cents = 0.0  # Clear cost basis for the short side
                elif self.yes_qty == 0:
                    self.yes_cost_cents = 0.0
        else:   # "no"
            if action == "buy":
                self.no_qty        += qty
                self.no_cost_cents += qty * price_cents
            else:
                avg_cost             = self._active_no_cost()
                self.realized_cents += (qty * (price_cents - avg_cost)) - (TAKER_FEE_CENTS * qty)
                self.no_qty        -= qty
                self.no_cost_cents -= qty * avg_cost
                if self.no_qty < 0:
                    # ALLOW NEGATIVE INVENTORY: mirror of YES-side logic — track natively, do not clamp.
                    logging.critical(f"🚨 GHOST FILL (SHORT POS): no_qty dropped to {self.no_qty}. Tracking natively.")
                    self.no_cost_cents = 0.0  # Clear cost basis for the short side
                elif self.no_qty == 0:
                    self.no_cost_cents = 0.0

    def open_position(self) -> int:
        return self.yes_qty + self.no_qty

    def unrealized_cents(self, current_yes_price: float) -> float:
        """
        current_yes_price: live YES mid in cents (always YES-space).
        YES PnL: (current YES price - avg YES cost) × qty
        NO PnL:  (current NO price  - avg NO cost)  × qty
                 where current NO price = 100 - current YES price
        avg costs are per-contract, in their respective spaces.
        """
        pnl = 0.0
        if self.yes_qty > 0:
            avg_yes_cost = self._active_yes_cost()
            pnl += self.yes_qty * (current_yes_price - avg_yes_cost)
        if self.no_qty > 0:
            current_no_price = 100.0 - current_yes_price
            avg_no_cost      = self._active_no_cost()
            pnl             += self.no_qty * (current_no_price - avg_no_cost)
        return pnl

    def net_unrealized_cents(self, current_yes_price: float) -> float:
        """
        Gross unrealized PnL minus Kalshi taker round-trip fee (3.6¢ per open contract).
        Use this for all exit decisions so profit targets are compared against
        what we actually keep after fees — not the pre-fee gross.
        3.6¢ ≈ 2 × 1.75¢ taker fee (entry + exit) rounded up for safety margin.
        """
        TAKER_FEE_CENTS = 1.7  # Honest exit taker fee per contract (~1.7¢ on Kalshi)
        gross           = self.unrealized_cents(current_yes_price)
        return gross - (TAKER_FEE_CENTS * self.open_position())

# ─────────────────────────────────────────────────────────────────────────────
# QUOTE MANAGER  (replaces GridManager)
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class QuoteManager:
    """
    Lightweight bookkeeper for the two-sided quote ladder.
    Unlike GridManager, this object does NOT own grid prices —
    prices are recomputed every scan tick from the live oracle center.
    It only tracks which price levels already have resting orders
    to prevent double-placement.
    """
    levels:          int   = 2
    base_qty:        int   = 4
    spacing:         float = 3.0
    trailing_thresh: float = 4.0
    center:          float = 50.0
    decay_start_sec: float = 360.0
    decay_half_life: float = 150.0

    placed_buy_prices:  set = field(default_factory=set)
    placed_sell_prices: set = field(default_factory=set)

    def should_reanchor(self, oracle_center: float) -> bool:
        return abs(oracle_center - self.center) > self.trailing_thresh

    def reanchor(self, new_center: float):
        self.center = new_center
        self.placed_buy_prices.clear()
        self.placed_sell_prices.clear()

    def get_decay_metrics(self, seconds_left: float) -> tuple:
        """Returns (spread_multiplier, qty_after_decay)."""
        if seconds_left > self.decay_start_sec:
            return 1.0, self.base_qty
        elapsed   = self.decay_start_sec - seconds_left
        ratio     = math.exp(-0.693 * elapsed / self.decay_half_life)
        spread_m  = min(1.0 + (1.0 - ratio), 2.0)
        qty       = max(1, int(self.base_qty * ratio + 0.5))
        return spread_m, qty


# ─────────────────────────────────────────────────────────────────────────────
# CHOP WOLF BTC
# ─────────────────────────────────────────────────────────────────────────────

class ChopWolf:

    def __init__(self, config_path: str = "wolf_config_tightchop_btc.yaml"):
        with open(config_path) as fh:
            self.config: dict = yaml.safe_load(fh)

        self.api = AsyncKalshiClient(KALSHI_KEY_ID, KALSHI_PRIVATE_KEY_PATH, BASE_URL)
        self.auditor = AuditorV3(
            jsonl_path = self.config["jsonl_path"],
            pnl_path   = self.config.get("pnl_path", "pnl_tracker_btc.txt"),
        )

        # ── Binance oracle state (Sentinel variable names preserved) ────────
        self.live_btc_price:       float | None            = None
        self.btc_price_history:    list                    = []
        self.futures_price:        float | None            = None
        self.perp_basis:           float                   = 0.0
        self.basis_ema:            float                   = 0.0
        self.basis_shift:          float                   = 0.0
        self.velocity_ema:         float                   = 0.0

        # OFI state (verbatim Sentinel _update_ofi)
        self.ofi_prev_bid_price:   float | None            = None
        self.ofi_prev_bid_qty:     float                   = 0.0
        self.ofi_prev_ask_price:   float | None            = None
        self.ofi_prev_ask_qty:     float                   = 0.0
        self.ofi_ema:              float                   = 0.0
        self.ofi_scalar:           float                   = 0.0

        # ── Kalshi WS live price (Sentinel field names, cents) ───────────────
        self.live_exchange_bid:    float                   = 0.0
        self.live_exchange_ask:    float                   = 0.0
        self.ws_price_valid:       bool                    = False
        # L2 BBO quantity — contracts available at best bid / best ask
        self.live_exchange_bid_qty: int                    = 0
        self.live_exchange_ask_qty: int                    = 0

        # ── Cycle / session state ────────────────────────────────────────────
        self.is_running:           bool                    = False
        self.active_ticker:        str | None              = None
        self.market_close_time:    datetime.datetime | None = None
        self.active_side:          str | None              = None
        self.pyramid_step:         int                     = 0
        self.cycle_entry_time:     float | None            = None
        self.session_peak_pnl:     float                   = 0.0
        self.cycle_start_pnl:      float                   = 0.0   # anchor: Telegram reports per-cycle delta, not cumulative
        self.trade_peak_unrealized:float                   = 0.0
        self._scale_t1_done:       bool                    = False
        self._scale_t2_done:       bool                    = False
        self.seen_trade_ids:       deque                   = deque(maxlen=5000)
        self.pending_orders:       dict                    = {}   # {kalshi_id: metadata}
        self.ws_last_msg_time:     float                   = time.time()
        self._strike_in_flight:    bool                    = False
        self._dump_in_flight:      bool                    = False   # fast-fail flag: prevents re-entry
        self._dump_lock:           asyncio.Lock | None     = None    # bound lazily in run() to active loop
        self._inventory_lock:      asyncio.Lock | None     = None    # bound lazily in run() to active loop
        self._bg_tasks:            set                     = set()   # GC anchor: strong refs to fire-and-forget tasks
        self._last_heartbeat_time: float                   = 0.0
        self._last_rest_sync: float                        = 0.0
        self._last_stalled_log_time: float                 = 0.0
        self.score_history:        deque                   = deque(maxlen=5)   # first-derivative gate
        self.kalshi_bid_history:   list                    = []      # Kalshi-native velocity tracking
        self.kalshi_velocity:      float                   = 0.0     # cents/second from Kalshi ticker
        self._last_sigma_sq:       float                   = 4.0     # persists σ² across cycles for cold-start
        self._oracle_center_history: list                  = []      # (timestamp, center) for stability check
        self.current_balance:      float                   = 100.0   # guard 3: updated per-cycle from API
        # Exit-tracking state (anti-whipsaw, post-TP exhaustion)
        self.last_exit_reason:     str | None              = None
        self.last_exit_time:       float                   = 0.0
        self.last_exit_price:      float                   = 0.0     # yes_mid at exit
        self.last_exit_side:       str | None              = None
        self.inventory                                     = InventoryManager()
        self.blacklisted_tickers:      dict                = {}      # Burned Hand: {ticker: cooldown_expiry_timestamp}

        # ── Scratch engine state (TightChop additions) ───────────────────────
        self._last_scratch_time:       float      = 0.0
        self._scratch_active:          bool       = False
        self._scratch_order_id:        str | None = None
        self._pride_override_logged:   bool       = False

    # ─────────────────────────────────────────────────────────────────────────
    # BINANCE SPOT WS  (verbatim Sentinel — .us stream, exponential backoff)
    # ─────────────────────────────────────────────────────────────────────────

    async def listen_to_binance_ws(self):
        uri = "wss://stream.binance.us:9443/stream?streams=btcusdt@aggTrade/btcusdt@bookTicker"
        logging.info("Connecting to Binance Combined Spot WS (BTC aggTrade + bookTicker)...")
        reconnect_delay = 5
        while True:
            try:
                async with websockets.connect(uri) as ws:
                    reconnect_delay = 5
                    logging.info("✅ Connected to Binance Combined BTC Spot feed (OFI active).")
                    while True:
                        message     = await ws.recv()
                        envelope    = json.loads(message)
                        stream_name = envelope.get("stream", "")
                        msg_data    = envelope.get("data", envelope)

                        if stream_name == "btcusdt@aggTrade":
                            price = float(msg_data.get("p", 0))
                            if price > 0:
                                now = time.time()
                                self.live_btc_price = price
                                self.btc_price_history.append((now, price))
                                self.btc_price_history = [x for x in self.btc_price_history if now - x[0] <= 15]

                        elif stream_name.endswith("@bookTicker"):
                            try:
                                bp = float(msg_data["b"])
                                bq = float(msg_data["B"])
                                ap = float(msg_data["a"])
                                aq = float(msg_data["A"])
                                if bp > 0.0 and ap > 0.0:
                                    self._update_ofi(bp, bq, ap, aq)
                                    # FALLBACK: If aggTrade is dead, use BBO mid-price to warm up the oracle
                                    if self.live_btc_price is None:
                                        self.live_btc_price = (bp + ap) / 2.0
                                        logging.info(f"✅ Spot oracle warmed via BBO mid = ${self.live_btc_price:,.2f}")
                            except (KeyError, ValueError, TypeError):
                                pass

            except Exception as e:
                logging.warning(f"Binance WS dropped. Reconnecting in {reconnect_delay}s...")
                await asyncio.sleep(reconnect_delay)
                reconnect_delay = min(60, reconnect_delay * 2)

    # ─────────────────────────────────────────────────────────────────────────
    # _update_ofi  (verbatim Sentinel — full BBO OFI with prev-state tracking)
    # ─────────────────────────────────────────────────────────────────────────

    def _update_ofi(
        self, bid_price: float, bid_qty: float, ask_price: float, ask_qty: float
    ) -> None:
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

        raw_ofi         = e - f
        clamped_raw_ofi = max(-500.0, min(500.0, raw_ofi))
        alpha           = float(self.config.get("ofi_alpha", 0.3))
        self.ofi_ema    = (alpha * clamped_raw_ofi) + ((1.0 - alpha) * self.ofi_ema)
        normalizer   = float(self.config.get("ofi_normalizer", 50.0))
        if normalizer > 0.0:
            self.ofi_scalar = max(-1.0, min(1.0, self.ofi_ema / normalizer))

        self.ofi_prev_bid_price = bid_price
        self.ofi_prev_bid_qty   = bid_qty
        self.ofi_prev_ask_price = ask_price
        self.ofi_prev_ask_qty   = ask_qty

    # ─────────────────────────────────────────────────────────────────────────
    # BINANCE FUTURES WS  (verbatim Sentinel — fstream.binance.com)
    # Adds: basis/shift/velocity computation on every perp tick.
    # ─────────────────────────────────────────────────────────────────────────

    async def listen_to_binance_futures_ws(self):
        uri = "wss://fstream.binance.com/ws/btcusdt@ticker"
        logging.info("Connecting to Binance Futures WS (Perp Basis feed)...")
        reconnect_delay = 5
        prev_perp       = 0.0
        while True:
            try:
                async with websockets.connect(uri) as ws:
                    reconnect_delay = 5
                    logging.info("✅ Connected to Binance Futures BTC Perp feed.")
                    while True:
                        message    = await ws.recv()
                        data       = json.loads(message)
                        last_price = float(data.get("c", 0))
                        if last_price > 0:
                            self.futures_price = last_price
                            # Basis / shift
                            safe_spot = float(self.live_btc_price or 0.0)
                            if safe_spot > 0:
                                self.perp_basis  = last_price - safe_spot
                                self.basis_ema   = (self.perp_basis * 0.08) + (self.basis_ema * 0.92)
                                self.basis_shift = self.perp_basis - self.basis_ema
                            # Velocity EMA (tick-to-tick perp change)
                            if prev_perp > 0:
                                vel_alpha         = float(self.config.get("velocity_alpha", 0.3))
                                vel               = ((last_price - prev_perp) / prev_perp) * 10000.0
                                clamped_vel       = max(-100.0, min(100.0, vel))
                                self.velocity_ema = (vel_alpha * clamped_vel) + ((1 - vel_alpha) * self.velocity_ema)
                            prev_perp = last_price

            except Exception as e:
                logging.warning(f"Binance Futures WS dropped. Reconnecting in {reconnect_delay}s...")
                prev_perp = 0.0   # reset stale price — prevents fake velocity spike on reconnect
                await asyncio.sleep(reconnect_delay)
                reconnect_delay = min(60, reconnect_delay * 2)

    # ─────────────────────────────────────────────────────────────────────────
    # KALSHI WS  (Sentinel connection pattern — auth on HTTP upgrade)
    # Fill/ticker handler adapted for Wolf's single-leg directional inventory.
    # ─────────────────────────────────────────────────────────────────────────

    async def listen_to_market_data(self, ticker: str):
        """
        Kalshi WS with exponential backoff reconnection (1 → 2 → 4 → 8s cap).
        Sets ws_price_valid = False the moment a disconnect is detected so the
        scanner stops trading blind while the feed is down.
        Captures L2 BBO quantity (yes_bid_size / yes_ask_size) for liquidity checks.
        """
        ws_path         = "/trade-api/ws/v2"
        reconnect_delay = 1   # exponential backoff: 1, 2, 4, 8 (capped)

        while self.is_running:
            try:
                # Fresh signature on every connect — verbatim Sentinel
                auth_headers = await self.api._sign_request_async("GET", ws_path)
                async with websockets.connect(
                    WS_URL, additional_headers=auth_headers
                ) as ws:
                    reconnect_delay = 1   # reset on successful connection
                    subscribe_msg = {
                        "id":  1,
                        "cmd": "subscribe",
                        "params": {
                            "channels":       ["ticker", "fill"],
                            "market_tickers": [ticker],
                        },
                    }
                    await ws.send(_json_str(subscribe_msg))
                    logging.info(f"✅ Kalshi WS subscribed: {ticker}")

                    while self.is_running:
                        try:
                            message = await asyncio.wait_for(ws.recv(), timeout=1.0)
                        except asyncio.TimeoutError:
                            continue
                        except websockets.exceptions.ConnectionClosed:
                            # Feed dropped — stop trading blind immediately.
                            # Zero L2 qty so the liquidity guard blocks all strikes
                            # until the feed reconnects and delivers fresh BBO depth.
                            self.ws_price_valid        = False
                            self.live_exchange_bid_qty = 0
                            self.live_exchange_ask_qty = 0
                            logging.warning("[WS_RECONNECTING] Kalshi WS dropped — price and L2 marked stale.")
                            break

                        data     = json.loads(message)
                        msg_type = data.get("type")

                        if msg_type == "fill":
                            self.ws_last_msg_time = time.time()
                            await self._process_directional_fill_confirmation(data)

                        elif msg_type == "ticker":
                            self.ws_last_msg_time = time.time()
                            msg_data = data.get("msg", {})
                            # Sentinel field names: yes_bid_dollars (fractional) × 100 = cents
                            raw_bid = msg_data.get("yes_bid_dollars")
                            raw_ask = msg_data.get("yes_ask_dollars")
                            if raw_bid is not None:
                                self.live_exchange_bid = float(raw_bid) * 100.0
                            if raw_ask is not None:
                                self.live_exchange_ask = float(raw_ask) * 100.0
                            if raw_bid is not None and raw_ask is not None:
                                self.ws_price_valid = True

                            # L2 BBO quantity — fixed-point string fields (Kalshi V2 API)
                            # Keys changed from yes_bid_size / yes_ask_size (deprecated int)
                            # to yes_bid_size_fp / yes_ask_size_fp (string, e.g. "15.000").
                            raw_bid_sz = msg_data.get("yes_bid_size_fp")
                            raw_ask_sz = msg_data.get("yes_ask_size_fp")
                            if raw_bid_sz is not None:
                                try:
                                    self.live_exchange_bid_qty = int(float(raw_bid_sz))
                                except (ValueError, TypeError):
                                    pass
                            if raw_ask_sz is not None:
                                try:
                                    self.live_exchange_ask_qty = int(float(raw_ask_sz))
                                except (ValueError, TypeError):
                                    pass

                            # Kalshi-native velocity: cents-per-second from bid history
                            if raw_bid is not None:
                                now_t = time.time()
                                self.kalshi_bid_history.append((now_t, self.live_exchange_bid))
                                self.kalshi_bid_history = [
                                    x for x in self.kalshi_bid_history
                                    if now_t - x[0] <= 20.0
                                ]
                                if len(self.kalshi_bid_history) >= 2:
                                    oldest_ts, oldest_price = self.kalshi_bid_history[0]
                                    elapsed = now_t - oldest_ts
                                    if elapsed > 0.5:
                                        raw_kv = (
                                            self.live_exchange_bid - oldest_price
                                        ) / elapsed
                                        self.kalshi_velocity = raw_kv  # UNCLAMPED — let oracle track flash crashes

                                    # Fast EMA kalshi velocity (3-tick half-life) to catch instant local drops
                                    if hasattr(self, '_prev_kalshi_bid') and self._prev_kalshi_bid > 0:
                                        tick_vel = self.live_exchange_bid - self._prev_kalshi_bid
                                        self.kalshi_velocity_fast = 0.5 * tick_vel + 0.5 * getattr(self, 'kalshi_velocity_fast', 0.0)
                                    self._prev_kalshi_bid = self.live_exchange_bid

            except Exception as e:
                if self.is_running:
                    self.ws_price_valid = False   # stop trading blind
                    await self.auditor.record("WS_RECONNECTING", {
                        "error": str(e), "retry_in": reconnect_delay,
                    })
                    logging.warning(
                        f"[WS_RECONNECTING] Kalshi WS error: {e}. "
                        f"Retrying in {reconnect_delay}s..."
                    )
                    await asyncio.sleep(reconnect_delay)
                    reconnect_delay = min(reconnect_delay * 2, 8)

    async def _process_directional_fill_confirmation(self, data: dict):
        """
        Single-leg fill handler.
        Price extraction logic verbatim from Sentinel (handles all WS field variants).
        Applies fill to Wolf's InventoryManager after NO-price inversion.
        """
        fill_data = data.get("msg", {})
        trade_id  = fill_data.get("trade_id")
        if not trade_id or trade_id in self.seen_trade_ids:
            return
        self.seen_trade_ids.append(trade_id)

        action = fill_data.get("action")
        if action not in ("buy", "sell"):
            logging.critical(f"🚨 FILL ACTION INVALID ({action}) — trade_id={trade_id}. Syncing REST.")
            _sync_task = asyncio.create_task(self._sync_position_from_api(self.active_ticker))
            self._bg_tasks.add(_sync_task)
            _sync_task.add_done_callback(self._bg_tasks.discard)
            return

        side      = fill_data.get("side")
        raw_count = fill_data.get("count") or fill_data.get("count_fp")
        if not raw_count or float(raw_count) <= 0:
            logging.critical(f"🚨 FILL COUNT MISSING OR ZERO — trade_id={trade_id}. Syncing REST.")
            _sync_task = asyncio.create_task(self._sync_position_from_api(self.active_ticker))
            self._bg_tasks.add(_sync_task)
            _sync_task.add_done_callback(self._bg_tasks.discard)
            return
        count          = int(round(float(raw_count)))
        purchased_side = fill_data.get("purchased_side")

        # ── Price extraction — native-space-first ──────────────────────────
        # For YES fills: price is always in YES-space; no inversion needed.
        # For NO fills: prefer native NO-space fields (no_price_dollars / no_price)
        # to avoid double-inversion if Kalshi returns NO-native prices.
        # Only fall back to YES-space fields and invert if native NO fields absent.
        price       = None
        in_no_space = False   # True when price arrived via native NO-space field

        if purchased_side == "yes" or side == "yes":
            price = (
                fill_data.get("yes_price_dollars") or
                fill_data.get("yes_price") or
                (fill_data.get("order") or {}).get("yes_price_dollars") or
                (fill_data.get("trade") or {}).get("yes_price_dollars") or
                fill_data.get("price")
            )
        elif purchased_side == "no" or side == "no":
            _raw_no = (
                fill_data.get("no_price_dollars") or
                fill_data.get("no_price")
            )
            if _raw_no:
                price       = _raw_no
                in_no_space = True
            else:
                # Native NO fields absent — fall back to YES-space; invert below.
                price = (
                    fill_data.get("yes_price_dollars") or
                    fill_data.get("yes_price") or
                    (fill_data.get("order") or {}).get("yes_price_dollars") or
                    (fill_data.get("trade") or {}).get("yes_price_dollars") or
                    fill_data.get("price")
                )

        if price is not None:
            try:
                price = float(price)
                if price < 1.0:
                    price *= 100.0   # fractional dollars → cents
            except (ValueError, TypeError):
                price = None

        if price is None or price == 0.0:
            # Do NOT fabricate a cost basis. Bail and let REST reconcile ground truth.
            logging.critical(
                f"🚨 FILL PRICE MISSING — cost-basis corruption averted. "
                f"trade_id={trade_id} keys={list(fill_data.keys())}"
            )
            t = asyncio.create_task(self._sync_position_from_api(self.active_ticker))
            self._bg_tasks.add(t)
            t.add_done_callback(self._bg_tasks.discard)
            return

        # ── NO-space conversion: invert only when price arrived in YES-space ──
        # If in_no_space is True the price is already in NO-space — inversion
        # would corrupt the cost basis (double-inversion hallucinated-profit bug).
        # Strictly use side (our order's field) — purchased_side can be "no" on YES sells,
        # which would incorrectly trigger inversion and hallucinate phantom profit.
        if side == "no" and not in_no_space:
            yes_space = price
            price     = 100.0 - yes_space   # YES-space → NO-space cents
            logging.info(f"🔄 NO FILL (YES-fallback): YES {yes_space:.1f}¢ → NO cost {price:.1f}¢")

        # ── Apply to inventory ─────────────────────────────────────────────
        order_id = fill_data.get("order_id", "")
        if order_id in self.pending_orders:
            meta = self.pending_orders[order_id]
            meta["qty"] -= count
            if meta["qty"] <= 0:
                self.pending_orders.pop(order_id)

        async with self._inventory_lock:
            self.inventory._apply_fill_to_inventory(side, count, price, action)
        await self.auditor.record("WS_FILL", {
            "order_id": order_id, "side": side,
            "qty": count, "price": price, "action": action,
        })

        # Ensure resting sells do not exceed physical inventory
        resting_sell_qty = sum(m.get("qty", 0) for m in self.pending_orders.values() if m.get("action") == "sell")
        if resting_sell_qty > self.inventory.yes_qty:
            logging.warning(f"⚠️ SELL OVERHANG: resting sells ({resting_sell_qty}) > inventory ({self.inventory.yes_qty}). Sweeping book.")
            _sweep_task = asyncio.create_task(self.cancel_active_orders())
            self._bg_tasks.add(_sweep_task)
            _sweep_task.add_done_callback(self._bg_tasks.discard)

    # ─────────────────────────────────────────────────────────────────────────
    # NUCLEAR RISK HIERARCHY  (Ironclad — Wolf math verbatim)
    # ─────────────────────────────────────────────────────────────────────────

    def _check_guillotine(self, yes_mid: float):
        # WS blip guard — stale/dropped feed must not trigger a stop
        if self.live_exchange_bid <= 0.0 or self.live_exchange_ask <= 0.0:
            return

        cfg = self.config
        pos = self.inventory.open_position()

        if pos > 0:
            # Compute once — reused for both instant gap check and standard naked check
            naked        = -self.inventory.unrealized_cents(yes_mid)
            max_loss     = float(cfg["hard_stop_naked_cents"]) * pos

            # Hard Take Profit: Sweep the book if per-contract profit target is hit
            unrealized_pnl = self.inventory.unrealized_cents(yes_mid)
            tp_limit = float(cfg.get("take_profit_per_contract_cents", 999.0)) * pos
            if unrealized_pnl >= tp_limit:
                raise GuillotineException(f"TAKE_PROFIT: Target hit at {unrealized_pnl:.2f}c")

            # Spread guard: a blown spread signals an illiquid quote, not a real gap move.
            # Suppresses the instant gap check only — velocity shield and hard stop fire unconditionally.
            live_spread  = self.live_exchange_ask - self.live_exchange_bid
            spread_blown = live_spread > cfg.get("spread_blown_threshold_cents", 10.0)

            # Instant Gap Stop-Loss: fires first, threshold scales with position size.
            # Bypassed when spread is blown to avoid phantom stop-outs on stale/crossed quotes.
            gap_limit = float(cfg.get("guillotine_gap_cents", 8.0)) * pos
            if not spread_blown and naked >= gap_limit:
                raise GuillotineException(
                    f"INSTANT_GAP_STOP: gap loss {naked:.2f}c"
                )

            # Directional velocity gate — only raise on adverse momentum
            threshold = cfg["guillotine_velocity_threshold"]
            if self.active_side == "yes" and self.velocity_ema < -threshold:
                raise GuillotineException(f"velocity_ema={self.velocity_ema:.4f} < -threshold (YES side)")
            elif self.active_side == "no" and self.velocity_ema > threshold:
                raise GuillotineException(f"velocity_ema={self.velocity_ema:.4f} > threshold (NO side)")

            # Absolute hard stop: gated behind spread guard — same reasoning as gap stop above.
            if not spread_blown and naked > max_loss:
                raise GuillotineException(
                    f"naked loss {naked:.2f}c > hard_stop {max_loss:.2f}c"
                )

    def _check_cushion_guard(self, yes_mid: float):
        if self.inventory.open_position() == 0:
            return
        total = self.inventory.realized_cents + self.inventory.unrealized_cents(yes_mid)
        if (
            self.session_peak_pnl > self.config["cushion_guard_min_pnl_cents"]
            and total < self.config["cushion_guard_min_pnl_cents"]
        ):
            raise GuillotineException(f"cushion guard: total={total:.2f}c")

    def _check_vault_and_daily(self):
        cfg = self.config
        if self.inventory.realized_cents <= -abs(cfg["vault_drawdown_cents"]):
            raise CriticalDrawdownException(
                f"vault breached: {self.inventory.realized_cents:.2f}c"
            )
        if self.inventory.realized_cents >= cfg["daily_target_cents"]:
            raise CriticalDrawdownException("daily_target_cents hit — pack the Wolf")

    def _check_trailing_ratchet(self, yes_mid: float):
        # WS blip guard — hallucinated 50¢ mid must not arm or fire the ratchet
        if self.live_exchange_bid <= 0.0 or self.live_exchange_ask <= 0.0:
            return
        total = self.inventory.realized_cents + self.inventory.unrealized_cents(yes_mid)

        # Only update peak on new highs
        if total > self.session_peak_pnl:
            self.session_peak_pnl = total

        # Ratchet ONLY arms after gross profit clears entry fee tax + safety margin.
        # arm_threshold scales with position size — prevents bid-ask noise from firing
        # the ratchet on a fully loaded pyramid where per-contract noise is amplified.
        pos = abs(self.inventory.open_position())
        quick_profit = float(self.config.get("quick_profit_cents", 12.0))
        arm_threshold = max(quick_profit * 1.5, 18.0 + (4.0 * pos))
        if self.session_peak_pnl <= arm_threshold:
            return

        floor = self.session_peak_pnl * (1 - self.config["trailing_ratchet_pct"])
        if total < floor:
            raise GuillotineException(
                f"trailing ratchet: {total:.2f}c < floor {floor:.2f}c "
                f"(armed at peak {self.session_peak_pnl:.2f})"
            )

    def _check_dislocation_ejector(self):
        if abs(self.basis_shift) > self.config["basis_dislocation_threshold"]:
            if self.inventory.open_position() > 0:
                raise DislocationEjectorException(
                    f"basis_shift={self.basis_shift:.4f}"
                )

    def _check_ws_blackout(self):
        if not self.active_ticker:
            return
        gap = time.time() - self.ws_last_msg_time
        if gap > self.config["ws_blackout_seconds"]:
            if self.inventory.open_position() > 0:
                raise GuillotineException(f"WS blackout: {gap:.1f}s since last message")

    def _run_full_risk_hierarchy(self, yes_mid: float):
        self._check_guillotine(yes_mid)
        self._check_cushion_guard(yes_mid)
        self._check_trailing_ratchet(yes_mid)
        self._check_dislocation_ejector()
        self._check_vault_and_daily()
        self._check_ws_blackout()

    # ─────────────────────────────────────────────────────────────────────────
    # CYCLE RESET
    # ─────────────────────────────────────────────────────────────────────────

    async def _reset_cycle_state(self):
        cycle_pnl            = self.inventory.realized_cents - self.cycle_start_pnl
        self.cycle_start_pnl = self.inventory.realized_cents  # advance anchor; next cycle starts clean
        if cycle_pnl != 0:
            _t = asyncio.create_task(TelegramAlerts.send(
                f"💸 Cycle complete: {self.active_ticker}\nCycle PnL: {cycle_pnl:.2f}¢"
            ))
            self._bg_tasks.add(_t)
            _t.add_done_callback(self._bg_tasks.discard)
            _t.add_done_callback(
                lambda t: logging.warning(f"Telegram alert failed: {t.exception()}")
                if not t.cancelled() and t.exception() else None
            )
        self.is_running            = False
        self.active_ticker         = None
        self.market_close_time     = None
        self.active_side           = None
        self.pyramid_step          = 0
        self.cycle_entry_time      = None
        self.trade_peak_unrealized = 0.0
        self._scale_t1_done        = False
        self._scale_t2_done        = False
        self.ws_price_valid        = False
        self._strike_in_flight     = False
        self._dump_in_flight       = False
        self.score_history.clear()
        self.pending_orders.clear()   # purge orphaned orders so they cannot bleed into the next cycle
        self.kalshi_bid_history    = []
        self.kalshi_velocity       = 0.0
        self.cycle_entry_time      = time.time()
        self._oracle_center_history = []
        self._trend_history        = []
        self._local_spot_history   = []
        self._cti_score            = 0.0
        self._neg_tick_fraction    = 0.0
        self.kalshi_velocity_fast  = 0.0
        self.live_exchange_bid     = 0.0
        self.live_exchange_ask     = 0.0
        self.live_exchange_bid_qty = 0
        self.live_exchange_ask_qty = 0
        # seen_trade_ids intentionally NOT cleared — deque(maxlen=5000) self-manages memory.
        # Preserving IDs across cycles prevents late Kalshi fills from prior cycle being double-processed.
        if self.inventory.open_position() == 0:
            self._clear_inventory_preserve_pnl()   # preserves realized_cents for vault guard
        self.session_peak_pnl      = 0.0   # bug fix: prevent false ratchet on new cycle
        # Note: btc_price_history, velocity_ema, basis_ema, and basis_shift
        # are explicitly NOT reset here so they persist across Kalshi cycles.
        self.ofi_ema               = 0.0
        self.ofi_scalar            = 0.0
        self.ofi_prev_bid_price    = None
        self.ofi_prev_bid_qty      = 0.0
        self.ofi_prev_ask_price    = None
        self.ofi_prev_ask_qty      = 0.0
        # last_exit_* intentionally NOT reset here — they are cross-cycle cooldown
        # triggers (anti-whipsaw, post-TP exhaustion) and must survive the reset.
        self.ws_last_msg_time      = time.time()
        # Scratch engine state — reset per cycle
        self._last_scratch_time    = 0.0
        self._scratch_active       = False
        self._scratch_order_id       = None
        self._pride_override_logged  = False
        self._last_valid_center      = 50.0
        # Phase-out state — reset per cycle
        self._sunset_sweep_done    = False
        self._hyper_logged         = False
        await self.auditor.record("CYCLE_RESET", {})

    # ─────────────────────────────────────────────────────────────────────────
    # WS-ONLY MARK PRICE  (synchronous, zero REST)
    # ─────────────────────────────────────────────────────────────────────────

    def _get_yes_mid(self) -> float:
        bid = self.live_exchange_bid
        ask = self.live_exchange_ask
        bid_qty = self.live_exchange_bid_qty
        ask_qty = self.live_exchange_ask_qty
        if bid <= 0 or ask <= 0:
            return getattr(self, '_last_valid_center', 50.0)

        # Depth-weighted microprice
        total_qty = bid_qty + ask_qty
        if total_qty == 0:
            return (bid + ask) / 2.0

        microprice = (bid * ask_qty + ask * bid_qty) / total_qty
        self._last_valid_center = microprice  # persist for WS blips
        return microprice

    # ─────────────────────────────────────────────────────────────────────────
    # ORACLE → PROBABILITY CENTER  (Block B)
    # ─────────────────────────────────────────────────────────────────────────

    def _map_oracle_to_probability(self) -> float:
        """
        TightChop V2 Oracle — NO artificial clamps.

        Design changes vs ChopWolf:
          • kalshi_velocity (kv_signal) is passed through RAW. No ±5 or ±25 clamp.
            This lets the oracle price instantly reflect a 20¢ flash-crash tick
            instead of lagging 4-5 scan cycles behind.
          • velocity_ema is unclamped (was ±5.0).  The Stoikov offset and risk
            hierarchy remain the backstop — the oracle itself should never lie.
          • Weights are re-tuned in YAML (W_kv raised to 1.5).
        """
        base_mid   = self._get_yes_mid()
        raw_center = base_mid

        # ── Signal stack — ALL UNCLAMPED ────────────────────────────────────
        raw_center += self.ofi_scalar * float(self.config.get("W_ofi", 0.5))

        # Velocity: raw, unclamped
        raw_center += self.velocity_ema * float(self.config.get("W_vel", 0.4))

        # Kalshi-native velocity: raw, unclamped — the strongest signal
        kv_signal = min(
            self.kalshi_velocity,
            getattr(self, 'kalshi_velocity_fast', 0.0),
        )
        raw_center += kv_signal * float(self.config.get("W_kv", 1.5))

        # Basis shift: raw
        raw_center += self.basis_shift * float(self.config.get("W_basis", 0.2))

        # Stoikov inventory skew (unchanged math, tighter leash in YAML)
        raw_center += self._compute_stoikov_offset()

        # Hard boundary: Kalshi prices live in [1, 99]
        return max(1.0, min(99.0, raw_center))

    # ─────────────────────────────────────────────────────────────────────────
    # STOIKOV INVENTORY OFFSET  (Block B-1)
    # ─────────────────────────────────────────────────────────────────────────

    def _compute_stoikov_offset(self) -> float:
        q = self.inventory.open_position()  # signed: +long YES, -short YES
        if q == 0:
            return 0.0

        # Realized variance over last 60 seconds from Kalshi bid history
        if len(self.kalshi_bid_history) < 2:
            sigma_sq = self._last_sigma_sq  # seed from previous cycle's terminal variance
        else:
            prices = [p for ts, p in self.kalshi_bid_history]
            returns = [(prices[i] - prices[i-1])**2 for i in range(1, len(prices))]
            sigma_sq = sum(returns) / len(returns) if returns else self._last_sigma_sq
            self._last_sigma_sq = sigma_sq  # persist for next cold start

        tau = 0.0
        if getattr(self, 'market_close_time', None):
            seconds_left = (self.market_close_time - datetime.datetime.now(datetime.timezone.utc)).total_seconds()
            tau = max(0.0, seconds_left / 900.0)  # 15 min = 900s

        gamma = float(self.config.get("inventory_gamma", 0.5))
        offset = -gamma * q * sigma_sq * tau

        # Leash the offset to prevent extreme Volatility/God Candle blowouts
        max_offset = float(self.config.get("max_stoikov_offset_cents", 15.0))
        offset = max(-max_offset, min(max_offset, offset))

        return offset

    # ─────────────────────────────────────────────────────────────────────────
    # MICRO-SCRATCH ENGINE  (NEW — the core of TightChop)
    # ─────────────────────────────────────────────────────────────────────────

    async def _run_scratch_engine(self, oracle_center: float, time_left: float = 999.0) -> None:
        """
        Micro-Scratch Inventory Routing — the heart of TightChop.

        Called every scan tick when we hold YES inventory.
        Decides whether the position has gone toxic, and if so, posts an
        aggressive MAKER sell to scratch out at a controlled loss.

        PHASE-OUT OVERRIDE (Patch 2):
          When time_left <= hyper_scratch_start_sec (default 120s / T-2:00),
          the scratch engine enters HYPER mode:
            - trigger_drift drops to 0¢ (arm on ANY adverse drift)
            - loss_tolerance ramps linearly from normal → 5¢ as clock runs down
          This forces maker exits before the terminal dump is needed.

        Fee-Awareness:
          scratch_price is set at best_ask - scratch_maker_offset (default: 1¢).
          This guarantees our sell order RESTS on the ask side (maker, 0 fee).
          If we set scratch_price ≤ best_bid, we'd cross the spread and pay
          the 1.7¢ taker fee — which would turn a 1¢ scratch into a 2.7¢ loss.
          The offset ensures we stay maker while still being the most aggressive
          ask in the book.

          Floor: scratch_price ≥ avg_entry - scratch_loss_tolerance_cents.
          This caps downside per contract to the YAML tolerance (default 1.5¢).
        """
        cfg = self.config
        if not cfg.get("scratch_enabled", True):
            return
        if not self.active_ticker:
            return
        if self.inventory.yes_qty <= 0:
            # No position to scratch — cancel any orphaned scratch order
            if self._scratch_order_id:
                await self._cancel_scratch_order()
            return

        # ── Cooldown gate ────────────────────────────────────────────────────
        # Hyper-scratch mode halves the cooldown for faster requoting
        hyper_scratch_start = float(cfg.get("hyper_scratch_start_sec", 120.0))
        is_hyper = time_left <= hyper_scratch_start
        base_cooldown_ms = float(cfg.get("scratch_cooldown_ms", 500))
        cooldown_ms = base_cooldown_ms * 0.5 if is_hyper else base_cooldown_ms
        now = time.time()
        if (now - self._last_scratch_time) * 1000 < cooldown_ms:
            return

        # ── Compute drift: how far has the oracle moved against our entry? ───
        avg_entry     = self.inventory._active_yes_cost()
        drift         = avg_entry - oracle_center        # positive = market fell against us

        # ── HYPER-SCRATCH OVERRIDE ───────────────────────────────────────────
        # In the final 2 minutes, progressively relax the trigger to force exits.
        #   At T-2:00: trigger_drift = 0.5¢ (arm on tiny adverse moves)
        #   At T-0:30: trigger_drift = 0.0¢ (arm on ANY position, even profitable)
        # This ensures the scratch engine posts maker sells every tick.
        if is_hyper:
            # Linear ramp: 0.5 → 0.0 over the hyper window
            last_resort_sec = float(cfg.get("last_resort_flatten_sec", 15.0))
            hyper_remaining = max(0.0, time_left - last_resort_sec)
            hyper_window    = hyper_scratch_start - last_resort_sec  # e.g. 120 - 15 = 105s
            ramp_ratio      = hyper_remaining / hyper_window if hyper_window > 0 else 0.0
            trigger_drift   = 0.5 * ramp_ratio  # 0.5¢ → 0.0¢
            if is_hyper and not getattr(self, '_hyper_logged', False):
                logging.info(f"⚡ HYPER-SCRATCH ACTIVE at T-{int(time_left)}s | trigger={trigger_drift:.2f}¢")
                self._hyper_logged = True
        else:
            trigger_drift = float(cfg.get("scratch_trigger_drift_cents", 2.0))

        if drift < trigger_drift:
            # Position is healthy — cancel scratch if resting, let profit sells work
            if self._scratch_order_id:
                await self._cancel_scratch_order()
                self._scratch_active = False
            return

        # ── Position is TOXIC — compute scratch exit price ───────────────────
        scratch_price = self._compute_scratch_price(avg_entry, time_left=time_left)
        if scratch_price is None:
            return  # can't compute a valid scratch price right now

        # ── Cancel stale scratch order if price has changed ──────────────────
        if self._scratch_order_id:
            stale_meta = self.pending_orders.get(self._scratch_order_id)
            if stale_meta and int(stale_meta.get("price", 0)) == scratch_price:
                return  # already resting at the right price
            await self._cancel_scratch_order()

        # ── Place the scratch sell (GTC maker limit) ─────────────────────────
        scratch_qty = self.inventory.yes_qty  # scratch the ENTIRE position
        # Subtract any resting non-scratch sells to avoid over-selling
        resting_sell_qty = sum(
            m.get("qty", 0) for m in self.pending_orders.values()
            if m.get("action") == "sell"
            and m.get("leg") != "scratch"
            and m.get("status") != "cancelling"
        )
        scratch_qty = max(0, scratch_qty - resting_sell_qty)
        if scratch_qty <= 0:
            return

        client_oid = str(uuid.uuid4())
        order = {
            "action":          "sell",
            "client_order_id": client_oid,
            "count":           scratch_qty,
            "side":            "yes",
            "ticker":          self.active_ticker,
            "type":            "limit",
            "yes_price":       scratch_price,
            "time_in_force":   "good_till_canceled",
        }

        try:
            res       = await self.api.request("POST", "/portfolio/orders", body=order)
            kalshi_id = res.get("order", {}).get("order_id")
            if kalshi_id:
                self.pending_orders[kalshi_id] = {
                    "side":       "yes",
                    "qty":        scratch_qty,
                    "price":      scratch_price,
                    "action":     "sell",
                    "grid_price": scratch_price,
                    "leg":        "scratch",
                }
                self._scratch_order_id = kalshi_id
                self._scratch_active   = True
                self._last_scratch_time = now

                expected_loss = (avg_entry - scratch_price) * scratch_qty
                await self.auditor.record("SCRATCH_POSTED", {
                    "avg_entry":     round(avg_entry, 2),
                    "oracle_center": round(oracle_center, 2),
                    "drift":         round(drift, 2),
                    "scratch_price": scratch_price,
                    "scratch_qty":   scratch_qty,
                    "expected_loss_cents": round(expected_loss, 2),
                })
                logging.info(
                    f"🔪 SCRATCH SELL | entry={avg_entry:.1f}¢ → exit={scratch_price}¢ "
                    f"| drift={drift:.1f}¢ | qty={scratch_qty} "
                    f"| max_loss={expected_loss:.1f}¢"
                )
        except Exception as e:
            await self.auditor.record("SCRATCH_ERROR", {"error": str(e)})

    async def _cancel_scratch_order(self) -> None:
        """Cancel the resting scratch sell and clear tracking state."""
        if not self._scratch_order_id:
            return
        oid = self._scratch_order_id
        self._scratch_order_id = None
        try:
            await self.api.request("DELETE", f"/portfolio/orders/{oid}")
            self.pending_orders.pop(oid, None)
            await self.auditor.record("SCRATCH_CANCELLED", {"oid": oid})
        except Exception as e:
            # 404 means already filled or cancelled — clean up memory
            if "404" in str(e).lower() or "not found" in str(e).lower():
                self.pending_orders.pop(oid, None)
            await self.auditor.record("SCRATCH_CANCEL_ERROR", {"oid": oid, "err": str(e)})

    # ─────────────────────────────────────────────────────────────────────────
    # FEE-AWARE SCRATCH PRICING  (NEW)
    # ─────────────────────────────────────────────────────────────────────────

    def _compute_scratch_price(self, avg_entry: float, time_left: float = 999.0) -> int | None:
        """
        Compute the optimal scratch exit price.  Two constraints:

        Constraint A — Loss Cap:
            scratch_price ≥ avg_entry - effective_tolerance
            Ensures per-contract loss never exceeds the tolerance.
            HYPER MODE: tolerance ramps from 1.5¢ → 5.0¢ as expiry approaches,
            accepting deeper losses to guarantee a MAKER exit before the
            terminal dump would fire.

        Constraint B — Maker Guarantee:
            scratch_price ≥ best_ask - scratch_maker_offset_cents
            Ensures the sell order RESTS on the ask side of the spread,
            avoiding the 1.7¢ taker fee.  The offset (default 1¢) makes
            us the most aggressive ask without crossing.

        Final price = max(Constraint A, Constraint B)
        Returns None if we can't compute a valid price (stale book).
        """
        cfg = self.config

        if self.live_exchange_ask <= 0 or self.live_exchange_bid <= 0:
            return None  # stale book — don't scratch blind

        # Constraint A: loss cap (with hyper-scratch time ramp)
        base_tolerance = float(cfg.get("scratch_loss_tolerance_cents", 1.5))
        hyper_scratch_start = float(cfg.get("hyper_scratch_start_sec", 120.0))
        last_resort_sec = float(cfg.get("last_resort_flatten_sec", 15.0))
        max_hyper_tolerance = float(cfg.get("hyper_scratch_max_tolerance_cents", 5.0))
        if time_left <= hyper_scratch_start:
            # Linear ramp: base_tolerance → max_hyper_tolerance as clock runs down
            hyper_remaining = max(0.0, time_left - last_resort_sec)
            hyper_window    = hyper_scratch_start - last_resort_sec
            ramp_ratio      = hyper_remaining / hyper_window if hyper_window > 0 else 0.0
            tolerance = base_tolerance + (max_hyper_tolerance - base_tolerance) * (1.0 - ramp_ratio)
        else:
            tolerance = base_tolerance
        loss_floor   = int(math.ceil(avg_entry - tolerance))  # ceil to stay conservative

        # Constraint B: maker guarantee
        maker_offset = int(cfg.get("scratch_maker_offset_cents", 1))
        maker_floor  = int(self.live_exchange_ask) - maker_offset

        # Additional safety: never post below best_bid (would cross immediately)
        bid_floor    = int(self.live_exchange_bid) + 1  # 1¢ above bid = maker side

        # ── PRIDE OVERRIDE ────────────────────────────────────────────────
        # When loss_floor exceeds maker_floor by more than pride_gap, the
        # market has fallen well past our tolerance zone.  Posting at
        # loss_floor would leave an unfillable order that stalls until the
        # guillotine fires a TAKER dump at an even worse price + 1.7¢ fee.
        pride_gap = float(cfg.get("scratch_pride_override_gap_cents", 3.0))

        if loss_floor > maker_floor + pride_gap:
            # Extreme drop: loss_floor is unreachable.
            # Abandon Maker status. Nuke the position into the Bid as a Taker.
            scratch_price = max(1, int(self.live_exchange_bid))
            if not getattr(self, '_pride_override_logged', False):
                logging.info(
                    f"⚡ PRIDE OVERRIDE: Freefall detected (gap={loss_floor - maker_floor}¢ > {pride_gap}¢). "
                    f"Abandoning maker status. Dumping into Bid at {scratch_price}¢."
                )
                self._pride_override_logged = True
        else:
            # Normal scratch: loss cap is achievable alongside maker guarantee
            scratch_price = max(loss_floor, maker_floor, bid_floor, 1)
            self._pride_override_logged = False

        # Sanity: if scratch_price >= avg_entry, we'd actually profit — just use normal sells
        if scratch_price >= avg_entry:
            return None  # not actually a scratch situation

        return min(scratch_price, 99)

    # ─────────────────────────────────────────────────────────────────────────
    # DYNAMIC SPACING  (P2 — live spread-aware grid pitch)
    # ─────────────────────────────────────────────────────────────────────────

    def _compute_dynamic_spacing(self) -> float:
        """Tighter floor (1.5¢) for micro-scratch — we WANT to be filled."""
        live_spread = self.live_exchange_ask - self.live_exchange_bid
        if live_spread <= 0 or live_spread > 15.0:
            return float(self.config.get("quote_spacing_cents", 3.0))
        raw = live_spread * 0.55
        return max(1.5, min(raw, 5.0))

    def _compute_asymmetric_spacing(self, base_spacing: float) -> tuple:
        dp = max(-1.0, min(1.0,
            self.ofi_scalar * 0.6
            + (max(-3.0, min(3.0, self.velocity_ema)) / 3.0 * 0.4)
        ))
        asym = 1.0 + dp * float(self.config.get("asym_skew_strength", 0.55))
        buy_spacing  = base_spacing * (2.0 - asym)
        sell_spacing = base_spacing * asym
        return buy_spacing, sell_spacing

    def _compute_dynamic_qty(self, base_qty: int, seconds_left: float) -> int:
        """
        Spread-aware AND inventory-aware quantity scaling.
        New: reduces qty linearly as inventory approaches soft cap.
        """
        spread = self.live_exchange_ask - self.live_exchange_bid
        if spread <= 0 or spread > 20:
            return base_qty
        if spread <= 2.0:
            mult = 1.25
        elif spread <= 4.0:
            mult = 1.0
        elif spread <= 6.0:
            mult = 0.75
        else:
            mult = 0.5

        # Time decay bonus (retained)
        if seconds_left < 240.0 and spread <= 3.0:
            mult *= 1.15

        # NEW: Inventory pressure — scale down as we approach soft cap
        soft_cap = int(self.config.get("inventory_soft_cap_contracts", 5))
        pos = self.inventory.open_position()
        if soft_cap > 0 and pos > 0:
            inv_ratio = pos / soft_cap  # 0.0 (empty) → 1.0+ (at/above cap)
            inv_mult  = max(0.25, 1.0 - (inv_ratio * 0.5))  # scale down to 25%
            mult *= inv_mult

        return max(1, int(base_qty * mult + 0.5))

    def _is_dangerous_market(self) -> bool:
        """
        Returns True if the market is DEAD (no volume) OR CRASHING (falling knife).
        Pauses buy-leg placement to protect capital.
        """
        # 1. Dead market checks (Requires all 3 to be flat)
        ofi_dead = abs(self.ofi_scalar) < 0.05
        vel_dead = abs(self.kalshi_velocity) < 0.08
        binance_dead = abs(self.velocity_ema) < 0.3
        is_dead = ofi_dead and vel_dead and binance_dead

        # 2. Crash checks (Requires only 1 to indicate a steep drop)
        # Strong negative velocity indicates a sharp downtrend
        is_crashing = self.kalshi_velocity < -0.15 or self.velocity_ema < -0.5

        # 3. Slow-bleed detection (cumulative)
        cti = getattr(self, '_cti_score', 0.0)
        neg_frac = getattr(self, '_neg_tick_fraction', 0.5)
        cti_thresh = float(self.config.get("cti_block_threshold", -4.0))
        neg_thresh = float(self.config.get("cti_neg_fraction_min", 0.65))

        is_slow_bleed = (cti < cti_thresh) and (neg_frac > neg_thresh)

        if is_slow_bleed:
            logging.debug(f"⚠️ SLOW BLEED: CTI={cti:.1f}¢, neg_frac={neg_frac:.0%}. Blocking buys.")
        if is_crashing:
            logging.debug("⚠️ DANGEROUS MARKET: Crash detected. Pausing buy legs.")

        return is_dead or is_crashing or is_slow_bleed

    def _is_oracle_unstable(self, oracle_center: float) -> bool:
        """Blocks buy legs if oracle drifts > 10¢ in 30s (trending regime)."""
        now = time.time()
        self._oracle_center_history.append((now, oracle_center))
        self._oracle_center_history = [(ts, c) for ts, c in self._oracle_center_history if now - ts <= 30.0]
        if len(self._oracle_center_history) < 3:
            return False
        drift = abs(oracle_center - self._oracle_center_history[0][1])
        if drift > 6.0:
            logging.debug(f"⚠️ ORACLE UNSTABLE: {drift:.1f}¢ drift in 30s. Blocking buy legs.")
            return True
        return False

    def _is_spot_trending(self) -> bool:
        """Blocks buy legs if BTC spot is falling > 3 bps/min over the last 15s."""
        now = time.time()

        # Maintain a local, decoupled spot history to avoid WS truncation limits
        if not hasattr(self, '_local_spot_history'):
            self._local_spot_history = []

        if getattr(self, 'live_btc_price', None):
            self._local_spot_history.append((now, self.live_btc_price))

        # Keep exactly 15 seconds of scan-interval history
        self._local_spot_history = [(ts, px) for ts, px in self._local_spot_history if now - ts <= 15.0]

        if len(self._local_spot_history) < 3:
            return False  # Fail-safe (allow buys) instead of fail-deadly lockouts

        oldest_ts, oldest_px = self._local_spot_history[0]
        newest_ts, newest_px = self._local_spot_history[-1]
        elapsed = newest_ts - oldest_ts

        if elapsed < 2.0 or oldest_px <= 0:
            return False  # Fail-safe

        spot_vel_bps_min = ((newest_px - oldest_px) / oldest_px) * 10000.0 / (elapsed / 60.0)
        threshold = float(self.config.get("spot_trend_block_bps", -3.0))

        if spot_vel_bps_min < threshold:
            logging.debug(f"⚠️ SPOT TREND GATE: vel={spot_vel_bps_min:.1f} bps/min < threshold {threshold}. Blocking buys.")
            return True
        return False

    def _update_trend_integral(self, oracle_center: float):
        """Computes Cumulative Trend Integral (CTI) to detect slow-bleed regimes."""
        now = time.time()
        if not hasattr(self, '_trend_history'):
            self._trend_history = []
        self._trend_history.append((now, oracle_center))
        self._trend_history = [(t, c) for t, c in self._trend_history if now - t <= float(self.config.get("cti_window_seconds", 60.0))]

        if len(self._trend_history) < 10:
            self._cti_score = 0.0
            self._neg_tick_fraction = 0.0
            return

        prices = [c for _, c in self._trend_history]
        signed_returns = [prices[i] - prices[i-1] for i in range(1, len(prices))]

        self._cti_score = sum(signed_returns)
        self._neg_tick_fraction = sum(1 for r in signed_returns if r < 0) / len(signed_returns)

    # ─────────────────────────────────────────────────────────────────────────
    # MAIN SCAN LOOP  (replaces _grid_scan)
    # ─────────────────────────────────────────────────────────────────────────

    async def _quote_scan(self):
        """
        TightChop main loop — replaces ChopWolf's _grid_scan.

        Structural change: after oracle computation and quote placement,
        the scratch engine runs on every tick to check whether open inventory
        has become toxic and needs aggressive exit.

        Scan interval is tightened to 300ms (from 350ms) for faster scratch response.
        """
        cfg = self.config
        quoter = QuoteManager(
            levels          = int(cfg.get("quote_levels", 2)),
            base_qty        = int(cfg.get("quote_qty_per_level", 4)),
            spacing         = float(cfg.get("quote_spacing_cents", 3.0)),
            trailing_thresh = float(cfg.get("trailing_threshold_cents", 4.0)),
            decay_start_sec = float(cfg.get("decay_start_min_left", 6.0)) * 60.0,
            decay_half_life = float(cfg.get("decay_half_life_sec", 150.0)),
        )
        poll_s = cfg["scan_interval_ms"] / 1000

        while self.is_running:
            await asyncio.sleep(poll_s)

            time_left = 0.0
            if self.market_close_time:
                time_left = (
                    self.market_close_time - datetime.datetime.now(datetime.timezone.utc)
                ).total_seconds()
                if time_left < -10:
                    self.is_running = False
                    return

            if not self.live_exchange_bid or not self.live_exchange_ask or not self.live_btc_price or getattr(self, 'ws_price_valid', True) is False:
                continue

            yes_mid = self._get_yes_mid()

            # ── 1. GRACEFUL PHASE-OUT (replaces hard terminal flatten) ────────
            phase_out_start = float(cfg.get("phase_out_start_sec", 240.0))  # T-4:00
            hyper_scratch_start = float(cfg.get("hyper_scratch_start_sec", 120.0))  # T-2:00
            last_resort_sec = float(cfg.get("last_resort_flatten_sec", 15.0))  # T-0:15
            # Phase 3: LAST RESORT — hard taker dump (only if hyper-scratch failed)
            if time_left <= last_resort_sec:
                if not self._dump_in_flight and self.inventory.open_position() > 0:
                    logging.info(f"⏰ LAST RESORT Flatten at {int(time_left)}s [{self.active_ticker}]")
                    await self.cancel_active_orders()
                    await self._dump_full_position(yes_mid)
                else:
                    await self.cancel_active_orders()
                self.is_running = False
                return
            # Phase 1: SUNSET — cancel resting buys, let sells + scratch work
            if time_left <= phase_out_start and not getattr(self, '_sunset_sweep_done', False):
                buy_oids = [
                    oid for oid, meta in self.pending_orders.items()
                    if meta.get("action") == "buy" and meta.get("status") != "cancelling"
                ]
                for oid in buy_oids:
                    if oid in self.pending_orders:
                        self.pending_orders[oid]["status"] = "cancelling"
                    async def _cancel_buy(order_id=oid):
                        try:
                            await self.api.request("DELETE", f"/portfolio/orders/{order_id}")
                            self.pending_orders.pop(order_id, None)
                            await self.auditor.record("PHASE_OUT_BUY_CANCELLED", {"oid": order_id})
                        except Exception:
                            pass
                    _t = asyncio.create_task(_cancel_buy())
                    self._bg_tasks.add(_t)
                    _t.add_done_callback(self._bg_tasks.discard)
                self._sunset_sweep_done = True
                if buy_oids:
                    logging.info(f"🌅 SUNSET: Cancelled {len(buy_oids)} resting buy legs at T-{int(time_left)}s")

            # ── 2. RISK HIERARCHY ─────────────────────────────────────────────
            try:
                self._run_full_risk_hierarchy(yes_mid)
            except (GuillotineException, DislocationEjectorException) as e:
                await self.auditor.record("RISK_KILL_SCAN", {"reason": str(e)})
                if self.active_ticker:
                    self.blacklisted_tickers[self.active_ticker] = time.time() + 60.0
                if not self._dump_in_flight and self.inventory.open_position() > 0:
                    await self.cancel_active_orders()
                    await self._dump_full_position(yes_mid)
                await self._reset_cycle_state()
                return
            except CriticalDrawdownException:
                raise

            # ── 3. PERIODIC REST SYNC ─────────────────────────────────────────
            now = time.time()
            if now - self._last_rest_sync > 45.0:
                await self._sync_position_from_api(self.active_ticker)
                self._last_rest_sync = now

            if self._dump_in_flight:
                continue

            # ── 4. ORACLE + TREND DETECTION ───────────────────────────────────
            oracle_center = self._map_oracle_to_probability()
            if oracle_center is None:
                continue

            self._update_trend_integral(oracle_center)

            # ── 5. SPACING + DECAY ────────────────────────────────────────────
            active_spacing_raw = self._compute_dynamic_spacing()
            buy_spacing, sell_spacing = self._compute_asymmetric_spacing(active_spacing_raw)
            spread_mult, decay_qty = quoter.get_decay_metrics(time_left)

            final_buy_spacing  = buy_spacing * spread_mult
            final_sell_spacing = sell_spacing * spread_mult

            if quoter.should_reanchor(oracle_center):
                quoter.reanchor(oracle_center)
                await self.cancel_active_orders()
                self._scratch_order_id = None   # scratch order was in the cancelled batch
                self._scratch_active   = False

            # ── 6. DYNAMIC QTY ────────────────────────────────────────────────
            dynamic_base = self._compute_dynamic_qty(quoter.base_qty, time_left)
            current_qty  = max(1, int(dynamic_base * (decay_qty / quoter.base_qty)))

            # ── 7. PLACE QUOTES ───────────────────────────────────────────────
            await self._update_quotes(
                quoter, current_qty, final_buy_spacing, final_sell_spacing, oracle_center, time_left,
            )

            # ── 8. SCRATCH ENGINE ─────────────────────────────────────────────
            # Runs AFTER quotes so it can coexist with profit-taking sells.
            # Passes time_left so hyper-scratch mode can activate near expiry.
            if self.inventory.yes_qty > 0:
                await self._run_scratch_engine(oracle_center, time_left=time_left)

    # ─────────────────────────────────────────────────────────────────────────
    # INVENTORY-AWARE QUOTING  (replaces _update_grid_orders)
    # ─────────────────────────────────────────────────────────────────────────

    async def _update_quotes(
        self,
        quoter: 'QuoteManager',
        current_qty: int,
        buy_spacing: float,
        sell_spacing: float,
        oracle_center: float,
        time_left: float,
    ) -> None:
        """
        TightChop quote placer — replaces ChopWolf's _update_grid_orders.

        Key differences from ChopWolf:
        1. INVENTORY PRESSURE: Buy legs are gated by both a hard cap AND a soft cap.
           Above the soft cap, spacing doubles and qty drops to 1 — the bot is
           "reluctantly" quoting, not aggressively accumulating.
        2. SCRATCH COEXISTENCE: When the scratch engine has a resting sell,
           normal profit-taking sells are still placed above entry — the scratch
           sell and profit sells coexist to give the market two exit paths.
        3. NO MEMORY LOCK ON SELLS: ChopWolf's placed_sell_prices prevented
           re-quoting at the same price after a cancel-rebuild. TightChop allows
           it — sell quotes must track the oracle, not the prior anchor.
        """
        if not self.active_ticker:
            return

        cfg = self.config

        # ── Resting price set ─────────────────────────────────────────────────
        resting_prices: set = {
            int(meta["grid_price"])
            for meta in self.pending_orders.values()
            if meta.get("grid_price") is not None
            and meta.get("status") != "cancelling"
        }

        # ── Inventory state ───────────────────────────────────────────────────
        current_pos       = self.inventory.open_position()
        hard_cap          = int(cfg.get("max_inventory_contracts", 8))
        soft_cap          = int(cfg.get("inventory_soft_cap_contracts", 5))
        max_pending_buys  = int(cfg.get("max_pending_buy_contracts", 4))
        max_inv_pct       = float(cfg.get("max_inventory_pct", 0.12))
        max_inv_budget    = self.current_balance * 100 * max_inv_pct

        pending_buy_qty = sum(
            m.get("qty", 0) for m in self.pending_orders.values()
            if m.get("action") == "buy" and m.get("side") == "yes"
        )

        committed_cents = self.inventory.yes_cost_cents + sum(
            m.get("qty", 0) * m.get("grid_price", 0)
            for m in self.pending_orders.values()
            if m.get("action") == "buy"
        )

        chop_min = int(cfg.get("chop_zone_min_cents", 12))
        chop_max = int(cfg.get("chop_zone_max_cents", 88))

        # ── Inventory pressure adjustments ────────────────────────────────────
        # Above soft cap: double spacing, drop qty to 1
        inv_buy_spacing = buy_spacing
        inv_buy_qty     = current_qty
        if current_pos >= soft_cap:
            inv_buy_spacing = buy_spacing * 2.0
            inv_buy_qty     = 1

        # Above hard cap: NO new buys at all — pure scratch/liquidation mode
        buys_allowed = current_pos < hard_cap

        # ── Compute leg prices ─────────────────────────────────────────────────
        adj_buy_prices = [
            max(1, int(round(oracle_center - (i * inv_buy_spacing))))
            for i in range(1, quoter.levels + 1)
        ]
        adj_sell_prices = [
            min(99, int(round(oracle_center + (i * sell_spacing))))
            for i in range(1, quoter.levels + 1)
        ]

        # ══════════════════════════════════════════════════════════════════════
        # BUY LEGS
        # ══════════════════════════════════════════════════════════════════════
        is_warmup = self.cycle_entry_time and (time.time() - self.cycle_entry_time) < 15.0

        # ── PHASE-OUT: Block new buys in the final 4 minutes ──────────────
        phase_out_active = time_left <= float(cfg.get("phase_out_start_sec", 240.0))

        # ── ADVERSE SELECTION GATE ────────────────────────────────────────
        # When short-term velocity signals indicate a flash crash in progress,
        # we must not only skip new buys but also PULL all resting bids off
        # the book.
        adv_sel_kv_thresh  = float(cfg.get("adverse_sel_kv_threshold", -3.0))
        adv_sel_vel_thresh = float(cfg.get("adverse_sel_vel_threshold", -2.0))
        kv_val  = getattr(self, 'kalshi_velocity', 0.0)
        vel_val = getattr(self, 'velocity_ema', 0.0)

        adverse_selection_active = (kv_val < adv_sel_kv_thresh) or (vel_val < adv_sel_vel_thresh)

        if adverse_selection_active:
            # Pull ALL resting buys — they are toxic in a crash
            pulled = await self._pull_resting_buys()
            if pulled > 0:
                quoter.placed_buy_prices.clear()
                await self.auditor.record("ADVERSE_SEL_GATE", {
                    "kv": round(kv_val, 3),
                    "vel_ema": round(vel_val, 3),
                    "pulled_count": pulled,
                })
                logging.info(
                    f"🛡️ ADVERSE SELECTION GATE: Pulled {pulled} resting buys "
                    f"| kv={kv_val:.2f} vel={vel_val:.2f}"
                )
            # Fall through — buys_allowed block below will NOT execute

        if (buys_allowed
            and not phase_out_active
            and not adverse_selection_active
            and not self._is_dangerous_market()
            and not is_warmup
            and not self._is_oracle_unstable(oracle_center)
            and not self._is_spot_trending()):

            for price_int in adj_buy_prices:
                if price_int < chop_min or price_int > chop_max:
                    continue
                if price_int in resting_prices or price_int in quoter.placed_buy_prices:
                    continue

                # ── MOMENTUM TAKER ENTRY ENABLED ────────────────────────────
                # The oracle is uncapped and allowed to cross the live ask.
                if self.live_exchange_ask <= 0:
                    continue  # no live ask — refuse to buy blind

                taker_fee = float(cfg.get("taker_fee_cents", 1.7))
                maker_fee = float(cfg.get("maker_fee_cents", 0.0))
                min_edge = float(cfg.get("min_edge_after_fees_cents", 0.5))

                # ── SCREAMING ORACLE OVERRIDE ──
                # If the Oracle thinks true value is significantly higher than the Kalshi Ask,
                # abandon passive quote spacing. Slam the Ask directly to guarantee a Taker fill.
                if oracle_center >= (self.live_exchange_ask + taker_fee + maker_fee + min_edge):
                    price_int = int(self.live_exchange_ask)

                # Hard cap check (position + pending + this order)
                if (current_pos + pending_buy_qty + inv_buy_qty) > hard_cap:
                    break
                # Pending buy cap
                if (pending_buy_qty + inv_buy_qty) > max_pending_buys:
                    break
                # Budget cap
                if (committed_cents + inv_buy_qty * price_int) > max_inv_budget:
                    break

                # Fee-edge check: only buy if expected spread capture > fees
                # We assume a TAKER entry (paying taker_fee) and a MAKER exit (paying maker_fee).
                min_edge = float(cfg.get("min_edge_after_fees_cents", 0.5))
                expected_sell = price_int + sell_spacing
                taker_fee = float(cfg.get("taker_fee_cents", 1.7))
                maker_fee = float(cfg.get("maker_fee_cents", 0.0))

                edge = expected_sell - price_int - taker_fee - maker_fee
                if edge < min_edge:
                    continue

                client_oid = str(uuid.uuid4())
                order = {
                    "action":          "buy",
                    "client_order_id": client_oid,
                    "count":           inv_buy_qty,
                    "side":            "yes",
                    "ticker":          self.active_ticker,
                    "type":            "limit",
                    "yes_price":       price_int,
                    "time_in_force":   "good_till_canceled",
                }
                try:
                    res       = await self.api.request("POST", "/portfolio/orders", body=order)
                    kalshi_id = res.get("order", {}).get("order_id")
                    if kalshi_id:
                        self.pending_orders[kalshi_id] = {
                            "side":       "yes",
                            "qty":        inv_buy_qty,
                            "price":      price_int,
                            "action":     "buy",
                            "grid_price": price_int,
                            "leg":        "buy",
                        }
                        resting_prices.add(price_int)
                        quoter.placed_buy_prices.add(price_int)
                        committed_cents += inv_buy_qty * price_int
                        pending_buy_qty += inv_buy_qty
                        await self.auditor.record("QUOTE_BUY_PLACED", {
                            "price": price_int, "qty": inv_buy_qty, "kalshi_id": kalshi_id,
                        })
                except Exception as e:
                    await self.auditor.record("QUOTE_BUY_ERROR", {
                        "price": price_int, "error": str(e),
                    })

        # ══════════════════════════════════════════════════════════════════════
        # SELL LEGS (profit-taking — coexists with scratch sells)
        # ══════════════════════════════════════════════════════════════════════
        remaining_yes = self.inventory.yes_qty
        if remaining_yes <= 0:
            return

        # Calculate how many contracts are already committed to sell orders
        resting_sell_qty = sum(
            m.get("qty", 0) for m in self.pending_orders.values()
            if m.get("action") == "sell" and m.get("status") != "cancelling"
        )
        available_to_sell = max(0, remaining_yes - resting_sell_qty)

        avg_cost = self.inventory._active_yes_cost()

        for price_int in adj_sell_prices:
            if price_int in resting_prices:
                continue
            if available_to_sell <= 0:
                break

            # Profit sells must be above cost basis (that's the point)
            # Scratch sells handle below-cost exits
            if avg_cost > 0 and price_int < int(math.ceil(avg_cost)):
                continue

            leg_qty = min(current_qty, available_to_sell)
            if leg_qty <= 0:
                break

            client_oid = str(uuid.uuid4())
            order = {
                "action":          "sell",
                "client_order_id": client_oid,
                "count":           leg_qty,
                "side":            "yes",
                "ticker":          self.active_ticker,
                "type":            "limit",
                "yes_price":       price_int,
                "time_in_force":   "good_till_canceled",
                "post_only":       True,
            }
            try:
                res       = await self.api.request("POST", "/portfolio/orders", body=order)
                kalshi_id = res.get("order", {}).get("order_id")
                if kalshi_id:
                    self.pending_orders[kalshi_id] = {
                        "side":       "yes",
                        "qty":        leg_qty,
                        "price":      price_int,
                        "action":     "sell",
                        "grid_price": price_int,
                        "leg":        "sell",
                    }
                    resting_prices.add(price_int)
                    available_to_sell -= leg_qty
                    await self.auditor.record("QUOTE_SELL_PLACED", {
                        "price": price_int, "qty": leg_qty, "kalshi_id": kalshi_id,
                    })
            except Exception as e:
                await self.auditor.record("QUOTE_SELL_ERROR", {
                    "price": price_int, "error": str(e),
                })

    # ─────────────────────────────────────────────────────────────────────────
    # EXECUTION HELPERS
    # ─────────────────────────────────────────────────────────────────────────

    async def _cancel_if_unfilled(self, kalshi_id: str, delay: int, step_to_rollback: int = -1):
        """
        Belt-and-suspenders IOC enforcement.
        Waits `delay` seconds, then DELETEs the order.
        step_to_rollback is a snapshot of pyramid_step at order placement time.
        """
        await asyncio.sleep(delay)
        if kalshi_id not in self.pending_orders:
            return  # Already filled or cancelled by another process
        try:
            await self.api.request("DELETE", f"/portfolio/orders/{kalshi_id}")
            if kalshi_id not in self.pending_orders:
                # Fill handler processed this order during the DELETE await —
                # inventory already updated; skip rollback to prevent step double-fire.
                await self.auditor.record("IOC_CANCEL_FILL_RACE", {"kalshi_id": kalshi_id})
                return
            self.pending_orders.pop(kalshi_id, None)
            if step_to_rollback >= 0:
                self.pyramid_step = max(0, step_to_rollback - 1)
            await self.auditor.record("IOC_CANCELLED", {
                "kalshi_id": kalshi_id, "step_rb": step_to_rollback,
            })
        except Exception as e:
            await self.auditor.record("IOC_CANCEL_FAILED", {
                "kalshi_id": kalshi_id, "error": str(e),
            })

    async def _pull_resting_buys(self) -> int:
        """
        Emergency bid-pull: cancel ALL resting buy orders while leaving sells intact.
        Returns the count of orders cancelled.  Used by the Adverse Selection Gate
        to yank bids off the book when the market is in freefall.
        """
        buy_oids = [
            oid for oid, meta in self.pending_orders.items()
            if meta.get("action") == "buy"
            and meta.get("status") != "cancelling"
        ]
        for oid in buy_oids:
            if oid in self.pending_orders:
                self.pending_orders[oid]["status"] = "cancelling"

            async def _do_cancel(order_id: str = oid):
                try:
                    await self.api.request("DELETE", f"/portfolio/orders/{order_id}")
                    await self.auditor.record("ADVERSE_SEL_BUY_PULLED", {"oid": order_id})
                    self.pending_orders.pop(order_id, None)
                except Exception as _ce:
                    err_str = str(_ce).lower()
                    if "404" in err_str or "not found" in err_str:
                        async def _delayed_pop(oid=order_id):
                            await asyncio.sleep(2.0)
                            self.pending_orders.pop(oid, None)
                        _dp_task = asyncio.create_task(_delayed_pop())
                        self._bg_tasks.add(_dp_task)
                        _dp_task.add_done_callback(self._bg_tasks.discard)
                    else:
                        if order_id in self.pending_orders:
                            self.pending_orders[order_id]["status"] = "resting"

            _t = asyncio.create_task(_do_cancel())
            self._bg_tasks.add(_t)
            _t.add_done_callback(self._bg_tasks.discard)
        return len(buy_oids)

    async def cancel_active_orders(self):
        """Fire-and-forget REST cancels — memory is ONLY cleared after Kalshi confirms."""
        ids = list(self.pending_orders.keys())
        for oid in ids:
            # Prevent sending duplicate cancel requests for the same order
            if self.pending_orders.get(oid, {}).get("status") == "cancelling":
                continue
            if oid in self.pending_orders:
                self.pending_orders[oid]["status"] = "cancelling"

            async def _do_cancel(order_id: str = oid):
                try:
                    await self.api.request("DELETE", f"/portfolio/orders/{order_id}")
                    await self.auditor.record("ORDER_CANCELLED", {"oid": order_id})
                    self.pending_orders.pop(order_id, None)  # Pop ONLY on success
                except Exception as _ce:
                    err_str = str(_ce).lower()
                    if "404" in err_str or "not found" in err_str:
                        # RACE CONDITION SHIELD: 404 means filled OR cancelled on Kalshi.
                        # Wait 2 seconds for the WS fill message to arrive and credit inventory
                        # before clearing local memory.
                        async def _delayed_pop(oid=order_id):
                            await asyncio.sleep(2.0)
                            self.pending_orders.pop(oid, None)

                        _dp_task = asyncio.create_task(_delayed_pop())
                        self._bg_tasks.add(_dp_task)
                        _dp_task.add_done_callback(self._bg_tasks.discard)
                    else:
                        # 429 or other transient error: keep in memory and retry later
                        if order_id in self.pending_orders:
                            self.pending_orders[order_id]["status"] = "resting"
                    await self.auditor.record("CANCEL_ERROR", {"oid": order_id, "err": str(_ce)})

            _t = asyncio.create_task(_do_cancel())
            self._bg_tasks.add(_t)
            _t.add_done_callback(self._bg_tasks.discard)

    async def _sell_clip(self, qty: int):
        if qty <= 0 or not self.active_ticker:
            return False
        ioc_timeout = int(self.config.get("ioc_timeout_secs", 3))
        client_oid  = str(uuid.uuid4())
        if self.active_side == "yes":
            # Empty book guard: if bid has dropped to zero, post at 1¢ to guarantee fill
            limit_price = 1 if self.live_exchange_bid <= 0.0 else int(max(self.live_exchange_bid - 1, 1))
            order = {
                "action":          "sell",
                "client_order_id": client_oid,
                "count":           qty,
                "side":            "yes",
                "ticker":          self.active_ticker,
                "type":            "limit",
                "yes_price":       limit_price,
                "time_in_force":   "immediate_or_cancel",
            }
        else:
            # NO bid = 100 − YES ask; cross by 1c
            # Empty book guard: if ask has dropped to zero, post at 1¢ to guarantee fill
            if self.live_exchange_ask <= 0.0:
                limit_price = 1
            else:
                no_bid      = 100.0 - self.live_exchange_ask
                limit_price = int(max(no_bid - 1.0, 1.0))
            order = {
                "action":          "sell",
                "client_order_id": client_oid,
                "count":           qty,
                "side":            "no",
                "ticker":          self.active_ticker,
                "type":            "limit",
                "no_price":        limit_price,
                "time_in_force":   "immediate_or_cancel",
            }
        try:
            res       = await self.api.request("POST", "/portfolio/orders", body=order)
            kalshi_id = res.get("order", {}).get("order_id")
            if kalshi_id:
                self.pending_orders[kalshi_id] = {
                    "action": "sell",
                    "qty":    qty,
                    "leg":    "sell",
                }
                await self.auditor.record("STRIKE_PLACED", {
                    "id": kalshi_id,
                    "side": self.active_side.upper(),
                    "qty": qty,
                })
                _cancel_task = asyncio.create_task(
                    self._cancel_if_unfilled(kalshi_id, ioc_timeout)
                )
                self._bg_tasks.add(_cancel_task)
                _cancel_task.add_done_callback(self._bg_tasks.discard)
                return True
            return False   # empty response — order not placed
        except Exception as e:
            await self.auditor.record("SELL_CLIP_FAILED", {"error": str(e)})
            return False

    def _clear_inventory_preserve_pnl(self):
        """Reset position state without destroying daily realized PnL."""
        saved_pnl                     = self.inventory.realized_cents
        self.inventory                = InventoryManager()
        self.inventory.realized_cents = saved_pnl

    async def _sync_position_from_api(self, ticker: str):
        """
        Fetch ground-truth position from Kalshi REST and reconcile local inventory.
        Prevents ghost positions after IOC-cancelled exits or bot restarts.
        Called at cycle start and after exhausted dump retries.
        """
        try:
            res = await self.api.request("GET", f"/portfolio/positions?ticker={ticker}")

            if not res or "market_positions" not in res:
                logging.error(f"🚨 SYNC ABORTED — API returned empty/invalid response [{ticker}]. Inventory preserved.")
                await self.auditor.record("POSITION_SYNC_ABORTED", {"ticker": ticker, "reason": "empty_response"})
                return

            positions = res.get("market_positions")
            if positions is None:
                logging.warning("SYNC ABORTED — market_positions returned null.")
                return
            if not positions:   # confirmed empty list []
                ws_qty = self.inventory.yes_qty if self.active_side == "yes" else self.inventory.no_qty
                if ws_qty != 0:
                    logging.debug(f"⚠️ API Glitch: REST reported empty list [], but WS holds {ws_qty}. Ignoring REST wipe.")
                    return
                self._clear_inventory_preserve_pnl()
                await self.auditor.record("POSITION_SYNC", {"ticker": ticker, "result": "flat_confirmed"})
                return

            # Safely find the exact market instead of blindly grabbing positions[0]
            matching_pos = None
            for p in positions:
                if p.get("ticker") == ticker:
                    matching_pos = p
                    break

            if not matching_pos:
                self._clear_inventory_preserve_pnl()
                await self.auditor.record("POSITION_SYNC", {"ticker": ticker, "result": "flat_confirmed_no_match"})
                return

            qty = int(matching_pos.get("position", 0))

            if qty == 0:
                ws_qty = self.inventory.yes_qty if self.active_side == "yes" else self.inventory.no_qty
                if ws_qty != 0:
                    # Kalshi API glitch: REST says 0, but WS tracking shows exposure. Trust WS.
                    logging.debug(f"⚠️ API Glitch: REST reported 0, but WS holds {ws_qty}. Ignoring REST wipe.")
                    return

                self._clear_inventory_preserve_pnl()
                await self.auditor.record("POSITION_SYNC", {"ticker": ticker, "result": "flat_confirmed"})
                return

            # Desync detected — rebuild InventoryManager from API data
            new_inv  = InventoryManager()
            new_inv.realized_cents = self.inventory.realized_cents  # preserve daily PnL
            if qty > 0:
                cost = float(matching_pos.get("average_price_cents") or self._get_yes_mid())
                new_inv.yes_qty        = qty
                new_inv.yes_cost_cents = cost * qty
                self.active_side       = "yes"
            else:
                abs_qty  = abs(qty)
                raw_cost = float(matching_pos.get("average_price_cents") or 50.0)
                no_cost  = (100.0 - raw_cost) if self.config.get("no_price_inversion", True) else raw_cost
                new_inv.no_qty        = abs_qty
                new_inv.no_cost_cents = no_cost * abs_qty
                self.active_side      = "no"

            async with self._inventory_lock:
                self.inventory = new_inv
            await self.auditor.record("POSITION_SYNC", {
                "ticker": ticker, "qty": qty,
                "side": self.active_side, "result": "desync_corrected",
            })
            logging.warning(f"⚠️ POSITION SYNC: Restored {abs(qty)} {self.active_side.upper()} contracts from API [{ticker}]")

        except Exception as e:
            await self.auditor.record("POSITION_SYNC_FAILED", {"ticker": ticker, "error": str(e)})

    async def _dump_full_position(self, yes_mid: float):
        """
        Two-layer dump guard:
          1. _dump_in_flight fast-fail boolean — zero-cost check, returns immediately
             if a dump sequence is already in progress (no lock contention).
          2. _dump_lock asyncio.Lock — formal mutual exclusion. If the fast-fail
             somehow races at an await boundary, the lock guarantees only one
             _dump_full_position_inner executes at a time.
        """
        if self._dump_in_flight:
            return
        self._dump_in_flight = True
        try:
            async with self._dump_lock:
                await self._dump_full_position_inner(yes_mid)
        finally:
            self._dump_in_flight = False

    async def _dump_full_position_inner(self, yes_mid: float):
        """
        Cancel all resting legs, then flatten with an IOC retry loop.
        Polls for WS fill confirmation after each sell clip. If the IOC order
        expires without a fill, re-prices and retries up to dump_max_retries.
        On exhaustion, syncs against Kalshi REST and fires a ghost-position alert.
        """
        if self.inventory.open_position() == 0:
            return   # second concurrent dump reached the lock after first already flattened
        await self.cancel_active_orders()

        # BARRIER: Wait up to 3 seconds for 429s to clear and book to confirm clean
        for _ in range(30):
            if not self.pending_orders:
                break
            await asyncio.sleep(0.1)

        if self.pending_orders:
            logging.warning(f"⚠️ DUMP BARRIER TIMEOUT: {len(self.pending_orders)} orders still resting. Proceeding with dump.")

        await asyncio.sleep(0.5)   # let WS deliver any in-flight fills first

        # TRUST WS STATE FOR EMERGENCY DUMPS (Bypass lagging REST API)
        qty_to_dump = self.inventory.yes_qty if self.active_side == "yes" else self.inventory.no_qty

        if qty_to_dump <= 0:
            logging.info("✅ DUMP: WS Inventory confirms flat. No orders placed.")
            return

        ioc_secs    = float(self.config.get("ioc_timeout_secs", 3))
        max_retries = int(self.config.get("dump_max_retries", 5))

        for attempt in range(max_retries):
            pos = self.inventory.open_position()
            if pos == 0:
                return

            # Re-price on every attempt so we cross whatever the current spread is
            current_mid = self._get_yes_mid()
            success = await self._sell_clip(abs(pos))
            if not success:
                await asyncio.sleep(0.2)
                continue

            # Poll for WS fill confirmation until IOC expiry + small buffer
            deadline = time.time() + ioc_secs + 0.5
            while time.time() < deadline:
                await asyncio.sleep(0.2)
                if self.inventory.open_position() == 0:
                    return   # WS confirmed fill — done

            # Still holding after IOC timeout — log and loop for a fresh attempt
            remaining = self.inventory.open_position()
            if remaining > 0:
                await self.auditor.record("DUMP_RETRY", {
                    "attempt": attempt + 1,
                    "remaining": remaining,
                    "mid": current_mid,
                })

        # All retries exhausted — hit the REST API for ground truth
        if self.active_ticker:
            await self._sync_position_from_api(self.active_ticker)

        if self.inventory.open_position() > 0:
            await self.auditor.record("DUMP_EXHAUSTED_GHOST_RISK", {
                "remaining":  self.inventory.open_position(),
                "ticker":     self.active_ticker,
                "net_unreal": self.inventory.net_unrealized_cents(self._get_yes_mid()),
            })
            logging.critical(
                f"🚨 GHOST POSITION: {self.inventory.open_position()} contracts "
                f"may still be held on Kalshi [{self.active_ticker}]. "
                f"Check your account immediately."
            )

    # ─────────────────────────────────────────────────────────────────────────
    # MARKET DISCOVERY  (Sentinel series ticker + 210s floor)
    # ─────────────────────────────────────────────────────────────────────────

    async def discover_btc_market(self) -> tuple | None:
        """Returns (time_left_secs, ticker, close_dt) or None.

        Upgraded: ATM-strike selection against live Binance spot oracle.
        Instead of blindly grabbing valid[0] by time_left, we now:
          1. Wait for the Binance WS to deliver the first price tick.
          2. Filter markets to the 210–1000s entry window.
          3. Isolate the nearest expiry bucket (smallest close_time).
          4. Within that bucket, select the strike whose price is closest
             to self.live_btc_price (true At-The-Money selection).
        """
        # ── 1. Oracle Warmup Barrier ─────────────────────────────────────────
        # Wait for either Binance Spot OR Futures to warm up
        while not (self.live_btc_price or self.futures_price):
            logging.info("⏳ Waiting for Binance oracle warmup to determine ATM strike...")
            await asyncio.sleep(1.0)

        # Snapshot the safest available live price for ATM comparison
        spot = float(self.live_btc_price or self.futures_price)
        logging.info(f"🎯 Oracle confirmed for ATM selection. Live Reference: ${spot:,.2f}")

        # ── 2. Fetch open markets ────────────────────────────────────────────
        res     = await self.api.request("GET", "/markets?series_ticker=KXBTC15M&status=open")
        markets = res.get("markets", [])
        if not markets:
            return None

        # ── 3. Build candidate list with strike extraction ───────────────────
        # Each entry: (time_left, ticker, close_dt, strike_price)
        candidates: list[tuple[float, str, datetime.datetime, float]] = []

        for m in markets:
            close_dt  = datetime.datetime.fromisoformat(
                m["close_time"].replace("Z", "+00:00")
            )
            time_left = (
                close_dt - datetime.datetime.now(datetime.timezone.utc)
            ).total_seconds()

            if time_left <= 210:
                logging.info(
                    f"⏭️ SKIP: {m['ticker']} has {int(time_left)}s left — below 210s entry floor."
                )
                continue
            if time_left > 1000:
                continue  # Too far out — not our window

            # ── Strike extraction (multi-method, most-specific-first) ────────
            strike_price: float | None = None

            # Method A: direct numeric fields from Kalshi V2
            for field in ("yes_strike", "floor_strike", "cap_strike"):
                raw = m.get(field)
                if raw is not None:
                    try:
                        strike_price = float(raw)
                        break
                    except (TypeError, ValueError):
                        pass

            # Method B: subtitle string (e.g. "$67,500" or "67714.92")
            if strike_price is None:
                subtitle = m.get("subtitle") or m.get("yes_sub_title") or ""
                if subtitle:
                    # Strip currency symbols, commas, whitespace; grab first numeric token
                    import re as _re
                    nums = _re.findall(r"[\d]+(?:[.,]\d+)*", subtitle.replace(",", ""))
                    if nums:
                        try:
                            strike_price = float(nums[0])
                        except ValueError:
                            pass

            # Method C: ticker suffix (e.g. "KXBTC15M-26MAR3100-B67500" → 67500)
            if strike_price is None:
                ticker_str = m.get("ticker", "")
                parts = ticker_str.split("-")
                if parts:
                    suffix = parts[-1].lstrip("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")
                    try:
                        strike_price = float(suffix)
                    except ValueError:
                        pass

            if strike_price is None:
                logging.warning(
                    f"⚠️ SKIP: {m['ticker']} — could not extract strike price from any field."
                )
                continue

            candidates.append((time_left, m["ticker"], close_dt, strike_price))

        if not candidates:
            return None

        # ── 4. ATM selection: nearest expiry bucket → minimum |Δ strike| ────
        # Identify the smallest close_time among all candidates (nearest expiry).
        nearest_close = min(c[2] for c in candidates)

        # Tolerance: treat markets within 5 s of the nearest close_time as the same bucket.
        _bucket_tol = datetime.timedelta(seconds=5)
        bucket = [
            c for c in candidates
            if abs((c[2] - nearest_close).total_seconds()) <= _bucket_tol.total_seconds()
        ]

        # Select the candidate whose strike is closest to live spot
        atm = min(bucket, key=lambda c: abs(c[3] - spot))
        time_left_atm, ticker_atm, close_dt_atm, strike_atm = atm

        delta = strike_atm - spot
        logging.info(
            f"🎯 ATM LOCK  | ticker={ticker_atm} | "
            f"spot=${spot:,.2f} | strike=${strike_atm:,.2f} | "
            f"Δ={delta:+.2f} | {int(time_left_atm)}s to close"
        )

        return (time_left_atm, ticker_atm, close_dt_atm)

    # ─────────────────────────────────────────────────────────────────────────
    # ④ RUN  (Sentinel outer loop structure + Wolf task set)
    # ─────────────────────────────────────────────────────────────────────────

    async def run(self):
        # Patch 1: bind locks to the active running event loop, not the __init__ loop.
        self._dump_lock      = asyncio.Lock()
        self._inventory_lock = asyncio.Lock()
        await self.api.start_session()
        await TelegramAlerts.start()
        _t_boot = asyncio.create_task(TelegramAlerts.send("🐺 ChopWolf BTC online — hunting KXBTC15M [TIGHT CHOP MODE]"))
        self._bg_tasks.add(_t_boot)
        _t_boot.add_done_callback(self._bg_tasks.discard)
        await self.auditor.record("WOLF_BOOT", {"config": self.config})

        # Persistent Binance tasks — never per-cycle
        binance_task  = asyncio.create_task(self.listen_to_binance_ws(),         name="binance_spot")
        futures_task  = asyncio.create_task(self.listen_to_binance_futures_ws(),  name="binance_perp")
        self._bg_tasks.add(binance_task)
        self._bg_tasks.add(futures_task)
        binance_task.add_done_callback(self._bg_tasks.discard)
        futures_task.add_done_callback(self._bg_tasks.discard)

        try:
            while True:
                market_data = await self.discover_btc_market()
                if not market_data:
                    logging.info("No valid KXBTC15M market. Sleeping 12s...")
                    await asyncio.sleep(12)
                    continue

                time_left, ticker, close_dt = market_data

                if ticker in self.blacklisted_tickers:
                    if time.time() < self.blacklisted_tickers[ticker]:
                        logging.info(f"⏭️ SKIP: {ticker} is on cooldown (Burned Hand).")
                        await asyncio.sleep(12)
                        continue
                    else:
                        del self.blacklisted_tickers[ticker]

                await self._reset_cycle_state()
                self.active_side = "yes"  # P0 Fix: Hardcode side for YES-only grid

                # Dynamic balance fetch — keeps capital exposure cap accurate each cycle
                try:
                    bal_res = await self.api.request("GET", "/portfolio/balance")
                    self.current_balance = float(bal_res.get("balance", 10000)) / 100.0
                    logging.info(f"💰 Balance refreshed: ${self.current_balance:.2f}")
                except Exception as _be:
                    logging.warning(f"Balance fetch failed: {_be} — using ${self.current_balance:.2f}")

                self.active_ticker     = ticker
                self.market_close_time = close_dt
                self.is_running        = True

                # Restore any orphaned position from a prior crash or partial IOC exit.
                # Must run before tasks spin up so inventory is accurate from tick 1.
                await self._sync_position_from_api(ticker)
                if self.inventory.open_position() > 0:
                    logging.info(
                        f"🔄 POSITION RESTORED: {self.inventory.open_position()} "
                        f"{self.active_side} contract(s) carried forward from API [{ticker}]"
                    )

                logging.info(f"=== Wolf BTC cycle: {ticker} | {int(time_left)}s remaining ===")

                ws_task    = asyncio.create_task(self.listen_to_market_data(ticker), name="kalshi_ws")
                quote_task = asyncio.create_task(self._quote_scan(),                name="quote_scan")

                self._bg_tasks.add(ws_task)
                self._bg_tasks.add(quote_task)
                ws_task.add_done_callback(self._bg_tasks.discard)
                quote_task.add_done_callback(self._bg_tasks.discard)

                all_tasks = {ws_task, quote_task}
                try:
                    while all_tasks:
                        done, pending = await asyncio.wait(
                            all_tasks, return_when=asyncio.FIRST_COMPLETED
                        )
                        for t in done:
                            if not t.cancelled():
                                exc = t.exception()
                                if isinstance(exc, CriticalDrawdownException):
                                    raise exc
                                elif exc:
                                    # Unhandled supervisor exception — hard crash is cleaner than zombifying.
                                    logging.critical(f"☠️ UNHANDLED SUPERVISOR EXCEPTION [{t.get_name()}]: {exc!r}")
                                    raise exc
                        all_tasks = pending
                        # is_running flipped False → cycle done, wind down remaining tasks
                        if not self.is_running:
                            for t in list(all_tasks):
                                t.cancel()
                            for t in list(all_tasks):
                                try:
                                    await t
                                except (asyncio.CancelledError, Exception):
                                    pass
                            break

                except CriticalDrawdownException:
                    for t in (ws_task, quote_task):
                        t.cancel()
                    raise

                # Cycle cleanup — flatten any position that survived the task teardown
                if self.inventory.open_position() > 0:
                    logging.warning("⚠️ Cycle ended with open position — flattening.")
                    try:
                        await self._dump_full_position(self._get_yes_mid())
                    except Exception as ex:
                        logging.error(f"Cycle-end dump failed: {ex}")

                await self.auditor.record("CYCLE_END", {"ticker": ticker})
                _t_cycle = asyncio.create_task(TelegramAlerts.send(f"🏁 Cycle Complete: {ticker}"))
                self._bg_tasks.add(_t_cycle)
                _t_cycle.add_done_callback(self._bg_tasks.discard)
                logging.info(f"=== BTC Cycle complete: {ticker}. Sleeping 12s. ===")
                await asyncio.sleep(12)

        except CriticalDrawdownException as e:
            logging.critical(f"☠️ CRITICAL DRAWDOWN: {e}. Stopping.")
            if self.inventory.open_position() > 0:
                try:
                    await self._dump_full_position(self._get_yes_mid())
                except Exception as ex:
                    logging.error(f"Emergency dump failed: {ex}")

        except asyncio.CancelledError:
            logging.info("Wolf cancelled — graceful shutdown.")

        finally:
            self.is_running = False
            binance_task.cancel()
            futures_task.cancel()
            await asyncio.gather(binance_task, futures_task, return_exceptions=True)
            await self.api.close_session()
            await self.auditor.record("WOLF_OFFLINE", {})
            # BUGFIX: await the send DIRECTLY before closing the session.
            await TelegramAlerts.send("🐺 ChopWolf BTC offline")
            await TelegramAlerts.close()


# ─────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    wolf = ChopWolf(config_path="wolf_config_tightchop_btc.yaml")
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(wolf.run())
    except KeyboardInterrupt:
        print("\n🛑 KeyboardInterrupt detected. Sweeping order book...")
    finally:
        # Guarantee all resting nets are cleared from Kalshi on exit
        loop.run_until_complete(wolf.cancel_active_orders())
        pending = [t for t in wolf._bg_tasks if not t.done()]
        if pending:
            loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
        loop.close()
        print("🐺 Wolf safely offline. Order book is clean.")
