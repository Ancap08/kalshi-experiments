"""
MomentumWolf_v2.py
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
from dataclasses import dataclass
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
_fh  = RotatingFileHandler("MomentumWolf.log", maxBytes=10*1024*1024, backupCount=5)
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
        if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID or cls._session is None:
            return
        url     = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        payload = {"chat_id": TELEGRAM_CHAT_ID, "text": f"🐺 MomentumWolf\n{message}"}
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
        self.log        = logging.getLogger("MomentumWolf")

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
        TAKER_FEE_CENTS = 3.6   # round-trip: entry + exit taker fee per contract
        if side == "yes":
            if action == "buy":
                self.yes_qty        += qty
                self.yes_cost_cents += qty * price_cents
            else:
                avg_cost             = self._active_yes_cost()
                self.realized_cents += (qty * (price_cents - avg_cost)) - (TAKER_FEE_CENTS * qty)
                self.yes_qty        -= qty
                self.yes_cost_cents -= qty * avg_cost
                if self.yes_qty <= 0:
                    self.yes_qty, self.yes_cost_cents = 0, 0.0
        else:   # "no"
            if action == "buy":
                self.no_qty        += qty
                self.no_cost_cents += qty * price_cents
            else:
                avg_cost             = self._active_no_cost()
                self.realized_cents += (qty * (price_cents - avg_cost)) - (TAKER_FEE_CENTS * qty)
                self.no_qty        -= qty
                self.no_cost_cents -= qty * avg_cost
                if self.no_qty <= 0:
                    self.no_qty, self.no_cost_cents = 0, 0.0

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
        TAKER_FEE_CENTS = 3.6
        gross           = self.unrealized_cents(current_yes_price)
        return gross - (TAKER_FEE_CENTS * self.open_position())

# ─────────────────────────────────────────────────────────────────────────────
# MOMENTUM WOLF v2
# ─────────────────────────────────────────────────────────────────────────────

class MomentumWolf:

    def __init__(self, config_path: str = "wolf_config.yaml"):
        with open(config_path) as fh:
            self.config: dict = yaml.safe_load(fh)

        self.api = AsyncKalshiClient(KALSHI_KEY_ID, KALSHI_PRIVATE_KEY_PATH, BASE_URL)
        self.auditor = AuditorV3(
            jsonl_path = self.config["jsonl_path"],
            pnl_path   = self.config.get("pnl_path", "pnl_tracker_eth.txt"),
        )

        # ── Binance oracle state (Sentinel variable names preserved) ────────
        self.live_eth_price:       float | None            = None
        self.eth_price_history:    list                    = []
        self.futures_price:        float | None            = None
        self.perp_basis:           float                   = 0.0
        self.basis_ema:            float                   = 0.0
        self.basis_shift:          float                   = 0.0
        self.velocity_ema:         float                   = 0.0
        self.binance_delta:        float                   = 0.0

        # V4 Data Plumbing
        self.eth_volume_history:   list                    = []
        self.btc_price_history:    list                    = []

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
        self.seen_trade_ids:       deque                   = deque(maxlen=5000)  # bounded; never cleared — prevents late-fill double-processing across cycles
        self.pending_orders:       dict                    = {}   # {kalshi_id: metadata}
        self.ws_last_msg_time:     float                   = time.time()
        self._strike_in_flight:    bool                    = False
        self._dump_in_flight:      bool                    = False   # fast-fail flag: prevents re-entry
        self._dump_lock:           asyncio.Lock | None     = None    # bound in run() to avoid loop-binding error in 3.10+
        self._last_heartbeat_time: float                   = 0.0
        self._last_stalled_log_time: float                 = 0.0
        self.score_history:        deque                   = deque(maxlen=5)   # first-derivative gate
        self.kalshi_bid_history:   list                    = []      # Kalshi-native velocity tracking
        self.kalshi_velocity:      float                   = 0.0     # cents/second from Kalshi ticker
        self.current_balance:      float                   = 100.0   # guard 3: updated per-cycle from API
        # Exit-tracking state (anti-whipsaw, post-TP exhaustion)
        self.last_exit_reason:     str | None              = None
        self.last_exit_time:       float                   = 0.0
        self.last_exit_price:      float                   = 0.0     # yes_mid at exit
        self.last_exit_side:       str | None              = None
        self.inventory                                     = InventoryManager()
        self._bg_tasks:            set                     = set()   # GC anchor for fire-and-forget tasks

    # ─────────────────────────────────────────────────────────────────────────
    # BINANCE SPOT WS  (verbatim Sentinel — .us stream, exponential backoff)
    # ─────────────────────────────────────────────────────────────────────────

    async def listen_to_binance_ws(self):
        uri = "wss://stream.binance.us:9443/stream?streams=ethusdt@aggTrade/btcusdt@aggTrade/ethusdt@bookTicker"
        logging.info("Connecting to Binance Combined Spot WS (ETH/BTC aggTrade + bookTicker)...")
        reconnect_delay = 5
        while True:
            try:
                async with websockets.connect(uri) as ws:
                    reconnect_delay = 5
                    logging.info("✅ Connected to Binance Combined ETH Spot feed (OFI active).")
                    while True:
                        message     = await ws.recv()
                        envelope    = json.loads(message)
                        stream_name = envelope.get("stream", "")
                        msg_data    = envelope.get("data", envelope)

                        if stream_name == "btcusdt@aggTrade":
                            price = float(msg_data.get("p", 0))
                            if price > 0:
                                now = time.time()
                                self.btc_price_history.append((now, price))
                                self.btc_price_history = [x for x in self.btc_price_history if now - x[0] <= 300]

                        elif stream_name == "ethusdt@aggTrade":
                            price = float(msg_data.get("p", 0))
                            qty   = float(msg_data.get("q", 0))
                            if price > 0:
                                now = time.time()
                                self.live_eth_price = price
                                self.eth_price_history.append((now, price))

                                # CVD Prep: negative qty for market sells, positive for market buys
                                signed_qty = -qty if msg_data.get("m", False) else qty
                                self.eth_volume_history.append((now, signed_qty))

                                # Prune arrays
                                self.eth_price_history  = [x for x in self.eth_price_history  if now - x[0] <= 15]
                                self.eth_volume_history = [x for x in self.eth_volume_history if now - x[0] <= 300]

                        elif stream_name.endswith("@bookTicker"):
                            try:
                                bp = float(msg_data["b"])
                                bq = float(msg_data["B"])
                                ap = float(msg_data["a"])
                                aq = float(msg_data["A"])
                                if bp > 0.0 and ap > 0.0:
                                    self._update_ofi(bp, bq, ap, aq)
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
        uri = "wss://fstream.binance.com/ws/ethusdt@ticker"
        logging.info("Connecting to Binance Futures WS (Perp Basis feed)...")
        reconnect_delay = 5
        prev_perp       = 0.0
        while True:
            try:
                async with websockets.connect(uri) as ws:
                    reconnect_delay = 5
                    logging.info("✅ Connected to Binance Futures ETH Perp feed.")
                    while True:
                        message    = await ws.recv()
                        data       = json.loads(message)
                        last_price = float(data.get("c", 0))
                        if last_price > 0:
                            self.futures_price = last_price
                            # Basis / shift
                            safe_spot = float(self.live_eth_price or 0.0)
                            if safe_spot > 0:
                                self.perp_basis  = last_price - safe_spot
                                self.basis_ema   = (self.perp_basis * 0.2) + (self.basis_ema * 0.8)
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
                                        self.kalshi_velocity = (
                                            self.live_exchange_bid - oldest_price
                                        ) / elapsed

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
        count          = int(float(raw_count))
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
        if (side == "no" or purchased_side == "no") and not in_no_space:
            yes_space = price
            price     = 100.0 - yes_space   # YES-space → NO-space cents
            logging.info(f"🔄 NO FILL (YES-fallback): YES {yes_space:.1f}¢ → NO cost {price:.1f}¢")

        # ── Apply to inventory ─────────────────────────────────────────────
        order_id = fill_data.get("order_id", "")
        if order_id in self.pending_orders:
            self.pending_orders.pop(order_id)

        self.inventory._apply_fill_to_inventory(side, count, price, action)
        await self.auditor.record("WS_FILL", {
            "order_id": order_id, "side": side,
            "qty": count, "price": price, "action": action,
        })

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
            # Compute once — reused for all checks below
            naked        = -self.inventory.unrealized_cents(yes_mid)
            max_loss     = cfg["hard_stop_naked_cents"] * pos
            live_spread  = self.live_exchange_ask - self.live_exchange_bid
            spread_blown = live_spread > cfg.get("spread_blown_threshold_cents", 10.0)

            # Instant Gap Stop-Loss: gated behind spread guard — a blown spread is a
            # low-liquidity artifact, not a real gap loss. Skip only this check when wide.
            # Velocity and hard-stop ALWAYS evaluate regardless of spread.
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
        arm_threshold = max(quick_profit * 0.75, 8.0 + (2.0 * pos))
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
            _tg_task = asyncio.create_task(TelegramAlerts.send(
                f"💸 Cycle complete: {self.active_ticker}\nCycle PnL: {cycle_pnl:.2f}¢"
            ))
            self._bg_tasks.add(_tg_task)
            _tg_task.add_done_callback(self._bg_tasks.discard)
            _tg_task.add_done_callback(
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
        self.kalshi_bid_history    = []
        self.kalshi_velocity       = 0.0
        self.live_exchange_bid     = 0.0
        self.live_exchange_ask     = 0.0
        self.live_exchange_bid_qty = 0
        self.live_exchange_ask_qty = 0
        self.pending_orders.clear()
        # seen_trade_ids intentionally NOT cleared — deque(maxlen=5000) self-manages memory.
        # Preserving IDs across cycles prevents late Kalshi fills from prior cycle being double-processed.
        if self.inventory.open_position() == 0:
            self._clear_inventory_preserve_pnl()   # preserves realized_cents for vault guard
        self.session_peak_pnl      = 0.0   # bug fix: prevent false ratchet on new cycle
        # Oracle state reset — prevents traded asset history from contaminating the next cycle.
        # NOTE: Macro rolling volume and BTC Anchor history are intentionally preserved across cycles.
        self.eth_price_history     = []
        self.ofi_ema               = 0.0
        self.ofi_scalar            = 0.0
        self.ofi_prev_bid_price    = None
        self.ofi_prev_ask_price    = None
        self.ofi_prev_bid_qty      = 0.0
        self.ofi_prev_ask_qty      = 0.0
        # EMA state bleed fix: zero directional signals so a dying market's
        # velocity/basis/delta don't seed the first ticks of a new cycle.
        self.velocity_ema          = 0.0
        self.basis_ema             = 0.0
        self.basis_shift           = 0.0
        self.binance_delta         = 0.0
        # last_exit_* intentionally NOT reset here — they are cross-cycle cooldown
        # triggers (anti-whipsaw, post-TP exhaustion) and must survive the reset.
        self.ws_last_msg_time      = time.time()
        await self.auditor.record("CYCLE_RESET", {})

    # ─────────────────────────────────────────────────────────────────────────
    # WS-ONLY MARK PRICE  (synchronous, zero REST)
    # ─────────────────────────────────────────────────────────────────────────

    def _get_yes_mid(self) -> float:
        bid = self.live_exchange_bid
        ask = self.live_exchange_ask
        if bid <= 0 or ask <= 0:
            return 50.0
        return (bid + ask) / 2.0

    # ─────────────────────────────────────────────────────────────────────────
    # ① CALCULATE MOMENTUM SCORE
    # ─────────────────────────────────────────────────────────────────────────

    def calculate_momentum_score(self) -> float:
        """
        Normalized composite momentum. Returns float in [-1, 1].
        Components:
          binance_delta  — 15-second spot price window (Sentinel approach)
          ofi_scalar     — BBO order-flow imbalance (Sentinel _update_ofi)
          basis_shift    — perp basis deviation from EMA
          velocity_ema   — tick-to-tick perp velocity EMA
        """
        cfg           = self.config
        ofi_component = self.ofi_scalar * cfg["ofi_q0_influence"]
        k_vel_norm    = max(-1.0, min(1.0, self.kalshi_velocity / 2.0))
        # Clamp raw delta to ±15.0 so a large spot move cannot saturate the
        # composite oracle and drown out OFI, Basis, and Velocity signals.
        clamped_delta = max(-15.0, min(15.0, self.binance_delta))
        clamped_vel   = max(-15.0, min(15.0, self.velocity_ema))
        # Clamp basis contribution to max ±12.0 raw score points
        # (max 0.30 impact on final normalized score)
        raw_basis_contrib    = cfg["w_basis"] * self.basis_shift
        clamped_basis_contrib = max(-12.0, min(12.0, raw_basis_contrib))
        raw = (
            cfg["w_delta"]                    * clamped_delta      +
            cfg["w_ofi"]                      * ofi_component      +
            clamped_basis_contrib                                   +
            cfg["w_velocity"]                 * clamped_vel        +
            cfg.get("w_kalshi_vel", 0.0)      * k_vel_norm
        )
        return max(-1.0, min(1.0, raw / cfg["score_norm_factor"]))

    # ─────────────────────────────────────────────────────────────────────────
    # ② EXECUTE PYRAMID STRIKE
    # ─────────────────────────────────────────────────────────────────────────

    async def execute_pyramid_strike(self, tier: int):
        if self._dump_in_flight:
            return
        # Reset ratchet peak when opening a fresh position so prior realized
        # gains don't ghost-arm the ratchet on the new trade.
        if self.inventory.open_position() == 0:
            self.session_peak_pnl = self.inventory.realized_cents
        if not self.active_ticker or not self.active_side:
            return
        self._strike_in_flight = True
        try:
            await self._execute_pyramid_strike_inner(tier)
        finally:
            self._strike_in_flight = False

    async def _execute_pyramid_strike_inner(self, tier: int):
        # Restore log so silent blocks are visible in the flight recorder.
        # Root cause of the "no BAD_ODDS_BLOCKED log" bug: a fresh WS reconnect
        # resets ws_price_valid = False; one-sided ticker ticks leave it False;
        # the strike returns here before any price guard ever runs.
        if not self.ws_price_valid:
            await self.auditor.record("STRIKE_BLOCKED_STALE_PRICE", {
                "tier": tier,
                "bid": self.live_exchange_bid,
                "ask": self.live_exchange_ask,
            })
            return

        pyramid_levels: list = self.config["pyramid_levels"]
        step = self.pyramid_step
        if step >= len(pyramid_levels):
            await self.auditor.record("PYRAMID_MAXED", {"step": step})
            return

        # FIX 4: cancel any resting orders before adding to an existing position
        # so stale sell legs cannot fill against the incoming pyramid clip.
        if self.inventory.open_position() > 0:
            await self.cancel_active_orders()

        qty     = pyramid_levels[step]
        yes_mid = self._get_yes_mid()

        # Soft avg-cost guardrail — compare current mark vs per-contract avg cost
        guard_pct = self.config["avg_cost_guard_pct"] / 100
        if self.active_side == "yes" and self.inventory.yes_qty > 0:
            avg = self.inventory._active_yes_cost()   # per-contract YES-space
            if yes_mid < avg * (1 - guard_pct):
                await self.auditor.record("AVG_COST_GUARD_BLOCKED", {"avg": avg, "mid": yes_mid})
                return
        elif self.active_side == "no" and self.inventory.no_qty > 0:
            avg    = self.inventory._active_no_cost()  # per-contract NO-space
            no_mid = 100.0 - yes_mid
            if no_mid < avg * (1 - guard_pct):
                await self.auditor.record("AVG_COST_GUARD_BLOCKED", {"avg": avg, "no_mid": no_mid})
                return

        # Compute limit_price before guards so all checks share the same value
        if self.active_side == "yes":
            limit_price = int(min(self.live_exchange_ask + 1, 99))
        else:
            no_ask      = 100.0 - self.live_exchange_bid
            limit_price = int(min(no_ask + 1.0, 99.0))

        # Guard 4: Bad Odds ceiling — enforced at every pyramid step.
        # Step 0: block entry entirely (BAD_ODDS_BLOCKED).
        # Step > 0: cap the chase price at the ceiling rather than blocking —
        #   we still want to fill a pyramid add, just never above bad odds.
        bad_odds_ceil = int(self.config.get("bad_odds_tier1_cents", 68))
        if step == 0 and limit_price > bad_odds_ceil:
            await self.auditor.record("BAD_ODDS_BLOCKED", {
                "price": limit_price, "ceiling": bad_odds_ceil, "step": step,
            })
            return
        elif step > 0 and limit_price > bad_odds_ceil:
            await self.auditor.record("CHASE_PRICE_CAPPED", {
                "original_price": limit_price, "ceiling": bad_odds_ceil, "step": step,
            })
            limit_price = bad_odds_ceil

        # Guard 5: Bottom-Feeder Floor — never open a Tier-1 position below the floor.
        # Prevents entering effectively-dead 2¢ contracts during extreme Binance rips.
        # Floor is config-driven (min_entry_price_cents, default 35¢).
        floor_cents = int(self.config.get("min_entry_price_cents", 35))
        if step == 0 and limit_price < floor_cents:
            await self.auditor.record("BOTTOM_FEEDER_BLOCKED", {
                "price": limit_price, "floor": floor_cents,
            })
            return

        # Guard 6.5: V4 L2 Liquidity Guard — ratio-scaled depth check, step 0 only.
        # Protects initial entries from thin books. Chase steps (step > 0) are exempt
        # so the bot is never blocked from adding to or exiting an existing position.
        if step == 0:
            min_ratio = float(self.config.get("min_liquidity_ratio", 2.0))
            required  = qty * min_ratio

            if self.active_side == "yes":
                available = self.live_exchange_ask_qty
            else:
                available = self.live_exchange_bid_qty

            if available < required:
                await self.auditor.record("L2_LIQUIDITY_REJECT", {
                    "side": self.active_side, "qty": qty,
                    "required": required, "available": available,
                })
                return

        # Guard 7: L2 Liquidity Check — verify sufficient BBO depth before striking.
        # YES buy: needs ask-side contracts. NO buy: needs bid-side contracts
        # (NO buyers are YES bid-side participants).
        # If available < 3, block entirely. If available < qty, cap to available.
        if self.active_side == "yes":
            available_liq = self.live_exchange_ask_qty
        else:
            available_liq = self.live_exchange_bid_qty

        if available_liq < 3:
            await self.auditor.record("LIQUIDITY_BLOCKED", {
                "available": available_liq, "needed": qty,
                "side": self.active_side, "price": limit_price, "tier": tier,
            })
            return

        if available_liq < qty:
            original_qty = qty
            qty          = available_liq
            await self.auditor.record("LIQUIDITY_CAPPED", {
                "original_qty": original_qty, "capped_qty": qty,
                "side": self.active_side, "price": limit_price,
            })

        # Guard 3: Capital Exposure Cap (5% of bankroll)
        max_spend_cents = self.current_balance * 100 * 0.05
        if qty * limit_price > max_spend_cents:
            qty = max(1, int(max_spend_cents / max(limit_price, 1)))

        # Build order with final (possibly capped) qty
        client_oid = str(uuid.uuid4())
        if self.active_side == "yes":
            order = {
                "action":          "buy",
                "client_order_id": client_oid,
                "count":           qty,
                "side":            "yes",
                "ticker":          self.active_ticker,
                "type":            "limit",
                "yes_price":       limit_price,
                "time_in_force":   "immediate_or_cancel",
            }
        else:
            order = {
                "action":          "buy",
                "client_order_id": client_oid,
                "count":           qty,
                "side":            "no",
                "ticker":          self.active_ticker,
                "type":            "limit",
                "no_price":        limit_price,
                "time_in_force":   "immediate_or_cancel",
            }

        self.pyramid_step += 1   # eager — increment before network yield to prevent race
        try:
            res       = await self.api.request("POST", "/portfolio/orders", body=order)
            kalshi_id = res.get("order", {}).get("order_id")
            if not kalshi_id:
                await self.auditor.record("STRIKE_NO_ORDER_ID", {"res": str(res)[:200]})
                self.pyramid_step = max(0, self.pyramid_step - 1)
                if self.active_ticker:
                    _sync_task = asyncio.create_task(self._sync_position_from_api(self.active_ticker))
                    self._bg_tasks.add(_sync_task)
                    _sync_task.add_done_callback(self._bg_tasks.discard)
                return
            self.pending_orders[kalshi_id] = {
                "side":         self.active_side,
                "qty":          qty,
                "price":        limit_price,
                "action":       "buy",
            }
            # Belt-and-suspenders: cancel via REST if still resting after ioc_timeout.
            # Pass pyramid_step snapshot so rollback is reliable even if
            # cancel_active_orders() pre-clears pending_orders before this fires.
            _ioc_task = asyncio.create_task(
                self._cancel_if_unfilled(
                    kalshi_id, self.config.get("ioc_timeout_secs", 3), self.pyramid_step
                ),
                name=f"ioc_{kalshi_id[:8]}",
            )
            self._bg_tasks.add(_ioc_task)
            _ioc_task.add_done_callback(self._bg_tasks.discard)
            if not self.cycle_entry_time:
                self.cycle_entry_time = time.time()
            await self.auditor.record("PYRAMID_STRIKE", {
                "tier": tier, "step": step, "qty": qty,
                "price": limit_price, "side": self.active_side,
                "ticker": self.active_ticker, "kalshi_id": kalshi_id,
            })
            await TelegramAlerts.send(
                f"🐺 STRIKE tier={tier} step={step} "
                f"{qty}× {self.active_side.upper()} @ {limit_price}¢ [{self.active_ticker}]"
            )
        except Exception as e:
            # Assume-assent: API exception ≠ rejection. Order may have landed.
            # Do NOT roll back pyramid_step — sync REST to reconcile truth.
            logging.warning(
                f"🚨 STRIKE EXCEPTION tier={tier} — assume assent, syncing REST. err={e}"
            )
            await self.auditor.record("STRIKE_FAILED_ASSENT", {"error": str(e), "tier": tier})
            if self.active_ticker:
                _sync_task = asyncio.create_task(self._sync_position_from_api(self.active_ticker))
                self._bg_tasks.add(_sync_task)
                _sync_task.add_done_callback(self._bg_tasks.discard)

    # ─────────────────────────────────────────────────────────────────────────
    # ③ MANAGE WOLF EXITS
    # ─────────────────────────────────────────────────────────────────────────

    async def manage_wolf_exits(self):
        """
        250ms exit loop. Loops on is_running so it exits cleanly with the cycle.
        Priority 1: nuclear risk hierarchy (+ exit tracking for anti-whipsaw).
        Priority 2: fee-aware ripcord / hold-to-settlement (final 3 minutes).
        Priority 3: profit-taking per exit_mode (micro-scalp fee block applied).
        """
        last_snapshot_time = 0.0   # throttle pnl_snapshot to every 5s
        while self.is_running:
            await asyncio.sleep(0.25)

            if not self.active_ticker or self.inventory.open_position() == 0:
                continue

            if self.live_exchange_bid <= 0.0 or self.live_exchange_ask <= 0.0:
                continue   # WS blip — skip tick, never compute yes_mid from stale book

            yes_mid = self._get_yes_mid()

            # Compute time_left once — used by ripcord and settlement logic
            time_left = 0.0
            if self.market_close_time:
                time_left = (
                    self.market_close_time -
                    datetime.datetime.now(datetime.timezone.utc)
                ).total_seconds()

            # ── PRIORITY 1: nuclear risk hierarchy ────────────────────────
            if not self._dump_in_flight:
                try:
                    self._run_full_risk_hierarchy(yes_mid)
                except (GuillotineException, DislocationEjectorException) as e:
                    await self.auditor.record("RISK_DUMP", {"reason": str(e)})
                    self.last_exit_reason = "STOP_LOSS"
                    self.last_exit_time   = time.time()
                    self.last_exit_price  = yes_mid
                    self.last_exit_side   = self.active_side
                    if self._dump_in_flight:
                        # A concurrent dump already owns the sequence — skip this tick
                        # so the loop stays alive rather than killing the 250ms monitor.
                        continue
                    await self._dump_full_position(yes_mid)
                    await self._reset_cycle_state()
                    return
                except CriticalDrawdownException:
                    raise

            unreal    = self.inventory.unrealized_cents(yes_mid)
            net_unreal = self.inventory.net_unrealized_cents(yes_mid)
            exit_mode = self.config["exit_mode"]
            quick_tgt = self.config["quick_profit_cents"]

            # ── 70¢ HARD EXIT CEILING ─────────────────────────────────────
            # Dump any position whose held-asset mark hits 70¢ regardless of
            # exit_mode. YES at 70¢ or NO at 70¢ (YES at 30¢) both trigger.
            # Prevents holding through settlement on deep-ITM contracts where
            # liquidity evaporates and slippage becomes catastrophic.
            _hit_ceiling = (
                (self.active_side == "yes" and yes_mid >= 70.0) or
                (self.active_side == "no"  and (100.0 - yes_mid) >= 70.0)
            )
            if _hit_ceiling:
                await self.auditor.record("FULL_DUMP", {"reason": "70_CEILING", "yes_mid": yes_mid})
                await TelegramAlerts.send(
                    f"🐺 DUMP [70_CEILING] yes_mid={yes_mid:.1f}¢ [{self.active_ticker}]"
                )
                self.last_exit_reason = "70_CEILING"
                self.last_exit_time   = time.time()
                self.last_exit_price  = yes_mid
                self.last_exit_side   = self.active_side
                await self._dump_full_position(yes_mid)
                await self._reset_cycle_state()
                return

            # ── PRIORITY 2: Fee-Aware Ripcord (final 3 minutes) ───────────
            if 0 < time_left <= 180:
                # True bid of held asset in its own space
                if self.active_side == "yes":
                    asset_bid = self.live_exchange_bid
                else:
                    asset_bid = 100.0 - self.live_exchange_ask   # NO bid in NO-space

                if asset_bid >= 97.0:
                    # Hold to settlement — guaranteed payout, bypass all profit logic
                    if time.time() - last_snapshot_time >= 5.0:
                        await self.auditor.pnl_snapshot(
                            self.inventory.realized_cents,
                            self.inventory.unrealized_cents(yes_mid),
                        )
                        last_snapshot_time = time.time()
                    continue

                elif 92.0 <= asset_bid < 97.0:
                    # Ripcord: lock profit before liquidity evaporates
                    await self.auditor.record("FULL_DUMP", {
                        "reason": "3_MIN_RIPCORD",
                        "asset_bid": asset_bid,
                        "unreal": unreal,
                    })
                    await TelegramAlerts.send(
                        f"🐺 RIPCORD [bid={asset_bid:.1f}¢] [{self.active_ticker}]"
                    )
                    self.last_exit_reason = "3_MIN_RIPCORD"
                    self.last_exit_time   = time.time()
                    self.last_exit_price  = yes_mid
                    self.last_exit_side   = self.active_side
                    await self._dump_full_position(yes_mid)
                    await self._reset_cycle_state()
                    return

            # ── PRIORITY 3: profit-taking ──────────────────────────────────
            # God-Candle Conviction Hold: in the final 3 minutes the Priority 2
            # Ripcord (92/97 thresholds) owns exit management. Bypass quick_profit
            # entirely so high-conviction trades are not prematurely dumped.
            if time_left <= 180:
                if time.time() - last_snapshot_time >= 5.0:
                    await self.auditor.pnl_snapshot(
                        self.inventory.realized_cents,
                        self.inventory.unrealized_cents(yes_mid),
                    )
                    last_snapshot_time = time.time()
                continue

            if exit_mode == "full_dump":
                score         = self.calculate_momentum_score()
                reversed_flag = (
                    (self.active_side == "yes" and score < -self.config["reversal_threshold"]) or
                    (self.active_side == "no"  and score >  self.config["reversal_threshold"])
                )
                # Reversal is unconditional — bypasses fee filter, exits immediately
                if reversed_flag:
                    await self.auditor.record("FULL_DUMP", {
                        "reason": "REVERSAL", "unreal": unreal, "net_unreal": net_unreal,
                    })
                    await TelegramAlerts.send(
                        f"🐺 DUMP [REVERSAL] gross={unreal:.2f}¢ net={net_unreal:.2f}¢ [{self.active_ticker}]"
                    )
                    self.last_exit_reason = "REVERSAL"
                    self.last_exit_time   = time.time()
                    self.last_exit_price  = yes_mid
                    self.last_exit_side   = self.active_side
                    await self._dump_full_position(yes_mid)
                    await self._reset_cycle_state()
                    return
                # Profit target: fee-gated — only exit if net PnL has cleared the threshold
                if unreal >= quick_tgt and net_unreal > quick_tgt:
                    await self.auditor.record("FULL_DUMP", {
                        "reason": "PROFIT_TARGET", "unreal": unreal, "net_unreal": net_unreal,
                    })
                    await TelegramAlerts.send(
                        f"🐺 DUMP [PROFIT_TARGET] gross={unreal:.2f}¢ net={net_unreal:.2f}¢ [{self.active_ticker}]"
                    )
                    self.last_exit_reason = "PROFIT_TARGET"
                    self.last_exit_time   = time.time()
                    self.last_exit_price  = yes_mid
                    self.last_exit_side   = self.active_side
                    await self._dump_full_position(yes_mid)
                    await self._reset_cycle_state()
                    return

            elif exit_mode == "scale_out":
                t1 = self.config["scale_tier1_cents"]
                t2 = self.config["scale_tier2_cents"]

                if unreal > self.trade_peak_unrealized:
                    self.trade_peak_unrealized = unreal

                open_pos = self.inventory.open_position()

                if unreal >= t1 and not self._scale_t1_done:
                    if net_unreal > 0:   # only clip if net-positive after fees
                        clip = max(1, open_pos // 2)
                        if await self._sell_clip(clip, yes_mid):   # gate on API success
                            self._scale_t1_done = True
                            await self.auditor.record("SCALE_T1", {
                                "clip": clip, "unreal": unreal, "net_unreal": net_unreal,
                            })

                elif unreal >= t2 and self._scale_t1_done and not self._scale_t2_done:
                    if net_unreal > 0:   # only clip if net-positive after fees
                        clip = max(1, int(self.inventory.open_position() * 0.6))
                        if await self._sell_clip(clip, yes_mid):   # gate on API success
                            self._scale_t2_done = True
                            await self.auditor.record("SCALE_T2", {
                                "clip": clip, "unreal": unreal, "net_unreal": net_unreal,
                            })

                elif self._scale_t2_done and self.inventory.open_position() > 0:
                    runner_stop = self.config["runner_trailing_stop_cents"]
                    if self.trade_peak_unrealized - unreal > runner_stop:
                        self.last_exit_reason = "RUNNER_STOPPED"
                        self.last_exit_time   = time.time()
                        self.last_exit_price  = yes_mid
                        self.last_exit_side   = self.active_side
                        await self._dump_full_position(yes_mid)
                        await self.auditor.record("RUNNER_STOPPED", {"unreal": unreal})
                        await self._reset_cycle_state()
                        return

            if time.time() - last_snapshot_time >= 5.0:
                await self.auditor.pnl_snapshot(
                    self.inventory.realized_cents,
                    self.inventory.unrealized_cents(yes_mid),
                )
                last_snapshot_time = time.time()

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

    async def cancel_active_orders(self):
        """Fire-and-forget REST cancels — returns immediately, does not block dump path."""
        ids = list(self.pending_orders.keys())
        self.pending_orders.clear()   # mark locally clean before awaiting network
        for oid in ids:
            async def _do_cancel(order_id: str = oid):
                try:
                    await self.api.request("DELETE", f"/portfolio/orders/{order_id}")
                    await self.auditor.record("ORDER_CANCELLED", {"oid": order_id})
                except Exception as _ce:
                    await self.auditor.record("CANCEL_ERROR", {"oid": order_id, "err": str(_ce)})
            _t = asyncio.create_task(_do_cancel())
            self._bg_tasks.add(_t)
            _t.add_done_callback(self._bg_tasks.discard)

    async def _sell_clip(self, qty: int, yes_mid: float):
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
                self.pending_orders[kalshi_id] = {"action": "sell", "qty": qty}
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

            # Guard: empty/error response must not wipe a live inventory.
            # {} means 503/429/retry-exhausted — NOT a confirmed flat.
            if not res or "market_positions" not in res:
                logging.error(
                    f"🚨 SYNC ABORTED — API returned empty/invalid response [{ticker}]. Inventory preserved."
                )
                await self.auditor.record("POSITION_SYNC_ABORTED", {
                    "ticker": ticker, "reason": "empty_response",
                })
                return

            positions = res.get("market_positions")
            if positions is None:
                logging.warning("SYNC ABORTED — market_positions returned null.")
                return
            if not positions:   # confirmed empty list []
                self._clear_inventory_preserve_pnl()
                await self.auditor.record("POSITION_SYNC", {
                    "ticker": ticker, "result": "flat_confirmed",
                })
                return

            p   = positions[0]
            qty = int(p.get("position", 0))

            if qty == 0:
                self._clear_inventory_preserve_pnl()
                await self.auditor.record("POSITION_SYNC", {
                    "ticker": ticker, "result": "flat_confirmed",
                })
                return

            # Desync detected — rebuild InventoryManager from API data
            new_inv  = InventoryManager()
            new_inv.realized_cents = self.inventory.realized_cents  # preserve daily PnL
            if qty > 0:
                cost = float(p.get("average_price_cents") or self._get_yes_mid())
                new_inv.yes_qty        = qty
                new_inv.yes_cost_cents = cost * qty
                self.active_side       = "yes"
            else:
                abs_qty  = abs(qty)
                raw_cost = float(p.get("average_price_cents") or 50.0)
                # Invert to NO-space; Kalshi reports NO positions in YES-space
                no_cost  = (100.0 - raw_cost) if self.config.get("no_price_inversion", True) else raw_cost
                new_inv.no_qty        = abs_qty
                new_inv.no_cost_cents = no_cost * abs_qty
                self.active_side      = "no"

            self.inventory = new_inv
            await self.auditor.record("POSITION_SYNC", {
                "ticker": ticker, "qty": qty,
                "side": self.active_side, "result": "desync_corrected",
            })
            await TelegramAlerts.send(
                f"⚠️ POSITION SYNC: Restored {abs(qty)} {self.active_side.upper()} "
                f"contracts from API [{ticker}]"
            )

        except Exception as e:
            await self.auditor.record("POSITION_SYNC_FAILED", {
                "ticker": ticker, "error": str(e),
            })

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
        await asyncio.sleep(0.5)   # let WS deliver any in-flight fills first

        ioc_secs    = float(self.config.get("ioc_timeout_secs", 3))
        max_retries = int(self.config.get("dump_max_retries", 5))

        for attempt in range(max_retries):
            pos = self.inventory.open_position()
            if pos == 0:
                return

            # Re-price on every attempt so we cross whatever the current spread is
            current_mid = self._get_yes_mid()
            success = await self._sell_clip(abs(pos), current_mid)
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
            await TelegramAlerts.send(
                f"🚨 GHOST POSITION: {self.inventory.open_position()} contracts "
                f"may still be held on Kalshi [{self.active_ticker}]. "
                f"Check your account immediately."
            )

    # ─────────────────────────────────────────────────────────────────────────
    # MARKET DISCOVERY  (Sentinel series ticker + 210s floor)
    # ─────────────────────────────────────────────────────────────────────────

    async def discover_eth_market(self) -> tuple | None:
        """Returns (time_left_secs, ticker, close_dt) or None."""
        res     = await self.api.request("GET", "/markets?series_ticker=KXETH15M&status=open")
        markets = res.get("markets", [])
        if not markets:
            return None
        valid = []
        for m in markets:
            close_dt  = datetime.datetime.fromisoformat(
                m["close_time"].replace("Z", "+00:00")
            )
            time_left = (
                close_dt - datetime.datetime.now(datetime.timezone.utc)
            ).total_seconds()
            if 210 < time_left <= 1000:
                valid.append((time_left, m["ticker"], close_dt))
            elif time_left <= 210:
                logging.info(
                    f"⏭️ SKIP: {m['ticker']} has {int(time_left)}s left — below 210s entry floor."
                )
        if valid:
            valid.sort()
            return valid[0]
        return None

    # ─────────────────────────────────────────────────────────────────────────
    # ④ RUN  (Sentinel outer loop structure + Wolf task set)
    # ─────────────────────────────────────────────────────────────────────────

    async def run(self):
        # Bind the mutex here — asyncio.Lock() must be created inside a running event loop (3.10+).
        self._dump_lock = asyncio.Lock()

        await self.api.start_session()
        await TelegramAlerts.start()
        await TelegramAlerts.send("🐺 MomentumWolf v2 online — hunting KXETH15M")
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
                market_data = await self.discover_eth_market()
                if not market_data:
                    logging.info("No valid KXETH15M market. Sleeping 12s...")
                    await asyncio.sleep(12)
                    continue

                time_left, ticker, close_dt = market_data

                await self._reset_cycle_state()

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

                logging.info(f"=== Wolf cycle: {ticker} | {int(time_left)}s remaining ===")

                ws_task   = asyncio.create_task(self.listen_to_market_data(ticker), name="kalshi_ws")
                exit_task = asyncio.create_task(self.manage_wolf_exits(),           name="exits")
                scan_task = asyncio.create_task(self._momentum_scan(),              name="scan")
                for _t in (ws_task, exit_task, scan_task):
                    self._bg_tasks.add(_t)
                    _t.add_done_callback(self._bg_tasks.discard)

                all_tasks = {ws_task, exit_task, scan_task}
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
                                    # Non-Guillotine crash in a core task — hard-crash rather than
                                    # running blind as a zombie with corrupted state.
                                    logging.error(f"Background task crashed: {exc}")
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
                    for t in (ws_task, exit_task, scan_task):
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
                logging.info(f"=== Cycle complete: {ticker}. Sleeping 12s. ===")
                await asyncio.sleep(12)

        except CriticalDrawdownException as e:
            logging.critical(f"☠️ CRITICAL DRAWDOWN: {e}. Stopping.")
            await TelegramAlerts.send(f"☠️ CRITICAL DRAWDOWN: {e}")
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
            await TelegramAlerts.send("🐺 MomentumWolf v2 offline")
            await TelegramAlerts.close()

    # ─────────────────────────────────────────────────────────────────────────
    # MOMENTUM SCAN  (200ms signal loop)
    # ─────────────────────────────────────────────────────────────────────────

    async def _momentum_scan(self):
        """
        Core signal loop — 200ms tick.
        binance_delta updated from 60-tick spot window (Sentinel approach):
          oldest price vs current = slow-trend directional momentum.
        """
        cfg    = self.config
        t1     = cfg["spike_threshold_tier1"]
        t2     = cfg["spike_threshold_tier2"]
        t3     = cfg["spike_threshold_tier3"]
        poll_s = cfg["scan_interval_ms"] / 1000

        while self.is_running:
            await asyncio.sleep(poll_s)

            # binance_delta: 15-second time-based lookback.
            # Requires at least 5 seconds of history before trusting the delta.
            if self.live_eth_price and self.eth_price_history and \
               (time.time() - self.eth_price_history[0][0]) >= 5.0:
                oldest_price = self.eth_price_history[0][1]
                if oldest_price > 0:
                    self.binance_delta = ((self.live_eth_price - oldest_price) / oldest_price) * 10000.0
                else:
                    self.binance_delta = 0.0

            # Compute time_left once — used by expiry check, blindfold, and state guards
            time_left = 0.0
            if self.market_close_time:
                time_left = (
                    self.market_close_time -
                    datetime.datetime.now(datetime.timezone.utc)
                ).total_seconds()
                if time_left < -30:
                    logging.info(f"Market {self.active_ticker} expired. Ending cycle.")
                    self.is_running = False
                    return

            # Guard 1: State Readiness — Oracle must not score on empty data
            if not self.live_exchange_bid or not self.live_exchange_ask or not self.live_eth_price:
                continue

            # Guard 1.5: Stale Oracle Watchdog (5-second Binance freeze failsafe)
            if not self.eth_price_history or (time.time() - self.eth_price_history[-1][0] > 5.0):
                continue

            yes_mid = self._get_yes_mid()

            try:
                self._run_full_risk_hierarchy(yes_mid)
            except (GuillotineException, DislocationEjectorException) as e:
                await self.auditor.record("RISK_KILL_SCAN", {"reason": str(e)})
                self.last_exit_reason = "STOP_LOSS"
                self.last_exit_time   = time.time()
                self.last_exit_price  = yes_mid
                self.last_exit_side   = self.active_side
                if self._dump_in_flight:
                    # manage_wolf_exits already owns the dump-and-reset sequence.
                    # Do not touch self.inventory or call _reset_cycle_state here —
                    # doing so would wipe inventory mid-dump and cause a ghost position.
                    return
                if self.inventory.open_position() > 0:
                    await self._dump_full_position(yes_mid)
                await self._reset_cycle_state()
                return
            except CriticalDrawdownException:
                raise

            if self._strike_in_flight:
                continue

            if self.inventory.open_position() == 0:
                # Anti-Whipsaw: 45s hard cooldown after a stop loss so we don't
                # re-enter into the same volatile move that just ejected us.
                if self.last_exit_reason == "STOP_LOSS" and \
                   time.time() - self.last_exit_time < 45.0:
                    continue

                entry_vel_max = float(cfg.get("entry_velocity_max", 0.70))
                if abs(self.velocity_ema) > entry_vel_max or \
                   abs(self.basis_shift)  > cfg["basis_dislocation_threshold"]:
                    continue   # wait for market to stabilise without dropping WS

                score = self.calculate_momentum_score()
                self.score_history.append(score)

                # Require a full 5-tick window before evaluating entries
                if len(self.score_history) < 5:
                    continue

                _now = time.time()
                if (_now - self._last_heartbeat_time >= 10.0) or (abs(score) > 0.15):
                    logging.info(
                        f"[ORACLE] Pos: {self.inventory.open_position()} | "
                        f"Score: {score:+.3f} | "
                        f"Δ: {self.binance_delta:+.2f} | "
                        f"OFI: {self.ofi_scalar:+.3f} | "
                        f"Basis: {self.basis_shift:+.3f} | "
                        f"Vel: {self.velocity_ema:+.3f} | "
                        f"K-Bid: {self.live_exchange_bid:.0f} | "
                        f"K-Ask: {self.live_exchange_ask:.0f}"
                    )
                    self._last_heartbeat_time = _now

                # Guard 2: Dynamic opening blindfold — oracle updates and heartbeat fire,
                # but no strikes until ws_blackout_seconds have elapsed from cycle start.
                # Fully YAML-driven via ws_blackout_seconds; zero hardcoded values.
                blackout_secs = int(self.config.get("ws_blackout_seconds", 30))
                if time_left > (900.0 - blackout_secs):
                    continue

                # God-Candle Gate: final 3 minutes — block all entries unless all
                # four confluence signals are simultaneously confirmed.
                if time_left <= 180:
                    is_god_candle = (
                        abs(score) >= 0.75 and
                        abs(self.binance_delta) >= 3.0 and
                        abs(self.basis_shift)   >= 0.40 and
                        (self.live_exchange_ask - self.live_exchange_bid) <= cfg.get("god_candle_max_spread_cents", 6.0)
                    )
                    if not is_god_candle:
                        continue

                # First-Derivative Gate (3-tick lookback) with conviction bypass.
                # Escape velocity (abs(score) >= 0.35) skips the acceleration check
                # entirely so massive spike signals are never blocked by plateauing math.
                DERIV_NOISE_FLOOR = float(self.config.get("momentum_deriv_floor", 0.008))
                hist = list(self.score_history)
                if abs(score) >= 0.35:
                    is_rising = True   # escape velocity — bypass acceleration check
                elif len(hist) >= 4:
                    score_3ago = hist[-4]
                    if score > 0:
                        is_rising = (score - score_3ago) > DERIV_NOISE_FLOOR
                    elif score < 0:
                        is_rising = (score_3ago - score) > DERIV_NOISE_FLOOR
                    else:
                        is_rising = False
                else:
                    is_rising = True   # not enough history — let it through

                if not is_rising:
                    # Throttle: emit at most once every 30s to prevent terminal flood.
                    _stall_now = time.time()
                    if abs(score) >= 0.15 and (_stall_now - self._last_stalled_log_time >= 30.0):
                        await self.auditor.record("MOMENTUM_STALLED", {
                            "score": score,
                            "score_3ago": score_3ago if len(hist) >= 4 else None,
                        })
                        self._last_stalled_log_time = _stall_now
                    continue

                if self.binance_delta == 0.0 and len(self.eth_price_history) < 2:
                    await self.auditor.record("ETH_DELTA_STALE", {"score": score})

                # ── V4 Conviction Engine (Phase 2) ─────────────────────────
                # Volume-Weighted Delta, CVD, and BTC Macro Anchor checks.
                if score != 0:
                    # Metrics from Phase 1 plumbing
                    rolling_vol = sum(abs(q) for _, q in self.eth_volume_history)
                    cvd         = sum(q for _, q in self.eth_volume_history)

                    _btc_now    = time.time()
                    _btc_recent = [x for x in self.btc_price_history if _btc_now - x[0] <= 300.0]
                    btc_delta   = (
                        (_btc_recent[-1][1] - _btc_recent[0][1])
                        if len(_btc_recent) >= 2 else 0.0
                    )

                    min_binance_volume = float(cfg.get("min_binance_volume", 50.0))
                    min_cvd_alignment  = float(cfg.get("min_cvd_alignment", 0.50))
                    min_btc_delta      = float(cfg.get("min_btc_delta", 5.0))

                    # 1. Volume Gate
                    if rolling_vol < min_binance_volume:
                        await self.auditor.record("LOW_VOLUME_REJECT", {
                            "score": score, "rolling_vol": rolling_vol, "floor": min_binance_volume
                        })
                        continue

                    # 2. BTC Anchor Gate
                    if btc_delta != 0.0:
                        if (score > 0 and btc_delta < min_btc_delta) or (score < 0 and btc_delta > -min_btc_delta):
                            await self.auditor.record("BTC_ANCHOR_REJECT", {
                                "side": "yes" if score > 0 else "no", "btc_delta": btc_delta, "floor": min_btc_delta
                            })
                            continue
                    else:
                        # Bypass the gate due to stale feed, but log it so we aren't blind
                        await self.auditor.record("BTC_ANCHOR_BYPASSED_STALE", {
                            "side": "yes" if score > 0 else "no", "score": score
                        })

                    # 3. CVD Alignment Gate
                    if (score > 0 and cvd < min_cvd_alignment) or (score < 0 and cvd > -min_cvd_alignment):
                        await self.auditor.record("CVD_REJECT", {
                            "side": "yes" if score > 0 else "no", "cvd": cvd, "floor": min_cvd_alignment
                        })
                        continue

                # Price-adjusted thresholds: higher-priced contracts require
                # stronger conviction. A 65¢ entry needs more signal than 38¢.
                if self.active_side == "yes" or (self.active_side is None and score > 0):
                    entry_price_est = yes_mid
                else:
                    entry_price_est = 100.0 - yes_mid
                price_adj = 1.0 + max(0.0, (entry_price_est - 50.0) / 100.0)

                # Time-decay penalty: activates below 5 minutes remaining.
                # At 300s: time_adj = 1.0 (no penalty).
                # At 0s:   time_adj = 2.0 (thresholds double — effectively blocked).
                time_adj  = 1.0 + max(0.0, (300.0 - time_left) / 300.0)

                # Combined conviction multiplier applied to all three tiers.
                total_adj = min(price_adj * time_adj, float(self.config.get("max_total_adj", 1.3)))
                adj_t1    = t1 * total_adj
                adj_t2    = t2 * total_adj
                adj_t3    = t3 * total_adj

                if score >= adj_t3:
                    self.active_side = "yes"
                    await self.execute_pyramid_strike(tier=3)
                elif score >= adj_t2:
                    self.active_side = "yes"
                    await self.execute_pyramid_strike(tier=2)
                elif score >= adj_t1:
                    self.active_side = "yes"
                    await self.execute_pyramid_strike(tier=1)
                elif score <= -adj_t3:
                    self.active_side = "no"
                    await self.execute_pyramid_strike(tier=3)
                elif score <= -adj_t2:
                    self.active_side = "no"
                    await self.execute_pyramid_strike(tier=2)
                elif score <= -adj_t1:
                    self.active_side = "no"
                    await self.execute_pyramid_strike(tier=1)

            else:
                levels = cfg["pyramid_levels"]
                if self.pyramid_step < len(levels):
                    score      = self.calculate_momentum_score()

                    _now = time.time()
                    if (_now - self._last_heartbeat_time >= 10.0) or (abs(score) > 0.15):
                        logging.info(
                            f"[ORACLE] Pos: {self.inventory.open_position()} | "
                            f"Score: {score:+.3f} | "
                            f"Δ: {self.binance_delta:+.2f} | "
                            f"OFI: {self.ofi_scalar:+.3f} | "
                            f"Basis: {self.basis_shift:+.3f} | "
                            f"Vel: {self.velocity_ema:+.3f} | "
                            f"K-Bid: {self.live_exchange_bid:.0f} | "
                            f"K-Ask: {self.live_exchange_ask:.0f}"
                        )
                        self._last_heartbeat_time = _now

                    side_score = score if self.active_side == "yes" else -score
                    tier_map   = [0, t1, t2, t3]
                    required   = tier_map[min(self.pyramid_step + 1, 3)]
                    if side_score >= required:
                        await self.execute_pyramid_strike(tier=self.pyramid_step + 1)

# ─────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    wolf = MomentumWolf(config_path="wolf_config.yaml")
    asyncio.run(wolf.run())
