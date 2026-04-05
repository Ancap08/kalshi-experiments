# kalshi-experiments

A collection of experimental trading scripts for Kalshi binary options markets. I built them while exploring different approaches — market making, arbitrage, momentum, and grid strategies — and to learn how prediction markets and automated trading actually work.
With the right volume and YAML tweaks, some of them showed real edge and were profitable for stretches — but never consistently enough to scale into something bigger. I’m sharing them openly in case you’re on a similar journey; maybe one of these ideas helps you break through where I didn’t.

Nothing here is financial advice. These are experiments. Use them to learn, adapt, or build on.

---

## Scripts

| Script | Folder | Description |
|--------|--------|-------------|
| `StoikovSentinel_v6_5_GOLD.py` | `bots/stoikov/` | Avellaneda-Stoikov market maker on Kalshi 15-min BTC binary options |
| `StoikovSentinel_v7_Aggressive.py` | `bots/stoikov/` | Advanced ETH Stoikov variant with pair-locking arb and full risk guards |
| `kalshi_lobster_trader.py` | `bots/llm/` | LLM-driven directional sniper using macro sentiment signals and spend caps |
| `kalshi_falcon.py` | `bots/arb/` | BTC spot-price cross-arb (Coinbase price truth vs Kalshi strike) |
| `kalshi_mantis_hunter.py` | `bots/arb/` | Fast async L2 pair-arb sniper with FOK atomic execution |
| `MomentumWolf_v2.py` | `bots/momentum/` | MomentumWolf_v2.py — Directional momentum hunter (ETH 15-min). BTC and SOL versions use identical logic with different tickers. |
| `ChopWolf_BTC.py` | `bots/grid/` | Oracle-centered grid chop hunter on BTC 15-min |
| `TightChop_BTC.py` | `bots/grid/` | Ultra-tight micro-scratch grid on BTC 15-min |

---

## Setup

1. Clone the repo
2. Copy `.env.example` to `.env` and fill in your credentials
3. For `MomentumWolf_v2.py`, copy `bots/momentum/wolf_config.yaml.example` to `wolf_config.yaml` and tune
4. For grid bots, copy the relevant `yaml.example` in `bots/grid/` and tune
5. Install dependencies (each script lists its imports at the top)

Most scripts use: `aiohttp`, `websockets`, `orjson`, `cryptography`, `python-dotenv`, `pyyaml`

```bash
pip install aiohttp websockets orjson cryptography python-dotenv pyyaml
```

---

## Security

**Never commit your `.env` file or private key files.**

- Add `.env` and `*.pem` to your `.gitignore` (already done in this repo)
- Use environment variables for all credentials — never hardcode keys
- See [SECURITY.md](SECURITY.md) for more detail

---

## License

MIT — do whatever you want with it, at your own risk.
