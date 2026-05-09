# adblock32

`adblock32` is a DNS-based ad blocker for the Seeed XIAO ESP32-C6. It sits on your network edge and filters ads and tracking domains at the DNS level — no client-side software needed.

## Features

- **DNS filtering engine** — suffix, exact, and glob pattern matching (`*`, `?`, `[...]`)
- **Allowlist** — bypass blocking for specific domains
- **CIDR-based per-client policies** — apply rules to specific subnets
- **DNS cache** — 64-entry LRU with TTL-aware expiry and negative caching (30s)
- **Stats & logging** — 200-entry ring buffer query log, running counters, top-N blocked domains, per-client tracking (16 max)
- **OLED display** (optional) — SH110X 128x64, terminal-style 7-line scrolling blocked list with stats bar
- **Wi-Fi provisioning** via hidden serial protocol (not exposed in public shell)
- **Persistent storage** — rules, policies, and credentials stored in NVS across reboots

## Hardware

- **Target**: Seeed XIAO ESP32-C6 (RISC-V, 4MB flash, 320KB RAM)
- **Display** (optional): SH110X 128x64 OLED via I2C
- **Partition layout**: two 1.75MB OTA app slots + 448KB SPIFFS

## Quick start

1. Install [PlatformIO Core](https://platformio.org/install/core).
2. Clone the repo and build:
   ```
   git clone https://github.com/CierCier/adblock32.git
   cd adblock32
   pio run -e seeed_xiao_esp32c6
   ```
3. Connect the board and upload:
   ```
   pio run -e seeed_xiao_esp32c6 -t upload --upload-port /dev/ttyACM0
   ```
4. Configure Wi-Fi using the provisioning script:
   ```
   ./setup-wifi.py /dev/ttyACM0
   ```
5. Point your router's DNS at the board's IP and you're done.

## Build variants

| Variant | Description |
|---|---|
| `seeed_xiao_esp32c6` | Headless build — no display support |
| `seeed_xiao_esp32c6_display` | Enables SH110X OLED display driver and terminal status output |

## Serial protocol

Wi-Fi commands are hidden behind a 3-byte magic prefix (`\x02\xAD\x32`) and are not accessible from the public serial shell. Use the included `setup-wifi.py` script for provisioning.

Available public commands:

- `help` — print the command list
- `stats` — show query/block/cache counters
- `filter <add|remove|list>` — manage block rules
- `source <list|add|remove>` — manage remote filter sources

## DNS filtering pipeline

```
client query → DNS cache (hit? return) → filter engine → stats collector → upstream forward → cache response
```

- Queries are first checked against the DNS cache (LRU, TTL-aware).
- Misses go through the filter engine: allowlist → CIDR policy → blocklist.
- Allowed queries are forwarded to `1.1.1.1`; blocked queries return `NXDOMAIN`.
- Responses are cached with the TTL from the first answer record.
- Remote filter sources are refreshed automatically every 24 hours with retry backoff.

## Landing page

The `landingpage/` directory contains an Astro-based static site for project info:

```
cd landingpage
bun install
bun dev      # development
bun build    # production build
```
