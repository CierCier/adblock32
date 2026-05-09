# adblock32

`adblock32` is a DNS-based ad blocker for the ESP32 platform.

## Layout

- `platformio.ini`: firmware build configuration for the Seeed XIAO ESP32-C6 target.
- `src/`: firmware source files.
- `partitions.csv`: flash partition table used by PlatformIO.
- `landingpage/`: Astro-based landing page for project information and releases.

## Firmware setup

1. Install [PlatformIO Core](https://platformio.org/install/core) or the PlatformIO IDE extension.
2. From the repository root, run `pio run` to build.
3. Connect the target board and run `pio run -t upload` to flash.
4. Open logs with `pio device monitor -b 115200`.

## Build variants

- `seeed_xiao_esp32c6`: default headless build with display support disabled.
- `seeed_xiao_esp32c6_display`: enables the SH110X display driver and display status output.

Use `pio run -e <env>` and `pio run -e <env> -t upload` to select a specific variant.

## Wi-Fi credential persistence

The firmware stores Wi-Fi credentials in ESP32 NVS so the device can reconnect automatically after reboot.

Available serial commands:

- `wifi set <ssid> <password>`: save credentials and connect immediately.
- `wifi status`: print current Wi-Fi status.
- `wifi clear`: erase saved credentials.
- `help`: print the command list.

## DNS filtering

When Wi-Fi connects successfully, the firmware starts a DNS listener on port `53` and forwards allowed queries to `1.1.1.1`.

- Built-in ad-domain rules are always active.
- Custom block rules are stored in ESP32 NVS and survive reboot.
- Remote ad-domain rules are fetched from a configurable source list.
- The default source list includes:
  `https://adguardteam.github.io/AdguardFilters/BaseFilter/sections/adservers.txt`
  `https://adguardteam.github.io/AdguardFilters/BaseFilter/sections/adservers_firstparty.txt`
- Remote rules are refreshed automatically about once every 24 hours, with retry backoff on fetch failure.
- Blocked domains currently return `NXDOMAIN`.

Available filter commands:

- `filter add <domain>`: add a persistent custom block rule.
- `filter remove <domain>`: remove a persistent custom block rule.
- `filter list`: print built-in and custom rule state.
- `filter status`: print the same rule summary plus DNS listener state.
- `filter refresh`: force an immediate remote rule refresh.

Available source commands:

- `source list`: print the active remote filter source list.
- `source add <url>`: add another HTTPS filter source.
- `source remove <url>`: remove an active HTTPS filter source.

## Landing page setup

1. Change into `landingpage/`.
2. Install dependencies with `bun install`.
3. Start local development with `bun dev`.
4. Build production assets with `bun build`.
