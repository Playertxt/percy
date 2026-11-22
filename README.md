# Percy: home network guard for Linux

A GTK4 / libadwaita desktop app (plus a `percy` command) that:

- **Manages your router and Wi-Fi.** Status, connected devices, Wi-Fi on/off, guest network,
  Wi-Fi name and password, which DNS the router hands out, and switching Telnet, SSH, UPnP, WPS
  and remote admin on or off. Every change shows before → after and asks first.
- **Blocks ads on every device.** Installs [AdGuard Home](https://github.com/AdguardTeam/AdGuardHome)
  on this PC with one click, adds block lists, can block whole apps (TikTok, games…) network-wide,
  and points the router at it.
- **Checks your network's security, all the time.** Built-in checks cover open router ports
  (Telnet!), UPnP and what it opened, WPS, remote admin, DMZ, weak Wi-Fi encryption, ISP DNS
  rewriting, new or unknown devices, and risky open ports on any device (ADB on a TV, Telnet on a
  camera…). A background monitor re-runs them and sends a desktop notification when something new
  and serious shows up.
- **Runs proven open-source monitors** next to it: [NetAlertX](https://github.com/netalertx/NetAlertX)
  (always-on device scanner with alerts) and AdGuard Home.
- **Keeps a per-device activity log:** which site or app each device looked up, and when, grouped by
  app (YouTube, WhatsApp, Netflix, games, ads…) or as a full list, with search.
- **Explains it in plain words with Claude** (optional, needs an Anthropic API key).

Built for a **TP-Link XC220-G3v** (GPON fiber router, stock firmware). Other TP-Link routers that use
the same "DEV2" web API (VX/EX/XC series) are likely to work.

## What it can't do (and why)

| You might expect | Reality |
|---|---|
| Install the ad blocker *on the router* | The XC220-G3v's stock firmware has no package system and OpenWrt doesn't support it. AdGuard Home runs on this PC instead and the router tells devices to use it. |
| See the full link or page each device opened | Almost all traffic is HTTPS, so only the **domain** (e.g. `youtube.com`) is visible. Seeing more would need an interception certificate installed on every device, which Percy deliberately does not do. |
| Watch all traffic (Zeek/Suricata/ntopng) | The router can't mirror traffic to this PC, so those tools would only see this PC's own traffic. |
| Log a device that doesn't use the ad blocker | Devices with hard-coded DNS (some smart TVs, Chrome's "secure DNS") bypass it, so they won't appear in the activity log. |

The activity log records what other people in your home do online. Tell them it's on.

## Install

```bash
cd percy
python3 -m venv --system-site-packages .venv   # system site packages give access to GTK (PyGObject)
.venv/bin/pip install -e '.[test]'
```

Needs Python 3.11+, GTK 4, libadwaita 1.5+, PyGObject, Docker (your user in the `docker` group)
and a desktop keyring (GNOME Keyring or KWallet).

Optional launcher: copy `data/percy.desktop` to `~/.local/share/applications/`. Edit its `Exec=`
line if `percy` is not on your PATH (e.g. point it at `.venv/bin/percy`).

## First run

1. **Router password:** `.venv/bin/percy login`, or Settings in the app. The username is `user`
   on the XC220-G3v (its login page only asks for a password) and the password is on the router's sticker. Percy stops after one rejected login, so a
   typo can't lock you out of the admin page.
2. **Check that Percy understands your firmware:** `.venv/bin/percy router-probe` prints what the
   router exposes, with passwords masked. If Wi-Fi names or the DHCP DNS field are missing, share
   that output so the field names can be added.
3. **Security check:** Security page → *Run check now*, or `percy check`.
4. **Ad blocker:** Ad blocker page → *Install*, or `percy adblock setup`. Then *Use for whole network*
   (`percy adblock use-for-network`). Devices pick up the new DNS when they reconnect; turn Wi-Fi off
   and on, or reboot the router.
   - The default also hands out a backup DNS (1.1.1.1), so the internet keeps working when this PC
     is off. Some devices will use the backup part of the time and see ads. `--no-fallback` gives
     the best blocking, but then the internet stops whenever this PC is off.
   - Give this PC a fixed address in the router's DHCP settings (address reservation) so the DNS
     address doesn't change.
5. **Always-on monitoring:** Agents page → *Run in the background* (`percy install-service`). It
   runs as a systemd **user** service, with no root needed.

## Commands

```text
percy                         open the app
percy login                   save + test router password (keyring)
percy router-info             model, firmware, connected devices
percy routers                 other routers in the home: saved ones plus ones Percy found by itself
percy routers add <address>   manage a sub-router (detects its login type first, then asks the password once)
percy router-info --router X  status and devices of a saved sub-router
percy router-probe            what the router exposes (passwords masked)
percy wifi [--set-ssid NAME] [--set-password] [--index N]
percy service telnet off      also: ssh, upnp, wps, remote-admin
percy check [--json]          run all security checks
percy summary [--with-activity]   Claude explains the results
percy adblock setup|status|use-for-network|off-for-network [--no-fallback]
percy activity [--device NAME|IP|MAC] [--hours 24] [--apps] [--search TEXT]
percy devices [NAME --trust --label "Living-room TV"]
percy agents [--install netalertx]
percy monitor [--once]        run the monitor in the foreground
percy install-service [--remove]
```

## Sub-routers

Percy finds other TP-Link routers on its own: by name or TP-Link hardware address in the main
router's device list, and by this PC's gateway on each network card (plug into a sub-router or join
its Wi-Fi and it shows up). Finding them never logs in. A sub-router in *router mode* blocks its
admin page from the main network, so Percy can only reach it from its own Wi-Fi or LAN ports, and
its devices look like one device to the ad blocker's activity log. *Access point mode* avoids both.
Each sub-router has its own keyring password and its own stop-after-one-wrong-password guard.

## Where things live

| What | Where |
|---|---|
| Settings (no secrets) | `~/.config/percy/config.json` |
| Router password, AdGuard password, Anthropic key | desktop keyring, service `percy` |
| Devices, activity log, findings, events | `~/.local/share/percy/percy.db` (SQLite, kept 30 days by default) |
| AdGuard Home / NetAlertX data | `~/.local/share/percy/adguard`, `…/netalertx` |
| Background service | `~/.config/systemd/user/percy-monitor.service` |

Pinned container versions (in `percy/config.py`): AdGuard Home `v0.107.80`, NetAlertX `26.10.28`.
AdGuard's DNS listens only on this PC's LAN address and its admin page only on `127.0.0.1:3000`.
NetAlertX needs host networking to scan, so its dashboard is reachable on port 20211 from your LAN.

## Claude summaries

Only the security findings are sent, with MAC addresses shortened, and only when you press
*Explain* or run `percy summary`. App totals for the last 24 hours (no device names) are added only
if you switch that on. Model: `claude-opus-5-5`, with server-side refusal fallback enabled.

## Layout

```text
percy/router/     TP-Link DEV2 session (login via tplinkrouterc6u) + probed settings with change plans
percy/net/        tiny DNS client, port checks, neighbours, Wi-Fi link, UPnP discovery
percy/security/   pure check functions (checks.py) + fact gathering (runner.py)
percy/services/   docker wrapper, pinned container catalog, AdGuard REST client, ad-block setup
percy/activity/   SQLite store, domain→app classifier, AdGuard query-log collector
percy/monitor/    background loop, notifications, systemd user unit
percy/agents/     Claude summary
percy/ui/         GTK4/libadwaita window and pages
```

## Tests

```bash
.venv/bin/python -m pytest -q
```

The UI smoke test builds every page on GTK's off-screen Broadway display, so no window opens:

```bash
gtk4-broadwayd --address 127.0.0.1 --port 18085 :7 &
GDK_BACKEND=broadway BROADWAY_DISPLAY=:7 .venv/bin/python -m pytest -q tests/test_ui_smoke.py
kill %1
```
