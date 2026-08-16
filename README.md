# signalk-glinet

SignalK plugin that publishes status from a **GL.iNet router running stock
GL.iNet firmware** — e.g. GL-X3000 (Spitz AX) — to SignalK: system health,
WAN/WiFi status, running services, connected clients, and (if the router
has one) cellular signal metrics (RSSI/RSRP/RSRQ/SINR).

Unlike routers running vanilla OpenWrt + ModemManager, GL.iNet's stock
firmware doesn't expose this over ubus/LuCI in the usual way. This plugin
instead talks to GL.iNet's own documented JSON-RPC API at `/rpc` (the same
API their web admin panel and mobile app use), authenticating with a
normal username/password — **no router-side setup required**. Just
install the plugin and point it at the router's IP.

Works on GL.iNet routers **with or without** a cellular modem — cellular
paths are simply skipped if the router doesn't report one (auto-detected;
you can also switch it off explicitly in config).

## SignalK paths published

All paths live under the vendor-specific `glinet.status.` prefix (not the
core `environment.outside.` namespace), since most of this — CPU temp,
WiFi state, service status — isn't a physical environment measurement.

### Cellular (only if the router has a modem)

| Path                                    | Description                       | Unit                       |
| ----------------------------------------- | ------------------------------------ | ----------------------------- |
| `glinet.status.cellular.<i>.type`       | Network technology                  | `lte`, `5g`, `umts`, `gsm`   |
| `glinet.status.cellular.<i>.rssi`       | Received Signal Strength Indicator  | dBm                           |
| `glinet.status.cellular.<i>.rsrp`       | Reference Signal Received Power     | dBm                           |
| `glinet.status.cellular.<i>.rsrq`       | Reference Signal Received Quality   | dB                            |
| `glinet.status.cellular.<i>.snr`        | SINR                                | dB                            |
| `glinet.status.cellular.<i>.signalQuality` | GL.iNet signal bars, normalised  | ratio (0–1)                   |
| `glinet.status.cellular.<i>.operator`   | Mobile operator name                | string                        |
| `glinet.status.cellular.<i>.iccid`      | SIM ICCID                           | string                        |
| `glinet.status.cellular.<i>.apn`        | Active APN                          | string                        |
| `glinet.status.cellular.<i>.connected`  | Active data connection              | boolean                       |

`<i>` is the modem's position in the router's modem list (0 for a
single-modem router like the X3000).

### System

| Path                                        | Description       | Unit    |
| ---------------------------------------------- | -------------------- | -------- |
| `glinet.status.system.uptime`               | Router uptime      | s       |
| `glinet.status.system.cpuTemperature`       | CPU temperature    | K       |
| `glinet.status.system.loadAverage1m/5m/15m` | Load average        | —       |
| `glinet.status.system.memoryTotal/Free/BuffCache` | RAM            | bytes   |
| `glinet.status.system.flashTotal/Free/App`  | Flash storage       | bytes   |
| `glinet.status.system.lanIp` / `lanNetmask` | LAN address         | —       |
| `glinet.status.system.timeSyncStatus`       | Clock synced (NTP) | boolean |
| `glinet.status.system.ipv6Enabled`          | IPv6 enabled        | boolean |

### Network (per WAN/tethering interface)

`glinet.status.network.<interface>.online` / `.up` — one pair per
interface name reported by the router (`wan`, `wwan`, `tethering`,
`modem_0001`, etc.).

### WiFi (per radio/SSID)

`glinet.status.wifi.<name>.ssid` / `.band` / `.encryption` / `.channel` /
`.up` / `.guest` / `.hidden`

**WiFi passwords are never published**, even though the router's API
returns them in plaintext — this plugin deliberately drops that field
before anything is sent to SignalK, since SignalK data is often displayed,
logged, or synced more broadly than you'd want a plaintext password to
travel.

### Services

`glinet.status.service.<name>.status` — raw status code per GL.iNet
service (`tailscale`, `adguard`, `tor`, `wgserver`, etc.). The router
doesn't document what each status code means per service, so this is
published as-is; treat it as a change-detection signal rather than a
strict boolean unless you've confirmed the meaning for a given service.

### Clients

`glinet.status.client.cableTotal` / `glinet.status.client.wirelessTotal`

## Requirements

- A GL.iNet router on stock firmware (tested on GL-X3000 / Spitz AX).
- The router's `/rpc` JSON-RPC API reachable from the SignalK server (this
  is the same API the router's own web admin UI uses — if you can log
  into the router's web UI, this will work).
- Root username and password for the router.

No changes to the router are required, and no additional npm dependencies
are installed — the plugin implements the necessary MD5-crypt algorithm
itself.

## Configuration

In SignalK: **Server → Plugin Config → GL.iNet Status**

| Option                      | Description                                              | Default        |
| ------------------------------ | ---------------------------------------------------------- | --------------- |
| Router address               | IP or hostname of the GL.iNet router                      | `192.168.8.1`  |
| Use HTTPS                    | Whether to connect over HTTPS                              | `true`         |
| Port                         | Leave blank for protocol default (80/443)                  | —              |
| Username                     | Router admin username                                      | `root`         |
| Password                     | Router admin password                                      | —              |
| Verify TLS certificate       | Leave unchecked — GL.iNet routers use a self-signed cert   | `false`        |
| Poll cellular modem status   | Turn off for routers with no cellular modem (auto-detected either way) | `true` |
| Poll interval                | Seconds between polls                                      | `30`           |

## How it works

1. Plugin sends a `challenge` request to `/rpc`, receiving a salt, nonce,
   and crypt algorithm identifier from the router.
2. The password is hashed with MD5-crypt using the given salt (matching
   how the router's `/etc/shadow` stores it), then combined with the
   username and nonce and hashed again with SHA-256 to produce a login
   hash — this mirrors exactly what the router's own web UI does.
3. Plugin logs in, receives a session id (`sid`), and polls
   `system.get_status` every interval, plus `modem.get_status` if the
   router has a cellular modem.
4. If the session expires between polls, the plugin transparently logs in
   again and retries once.
5. If `modem.get_status` returns "method not found," the plugin assumes
   the router has no cellular modem and stops asking, without raising an
   error.

## Compatibility

Only tested against a GL-X3000 (Spitz AX) on the firmware version current
as of testing. GL.iNet has changed this login algorithm across firmware
versions before, so if login fails on your router/firmware, please open an
issue including the `alg` and `hash-method` values from a `challenge`
response (no passwords needed) so support can be extended. Field names in
`system.get_status` / `modem.get_status` may also differ slightly across
router models — if paths come through empty, a fresh response dump from
your router (with passwords/SIM identifiers redacted) helps a lot.

## License

MIT
