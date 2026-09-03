/**
 * signalk-glinet
 *
 * Publishes router status (and, if present, cellular signal metrics) from
 * a GL.iNet router to SignalK, by talking to GL.iNet's documented
 * JSON-RPC API at /rpc — the same API their web admin panel and mobile
 * app use, authenticated with a normal username/password. No changes to
 * the router are required.
 *
 * Cellular metrics are only published if the router reports a modem
 * (module "modem", method "get_status"), so this plugin also works on
 * GL.iNet routers without a cellular modem — it'll just publish system
 * status paths.
 */

const https = require('https');
const http = require('http');
const crypto = require('crypto');

// --- MD5-crypt ($1$) implementation -----------------------------------
// Node has no built-in crypt(3). GL.iNet's challenge response tells us
// which crypt algorithm to use for the *inner* password hash (alg 1 =
// classic MD5-crypt, the "$1$" format). This is the standard
// Poul-Henning Kamp / FreeBSD MD5-crypt algorithm, re-implemented here
// so the plugin has zero native/npm dependencies.

const ITOA64 =
  './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';

function md5(buf) {
  return crypto.createHash('md5').update(buf).digest();
}

function to64(v, n) {
  let s = '';
  for (let i = 0; i < n; i++) {
    s += ITOA64[v & 0x3f];
    v = v >>> 6;
  }
  return s;
}

function md5Crypt(password, saltIn) {
  const salt = String(saltIn).slice(0, 8);
  const pw = Buffer.from(password, 'utf8');
  const sp = Buffer.from(salt, 'utf8');
  const magic = Buffer.from('$1$', 'utf8');

  // final = MD5(pw + salt + pw)
  let final = md5(Buffer.concat([pw, sp, pw]));

  // ctx = MD5(pw + magic + salt + final[0..pw.length] repeated)
  const parts = [pw, magic, sp];
  for (let pl = pw.length; pl > 0; pl -= 16) {
    parts.push(final.subarray(0, pl > 16 ? 16 : pl));
  }

  const zero = Buffer.from([0]);
  for (let i = pw.length; i; i = i >> 1) {
    parts.push(i & 1 ? zero : pw.subarray(0, 1));
  }

  final = md5(Buffer.concat(parts));

  for (let i = 0; i < 1000; i++) {
    const round = [];
    round.push(i & 1 ? pw : final);
    if (i % 3) round.push(sp);
    if (i % 7) round.push(pw);
    round.push(i & 1 ? final : pw);
    final = md5(Buffer.concat(round));
  }

  let out = '';
  out += to64((final[0] << 16) | (final[6] << 8) | final[12], 4);
  out += to64((final[1] << 16) | (final[7] << 8) | final[13], 4);
  out += to64((final[2] << 16) | (final[8] << 8) | final[14], 4);
  out += to64((final[3] << 16) | (final[9] << 8) | final[15], 4);
  out += to64((final[4] << 16) | (final[10] << 8) | final[5], 4);
  out += to64(final[11], 2);

  return `$1$${salt}$${out}`;
}

// --- Minimal JSON-RPC client over http(s), no deps ---------------------

function rpcRequest(opts, body) {
  const payload = JSON.stringify(body);
  const lib = opts.https ? https : http;
  const requestOptions = {
    hostname: opts.host,
    port: opts.port,
    path: '/rpc',
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(payload),
    },
    rejectUnauthorized: !!opts.rejectUnauthorized,
    timeout: 10000,
  };

  return new Promise((resolve, reject) => {
    const req = lib.request(requestOptions, (res) => {
      let data = '';
      res.on('data', (chunk) => (data += chunk));
      res.on('end', () => {
        try {
          resolve(JSON.parse(data));
        } catch (err) {
          reject(new Error(`Invalid JSON from router: ${err.message}`));
        }
      });
    });
    req.on('timeout', () => req.destroy(new Error('Request timed out')));
    req.on('error', reject);
    req.write(payload);
    req.end();
  });
}

class GlInetClient {
  constructor({ host, port, useHttps, username, password, rejectUnauthorized }) {
    this.host = host;
    this.port = port;
    this.useHttps = useHttps;
    this.username = username || 'root';
    this.password = password;
    this.rejectUnauthorized = !!rejectUnauthorized;
    this.sid = null;
    this._id = 0;
  }

  nextId() {
    this._id += 1;
    return this._id;
  }

  async login() {
    const challengeResp = await rpcRequest(
      { host: this.host, port: this.port, https: this.useHttps, rejectUnauthorized: this.rejectUnauthorized },
      {
        jsonrpc: '2.0',
        id: this.nextId(),
        method: 'challenge',
        params: { username: this.username },
      }
    );

    if (!challengeResp || !challengeResp.result) {
      throw new Error(
        `Challenge request failed: ${JSON.stringify(challengeResp && challengeResp.error)}`
      );
    }

    const { alg, salt, nonce } = challengeResp.result;
    // hash-method is an optional field in the challenge response that specifies
    // the outer hash algorithm. Older GL.iNet firmware omits it and uses MD5.
    const hashMethod = challengeResp.result['hash-method'] || 'md5';

    if (alg !== 1) {
      // Only MD5-crypt (alg 1) is implemented. This is what stock
      // GL.iNet firmware uses for the root account as of testing
      // (2026). If your router's admin password was created under a
      // different crypt scheme, alg may be 5 (SHA-256-crypt) or 6
      // (SHA-512-crypt) and login will fail here with a clear error
      // instead of silently sending a wrong hash.
      throw new Error(
        `Router requested crypt algorithm ${alg}, but this plugin only supports alg 1 (MD5-crypt). ` +
          `Please open an issue with this value so support can be added.`
      );
    }

    const cryptHash = md5Crypt(this.password, salt);
    const loginHash = crypto
      .createHash(hashMethod)
      .update(`${this.username}:${cryptHash}:${nonce}`)
      .digest('hex');

    const loginResp = await rpcRequest(
      { host: this.host, port: this.port, https: this.useHttps, rejectUnauthorized: this.rejectUnauthorized },
      {
        jsonrpc: '2.0',
        id: this.nextId(),
        method: 'login',
        params: { username: this.username, hash: loginHash },
      }
    );

    if (!loginResp || !loginResp.result || !loginResp.result.sid) {
      throw new Error(
        `Login failed: ${JSON.stringify(loginResp && loginResp.error)}. ` +
          `Check the router password. If this router's firmware was updated, ` +
          `the login algorithm may have changed since this plugin was written.`
      );
    }

    this.sid = loginResp.result.sid;
    return this.sid;
  }

  async call(module, method, params = {}, retry = true) {
    if (!this.sid) {
      await this.login();
    }

    const resp = await rpcRequest(
      { host: this.host, port: this.port, https: this.useHttps, rejectUnauthorized: this.rejectUnauthorized },
      {
        jsonrpc: '2.0',
        id: this.nextId(),
        method: 'call',
        params: [this.sid, module, method, params],
      }
    );

    if (resp && resp.error) {
      const code = resp.error.code;
      const deniedOrExpired = code === -32000 || code === -32002;
      if (deniedOrExpired && retry) {
        // Session expired or was never valid; log in again and retry once.
        this.sid = null;
        await this.login();
        return this.call(module, method, params, false);
      }
      throw new Error(`RPC ${module}.${method} failed: ${JSON.stringify(resp.error)}`);
    }

    return resp.result;
  }
}

// --- SignalK path mapping ------------------------------------------------
// All paths live under the vendor-specific "glinet.status." prefix (not
// the core "environment.outside." namespace), since most of this data
// (router CPU temp, WiFi status, service status, etc.) isn't a physical
// environment measurement.

const PATH_PREFIX = 'glinet.status';

function mapNetworkType(networkType) {
  if (!networkType) return undefined;
  const t = String(networkType).toUpperCase();
  if (t.includes('5G') || t.includes('NR')) return '5g';
  if (t.includes('LTE')) return 'lte';
  if (t.includes('UMTS') || t.includes('3G') || t.includes('WCDMA')) return 'umts';
  if (t.includes('GSM') || t.includes('2G') || t.includes('EDGE') || t.includes('GPRS')) return 'gsm';
  return networkType.toLowerCase();
}

function celsiusToKelvin(c) {
  return typeof c === 'number' ? c + 273.15 : undefined;
}

// name -> {description, units}. Used to send SignalK metadata once per
// path. `units` follows SignalK convention (Kelvin for temperature,
// ratio 0-1 for fractional quantities, bytes for data sizes).
const CELLULAR_META = {
  type: { description: 'Cellular network technology (lte, 5g, umts, gsm)' },
  rssi: { description: 'Received Signal Strength Indicator', units: 'dBm' },
  rsrp: { description: 'Reference Signal Received Power (LTE/5G)', units: 'dBm' },
  rsrq: { description: 'Reference Signal Received Quality (LTE/5G)', units: 'dB' },
  snr: { description: 'Signal-to-Noise Ratio / SINR (LTE/5G)', units: 'dB' },
  signalQuality: { description: 'GL.iNet signal strength bars, normalised', units: 'ratio' },
  operator: { description: 'Mobile operator name' },
  connected: { description: 'Whether the modem reports an active data connection' },
  iccid: { description: 'SIM card ICCID' },
  apn: { description: 'Active APN' },
};

const SYSTEM_META = {
  uptime: { description: 'Router uptime', units: 's' },
  cpuTemperature: { description: 'Router CPU temperature', units: 'K' },
  loadAverage1m: { description: '1 minute load average' },
  loadAverage5m: { description: '5 minute load average' },
  loadAverage15m: { description: '15 minute load average' },
  memoryTotal: { description: 'Total RAM', units: 'bytes' },
  memoryFree: { description: 'Free RAM', units: 'bytes' },
  memoryBuffCache: { description: 'RAM used for buffers/cache', units: 'bytes' },
  flashTotal: { description: 'Total flash storage', units: 'bytes' },
  flashFree: { description: 'Free flash storage', units: 'bytes' },
  flashApp: { description: 'Flash storage used by installed apps', units: 'bytes' },
  lanIp: { description: 'LAN IP address' },
  lanNetmask: { description: 'LAN netmask' },
  timeSyncStatus: { description: 'Whether the router has synced its clock (e.g. via NTP)' },
  ipv6Enabled: { description: 'Whether IPv6 is enabled' },
};

const NETWORK_META = {
  online: { description: 'Whether this WAN interface has working internet connectivity' },
  up: { description: 'Whether this WAN interface link is up' },
};

const WIFI_META = {
  ssid: { description: 'WiFi network name' },
  band: { description: 'WiFi band (2G / 5G)' },
  encryption: { description: 'WiFi encryption type' },
  channel: { description: 'WiFi channel' },
  up: { description: 'Whether this WiFi radio/SSID is broadcasting' },
  guest: { description: 'Whether this is a guest network' },
  hidden: { description: 'Whether this SSID is hidden' },
  // Deliberately no "passwd" entry: WiFi passwords are never published.
};

const SERVICE_META = {
  status: { description: 'GL.iNet service status code, as reported by the router (raw, meaning varies by service)' },
};

const CLIENT_META = {
  cableTotal: { description: 'Number of clients connected over Ethernet' },
  wirelessTotal: { description: 'Number of clients connected over WiFi' },
};

module.exports = function (app) {
  let timer = null;
  let polling = false;
  let client = null;
  let cellularSupported = true; // becomes false permanently once we see "method not found"
  const metadataSent = new Set();

  const plugin = {
    id: 'signalk-glinet',
    name: 'GL.iNet Status',
    description:
      "Publishes a GL.iNet router's status (system, WiFi, WAN, services, and cellular signal if present) via its JSON-RPC /rpc API",
  };

  plugin.schema = {
    type: 'object',
    required: ['host', 'password'],
    properties: {
      host: {
        type: 'string',
        title: 'Router address',
        description: 'IP or hostname of the GL.iNet router',
        default: '192.168.8.1',
      },
      https: {
        type: 'boolean',
        title: 'Use HTTPS',
        default: true,
      },
      port: {
        type: 'number',
        title: 'Port',
        description: 'Leave blank to use the protocol default (80/443)',
      },
      username: {
        type: 'string',
        title: 'Username',
        default: 'root',
      },
      password: {
        type: 'string',
        title: 'Password',
      },
      rejectUnauthorized: {
        type: 'boolean',
        title: 'Verify TLS certificate',
        description: 'Leave unchecked for GL.iNet routers, which use a self-signed certificate',
        default: false,
      },
      pollCellular: {
        type: 'boolean',
        title: 'Poll cellular modem status',
        description:
          'Turn off for GL.iNet routers with no cellular modem. Even if left on, the plugin auto-detects a missing modem and skips it without error.',
        default: true,
      },
      pollInterval: {
        type: 'number',
        title: 'Poll interval (seconds)',
        default: 30,
        minimum: 5,
      },
    },
  };

  function sendMetaOnce(path, meta) {
    if (metadataSent.has(path) || !meta) return;
    metadataSent.add(path);
    app.handleMessage(plugin.id, { updates: [{ meta: [{ path, value: meta }] }] });
  }

  function pushValue(values, path, value, meta) {
    if (value === undefined || value === null) return;
    sendMetaOnce(path, meta);
    values.push({ path, value });
  }

  function addCellularValues(values, result) {
    const modems = (result && result.modems) || [];
    modems.forEach((modem, index) => {
      const sim = modem.simcard || {};
      const sig = sim.signal || {};
      const net = modem.network || {};
      const base = `${PATH_PREFIX}.cellular.${index}`;

      pushValue(values, `${base}.type`, mapNetworkType(sig.network_type), CELLULAR_META.type);
      pushValue(values, `${base}.rssi`, sig.rssi, CELLULAR_META.rssi);
      pushValue(values, `${base}.rsrp`, sig.rsrp, CELLULAR_META.rsrp);
      pushValue(values, `${base}.rsrq`, sig.rsrq, CELLULAR_META.rsrq);
      pushValue(values, `${base}.snr`, sig.sinr, CELLULAR_META.snr);
      pushValue(
        values,
        `${base}.signalQuality`,
        typeof sig.strength === 'number' ? Math.max(0, Math.min(1, sig.strength / 5)) : undefined,
        CELLULAR_META.signalQuality
      );
      pushValue(values, `${base}.operator`, sim.carrier, CELLULAR_META.operator);
      pushValue(values, `${base}.iccid`, sim.iccid, CELLULAR_META.iccid);
      pushValue(values, `${base}.apn`, sim.apn, CELLULAR_META.apn);
      pushValue(
        values,
        `${base}.connected`,
        typeof net.status === 'number' ? net.status === 0 : undefined,
        CELLULAR_META.connected
      );
    });
    return modems.length;
  }

  function addSystemValues(values, result) {
    const sys = (result && result.system) || {};
    const base = `${PATH_PREFIX}.system`;

    pushValue(values, `${base}.uptime`, sys.uptime, SYSTEM_META.uptime);
    pushValue(values, `${base}.cpuTemperature`, celsiusToKelvin(sys.cpu && sys.cpu.temperature), SYSTEM_META.cpuTemperature);
    if (Array.isArray(sys.load_average)) {
      pushValue(values, `${base}.loadAverage1m`, sys.load_average[0], SYSTEM_META.loadAverage1m);
      pushValue(values, `${base}.loadAverage5m`, sys.load_average[1], SYSTEM_META.loadAverage5m);
      pushValue(values, `${base}.loadAverage15m`, sys.load_average[2], SYSTEM_META.loadAverage15m);
    }
    pushValue(values, `${base}.memoryTotal`, sys.memory_total, SYSTEM_META.memoryTotal);
    pushValue(values, `${base}.memoryFree`, sys.memory_free, SYSTEM_META.memoryFree);
    pushValue(values, `${base}.memoryBuffCache`, sys.memory_buff_cache, SYSTEM_META.memoryBuffCache);
    pushValue(values, `${base}.flashTotal`, sys.flash_total, SYSTEM_META.flashTotal);
    pushValue(values, `${base}.flashFree`, sys.flash_free, SYSTEM_META.flashFree);
    pushValue(values, `${base}.flashApp`, sys.flash_app, SYSTEM_META.flashApp);
    pushValue(values, `${base}.lanIp`, sys.lan_ip, SYSTEM_META.lanIp);
    pushValue(values, `${base}.lanNetmask`, sys.lan_netmask, SYSTEM_META.lanNetmask);
    pushValue(values, `${base}.timeSyncStatus`, sys.time_sync_status, SYSTEM_META.timeSyncStatus);
    pushValue(values, `${base}.ipv6Enabled`, sys.ipv6_enabled, SYSTEM_META.ipv6Enabled);
  }

  function addNetworkValues(values, result) {
    const networks = (result && result.network) || [];
    networks.forEach((iface) => {
      if (!iface.interface) return;
      const base = `${PATH_PREFIX}.network.${iface.interface}`;
      pushValue(values, `${base}.online`, iface.online, NETWORK_META.online);
      pushValue(values, `${base}.up`, iface.up, NETWORK_META.up);
    });
  }

  function addWifiValues(values, result) {
    const wifis = (result && result.wifi) || [];
    wifis.forEach((w) => {
      if (!w.name) return;
      const base = `${PATH_PREFIX}.wifi.${w.name}`;
      pushValue(values, `${base}.ssid`, w.ssid, WIFI_META.ssid);
      pushValue(values, `${base}.band`, w.band, WIFI_META.band);
      pushValue(values, `${base}.encryption`, w.encryption, WIFI_META.encryption);
      pushValue(values, `${base}.channel`, w.channel, WIFI_META.channel);
      pushValue(values, `${base}.up`, w.up, WIFI_META.up);
      pushValue(values, `${base}.guest`, w.guest, WIFI_META.guest);
      pushValue(values, `${base}.hidden`, w.hidden, WIFI_META.hidden);
      // w.passwd is intentionally never read or published.
    });
  }

  function addServiceValues(values, result) {
    const services = (result && result.service) || [];
    services.forEach((s) => {
      if (!s.name) return;
      pushValue(values, `${PATH_PREFIX}.service.${s.name}.status`, s.status, SERVICE_META.status);
    });
  }

  function addClientValues(values, result) {
    const client = (result && result.client && result.client[0]) || {};
    pushValue(values, `${PATH_PREFIX}.client.cableTotal`, client.cable_total, CLIENT_META.cableTotal);
    pushValue(values, `${PATH_PREFIX}.client.wirelessTotal`, client.wireless_total, CLIENT_META.wirelessTotal);
  }

  async function poll(options) {
    if (polling) {
      app.debug('Previous poll still in progress, skipping this interval');
      return;
    }
    polling = true;

    const values = [];
    let modemCount = 0;
    const errors = [];

    // System/network/wifi/service status - always polled.
    try {
      const sysResult = await client.call('system', 'get_status', {});
      addSystemValues(values, sysResult);
      addNetworkValues(values, sysResult);
      addWifiValues(values, sysResult);
      addServiceValues(values, sysResult);
      addClientValues(values, sysResult);
    } catch (err) {
      errors.push(`system.get_status: ${err.message}`);
    }

    // Cellular - optional, and auto-disabled if the router has no modem.
    if (options.pollCellular !== false && cellularSupported) {
      try {
        const modemResult = await client.call('modem', 'get_status', {});
        modemCount = addCellularValues(values, modemResult);
      } catch (err) {
        if (/method not found/i.test(err.message) || /-32601/.test(err.message)) {
          app.debug('Router reports no "modem" module (no cellular modem) - disabling cellular polling');
          cellularSupported = false;
        } else {
          errors.push(`modem.get_status: ${err.message}`);
        }
      }
    }

    if (values.length > 0) {
      app.handleMessage(plugin.id, { updates: [{ values }] });
    }

    if (errors.length > 0) {
      app.error(`Poll had errors: ${errors.join('; ')}`);
      app.setPluginError(errors.join('; '));
    } else {
      app.setPluginStatus(
        cellularSupported && options.pollCellular !== false
          ? `OK, ${modemCount} modem(s) polled`
          : 'OK (no cellular modem)'
      );
    }

    polling = false;
  }

  plugin.start = function (options) {
    if (!options.host || !options.password) {
      app.setPluginError('Router address and password are required');
      return;
    }

    client = new GlInetClient({
      host: options.host,
      port: options.port || undefined,
      useHttps: options.https !== false,
      username: options.username || 'root',
      password: options.password,
      rejectUnauthorized: !!options.rejectUnauthorized,
    });
    cellularSupported = true;

    const intervalMs = Math.max(5, options.pollInterval || 30) * 1000;

    app.setPluginStatus('Starting...');
    poll(options);
    timer = setInterval(() => poll(options), intervalMs);
  };

  plugin.stop = function () {
    if (timer) {
      clearInterval(timer);
      timer = null;
    }
    client = null;
    metadataSent.clear();
  };

  return plugin;
};
