#!/usr/bin/env python3
"""
Сборщик VLESS-конфигов для v2rayTun
- Собирает конфиги из источников
- Фильтрует: SNI из РФ whitelist ИЛИ хост-домен ИЛИ IP 158./89./84.
- TCP-проверка живых серверов
- Генерирует bb.json (паки по 10) и vlees.txt
"""

import re
import ipaddress
import json
import time
import base64
import socket
import logging
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import unquote

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)

# ─── Настройки ────────────────────────────────────────────────────────────────

PACK_SIZE     = 10
CHECK_WORKERS = 100
TCP_TIMEOUT   = 2

IP_PREFIXES   = ("158.", "89.", "84.")

# ─── Источники VLESS ──────────────────────────────────────────────────────────

SOURCES = [
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/BLACK_VLESS_RUS.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/BLACK_VLESS_RUS_mobile.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/Vless-Reality-White-Lists-Rus-Mobile-2.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/Vless-Reality-White-Lists-Rus-Mobile.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/WHITE-CIDR-RU-all.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/WHITE-CIDR-RU-checked.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/WHITE-SNI-RU-all.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/BLACK_SS%2BAll_RUS.txt",
    "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass-unsecure/raw/bypass-unsecure-all-raw.txt",
    "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass/raw/bypass-all-raw.txt",
    "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/default/all-secure-1.txt",
    "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/default/all-secure-2.txt",
    "https://raw.githubusercontent.com/VOID-Anonymity/V.O.I.D-VPN_Bypass/refs/heads/main/url_work.txt",
    "https://raw.githubusercontent.com/zieng2/wl/refs/heads/main/vless_universal.txt",
    "https://raw.githubusercontent.com/zieng2/wl/refs/heads/main/vless_lite.txt",
    "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass/bypass-all.txt",
    "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/split-by-protocols/vless-secure.txt",
    "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/split-by-protocols/vless.txt",
    "https://raw.githubusercontent.com/Temnuk/naabuzil/refs/heads/main/whitelist_full",
    "https://raw.githubusercontent.com/Temnuk/naabuzil/refs/heads/main/wifi",
    "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/refs/heads/main/githubmirror/26.txt",
    "https://raw.githubusercontent.com/sevcator/5ubscrpt10n/main/protocols/vl.txt",
    "https://raw.githubusercontent.com/Epodonios/v2ray-configs/refs/heads/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/mohamadfg-dev/telegram-v2ray-configs-collector/refs/heads/main/category/vless.txt",
    "https://raw.githubusercontent.com/mheidari98/.proxy/refs/heads/main/vless",
    "https://raw.githubusercontent.com/Mr-Meshky/vify/raw/refs/heads/main/configs/vless.txt",
    "https://raw.githubusercontent.com/V2RayRoot/V2RayConfig/refs/heads/main/Config/vless.txt",
]

# ─── Whitelist РФ ─────────────────────────────────────────────────────────────

SNI_WHITELIST_URL  = "https://raw.githubusercontent.com/hxehex/russia-mobile-internet-whitelist/refs/heads/main/whitelist.txt"
CIDR_WHITELIST_URL = "https://raw.githubusercontent.com/hxehex/russia-mobile-internet-whitelist/refs/heads/main/cidrwhitelist.txt"
IP_WHITELIST_URL   = "https://raw.githubusercontent.com/hxehex/russia-mobile-internet-whitelist/refs/heads/main/ip%20whitelist.txt"

# Глобальные наборы — заполняются в load_whitelists()
SNI_WHITELIST:  set[str] = set()
IP_WHITELIST:   set[str] = set()
CIDR_WHITELIST: list     = []


def load_whitelists():
    """Загружает SNI/IP/CIDR whitelist РФ."""
    global SNI_WHITELIST, IP_WHITELIST, CIDR_WHITELIST

    # SNI (домены)
    text = fetch_text(SNI_WHITELIST_URL)
    for line in text.splitlines():
        line = line.strip().lower()
        if line and not line.startswith("#"):
            SNI_WHITELIST.add(line)
    log.info(f"SNI whitelist: {len(SNI_WHITELIST)} доменов")

    # IP whitelist
    text = fetch_text(IP_WHITELIST_URL)
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            IP_WHITELIST.add(line)
    log.info(f"IP whitelist: {len(IP_WHITELIST)} адресов")

    # CIDR whitelist
    text = fetch_text(CIDR_WHITELIST_URL)
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            try:
                CIDR_WHITELIST.append(ipaddress.ip_network(line, strict=False))
            except ValueError:
                pass
    log.info(f"CIDR whitelist: {len(CIDR_WHITELIST)} подсетей")


# ─── Фильтр ───────────────────────────────────────────────────────────────────

IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

def is_ip(host: str) -> bool:
    return bool(IP_RE.match(host))

def ip_in_whitelist(host: str) -> bool:
    if host in IP_WHITELIST:
        return True
    try:
        addr = ipaddress.ip_address(host)
        return any(addr in net for net in CIDR_WHITELIST)
    except ValueError:
        return False

def is_allowed(cfg: dict) -> bool:
    """
    Сервер проходит если выполняется хотя бы одно:
    1. SNI в РФ whitelist
    2. Хост — домен (не IP)
    3. Хост — IP с префиксом 158./89./84.
    4. Хост — IP из IP/CIDR whitelist РФ
    """
    host = cfg["host"]
    sni  = cfg.get("sni", "").lower()

    # SNI в whitelist
    if sni and sni in SNI_WHITELIST:
        return True

    if is_ip(host):
        # IP префикс
        if any(host.startswith(p) for p in IP_PREFIXES):
            return True
        # IP/CIDR whitelist
        if ip_in_whitelist(host):
            return True
        return False

    # Домен — всегда разрешён
    return True

# ─── Загрузка и парсинг ───────────────────────────────────────────────────────

def fetch_text(url: str) -> str:
    try:
        r = requests.get(url, timeout=15)
        r.raise_for_status()
        return r.text
    except Exception as e:
        log.warning(f"Пропуск {url}: {e}")
        return ""


def try_base64_decode(text: str) -> str:
    for _ in range(5):
        if "vless://" in text:
            return text
        try:
            decoded = base64.b64decode(text.strip()).decode("utf-8", errors="ignore")
            if "vless://" in decoded:
                return decoded
            text = decoded
        except Exception:
            break
    return text


def parse_vless(uri: str) -> dict | None:
    try:
        m = re.match(r"vless://([^@]+)@([^:/?#]+):(\d+)([/?].*)?", uri)
        if not m:
            return None
        uuid, host, port_str, rest = m.group(1), m.group(2), m.group(3), m.group(4) or ""
        port = int(port_str)

        qs = {}
        if "?" in rest:
            query = rest.split("?", 1)[1].split("#")[0]
            for pair in query.split("&"):
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    qs[k] = unquote(v)

        return {
            "uuid": uuid,
            "host": host,
            "port": port,
            "flow":     qs.get("flow",     "xtls-rprx-vision"),
            "security": qs.get("security", "reality"),
            "sni":      qs.get("sni",      ""),
            "pbk":      qs.get("pbk",      ""),
            "fp":       qs.get("fp",       "chrome"),
            "sid":      qs.get("sid",      ""),
            "type":     qs.get("type",     "tcp"),
        }
    except Exception:
        return None


def collect_configs() -> list[dict]:
    seen: set[str] = set()
    configs: list[dict] = []

    for url in SOURCES:
        log.info(f"Загружаем: {url}")
        raw = fetch_text(url)
        if not raw:
            continue

        text = try_base64_decode(raw)

        for line in text.splitlines():
            line = line.strip()
            if not line.startswith("vless://"):
                continue
            base = re.sub(r"#.*$", "", line).strip()
            cfg = parse_vless(base)
            if cfg is None:
                continue

            key = f"{cfg['host']}:{cfg['port']}"
            if key in seen:
                continue
            if not is_allowed(cfg):
                continue

            seen.add(key)
            configs.append(cfg)

    log.info(f"Собрано уникальных конфигов: {len(configs)}")
    return configs

# ─── Проверка через xray ──────────────────────────────────────────────────────

def find_free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def make_xray_config(cfg: dict, socks_port: int) -> dict:
    """Генерирует минимальный xray JSON для проверки одного сервера."""
    outbound = {
        "tag": "proxy",
        "protocol": "vless",
        "settings": {
            "vnext": [{
                "address": cfg["host"],
                "port":    cfg["port"],
                "users":  [{
                    "id":         cfg["uuid"],
                    "encryption": "none",
                    "flow":       cfg["flow"]
                }]
            }]
        },
        "streamSettings": {
            "network":  "tcp",
            "security": cfg["security"],
        }
    }

    if cfg["security"] == "reality":
        outbound["streamSettings"]["realitySettings"] = {
            "serverName":  cfg["sni"],
            "publicKey":   cfg["pbk"],
            "shortId":     cfg["sid"],
            "fingerprint": cfg["fp"]
        }
    elif cfg["security"] == "tls":
        outbound["streamSettings"]["tlsSettings"] = {
            "serverName":  cfg["sni"],
            "fingerprint": cfg["fp"]
        }

    return {
        "log": {"loglevel": "none"},
        "inbounds": [{
            "tag":      "socks-in",
            "port":     socks_port,
            "listen":   "127.0.0.1",
            "protocol": "socks",
            "settings": {"udp": False, "auth": "noauth"}
        }],
        "outbounds": [
            outbound,
            {"tag": "direct",   "protocol": "freedom"},
            {"tag": "block",    "protocol": "blackhole"}
        ]
    }


def check_server(cfg: dict) -> tuple[dict, float] | None:
    """TCP connect проверка — открыт ли порт."""
    try:
        t0 = time.monotonic()
        with socket.create_connection((cfg["host"], cfg["port"]), timeout=TCP_TIMEOUT):
            rtt = (time.monotonic() - t0) * 1000
        log.debug(f"✅ {cfg['host']}:{cfg['port']} — {rtt:.0f}ms")
        return (cfg, rtt)
    except Exception:
        log.debug(f"❌ {cfg['host']}:{cfg['port']}")
        return None


def check_all(configs: list[dict]) -> list[tuple[dict, float]]:
    """Параллельная проверка всех конфигов через TCP."""
    log.info(f"Проверяем {len(configs)} серверов ({CHECK_WORKERS} потоков)...")
    results = []

    with ThreadPoolExecutor(max_workers=CHECK_WORKERS) as ex:
        futures = {ex.submit(check_server, cfg): cfg for cfg in configs}
        done = 0
        try:
            for fut in as_completed(futures, timeout=600):
                done += 1
                if done % 50 == 0:
                    log.info(f"Проверено: {done}/{len(configs)} | живых: {len(results)}")
                try:
                    res = fut.result(timeout=TCP_TIMEOUT + 1)
                    if res is not None:
                        results.append(res)
                except Exception:
                    pass
        except Exception:
            log.warning(f"Таймаут пула — собрано {len(results)} живых, продолжаем...")

    results.sort(key=lambda x: x[1])
    log.info(f"Живых серверов: {len(results)} из {len(configs)}")
    return results

# ─── Генерация outbound ───────────────────────────────────────────────────────

def make_outbound(cfg: dict, tag: str) -> dict:
    ob = {
        "tag":      tag,
        "protocol": "vless",
        "settings": {
            "vnext": [{
                "address": cfg["host"],
                "port":    cfg["port"],
                "users":  [{
                    "id":         cfg["uuid"],
                    "encryption": "none",
                    "flow":       cfg["flow"]
                }]
            }]
        },
        "streamSettings": {
            "network":     "tcp",
            "tcpSettings": {},
            "security":    cfg["security"],
        }
    }

    if cfg["security"] == "reality":
        ob["streamSettings"]["realitySettings"] = {
            "serverName":  cfg["sni"],
            "publicKey":   cfg["pbk"],
            "shortId":     cfg["sid"],
            "fingerprint": cfg["fp"]
        }
    elif cfg["security"] == "tls":
        ob["streamSettings"]["tlsSettings"] = {
            "serverName":  cfg["sni"],
            "fingerprint": cfg["fp"]
        }

    return ob

# ─── Сборка пака ──────────────────────────────────────────────────────────────

def make_pack(configs: list[dict], rtts: list[float], pack_num: int) -> dict:
    outbounds = []
    for i, cfg in enumerate(configs, 1):
        outbounds.append(make_outbound(cfg, f"lte-{i}"))

    outbounds += [
        {"tag": "direct", "protocol": "freedom",   "settings": {"domainStrategy": "UseIP"}},
        {"tag": "block",  "protocol": "blackhole"}
    ]

    avg_rtt = sum(rtts) / len(rtts) if rtts else 0

    return {
        "remarks": f"🇳🇴LTE | 📶 — {pack_num} ⚡ | RU",
        "log": {"dnsLog": False, "loglevel": "error"},
        "dns": {
            "servers":       ["1.1.1.1", "1.0.0.1", "8.8.8.8"],
            "queryStrategy": "UseIPv4"
        },
        "routing": {
            "domainMatcher":  "hybrid",
            "domainStrategy": "IPIfNonMatch",
            "rules": [
                {
                    "ip": [
                        "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
                        "172.16.0.0/12", "192.168.0.0/16",
                        "169.254.0.0/16", "224.0.0.0/4", "255.255.255.255"
                    ],
                    "outboundTag": "direct"
                },
                {
                    "type":        "field",
                    "protocol":    ["bittorrent"],
                    "outboundTag": "direct"
                },
                {
                    "network":     "tcp,udp",
                    "balancerTag": "LTE-Balancer"
                }
            ],
            "balancers": [{
                "tag":      "LTE-Balancer",
                "selector": ["lte-"],
                "strategy": {
                    "type": "leastLoad",
                    "settings": {"maxRTT": "3000ms", "expected": 2}
                }
            }]
        },
        "inbounds": [
            {
                "tag":      "socks",
                "port":     10808,
                "listen":   "127.0.0.1",
                "protocol": "socks",
                "settings": {"udp": True, "auth": "noauth"},
                "sniffing": {
                    "enabled":     True,
                    "routeOnly":   False,
                    "destOverride": ["tls", "http", "quic"],
                    "metadataOnly": False
                }
            },
            {
                "tag":      "http",
                "port":     10809,
                "listen":   "127.0.0.1",
                "protocol": "http",
                "sniffing": {
                    "enabled":     True,
                    "routeOnly":   False,
                    "destOverride": ["tls", "http", "quic"],
                    "metadataOnly": False
                }
            }
        ],
        "outbounds": outbounds,
        "burstObservatory": {
            "pingConfig": {
                "timeout":     "5s",
                "interval":    "36s",
                "sampling":    5,
                "httpMethod":  "HEAD",
                "destination": "http://connectivitycheck.gstatic.com/generate_204",
                "connectivity": ""
            },
            "subjectSelector": ["lte-"]
        }
    }

# ─── Главная функция ──────────────────────────────────────────────────────────

def main():
    # 1. Загружаем whitelist РФ
    load_whitelists()

    # 2. Собираем конфиги
    configs = collect_configs()
    if not configs:
        log.error("Нет конфигов!")
        return

    # 3. Проверяем через TCP
    alive = check_all(configs)
    if not alive:
        log.error("Нет живых серверов!")
        return

    alive_cfgs = [c for c, _ in alive]
    alive_rtts = [r for _, r in alive]

    # 4. Генерируем vlees.txt
    with open("vlees.txt", "w", encoding="utf-8") as f:
        f.write("#profile-title: HiBypass 🗽 | FREE LTE | ∞\n")
        f.write("#subscription-userinfo: upload=0; download=0; total=999999999999999; expire=4102444800\n")
        f.write("#profile-update-interval: 1\n")
        f.write("#announce: Бесплатный обход белых списков 🏳🇷🇺 | Если перестало работать — обновите подписку 🔄\n")
        f.write("#announce-url: https://t.me/HiBypass\n")
        f.write("#update-always: true\n")
        for i, (cfg, rtt) in enumerate(alive, 1):
            uri = (
                f"vless://{cfg['uuid']}@{cfg['host']}:{cfg['port']}"
                f"?security={cfg['security']}&sni={cfg['sni']}"
                f"&pbk={cfg['pbk']}&fp={cfg['fp']}&sid={cfg['sid']}"
                f"&flow={cfg['flow']}&type={cfg['type']}"
                f"#🇳🇴LTE | 📶 — {i} ⚡ | RU | {rtt:.0f}ms"
            )
            f.write(uri + "\n")
    log.info(f"vlees.txt: {len(alive)} живых конфигов")

    # 5. Нарезаем на паки
    packs = []
    for i in range(0, len(alive_cfgs), PACK_SIZE):
        chunk_cfgs = alive_cfgs[i:i + PACK_SIZE]
        chunk_rtts = alive_rtts[i:i + PACK_SIZE]
        pack_num   = (i // PACK_SIZE) + 1
        packs.append(make_pack(chunk_cfgs, chunk_rtts, pack_num))

    # 6. Сохраняем bb.json
    with open("bb.json", "w", encoding="utf-8") as f:
        json.dump(packs, f, ensure_ascii=False, indent=2)

    log.info(f"bb.json: {len(packs)} паков × до {PACK_SIZE} серверов = {len(alive_cfgs)} живых")


if __name__ == "__main__":
    main()
