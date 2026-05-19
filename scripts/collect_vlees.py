#!/usr/bin/env python3
"""
Сборщик VLESS-конфигов для v2rayTun
Генерирует bb.json (паки по 10 серверов) и vlees.txt
"""

import re
import json
import base64
import logging
import requests
from urllib.parse import urlparse, parse_qs, unquote

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)

# ─── Источники ────────────────────────────────────────────────────────────────
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

# ─── IP-фильтр ────────────────────────────────────────────────────────────────
# Пропускаем только IP из диапазонов 158.x / 89.x / 84.x
# Домены (не IP) — пропускаем всегда

IP_PREFIXES = ("158.", "89.", "84.")

def is_allowed_host(host: str) -> bool:
    """True → конфиг допустим (домен или нужный IP-префикс)."""
    # Проверяем, IP ли это вообще
    ip_pattern = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
    if ip_pattern.match(host):
        return any(host.startswith(p) for p in IP_PREFIXES)
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
    """Пытаемся раскодировать base64 (до 5 раз рекурсивно)."""
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


def extract_vless(text: str) -> list[str]:
    """Извлекает строки vless:// из текста (без #-комментария)."""
    lines = []
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("vless://"):
            # Обрезаем имя (#...) в конце
            base = re.sub(r"#.*$", "", line).strip()
            lines.append(base)
    return lines


def parse_vless(uri: str) -> dict | None:
    """Парсит vless:// URI в словарь параметров."""
    try:
        # vless://UUID@HOST:PORT?params
        m = re.match(r"vless://([^@]+)@([^:/?#]+):(\d+)([/?].*)?", uri)
        if not m:
            return None
        uuid, host, port_str, rest = m.group(1), m.group(2), m.group(3), m.group(4) or ""
        port = int(port_str)

        # Парсим query-параметры
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
            "flow": qs.get("flow", "xtls-rprx-vision"),
            "security": qs.get("security", "reality"),
            "sni": qs.get("sni", ""),
            "pbk": qs.get("pbk", ""),
            "fp": qs.get("fp", "chrome"),
            "sid": qs.get("sid", ""),
            "type": qs.get("type", "tcp"),
        }
    except Exception:
        return None


# ─── Сборка ───────────────────────────────────────────────────────────────────

def collect_configs() -> list[dict]:
    seen: set[str] = set()
    configs: list[dict] = []

    for url in SOURCES:
        log.info(f"Загружаем: {url}")
        raw = fetch_text(url)
        if not raw:
            continue

        text = try_base64_decode(raw)
        uris = extract_vless(text)

        for uri in uris:
            cfg = parse_vless(uri)
            if cfg is None:
                continue

            host = cfg["host"]
            port = cfg["port"]
            key = f"{host}:{port}"

            if key in seen:
                continue

            if not is_allowed_host(host):
                log.debug(f"Пропуск по IP-фильтру: {host}")
                continue

            seen.add(key)
            configs.append(cfg)

    log.info(f"Уникальных конфигов после фильтра: {len(configs)}")
    return configs


# ─── Генерация outbound ───────────────────────────────────────────────────────

def make_outbound(cfg: dict, tag: str) -> dict:
    ob = {
        "tag": tag,
        "protocol": "vless",
        "settings": {
            "vnext": [{
                "address": cfg["host"],
                "port": cfg["port"],
                "users": [{
                    "id": cfg["uuid"],
                    "encryption": "none",
                    "flow": cfg["flow"]
                }]
            }]
        },
        "streamSettings": {
            "network": "tcp",
            "tcpSettings": {},
            "security": cfg["security"],
        }
    }

    if cfg["security"] == "reality":
        ob["streamSettings"]["realitySettings"] = {
            "serverName": cfg["sni"],
            "publicKey": cfg["pbk"],
            "shortId": cfg["sid"],
            "fingerprint": cfg["fp"]
        }
    elif cfg["security"] == "tls":
        ob["streamSettings"]["tlsSettings"] = {
            "serverName": cfg["sni"],
            "fingerprint": cfg["fp"]
        }

    return ob


# ─── Сборка пака ──────────────────────────────────────────────────────────────

PACK_SIZE = 10   # серверов в одном паке

def make_pack(configs: list[dict], pack_num: int) -> dict:
    outbounds = []
    for i, cfg in enumerate(configs, 1):
        outbounds.append(make_outbound(cfg, f"lte-{i}"))

    outbounds += [
        {"tag": "direct", "protocol": "freedom", "settings": {"domainStrategy": "UseIP"}},
        {"tag": "block", "protocol": "blackhole"}
    ]

    return {
        "remarks": f"🇳🇴LTE | 📶 — {pack_num} ⚡ | RU",
        "log": {
            "dnsLog": False,
            "loglevel": "error"
        },
        "dns": {
            "servers": ["1.1.1.1", "1.0.0.1", "8.8.8.8"],
            "queryStrategy": "UseIPv4"
        },
        "routing": {
            "domainMatcher": "hybrid",
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
                    "type": "field",
                    "protocol": ["bittorrent"],
                    "outboundTag": "direct"
                },
                {
                    "network": "tcp,udp",
                    "balancerTag": "LTE-Balancer"
                }
            ],
            "balancers": [{
                "tag": "LTE-Balancer",
                "selector": ["lte-"],
                "strategy": {
                    "type": "leastLoad",
                    "settings": {
                        "maxRTT": "3000ms",
                        "expected": 2
                    }
                }
            }]
        },
        "inbounds": [
            {
                "tag": "socks",
                "port": 10808,
                "listen": "127.0.0.1",
                "protocol": "socks",
                "settings": {"udp": True, "auth": "noauth"},
                "sniffing": {
                    "enabled": True,
                    "routeOnly": False,
                    "destOverride": ["tls", "http", "quic"],
                    "metadataOnly": False
                }
            },
            {
                "tag": "http",
                "port": 10809,
                "listen": "127.0.0.1",
                "protocol": "http",
                "sniffing": {
                    "enabled": True,
                    "routeOnly": False,
                    "destOverride": ["tls", "http", "quic"],
                    "metadataOnly": False
                }
            }
        ],
        "outbounds": outbounds,
        "burstObservatory": {
            "pingConfig": {
                "timeout": "5s",
                "interval": "36s",
                "sampling": 5,
                "httpMethod": "HEAD",
                "destination": "http://connectivitycheck.gstatic.com/generate_204",
                "connectivity": ""
            },
            "subjectSelector": ["lte-"]
        }
    }


# ─── Главная функция ──────────────────────────────────────────────────────────

def main():
    configs = collect_configs()

    if not configs:
        log.error("Нет конфигов! Выход.")
        return

    # Генерируем vlees.txt
    with open("vlees.txt", "w", encoding="utf-8") as f:
        f.write("#profile-title: HiBypass 🗽 | FREE LTE | ∞\n")
        f.write("#subscription-userinfo: upload=0; download=0; total=999999999999999; expire=4102444800\n")
        f.write("#profile-update-interval: 1\n")
        f.write("#announce: Бесплатный обход белых списков 🏳🇷🇺 | Если перестало работать — обновите подписку 🔄\n")
        f.write("#announce-url: https://t.me/HiBypass\n")
        f.write("#update-always: true\n")
        for i, cfg in enumerate(configs, 1):
            uri = (
                f"vless://{cfg['uuid']}@{cfg['host']}:{cfg['port']}"
                f"?security={cfg['security']}&sni={cfg['sni']}"
                f"&pbk={cfg['pbk']}&fp={cfg['fp']}&sid={cfg['sid']}"
                f"&flow={cfg['flow']}&type={cfg['type']}"
                f"#🇳🇴LTE | 📶 — {i} ⚡ | RU"
            )
            f.write(uri + "\n")
    log.info(f"vlees.txt: {len(configs)} конфигов")

    # Нарезаем на паки по PACK_SIZE
    packs = []
    for i in range(0, len(configs), PACK_SIZE):
        chunk = configs[i:i + PACK_SIZE]
        pack_num = (i // PACK_SIZE) + 1
        packs.append(make_pack(chunk, pack_num))

    # Сохраняем bb.json
    with open("bb.json", "w", encoding="utf-8") as f:
        json.dump(packs, f, ensure_ascii=False, indent=2)

    log.info(f"bb.json: {len(packs)} паков × до {PACK_SIZE} серверов = {len(configs)} всего")


if __name__ == "__main__":
    main()
