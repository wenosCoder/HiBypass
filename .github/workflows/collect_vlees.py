#!/usr/bin/env python3
"""
VLESS Collector → bb.json (один готовый v2rayTun JSON-конфиг, топ-10 LTE)
"""

import json
import base64
import urllib.parse
import os
import ipaddress
from datetime import datetime, timezone

try:
    import requests
except ImportError:
    import subprocess, sys
    subprocess.check_call([sys.executable, "-m", "pip", "install", "requests"])
    import requests

# ──────────────────────────────────────────────
# Настройки
# ──────────────────────────────────────────────

PROFILE_TITLE   = "HiBypass 🗽 | FREE LTE | ∞"
SUPPORT_URL     = "https://t.me/HiBypass"
ANNOUNCE        = "Бесплатный обход белых списков 🏳🇷🇺 | Если перестало работать — обновите подписку 🔄"
TOP_N           = 10          # сколько серверов в паке

# Метки серверов в паке
def lte_tag(n: int) -> str:
    return f"🇳🇴LTE | 📶 — {n} ⚡ | RU"

# Внутренние теги для балансировщика (короткие, ASCII)
def lte_internal(n: int) -> str:
    return f"lte-{n}"

# ──────────────────────────────────────────────
# Источники
# ──────────────────────────────────────────────
SOURCES = [
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/BLACK_VLESS_RUS.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/BLACK_VLESS_RUS_mobile.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/Vless-Reality-White-Lists-Rus-Mobile-2.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/Vless-Reality-White-Lists-Rus-Mobile.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/BLACK_SS%2BAll_RUS.txt",
    "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass-unsecure/raw/bypass-unsecure-all-raw.txt",
    "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass/raw/bypass-all-raw.txt",
    "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/default/all-secure-1.txt",
    "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/default/all-secure-2.txt",
    "https://raw.githubusercontent.com/VOID-Anonymity/V.O.I.D-VPN_Bypass/refs/heads/main/url_work.txt",
    "https://raw.githubusercontent.com/zieng2/wl/refs/heads/main/vless_universal.txt",
    "https://raw.githubusercontent.com/zieng2/wl/refs/heads/main/vless_lite.txt",
]

# ──────────────────────────────────────────────
# IP-фильтр: 158/8, 89/8, 84/8 + домены
# ──────────────────────────────────────────────
ALLOWED_NETS = [
    ipaddress.ip_network("158.0.0.0/8"),
    ipaddress.ip_network("89.0.0.0/8"),
    ipaddress.ip_network("84.0.0.0/8"),
]

HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; vless-collector/1.0)"}


# ──────────────────────────────────────────────
# Утилиты
# ──────────────────────────────────────────────

def is_domain(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return False
    except ValueError:
        return True


def ip_allowed(host: str) -> bool:
    if is_domain(host):
        return True          # домены всегда проходят
    try:
        addr = ipaddress.ip_address(host)
        return any(addr in net for net in ALLOWED_NETS)
    except ValueError:
        return False


def fetch_lines(url: str) -> list[str]:
    try:
        r = requests.get(url, headers=HEADERS, timeout=20)
        r.raise_for_status()
        text = r.text.strip()
        # Рекурсивное base64-декодирование (до 5 попыток)
        for _ in range(5):
            if any(text.startswith(p) for p in ("vless://", "vmess://", "ss://", "trojan://")):
                break
            try:
                dec = base64.b64decode(text + "==").decode("utf-8", errors="ignore")
                if "://" in dec:
                    text = dec
                else:
                    break
            except Exception:
                break
        return [l.strip() for l in text.splitlines() if "://" in l]
    except Exception as e:
        print(f"  ⚠ {url.split('/')[-1]}: {e}")
        return []


def parse_vless(uri: str) -> dict | None:
    try:
        body = uri[len("vless://"):]
        name = ""
        if "#" in body:
            body, name = body.rsplit("#", 1)
            name = urllib.parse.unquote(name)

        userinfo, rest = body.split("@", 1)
        hostport, params_raw = (rest.split("?", 1) + [""])[:2]

        if hostport.startswith("["):
            end = hostport.index("]")
            host = hostport[1:end]
            port = int(hostport[end + 2:])
        else:
            host, port_str = hostport.rsplit(":", 1)
            port = int(port_str)

        p = dict(urllib.parse.parse_qsl(params_raw))
        return {
            "uuid":        userinfo,
            "address":     host,
            "port":        port,
            "name":        name,
            "encryption":  p.get("encryption", "none"),
            "flow":        p.get("flow", "xtls-rprx-vision"),
            "network":     p.get("type", "tcp"),
            "security":    p.get("security", "none"),
            "sni":         p.get("sni", host),
            "fp":          p.get("fp", "chrome"),
            "pbk":         p.get("pbk", ""),
            "sid":         p.get("sid", ""),
            "path":        p.get("path", "/"),
            "host_header": p.get("host", ""),
            "mode":        p.get("mode", ""),
            "_uri":        uri,
        }
    except Exception:
        return None


def score(cfg: dict) -> int:
    s = 0
    if cfg["security"] == "reality": s += 30
    elif cfg["security"] == "tls":   s += 20
    if "xtls" in cfg["flow"]:        s += 10
    if is_domain(cfg["address"]):    s += 15
    if cfg["network"] in ("xhttp", "ws", "grpc", "h2"): s += 10
    if cfg["port"] in (443, 8443, 2083, 2053):           s += 5
    return s


def build_outbound(cfg: dict, tag: str) -> dict:
    """Строит один outbound-блок для v2rayTun / Xray."""
    stream: dict = {"network": cfg["network"], "security": cfg["security"]}

    if cfg["security"] == "reality":
        stream["realitySettings"] = {
            "serverName":  cfg["sni"],
            "fingerprint": cfg["fp"],
            "publicKey":   cfg["pbk"],
            "shortId":     cfg["sid"],
        }
    elif cfg["security"] == "tls":
        stream["tlsSettings"] = {
            "serverName":  cfg["sni"],
            "fingerprint": cfg["fp"],
        }

    net = cfg["network"]
    if net == "ws":
        stream["wsSettings"] = {
            "path": cfg["path"],
            "headers": {"Host": cfg["host_header"] or cfg["sni"]},
        }
    elif net == "grpc":
        stream["grpcSettings"] = {"serviceName": cfg["path"]}
    elif net == "h2":
        stream["httpSettings"] = {
            "path": cfg["path"],
            "host": [cfg["host_header"] or cfg["sni"]],
        }
    elif net == "xhttp":
        stream["xhttpSettings"] = {"path": cfg["path"], "mode": cfg["mode"] or "auto"}

    return {
        "tag":      tag,
        "protocol": "vless",
        "settings": {
            "vnext": [{
                "address": cfg["address"],
                "port":    cfg["port"],
                "users":  [{
                    "id":         cfg["uuid"],
                    "encryption": cfg["encryption"],
                    "flow":       cfg["flow"],
                }],
            }]
        },
        "streamSettings": stream,
    }


# ──────────────────────────────────────────────
# Сборка bb.json — один v2rayTun-конфиг с топ-10
# ──────────────────────────────────────────────

def build_bb_json(top10: list[dict], generated_at: str) -> dict:
    """
    Возвращает полноценный JSON-конфиг для v2rayTun:
      - remarks / метаданные подписки
      - dns
      - observatory (автопинг)
      - routing + балансировщик leastPing по топ-10
      - inbounds (socks + http)
      - outbounds: топ-10 LTE + direct + block
    """
    # Строим outbounds для топ-10
    lte_outbounds = []
    for n, cfg in enumerate(top10, 1):
        ob = build_outbound(cfg, lte_internal(n))
        # Человекочитаемое имя хранится в remarks тега через _name (v2rayTun читает tag)
        # Переименовываем tag в красивый вид — v2rayTun показывает его как имя сервера
        ob["tag"] = lte_tag(n)
        lte_outbounds.append(ob)

    # Селектор для балансировщика — ищем по началу строки тега
    selector_prefix = "🇳🇴LTE"

    bb = {
        # ── Метаданные подписки (v2rayTun читает эти поля) ──
        "remarks": PROFILE_TITLE,
        "_profile-update-interval": 1,
        "_support-url": SUPPORT_URL,
        "_announce": ANNOUNCE,
        "_generated": generated_at,

        # ── DNS ──
        "dns": {
            "servers": ["1.1.1.1", "1.0.0.1", "8.8.8.8"],
            "queryStrategy": "UseIPv4",
        },

        # ── Observatory — автопинг всех lte-серверов ──
        "observatory": {
            "enableConcurrency": True,
            "probeInterval":     "15s",
            "probeUrl":          "http://www.gstatic.com/generate_204",
            "subjectSelector":   [selector_prefix],
        },

        # ── Routing + балансировщик leastPing ──
        "routing": {
            "domainMatcher":  "hybrid",
            "domainStrategy": "IPIfNonMatch",
            "rules": [
                {
                    "type":        "field",
                    "protocol":    ["bittorrent"],
                    "outboundTag": "direct",
                },
                {
                    "type":        "field",
                    "inboundTag":  ["socks", "http"],
                    "balancerTag": "BALANCER",
                },
            ],
            "balancers": [{
                "tag":      "BALANCER",
                "selector": [selector_prefix],
                "strategy": {"type": "leastPing"},
            }],
        },

        # ── Inbounds ──
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
                    "destOverride": ["http", "tls", "quic"],
                },
            },
            {
                "tag":      "http",
                "port":     10809,
                "listen":   "127.0.0.1",
                "protocol": "http",
                "settings": {"allowTransparent": False},
                "sniffing": {
                    "enabled":     True,
                    "routeOnly":   False,
                    "destOverride": ["http", "tls", "quic"],
                },
            },
        ],

        # ── Outbounds: топ-10 LTE + служебные ──
        "outbounds": lte_outbounds + [
            {"tag": "direct", "protocol": "freedom"},
            {"tag": "block",  "protocol": "blackhole"},
        ],
    }

    return bb


# ──────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────

def main():
    now = datetime.now(timezone.utc)
    print(f"\n{'='*55}")
    print(f"  VLESS Collector  |  {now.strftime('%Y-%m-%d %H:%M UTC')}")
    print(f"{'='*55}\n")

    # ── Сбор ──
    all_uris: set[str] = set()
    for url in SOURCES:
        print(f"📥 {url.split('/')[-1]}")
        lines = fetch_lines(url)
        before = len(all_uris)
        all_uris.update(lines)
        print(f"   +{len(all_uris) - before} уник.")

    print(f"\n📊 Всего строк: {len(all_uris)}")

    # ── Парсинг + IP-фильтр ──
    configs, skip_ip, skip_parse = [], 0, 0
    for uri in all_uris:
        if not uri.startswith("vless://"):
            continue
        cfg = parse_vless(uri)
        if cfg is None:
            skip_parse += 1
            continue
        if not ip_allowed(cfg["address"]):
            skip_ip += 1
            continue
        configs.append(cfg)

    print(f"✅ После фильтра: {len(configs)}  (−IP: {skip_ip}, −parse: {skip_parse})")

    # ── Дедупликация (3 уровня) ──
    # 1. по uuid            — один сервер из разных источников
    # 2. по (address, port) — один хост:порт с разными uuid
    # 3. по URI без #имени  — точные дубли с разными метками
    seen_uuid:     set[str]   = set()
    seen_hostport: set[tuple] = set()
    seen_uri:      set[str]   = set()
    unique: list[dict] = []
    dup_uuid, dup_hp, dup_uri = 0, 0, 0

    for cfg in configs:
        norm_uri = cfg["_uri"].split("#")[0].strip()

        if cfg["uuid"] in seen_uuid:
            dup_uuid += 1
            continue
        if (cfg["address"], cfg["port"]) in seen_hostport:
            dup_hp += 1
            continue
        if norm_uri in seen_uri:
            dup_uri += 1
            continue

        seen_uuid.add(cfg["uuid"])
        seen_hostport.add((cfg["address"], cfg["port"]))
        seen_uri.add(norm_uri)
        unique.append(cfg)

    print(f"🔑 Уникальных: {len(unique)}  (дублей uuid:{dup_uuid} host:port:{dup_hp} uri:{dup_uri})")

    # ── Ранжирование → топ-10 ──
    top10 = sorted(unique, key=score, reverse=True)[:TOP_N]

    # ── bb.json — один v2rayTun-конфиг ──
    bb = build_bb_json(top10, now.isoformat())

    with open("bb.json", "w", encoding="utf-8") as f:
        json.dump(bb, f, ensure_ascii=False, indent=2)

    print(f"\n🎉 bb.json готов — {len(top10)} серверов в паке")
    print(f"\n{'─'*40}")
    print("🏆 ТОП-10 LTE:")
    for n, cfg in enumerate(top10, 1):
        print(f"  {lte_tag(n)}")
        print(f"    {cfg['address']}:{cfg['port']} | {cfg['security']} | {cfg['network']} | score={score(cfg)}")


if __name__ == "__main__":
    main()
