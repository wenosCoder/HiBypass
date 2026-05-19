#!/usr/bin/env python3
"""
VLESS Config Collector for v2rayTun
Собирает публичные конфиги, фильтрует по IP-диапазонам RU, строит bb.json
"""

import json
import re
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
# IP-фильтр: разрешённые диапазоны (RU LTE)
# 158.x.x.x / 89.x.x.x / 84.x.x.x
# ──────────────────────────────────────────────
ALLOWED_IP_PREFIXES = [
    ipaddress.ip_network("158.0.0.0/8"),
    ipaddress.ip_network("89.0.0.0/8"),
    ipaddress.ip_network("84.0.0.0/8"),
]

# ──────────────────────────────────────────────
# Флаги LTE-пака (эмодзи + метка)
# ──────────────────────────────────────────────
LTE_LABEL_TEMPLATE = "🇷🇺LTE | 📶 — {n} ⚡ | RU"

HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; vless-collector/1.0)",
}

# ──────────────────────────────────────────────
# Утилиты
# ──────────────────────────────────────────────

def is_domain(host: str) -> bool:
    """Возвращает True если хост — доменное имя, а не IP."""
    try:
        ipaddress.ip_address(host)
        return False
    except ValueError:
        return True


def ip_allowed(host: str) -> bool:
    """
    Пропускает хост если:
      - это домен (домены проходят всегда)
      - IP входит в один из разрешённых /8-диапазонов
    """
    if is_domain(host):
        return True
    try:
        addr = ipaddress.ip_address(host)
        return any(addr in net for net in ALLOWED_IP_PREFIXES)
    except ValueError:
        return False


def fetch_source(url: str) -> list[str]:
    """Скачивает URL и возвращает список строк. Поддерживает base64."""
    try:
        r = requests.get(url, headers=HEADERS, timeout=20)
        r.raise_for_status()
        text = r.text.strip()

        # Попытка base64-декодирования (формат V2RayN)
        if not text.startswith("vless://") and not text.startswith("vmess://") \
                and not text.startswith("ss://") and not text.startswith("trojan://"):
            try:
                decoded = base64.b64decode(text + "==").decode("utf-8", errors="ignore")
                if "://" in decoded:
                    text = decoded
            except Exception:
                pass

        return [line.strip() for line in text.splitlines() if "://" in line]
    except Exception as e:
        print(f"  ⚠ Ошибка загрузки {url}: {e}")
        return []


def parse_vless(uri: str) -> dict | None:
    """Парсит vless:// URI в словарь."""
    try:
        # vless://UUID@host:port?params#name
        without_scheme = uri[len("vless://"):]
        if "#" in without_scheme:
            main, name = without_scheme.rsplit("#", 1)
            name = urllib.parse.unquote(name)
        else:
            main, name = without_scheme, ""

        userinfo, hostport_params = main.split("@", 1)

        if "?" in hostport_params:
            hostport, params_raw = hostport_params.split("?", 1)
        else:
            hostport, params_raw = hostport_params, ""

        # Разбор host:port (IPv6 — [::1]:443)
        if hostport.startswith("["):
            bracket_end = hostport.index("]")
            host = hostport[1:bracket_end]
            port = int(hostport[bracket_end+2:])
        elif ":" in hostport:
            host, port_str = hostport.rsplit(":", 1)
            port = int(port_str)
        else:
            return None

        params = dict(urllib.parse.parse_qsl(params_raw))

        return {
            "protocol": "vless",
            "uuid": userinfo,
            "address": host,
            "port": port,
            "name": name,
            "encryption": params.get("encryption", "none"),
            "flow": params.get("flow", ""),
            "network": params.get("type", "tcp"),
            "security": params.get("security", "none"),
            "sni": params.get("sni", host),
            "fp": params.get("fp", ""),
            "pbk": params.get("pbk", ""),
            "sid": params.get("sid", ""),
            "path": params.get("path", "/"),
            "host_header": params.get("host", ""),
            "mode": params.get("mode", ""),
            "_uri": uri,
        }
    except Exception:
        return None


def build_v2raytun_outbound(cfg: dict, tag: str) -> dict:
    """Строит outbound-блок в формате v2rayTun / Xray."""
    stream = {
        "network": cfg["network"],
        "security": cfg["security"],
    }

    # TLS / Reality
    if cfg["security"] in ("tls", "reality"):
        tls_settings = {
            "serverName": cfg["sni"],
            "fingerprint": cfg["fp"],
        }
        if cfg["security"] == "reality":
            tls_settings["publicKey"] = cfg["pbk"]
            tls_settings["shortId"] = cfg["sid"]
            stream["realitySettings"] = tls_settings
        else:
            stream["tlsSettings"] = tls_settings

    # Transport
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
        stream["xhttpSettings"] = {
            "path": cfg["path"],
            "mode": cfg["mode"] or "auto",
        }

    outbound = {
        "tag": tag,
        "protocol": "vless",
        "settings": {
            "vnext": [{
                "address": cfg["address"],
                "port": cfg["port"],
                "users": [{
                    "id": cfg["uuid"],
                    "encryption": cfg["encryption"],
                    "flow": cfg["flow"],
                }],
            }],
        },
        "streamSettings": stream,
    }
    return outbound


def score_config(cfg: dict) -> int:
    """
    Простая эвристика «лучшести» конфига для авто-выбора топ-10.
    Больше = лучше.
    """
    score = 0
    # Reality > TLS > none
    if cfg["security"] == "reality":
        score += 30
    elif cfg["security"] == "tls":
        score += 20
    # XTLS flow — быстрее
    if "xtls" in cfg.get("flow", ""):
        score += 10
    # Домены надёжнее сырых IP для мобилок
    if is_domain(cfg["address"]):
        score += 15
    # xhttp / ws / grpc = современные транспорты
    if cfg["network"] in ("xhttp", "ws", "grpc", "h2"):
        score += 10
    # Стандартные порты
    if cfg["port"] in (443, 8443, 2083, 2053):
        score += 5
    return score


# ──────────────────────────────────────────────
# Главная логика
# ──────────────────────────────────────────────

def main():
    print(f"\n{'='*55}")
    print(f"  VLESS Collector  |  {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
    print(f"{'='*55}\n")

    all_uris: set[str] = set()

    for url in SOURCES:
        print(f"📥 {url.split('/')[-1]}")
        lines = fetch_source(url)
        before = len(all_uris)
        all_uris.update(lines)
        print(f"   → +{len(all_uris)-before} уникальных строк")

    print(f"\n📊 Всего строк: {len(all_uris)}")

    # ── Парсинг и IP-фильтр ──
    configs: list[dict] = []
    skipped_ip = 0
    skipped_parse = 0

    for uri in all_uris:
        uri = uri.strip()
        if not uri.startswith("vless://"):
            continue  # только VLESS

        cfg = parse_vless(uri)
        if cfg is None:
            skipped_parse += 1
            continue

        if not ip_allowed(cfg["address"]):
            skipped_ip += 1
            continue

        configs.append(cfg)

    print(f"✅ Прошло фильтр: {len(configs)}")
    print(f"   Отброшено по IP: {skipped_ip}")
    print(f"   Не распарсено:   {skipped_parse}")

    # ── Дедупликация по (address, port, uuid) ──
    seen: set[tuple] = set()
    unique: list[dict] = []
    for cfg in configs:
        key = (cfg["address"], cfg["port"], cfg["uuid"])
        if key not in seen:
            seen.add(key)
            unique.append(cfg)

    print(f"🔑 После дедупликации: {len(unique)}")

    # ── Ранжирование → топ-10 LTE ──
    ranked = sorted(unique, key=score_config, reverse=True)
    top10 = ranked[:10]

    # ── Строим outbounds для всех конфигов ──
    outbounds = []
    for i, cfg in enumerate(unique):
        tag = f"vless_{i+1:04d}"
        outbounds.append(build_v2raytun_outbound(cfg, tag))

    # ── Топ-10 с LTE-метками ──
    lte_pack = []
    for n, cfg in enumerate(top10, start=1):
        tag = LTE_LABEL_TEMPLATE.format(n=n)
        ob = build_v2raytun_outbound(cfg, tag)
        ob["_score"] = score_config(cfg)
        ob["_original_name"] = cfg["name"]
        lte_pack.append(ob)

    # ── Формируем bb.json ──
    bb = {
        "_meta": {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "sources_count": len(SOURCES),
            "total_collected": len(all_uris),
            "after_filter": len(configs),
            "unique": len(unique),
            "ip_filter": ["158.0.0.0/8", "89.0.0.0/8", "84.0.0.0/8"],
            "domains": "allowed",
        },
        "lte_top10": lte_pack,          # 🇷🇺LTE | 📶 — N ⚡ | RU
        "all_outbounds": outbounds,      # полный список для v2rayTun
    }

    os.makedirs("output", exist_ok=True)
    os.makedirs("scripts", exist_ok=True)

    with open("bb.json", "w", encoding="utf-8") as f:
        json.dump(bb, f, ensure_ascii=False, indent=2)

    # ── Отдельный файл только LTE-пак ──
    with open("output/lte_pack.json", "w", encoding="utf-8") as f:
        json.dump(lte_pack, f, ensure_ascii=False, indent=2)

    # ── Текстовый список URI для подписки ──
    with open("output/filtered_vless.txt", "w", encoding="utf-8") as f:
        for cfg in unique:
            f.write(cfg["_uri"] + "\n")

    # ── base64-подписка (для импорта в v2rayTun) ──
    sub_text = "\n".join(cfg["_uri"] for cfg in unique)
    sub_b64 = base64.b64encode(sub_text.encode()).decode()
    with open("output/subscription.txt", "w") as f:
        f.write(sub_b64)

    print(f"\n🎉 Готово!")
    print(f"   bb.json             — полный конфиг ({len(unique)} outbounds)")
    print(f"   output/lte_pack.json — топ-10 LTE серверов")
    print(f"   output/filtered_vless.txt — URI-список")
    print(f"   output/subscription.txt   — base64-подписка для v2rayTun")

    print(f"\n{'─'*40}")
    print("🏆 ТОП-10 LTE серверов:")
    for n, cfg in enumerate(top10, 1):
        label = LTE_LABEL_TEMPLATE.format(n=n)
        print(f"  {label}")
        print(f"    {cfg['address']}:{cfg['port']} | {cfg['security']} | {cfg['network']}")


if __name__ == "__main__":
    main()
