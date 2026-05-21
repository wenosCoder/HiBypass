#!/usr/bin/env python3
"""
VLESS fetcher, deduplicator, packer + TCP/TLS health-check.
Фильтр по белому списку SNI (scripts/sni.txt).
Фильтр по префиксам IP: разрешены только 158.x.x.x, 89.x.x.x, 84.x.x.x
Split-tunneling для российских сервисов + RFC1918 в direct.
Мёртвые серверы отсеиваются через TCP+TLS probe.
"""
import argparse
import base64
import json
import os
import re
import socket
import ssl
import sys
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

# =============================================================================
# Разрешённые префиксы IP (первый октет)
# =============================================================================
DEFAULT_IP_PREFIXES = (158, 89, 84)

# =============================================================================
# 61 источник
# =============================================================================
SOURCES = {
    1: [
        ("https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile-2.txt", "1"),
        ("https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile.txt", "2"),
        ("https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_VLESS_RUS.txt", "3"),
        ("https://github.com/igareck/vpn-configs-for-russia/raw/refs/heads/main/BLACK_VLESS_RUS_mobile.txt", "4"),
        ("https://raw.githubusercontent.com/zieng2/wl/refs/heads/main/vless_universal.txt", "5"),
        ("https://raw.githubusercontent.com/zieng2/wl/refs/heads/main/vless_lite.txt", "6"),
        ("https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass/bypass-all.txt", "7"),
        ("https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/split-by-protocols/vless-secure.txt", "8"),
        ("https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/split-by-protocols/vless.txt", "9"),
        ("https://sub.obbhod.online/premium", "10"),
    ],
    2: [
        ("https://mifa.world/vless", "11"),
        ("https://raw.githubusercontent.com/Temnuk/naabuzil/refs/heads/main/whitelist_full", "12"),
        ("https://raw.githubusercontent.com/Temnuk/naabuzil/refs/heads/main/wifi", "13"),
        ("https://raw.githubusercontent.com/VOID-Anonymity/V.O.I.D-VPN_Bypass/refs/heads/main/url_work.txt", "14"),
        ("https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/refs/heads/main/githubmirror/26.txt", "15"),
        ("https://raw.githubusercontent.com/EtoNeYaProject/etoneyaproject.github.io/refs/heads/main/2", "16"),
        ("https://raw.githubusercontent.com/ByeWhiteLists/ByeWhiteLists2/refs/heads/main/ByeWhiteLists2.txt", "17"),
        ("https://ety.twinkvibe.gay/whitelist", "18"),
        ("https://white-lists.vercel.app/api/filter?code=RU", "19"),
        ("https://raw.githubusercontent.com/Hidashimora/free-vpn-anti-rkn/main/configs/31.txt", "20"),
    ],
    3: [
        ("https://raw.githubusercontent.com/tankist939-afk/Obhod-WL/refs/heads/main/Obhod%20WL", "21"),
        ("https://gbr.mydan.online/configs", "22"),
        ("https://gitverse.ru/api/repos/bywarm/rser/raw/branch/master/wl.txt", "23"),
        ("https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass-unsecure/bypass-unsecure-all.txt", "24"),
        ("https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass/raw/bypass-all-raw.txt", "25"),
        ("https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-all.txt", "26"),
        ("https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-checked.txt", "27"),
        ("https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-SNI-RU-all.txt", "28"),
        ("https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_SS%2BAll_RUS.txt", "29"),
        ("https://gist.github.com/DestroyST6767/50af50221ca1858ba2084efc0f524fbc.txt", "30"),
    ],
    4: [
        ("https://github.com/sakha1370/OpenRay/raw/refs/heads/main/output/all_valid_proxies.txt", "31"),
        ("https://raw.githubusercontent.com/sevcator/5ubscrpt10n/main/protocols/vl.txt", "32"),
        ("https://raw.githubusercontent.com/yitong2333/proxy-minging/refs/heads/main/v2ray.txt", "33"),
        ("https://raw.githubusercontent.com/acymz/AutoVPN/refs/heads/main/data/V2.txt", "34"),
        ("https://raw.githubusercontent.com/miladtahanian/V2RayCFGDumper/refs/heads/main/sub.txt", "35"),
        ("https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_RAW.txt", "36"),
        ("https://raw.githubusercontent.com/Epodonios/v2ray-configs/refs/heads/main/All_Configs_Sub.txt", "37"),
        ("https://raw.githubusercontent.com/CidVpn/cid-vpn-config/refs/heads/main/general.txt", "38"),
        ("https://raw.githubusercontent.com/mohamadfg-dev/telegram-v2ray-configs-collector/refs/heads/main/category/vless.txt", "39"),
        ("https://raw.githubusercontent.com/mheidari98/.proxy/refs/heads/main/vless", "40"),
    ],
    5: [
        ("https://raw.githubusercontent.com/youfoundamin/V2rayCollector/main/mixed_iran.txt", "41"),
        ("https://raw.githubusercontent.com/expressalaki/ExpressVPN/refs/heads/main/configs3.txt", "42"),
        ("https://raw.githubusercontent.com/MahsaNetConfigTopic/config/refs/heads/main/xray_final.txt", "43"),
        ("https://github.com/LalatinaHub/Mineral/raw/refs/heads/master/result/nodes", "44"),
        ("https://raw.githubusercontent.com/miladtahanian/Config-Collector/refs/heads/main/mixed_iran.txt", "45"),
        ("https://raw.githubusercontent.com/Pawdroid/Free-servers/refs/heads/main/sub", "46"),
        ("https://github.com/MhdiTaheri/V2rayCollector_Py/raw/refs/heads/main/sub/Mix/mix.txt", "47"),
        ("https://raw.githubusercontent.com/free18/v2ray/refs/heads/main/v.txt", "48"),
        ("https://github.com/MhdiTaheri/V2rayCollector/raw/refs/heads/main/sub/mix", "49"),
        ("https://github.com/Argh94/Proxy-List/raw/refs/heads/main/All_Config.txt", "50"),
    ],
    6: [
        ("https://raw.githubusercontent.com/shabane/kamaji/master/hub/merged.txt", "51"),
        ("https://raw.githubusercontent.com/wuqb2i4f/xray-config-toolkit/main/output/base64/mix-uri", "52"),
        ("https://github.com/Mr-Meshky/vify/raw/refs/heads/main/configs/vless.txt", "53"),
        ("https://raw.githubusercontent.com/V2RayRoot/V2RayConfig/refs/heads/main/Config/vless.txt", "54"),
        ("https://github.com/Epodonios/v2ray-configs/raw/main/Splitted-By-Protocol/trojan.txt", "55"),
        ("https://github.com/rtwo2/FastNodes/raw/refs/heads/main/sub/protocols/hysteria2.txt", "56"),
        ("https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/split-by-protocols/tuic.txt", "57"),
        ("https://gist.githubusercontent.com/angelivan388283-beep/706d96d52a24deedea0fd825d73160e0/raw/ae5c2309e86954dcf061d6da4bba1dfefbd3ac3c/HaizWait2.0", "58"),
        ("https://gist.githubusercontent.com/angelivan388283-beep/706d96d52a24deedea0fd825d73160e0/raw/ae5c2309e86954dcf061d6da4bba1dfefbd3ac3c/heisen2.0", "59"),
        ("https://gist.githubusercontent.com/angelivan388283-beep/706d96d52a24deedea0fd825d73160e0/raw/ae5c2309e86954dcf061d6da4bba1dfefbd3ac3c/heisen1.0", "60"),
        ("https://gist.githubusercontent.com/angelivan388283-beep/706d96d52a24deedea0fd825d73160e0/raw/HaizFill", "61"),
    ],
}

# =============================================================================
# Белый список SNI
# =============================================================================
def load_white_sni(path: str) -> set:
    white = set()
    if not os.path.exists(path):
        print(f"[WARN] Файл белого списка не найден: {path}", file=sys.stderr)
        return white
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            domain = line.strip().lower()
            if domain and not domain.startswith("#"):
                white.add(domain)
    return white


def is_allowed_sni(sni: str, white: set) -> bool:
    if not sni:
        return False
    sni = sni.lower().strip()
    if sni in white:
        return True
    for domain in white:
        if sni.endswith("." + domain):
            return True
    return False


def is_ip(addr: str) -> bool:
    return bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", addr))


# =============================================================================
# Фильтр по префиксам IP
# =============================================================================
def is_allowed_ip(host: str, allowed_prefixes: tuple) -> bool:
    """
    Возвращает True, если host — домен (фильтруется по SNI, не здесь).
    Если host — IP, первый октет должен быть в allowed_prefixes.
    Если allowed_prefixes пустой — пропускаем всё.
    """
    if not is_ip(host):
        return True
    if not allowed_prefixes:
        return True
    try:
        first_octet = int(host.split(".")[0])
        return first_octet in allowed_prefixes
    except (ValueError, IndexError):
        return False


# =============================================================================
# Сеть
# =============================================================================
def fetch(url: str, timeout: int = 15) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "curl/7.68.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def decode_until_vless(data: bytes, depth: int = 0, max_depth: int = 7) -> str:
    text = data.decode("utf-8", errors="ignore")
    if "vless://" in text:
        return text
    found = re.findall(r'vless://[^\s"\\]+', text)
    if found:
        return "\n".join(found)
    if depth >= max_depth:
        return ""
    try:
        decoded = base64.b64decode(data, validate=True)
        if any(b < 0x20 and b not in (0x0A, 0x0D, 0x09) for b in decoded[:256]):
            return ""
        return decode_until_vless(decoded, depth + 1, max_depth)
    except Exception:
        return ""


# =============================================================================
# Парсинг VLESS
# =============================================================================
VLESS_RE = re.compile(
    r"^vless://([^@]+)@([^:]+):(\d+)(?:\?([^#]*))?(?:#.*)?$", re.IGNORECASE
)


def parse_query(query: str) -> dict:
    params = {}
    if query:
        for part in query.split("&"):
            if "=" in part:
                k, v = part.split("=", 1)
                params[k.lower()] = v
    return params


def process_source(url: str, prefix: str, white_sni: set, allowed_prefixes: tuple):
    configs = []
    try:
        raw = fetch(url)
    except Exception as e:
        print(f"[{prefix}] Ошибка загрузки {url}: {e}", file=sys.stderr)
        return configs

    text = decode_until_vless(raw)
    if not text:
        return configs

    skipped_sni = 0
    skipped_ip = 0

    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("vless://"):
            continue
        base = line.split("#", 1)[0]

        m = VLESS_RE.match(base)
        if not m:
            continue

        uuid_str = m.group(1)
        host = m.group(2)
        port_str = m.group(3)
        query = m.group(4) or ""

        if not port_str.isdigit():
            continue
        port = int(port_str)

        params = parse_query(query)
        sni = params.get("sni", "")

        # === ФИЛЬТР БЕЛОГО СПИСКА SNI ===
        if is_allowed_sni(sni, white_sni):
            pass
        elif not sni and not is_ip(host) and is_allowed_sni(host, white_sni):
            pass
        else:
            skipped_sni += 1
            continue

        # === ФИЛЬТР ПО IP-ПРЕФИКСУ ===
        if not is_allowed_ip(host, allowed_prefixes):
            skipped_ip += 1
            continue

        configs.append({
            "base": base,
            "host": host,
            "port": port,
            "prefix": prefix,
            "uuid": uuid_str,
            "query": query,
            "sni": sni,
        })

    if skipped_ip > 0:
        print(
            f"[{prefix}] ⛔ Отсеяно по IP-префиксу (не 158/89/84): {skipped_ip}",
            file=sys.stderr,
        )

    return configs


# =============================================================================
# TCP + TLS PROBE (health-check)
# =============================================================================
def tcp_tls_probe(host: str, port: int, sni: str, timeout: float = 5.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            pass
    except Exception:
        return False

    if not sni:
        return True

    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=sni):
                return True
    except Exception:
        return False


def filter_alive(configs, max_workers: int = 100, timeout: float = 5.0):
    alive = []
    dead = 0
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        future_to_cfg = {
            ex.submit(
                tcp_tls_probe,
                c["host"],
                c["port"],
                c.get("sni") or ("" if is_ip(c["host"]) else c["host"]),
                timeout,
            ): c
            for c in configs
        }
        for future in as_completed(future_to_cfg):
            cfg = future_to_cfg[future]
            try:
                if future.result():
                    alive.append(cfg)
                else:
                    dead += 1
            except Exception:
                dead += 1

    print(f"  ❌ Отсеяно мёртвых: {dead}")
    return alive


# =============================================================================
# Генерация vlees.txt
# =============================================================================
def generate_vlees(configs, filepath: str):
    with open(filepath, "w", encoding="utf-8") as f:
        f.write("#profile-title: HiBypass | LTE FREE 🏳🇷🇺\n")
        f.write("#profile-update-interval: 1\n")
        f.write("#support-url: https://t.me/Hibypass\n")
        f.write("#profile-web-page-url: https://t.me/Hibypass\n")
        f.write("#announce: Бесплатный обход белых списков РФ 🏳🇷🇺 | ТГ : @Hibypass\n")
        f.write("#traffic-limit: ∞\n")
        f.write("#traffic-remaining: ∞\n")
        for idx, cfg in enumerate(configs, start=1):
            f.write(f"{cfg['base']}#🇪🇺LTE | {idx} 🌐 RU\n")


# =============================================================================
# Генерация packs.json
# =============================================================================
RU_DOMAINS = [
    "keyword:vk", "keyword:ok.ru", "keyword:mail.ru", "keyword:gosuslugi",
    "keyword:ozon", "keyword:wildberries", "keyword:avito", "keyword:kinopoisk",
    "keyword:dzen", "keyword:hh", "keyword:2gis", "keyword:rutube",
    "keyword:magnit", "keyword:5ka", "keyword:perekrestok", "keyword:alfabank",
    "keyword:alfaonline", "keyword:tbank", "keyword:t-bank", "keyword:tinkoff",
    "keyword:yookassa", "keyword:yoomoney", "keyword:vtb",
]


def build_outbound(cfg, tag: str):
    params = parse_query(cfg["query"])
    flow = params.get("flow", "xtls-rprx-vision")
    sni = params.get("sni", "")
    pbk = params.get("pbk", "")
    fp = params.get("fp", "chrome")
    sid = params.get("sid", "")
    sec = params.get("security", "reality")

    return {
        "tag": tag,
        "protocol": "vless",
        "settings": {
            "vnext": [{
                "address": cfg["host"],
                "port": cfg["port"],
                "users": [{
                    "id": cfg["uuid"],
                    "encryption": "none",
                    "flow": flow,
                }]
            }]
        },
        "streamSettings": {
            "network": "tcp",
            "security": sec,
            "realitySettings": {
                "serverName": sni,
                "publicKey": pbk,
                "shortId": sid,
                "fingerprint": fp,
                "allowInsecure": False,
                "show": False,
            },
        },
    }


def generate_packs(configs, filepath: str, pack_size: int = 50):
    packs = []
    total = len(configs)

    for pack_num in range(0, total, pack_size):
        chunk = configs[pack_num: pack_num + pack_size]
        outbounds = [build_outbound(c, f"lte-{i}") for i, c in enumerate(chunk, start=1)]
        outbounds.append({"tag": "direct", "protocol": "freedom"})
        outbounds.append({"tag": "block", "protocol": "blackhole"})

        pack = {
            "remarks": f"🇪🇺LTE | 1.{pack_num // pack_size + 1} 🌐",
            "dns": {
                "queryStrategy": "UseIP",
                "servers": [
                    "1.1.1.1",
                    "8.8.8.8",
                    "tls://1.1.1.1",
                    "https://dns.google/dns-query",
                    "https://cloudflare-dns.com/dns-query",
                ],
            },
            "observatory": {
                "enableConcurrency": True,
                "probeInterval": "15s",
                "probeUrl": "https://cp.cloudflare.com/generate_204",
                "subjectSelector": ["lte-"],
            },
            "routing": {
                "domainMatcher": "hybrid",
                "domainStrategy": "IPIfNonMatch",
                "rules": [
                    {"type": "field", "domain": RU_DOMAINS, "outboundTag": "direct"},
                    {
                        "type": "field",
                        "ip": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.1", "::1"],
                        "outboundTag": "direct",
                    },
                    {"type": "field", "protocol": ["bittorrent"], "outboundTag": "direct"},
                    {"type": "field", "inboundTag": ["socks", "http"], "balancerTag": "BALANCER"},
                ],
                "balancers": [{
                    "tag": "BALANCER",
                    "selector": ["lte-"],
                    "strategy": {"type": "leastPing"},
                }],
            },
            "inbounds": [
                {
                    "tag": "socks",
                    "port": 10808,
                    "listen": "127.0.0.1",
                    "protocol": "socks",
                    "settings": {"udp": True, "auth": "noauth"},
                    "sniffing": {"enabled": True, "routeOnly": False, "destOverride": ["http", "tls", "quic"]},
                },
                {
                    "tag": "http",
                    "port": 10809,
                    "listen": "127.0.0.1",
                    "protocol": "http",
                    "settings": {"allowTransparent": False},
                    "sniffing": {"enabled": True, "routeOnly": False, "destOverride": ["http", "tls", "quic"]},
                },
            ],
            "outbounds": outbounds,
        }
        packs.append(pack)

    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(packs, f, ensure_ascii=False, indent=2)


# =============================================================================
# CLI
# =============================================================================
def main():
    parser = argparse.ArgumentParser(description="VLESS fetcher & packer + health-check")
    parser.add_argument("--batch", type=int, default=None, help="Только один батч (1–6)")
    parser.add_argument("--white-sni", type=str, default="scripts/sni.txt")
    parser.add_argument("--vlees", type=str, default="vlees.txt")
    parser.add_argument("--packs", type=str, default="packs.json")
    parser.add_argument("--probe", action="store_true", default=True, help="TCP/TLS health-check (def: True)")
    parser.add_argument("--no-probe", action="store_true", help="Отключить health-check")
    parser.add_argument("--probe-timeout", type=float, default=5.0, help="Таймаут probe, сек")
    parser.add_argument("--probe-workers", type=int, default=100, help="Потоков для probe")
    parser.add_argument(
        "--ip-prefixes",
        type=str,
        default="158,89,84",
        help="Разрешённые первые октеты IP через запятую (по умолчанию: 158,89,84). "
             "Пустая строка — отключить фильтр.",
    )
    args = parser.parse_args()

    do_probe = args.probe and not args.no_probe

    # Парсим префиксы — без global, просто локальная переменная
    if args.ip_prefixes.strip():
        try:
            allowed_prefixes = tuple(int(x.strip()) for x in args.ip_prefixes.split(",") if x.strip())
        except ValueError:
            print("[ERROR] --ip-prefixes должен содержать числа через запятую, например: 158,89,84", file=sys.stderr)
            sys.exit(1)
    else:
        allowed_prefixes = ()

    if allowed_prefixes:
        print(f"🔒 Фильтр IP-префиксов активен: {list(allowed_prefixes)}")
    else:
        print("⚠️  Фильтр IP-префиксов отключён (пропускаются все IP)")

    white_sni = load_white_sni(args.white_sni)
    print(f"Загружено разрешённых SNI/доменов: {len(white_sni)}")

    all_configs = []
    batches = [args.batch] if args.batch else range(1, 7)

    tasks = []
    for batch in batches:
        for url, prefix in SOURCES.get(batch, []):
            tasks.append((url, prefix))

    with ThreadPoolExecutor(max_workers=16) as ex:
        future_to_src = {
            ex.submit(process_source, url, pfx, white_sni, allowed_prefixes): (url, pfx)
            for url, pfx in tasks
        }
        for future in as_completed(future_to_src):
            url, prefix = future_to_src[future]
            try:
                cfgs = future.result()
            except Exception as e:
                print(f"[{prefix}] Крит ошибка {url}: {e}", file=sys.stderr)
                continue
            print(f"[{prefix}] {url.split('/')[-1][:40]:<<40} → {len(cfgs):>3} конфигов")
            all_configs.extend(cfgs)

    print(f"\nВсего до дедупликации: {len(all_configs)}")

    seen = set()
    unique = []
    for cfg in all_configs:
        params = parse_query(cfg["query"])
        key = f"{cfg['host']}:{cfg['port']}:{cfg['uuid']}:{params.get('pbk', '')}:{cfg.get('sni', '')}"
        if key not in seen:
            seen.add(key)
            unique.append(cfg)

    print(f"Всего уникальных: {len(unique)}")

    if do_probe:
        print(f"\n🔍 TCP/TLS health-check {len(unique)} серверов (workers={args.probe_workers}, timeout={args.probe_timeout}s)...")
        unique = filter_alive(unique, max_workers=args.probe_workers, timeout=args.probe_timeout)
        print(f"✅ Живых после probe: {len(unique)}")

    generate_vlees(unique, args.vlees)
    generate_packs(unique, args.packs)

    try:
        with open(args.packs, "r", encoding="utf-8") as f:
            packs = json.load(f)
        server_count = sum(
            1 for p in packs for o in p.get("outbounds", [])
            if o.get("tag", "").startswith("lte-")
        )
        print(f"\n✅ packs.json валидный | {len(packs)} паков | {server_count} серверов")
    except Exception as e:
        print(f"\n❌ Ошибка валидации packs.json: {e}")
        sys.exit(1)

    print("✅ Готово.")


if __name__ == "__main__":
    main()
