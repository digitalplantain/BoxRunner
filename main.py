import base64
import json
import os
import re
import socket
import subprocess
import tempfile
import time
import urllib.parse
import argparse
import requests
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm

# ================= 1. ИСТОЧНИКИ ПРОКСИ (SCRAPER CONFIG) =================

PLAINTEXT_URLS = [
    "https://raw.githubusercontent.com/Mosifree/-FREE2CONFIG/refs/heads/main/T,H",
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/refs/heads/master/sub/sub_merge.txt",
    "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/MrMohebi/xray-proxy-grabber-telegram/refs/heads/master/collected-proxies/row-url/all.txt",
    "https://raw.githubusercontent.com/itsyebekhe/PSG/refs/heads/main/config.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Config/refs/heads/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Sub1.txt",
    "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list_raw.txt",
    "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/v2ray.txt",
    "https://raw.githubusercontent.com/theGreatPeter/v2rayNodes/main/nodes.txt",
    "https://raw.githubusercontent.com/Mahdi0024/ProxyCollector/master/sub/proxies.txt",
    "https://raw.githubusercontent.com/Barabama/FreeNodes/master/nodes/merged.txt",
    "https://raw.githubusercontent.com/coldwater-10/V2Hub2/main/merged",
    "https://raw.githubusercontent.com/Proxydaemitelegram/Proxydaemi44/refs/heads/main/Proxydaemi44",
    "https://raw.githubusercontent.com/ndsphonemy/proxy-sub/refs/heads/main/speed.txt",
    "https://raw.githubusercontent.com/Mosifree/-FREE2CONFIG/refs/heads/main/Movaghat",
    "https://raw.githubusercontent.com/tkamirparsa/Javid-shah/refs/heads/main/Sub.text",
    "https://raw.githubusercontent.com/awesome-vpn/awesome-vpn/master/all",
    "https://raw.githubusercontent.com/mahdibland/ShadowsocksAggregator/master/sub/sub_merge.txt",
    "https://raw.githubusercontent.com/Surfboardv2ray/v2ray-worker-sub/refs/heads/master/providers/providers",
    "https://raw.githubusercontent.com/NiREvil/vless/refs/heads/main/sub/v2rayng-wg.txt",
    "https://raw.githubusercontent.com/NiREvil/vless/refs/heads/main/sub/SSTime",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_RAW.txt",
    "https://raw.githubusercontent.com/Kwinshadow/TelegramV2rayCollector/refs/heads/main/sublinks/mix.txt",
    "https://raw.githubusercontent.com/LalatinaHub/Mineral/refs/heads/master/result/nodes",
    "https://raw.githubusercontent.com/MhdiTaheri/V2rayCollector_Py/refs/heads/main/sub/Mix/mix.txt",
    "https://raw.githubusercontent.com/MhdiTaheri/V2rayCollector/refs/heads/main/sub/mix",
    "https://raw.githubusercontent.com/mehran1404/Sub_Link/refs/heads/main/V2RAY-Sub.txt",
    "https://raw.githubusercontent.com/shabane/kamaji/master/hub/merged.txt",
    "https://raw.githubusercontent.com/wuqb2i4f/xray-config-toolkit/main/output/base64/mix-uri",
    "https://raw.githubusercontent.com/Rayan-Config/C-Sub/refs/heads/main/configs/proxy.txt",
    "https://raw.githubusercontent.com/sinabigo/Xray/main/@sinavm",
    "https://raw.githubusercontent.com/MahsaNetConfigTopic/config/refs/heads/main/xray_final.txt",
    "https://raw.githubusercontent.com/darkvpnapp/CloudflarePlus/refs/heads/main/proxy",
    "https://raw.githubusercontent.com/sakha1370/OpenRay/refs/heads/main/output/all_valid_proxies.txt",
    "https://raw.githubusercontent.com/sevcator/5ubscrpt10n/main/protocols/vl.txt",
    "https://raw.githubusercontent.com/yitong2333/proxy-minging/refs/heads/main/v2ray.txt",
    "https://raw.githubusercontent.com/miladtahanian/V2RayCFGDumper/refs/heads/main/config.txt",
    "https://raw.githubusercontent.com/miladtahanian/multi-proxy-config-fetcher/refs/heads/main/configs/proxy_configs.txt",
    "https://raw.githubusercontent.com/YasserDivaR/pr0xy/refs/heads/main/ShadowSocks2021.txt",
    "https://raw.githubusercontent.com/mohamadfg-dev/telegram-v2ray-configs-collector/refs/heads/main/category/vless.txt",
    "https://raw.githubusercontent.com/youfoundamin/V2rayCollector/main/mixed_iran.txt",
    "https://github.com/Argh94/Proxy-List/raw/refs/heads/main/All_Config.txt",
    "https://raw.githubusercontent.com/STR97/STRUGOV/refs/heads/main/STR.BYPASS",
    "https://raw.githubusercontent.com/V2RayRoot/V2RayConfig/refs/heads/main/Config/vless.txt",
    "https://github.com/AvenCores/goida-vpn-configs/raw/refs/heads/main/githubmirror/26.txt",
    "https://v2.alicivil.workers.dev/",
    "https://robin.nscl.ir",
    "https://vpn.fail/free-proxy/v2ray",
    "https://weoknow.com/data/dayupdate/1/z.txt",
    "https://igdux.top/~FREE2CONFIG,T,H",
    "https://istanbulsydneyhotel.com/blogs/site/sni.php",
    "https://hideshots.eu/sub.txt",
    "https://raw.githubusercontent.com/10ium/ScrapeAndCategorize/refs/heads/main/output_configs/Vmess.txt",
    "https://raw.githubusercontent.com/10ium/ScrapeAndCategorize/refs/heads/main/output_configs/Vless.txt",
    "https://raw.githubusercontent.com/10ium/ScrapeAndCategorize/refs/heads/main/output_configs/Tuic.txt",
    "https://raw.githubusercontent.com/10ium/ScrapeAndCategorize/refs/heads/main/output_configs/Trojan.txt",
    "https://raw.githubusercontent.com/10ium/ScrapeAndCategorize/refs/heads/main/output_configs/ShadowSocksR.txt",
    "https://raw.githubusercontent.com/10ium/ScrapeAndCategorize/refs/heads/main/output_configs/ShadowSocks.txt"
]

BASE64_URLS = [
    "https://raw.githubusercontent.com/mahsanet/MahsaFreeConfig/main/mci/sub_1.txt",
    "https://raw.githubusercontent.com/mahsanet/MahsaFreeConfig/refs/heads/main/mtn/sub_1.txt",
    "https://raw.githubusercontent.com/AzadNetCH/Clash/main/AzadNet.txt",
    "https://raw.githubusercontent.com/mfuu/v2ray/master/v2ray",
    "https://raw.githubusercontent.com/aiboboxx/v2rayfree/main/v2",
    "https://raw.githubusercontent.com/freefq/free/master/v2",
    "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub",
    "https://raw.githubusercontent.com/ripaojiedian/freenode/main/sub",
    "https://raw.githubusercontent.com/yebekhe/vpn-fail/refs/heads/main/sub-link",
    "https://raw.githubusercontent.com/w1770946466/Auto_proxy/main/Long_term_subscription_num",
    "https://raw.githubusercontent.com/Leon406/SubCrawler/refs/heads/main/sub/share/vless",
    "https://raw.githubusercontent.com/Leon406/SubCrawler/refs/heads/main/sub/share/hysteria2",
    "https://raw.githubusercontent.com/Leon406/SubCrawler/refs/heads/main/sub/share/a11",
    "https://raw.githubusercontent.com/acymz/AutoVPN/refs/heads/main/data/V2.txt",
    "https://raw.githubusercontent.com/mheidari98/.proxy/refs/heads/main/all",
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/Eternity",
    "https://shadowmere.xyz/api/b64sub/",
    "https://www.xrayvip.com/free.txt",
    "https://a.nodeshare.xyz/uploads/2025/7/20250712.txt",
    "https://v2rayshare.githubrowcontent.com/2025/07/20250712.txt",
    "https://a.nodeshare.xyz/uploads/2025/7/20250712.txt",
    "https://oneclash.githubrowcontent.com/2025/07/20250712.txt",
    "https://raw.githubusercontent.com/awesome-vpn/awesome-vpn/master/all",
    "https://trojanvmess.pages.dev/cmcm?b64",
    "https://shadowmere.xyz/api/b64sub/",
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/All_Configs_base64_Sub.txt"
]

# ================= 2. НАСТРОЙКИ ЧЕКЕРА =================

# Windows: "sing-box.exe", Linux: "./sing-box"
SING_BOX_PATH = "sing-box.exe"  

MAX_WORKERS = 50       
TIMEOUT = 10           
API_RETRIES = 3        
API_RETRY_DELAY = 1.5  

GIST_ID = os.environ.get("GIST_ID")
GIST_TOKEN = os.environ.get("GIST_TOKEN")
GIST_FILENAME = "working_proxies.txt"

# === НОВЫЙ API ===
IP_API_URL = "http://ipinfo.io/json"
TEST_URL = "http://www.gstatic.com/generate_204"

BANNED_ISP_REGEX = r"(?i)(hetzner|cloudflare|pq hosting)"

GEMINI_ALLOWED_COUNTRY_CODES = {
    'AL', 'DZ', 'AS', 'AO', 'AI', 'AQ', 'AG', 'AR', 'AM', 'AW', 'AU', 'AT', 'AZ', 'BS', 'BH', 'BD', 'BB', 'BE', 'BZ', 'BJ', 'BM', 'BT', 'BO', 'BA', 'BW', 'BR', 'IO', 'VG', 'BN', 'BG', 'BF', 'BI', 'CV', 'KH', 'CM', 'CA', 'BQ', 'KY', 'CF', 'TD', 'CL', 'CX', 'CC', 'CO', 'KM', 'CK', 'CI', 'CR', 'HR', 'CW', 'CZ', 'CD', 'DK', 'DJ', 'DM', 'DO', 'EC', 'EG', 'SV', 'GQ', 'ER', 'EE', 'SZ', 'ET', 'FK', 'FO', 'FJ', 'FI', 'FR', 'GA', 'GM', 'GE', 'DE', 'GH', 'GI', 'GR', 'GL', 'GD', 'GU', 'GT', 'GG', 'GN', 'GW', 'GY', 'HT', 'HM', 'HN', 'HU', 'IS', 'IN', 'ID', 'IQ', 'IE', 'IM', 'IL', 'IT', 'JM', 'JP', 'JE', 'JO', 'KZ', 'KE', 'KI', 'XK', 'KG', 'KW', 'LA', 'LV', 'LB', 'LS', 'LR', 'LY', 'LI', 'LT', 'LU', 'MG', 'MW', 'MY', 'MV', 'ML', 'MT', 'MH', 'MR', 'MU', 'MX', 'FM', 'MN', 'ME', 'MS', 'MA', 'MZ', 'NA', 'NR', 'NP', 'NL', 'NC', 'NZ', 'NI', 'NE', 'NG', 'NU', 'NF', 'MK', 'MP', 'NO', 'OM', 'PK', 'PW', 'PS', 'PA', 'PG', 'PY', 'PE', 'PH', 'PN', 'PL', 'PT', 'PR', 'QA', 'CY', 'CG', 'RO', 'RW', 'BL', 'KN', 'LC', 'PM', 'VC', 'SH', 'WS', 'ST', 'SA', 'SN', 'RS', 'SC', 'SL', 'SG', 'SK', 'SI', 'SB', 'SO', 'ZA', 'GS', 'KR', 'SS', 'ES', 'LK', 'SD', 'SR', 'SE', 'CH', 'TW', 'TJ', 'TZ', 'TH', 'TL', 'TG', 'TK', 'TO', 'TT', 'TN', 'TR', 'TM', 'TC', 'TV', 'UG', 'UA', 'GB', 'AE', 'US', 'UM', 'VI', 'UY', 'UZ', 'VU', 'VE', 'VN', 'WF', 'EH', 'YE', 'ZM', 'ZW'
}

YT_MUSIC_ALLOWED_COUNTRY_CODES = {
    'DZ', 'AS', 'AR', 'AW', 'AU', 'AT', 'AZ', 'BH', 'BD', 'BY', 'BE', 'BM', 'BO', 'BA', 'BR', 'BG', 'KH', 'CA', 'KY', 'CL', 'CO', 'CR', 'HR', 'CY', 'CZ', 'DK', 'DO', 'EC', 'EG', 'SV', 'EE', 'FI', 'FR', 'GF', 'PF', 'GE', 'DE', 'GH', 'GR', 'GP', 'GU', 'GT', 'HN', 'HK', 'HU', 'IS', 'IN', 'ID', 'IQ', 'IE', 'IL', 'IT', 'JM', 'JP', 'JO', 'KZ', 'KE', 'KW', 'LA', 'LV', 'LB', 'LY', 'LI', 'LT', 'LU', 'MY', 'MT', 'MX', 'MA', 'NP', 'NL', 'NZ', 'NI', 'NG', 'MK', 'MP', 'NO', 'OM', 'PK', 'PA', 'PG', 'PY', 'PE', 'PH', 'PL', 'PT', 'PR', 'QA', 'RE', 'RO', 'RU', 'SA', 'SN', 'RS', 'SG', 'SK', 'SI', 'ZA', 'KR', 'ES', 'LK', 'SE', 'CH', 'TW', 'TZ', 'TH', 'TN', 'TR', 'TC', 'VI', 'UG', 'UA', 'AE', 'GB', 'US', 'UY', 'VE', 'VN', 'YE', 'ZW'
}

VALID_PROTOCOLS = ('vmess://', 'vless://', 'ss://', 'trojan://', 'ssr://', 'hysteria://', 'hy2://', 'hysteria2://', 'wireguard://')
seen_proxies = set()

# ================= 3. ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ =================

def safe_base64_decode(s):
    if not s: return b""
    s = s.strip().replace('\n', '').replace('\r', '')
    missing_padding = len(s) % 4
    if missing_padding: s += '=' * (4 - missing_padding)
    try: return base64.urlsafe_b64decode(s)
    except:
        try: return base64.b64decode(s)
        except: return b""

def get_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("", 0))
        return s.getsockname()[1]

def country_flag(code):
    if not code or len(code) != 2: return "🏁"
    return "".join(chr(0x1F1E6 + ord(char.upper()) - ord('A')) for char in code)

# ================= 4. ЛОГИКА СБОРКИ (SCRAPING) =================

def fetch_content(url, url_type):
    try:
        response = requests.get(url, timeout=15)
        response.raise_for_status()
        return response.text, url_type
    except requests.RequestException:
        return None, url_type

def process_content(content, url_type):
    links = []
    if not content: return []
    
    if url_type == 'plaintext':
        content = content.replace('<br/>', '\n').replace('<br>', '\n')
        links = content.splitlines()
    elif url_type == 'base64':
        try:
            decoded = safe_base64_decode(content).decode('utf-8', errors='ignore')
            decoded = decoded.replace('<br/>', '\n').replace('<br>', '\n')
            links = decoded.splitlines()
        except:
            pass
    
    valid_links = []
    for link in links:
        link = link.strip()
        if link and link.startswith(VALID_PROTOCOLS):
            valid_links.append(link)
    return valid_links

def scrape_all_proxies():
    print(f"Starting scraper for {len(PLAINTEXT_URLS) + len(BASE64_URLS)} sources...")
    all_proxies = set()
    
    tasks = [(url, 'plaintext') for url in PLAINTEXT_URLS] + [(url, 'base64') for url in BASE64_URLS]
    
    with ThreadPoolExecutor(max_workers=20) as executor:
        future_to_url = {executor.submit(fetch_content, url, url_type): (url, url_type) for url, url_type in tasks}
        
        for future in tqdm(as_completed(future_to_url), total=len(tasks), desc="Scraping Sources"):
            content, url_type = future.result()
            links = process_content(content, url_type)
            all_proxies.update(links)
            
    print(f"Scraping finished. Found {len(all_proxies)} unique valid proxies.")
    return list(all_proxies)

# ================= 5. ПАРСЕРЫ ПРОТОКОЛОВ =================

def parse_vmess(link):
    try:
        b64 = link[8:]
        conf = json.loads(safe_base64_decode(b64).decode('utf-8', errors='ignore'))
        return {
            'type': 'vmess', 'name': conf.get('ps', 'vmess'), 'server': conf.get('add'), 'port': int(conf.get('port')),
            'uuid': conf.get('id'), 'alterId': int(conf.get('aid', 0)), 'security': conf.get('scy', 'auto'),
            'network': conf.get('net', 'tcp'), 'tls': conf.get('tls', ''), 'sni': conf.get('sni', '') or conf.get('host', ''),
            'path': conf.get('path', ''), 'host': conf.get('host', ''), 'fp': conf.get('fp', ''),
            'serviceName': conf.get('serviceName', ''), 'original_conf': conf
        }
    except: return None

def parse_vless_trojan(link, protocol):
    try:
        parsed = urllib.parse.urlparse(link)
        params = urllib.parse.parse_qs(parsed.query)
        data = {
            'type': protocol, 'server': parsed.hostname, 'port': parsed.port, 'uuid': parsed.username, 'password': parsed.username,
            'name': urllib.parse.unquote(parsed.fragment), 'network': params.get('type', ['tcp'])[0],
            'security': params.get('security', [''])[0], 'sni': params.get('sni', [''])[0],
            'pbk': params.get('pbk', [''])[0], 'sid': params.get('sid', [''])[0], 'fp': params.get('fp', [''])[0],
            'path': params.get('path', [''])[0], 'host': params.get('host', [''])[0], 'serviceName': params.get('serviceName', [''])[0],
            'flow': params.get('flow', [''])[0]
        }
        if not data['server'] or not data['port']: return None
        return data
    except: return None

def parse_ss(link): return {'type': 'shadowsocks', 'name': 'SS'}
def parse_ssr(link): return {'type': 'shadowsocksr', 'name': 'SSR'} 

def parse_tuic(link):
    try:
        parsed = urllib.parse.urlparse(link)
        params = urllib.parse.parse_qs(parsed.query)
        return {
            'type': 'tuic', 'server': parsed.hostname, 'port': parsed.port, 'uuid': parsed.username, 'password': parsed.password,
            'congestion_control': params.get('congestion_control', ['bbr'])[0], 'sni': params.get('sni', [''])[0],
            'alpn': params.get('alpn', ['h3'])[0], 'allow_insecure': params.get('allow_insecure', ['0'])[0] == '1',
            'name': urllib.parse.unquote(parsed.fragment)
        }
    except: return None

def parse_hysteria2(link):
    try:
        parsed = urllib.parse.urlparse(link)
        params = urllib.parse.parse_qs(parsed.query)
        return {
            'type': 'hysteria2', 'server': parsed.hostname, 'port': parsed.port, 'password': parsed.username or '',
            'sni': params.get('sni', [''])[0], 'insecure': params.get('insecure', ['0'])[0] == '1',
            'obfs': params.get('obfs', [''])[0], 'obfs_password': params.get('obfs-password', [''])[0],
            'name': urllib.parse.unquote(parsed.fragment)
        }
    except: return None

def parse_wireguard(link):
    try:
        parsed = urllib.parse.urlparse(link)
        params = urllib.parse.parse_qs(parsed.query)
        return {
            'type': 'wireguard', 'server': parsed.hostname, 'port': parsed.port, 'private_key': parsed.username,
            'peer_public_key': params.get('public_key', [''])[0], 'ip': params.get('ip', ['10.0.0.2'])[0],
            'name': urllib.parse.unquote(parsed.fragment)
        }
    except: return None

def parse_link(link):
    link = link.strip()
    if not link: return None
    try:
        if link.startswith('vmess://'): return parse_vmess(link)
        if link.startswith('vless://'): return parse_vless_trojan(link, 'vless')
        if link.startswith('trojan://'): return parse_vless_trojan(link, 'trojan')
        if link.startswith('ss://'): return parse_ss(link)
        if link.startswith('ssr://'): return parse_ssr(link)
        if link.startswith('tuic://'): return parse_tuic(link)
        if link.startswith('hysteria2://') or link.startswith('hy2://'): return parse_hysteria2(link)
        if link.startswith('wireguard://'): return parse_wireguard(link)
    except: return None
    return None

# ================= 6. ГЕНЕРАТОР КОНФИГА SING-BOX =================

def generate_singbox_config(data, local_port):
    config = {
        "log": {"disabled": True},
        "inbounds": [{"type": "mixed","tag": "in","listen": "127.0.0.1","listen_port": local_port,"set_system_proxy": False}],
        "outbounds": []
    }
    outbound = {"tag": "proxy", "type": data['type']}

    if data['type'] == 'vmess':
        outbound.update({
            "server": data['server'], "server_port": data['port'], "uuid": data['uuid'], "security": data['security'],
            "alter_id": data['alterId'], "transport": {}
        })
        if data['network'] == 'ws': outbound['transport'] = {'type': 'ws', 'path': data.get('path', '/'), 'headers': {'Host': data.get('host', '') or data.get('sni', '')}}
        elif data['network'] == 'grpc': outbound['transport'] = {'type': 'grpc', 'service_name': data.get('serviceName', '') or data.get('path', '')}
        if data.get('tls') == 'tls': outbound['tls'] = {"enabled": True, "server_name": data.get('sni', ''), "insecure": True}

    elif data['type'] == 'vless':
        outbound.update({ "server": data['server'], "server_port": data['port'], "uuid": data['uuid'], "flow": data.get('flow', ''), "tls": {"enabled": False}, "transport": {} })
        security = data.get('security', '')
        if security in ['tls', 'reality']:
            tls_conf = {"enabled": True, "server_name": data.get('sni', ''), "insecure": True}
            if data.get('fp'): tls_conf['utls'] = {"enabled": True, "fingerprint": data['fp']}
            if security == 'reality': tls_conf['reality'] = {"enabled": True, "public_key": data.get('pbk', ''), "short_id": data.get('sid', '')}
            outbound['tls'] = tls_conf
        if data['network'] == 'ws': outbound['transport'] = {'type': 'ws', 'path': data.get('path', '/'), 'headers': {'Host': data.get('host', '')}}
        elif data['network'] == 'grpc': outbound['transport'] = {'type': 'grpc', 'service_name': data.get('serviceName', '')}

    elif data['type'] == 'trojan':
        outbound.update({ "server": data['server'], "server_port": data['port'], "password": data['password'], "tls": {"enabled": True, "server_name": data.get('sni', ''), "insecure": True} })
        if data.get('network') == 'ws': outbound['transport'] = {'type': 'ws', 'path': data.get('path', '/')}
        elif data.get('network') == 'grpc': outbound['transport'] = {'type': 'grpc', 'service_name': data.get('serviceName', '')}

    elif data['type'] == 'tuic':
        outbound.update({ "server": data['server'], "server_port": data['port'], "uuid": data['uuid'], "password": data['password'], "congestion_control": data.get('congestion_control', 'bbr'),
            "tls": {"enabled": True, "server_name": data.get('sni', ''), "alpn": [data.get('alpn', 'h3')], "insecure": data.get('allow_insecure', True)} })
    elif data['type'] == 'hysteria2':
        outbound.update({ "server": data['server'], "server_port": data['port'], "password": data['password'], "tls": {"enabled": True, "server_name": data.get('sni', ''), "insecure": data.get('insecure', True)} })
        if data.get('obfs'): outbound['obfs'] = {"type": data['obfs'], "password": data.get('obfs_password', '')}
    elif data['type'] == 'wireguard':
        outbound.update({ "server": data['server'], "server_port": data['port'], "local_address": [data.get('ip', '10.0.0.2') + "/32"], "private_key": data['private_key'], "peer_public_key": data['peer_public_key'] })
    
    elif data['type'] in ['shadowsocks', 'shadowsocksr']:
        return None

    config['outbounds'].append(outbound)
    return json.dumps(config)

# ================= 7. ПЕРЕСБОРКА ССЫЛКИ (REBUILD) =================

def rebuild_link(original_link, data, new_name):
    try:
        if data['type'] == 'vmess':
            conf = data.get('original_conf', {})
            conf['ps'] = new_name
            new_b64 = base64.b64encode(json.dumps(conf).encode('utf-8')).decode('utf-8')
            return f"vmess://{new_b64}"
        else:
            parsed = urllib.parse.urlparse(original_link)
            query = urllib.parse.parse_qs(parsed.query)
            for key in ['note', 'alias', 'remarks', 'des']:
                if key in query: del query[key]
            new_query = urllib.parse.urlencode(query, doseq=True)
            new_link = parsed._replace(query=new_query, fragment=urllib.parse.quote(new_name)).geturl()
            return new_link
    except:
        base = original_link.split('#')[0]
        return f"{base}#{urllib.parse.quote(new_name)}"

# ================= 8. ЛОГИКА ПРОВЕРКИ (CHECKER) =================

def check_proxy(link):
    proc = None
    config_file = None
    try:
        data = parse_link(link)
        if not data: return None
        
        if data['type'] in ['shadowsocks', 'shadowsocksr']:
            return None 

        identifier = f"{data.get('server')}:{data.get('port')}"
        if identifier in seen_proxies: return None
        seen_proxies.add(identifier)

        local_port = get_free_port()
        config_content = generate_singbox_config(data, local_port)
        if not config_content: return None

        config_file = tempfile.NamedTemporaryFile(mode='w+', suffix='.json', delete=False)
        config_file.write(config_content)
        config_file.close()

        proc = subprocess.Popen([SING_BOX_PATH, "run", "-c", config_file.name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1)
        if proc.poll() is not None: return None

        proxies = {'http': f'socks5://127.0.0.1:{local_port}', 'https': f'socks5://127.0.0.1:{local_port}'}
        
        # 3. Пинг
        start_time = time.time()
        try:
            requests.get(TEST_URL, proxies=proxies, timeout=TIMEOUT)
            ping = int((time.time() - start_time) * 1000)
        except:
            return None 

        # 4. API (ipinfo.io)
        api_data = {}
        for attempt in range(API_RETRIES):
            try:
                r = requests.get(IP_API_URL, proxies=proxies, timeout=TIMEOUT)
                if r.status_code == 200:
                    # ipinfo всегда возвращает 200 и JSON
                    api_data = r.json()
                    if 'ip' in api_data: # Проверка, что JSON валидный
                        break
            except: pass
            time.sleep(API_RETRY_DELAY)

        # 5. Фильтрация Unknown / Banned ISP (для ipinfo поля другие)
        cc = api_data.get('country', 'NA')  # ipinfo использует 'country'
        city = api_data.get('city', 'Unknown')
        isp = api_data.get('org', 'Unknown ISP') # ipinfo использует 'org' (ASxxxx Name)

        if not cc or cc == 'NA' or city == 'Unknown' or isp == 'Unknown ISP':
            return None

        # Убираем AS номер для красоты (AS12345 Google -> Google)
        isp_clean = re.sub(r'^AS\d+\s+', '', isp)

        if re.search(BANNED_ISP_REGEX, isp_clean):
            return None 

        # 6. Ренейминг
        flag = country_flag(cc)
        gemini_ok = cc in GEMINI_ALLOWED_COUNTRY_CODES
        yt_music_ok = cc in YT_MUSIC_ALLOWED_COUNTRY_CODES
        
        gemini_icon = '✅' if gemini_ok else '❌'
        yt_icon = '✅' if yt_music_ok else '❌'

        clean_name = f"{ping}ms {flag} {cc} - {city} ◈ {isp_clean} | 🎵YT_Music{yt_icon} ✨Gemini{gemini_icon}"
        
        # 7. Пересборка
        final_link = rebuild_link(link, data, clean_name)
        
        return (ping, final_link)

    except Exception:
        return None
    finally:
        if proc:
            proc.terminate()
            try: proc.wait(timeout=1)
            except: proc.kill()
        if config_file and os.path.exists(config_file.name):
            try: os.remove(config_file.name)
            except: pass

def update_gist(content):
    if not GIST_ID or not GIST_TOKEN: return
    headers = {'Authorization': f'token {GIST_TOKEN}', 'Accept': 'application/vnd.github.v3+json'}
    payload = {'files': {GIST_FILENAME: {'content': content}}, 'description': f'Updated: {time.strftime("%Y-%m-%d %H:%M:%S UTC")}'}
    try:
        requests.patch(f'https://api.github.com/gists/{GIST_ID}', headers=headers, json=payload).raise_for_status()
        print("Gist updated successfully.")
    except Exception as e:
        print(f"Failed to update Gist: {e}")

# ================= 9. MAIN =================

def main():
    print("Cleaning up old processes...")
    if os.name == 'nt':
        os.system('taskkill /F /IM sing-box.exe >nul 2>&1')
    else:
        os.system('pkill -9 sing-box >/dev/null 2>&1')

    if not os.path.exists(SING_BOX_PATH):
        print(f"ERROR: Sing-box executable not found at: {SING_BOX_PATH}")
        sys.exit(1)

    # 1. Сборка ссылок из всех источников
    links = scrape_all_proxies()
    
    # 2. Проверка
    working_proxies = []
    seen_proxies.clear()
    
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(check_proxy, link): link for link in links}
        for future in tqdm(as_completed(futures), total=len(links), desc="Checking & Renaming"):
            try:
                res = future.result()
                if res: working_proxies.append(res)
            except: pass

    print(f"\nWorking proxies found: {len(working_proxies)}")
    
    if working_proxies:
        working_proxies.sort(key=lambda x: x[0])
        final_content = "\n".join([x[1] for x in working_proxies])
        
        with open(GIST_FILENAME, 'w', encoding='utf-8') as f:
            f.write(final_content)
        print(f"Result saved to {GIST_FILENAME}")
        
        update_gist(final_content)
    else:
        print("No working proxies found.")

if __name__ == "__main__":
    main()
