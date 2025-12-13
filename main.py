import base64
import json
import os
import re
import socket
import subprocess
import tempfile
import time
import urllib.parse
import sys
import hashlib
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm

# ================= 1. ИСТОЧНИКИ ПРОКСИ (SCRAPER CONFIG) =================

# --- ВЗЯТО ИЗ ВАШЕГО ИСХОДНОГО КОДА ---
PLAINTEXT_URLS = [
    "https://raw.githubusercontent.com/Mosifree/-FREE2CONFIG/refs/heads/main/T,H",
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/refs/heads/master/sub/sub_merge.txt",
    "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/MrMohebi/xray-proxy-grabber-telegram/refs/heads/master/collected-proxies/row-url/all.txt",
    "https://raw.githubusercontent.com/MrMohebi/xray-proxy-grabber-telegram/master/collected-proxies/row-url/actives.txt",
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
    "https://raw.githubusercontent.com/liketolivefree/kobabi/refs/heads/main/sub.txt",
    "https://raw.githubusercontent.com/F0rc3Run/F0rc3Run/main/Special/Telegram.txt",
    "https://raw.githubusercontent.com/F0rc3Run/F0rc3Run/refs/heads/main/Best-Results/proxies.txt",
    "https://raw.githubusercontent.com/Ashkan-m/v2ray/main/Sub.txt",
    "https://raw.githubusercontent.com/Everyday-VPN/Everyday-VPN/main/subscription/main.txt",
    "https://raw.githubusercontent.com/Everyday-VPN/Everyday-VPN/main/subscription/test.txt",
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
    "https://raw.githubusercontent.com/10ium/ScrapeAndCategorize/refs/heads/main/output_configs/ShadowSocks.txt",
    "https://raw.githubusercontent.com/Firmfox/Proxify/refs/heads/main/v2ray_configs/seperated_by_protocol/other.txt",
    "https://raw.githubusercontent.com/Firmfox/Proxify/refs/heads/main/v2ray_configs/seperated_by_protocol/shadowsocks.txt",
    "https://raw.githubusercontent.com/Firmfox/Proxify/refs/heads/main/v2ray_configs/seperated_by_protocol/trojan.txt",
    "https://raw.githubusercontent.com/Firmfox/Proxify/refs/heads/main/v2ray_configs/seperated_by_protocol/vless.txt",
    "https://raw.githubusercontent.com/Firmfox/Proxify/refs/heads/main/v2ray_configs/seperated_by_protocol/vmess.txt",
    "https://raw.githubusercontent.com/Firmfox/Proxify/refs/heads/main/v2ray_configs/seperated_by_protocol/warp.txt"
]

BASE64_URLS = [
    "https://raw.githubusercontent.com/mahsanet/MahsaFreeConfig/main/mci/sub_1.txt",
    "https://raw.githubusercontent.com/ALIILAPRO/v2rayNG-Config/main/sub.txt",
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
    "https://raw.githubusercontent.com/ssrsub/ssr/master/v2ray",
    "https://raw.githubusercontent.com/MrPooyaX/VpnsFucking/main/BeVpn.txt",
    "https://shadowmere.xyz/api/b64sub/",
    "https://www.xrayvip.com/free.txt",
    "https://raw.githubusercontent.com/ts-sf/fly/main/v2",
    "https://a.nodeshare.xyz/uploads/2025/7/20250712.txt",
    "https://v2rayshare.githubrowcontent.com/2025/07/20250712.txt",
    "https://a.nodeshare.xyz/uploads/2025/7/20250712.txt",
    "https://oneclash.githubrowcontent.com/2025/07/20250712.txt",
    "https://raw.githubusercontent.com/awesome-vpn/awesome-vpn/master/all",
    "https://trojanvmess.pages.dev/cmcm?b64",
    "https://shadowmere.xyz/api/b64sub/",
    "https://raw.githubusercontent.com/Surfboardv2ray/TGParse/main/python/hy2",
    "https://raw.githubusercontent.com/Surfboardv2ray/TGParse/main/python/hysteria2",
    "https://raw.githubusercontent.com/Surfboardv2ray/TGParse/main/python/hysteria",
    "https://raw.githubusercontent.com/Surfboardv2ray/TGParse/main/splitted/vless",
    "https://raw.githubusercontent.com/Surfboardv2ray/TGParse/main/splitted/vmess",
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/All_Configs_base64_Sub.txt"
]
# --- КОНЕЦ ИСХОДНОГО БЛОКА ССЫЛОК ---


# ================= 2. КОНФИГУРАЦИЯ И КОНСТАНТЫ =================
SING_BOX_PATH = "./sing-box"  # Путь для Linux (GitHub Actions)
MAX_WORKERS = 200       
TIMEOUT = 10           
API_RETRIES = 2
API_RETRY_DELAY = 1

# Secrets
GH_TOKEN = os.environ.get("GH_TOKEN")
GIST_ID = os.environ.get("GIST_ID")
VERCEL_TOKEN = os.environ.get("VERCEL_TOKEN")
PROJ_ID = os.environ.get("PROJ_ID")

GIST_FILENAME = "gistfile1.txt"
PING_FILENAME = "pings.json"
ENV_KEY = "GIST_URL"

IP_API_URL = "http://ipinfo.io/json"
TEST_URL = "http://www.gstatic.com/generate_204"
OPENAI_URL = "https://api.openai.com/v1/models"

BANNED_ISP_REGEX = r"(?i)(hetzner|cloudflare|pq hosting|contabo|digitalocean|amazon|google|microsoft|oracle)"

# Списки стран (для Gemini/YT)
GEMINI_ALLOWED = {'AL', 'DZ', 'AS', 'AO', 'AI', 'AQ', 'AG', 'AR', 'AM', 'AW', 'AU', 'AT', 'AZ', 'BS', 'BH', 'BD', 'BB', 'BE', 'BZ', 'BJ', 'BM', 'BT', 'BO', 'BA', 'BW', 'BR', 'IO', 'VG', 'BN', 'BG', 'BF', 'BI', 'CV', 'KH', 'CM', 'CA', 'BQ', 'KY', 'CF', 'TD', 'CL', 'CX', 'CC', 'CO', 'KM', 'CK', 'CI', 'CR', 'HR', 'CW', 'CZ', 'CD', 'DK', 'DJ', 'DM', 'DO', 'EC', 'EG', 'SV', 'GQ', 'ER', 'EE', 'SZ', 'ET', 'FK', 'FO', 'FJ', 'FI', 'FR', 'GA', 'GM', 'GE', 'DE', 'GH', 'GI', 'GR', 'GL', 'GD', 'GU', 'GT', 'GG', 'GN', 'GW', 'GY', 'HT', 'HM', 'HN', 'HU', 'IS', 'IN', 'ID', 'IQ', 'IE', 'IM', 'IL', 'IT', 'JM', 'JP', 'JE', 'JO', 'KZ', 'KE', 'KI', 'XK', 'KG', 'KW', 'LA', 'LV', 'LB', 'LS', 'LR', 'LY', 'LI', 'LT', 'LU', 'MG', 'MW', 'MY', 'MV', 'ML', 'MT', 'MH', 'MR', 'MU', 'MX', 'FM', 'MN', 'ME', 'MS', 'MA', 'MZ', 'NA', 'NR', 'NP', 'NL', 'NC', 'NZ', 'NI', 'NE', 'NG', 'NU', 'NF', 'MK', 'MP', 'NO', 'OM', 'PK', 'PW', 'PS', 'PA', 'PG', 'PY', 'PE', 'PH', 'PN', 'PL', 'PT', 'PR', 'QA', 'CY', 'CG', 'RO', 'RW', 'BL', 'KN', 'LC', 'PM', 'VC', 'SH', 'WS', 'ST', 'SA', 'SN', 'RS', 'SC', 'SL', 'SG', 'SK', 'SI', 'SB', 'SO', 'ZA', 'GS', 'KR', 'SS', 'ES', 'LK', 'SD', 'SR', 'SE', 'CH', 'TW', 'TJ', 'TZ', 'TH', 'TL', 'TG', 'TK', 'TO', 'TT', 'TN', 'TR', 'TM', 'TC', 'TV', 'UG', 'UA', 'GB', 'AE', 'US', 'UM', 'VI', 'UY', 'UZ', 'VU', 'VE', 'VN', 'WF', 'EH', 'YE', 'ZM', 'ZW'}
YT_MUSIC_ALLOWED = {'DZ', 'AS', 'AR', 'AW', 'AU', 'AT', 'AZ', 'BH', 'BD', 'BY', 'BE', 'BM', 'BO', 'BA', 'BR', 'BG', 'KH', 'CA', 'KY', 'CL', 'CO', 'CR', 'HR', 'CY', 'CZ', 'DK', 'DO', 'EC', 'EG', 'SV', 'EE', 'FI', 'FR', 'GF', 'PF', 'GE', 'DE', 'GH', 'GR', 'GL', 'GD', 'GU', 'GT', 'GG', 'GN', 'GW', 'GY', 'HT', 'HM', 'HN', 'HU', 'IS', 'IN', 'ID', 'IQ', 'IE', 'IL', 'IT', 'JM', 'JP', 'JE', 'JO', 'KZ', 'KE', 'KW', 'LA', 'LV', 'LB', 'LS', 'LR', 'LY', 'LI', 'LT', 'LU', 'MG', 'MW', 'MY', 'MV', 'ML', 'MT', 'MH', 'MR', 'MU', 'MX', 'FM', 'MN', 'ME', 'MS', 'MA', 'MZ', 'NA', 'NR', 'NP', 'NL', 'NC', 'NZ', 'NI', 'NE', 'NG', 'NU', 'NF', 'MK', 'MP', 'NO', 'OM', 'PK', 'PW', 'PS', 'PA', 'PG', 'PY', 'PE', 'PH', 'PL', 'PT', 'PR', 'QA', 'RE', 'RO', 'RU', 'SA', 'SN', 'RS', 'SG', 'SK', 'SI', 'ZA', 'KR', 'ES', 'LK', 'SE', 'CH', 'TW', 'TJ', 'TZ', 'TH', 'TL', 'TG', 'TK', 'TO', 'TT', 'TN', 'TR', 'TM', 'TC', 'TV', 'UG', 'UA', 'AE', 'GB', 'US', 'UY', 'VE', 'VN', 'YE', 'ZW'}

VALID_PROTOCOLS = ('vmess://', 'vless://', 'ss://', 'trojan://', 'ssr://', 'hysteria://', 'hy2://', 'hysteria2://', 'wireguard://', 'tuic://')
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

# ================= 4. ФУНКЦИИ ПАРСИНГА ИЗ ЭТАЛОННОГО СКРИПТА =================

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

def parse_link(link):
    link = link.strip()
    if not link: return None
    try:
        if link.startswith('vmess://'): return parse_vmess(link)
        if link.startswith('vless://'): return parse_vless_trojan(link, 'vless')
        if link.startswith('trojan://'): return parse_vless_trojan(link, 'trojan')
        if link.startswith('tuic://'): return parse_tuic(link)
        if link.startswith('hysteria2://') or link.startswith('hy2://'): return parse_hysteria2(link)
        # Игнорируем SS/SSR/Wireguard в этом скрипте
    except: return None
    return None

def generate_singbox_config(data, local_port):
    # Адаптировано из Скрипта A
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
    
    else: return None

    config['outbounds'].append(outbound)
    return json.dumps(config)

def rebuild_link(original_link, data, new_name):
    # Адаптировано из Скрипта A
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

# ================= 5. ЛОГИКА СБОРА ИСТОЧНИКОВ =================

def fetch_content(url, url_type):
    # Адаптировано из Скрипта A
    try:
        # Убираем refs/heads/ для корректной работы raw.github
        clean_url = re.sub(r'/refs/heads/', '/', url)
        response = requests.get(clean_url, timeout=15)
        response.raise_for_status()
        return response.text, url_type
    except requests.RequestException:
        return None, url_type

def process_content(content, url_type):
    # Адаптировано из Скрипта A
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
        # Фильтруем только нужные протоколы
        if link and link.startswith(('vmess://', 'vless://', 'trojan://', 'tuic://', 'hysteria2://', 'hy2://')):
            valid_links.append(link)
    return valid_links

def scrape_all_proxies_from_sources():
    print(f"Starting scraper for {len(PLAINTEXT_URLS) + len(BASE64_URLS)} sources...")
    all_proxies = set()
    
    tasks = [(url, 'plaintext') for url in PLAINTEXT_URLS] + [(url, 'base64') for url in BASE64_URLS]
    
    # Используем 20 потоков для быстрого скачивания
    with ThreadPoolExecutor(max_workers=20) as executor:
        future_to_url = {executor.submit(fetch_content, url, url_type): (url, url_type) for url, url_type in tasks}
        
        for future in tqdm(as_completed(future_to_url), total=len(tasks), desc="Scraping Sources"):
            content, url_type = future.result()
            links = process_content(content, url_type)
            all_proxies.update(links)
            
    print(f"Scraping finished. Found {len(all_proxies)} unique links.")
    return list(all_proxies)

# ================= 6. ЗАГРУЗКА ТЕКУЩЕГО GIST =================

def fetch_gist_links(gist_id):
    # Адаптировано из Скрипта B (для чтения Gist)
    if not GIST_TOKEN: return []
    gist_url = f"https://api.github.com/gists/{gist_id}"
    headers = {'Authorization': f'token {GIST_TOKEN}', 'Accept': 'application/vnd.github.v3+json'}
    try:
        r = requests.get(gist_url, headers=headers, timeout=15)
        r.raise_for_status()
        files = r.json().get('files', {})
        content = files.get(GIST_FILENAME, {}).get('content', '')
        
        links = [l.strip() for l in content.splitlines() if l.strip()]
        valid = [l for l in links if l.startswith(('vmess://', 'vless://', 'trojan://', 'tuic://', 'hysteria2://', 'hy2://'))]
        print(f"Fetched {len(valid)} links from existing Gist.")
        return valid
    except Exception as e:
        print(f"Error fetching Gist: {e}")
        return []

# ================= 7. ЛОГИКА ПРОВЕРКИ И ФИЛЬТРАЦИИ =================

def check_proxy(link):
    proc = None
    config_file = None
    try:
        data = parse_link(link)
        if not data: return None
        
        # Пропускаем, если не VLESS/VMESS/Trojan/TUIC/Hysteria
        if data.get('type') in ['shadowsocks', 'shadowsocksr', 'wireguard']: return None

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
        time.sleep(1.5)
        if proc.poll() is not None: return None

        proxies = {'http': f'socks5://127.0.0.1:{local_port}', 'https': f'socks5://127.0.0.1:{local_port}'}

        # 1. PING (Google)
        start_time = time.time()
        try:
            requests.get(TEST_URL, proxies=proxies, timeout=TIMEOUT)
            ping = int((time.time() - start_time) * 1000)
        except: return None 

        # 2. CHATGPT CHECK (New)
        gpt_ok = False
        try:
            gpt_r = requests.get(OPENAI_URL, proxies=proxies, timeout=5)
            # 401 Unauthorized или 200 OK
            if gpt_r.status_code in [200, 401]:
                gpt_ok = True
        except:
            pass

        # 3. GEO (ipinfo.io)
        api_data = {}
        for attempt in range(API_RETRIES):
            try:
                r = requests.get(IP_API_URL, proxies=proxies, timeout=TIMEOUT)
                if r.status_code == 200 and 'ip' in r.json():
                    api_data = r.json()
                    break
            except: pass
            time.sleep(API_RETRY_DELAY)
        
        if not api_data: return None
        
        cc = api_data.get('country', 'XX')
        city = api_data.get('city', 'Unknown')
        isp = api_data.get('org', 'Unknown ISP')

        # Фильтрация RU и Banned ISP
        if cc == 'RU' or cc == 'XX': return None
        isp_clean = re.sub(r'^AS\d+\s+', '', isp)
        if re.search(BANNED_ISP_REGEX, isp_clean): return None

        # 4. Ренейминг
        flag = country_flag(cc)
        gemini_ok = cc in GEMINI_ALLOWED
        yt_music_ok = cc in YT_MUSIC_ALLOWED
        
        gemini_ico = '✅' if gemini_ok else '❌'
        yt_ico = '✅' if yt_music_ok else '❌'
        gpt_ico = '✅' if gpt_ok else '❌'
        
        name = f"{flag} {cc} - {city} ◈ {isp_clean} | 🎵YT_Music{yt_ico} ✨Gemini{gemini_ico} 🤖ChatGPT{gpt_ico}"
        
        # 5. Пересборка и хэширование
        final_link = rebuild_link(link, data, name)
        link_hash = hashlib.md5(final_link.encode('utf-8')).hexdigest()
        
        return (ping, final_link, link_hash)

    except Exception:
        # print(f"Error checking {link}: {e}")
        return None
    finally:
        if proc:
            proc.terminate()
            try: proc.wait(timeout=1)
            except: proc.kill()
        if config_file and os.path.exists(config_file.name):
            try: os.remove(config_file.name)
            except: pass

# ================= 8. ДЕПЛОЙ =================

def deploy(links_content, pings_content):
    if not all([GH_TOKEN, GIST_ID, VERCEL_TOKEN, PROJ_ID]):
        print("Secrets missing.")
        return

    print("Updating Gist (Links + Pings)...")
    try:
        # Получаем время обновления Gist
        gist_info_r = requests.get(f'https://api.github.com/gists/{GIST_ID}', headers={'Authorization': f'token {GH_TOKEN}'}).json()
        
        payload = {
            'files': {
                GIST_FILENAME: {'content': links_content},
                PING_FILENAME: {'content': pings_content}
            },
            'description': f'SingBox Updated: {time.strftime("%Y-%m-%d %H:%M UTC")}'
        }
        r = requests.patch(f'https://api.github.com/gists/{GIST_ID}', headers={'Authorization': f'token {GH_TOKEN}'}, json=payload)
        r.raise_for_status()
        
        raw_url = r.json()['files'][GIST_FILENAME]['raw_url']
        final_url = f"{raw_url}?t={int(time.time())}"
        print("Gist OK.")
    except Exception as e: print(f"Gist Error: {e}"); return

    # Trigger Vercel
    print("Triggering Vercel...")
    h = {"Authorization": f"Bearer {VERCEL_TOKEN}"}
    try:
        envs = requests.get(f"https://api.vercel.com/v9/projects/{PROJ_ID}/env", headers=h).json().get('envs', [])
        eid = next((e['id'] for e in envs if e['key'] == ENV_KEY), None)
        body = {"value": final_url, "target": ["production"], "type": "plain"}
        
        if eid: requests.patch(f"https://api.vercel.com/v9/projects/{PROJ_ID}/env/{eid}", headers=h, json=body)
        else: body['key'] = ENV_KEY; requests.post(f"https://api.vercel.com/v10/projects/{PROJ_ID}/env", headers=h, json=body)

        proj = requests.get(f"https://api.vercel.com/v9/projects/{PROJ_ID}", headers=h).json()
        payload_deploy = {"name": proj.get('name'), "project": PROJ_ID, "target": "production"}
        
        if 'link' in proj and 'repoId' in proj['link']:
            payload_deploy['gitSource'] = {"type": "github", "ref": "main", "repoId": proj['link']['repoId']}
            
        requests.post("https://api.vercel.com/v13/deployments", headers=h, json=payload_deploy)
        print("Vercel OK.")
    except Exception as e: print(f"Vercel Error: {e}")


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

    # 1. Сборка ссылок из всех внешних источников
    links_scraped = scrape_all_proxies_from_sources()
    
    # 2. Загрузка текущих ссылок из Gist
    links_from_gist = fetch_gist_links(GIST_ID)
    
    # 3. Объединение и дедупликация
    all_raw_links = list(set(links_scraped + links_from_gist))
    print(f"Total unique links to check: {len(all_raw_links)}")
    if not all_raw_links: return

    # 4. Проверка
    results = []
    seen_proxies.clear()
    
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(check_proxy, link): link for link in all_raw_links}
        for future in tqdm(as_completed(futures), total=len(all_raw_links), desc="Checking & Renaming"):
            res = future.result()
            if res: results.append(res)

    print(f"\nWorking proxies found: {len(results)}")
    
    if results:
        results.sort(key=lambda x: x[0])
        
        links_str = "\n".join([r[1] for r in results])
        pings_map = {r[2]: r[0] for r in results}
        pings_json = json.dumps(pings_map)
        
        deploy(links_str, pings_json)
    else:
        print("No working proxies found.")

if __name__ == "__main__":
    main()
