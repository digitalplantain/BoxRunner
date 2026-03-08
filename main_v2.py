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
import ipaddress
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
from radix import Radix
from bs4 import BeautifulSoup

# ========== НАСТРОЙКИ ==========
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
    "https://raw.githubusercontent.com/youfoundamin/V2rayCollector/main/vless_iran.txt",
    "https://raw.githubusercontent.com/youfoundamin/V2rayCollector/main/vmess_iran.txt",
    "https://raw.githubusercontent.com/youfoundamin/V2rayCollector/main/trojan_iran.txt",
    "https://github.com/Argh94/Proxy-List/raw/refs/heads/main/All_Config.txt",
    "https://raw.githubusercontent.com/Argh94/V2RayAutoConfig/refs/heads/main/configs/Russia.txt",
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
    "https://raw.githubusercontent.com/Firmfox/Proxify/refs/heads/main/v2ray_configs/seperated_by_protocol/warp.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_SS%2BAll_RUS.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_VLESS_RUS.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_VLESS_RUS_mobile.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile-2.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-all.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-checked.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-SNI-RU-all.txt",
    "https://gitverse.ru/api/repos/bywarm/rser/raw/branch/master/selected.txt",
    "https://wlr.s3-website.cloud.ru/bucket-93b250/selected.txt",
    "https://bp.wl.free.nf/confs/selected.txt",
    "https://gitverse.ru/api/repos/bywarm/rser/raw/branch/master/merged.txt",
    "https://wlr.s3-website.cloud.ru/bucket-93b250/merged.txt",
    "https://bp.wl.free.nf/confs/merged.txt",
    "https://gitverse.ru/api/repos/bywarm/rser/raw/branch/master/wl.txt",
    "https://wlr.s3-website.cloud.ru/bucket-93b250/wl.txt",
    "https://bp.wl.free.nf/confs/wl.txt",
    "https://raw.githubusercontent.com/nscl5/5/main/configs/all.txt",
    "https://raw.githubusercontent.com/FNET00bot/FNET00/Config/Main",
    "https://raw.githubusercontent.com/wiki/gfpcom/free-proxy-list/lists/ss.txt",
    "https://raw.githubusercontent.com/R3ZARAHIMI/7/main/Config_jo.txt",
    "https://raw.githubusercontent.com/4n0nymou3/multi-proxy-config-fetcher/refs/heads/main/configs/proxy_configs.txt"
]
BASE64_URLS = [
    "https://raw.githubusercontent.com/mahsanet/MahsaFreeConfig/main/mci/sub_1.txt",
    "https://raw.githubusercontent.com/ALIILAPRO/v2rayNG-Config/main/sub.txt",
    "https://raw.githubusercontent.com/mahsanet/MahsaFreeConfig/refs/heads/main/mtn/sub_1.txt",
    "https://raw.githubusercontent.com/mahsanet/MahsaFreeConfig/refs/heads/main/mci/sub_1.txt",
    "https://raw.githubusercontent.com/mahsanet/MahsaFreeConfig/refs/heads/main/mci/sub_2.txt",
    "https://raw.githubusercontent.com/mahsanet/MahsaFreeConfig/refs/heads/main/mci/sub_3.txt",
    "https://raw.githubusercontent.com/mahsanet/MahsaFreeConfig/refs/heads/main/mci/sub_4.txt",
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
    "https://raw.githubusercontent.com/Surfboardv2ray/TGParse/main/python/trojan",
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/All_Configs_base64_Sub.txt",
    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/super-sub.txt",
    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/all_sub.txt",
    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/vless.txt",
    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/vmess.txt",
    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/trojan.txt",
    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/hysteria2.txt",
    "https://raw.githubusercontent.com/mahsanet/MahsaFreeConfig/main/mci/sub_1.txt"
]

SING_BOX_PATH = "./sing-box"
MAX_WORKERS_CHECK = 300
MAX_WORKERS_SCRAPE = 30
MAX_WORKERS_FINAL = 50      # для финальной проверки через gateway
TIMEOUT = 10
GATEWAY_CHECK_TIMEOUT = 15  # таймаут для проверок через gateway
API_RETRIES = 2
GH_TOKEN = os.environ.get("GH_TOKEN")
GIST_ID = os.environ.get("GIST_ID")
VERCEL_TOKEN = os.environ.get("VERCEL_TOKEN")
PROJ_ID = os.environ.get("PROJ_ID")
GIST_FILENAME = "gistfile1.txt"
PING_FILENAME = "pings.json"
ENV_KEY = "GIST_URL"
IP_API_URL = "http://ipinfo.io/json"
IP_API_FALLBACK_URL = "http://ip-api.com/json"
IP_ENTRY_API_URL = "http://ipinfo.io/{ip}/json"
IP_ENTRY_API_FALLBACK_URL = "http://ip-api.com/json/{ip}?fields=country"
TEST_URL = "http://www.gstatic.com/generate_204"
OPENAI_URL = "https://api.openai.com/v1/models"
BANNED_ISP_REGEX = r"(?i)(hetzner|cloudflare|pq hosting|amazon|the constant company|gthost|contabo|m247|ponynet|fdcservers|oracle|digitalocean|ovh|kaopu|netcup|upcloud|worktitans|alibaba|global connectivity solutions llp|baykov|akamao|lucidacloud|global cloud|oc networks limited|play2go|acgnode inc|netranex|cognetcloud|rj network|bluevps|vdska|alexhost|h2nexus|hkt|timeweb|julian|microsoft|hostkey|dataforest|nexet|cloud hosting|leaseweb deutschland gmbh)"
RKN_SUBNET_URL = "https://antifilter.network/download/subnet.lst"
RKN_IPSUM_URL = "https://antifilter.network/download/ipsum.lst"
RKN_BANNED_NETWORKS = Radix()
GEMINI_ALLOWED = {'AL', 'DZ', 'AS', 'AO', 'AI', 'AQ', 'AG', 'AR', 'AM', 'AW', 'AU', 'AT', 'AZ', 'BS', 'BH', 'BD', 'BB', 'BE', 'BZ', 'BJ', 'BM', 'BT', 'BO', 'BA', 'BW', 'BR', 'IO', 'VG', 'BN', 'BG', 'BF', 'BI', 'CV', 'KH', 'CM', 'CA', 'BQ', 'KY', 'CF', 'TD', 'CL', 'CX', 'CC', 'CO', 'KM', 'CK', 'CI', 'CR', 'HR', 'CW', 'CZ', 'CD', 'DK', 'DJ', 'DM', 'DO', 'EC', 'EG', 'SV', 'GQ', 'ER', 'EE', 'SZ', 'ET', 'FK', 'FO', 'FJ', 'FI', 'FR', 'GA', 'GM', 'GE', 'DE', 'GH', 'GI', 'GR', 'GL', 'GD', 'GU', 'GT', 'GG', 'GN', 'GW', 'GY', 'HT', 'HM', 'HN', 'HU', 'IS', 'IN', 'ID', 'IQ', 'IE', 'IM', 'IL', 'IT', 'JM', 'JP', 'JE', 'JO', 'KZ', 'KE', 'KI', 'XK', 'KG', 'KW', 'LA', 'LV', 'LB', 'LS', 'LR', 'LY', 'LI', 'LT', 'LU', 'MG', 'MW', 'MY', 'MV', 'ML', 'MT', 'MH', 'MR', 'MU', 'MX', 'FM', 'MN', 'ME', 'MS', 'MA', 'MZ', 'NA', 'NR', 'NP', 'NL', 'NC', 'NZ', 'NI', 'NE', 'NG', 'NU', 'NF', 'MK', 'MP', 'NO', 'OM', 'PK', 'PW', 'PS', 'PA', 'PG', 'PY', 'PE', 'PH', 'PN', 'PL', 'PT', 'PR', 'QA', 'CY', 'CG', 'RO', 'RW', 'BL', 'KN', 'LC', 'PM', 'VC', 'SH', 'WS', 'ST', 'SA', 'SN', 'RS', 'SC', 'SL', 'SG', 'SK', 'SI', 'SB', 'SO', 'ZA', 'GS', 'KR', 'SS', 'ES', 'LK', 'SD', 'SR', 'SE', 'CH', 'TW', 'TJ', 'TZ', 'TH', 'TL', 'TG', 'TK', 'TO', 'TT', 'TN', 'TR', 'TM', 'TC', 'TV', 'UG', 'UA', 'GB', 'AE', 'US', 'UM', 'VI', 'UY', 'UZ', 'VU', 'VE', 'VN', 'WF', 'EH', 'YE', 'ZM', 'ZW'}
YT_MUSIC_ALLOWED = {'DZ', 'AS', 'AR', 'AW', 'AU', 'AT', 'AZ', 'BH', 'BD', 'BY', 'BE', 'BM', 'BO', 'BA', 'BR', 'BG', 'KH', 'CA', 'KY', 'CL', 'CO', 'CR', 'HR', 'CY', 'CZ', 'DK', 'DO', 'EC', 'EG', 'SV', 'EE', 'FI', 'FR', 'GF', 'PF', 'GE', 'DE', 'GH', 'GR', 'GP', 'GU', 'GT', 'HN', 'HK', 'HU', 'IS', 'IN', 'ID', 'IQ', 'IE', 'IL', 'IT', 'JM', 'JP', 'JE', 'JO', 'KZ', 'KE', 'KI', 'XK', 'KG', 'KW', 'LA', 'LV', 'LB', 'LS', 'LR', 'LY', 'LI', 'LT', 'LU', 'MY', 'MT', 'MX', 'MA', 'NP', 'NL', 'NZ', 'NI', 'NG', 'MK', 'MP', 'NO', 'OM', 'PK', 'PA', 'PG', 'PY', 'PE', 'PH', 'PL', 'PT', 'PR', 'QA', 'RE', 'RO', 'RU', 'SA', 'SN', 'RS', 'SG', 'SK', 'SI', 'ZA', 'KR', 'ES', 'LK', 'SE', 'CH', 'TW', 'TZ', 'TH', 'TN', 'TR', 'TC', 'VI', 'UG', 'UA', 'AE', 'GB', 'US', 'UY', 'VE', 'VN', 'YE', 'ZW'}

# ========== ДИАГНОСТИКА ==========
DEBUG = False  # отключим детальный вывод, но можно включить при необходимости
reject_stats = {
    'parse_failed': 0,
    'no_server': 0,
    'ip_banned': 0,
    'identifier_duplicate': 0,
    'singbox_failed': 0,
    'test_failed': 0,
    'api_failed': 0,
    'exit_country_banned': 0,
    'cheburcheck_blocked': 0,
    'isp_banned': 0,
    'other_error': 0,
    'success': 0,
    'gateway_filtered': 0   # для прокси, отсеянных на финальной проверке
}

def get_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("", 0))
        return s.getsockname()[1]

def country_flag(code):
    if not code or len(code) != 2: return "🏁"
    return "".join(chr(0x1F1E6 + ord(char.upper()) - ord('A')) for char in code)

def safe_base64_decode(s):
    if not s: return b""
    s = s.strip().replace('\n', '').replace('\r', '')
    pad = len(s) % 4
    if pad: s += '=' * (4 - pad)
    try: return base64.urlsafe_b64decode(s)
    except:
        try: return base64.b64decode(s)
        except: return b""

def load_rkn_lists():
    print("Downloading RKN block lists...")
    urls = [RKN_SUBNET_URL, RKN_IPSUM_URL]
    count = 0
    for url in urls:
        try:
            r = requests.get(url, timeout=15)
            r.raise_for_status()
            for line in r.text.splitlines():
                if line.strip():
                    node = RKN_BANNED_NETWORKS.add(line.strip())
                    node.data['banned'] = True
                    count += 1
        except Exception as e:
            print(f"Warning: Failed to load RKN list {url}: {e}")
    print(f"Loaded {count} banned networks into Radix tree.")

def is_ip_banned(ip_str):
    try:
        node = RKN_BANNED_NETWORKS.search_best(ip_str)
        return node is not None and 'banned' in node.data
    except (ValueError, TypeError):
        return False

CHEBURCHECK_HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
    'Accept-Language': 'ru,en;q=0.9', 'Dnt': '1', 'Sec-Fetch-Site': 'none',
    'Sec-Fetch-Mode': 'navigate', 'Sec-Fetch-User': '?1', 'Upgrade-Insecure-Requests': '1',
}
cheburcheck_cache = {}

def cheburcheck_is_blocked(target):
    if not target: return False
    if target in cheburcheck_cache: return cheburcheck_cache[target]
    try:
        url = f"https://cheburcheck.ru/check?target={target}"
        response = requests.get(url, headers=CHEBURCHECK_HEADERS, timeout=15)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'lxml')
        panel = soup.find('div', class_='result-panel')
        if not panel:
            cheburcheck_cache[target] = False
            return False
        panel_classes = panel.get('class', [])
        if 'whitelist-theme' in panel_classes:
            cheburcheck_cache[target] = False
            return False
        if 'blocked-theme' in panel_classes:
            if DEBUG: print(f"[Cheburcheck] {target} is BLOCKED")
            cheburcheck_cache[target] = True
            return True
        cheburcheck_cache[target] = False
        return False
    except Exception as e:
        if DEBUG: print(f"Warning: Cheburcheck request failed for {target}: {e}")
        return False

def fetch_url_content(url):
    try:
        r = requests.get(url, timeout=10)
        r.raise_for_status()
        return r.text
    except: return None

# ========== УНИВЕРСАЛЬНЫЙ СБОРЩИК ==========
def scrape_all_sources():
    print("Starting scraper...")
    all_proxies = set()

    def process_content(content, is_base64=False):
        if not content:
            return
        if is_base64:
            try:
                content = safe_base64_decode(content).decode('utf-8', errors='ignore')
            except:
                return
        content = content.replace('<br/>', '\n').replace('<br>', '\n')
        for line in content.splitlines():
            line = line.strip()
            if '://' in line and not any(c in line for c in ' \t\n\r'):
                all_proxies.add(line)

    with ThreadPoolExecutor(max_workers=MAX_WORKERS_SCRAPE) as exe:
        futures = {exe.submit(fetch_url_content, u): u for u in PLAINTEXT_URLS}
        for f in tqdm(as_completed(futures), total=len(PLAINTEXT_URLS), desc="Plaintext"):
            process_content(f.result(), is_base64=False)

    with ThreadPoolExecutor(max_workers=MAX_WORKERS_SCRAPE) as exe:
        futures = {exe.submit(fetch_url_content, u): u for u in BASE64_URLS}
        for f in tqdm(as_completed(futures), total=len(BASE64_URLS), desc="Base64"):
            process_content(f.result(), is_base64=True)

    if GIST_ID and GH_TOKEN:
        try:
            print("Fetching existing Gist...")
            r = requests.get(f"https://api.github.com/gists/{GIST_ID}", headers={'Authorization': f'token {GH_TOKEN}'})
            files = r.json().get('files', {})
            content = files.get(GIST_FILENAME, {}).get('content', '')
            for line in content.splitlines():
                l = line.strip()
                if l:
                    all_proxies.add(l)
        except Exception as e:
            print(f"Gist fetch warning: {e}")

    print(f"Total unique raw links: {len(all_proxies)}")
    return list(all_proxies)

# ========== ПАРСЕР (ПОЛНЫЙ) ==========
def parse_proxy_link(link):
    try:
        # ----- VMess -----
        if link.startswith('vmess://'):
            data = json.loads(safe_base64_decode(link[8:]).decode('utf-8'))
            data['protocol'] = 'vmess'
            data['uuid'] = data.get('id')
            data['server'] = data.get('add')
            data['port'] = int(data.get('port'))
            data['alter_id'] = int(data.get('aid', 0))
            data['security'] = data.get('scy', 'auto')
            data['network'] = data.get('net', 'tcp')
            data['sni'] = data.get('host') or data.get('sni')
            data['path'] = data.get('path')
            return data

        # ----- VLESS / Trojan -----
        parsed = urllib.parse.urlparse(link)
        protocol = parsed.scheme
        if protocol in ['vless', 'trojan']:
            data = {
                'protocol': protocol,
                'server': parsed.hostname,
                'port': parsed.port,
                'uuid': parsed.username,
                'password': parsed.username
            }
            query = urllib.parse.parse_qs(parsed.query)
            for k, v in query.items():
                data[k.lower()] = v[0]
            data['network'] = data.get('type', 'tcp')
            data['sni'] = data.get('sni') or data.get('host')
            return data

        # ----- Hysteria2 / Hy2 -----
        if protocol in ['hysteria2', 'hy2']:
            parsed = urllib.parse.urlparse(link)
            query = urllib.parse.parse_qs(parsed.query)
            data = {
                'protocol': 'hysteria2',
                'server': parsed.hostname,
                'port': parsed.port,
                'password': parsed.username,
                'sni': query.get('sni', [parsed.hostname])[0],
                'insecure': query.get('insecure', ['0'])[0] == '1'
            }
            return data

        # ----- TUIC -----
        if protocol == 'tuic':
            parsed = urllib.parse.urlparse(link)
            query = urllib.parse.parse_qs(parsed.query)
            data = {
                'protocol': 'tuic',
                'server': parsed.hostname,
                'port': parsed.port,
                'uuid': parsed.username,
                'password': parsed.password,
                'sni': query.get('sni', [parsed.hostname])[0],
                'congestion_control': query.get('congestion_control', ['bbr'])[0],
                'udp_relay_mode': query.get('udp_relay_mode', ['native'])[0]
            }
            return data

        # ----- Shadowsocks (ss://) -----
        if protocol == 'ss':
            parsed = urllib.parse.urlparse(link)
            if '@' in parsed.netloc:
                userinfo, hostport = parsed.netloc.split('@', 1)
            else:
                userinfo = parsed.username or ''
                hostport = parsed.hostname or ''
            decoded = safe_base64_decode(userinfo).decode('utf-8')
            if ':' in decoded:
                method, password = decoded.split(':', 1)
            else:
                return None
            data = {
                'protocol': 'shadowsocks',
                'method': method,
                'password': password,
                'server': parsed.hostname,
                'port': parsed.port or 443,
                'plugin': parsed.query
            }
            return data

        # ----- Hysteria v1 (hysteria://) -----
        if protocol == 'hysteria':
            parsed = urllib.parse.urlparse(link)
            query = urllib.parse.parse_qs(parsed.query)
            data = {
                'protocol': 'hysteria',
                'server': parsed.hostname,
                'port': parsed.port or 443,
                'auth': query.get('auth', [''])[0] or parsed.username or '',
                'up_mbps': int(query.get('upmbps', [10])[0]),
                'down_mbps': int(query.get('downmbps', [50])[0]),
                'sni': query.get('peer', [parsed.hostname])[0],
                'insecure': query.get('insecure', ['0'])[0] == '1',
                'alpn': query.get('alpn', ['h3'])[0],
            }
            return data

        # ----- AnyTLS (anytls://) -----
        if protocol == 'anytls':
            parsed = urllib.parse.urlparse(link)
            query = urllib.parse.parse_qs(parsed.query)
            data = {
                'protocol': 'anytls',
                'server': parsed.hostname,
                'port': parsed.port,
                'password': parsed.password or parsed.username or '',
                'sni': query.get('sni', [parsed.hostname])[0],
                'insecure': query.get('insecure', ['0'])[0] == '1',
            }
            return data

        # ----- ShadowTLS (sn://) -----
        if protocol == 'sn':
            parsed = urllib.parse.urlparse(link)
            query = urllib.parse.parse_qs(parsed.query)
            data = {
                'protocol': 'shadowtls',
                'server': parsed.hostname,
                'port': parsed.port,
                'password': parsed.username or '',
                'sni': query.get('sni', [parsed.hostname])[0],
                'insecure': query.get('insecure', ['0'])[0] == '1',
                'version': int(query.get('version', [3])[0]),
            }
            return data

        # ----- SOCKS5 / SOCKS4 -----
        if protocol in ('socks5', 'socks4', 'socks4a'):
            parsed = urllib.parse.urlparse(link)
            data = {
                'protocol': protocol,
                'server': parsed.hostname,
                'port': parsed.port or 1080,
                'username': parsed.username,
                'password': parsed.password,
            }
            return data

        # ----- HTTP / HTTPS прокси -----
        if protocol in ('http', 'https'):
            parsed = urllib.parse.urlparse(link)
            data = {
                'protocol': 'http',
                'server': parsed.hostname,
                'port': parsed.port or (443 if parsed.scheme == 'https' else 80),
                'username': parsed.username,
                'password': parsed.password,
                'tls': parsed.scheme == 'https',
            }
            return data

        return None
    except Exception as e:
        if DEBUG: print(f"Parse exception: {e}")
        return None

# ========== ГЕНЕРАЦИЯ КОНФИГА (ПОЛНАЯ) ==========
def generate_singbox_config(data, local_port, gateway=None):
    """
    gateway: (host, port) if not None, then the outbound will use detour to this gateway
    """
    config = {
        "log": {"disabled": True},
        "inbounds": [{"type": "mixed","tag": "in","listen": "127.0.0.1","listen_port": local_port,"set_system_proxy": False}],
        "outbounds": []
    }

    if gateway:
        gateway_host, gateway_port = gateway
        config["outbounds"].append({
            "tag": "gateway",
            "type": "socks",
            "server": gateway_host,
            "server_port": gateway_port
        })

    outbound = {"tag": "proxy"}

    proto = data['protocol']

    # ----- VMess -----
    if proto == 'vmess':
        outbound.update({
            "type": "vmess",
            "server": data['server'],
            "server_port": int(data['port']),
            "uuid": data['uuid'],
            "alter_id": int(data.get('alter_id', 0)),
            "security": data.get('security', 'auto')
        })
        if data.get('tls') == 'tls':
            outbound["tls"] = {"enabled": True, "server_name": data.get('sni', ''), "insecure": False}

    # ----- VLESS -----
    elif proto == 'vless':
        outbound.update({
            "type": "vless",
            "server": data['server'],
            "server_port": int(data['port']),
            "uuid": data['uuid']
        })
        if data.get('flow'):
            outbound["flow"] = data['flow']
        tls_enabled = data.get('security') in ['tls', 'reality']
        if tls_enabled:
            tls_conf = {"enabled": True, "server_name": data.get('sni', ''), "insecure": False}
            if data.get('security') == 'reality':
                tls_conf["reality"] = {"enabled": True, "public_key": data.get('pbk', ''), "short_id": data.get('sid', '')}
            if data.get('fp'):
                tls_conf["utls"] = {"enabled": True, "fingerprint": data['fp']}
            outbound["tls"] = tls_conf

    # ----- Trojan -----
    elif proto == 'trojan':
        outbound.update({
            "type": "trojan",
            "server": data['server'],
            "server_port": int(data['port']),
            "password": data['password']
        })
        outbound["tls"] = {"enabled": True, "server_name": data.get('sni', ''), "insecure": False}

    # ----- Hysteria2 -----
    elif proto == 'hysteria2':
        outbound.update({
            "type": "hysteria2",
            "server": data['server'],
            "server_port": int(data['port']),
            "password": data.get('password', '')
        })
        outbound["tls"] = {"enabled": True, "server_name": data.get('sni', data['server']), "insecure": data.get('insecure', False)}

    # ----- TUIC -----
    elif proto == 'tuic':
        outbound.update({
            "type": "tuic",
            "server": data['server'],
            "server_port": int(data['port']),
            "uuid": data['uuid'],
            "password": data.get('password', ''),
            "congestion_control": data.get('congestion_control', 'bbr'),
            "udp_relay_mode": data.get('udp_relay_mode', 'native'),
            "zero_rtt_handshake": True
        })
        outbound["tls"] = {"enabled": True, "server_name": data.get('sni', data['server']), "alpn": ["h3"]}

    # ----- Shadowsocks -----
    elif proto == 'shadowsocks':
        outbound.update({
            "type": "shadowsocks",
            "server": data['server'],
            "server_port": int(data['port']),
            "method": data['method'],
            "password": data['password']
        })
        if data.get('plugin'):
            outbound["plugin"] = data['plugin']

    # ----- Hysteria v1 -----
    elif proto == 'hysteria':
        outbound.update({
            "type": "hysteria",
            "server": data['server'],
            "server_port": int(data['port']),
            "up_mbps": data['up_mbps'],
            "down_mbps": data['down_mbps'],
            "auth": data['auth'],
            "tls": {
                "enabled": True,
                "server_name": data['sni'],
                "insecure": data['insecure'],
                "alpn": [data['alpn']]
            }
        })

    # ----- AnyTLS -----
    elif proto == 'anytls':
        outbound.update({
            "type": "anytls",
            "server": data['server'],
            "server_port": int(data['port']),
            "password": data['password'],
            "tls": {
                "enabled": True,
                "server_name": data['sni'],
                "insecure": data['insecure']
            }
        })

    # ----- ShadowTLS -----
    elif proto == 'shadowtls':
        outbound.update({
            "type": "shadowtls",
            "server": data['server'],
            "server_port": int(data['port']),
            "password": data['password'],
            "version": data['version'],
            "tls": {
                "enabled": True,
                "server_name": data['sni'],
                "insecure": data['insecure']
            }
        })

    # ----- SOCKS -----
    elif proto in ('socks5', 'socks4', 'socks4a'):
        outbound.update({
            "type": "socks",
            "server": data['server'],
            "server_port": int(data['port']),
            "version": proto.replace('socks', '')
        })
        if data.get('username') and data.get('password'):
            outbound["username"] = data['username']
            outbound["password"] = data['password']

    # ----- HTTP -----
    elif proto == 'http':
        outbound.update({
            "type": "http",
            "server": data['server'],
            "server_port": int(data['port'])
        })
        if data.get('username') and data.get('password'):
            outbound["username"] = data['username']
            outbound["password"] = data['password']
        if data.get('tls'):
            outbound["tls"] = {"enabled": True, "server_name": data['server']}

    else:
        if DEBUG: print(f"Unknown protocol: {proto}")
        return None

    # Добавляем detour, если есть gateway
    if gateway:
        outbound["detour"] = "gateway"

    # Добавляем транспорт для тех протоколов, где он нужен
    if proto in ['vmess', 'vless', 'trojan'] and data.get('network') in ['ws', 'grpc']:
        transport = {}
        net = data['network']
        if net == 'ws':
            transport = {"type": "ws", "path": data.get('path', '/')}
            if data.get('host') or data.get('sni'):
                transport["headers"] = {"Host": data.get('host') or data.get('sni')}
        elif net == 'grpc':
            transport = {"type": "grpc", "service_name": data.get('serviceName', '')}
        if transport:
            outbound["transport"] = transport

    config["outbounds"].append(outbound)
    return json.dumps(config)

# ========== ПРОВЕРКА (первичная) ==========
seen_proxies = set()
error_counter = 0
entry_ip_country_cache = {}

def check_proxy(link):
    global error_counter
    proc = None
    config_filename = None
    try:
        data = parse_proxy_link(link)
        if not data:
            reject_stats['parse_failed'] += 1
            return None

        server_address = data.get('server')
        if not server_address:
            reject_stats['no_server'] += 1
            return None

        entry_ip = None
        if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', server_address):
            try:
                entry_ip = socket.gethostbyname(server_address)
            except:
                reject_stats['other_error'] += 1
                return None
        else:
            entry_ip = server_address

        if not entry_ip or is_ip_banned(entry_ip):
            reject_stats['ip_banned'] += 1
            return None

        identifier = f"{data.get('server')}:{data.get('port')}"
        if identifier in seen_proxies:
            reject_stats['identifier_duplicate'] += 1
            return None
        seen_proxies.add(identifier)

        local_port = get_free_port()
        conf_str = generate_singbox_config(data, local_port)
        if not conf_str:
            reject_stats['singbox_failed'] += 1
            return None

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as config_file:
            config_file.write(conf_str)
            config_filename = config_file.name

        proc = subprocess.Popen([SING_BOX_PATH, "run", "-c", config_filename], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1.5)
        if proc.poll() is not None:
            reject_stats['singbox_failed'] += 1
            return None

        proxies = {'http': f'socks5://127.0.0.1:{local_port}', 'https': f'socks5://127.0.0.1:{local_port}'}

        try:
            st = time.time()
            requests.get(TEST_URL, proxies=proxies, timeout=TIMEOUT)
            ping = int((time.time() - st) * 1000)
        except Exception as e:
            reject_stats['test_failed'] += 1
            return None

        api_data = {}
        for _ in range(API_RETRIES):
            try:
                r = requests.get(IP_API_URL, proxies=proxies, timeout=TIMEOUT)
                if r.status_code == 200 and 'ip' in r.json():
                    api_data = r.json()
                    break
            except:
                pass

        if not api_data:
            try:
                r = requests.get(IP_API_FALLBACK_URL, proxies=proxies, timeout=TIMEOUT)
                if r.status_code == 200:
                    d = r.json()
                    api_data = {
                        'ip': d.get('query'),
                        'country': d.get('countryCode'),
                        'city': d.get('city'),
                        'org': d.get('isp')
                    }
            except:
                pass

        if not api_data:
            reject_stats['api_failed'] += 1
            return None

        exit_ip = api_data.get('ip')
        exit_country = api_data.get('country', 'XX')

        BANNED_EXIT_COUNTRIES = {'RU', 'BY', 'HK', 'CN'}
        if exit_country in BANNED_EXIT_COUNTRIES:
            reject_stats['exit_country_banned'] += 1
            return None

        is_russian_entry = False
        entry_country = ''

        entry_info = get_ip_info(entry_ip, entry_ip_country_cache)
        entry_country = entry_info.get('country', '')

        if entry_country == 'RU' and exit_country != 'RU':
            is_russian_entry = True

        if not is_russian_entry:
            if cheburcheck_is_blocked(exit_ip):
                reject_stats['cheburcheck_blocked'] += 1
                return None
            sni = data.get('sni')
            if sni and sni != exit_ip and not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', sni):
                if cheburcheck_is_blocked(sni):
                    reject_stats['cheburcheck_blocked'] += 1
                    return None

        isp = api_data.get('org', 'Unknown')
        isp_clean = re.sub(r'^AS\d+\s+', '', isp)
        if re.search(BANNED_ISP_REGEX, isp_clean):
            reject_stats['isp_banned'] += 1
            return None

        gpt_ok = False
        try:
            gpt_r = requests.get(OPENAI_URL, proxies=proxies, timeout=5)
            if gpt_r.status_code in [200, 401]:
                gpt_ok = True
        except:
            pass

        flag = country_flag(exit_country)
        city = api_data.get('city', 'Unknown')
        gemini_ico = '✅' if exit_country in GEMINI_ALLOWED else '❌'
        yt_ico = '✅' if exit_country in YT_MUSIC_ALLOWED else '❌'
        gpt_ico = '✅' if gpt_ok else '❌'

        proto = data['protocol']
        proto_tag = ""
        if proto == 'hysteria2':
            proto_tag = "[HY2] "
        elif proto == 'tuic':
            proto_tag = "[TUIC] "
        elif proto == 'shadowsocks':
            proto_tag = "[SS] "
        elif proto == 'hysteria':
            proto_tag = "[HY1] "
        elif proto == 'anytls':
            proto_tag = "[AnyTLS] "
        elif proto == 'shadowtls':
            proto_tag = "[ShadowTLS] "
        elif proto in ('socks5', 'socks4', 'socks4a'):
            proto_tag = f"[{proto.upper()}] "
        elif proto == 'http':
            proto_tag = "[HTTP] "

        base_name = f"{proto_tag}{flag} {exit_country} - {city} ◈ {isp_clean} | 🎵YT_Music{yt_ico} ✨Gemini{gemini_ico} 🤖ChatGPT{gpt_ico}"
        name = f"⚠️ Anti-Whitelist 🇷🇺 RU -> {base_name}" if is_russian_entry else base_name

        new_link = rebuild_link(link, data, name)
        link_hash = hashlib.md5(new_link.encode('utf-8')).hexdigest()

        reject_stats['success'] += 1
        return (ping, new_link, link_hash, data, is_russian_entry)

    except Exception as e:
        if error_counter < 5:
            error_counter += 1
        reject_stats['other_error'] += 1
        return None
    finally:
        if proc:
            try:
                proc.terminate()
                proc.wait(timeout=1)
            except:
                proc.kill()
        if config_filename and os.path.exists(config_filename):
            try:
                os.remove(config_filename)
            except:
                pass

def get_ip_info(ip, cache, is_exit=False):
    if ip in cache:
        return cache[ip]

    info = {'country': '', 'org': ''}
    try:
        r = requests.get(f"http://ipinfo.io/{ip}/json", timeout=5)
        r.raise_for_status()
        d = r.json()
        info['country'] = d.get('country', '')
        info['org'] = d.get('org', '')
    except:
        try:
            r = requests.get(f"http://ip-api.com/json/{ip}?fields=country,isp", timeout=5)
            r.raise_for_status()
            d = r.json()
            info['country'] = d.get('country', '')
            info['org'] = d.get('isp', '')
        except:
            pass

    cache[ip] = info
    return info

def rebuild_link(original_link, data, new_name):
    if original_link.startswith('vmess://'):
        try:
            b64 = original_link[8:]
            conf = json.loads(safe_base64_decode(b64).decode('utf-8'))
            conf['ps'] = new_name
            new_b64 = base64.b64encode(json.dumps(conf).encode('utf-8')).decode('utf-8')
            return f"vmess://{new_b64}"
        except:
            pass
    base = original_link.split('#')[0]
    return f"{base}#{urllib.parse.quote(new_name)}"

# ========== ФИНАЛЬНАЯ ПРОВЕРКА ЧЕРЕЗ GATEWAY ==========
def check_proxy_via_gateway(link, data, gateway_host, gateway_port):
    """
    Проверяет прокси, используя gateway как первый hop.
    Возвращает (ping, new_link, link_hash) или None.
    """
    proc = None
    config_filename = None
    try:
        local_port = get_free_port()
        conf_str = generate_singbox_config(data, local_port, gateway=(gateway_host, gateway_port))
        if not conf_str:
            return None

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as config_file:
            config_file.write(conf_str)
            config_filename = config_file.name

        proc = subprocess.Popen([SING_BOX_PATH, "run", "-c", config_filename], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1.5)
        if proc.poll() is not None:
            return None

        proxies = {'http': f'socks5://127.0.0.1:{local_port}', 'https': f'socks5://127.0.0.1:{local_port}'}

        try:
            st = time.time()
            requests.get(TEST_URL, proxies=proxies, timeout=GATEWAY_CHECK_TIMEOUT)
            ping = int((time.time() - st) * 1000)
        except Exception:
            return None

        api_data = {}
        for _ in range(API_RETRIES):
            try:
                r = requests.get(IP_API_URL, proxies=proxies, timeout=GATEWAY_CHECK_TIMEOUT)
                if r.status_code == 200 and 'ip' in r.json():
                    api_data = r.json()
                    break
            except:
                pass

        if not api_data:
            try:
                r = requests.get(IP_API_FALLBACK_URL, proxies=proxies, timeout=GATEWAY_CHECK_TIMEOUT)
                if r.status_code == 200:
                    d = r.json()
                    api_data = {
                        'ip': d.get('query'),
                        'country': d.get('countryCode'),
                        'city': d.get('city'),
                        'org': d.get('isp')
                    }
            except:
                pass

        if not api_data:
            return None

        exit_country = api_data.get('country', 'XX')
        flag = country_flag(exit_country)
        city = api_data.get('city', 'Unknown')
        isp = api_data.get('org', 'Unknown')
        isp_clean = re.sub(r'^AS\d+\s+', '', isp)

        proto = data['protocol']
        proto_tag = ""
        if proto == 'hysteria2':
            proto_tag = "[HY2] "
        elif proto == 'tuic':
            proto_tag = "[TUIC] "
        elif proto == 'shadowsocks':
            proto_tag = "[SS] "
        elif proto == 'hysteria':
            proto_tag = "[HY1] "
        elif proto == 'anytls':
            proto_tag = "[AnyTLS] "
        elif proto == 'shadowtls':
            proto_tag = "[ShadowTLS] "
        elif proto in ('socks5', 'socks4', 'socks4a'):
            proto_tag = f"[{proto.upper()}] "
        elif proto == 'http':
            proto_tag = "[HTTP] "

        base_name = f"{proto_tag}{flag} {exit_country} - {city} ◈ {isp_clean}"
        name = f"✅ GATEWAY: {base_name}"

        new_link = rebuild_link(link, data, name)
        link_hash = hashlib.md5(new_link.encode('utf-8')).hexdigest()

        return (ping, new_link, link_hash)
    except Exception:
        return None
    finally:
        if proc:
            try:
                proc.terminate()
                proc.wait(timeout=1)
            except:
                proc.kill()
        if config_filename and os.path.exists(config_filename):
            try:
                os.remove(config_filename)
            except:
                pass

def deploy(links_content, pings_content):
    if not all([GH_TOKEN, GIST_ID, VERCEL_TOKEN, PROJ_ID]):
        print("Secrets missing.")
        return

    print("Updating Gist...")
    try:
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
    except Exception as e:
        print(f"Gist Error: {e}")
        return

    print("Triggering Vercel...")
    h = {"Authorization": f"Bearer {VERCEL_TOKEN}"}
    try:
        envs = requests.get(f"https://api.vercel.com/v9/projects/{PROJ_ID}/env", headers=h).json().get('envs', [])
        eid = next((e['id'] for e in envs if e['key'] == ENV_KEY), None)
        body = {"value": final_url, "target": ["production"], "type": "plain"}

        if eid:
            requests.patch(f"https://api.vercel.com/v9/projects/{PROJ_ID}/env/{eid}", headers=h, json=body)
        else:
            body['key'] = ENV_KEY
            requests.post(f"https://api.vercel.com/v10/projects/{PROJ_ID}/env", headers=h, json=body)

        proj = requests.get(f"https://api.vercel.com/v9/projects/{PROJ_ID}", headers=h).json()
        payload = {"name": proj.get('name'), "project": PROJ_ID, "target": "production"}

        if 'link' in proj and 'repoId' in proj['link']:
            payload['gitSource'] = {"type": "github", "ref": "main", "repoId": proj['link']['repoId']}

        requests.post("https://api.vercel.com/v13/deployments", headers=h, json=payload)
        print("Vercel OK.")
    except Exception as e:
        print(f"Vercel Error: {e}")

def main():
    if not os.path.exists(SING_BOX_PATH):
        print("Sing-box not found!")
        sys.exit(1)

    try:
        result = subprocess.run([SING_BOX_PATH, "version"], capture_output=True, text=True)
        print("Sing-box version:", result.stdout.strip())
    except Exception as e:
        print(f"Failed to run sing-box: {e}")
        sys.exit(1)

    load_rkn_lists()

    all_raw = scrape_all_sources()
    if not all_raw:
        return

    results = []
    seen_proxies.clear()

    with ThreadPoolExecutor(max_workers=MAX_WORKERS_CHECK) as exe:
        futures = {exe.submit(check_proxy, l): l for l in all_raw}
        for f in tqdm(as_completed(futures), total=len(all_raw), desc="Checking"):
            res = f.result()
            if res:
                results.append(res)

    print(f"\nWorking after first pass: {len(results)}")
    print("\nRejection statistics (first pass):")
    total_rejects = sum(v for k,v in reject_stats.items() if k not in ('success', 'gateway_filtered'))
    print(f"Total processed: {len(all_raw)}, Success: {reject_stats['success']}, Rejects: {total_rejects}")
    for reason, count in reject_stats.items():
        if count > 0:
            print(f"  {reason}: {count}")

    if not results:
        print("No working proxies after first pass.")
        return

    # ========== ФИНАЛЬНАЯ ПРОВЕРКА ЧЕРЕЗ GATEWAY ==========
    print("\nStarting final gateway check...")

    # Выбираем лучший antiwhitelist прокси (с наименьшим пингом и пометкой)
    gateway_result = None
    for res in sorted(results, key=lambda x: x[0]):
        if res[4]:  # is_russian_entry
            gateway_result = res
            break
    if not gateway_result:
        gateway_result = min(results, key=lambda x: x[0])
        print("No anti-whitelist proxy found, using fastest proxy as gateway.")
    else:
        print(f"Selected gateway: ping={gateway_result[0]} ms, link={gateway_result[1][:100]}...")

    # Запускаем gateway
    gateway_ping, gateway_link, gateway_hash, gateway_data, gateway_is_russian = gateway_result
    gateway_port = get_free_port()
    gateway_conf = generate_singbox_config(gateway_data, gateway_port)
    if not gateway_conf:
        print("Failed to generate gateway config!")
        return

    gateway_config_file = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False)
    gateway_config_file.write(gateway_conf)
    gateway_config_file.close()
    gateway_proc = subprocess.Popen([SING_BOX_PATH, "run", "-c", gateway_config_file.name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(2)
    if gateway_proc.poll() is not None:
        print("Gateway failed to start!")
        os.unlink(gateway_config_file.name)
        return

    print(f"Gateway started on port {gateway_port}")

    final_results = []
    other_results = [r for r in results if r != gateway_result]

    def check_one(r):
        ping, link, link_hash, data, is_russian = r
        res = check_proxy_via_gateway(link, data, "127.0.0.1", gateway_port)
        if res:
            return res
        else:
            reject_stats['gateway_filtered'] += 1
            return None

    with ThreadPoolExecutor(max_workers=MAX_WORKERS_FINAL) as exe:
        futures = {exe.submit(check_one, r): r for r in other_results}
        for f in tqdm(as_completed(futures), total=len(other_results), desc="Gateway check"):
            res = f.result()
            if res:
                final_results.append(res)

    gateway_proc.terminate()
    gateway_proc.wait(timeout=5)
    os.unlink(gateway_config_file.name)

    final_results.append((gateway_ping, gateway_link, gateway_hash))

    print(f"\nWorking after gateway check: {len(final_results)} (filtered out {reject_stats['gateway_filtered']})")

    final_results.sort(key=lambda x: x[0])

    final_links = []
    pings_map = {}
    for idx, (ping, link, old_hash) in enumerate(final_results):
        try:
            if link.startswith('vmess://'):
                b64 = link[8:]
                data = json.loads(safe_base64_decode(b64).decode('utf-8'))
                old_name = data.get('ps', '')
                data['ps'] = f"{idx+1}. {old_name}"
                new_b64 = base64.b64encode(json.dumps(data).encode('utf-8')).decode('utf-8')
                new_link = f"vmess://{new_b64}"
            else:
                parts = link.split('#')
                base = parts[0]
                old_name = urllib.parse.unquote(parts[1]) if len(parts) > 1 else ""
                new_name = f"{idx+1} - {old_name}"
                new_link = f"{base}#{urllib.parse.quote(new_name)}"

            final_links.append(new_link)
            new_hash = hashlib.md5(new_link.encode('utf-8')).hexdigest()
            pings_map[new_hash] = ping
        except Exception as e:
            print(f"Error numbering link {idx+1}: {e}")
            final_links.append(link)
            pings_map[old_hash] = ping

    links_str = "\n".join(final_links)
    pings_json = json.dumps(pings_map)
    deploy(links_str, pings_json)

if __name__ == "__main__":
    main()
