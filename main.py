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
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm

# ================= 1. КОНФИГУРАЦИЯ =================

# ИСПРАВЛЕННАЯ ССЫЛКА (убрано refs/heads)
NEW_SOURCE_URL = "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/main/githubmirror/26.txt"

# Настройки Sing-box
SING_BOX_PATH = "./sing-box"
MAX_WORKERS = 40
TIMEOUT = 10
API_RETRIES = 2
API_RETRY_DELAY = 1

# Secrets
GH_TOKEN = os.environ.get("GH_TOKEN")
GIST_ID = os.environ.get("GIST_ID")
VERCEL_TOKEN = os.environ.get("VERCEL_TOKEN")
PROJ_ID = os.environ.get("PROJ_ID")

GIST_FILENAME = "gistfile1.txt"
ENV_KEY = "GIST_URL"

# API проверки
IP_API_URL = "http://ipinfo.io/json"
TEST_URL = "http://www.gstatic.com/generate_204"

# Фильтры
BANNED_ISP_REGEX = r"(?i)(hetzner|cloudflare|pq hosting)"

GEMINI_ALLOWED_COUNTRY_CODES = {'AL', 'DZ', 'AS', 'AO', 'AI', 'AQ', 'AG', 'AR', 'AM', 'AW', 'AU', 'AT', 'AZ', 'BS', 'BH', 'BD', 'BB', 'BE', 'BZ', 'BJ', 'BM', 'BT', 'BO', 'BA', 'BW', 'BR', 'IO', 'VG', 'BN', 'BG', 'BF', 'BI', 'CV', 'KH', 'CM', 'CA', 'BQ', 'KY', 'CF', 'TD', 'CL', 'CX', 'CC', 'CO', 'KM', 'CK', 'CI', 'CR', 'HR', 'CW', 'CZ', 'CD', 'DK', 'DJ', 'DM', 'DO', 'EC', 'EG', 'SV', 'GQ', 'ER', 'EE', 'SZ', 'ET', 'FK', 'FO', 'FJ', 'FI', 'FR', 'GA', 'GM', 'GE', 'DE', 'GH', 'GI', 'GR', 'GL', 'GD', 'GU', 'GT', 'GG', 'GN', 'GW', 'GY', 'HT', 'HM', 'HN', 'HU', 'IS', 'IN', 'ID', 'IQ', 'IE', 'IM', 'IL', 'IT', 'JM', 'JP', 'JE', 'JO', 'KZ', 'KE', 'KI', 'XK', 'KG', 'KW', 'LA', 'LV', 'LB', 'LS', 'LR', 'LY', 'LI', 'LT', 'LU', 'MG', 'MW', 'MY', 'MV', 'ML', 'MT', 'MH', 'MR', 'MU', 'MX', 'FM', 'MN', 'ME', 'MS', 'MA', 'MZ', 'NA', 'NR', 'NP', 'NL', 'NC', 'NZ', 'NI', 'NE', 'NG', 'NU', 'NF', 'MK', 'MP', 'NO', 'OM', 'PK', 'PW', 'PS', 'PA', 'PG', 'PY', 'PE', 'PH', 'PN', 'PL', 'PT', 'PR', 'QA', 'CY', 'CG', 'RO', 'RW', 'BL', 'KN', 'LC', 'PM', 'VC', 'SH', 'WS', 'ST', 'SA', 'SN', 'RS', 'SC', 'SL', 'SG', 'SK', 'SI', 'SB', 'SO', 'ZA', 'GS', 'KR', 'SS', 'ES', 'LK', 'SD', 'SR', 'SE', 'CH', 'TW', 'TJ', 'TZ', 'TH', 'TL', 'TG', 'TK', 'TO', 'TT', 'TN', 'TR', 'TM', 'TC', 'TV', 'UG', 'UA', 'GB', 'AE', 'US', 'UM', 'VI', 'UY', 'UZ', 'VU', 'VE', 'VN', 'WF', 'EH', 'YE', 'ZM', 'ZW'}
YT_MUSIC_ALLOWED_COUNTRY_CODES = {'DZ', 'AS', 'AR', 'AW', 'AU', 'AT', 'AZ', 'BH', 'BD', 'BY', 'BE', 'BM', 'BO', 'BA', 'BR', 'BG', 'KH', 'CA', 'KY', 'CL', 'CO', 'CR', 'HR', 'CY', 'CZ', 'DK', 'DO', 'EC', 'EG', 'SV', 'EE', 'FI', 'FR', 'GF', 'PF', 'GE', 'DE', 'GH', 'GR', 'GP', 'GU', 'GT', 'HN', 'HK', 'HU', 'IS', 'IN', 'ID', 'IQ', 'IE', 'IL', 'IT', 'JM', 'JP', 'JO', 'KZ', 'KE', 'KW', 'LA', 'LV', 'LB', 'LY', 'LI', 'LT', 'LU', 'MY', 'MT', 'MX', 'MA', 'NP', 'NL', 'NZ', 'NI', 'NG', 'MK', 'MP', 'NO', 'OM', 'PK', 'PA', 'PG', 'PY', 'PE', 'PH', 'PL', 'PT', 'PR', 'QA', 'RE', 'RO', 'RU', 'SA', 'SN', 'RS', 'SG', 'SK', 'SI', 'ZA', 'KR', 'ES', 'LK', 'SE', 'CH', 'TW', 'TZ', 'TH', 'TN', 'TR', 'TC', 'VI', 'UG', 'UA', 'AE', 'GB', 'US', 'UY', 'VE', 'VN', 'YE', 'ZW'}

# ================= 2. ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ =================

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

# ================= 3. ПАРСЕРЫ =================

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
        if link.startswith('hysteria2://') or link.startswith('hy2://'): return parse_hysteria2(link)
        if link.startswith('tuic://'): return {'type': 'tuic', 'server': 'skip', 'port': 0} # Заглушка, чтобы не падало
    except: return None
    return None

# ================= 4. SING-BOX CONFIG =================

def generate_singbox_config(data, local_port):
    if data['type'] == 'tuic': return None # Временно пропускаем TUIC
    
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

    elif data['type'] == 'hysteria2':
        outbound.update({ "server": data['server'], "server_port": data['port'], "password": data['password'], "tls": {"enabled": True, "server_name": data.get('sni', ''), "insecure": data.get('insecure', True)} })
        if data.get('obfs'): outbound['obfs'] = {"type": data['obfs'], "password": data.get('obfs_password', '')}

    config['outbounds'].append(outbound)
    return json.dumps(config)

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

# ================= 5. ЗАГРУЗКА ИСТОЧНИКОВ =================

def get_links_from_url(url, is_gist=False):
    print(f"Downloading: {url}...")
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }
    if is_gist and GH_TOKEN:
         headers['Authorization'] = f'token {GH_TOKEN}'
    
    try:
        if is_gist and 'api.github.com/gists' in url:
             r = requests.get(url, headers=headers, timeout=20)
             r.raise_for_status()
             files = r.json().get('files', {})
             if not files: return []
             content = list(files.values())[0]['content']
        else:
             r = requests.get(url, headers=headers, timeout=20)
             r.raise_for_status()
             content = r.text

        # ЛОГИКА ОПРЕДЕЛЕНИЯ ФОРМАТА
        # 1. Пробуем как обычный текст
        lines = content.splitlines()
        valid_count = sum(1 for l in lines if l.strip().startswith(('vmess://', 'vless://', 'trojan://', 'hy2://', 'hysteria2://')))
        
        if valid_count > 0:
            print(f"  -> Detected Plain Text ({valid_count} potential links)")
            return lines

        # 2. Если не похоже на текст, пробуем Base64
        print(f"  -> Plain text check failed (found {valid_count} links). Trying Base64...")
        try:
            decoded = safe_base64_decode(content).decode('utf-8', errors='ignore')
            lines = decoded.splitlines()
            print(f"  -> Base64 decode successful ({len(lines)} lines)")
            return lines
        except Exception as e:
            print(f"  -> Base64 failed: {e}")
            return []
            
    except Exception as e:
        print(f"Error fetching {url}: {e}")
        return []

def fetch_all_sources():
    all_links = set()
    
    # New Source
    new_links = get_links_from_url(NEW_SOURCE_URL)
    all_links.update([l.strip() for l in new_links if l.strip()])
    
    # Old Gist
    if GIST_ID:
        gist_links = get_links_from_url(f"https://api.github.com/gists/{GIST_ID}", is_gist=True)
        all_links.update([l.strip() for l in gist_links if l.strip()])
    
    valid_links = []
    for link in all_links:
        if link.startswith(('vmess://', 'vless://', 'trojan://', 'hy2://', 'hysteria2://')):
             valid_links.append(link)
             
    print(f"Total unique valid links to check: {len(valid_links)}")
    return valid_links

# ================= 6. ПРОВЕРКА =================

seen_proxies = set()

def check_proxy(link):
    proc = None
    config_file = None
    try:
        data = parse_link(link)
        if not data: return None
        
        # Строгая фильтрация SS/SSR
        if data['type'] in ['shadowsocks', 'shadowsocksr', 'ss', 'ssr']: return None

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
        time.sleep(2)
        if proc.poll() is not None: return None

        proxies = {'http': f'socks5://127.0.0.1:{local_port}', 'https': f'socks5://127.0.0.1:{local_port}'}
        
        # 1. Ping
        start_time = time.time()
        try:
            requests.get(TEST_URL, proxies=proxies, timeout=TIMEOUT)
            ping = int((time.time() - start_time) * 1000)
        except: return None 

        # 2. IP Info
        api_data = {}
        for _ in range(API_RETRIES):
            try:
                r = requests.get(IP_API_URL, proxies=proxies, timeout=TIMEOUT)
                if r.status_code == 200:
                    api_data = r.json()
                    break
            except: pass
            time.sleep(API_RETRY_DELAY)

        cc = api_data.get('country', 'XX')
        
        # Filters
        if cc == 'RU' or cc == 'XX': return None
        
        isp = api_data.get('org', 'Unknown ISP')
        isp_clean = re.sub(r'^AS\d+\s+', '', isp)
        if re.search(BANNED_ISP_REGEX, isp_clean): return None

        # Renaming
        city = api_data.get('city', 'Unknown')
        flag = country_flag(cc)
        
        gemini_icon = '✅' if cc in GEMINI_ALLOWED_COUNTRY_CODES else '❌'
        yt_icon = '✅' if cc in YT_MUSIC_ALLOWED_COUNTRY_CODES else '❌'

        clean_name = f"{flag} {cc} - {city} ◈ {isp_clean} | 🎵YT_Music{yt_icon} ✨Gemini{gemini_icon}"
        final_link = rebuild_link(link, data, clean_name)
        
        return (ping, final_link)

    except: return None
    finally:
        if proc:
            try: proc.terminate(); proc.wait(timeout=1)
            except: proc.kill()
        if config_file and os.path.exists(config_file.name):
            try: os.remove(config_file.name)
            except: pass

# ================= 7. DEPLOY =================

def deploy(content):
    if not GH_TOKEN or not GIST_ID or not VERCEL_TOKEN or not PROJ_ID:
        print("Secrets missing, skipping deploy.")
        return

    print("Updating Gist...")
    try:
        r = requests.patch(
            f'https://api.github.com/gists/{GIST_ID}',
            headers={'Authorization': f'token {GH_TOKEN}'},
            json={'files': {GIST_FILENAME: {'content': content}}, 'description': f'Updated: {time.strftime("%Y-%m-%d %H:%M:%S UTC")}'}
        )
        r.raise_for_status()
        raw_url = r.json()['files'][GIST_FILENAME]['raw_url']
        print("Gist updated.")
        
        # Update Vercel
        print("Updating Vercel...")
        headers_v = {"Authorization": f"Bearer {VERCEL_TOKEN}"}
        envs = requests.get(f"https://api.vercel.com/v9/projects/{PROJ_ID}/env", headers=headers_v).json().get('envs', [])
        eid = next((e['id'] for e in envs if e['key'] == ENV_KEY), None)
        body = {"value": f"{raw_url}?t={int(time.time())}", "target": ["production", "preview", "development"], "type": "plain"}
        
        if eid: requests.patch(f"https://api.vercel.com/v9/projects/{PROJ_ID}/env/{eid}", headers=headers_v, json=body)
        else: 
            body['key'] = ENV_KEY
            requests.post(f"https://api.vercel.com/v10/projects/{PROJ_ID}/env", headers=headers_v, json=body)

        # Trigger Deploy
        proj = requests.get(f"https://api.vercel.com/v9/projects/{PROJ_ID}", headers=headers_v).json()
        payload = {"name": proj.get('name'), "project": PROJ_ID, "target": "production"}
        if 'link' in proj and 'repoId' in proj['link']:
            payload['gitSource'] = {"type": "github", "ref": "main", "repoId": proj['link']['repoId']}
        requests.post("https://api.vercel.com/v13/deployments", headers=headers_v, json=payload)
        print("Deploy triggered successfully.")
        
    except Exception as e:
        print(f"Deploy failed: {e}")

# ================= MAIN =================

if __name__ == "__main__":
    if not os.path.exists(SING_BOX_PATH):
        print("Sing-box binary not found.")
        sys.exit(1)
    os.chmod(SING_BOX_PATH, 0o755)

    links = fetch_all_sources()
    
    if not links:
        print("No links to check.")
        sys.exit(0)

    results = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(check_proxy, link): link for link in links}
        for future in tqdm(as_completed(futures), total=len(links), desc="Checking"):
            res = future.result()
            if res: results.append(res)

    print(f"\nWorking proxies: {len(results)}")
    
    if results:
        results.sort(key=lambda x: x[0])
        final_content = "\n".join([x[1] for x in results])
        deploy(final_content)
    else:
        print("No working proxies found.")
