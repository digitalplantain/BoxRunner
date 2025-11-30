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

NEW_SOURCE_URL = "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/main/githubmirror/26.txt"
XRAY_PATH = "./xray"

# Xray требует ресурсов, ставим разумное число потоков
MAX_WORKERS = 25       
TIMEOUT = 10           
API_RETRIES = 2

# Secrets
GH_TOKEN = os.environ.get("GH_TOKEN")
GIST_ID = os.environ.get("GIST_ID")
VERCEL_TOKEN = os.environ.get("VERCEL_TOKEN")
PROJ_ID = os.environ.get("PROJ_ID")

GIST_FILENAME = "gistfile1.txt"
ENV_KEY = "GIST_URL"

# API
IP_API_URL = "http://ip-api.com/json/?fields=status,country,countryCode,city,isp,org"
TEST_URL = "http://www.gstatic.com/generate_204"

# Фильтры
BANNED_ISP_REGEX = r"(?i)(hetzner|cloudflare|pq hosting|contabo|digitalocean|amazon|google|microsoft|oracle)"

# Списки стран
GEMINI_ALLOWED = {'AL', 'DZ', 'AS', 'AO', 'AI', 'AQ', 'AG', 'AR', 'AM', 'AW', 'AU', 'AT', 'AZ', 'BS', 'BH', 'BD', 'BB', 'BE', 'BZ', 'BJ', 'BM', 'BT', 'BO', 'BA', 'BW', 'BR', 'IO', 'VG', 'BN', 'BG', 'BF', 'BI', 'CV', 'KH', 'CM', 'CA', 'BQ', 'KY', 'CF', 'TD', 'CL', 'CX', 'CC', 'CO', 'KM', 'CK', 'CI', 'CR', 'HR', 'CW', 'CZ', 'CD', 'DK', 'DJ', 'DM', 'DO', 'EC', 'EG', 'SV', 'GQ', 'ER', 'EE', 'SZ', 'ET', 'FK', 'FO', 'FJ', 'FI', 'FR', 'GA', 'GM', 'GE', 'DE', 'GH', 'GI', 'GR', 'GL', 'GD', 'GU', 'GT', 'GG', 'GN', 'GW', 'GY', 'HT', 'HM', 'HN', 'HU', 'IS', 'IN', 'ID', 'IQ', 'IE', 'IM', 'IL', 'IT', 'JM', 'JP', 'JE', 'JO', 'KZ', 'KE', 'KI', 'XK', 'KG', 'KW', 'LA', 'LV', 'LB', 'LS', 'LR', 'LY', 'LI', 'LT', 'LU', 'MG', 'MW', 'MY', 'MV', 'ML', 'MT', 'MH', 'MR', 'MU', 'MX', 'FM', 'MN', 'ME', 'MS', 'MA', 'MZ', 'NA', 'NR', 'NP', 'NL', 'NC', 'NZ', 'NI', 'NE', 'NG', 'NU', 'NF', 'MK', 'MP', 'NO', 'OM', 'PK', 'PW', 'PS', 'PA', 'PG', 'PY', 'PE', 'PH', 'PN', 'PL', 'PT', 'PR', 'QA', 'CY', 'CG', 'RO', 'RW', 'BL', 'KN', 'LC', 'PM', 'VC', 'SH', 'WS', 'ST', 'SA', 'SN', 'RS', 'SC', 'SL', 'SG', 'SK', 'SI', 'SB', 'SO', 'ZA', 'GS', 'KR', 'SS', 'ES', 'LK', 'SD', 'SR', 'SE', 'CH', 'TW', 'TJ', 'TZ', 'TH', 'TL', 'TG', 'TK', 'TO', 'TT', 'TN', 'TR', 'TM', 'TC', 'TV', 'UG', 'UA', 'GB', 'AE', 'US', 'UM', 'VI', 'UY', 'UZ', 'VU', 'VE', 'VN', 'WF', 'EH', 'YE', 'ZM', 'ZW'}
YT_MUSIC_ALLOWED = {'DZ', 'AS', 'AR', 'AW', 'AU', 'AT', 'AZ', 'BH', 'BD', 'BY', 'BE', 'BM', 'BO', 'BA', 'BR', 'BG', 'KH', 'CA', 'KY', 'CL', 'CO', 'CR', 'HR', 'CY', 'CZ', 'DK', 'DO', 'EC', 'EG', 'SV', 'EE', 'FI', 'FR', 'GF', 'PF', 'GE', 'DE', 'GH', 'GR', 'GP', 'GU', 'GT', 'HN', 'HK', 'HU', 'IS', 'IN', 'ID', 'IQ', 'IE', 'IL', 'IT', 'JM', 'JP', 'JO', 'KZ', 'KE', 'KW', 'LA', 'LV', 'LB', 'LY', 'LI', 'LT', 'LU', 'MY', 'MT', 'MX', 'MA', 'NP', 'NL', 'NZ', 'NI', 'NG', 'MK', 'MP', 'NO', 'OM', 'PK', 'PA', 'PG', 'PY', 'PE', 'PH', 'PL', 'PT', 'PR', 'QA', 'RE', 'RO', 'RU', 'SA', 'SN', 'RS', 'SG', 'SK', 'SI', 'ZA', 'KR', 'ES', 'LK', 'SE', 'CH', 'TW', 'TZ', 'TH', 'TN', 'TR', 'TC', 'VI', 'UG', 'UA', 'AE', 'GB', 'US', 'UY', 'VE', 'VN', 'YE', 'ZW'}

# ================= 2. ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ =================

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

# ================= 3. ЛОГИКА XRAY =================

def parse_proxy_link(link):
    try:
        if link.startswith('vmess://'):
            data = json.loads(safe_base64_decode(link[8:]).decode('utf-8'))
            data['protocol'] = 'vmess'
            return data
        
        parsed = urllib.parse.urlparse(link)
        protocol = parsed.scheme
        
        if protocol == 'ss': return {'protocol': 'shadowsocks'} 
        if protocol not in ['vless', 'trojan']: return None

        data = {'protocol': protocol, 'address': parsed.hostname, 'port': parsed.port}
        data['id'] = data['password'] = parsed.username
        
        query = urllib.parse.parse_qs(parsed.query)
        for k, v in query.items(): data[k.lower()] = v[0]
        
        data['sni'] = data.get('sni', data.get('host', ''))
        return data
    except: return None

def generate_xray_config(proxy_data, local_port):
    protocol = proxy_data['protocol']
    config = {
        "log": {"loglevel": "error"}, # Логируем ошибки
        "inbounds": [{"port": local_port,"listen": "127.0.0.1","protocol": "socks","settings": {"auth": "noauth", "udp": True}}],
        "outbounds": [{"protocol": protocol, "settings": {}, "streamSettings": {}}]
    }
    setts = config['outbounds'][0]['settings']
    stream = config['outbounds'][0]['streamSettings']
    
    port = int(proxy_data.get('port', 443))
    
    if protocol == 'vmess':
        setts['vnext'] = [{"address": proxy_data.get('add'), "port": port, "users": [{"id": proxy_data.get('id'), "alterId": int(proxy_data.get('aid', 0)), "security": proxy_data.get('scy', 'auto')}]}]
    elif protocol == 'vless':
        setts['vnext'] = [{"address": proxy_data.get('address'), "port": port, "users": [{"id": proxy_data.get('id'), "flow": proxy_data.get('flow', ''), "encryption": "none"}]}]
    elif protocol == 'trojan':
        setts['servers'] = [{"address": proxy_data.get('address'), "port": port, "password": proxy_data.get('password')}]
    
    stream['network'] = proxy_data.get('net', proxy_data.get('type', 'tcp'))
    security = proxy_data.get('tls', proxy_data.get('security', ''))
    stream['security'] = security
    
    if security in ['tls', 'reality']:
        sni = proxy_data.get('sni') or proxy_data.get('host') or proxy_data.get('add') or proxy_data.get('address')
        tls = {"serverName": sni, "allowInsecure": True}
        if security == 'reality':
            tls["reality"] = {"publicKey": proxy_data.get('pbk', ''), "shortId": proxy_data.get('sid', '')}
        if proxy_data.get('fp'): tls['fingerprint'] = proxy_data['fp']
        stream['tlsSettings'] = tls

    if stream['network'] == 'ws':
        host = proxy_data.get('host') or proxy_data.get('sni')
        stream['wsSettings'] = {"path": proxy_data.get('path', '/'), "headers": {"Host": host}}
    elif stream['network'] == 'grpc':
        stream['grpcSettings'] = {"serviceName": proxy_data.get('serviceName', '')}
        
    return json.dumps(config)

def rebuild_link(original_link, data, new_name):
    if original_link.startswith('vmess://'):
        try:
            b64 = original_link[8:]
            conf = json.loads(safe_base64_decode(b64).decode('utf-8'))
            conf['ps'] = new_name
            new_b64 = base64.b64encode(json.dumps(conf).encode('utf-8')).decode('utf-8')
            return f"vmess://{new_b64}"
        except: pass
    
    base = original_link.split('#')[0]
    return f"{base}#{urllib.parse.quote(new_name)}"

# ================= 4. ЗАГРУЗКА ИСТОЧНИКОВ =================

def fetch_links(url, is_gist=False):
    print(f"Downloading: {url}...")
    headers = {'User-Agent': 'Mozilla/5.0'}
    if is_gist and GH_TOKEN: headers['Authorization'] = f'token {GH_TOKEN}'
    
    try:
        if is_gist and 'api.github.com' in url:
            r = requests.get(url, headers=headers); r.raise_for_status()
            files = r.json().get('files', {})
            if not files: return []
            content = list(files.values())[0]['content']
        else:
            r = requests.get(url, headers=headers); r.raise_for_status()
            content = r.text
        
        links = [l.strip() for l in content.splitlines() if l.strip()]
        valid = [l for l in links if l.startswith(('vmess://', 'vless://', 'trojan://'))]
        
        if len(valid) > 0:
            print(f"  -> Found {len(valid)} links (Text)")
            return valid
        
        decoded = safe_base64_decode(content).decode('utf-8', errors='ignore')
        links_b64 = [l.strip() for l in decoded.splitlines() if l.strip() and l.startswith(('vmess://', 'vless://', 'trojan://'))]
        print(f"  -> Found {len(links_b64)} links (Base64)")
        return links_b64
        
    except Exception as e:
        print(f"  -> Error: {e}")
        return []

# ================= 5. ПРОВЕРКА =================

seen_proxies = set()
error_counter = 0

def check_proxy(link):
    global error_counter
    proc = None
    config_file = None
    try:
        data = parse_proxy_link(link)
        if not data: return None
        
        if data.get('protocol') in ['shadowsocks', 'ss']: return None 
        
        addr = data.get('address') or data.get('add')
        port = data.get('port')
        identifier = f"{addr}:{port}"
        
        if identifier in seen_proxies: return None
        seen_proxies.add(identifier)

        local_port = get_free_port()
        conf_str = generate_xray_config(data, local_port)
        
        config_file = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False)
        config_file.write(conf_str)
        config_file.close()

        # Запускаем Xray
        proc = subprocess.Popen([XRAY_PATH, "run", "-c", config_file.name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1.5)
        
        if proc.poll() is not None:
            # Если Xray упал сразу, это проблема конфига
            return None

        proxies = {'http': f'socks5://127.0.0.1:{local_port}', 'https': f'socks5://127.0.0.1:{local_port}'}

        # 1. PING
        st = time.time()
        requests.get(TEST_URL, proxies=proxies, timeout=TIMEOUT)
        ping = int((time.time() - st) * 1000)

        # 2. GEO
        info = {}
        for _ in range(API_RETRIES):
            try:
                r = requests.get(IP_API_URL, proxies=proxies, timeout=TIMEOUT)
                if r.status_code == 200 and r.json().get('status') == 'success':
                    info = r.json()
                    break
            except: pass
            time.sleep(1)
        
        if not info: return None
        
        cc = info.get('countryCode', 'XX')
        if cc == 'RU' or cc == 'XX': return None
        
        isp = info.get('isp') or info.get('org') or 'Unknown'
        if re.search(BANNED_ISP_REGEX, isp): return None

        flag = country_flag(cc)
        city = info.get('city', 'Unknown')
        
        gemini_ico = '✅' if cc in GEMINI_ALLOWED else '❌'
        yt_ico = '✅' if cc in YT_MUSIC_ALLOWED else '❌'
        
        name = f"{flag} {cc} - {city} ◈ {isp} | 🎵YT_Music{yt_ico} ✨Gemini{gemini_ico}"
        new_link = rebuild_link(link, data, name)
        
        return (ping, new_link)

    except Exception as e:
        # ЛОГИРУЕМ ОШИБКУ (только первые 5 раз)
        if error_counter < 5:
            print(f"\n[ERROR DEBUG] Link failed: {e}")
            error_counter += 1
        return None
    finally:
        if proc: 
            try: proc.terminate(); proc.wait(timeout=1)
            except: proc.kill()
        if config_file and os.path.exists(config_file.name):
            try: os.remove(config_file.name)
            except: pass

# ================= 6. DEPLOY =================

def deploy(content):
    if not all([GH_TOKEN, GIST_ID, VERCEL_TOKEN, PROJ_ID]):
        print("Secrets missing, skipping deploy.")
        return

    print("Updating Gist...")
    try:
        r = requests.patch(
            f'https://api.github.com/gists/{GIST_ID}',
            headers={'Authorization': f'token {GH_TOKEN}'},
            json={'files': {GIST_FILENAME: {'content': content}}, 'description': f'Xray Updated: {time.strftime("%Y-%m-%d %H:%M UTC")}'}
        )
        r.raise_for_status()
        raw_url = r.json()['files'][GIST_FILENAME]['raw_url']
        final_url = f"{raw_url}?t={int(time.time())}"
        print("Gist updated successfully.")
    except Exception as e:
        print(f"Gist Error: {e}")
        return

    print("Triggering Vercel...")
    h = {"Authorization": f"Bearer {VERCEL_TOKEN}"}
    try:
        envs = requests.get(f"https://api.vercel.com/v9/projects/{PROJ_ID}/env", headers=h).json().get('envs', [])
        eid = next((e['id'] for e in envs if e['key'] == ENV_KEY), None)
        
        body = {"value": final_url, "target": ["production", "preview", "development"], "type": "plain"}
        
        if eid: requests.patch(f"https://api.vercel.com/v9/projects/{PROJ_ID}/env/{eid}", headers=h, json=body)
        else: body['key'] = ENV_KEY; requests.post(f"https://api.vercel.com/v10/projects/{PROJ_ID}/env", headers=h, json=body)

        proj = requests.get(f"https://api.vercel.com/v9/projects/{PROJ_ID}", headers=h).json()
        payload = {"name": proj.get('name'), "project": PROJ_ID, "target": "production"}
        
        if 'link' in proj and 'repoId' in proj['link']:
            payload['gitSource'] = {"type": "github", "ref": "main", "repoId": proj['link']['repoId']}
            
        requests.post("https://api.vercel.com/v13/deployments", headers=h, json=payload)
        print("Vercel deploy triggered.")
    except Exception as e: 
        print(f"Vercel Error: {e}")


def main():
    if not os.path.exists(XRAY_PATH):
        print("Xray executable not found!")
        sys.exit(1)
    
    links_new = fetch_links(NEW_SOURCE_URL)
    links_old = []
    if GIST_ID:
        links_old = fetch_links(f"https://api.github.com/gists/{GIST_ID}", is_gist=True)
    
    all_raw_links = list(set(links_new + links_old))
    print(f"Total unique raw links: {len(all_raw_links)}")
    
    if not all_raw_links: return

    results = []
    seen_proxies.clear()
    
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as exe:
        futures = {exe.submit(check_proxy, l): l for l in all_raw_links}
        for f in tqdm(as_completed(futures), total=len(all_raw_links), desc="Checking"):
            res = f.result()
            if res: results.append(res)
    
    print(f"\nWorking proxies found: {len(results)}")
    
    if results:
        results.sort(key=lambda x: x[0])
        final_content = "\n".join([r[1] for r in results])
        deploy(final_content)
    else:
        print("No working proxies passed filters.")

if __name__ == "__main__":
    main()
