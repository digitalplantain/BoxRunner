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

# ================= 1. КОНФИГУРАЦИЯ =================

NEW_SOURCE_URL = "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/main/githubmirror/26.txt"
SING_BOX_PATH = "./sing-box"

MAX_WORKERS = 25       
TIMEOUT = 10           
API_RETRIES = 2

# Secrets
GH_TOKEN = os.environ.get("GH_TOKEN")
GIST_ID = os.environ.get("GIST_ID")
VERCEL_TOKEN = os.environ.get("VERCEL_TOKEN")
PROJ_ID = os.environ.get("PROJ_ID")

GIST_FILENAME = "gistfile1.txt"
PING_FILENAME = "pings.json"
ENV_KEY = "GIST_URL"

# API & Test URLs
IP_API_URL = "http://ipinfo.io/json"
TEST_URL = "http://www.gstatic.com/generate_204"
CHATGPT_URL = "https://chatgpt.com"  # <--- НОВАЯ ЦЕЛЬ ДЛЯ ПРОВЕРКИ

# Фильтры
BANNED_ISP_REGEX = r"(?i)(hetzner|cloudflare|pq hosting|contabo|digitalocean|amazon|google|microsoft|oracle)"

GEMINI_ALLOWED = {'AL', 'DZ', 'AS', 'AO', 'AI', 'AQ', 'AG', 'AR', 'AM', 'AW', 'AU', 'AT', 'AZ', 'BS', 'BH', 'BD', 'BB', 'BE', 'BZ', 'BJ', 'BM', 'BT', 'BO', 'BA', 'BW', 'BR', 'IO', 'VG', 'BN', 'BG', 'BF', 'BI', 'CV', 'KH', 'CM', 'CA', 'BQ', 'KY', 'CF', 'TD', 'CL', 'CX', 'CC', 'CO', 'KM', 'CK', 'CI', 'CR', 'HR', 'CW', 'CZ', 'CD', 'DK', 'DJ', 'DM', 'DO', 'EC', 'EG', 'SV', 'GQ', 'ER', 'EE', 'SZ', 'ET', 'FK', 'FO', 'FJ', 'FI', 'FR', 'GA', 'GM', 'GE', 'DE', 'GH', 'GI', 'GR', 'GL', 'GD', 'GU', 'GT', 'GG', 'GN', 'GW', 'GY', 'HT', 'HM', 'HN', 'HU', 'IS', 'IN', 'ID', 'IQ', 'IE', 'IM', 'IL', 'IT', 'JM', 'JP', 'JE', 'JO', 'KZ', 'KE', 'KI', 'XK', 'KG', 'KW', 'LA', 'LV', 'LB', 'LS', 'LR', 'LY', 'LI', 'LT', 'LU', 'MG', 'MW', 'MY', 'MV', 'ML', 'MT', 'MH', 'MR', 'MU', 'MX', 'FM', 'MN', 'ME', 'MS', 'MA', 'MZ', 'NA', 'NR', 'NP', 'NL', 'NC', 'NZ', 'NI', 'NE', 'NG', 'NU', 'NF', 'MK', 'MP', 'NO', 'OM', 'PK', 'PW', 'PS', 'PA', 'PG', 'PY', 'PE', 'PH', 'PN', 'PL', 'PT', 'PR', 'QA', 'CY', 'CG', 'RO', 'RW', 'BL', 'KN', 'LC', 'PM', 'VC', 'SH', 'WS', 'ST', 'SA', 'SN', 'RS', 'SC', 'SL', 'SG', 'SK', 'SI', 'SB', 'SO', 'ZA', 'GS', 'KR', 'SS', 'ES', 'LK', 'SD', 'SR', 'SE', 'CH', 'TW', 'TJ', 'TZ', 'TH', 'TL', 'TG', 'TK', 'TO', 'TT', 'TN', 'TR', 'TM', 'TC', 'TV', 'UG', 'UA', 'GB', 'AE', 'US', 'UM', 'VI', 'UY', 'UZ', 'VU', 'VE', 'VN', 'WF', 'EH', 'YE', 'ZM', 'ZW'}
YT_MUSIC_ALLOWED = {'DZ', 'AS', 'AR', 'AW', 'AU', 'AT', 'AZ', 'BH', 'BD', 'BY', 'BE', 'BM', 'BO', 'BA', 'BR', 'BG', 'KH', 'CA', 'KY', 'CL', 'CO', 'CR', 'HR', 'CY', 'CZ', 'DK', 'DO', 'EC', 'EG', 'SV', 'EE', 'FI', 'FR', 'GF', 'PF', 'GE', 'DE', 'GH', 'GR', 'GP', 'GU', 'GT', 'HN', 'HK', 'HU', 'IS', 'IN', 'ID', 'IQ', 'IE', 'IL', 'IT', 'JM', 'JP', 'JO', 'KZ', 'KE', 'KW', 'LA', 'LV', 'LB', 'LY', 'LI', 'LT', 'LU', 'MY', 'MT', 'MX', 'MA', 'NP', 'NL', 'NZ', 'NI', 'NG', 'MK', 'MP', 'NO', 'OM', 'PK', 'PA', 'PG', 'PY', 'PE', 'PH', 'PL', 'PT', 'PR', 'QA', 'RE', 'RO', 'RU', 'SA', 'SN', 'RS', 'SG', 'SK', 'SI', 'ZA', 'KR', 'ES', 'LK', 'SE', 'CH', 'TW', 'TZ', 'TH', 'TN', 'TR', 'TC', 'VI', 'UG', 'UA', 'AE', 'GB', 'US', 'UY', 'VE', 'VN', 'YE', 'ZW'}

# Остальные функции (get_free_port, country_flag, etc.) остаются без изменений
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

# ================= 3. ПАРСИНГ И КОНФИГ SING-BOX =================

def parse_proxy_link(link):
    try:
        if link.startswith('vmess://'):
            data = json.loads(safe_base64_decode(link[8:]).decode('utf-8'))
            data['protocol'] = 'vmess'
            data['uuid'] = data.get('id')
            data['server'] = data.get('add')
            data['port'] = int(data.get('port'))
            return data
        parsed = urllib.parse.urlparse(link)
        protocol = parsed.scheme
        if protocol == 'ss': return {'protocol': 'shadowsocks'}
        if protocol not in ['vless', 'trojan']: return None
        data = {'protocol': protocol, 'server': parsed.hostname, 'port': parsed.port, 'uuid': parsed.username, 'password': parsed.username}
        query = urllib.parse.parse_qs(parsed.query)
        for k, v in query.items(): data[k.lower()] = v[0]
        data['network'] = data.get('type', 'tcp')
        data['sni'] = data.get('sni') or data.get('host')
        return data
    except: return None

def generate_singbox_config(data, local_port):
    config = {"log": {"disabled": True}, "inbounds": [{"type": "mixed", "listen": "127.0.0.1", "listen_port": local_port}], "outbounds": []}
    outbound = {"tag": "proxy", "type": data['protocol'], "server": data['server'], "server_port": int(data['port'])}
    if data['protocol'] == 'vmess': outbound.update({"uuid": data['uuid'], "alter_id": int(data.get('aid', 0)), "security": data.get('scy', 'auto')})
    elif data['protocol'] == 'vless': outbound["uuid"] = data['uuid']; 
    elif data['protocol'] == 'trojan': outbound["password"] = data['password']
    tls_enabled = (data['protocol'] == 'vmess' and data.get('tls') == 'tls') or data.get('security') in ['tls', 'reality']
    if tls_enabled:
        tls_conf = {"enabled": True, "server_name": data.get('sni', ''), "insecure": True}
        if data.get('security') == 'reality': tls_conf["reality"] = {"enabled": True, "public_key": data.get('pbk', ''), "short_id": data.get('sid', '')}
        if data.get('fp'): tls_conf["utls"] = {"enabled": True, "fingerprint": data['fp']}
        outbound["tls"] = tls_conf
    transport = {}; net = data.get('network', 'tcp')
    if net == 'ws':
        transport = {"type": "ws", "path": data.get('path', '/')}
        if data.get('host') or data.get('sni'): transport["headers"] = {"Host": data.get('host') or data.get('sni')}
    elif net == 'grpc': transport = {"type": "grpc", "service_name": data.get('serviceName', '')}
    if transport: outbound["transport"] = transport
    config["outbounds"].append(outbound)
    return json.dumps(config)

def rebuild_link(original_link, data, new_name):
    if original_link.startswith('vmess://'):
        try:
            conf = json.loads(safe_base64_decode(original_link[8:]).decode('utf-8'))
            conf['ps'] = new_name
            return f"vmess://{base64.b64encode(json.dumps(conf).encode('utf-8')).decode('utf-8')}"
        except: pass
    return f"{original_link.split('#')[0]}#{urllib.parse.quote(new_name)}"

# ================= 4. ЗАГРУЗКА =================

def fetch_links(url, is_gist=False):
    print(f"Downloading: {url}...")
    headers = {'User-Agent': 'Mozilla/5.0'}
    if is_gist and GH_TOKEN: headers['Authorization'] = f'token {GH_TOKEN}'
    try:
        if is_gist:
            r = requests.get(url, headers=headers); r.raise_for_status()
            content = r.json().get('files', {}).get(GIST_FILENAME, {}).get('content', '')
        else:
            r = requests.get(url, headers=headers); r.raise_for_status()
            content = r.text
        links = [l.strip() for l in content.splitlines() if l.strip()]
        valid = [l for l in links if l.startswith(('vmess://', 'vless://', 'trojan://'))]
        if valid: print(f"  -> Found {len(valid)} links"); return valid
        decoded = safe_base64_decode(content).decode('utf-8', errors='ignore')
        return [l.strip() for l in decoded.splitlines() if l.strip()]
    except Exception as e: print(f"  -> Error: {e}"); return []

# ================= 5. ПРОВЕРКА (С ДОБАВЛЕНИЕМ ChatGPT) =================

seen_proxies = set()
error_counter = 0

def check_proxy(link):
    global error_counter
    proc, config_file = None, None
    try:
        data = parse_proxy_link(link)
        if not data or data.get('protocol') in ['shadowsocks', 'ss']: return None
        
        identifier = f"{data.get('server')}:{data.get('port')}"
        if identifier in seen_proxies: return None
        seen_proxies.add(identifier)

        local_port = get_free_port()
        conf_str = generate_singbox_config(data, local_port)
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as temp:
            config_file = temp.name
            temp.write(conf_str)

        proc = subprocess.Popen([SING_BOX_PATH, "run", "-c", config_file], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1.5)
        if proc.poll() is not None: return None

        proxies = {'http': f'socks5://127.0.0.1:{local_port}', 'https': f'socks5://127.0.0.1:{local_port}'}

        # --- ШАГ 1: Проверка базового подключения (Ping) ---
        st = time.time()
        requests.get(TEST_URL, proxies=proxies, timeout=TIMEOUT)
        ping = int((time.time() - st) * 1000)

        # --- ШАГ 2: Проверка ChatGPT (Обязательный фильтр) ---
        try:
            # Используем HEAD для скорости, нам не нужно тело страницы
            response_gpt = requests.head(CHATGPT_URL, proxies=proxies, timeout=TIMEOUT)
            response_gpt.raise_for_status() # Упадет, если статус 4xx или 5xx
        except requests.RequestException:
            return None # Отбрасываем, если не удалось подключиться
        
        # --- ШАГ 3: Получение Geo-информации ---
        api_data = {}
        for _ in range(API_RETRIES):
            try:
                r = requests.get(IP_API_URL, proxies=proxies, timeout=TIMEOUT)
                if r.status_code == 200 and 'ip' in r.json():
                    api_data = r.json(); break
            except: pass
            time.sleep(1)
        
        if not api_data: return None
        
        cc = api_data.get('country', 'XX')
        if cc == 'RU' or cc == 'XX': return None
        
        isp = re.sub(r'^AS\d+\s+', '', api_data.get('org', 'Unknown'))
        if re.search(BANNED_ISP_REGEX, isp): return None

        # --- ШАГ 4: Формирование имени и результата ---
        flag = country_flag(cc)
        city = api_data.get('city', 'Unknown')
        gemini_ico = '✅' if cc in GEMINI_ALLOWED else '❌'
        yt_ico = '✅' if cc in YT_MUSIC_ALLOWED else '❌'
        
        # Добавляем тег ChatGPT, так как проверка пройдена
        name = f"{flag} {cc} - {city} ◈ {isp} | 🎵YT{yt_ico} ✨Gemini{gemini_ico} 🤖ChatGPT✅"
        new_link = rebuild_link(link, data, name)
        
        link_hash = hashlib.md5(new_link.encode('utf-8')).hexdigest()
        
        return (ping, new_link, link_hash)

    except Exception as e:
        if error_counter < 5:
            print(f"\n[ERROR] Link failed: {e}")
            error_counter += 1
        return None
    finally:
        if proc: 
            try: proc.terminate(); proc.wait(timeout=1)
            except: proc.kill()
        if config_file and os.path.exists(config_file):
            try: os.remove(config_file)
            except: pass

# ================= 6. DEPLOY =================

def deploy(links_content, pings_content):
    if not all([GH_TOKEN, GIST_ID, VERCEL_TOKEN, PROJ_ID]):
        print("Secrets missing."); return

    print("Updating Gist (Links + Pings)...")
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
        raw_url_links = r.json()['files'][GIST_FILENAME]['raw_url']
        final_url = f"{raw_url_links}?t={int(time.time())}"
        print("Gist OK.")
    except Exception as e: print(f"Gist Error: {e}"); return

    print("Triggering Vercel...")
    h = {"Authorization": f"Bearer {VERCEL_TOKEN}"}
    try:
        # Обновление переменной и триггер деплоя
        res = requests.get(f"https://api.vercel.com/v9/projects/{PROJ_ID}/env", headers=h).json()
        eid = next((e['id'] for e in res.get('envs', []) if e['key'] == ENV_KEY), None)
        body = {"value": final_url, "target": ["production"], "type": "plain"}
        if eid: requests.patch(f"https://api.vercel.com/v9/projects/{PROJ_ID}/env/{eid}", headers=h, json=body)
        else: body['key'] = ENV_KEY; requests.post(f"https://api.vercel.com/v10/projects/{PROJ_ID}/env", headers=h, json=body)
        
        proj = requests.get(f"https://api.vercel.com/v9/projects/{PROJ_ID}", headers=h).json()
        payload = {"name": proj.get('name'), "project": PROJ_ID, "target": "production"}
        if 'link' in proj and 'repoId' in proj['link']:
            payload['gitSource'] = {"type": "github", "ref": "main", "repoId": proj['link']['repoId']}
        requests.post("https://api.vercel.com/v13/deployments", headers=h, json=payload)
        print("Vercel OK.")
    except Exception as e: print(f"Vercel Error: {e}")

def main():
    if not os.path.exists(SING_BOX_PATH): print("Sing-box not found!"); sys.exit(1)
    
    links_new = fetch_links(NEW_SOURCE_URL)
    links_old = fetch_links(f"https://api.github.com/gists/{GIST_ID}", is_gist=True) if GIST_ID else []
    all_raw = list(set(links_new + links_old))
    print(f"Total links: {len(all_raw)}")
    if not all_raw: return

    results = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as exe:
        futures = {exe.submit(check_proxy, l): l for l in all_raw}
        for f in tqdm(as_completed(futures), total=len(all_raw), desc="Checking"):
            res = f.result()
            if res: results.append(res)
    
    print(f"\nWorking & ChatGPT accessible: {len(results)}")
    
    if results:
        results.sort(key=lambda x: x[0])
        links_str = "\n".join([r[1] for r in results])
        pings_map = {r[2]: r[0] for r in results}
        deploy(links_str, json.dumps(pings_map))
    else:
        print("No working proxies found.")

if __name__ == "__main__":
    main()
