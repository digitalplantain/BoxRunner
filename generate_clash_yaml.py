# generate_clash_yaml.py
import base64
import json
import os
import sys
import urllib.parse
import requests
import yaml

# --- КОНФИГУРАЦИЯ ---
GIST_ID = os.environ.get("GIST_ID")
GH_TOKEN = os.environ.get("GH_TOKEN")
INPUT_FILENAME = "gistfile1.txt"
OUTPUT_FILENAME = "clash_profile.yaml"

# --- ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ (без изменений) ---
def safe_base64_decode(s):
    if not s: return b""
    s = s.strip().replace('\n', '').replace('\r', '')
    pad = len(s) % 4
    if pad: s += '=' * (4 - pad)
    try: return base64.urlsafe_b64decode(s)
    except:
        try: return base64.b64decode(s)
        except: return b""

def parse_proxy_link(link):
    try:
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
        parsed = urllib.parse.urlparse(link)
        protocol = parsed.scheme
        if protocol not in ['vless', 'trojan']: return None
        data = {
            'protocol': protocol,
            'server': parsed.hostname,
            'port': parsed.port,
            'uuid': parsed.username,
            'password': parsed.username
        }
        query = urllib.parse.parse_qs(parsed.query)
        for k, v in query.items(): data[k.lower()] = v[0]
        data['network'] = data.get('type', 'tcp')
        data['sni'] = data.get('sni') or data.get('host')
        return data
    except: return None

# --- ГЛАВНАЯ ФУНКЦИЯ КОНВЕРТАЦИИ ---

def convert_link_to_clash_proxy(link):
    """Конвертирует vless/vmess/trojan URL в словарь для Clash YAML."""
    try:
        url_parts = link.split('#', 1)
        if len(url_parts) != 2 or not url_parts[1]:
            return None
        name = urllib.parse.unquote(url_parts[1])
        data = parse_proxy_link(url_parts[0])
        if not data: return None
        proxy = {'name': name, 'type': data['protocol'], 'server': data['server'], 'port': data['port']}
        if data['protocol'] in ['vless', 'vmess']:
            proxy['uuid'] = data['uuid']
        if data['protocol'] == 'trojan':
            proxy['password'] = data['password']
        if data['protocol'] == 'vmess':
            proxy['alterId'] = data.get('alter_id', 0)
            proxy['cipher'] = data.get('security', 'auto')
        
        tls_enabled = data.get('security') in ['tls', 'reality'] or data.get('tls') == 'tls'
        if tls_enabled:
            proxy['tls'] = True
            if data.get('sni'):
                proxy['servername'] = data['sni']
            if data.get('fp'):
                proxy['client-fingerprint'] = data['fp']
            
            # ===================== ИЗМЕНЕННЫЙ БЛОК v2 =====================
            if data.get('security') == 'reality':
                reality_opts = {'public-key': data.get('pbk', '')}
                short_id = data.get('sid', '')
                
                # Более строгая проверка: добавляем sid, только если он существует и не состоит из пробелов
                if short_id and short_id.strip():
                    reality_opts['short-id'] = short_id.strip() # Очищаем от случайных пробелов
                
                proxy['reality-opts'] = reality_opts
            # ===================== КОНЕЦ ИЗМЕНЕННОГО БЛОКА =====================

        net = data.get('network', 'tcp')
        if net == 'ws':
            proxy['network'] = 'ws'
            proxy['ws-opts'] = {'path': data.get('path', '/')}
            host = data.get('host') or data.get('sni')
            if host:
                proxy['ws-opts']['headers'] = {'Host': host}
        elif net == 'grpc':
            proxy['network'] = 'grpc'
            proxy['grpc-opts'] = {'grpc-service-name': data.get('serviceName', '')}
        
        if data.get('protocol') == 'vless' and data.get('flow'):
            proxy['flow'] = data['flow']
        return proxy
    except Exception as e:
        print(f"Failed to convert link {link[:30]}...: {e}")
        return None

# --- ОСНОВНОЙ СКРИПТ (без изменений) ---
def main():
    if not GIST_ID or not GH_TOKEN:
        print("Error: GIST_ID or GH_TOKEN secrets are not set.")
        sys.exit(1)
    
    print(f"Fetching source file '{INPUT_FILENAME}' from Gist {GIST_ID}...")
    try:
        headers = {'Authorization': f'token {GH_TOKEN}'}
        r = requests.get(f'https://api.github.com/gists/{GIST_ID}', headers=headers)
        r.raise_for_status()
        gist_data = r.json()
        content = gist_data['files'][INPUT_FILENAME]['content']
    except Exception as e:
        print(f"Error fetching Gist file: {e}")
        sys.exit(1)
    
    print("Converting proxy links to Clash format and handling duplicates...")
    proxies = []
    proxy_names = []
    name_counts = {}

    for line in content.splitlines():
        if line.strip():
            clash_proxy = convert_link_to_clash_proxy(line.strip())
            if clash_proxy:
                original_name = clash_proxy['name']
                if original_name in name_counts:
                    name_counts[original_name] += 1
                    unique_name = f"{original_name} ({name_counts[original_name]})"
                    clash_proxy['name'] = unique_name
                else:
                    name_counts[original_name] = 1
                    unique_name = original_name
                proxies.append(clash_proxy)
                proxy_names.append(unique_name)

    if not proxies:
        print("No valid proxy links found to convert.")
        return

    print(f"Successfully converted {len(proxies)} proxies.")

    clash_config = {
        'port': 7890,
        'socks-port': 7891,
        'allow-lan': False,
        'mode': 'rule',
        'log-level': 'info',
        'external-controller': '127.0.0.1:9090',
        'proxies': proxies,
        'proxy-groups': [
            {'name': 'PROXY', 'type': 'select', 'proxies': ['URL-Test', 'Direct', *proxy_names]},
            {'name': 'URL-Test', 'type': 'url-test', 'proxies': proxy_names, 'url': 'http://www.gstatic.com/generate_204', 'interval': 300}
        ],
        'rules': ['MATCH,PROXY']
    }
    
    yaml_content = yaml.dump(clash_config, allow_unicode=True, sort_keys=False)

    print(f"Uploading generated '{OUTPUT_FILENAME}' to Gist...")
    try:
        payload = {'files': {OUTPUT_FILENAME: {'content': yaml_content}}}
        r = requests.patch(f'https://api.github.com/gists/{GIST_ID}', headers=headers, json=payload)
        r.raise_for_status()
        print("Gist updated successfully with Clash YAML profile.")
    except Exception as e:
        print(f"Error updating Gist: {e}")
        sys.exit(1)

if __name__ == "__main__":
    try:
        import yaml
    except ImportError:
        print("PyYAML not found. Installing...")
        os.system(f"{sys.executable} -m pip install pyyaml")
    main()
