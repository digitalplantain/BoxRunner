import base64
import json
import os
import sys
import urllib.parse
import requests
import yaml
import re
import string

GIST_ID = os.environ.get("GIST_ID")
GH_TOKEN = os.environ.get("GH_TOKEN")
INPUT_FILENAME = "gistfile1.txt"
OUTPUT_FILENAME = "clash_profile.yaml"

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

def clean_and_fix_short_id(sid):
    if not sid: return None
    sid = str(sid).strip()
    clean_sid = re.sub(r'[^0-9a-fA-F]', '', sid)
    if not clean_sid: return None
    if len(clean_sid) % 2 != 0: clean_sid = '0' + clean_sid
    return clean_sid.lower()

def convert_link_to_clash_proxy(link):
    try:
        url_parts = link.split('#', 1)
        if len(url_parts) != 2 or not url_parts[1]: return None
        name = urllib.parse.unquote(url_parts[1])
        data = parse_proxy_link(url_parts[0])
        if not data: return None
        
        proxy = {'name': name, 'type': data['protocol'], 'server': data['server'], 'port': data['port']}
        
        if data['protocol'] in ['vless', 'vmess']: proxy['uuid'] = data['uuid']
        if data['protocol'] == 'trojan': proxy['password'] = data['password']
        if data['protocol'] == 'vmess':
            proxy['alterId'] = data.get('alter_id', 0)
            proxy['cipher'] = data.get('security', 'auto')
        
        tls_enabled = data.get('security') in ['tls', 'reality'] or data.get('tls') == 'tls'
        if tls_enabled:
            proxy['tls'] = True
            if data.get('sni'): proxy['servername'] = data['sni']
            if data.get('fp'): proxy['client-fingerprint'] = data['fp']
            
            if data.get('security') == 'reality':
                reality_opts = {'public-key': data.get('pbk', '')}
                raw_sid = data.get('sid', '')
                valid_sid = clean_and_fix_short_id(raw_sid)
                if valid_sid: reality_opts['short-id'] = str(valid_sid)
                proxy['reality-opts'] = reality_opts

        net = data.get('network', 'tcp')
        if net == 'ws':
            proxy['network'] = 'ws'
            proxy['ws-opts'] = {'path': data.get('path', '/')}
            host = data.get('host') or data.get('sni')
            if host: proxy['ws-opts']['headers'] = {'Host': host}
        elif net == 'grpc':
            proxy['network'] = 'grpc'
            proxy['grpc-opts'] = {'grpc-service-name': data.get('serviceName', '')}
        
        if data.get('protocol') == 'vless' and data.get('flow'):
            proxy['flow'] = data['flow']
        return proxy
    except: return None

def get_base_config():
    return {
        'port': 7890,
        'socks-port': 7891,
        'mixed-port': 7892,
        'allow-lan': True,
        'bind-address': '*',
        'mode': 'rule',
        'log-level': 'info',
        'ipv6': True,
        'external-controller': '127.0.0.1:9090',
        'find-process-mode': 'strict',
        'global-client-fingerprint': 'chrome',
        
        'geox-url': {
            'geoip': "https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip.dat",
            'geosite': "https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geosite.dat",
            'mmdb': "https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip.metadb"
        },
        'geo-auto-update': True,
        'geo-update-interval': 24,

        'sniffer': {
            'enable': True,
            'sniff': {
                'TLS': {'ports': [443, 8443]},
                'HTTP': {'ports': [80, '8080-8880'], 'override-destination': True}
            }
        },

        'dns': {
            'enable': True,
            'listen': '0.0.0.0:53',
            'ipv6': True,
            'enhanced-mode': 'fake-ip',
            'fake-ip-range': '198.18.0.1/16',
            
            'fake-ip-filter': [
                '*', '+.lan', '+.local', 
                'digitalplantain.vercel.app', 
                '+.yandex-team.ru', '+.yndx.net', '+.yanet.org', '+.yandex.net', '+.yandex.cloud',
                'network-check.kde.org', 'msftconnecttest.com', '+.msftconnecttest.com', 
                'msftncsi.com', '+.msftncsi.com', 'localhost.ptlogin2.qq.com', 
                'localhost.sec.qq.com'
            ],
            
            'default-nameserver': [
                '8.8.8.8', '9.9.9.9', '223.5.5.5', '114.114.114.114'
            ],
            
            'nameserver': [
                'https://dns.google/dns-query',
                'tls://dns.google'
            ],
            
            'fallback': [
                'https://doh.pub/dns-query',
                'https://dns.alidns.com/dns-query',
                'tls://dns.adguard-dns.com',
                'quic://dns.adguard-dns.com'
            ],
            
            'fallback-filter': {'geoip': True, 'geoip-code': 'RU', 'ipcidr': ['240.0.0.0/4']},
            
            'nameserver-policy': {
                'yandex-team.ru': 'system',
                '+.yandex-team.ru': 'system',
                'yndx.net': 'system',
                '+.yndx.net': 'system',
                'yanet.org': 'system',
                '+.yanet.org': 'system',
                'yandex.net': 'system',
                '+.yandex.net': 'system',
                'yandex.cloud': 'system',
                '+.yandex.cloud': 'system',
                
                'digitalplantain.vercel.app': ['https://doh.pub/dns-query', 'system'],
                
                'geosite:category-gov-ru': 'system',
                'geosite:yandex': 'system',
                'geosite:vk': 'system',
                'geosite:mailru': 'system',
                '+.ru': 'system',
                '+.su': 'system',
                '+.rf': 'system',
                
                'geosite:cn,private': ['https://doh.pub/dns-query', 'https://dns.alidns.com/dns-query']
            }
        },

        'tun': {
            'enable': True,
            'stack': 'system',
            'dns-hijack': ['any:53'],
            'auto-route': True,
            'auto-redirect': True,
            'strict-route': True,
        },

        'rule-providers': {
            'reject': {
                'type': 'http',
                'behavior': 'domain',
                'url': "https://fastly.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/reject.txt",
                'path': './ruleset/reject.yaml',
                'interval': 86400
            },
            'telegram': {
                'type': 'http',
                'behavior': 'classical',
                'url': "https://fastly.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/telegramcidr.txt",
                'path': './ruleset/telegramcidr.yaml',
                'interval': 86400
            },
            'discord': {
                'type': 'http',
                'behavior': 'classical',
                'url': "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Discord/Discord.yaml",
                'path': './ruleset/discord.yaml',
                'interval': 86400
            },
            'antifilter': {
                'type': 'http',
                'behavior': 'domain',
                'url': "https://antifilter.download/list/domains.lst",
                'path': './ruleset/antifilter.yaml',
                'interval': 86400
            },
            'antifilter-community': {
                'type': 'http',
                'behavior': 'domain',
                'url': "https://community.antifilter.download/list/domains.lst",
                'path': './ruleset/antifilter-community.yaml',
                'interval': 86400
            }
        }
    }

def main():
    if not GIST_ID or not GH_TOKEN:
        print("Error: GIST_ID or GH_TOKEN secrets are not set.")
        sys.exit(1)
    
    print(f"Fetching source file from Gist {GIST_ID}...")
    try:
        headers = {'Authorization': f'token {GH_TOKEN}'}
        r = requests.get(f'https://api.github.com/gists/{GIST_ID}', headers=headers)
        r.raise_for_status()
        gist_data = r.json()
        content = gist_data['files'][INPUT_FILENAME]['content']
    except Exception as e:
        print(f"Error fetching Gist: {e}")
        sys.exit(1)
    
    proxies = []
    proxy_names = []
    name_counts = {}

    print("Converting proxies...")
    for line in content.splitlines():
        if line.strip():
            p = convert_link_to_clash_proxy(line.strip())
            if p:
                name = p['name']
                if name in name_counts:
                    name_counts[name] += 1
                    name = f"{name} ({name_counts[name]})"
                    p['name'] = name
                else:
                    name_counts[name] = 1
                proxies.append(p)
                proxy_names.append(name)

    if not proxies:
        print("No proxies found.")
        return

    config = get_base_config()
    config['proxies'] = proxies

    standard_names = []
    anti_wl_names = []

    for name in proxy_names:
        if 'Anti-Whitelist' in name:
            anti_wl_names.append(name)
        else:
            standard_names.append(name)

    if not standard_names and anti_wl_names:
        standard_names = anti_wl_names

    config = get_base_config()
    config['proxies'] = proxies
    
    config['proxy-groups'] = [
        {
            'name': '♻️ Auto',
            'type': 'fallback',
            'url': 'http://www.gstatic.com/generate_204',
            'interval': 3600,
            'proxies': ['⚡ Standard', '🛡️ Anti-Whitelist']
        },
        {
            'name': '⚡ Standard',
            'type': 'url-test',
            'url': 'http://www.gstatic.com/generate_204',
            'interval': 3600,
            'tolerance': 1000,
            'proxies': standard_names if standard_names else ['DIRECT'] 
        },
        {
            'name': '🛡️ Anti-Whitelist',
            'type': 'url-test',
            'url': 'http://www.gstatic.com/generate_204',
            'interval': 3600,
            'tolerance': 1000,
            'proxies': anti_wl_names if anti_wl_names else ['DIRECT']
        },
        {
            'name': '🚀 Manual',
            'type': 'select',
            'proxies': ['♻️ Auto', '⚡ Standard', '🛡️ Anti-Whitelist'] + proxy_names
        },
        {
            'name': '📲 Telegram',
            'type': 'select',
            'proxies': ['♻️ Auto', '🚀 Manual']
        },
        {
            'name': '🎮 Discord',
            'type': 'select',
            'proxies': ['♻️ Auto', '🚀 Manual']
        },
        {
            'name': '🤖 OpenAI',
            'type': 'select',
            'proxies': ['♻️ Auto', '🚀 Manual']
        }
    ]

    config['rules'] = [
        'RULE-SET,reject,REJECT',
        'GEOSITE,category-ads-all,REJECT',
        
        'DOMAIN-SUFFIX,digitalplantain.vercel.app,DIRECT',

        'DOMAIN-SUFFIX,habr.com,🚀 Manual',
        
        'DOMAIN-KEYWORD,openai,🤖 OpenAI',
        'GEOSITE,openai,🤖 OpenAI',
        'RULE-SET,telegram,📲 Telegram',
        'GEOSITE,telegram,📲 Telegram',
        'RULE-SET,discord,🎮 Discord',
        'GEOSITE,discord,🎮 Discord',
        
        'GEOSITE,youtube,🚀 Manual',
        'GEOSITE,facebook,🚀 Manual',
        'GEOSITE,twitter,🚀 Manual',
        'GEOSITE,instagram,🚀 Manual',
        'DOMAIN-SUFFIX,linkedin.com,🚀 Manual',
        'DOMAIN-SUFFIX,medium.com,🚀 Manual',
        
        'RULE-SET,antifilter,🚀 Manual',
        'RULE-SET,antifilter-community,🚀 Manual',

        'DOMAIN-SUFFIX,yandex-team.ru,DIRECT',
        'DOMAIN-SUFFIX,yndx.net,DIRECT',
        'DOMAIN-SUFFIX,yanet.org,DIRECT',
        'DOMAIN-SUFFIX,yandex.net,DIRECT',
        'DOMAIN-SUFFIX,yandex.cloud,DIRECT',
        
        'GEOSITE,category-gov-ru,DIRECT', 
        'GEOSITE,yandex,DIRECT',
        'GEOSITE,vk,DIRECT',
        'GEOSITE,mailru,DIRECT',
        'GEOSITE,steam,DIRECT',
        'DOMAIN-SUFFIX,ru,DIRECT',
        'DOMAIN-SUFFIX,su,DIRECT',
        'DOMAIN-SUFFIX,rf,DIRECT',
        
        'GEOIP,LAN,DIRECT',
        'GEOIP,RU,DIRECT',
        
        'MATCH,🚀 Manual'
    ]

    print("Saving YAML...")
    yaml_content = yaml.dump(config, allow_unicode=True, sort_keys=False)

    try:
        payload = {'files': {OUTPUT_FILENAME: {'content': yaml_content}}}
        requests.patch(f'https://api.github.com/gists/{GIST_ID}', headers=headers, json=payload).raise_for_status()
        print("Done! Clash profile updated.")
    except Exception as e:
        print(f"Error uploading: {e}")
        sys.exit(1)

if __name__ == "__main__":
    try: import yaml
    except:
        os.system(f"{sys.executable} -m pip install pyyaml")
        import yaml
    main()
