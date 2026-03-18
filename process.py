#!/usr/bin/env python3
"""
Второй проход: читает gistfile1.txt из Gist, применяет фильтрацию,
создаёт gistfile2.txt и pings2.json, опционально обновляет Gist.
"""

import os
import sys
import json
import hashlib
import urllib.parse
import base64
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm

# Импортируем оригинальный скрипт как модуль (должен лежать рядом)
import main_v2 as orig


def fetch_gist_file(gist_id, filename, token):
    """Скачивает содержимое указанного файла из Gist."""
    url = f"https://api.github.com/gists/{gist_id}"
    headers = {'Authorization': f'token {token}'}
    try:
        resp = requests.get(url, headers=headers)
        resp.raise_for_status()
        files = resp.json().get('files', {})
        if filename in files:
            return files[filename].get('content', '')
        else:
            print(f"Файл {filename} не найден в Gist")
            return None
    except Exception as e:
        print(f"Ошибка при получении Gist: {e}")
        return None


def update_gist(gist_id, token, files_dict):
    """Обновляет Gist, добавляя/изменяя указанные файлы."""
    url = f"https://api.github.com/gists/{gist_id}"
    headers = {'Authorization': f'token {token}'}
    payload = {
        'files': {name: {'content': content} for name, content in files_dict.items()}
    }
    try:
        resp = requests.patch(url, headers=headers, json=payload)
        resp.raise_for_status()
        print("Gist успешно обновлён")
        return True
    except Exception as e:
        print(f"Ошибка обновления Gist: {e}")
        return False


def main():
    # Проверяем наличие необходимых секретов
    gh_token = os.environ.get("GH_TOKEN")
    gist_id = os.environ.get("GIST_ID")
    if not gh_token or not gist_id:
        print("Ошибка: не заданы GH_TOKEN или GIST_ID")
        sys.exit(1)

    # Читаем gistfile1.txt из Gist
    print("Загружаем gistfile1.txt из Gist...")
    content = fetch_gist_file(gist_id, orig.GIST_FILENAME, gh_token)
    if content is None:
        sys.exit(1)

    links = [line.strip() for line in content.splitlines() if line.strip()]
    print(f"Загружено {len(links)} ссылок")

    # Загружаем RKN списки (нужно для проверки IP)
    print("Загружаем RKN списки...")
    orig.load_rkn_lists()

    # Сбрасываем глобальные счётчики и кэши
    orig.seen_proxies.clear()
    orig.cheburcheck_cache.clear()
    orig.entry_ip_country_cache.clear()
    for key in orig.reject_stats:
        orig.reject_stats[key] = 0

    # Проверяем прокси
    print(f"Начинаем проверку {len(links)} прокси...")
    results = []
    with ThreadPoolExecutor(max_workers=orig.MAX_WORKERS_CHECK) as executor:
        futures = {executor.submit(orig.check_proxy, link): link for link in links}
        for future in tqdm(as_completed(futures), total=len(links), desc="Проверка"):
            res = future.result()
            if res:
                results.append(res)

    # Статистика
    total_rejects = sum(v for k, v in orig.reject_stats.items() if k not in ("success", "gateway_filtered"))
    print(f"\nРабочих после проверки: {len(results)}")
    print(f"Всего обработано: {len(links)}, Успех: {orig.reject_stats['success']}, Отказ: {total_rejects}")
    for reason, count in orig.reject_stats.items():
        if count > 0:
            print(f"  {reason}: {count}")

    if not results:
        print("Нет рабочих прокси")
        return

    # Применяем фильтрацию
    antiwhitelist = []
    regular = []
    vless_reality_count = 0
    other_protocols_count = 0

    for ping, link, link_hash, data, is_russian_entry, is_russian_exit, speed_mbps in results:
        # Исключаем Shadowsocks
        if data['protocol'] == 'shadowsocks':
            continue

        # Фильтр для VLESS Reality
        if data['protocol'] == 'vless':
            if (data.get('security') != 'reality' or
                data.get('encryption') != 'none' or
                data.get('fp') != 'chrome' or
                data.get('type') != 'tcp' or
                data.get('flow') != 'xtls-rprx-vision'):
                continue
            vless_reality_count += 1
        else:
            other_protocols_count += 1

        # Исключаем прокси с российским выходом
        if is_russian_exit:
            continue

        if is_russian_entry:
            antiwhitelist.append((ping, link, link_hash, speed_mbps))
        else:
            regular.append((ping, link, link_hash, speed_mbps))

    print(f"Найдено VLESS reality: {vless_reality_count}")
    print(f"Найдено других протоколов (кроме SS): {other_protocols_count}")

    # Сортируем regular по убыванию скорости
    regular.sort(key=lambda x: x[3] if x[3] is not None else 0, reverse=True)

    # Берём первые 200 regular
    top_regular = regular[:200]

    # Объединяем: все antiwhitelist + топ regular
    combined = antiwhitelist + top_regular

    # Сортируем объединённый список по пингу
    combined.sort(key=lambda x: x[0])
    final_results = [(ping, link, link_hash) for ping, link, link_hash, _ in combined]

    print(f"Anti-whitelist count: {len(antiwhitelist)}, Regular top 200: {len(top_regular)}, Total final: {len(final_results)}")

    if not final_results:
        print("Нет прокси после фильтрации")
        return

    # Формируем финальные ссылки с нумерацией
    final_links = []
    pings_map = {}
    for idx, (ping, link, old_hash) in enumerate(final_results):
        try:
            if link.startswith("vmess://"):
                b64 = link[8:]
                data = json.loads(orig.safe_base64_decode(b64).decode("utf-8"))
                old_name = data.get("ps", "")
                data["ps"] = f"{idx+1}. {old_name}"
                new_b64 = base64.b64encode(json.dumps(data).encode("utf-8")).decode("utf-8")
                new_link = f"vmess://{new_b64}"
            else:
                parts = link.split("#")
                base = parts[0]
                old_name = urllib.parse.unquote(parts[1]) if len(parts) > 1 else ""
                new_name = f"{idx+1} - {old_name}"
                new_link = f"{base}#{urllib.parse.quote(new_name)}"

            final_links.append(new_link)
            new_hash = hashlib.md5(new_link.encode("utf-8")).hexdigest()
            pings_map[new_hash] = ping
        except Exception as e:
            print(f"Ошибка при обработке ссылки {idx+1}: {e}")
            final_links.append(link)
            pings_map[old_hash] = ping

    # Сохраняем локально
    with open("gistfile2.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(final_links))
    with open("pings2.json", "w", encoding="utf-8") as f:
        json.dump(pings_map, f, indent=2)

    print("Файлы сохранены локально: gistfile2.txt, pings2.json")

    # Опционально: загружаем обратно в Gist (как отдельные файлы)
    # Раскомментируйте, если хотите обновлять Gist
    # files_to_upload = {
    #     "gistfile2.txt": "\n".join(final_links),
    #     "pings2.json": json.dumps(pings_map)
    # }
    # update_gist(gist_id, gh_token, files_to_upload)


if __name__ == "__main__":
    main()
