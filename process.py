#!/usr/bin/env python3

import sys
import json
import hashlib
import urllib.parse
import base64
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
import main_v2 as orig


def main():
    input_file = "gistfile1.txt"
    try:
        with open(input_file, "r", encoding="utf-8") as f:
            links = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"Ошибка: файл {input_file} не найден.")
        sys.exit(1)

    if not links:
        print("Файл пуст. Нечего проверять.")
        return

    print("Загрузка списков...")
    orig.load_rkn_lists()

    orig.seen_proxies.clear()
    orig.cheburcheck_cache.clear()
    orig.entry_ip_country_cache.clear()
    for key in orig.reject_stats:
        orig.reject_stats[key] = 0

    print(f"Начинаем проверку {len(links)} прокси...")
    results = []
    with ThreadPoolExecutor(max_workers=orig.MAX_WORKERS_CHECK) as executor:
        futures = {executor.submit(orig.check_proxy, link): link for link in links}
        for future in tqdm(
            as_completed(futures), total=len(links), desc="Проверка прокси"
        ):
            res = future.result()
            if res:
                results.append(res)

    total_rejects = sum(
        v for k, v in orig.reject_stats.items() if k not in ("success", "gateway_filtered")
    )
    print(f"\nРабочих после первой проверки: {len(results)}")
    print(f"Всего обработано: {len(links)}, Успех: {orig.reject_stats['success']}, Отказ: {total_rejects}")
    for reason, count in orig.reject_stats.items():
        if count > 0:
            print(f"  {reason}: {count}")

    if not results:
        print("Нет рабочих прокси после первой проверки.")
        return

    antiwhitelist = []
    regular = []
    vless_reality_count = 0
    other_protocols_count = 0

    for ping, link, link_hash, data, is_russian_entry, is_russian_exit, speed_mbps in results:
        if data['protocol'] == 'shadowsocks':
            continue

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

        if is_russian_exit:
            continue

        if is_russian_entry:
            antiwhitelist.append((ping, link, link_hash, speed_mbps))
        else:
            regular.append((ping, link, link_hash, speed_mbps))

    print(f"Найдено VLESS reality: {vless_reality_count}")
    print(f"Найдено других протоколов (кроме SS): {other_protocols_count}")

    regular.sort(key=lambda x: x[3] if x[3] is not None else 0, reverse=True)

    top_regular = regular[:200]

    combined = antiwhitelist + top_regular

    combined.sort(key=lambda x: x[0])
    final_results = [(ping, link, link_hash) for ping, link, link_hash, _ in combined]

    print(f"Anti-whitelist count: {len(antiwhitelist)}, Regular top 200: {len(top_regular)}, Total final: {len(final_results)}")

    if not final_results:
        print("Нет прокси после фильтрации.")
        return

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

    out_links = "gistfile2.txt"
    out_pings = "pings2.json"
    with open(out_links, "w", encoding="utf-8") as f:
        f.write("\n".join(final_links))
    with open(out_pings, "w", encoding="utf-8") as f:
        json.dump(pings_map, f, indent=2)

    print(f"\nГотово! Результаты сохранены в {out_links} и {out_pings}.")


if __name__ == "__main__":
    main()
