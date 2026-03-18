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

    # Загружаем RKN списки (необходимо для is_ip_banned)
    print("Загрузка RKN списков...")
    orig.load_rkn_lists()

    # Сбрасываем глобальные счётчики и кэши
    orig.seen_proxies.clear()
    orig.cheburcheck_cache.clear()
    orig.entry_ip_country_cache.clear()
    for key in orig.reject_stats:
        orig.reject_stats[key] = 0

    # Проверка прокси (ожидаем кортеж из 7 элементов)
    print(f"Начинаем проверку {len(links)} прокси...")
    results = []
    with ThreadPoolExecutor(max_workers=orig.MAX_WORKERS_CHECK) as executor:
        futures = {executor.submit(orig.check_proxy, link): link for link in links}
        for future in tqdm(
            as_completed(futures), total=len(links), desc="Проверка прокси"
        ):
            res = future.result()
            if res:
                # Предполагаем, что check_proxy возвращает:
                # (ping, link, link_hash, data, is_russian_entry, is_russian_exit, speed_mbps)
                # Если у вас возвращается 6 элементов (без speed_mbps), раскомментируйте следующую строку и замените res
                # ping, link, link_hash, data, is_russian_entry, is_russian_exit = res
                # speed_mbps = None
                # res = (ping, link, link_hash, data, is_russian_entry, is_russian_exit, speed_mbps)
                results.append(res)

    # Статистика первого прохода
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
            # Проверяем обязательные параметры
            if (data.get('security') != 'reality' or
                data.get('encryption') != 'none' or
                data.get('fp') != 'chrome' or
                data.get('type') != 'tcp' or
                data.get('flow') != 'xtls-rprx-vision'):
                continue  # не подходит
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

    # Сортируем regular по убыванию скорости (если нет скорости, ставим 0)
    regular.sort(key=lambda x: x[3] if x[3] is not None else 0, reverse=True)

    # Берём первые 200 regular
    top_regular = regular[:200]

    # Объединяем: все antiwhitelist + топ regular
    combined = antiwhitelist + top_regular

    # Для нумерации оставляем только ping, link, link_hash
    # Также сортируем объединённый список по пингу (как в оригинале)
    combined.sort(key=lambda x: x[0])  # по пингу
    final_results = [(ping, link, link_hash) for ping, link, link_hash, _ in combined]

    print(f"Anti-whitelist count: {len(antiwhitelist)}, Regular top 200: {len(top_regular)}, Total final: {len(final_results)}")

    if not final_results:
        print("Нет прокси после фильтрации.")
        return

    # Формируем финальные ссылки с нумерацией
    final_links = []
    pings_map = {}
    for idx, (ping, link, old_hash) in enumerate(final_results):
        try:
            if link.startswith("vmess://"):
                # VMess – перезаписываем поле ps
                b64 = link[8:]
                data = json.loads(orig.safe_base64_decode(b64).decode("utf-8"))
                old_name = data.get("ps", "")
                data["ps"] = f"{idx+1}. {old_name}"
                new_b64 = base64.b64encode(json.dumps(data).encode("utf-8")).decode("utf-8")
                new_link = f"vmess://{new_b64}"
            else:
                # Остальные протоколы – добавляем номер в фрагмент
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

    # Сохраняем результаты
    out_links = "gistfile2.txt"
    out_pings = "pings2.json"
    with open(out_links, "w", encoding="utf-8") as f:
        f.write("\n".join(final_links))
    with open(out_pings, "w", encoding="utf-8") as f:
        json.dump(pings_map, f, indent=2)

    print(f"\nГотово! Результаты сохранены в {out_links} и {out_pings}.")


if __name__ == "__main__":
    main()
