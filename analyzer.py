import os
import json
import requests
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from collections import Counter

VULNERS_API_KEY = os.getenv("VULNERS_API_KEY")

if not VULNERS_API_KEY:
    raise ValueError("API ключ Vulners не найден. Добавьте переменную окружения VULNERS_API_KEY")

def load_suricata_logs(file_path):

    print("Чтение логов:", file_path)

    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    print("Всего событий:", len(data))

    return data

def analyze_ips(events):

    print("Анализ IP адресов")

    ip_list = []

    for event in events:

        if "src_ip" in event:
            ip_list.append(event["src_ip"])

    counter = Counter(ip_list)

    df = pd.DataFrame(counter.items(), columns=["ip", "requests"])

    print("Уникальных IP:", len(df))

    return df

def analyze_attack_types(events):

    print("Анализ типов атак")

    signatures = []

    for event in events:

        if "alert" in event:

            alert = event["alert"]

            if "signature" in alert:
                signatures.append(alert["signature"])

    counter = Counter(signatures)

    df = pd.DataFrame(counter.items(), columns=["attack_type", "count"])

    print("Типов атак найдено:", len(df))

    return df

def search_vulnerabilities():

    print("Запрос к Vulners API")

    url = "https://vulners.com/api/v3/search/lucene/"

    payload = {
        "query": "type:cve",
        "size": 20,
        "apiKey": VULNERS_API_KEY
    }

    headers = {
        "Content-Type": "application/json"
    }

    try:

        response = requests.post(
            url,
            json=payload,
            headers=headers,
            timeout=10
        )

        print("Статус API:", response.status_code)

        if response.status_code == 403:
            print("[WARNING] Vulners API отказал в доступе (403 Forbidden).")
            print("[INFO] Продолжаем анализ без данных Vulners.\n")
            return pd.DataFrame()

        if response.status_code != 200:
            print(f"[WARNING] Ошибка API Vulners: {response.status_code}")
            print("[INFO] Продолжаем анализ.\n")
            return pd.DataFrame()

        data = response.json()

    except requests.exceptions.RequestException as e:

        print("[WARNING] Ошибка соединения с Vulners API:", e)
        print("[INFO] Продолжаем анализ без данных Vulners.\n")
        return pd.DataFrame()

    vulns = []

    if "data" in data and "search" in data["data"]:

        for item in data["data"]["search"]:

            source = item["_source"]

            vulns.append({
                "cve": source.get("id"),
                "cvss": source.get("cvss", {}).get("score", 0)
            })

    df = pd.DataFrame(vulns)

    print("Найдено уязвимостей:", len(df))

    return df

def respond_to_threats(ip_df):

    print("Поиск подозрительных IP")

    suspicious_ips = ip_df[ip_df["requests"] > 10]

    if suspicious_ips.empty:
        print("Подозрительных IP не найдено")

    for _, row in suspicious_ips.iterrows():

        ip = row["ip"]

        print(f"[ALERT] Подозрительная активность от IP: {ip}")
        print(f"[ACTION] Имитация блокировки IP {ip}")

    return suspicious_ips

def save_reports(ip_df, attack_df, vuln_df):

    print("Сохранение отчётов")

    os.makedirs("report", exist_ok=True)

    combined = {
        "ip_analysis": ip_df.to_dict(orient="records"),
        "attack_types": attack_df.to_dict(orient="records"),
        "vulnerabilities": vuln_df.to_dict(orient="records")
    }

    with open("report/threats_report.json", "w", encoding="utf-8") as f:
        json.dump(combined, f, indent=4)

    ip_df.to_csv("report/ip_analysis.csv", index=False)

    attack_df.to_csv("report/attack_types.csv", index=False)

    print("Отчёты сохранены в папке report/")

def create_ip_graph(ip_df):

    print("Создание графика IP")

    os.makedirs("report", exist_ok=True)

    top_ips = ip_df.sort_values("requests", ascending=False).head(5)

    plt.figure(figsize=(8,5))

    sns.barplot(
        data=top_ips,
        x="ip",
        y="requests"
    )

    plt.title("Top 5 подозрительных IP")
    plt.xlabel("IP")
    plt.ylabel("Количество событий")

    plt.xticks(rotation=45)

    plt.tight_layout()

    plt.savefig("report/top_ips.png")

    plt.close()

    print("График сохранён: report/top_ips.png")

def create_attack_graph(attack_df):

    print("Создание графика типов атак")

    top_attacks = attack_df.sort_values("count", ascending=False).head(5)

    plt.figure(figsize=(10,6))

    sns.barplot(
        data=top_attacks,
        x="count",
        y="attack_type"
    )

    plt.title("Top 5 типов атак Suricata")
    plt.xlabel("Количество")
    plt.ylabel("Тип атаки")

    plt.tight_layout()

    plt.savefig("report/top_attack_types.png")

    plt.close()

    print("График сохранён: report/top_attack_types.png")

def main():

    print("Анализатор киберугроз")

    print("\n1. Загрузка логов Suricata")
    events = load_suricata_logs("logs/alerts-only.json")

    print("\n2. Анализ IP")
    ip_df = analyze_ips(events)

    print("\n3. Анализ типов атак")
    attack_df = analyze_attack_types(events)

    print("\n4. Получение уязвимостей (Vulners)")
    vuln_df = search_vulnerabilities()

    print("\n5. Реагирование на угрозы")
    respond_to_threats(ip_df)

    print("\n6. Сохранение отчётов")
    save_reports(ip_df, attack_df, vuln_df)

    print("\n7. Построение графиков")
    create_ip_graph(ip_df)
    create_attack_graph(attack_df)

    print("\nАнализ завершён")


if __name__ == "__main__":
    main()