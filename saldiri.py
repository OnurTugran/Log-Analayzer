import pandas as pd
import numpy as np
import win32evtlog
from sklearn.ensemble import IsolationForest

print("-" * 20)
print("*" * 10 + " Godzilla Log Analiz " + "*" * 10)

def read_event_logs(log_type="Security", max_events=100):
    server = "localhost"
    log = []
    hand = win32evtlog.OpenEventLog(server, log_type)
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    events = win32evtlog.ReadEventLog(hand, flags, 0)

    for i, event in enumerate(events):
        if i >= max_events:
            break
        data = {
            "Time": event.TimeGenerated.Format(),
            "Source": event.SourceName,
            "EventID": event.EventID,
            "Category": event.EventCategory,
            "Strings": str(event.StringInserts) if event.StringInserts else ""
        }
        log.append(data)
    return pd.DataFrame(log)

def yorumla_string(s):
    s = str(s).lower()
    if "ssl connection could not be established" in s:
        return "⚠️ Güncelleme sırasında ağ bağlantısı sağlanamadı."
    elif "bits" in s:
        return "ℹ️ Arka plan aktarım hizmeti başlatıldı (normal)."
    elif "access denied" in s or "unauthorized" in s:
        return "🚫 Yetkisiz erişim denemesi"
    elif "failed" in s or "error" in s:
        return "⚠️ Hata tespit edildi."
    else:
        return "✅ Her şey normal görünüyor."

def analiz_et(log_type):
    df = read_event_logs(log_type=log_type, max_events=200)
    df["EventID"] = pd.to_numeric(df["EventID"], errors="coerce")
    df["Yorum"] = df["Strings"].apply(lambda x: yorumla_string(x))
    
    model = IsolationForest(contamination=0.1, random_state=42)
    df["anomaly"] = model.fit_predict(df[["EventID"]])
    
    anomalies = df[df["anomaly"] == -1]
    
    df.to_csv(f"{log_type}_tum_loglar.csv", index=False)
    anomalies.to_csv(f"{log_type}_supheli_loglar.csv", index=False)

    print(f"\n🔎 {log_type} Loglarında Şüpheli Kayıtlar:")
    if not anomalies.empty:
        for _, row in anomalies.iterrows():
            print(f"Tarih: {row['Time']}")
            print(f"Kaynak: {row['Source']}")
            print(f"Olay ID: {row['EventID']}")
            print(f"Açıklama: {row['Yorum']}")
            print("-" * 40)
    else:
        print("Hiçbir şüpheli log bulunamadı. ✅ Sistem temiz görünüyor.")

# Ana döngü
while True:
    print("\nHangi logları analiz etmek istersiniz?")
    print("1 - Security Logları")
    print("2 - System Logları")
    print("3 - Application Logları")
    print("4 - Çıkış")
    secim = input("Seçiminizi girin (1/2/3/4): ")

    if secim == "1":
        analiz_et("Security")
    elif secim == "2":
        analiz_et("System")
    elif secim == "3":
        analiz_et("Application")
    elif secim == "4":
        print("Çıkılıyor... Görüşmek üzere!")
        break
    else:
        print("Geçersiz giriş! Lütfen 1-4 arası bir sayı girin.")
