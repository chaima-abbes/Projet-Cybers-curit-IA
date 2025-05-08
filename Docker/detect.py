import re
import pandas as pd
import joblib
from datetime import datetime
from sklearn.preprocessing import LabelEncoder


def parse_log(filepath):
    data = []
    with open(filepath, 'r') as file:
        for line in file:
            if "Failed password" in line or "Accepted password" in line:
                ip_match = re.search(r"from ([\d\.]+)", line)
                user_match = re.search(r"for (\w+)", line)
                timestamp_match = re.match(r"^(\w{3})\s+(\d+)\s+(\d+):(\d+):(\d+)", line)

                if ip_match and user_match and timestamp_match:
                    
                    month_str, day, hour, minute, second = timestamp_match.groups()
                    time_str = f"{month_str} {day} {hour}:{minute}:{second}"
                    time_obj = datetime.strptime(f"2024 {time_str}", "%Y %b %d %H:%M:%S")


                    data.append({
                        "timestamp": time_obj,
                        "ip": ip_match.group(1),
                        "user": user_match.group(1),
                        "status": "fail" if "Failed" in line else "success"
                    })
    return pd.DataFrame(data)


def extract_features(df):
    df = df.sort_values("timestamp")

    
    ip_encoder = LabelEncoder()
    user_encoder = LabelEncoder()
    df["ip_encoded"] = ip_encoder.fit_transform(df["ip"])
    df["user_encoded"] = user_encoder.fit_transform(df["user"])

    
    df["hour"] = df["timestamp"].dt.hour
    df["minute"] = df["timestamp"].dt.minute

    
    df["attempts"] = df.groupby("ip")["ip"].transform("count")

    
    df["time_diff"] = df.groupby("ip")["timestamp"].diff().dt.total_seconds().fillna(0)

    return df[["hour", "minute", "ip_encoded", "user_encoded", "attempts", "time_diff"]]


if __name__ == "__main__":
    log_df = parse_log("logs/auth.log")
    print("Parsed Log Data:")
    print(log_df)

    X = extract_features(log_df)
    print("\nExtracted Features (for Prediction):")
    print(X)

    try:
        model = joblib.load("model/ssh_attack_detector.pkl")
        predictions = model.predict(X)

        
        log_df["prediction"] = predictions
        print("\nPrediction Results:")
        print(log_df[["ip", "user", "status", "prediction"]])

        for _, row in log_df.iterrows():
            status = "[!] Brute-force attack" if row["prediction"] == 1 else "[OK] Normal"
            print(f"{row['ip']} ({row['user']}) -> {status}")

    except FileNotFoundError:
        print("\n[!] Model not found!")
