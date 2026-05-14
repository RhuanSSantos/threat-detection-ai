import pandas as pd
import joblib
from pathlib import Path

MODEL_PATH = Path("app/model/saved_model.pkl")
FEATURES_PATH = Path("app/model/feature_names.pkl")

print("[INFO] Carregando modelo...")

model = joblib.load(MODEL_PATH)

feature_names = joblib.load(FEATURES_PATH)

print("[INFO] Modelo carregado.")
print(f"[INFO] Total de features: {len(feature_names)}")


def prepare_features(packet_features):

    # cria dicionário vazio com TODAS as features do treino
    data = {feature: 0 for feature in feature_names}

    # mapeamento simples
    mapping = {
        "packet_length": "Packet Length Mean",
        "protocol": "Protocol",
        "src_port": "Source Port",
        "dst_port": "Destination Port"
    }

    # aplica dados capturados
    for packet_key, dataset_feature in mapping.items():

        if packet_key in packet_features and dataset_feature in data:

            data[dataset_feature] = packet_features[packet_key]

    # dataframe final
    df = pd.DataFrame([data])

    return df


def predict_packet(packet_features):

    try:

        processed = prepare_features(packet_features)

        prediction = model.predict(processed)[0]

        result = "BENIGN" if prediction == 0 else "ATTACK"

        return result

    except Exception as e:

        return f"ERRO: {str(e)}"