import joblib
import pandas as pd
from pathlib import Path

# Caminho do modelo treinado
MODEL_PATH = Path("app/model/saved_model.pkl")

# Carregando modelo
print("[INFO] Carregando modelo treinado...")

model = joblib.load(MODEL_PATH)

print("[INFO] Modelo carregado com sucesso.")


def predict(data):
    """
    Recebe um DataFrame com features
    e retorna a predição.
    """

    prediction = model.predict(data)

    return prediction


def interpret_prediction(prediction):
    """
    Interpreta o resultado da IA.
    """

    if prediction[0] == 0:
        return "BENIGN"
    else:
        return "ATTACK"


if __name__ == "__main__":

    print("[INFO] Testando predição...")

    # Carrega uma linha do dataset processado
    sample = pd.read_csv(
        "app/data/processed/cleaned_data.csv"
    )

    # Remove coluna Label
    X_sample = sample.drop(columns=["Label"])

    # Seleciona apenas 1 linha
    X_sample = X_sample.iloc[:1]

    prediction = predict(X_sample)

    result = interpret_prediction(prediction)

    print(f"[RESULTADO] Predição: {result}")