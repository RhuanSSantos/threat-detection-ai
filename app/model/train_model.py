import pandas as pd
import numpy as np
import joblib

from pathlib import Path

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix
)

# Caminho do dataset processado
DATA_PATH = Path("app/data/processed/cleaned_data.csv")


# Caminho para salvar modelo
MODEL_PATH = Path("app/model/saved_model.pkl")


def load_data():
    print("[INFO] Carregando dataset processado...")

    df = pd.read_csv(DATA_PATH)

    print(f"[INFO] Dataset carregado: {df.shape}")

    return df


def prepare_data(df):
    print("[INFO] Preparando dados...")

    # Remove espaços da coluna Label
    df["Label"] = df["Label"].str.strip()

    # Binary classification:
    # BENIGN = 0
    # ATTACK = 1

    df["Target"] = np.where(df["Label"] == "BENIGN", 0, 1)

    # Remove coluna original
    df.drop(columns=["Label"], inplace=True)

    # Separando features e target
    X = df.drop(columns=["Target"])
    y = df["Target"]

    print(f"[INFO] Features: {X.shape}")
    print(f"[INFO] Target: {y.shape}")

    return X, y


def train_model(X_train, y_train):
    print("[INFO] Treinando Random Forest...")

    model = RandomForestClassifier(
        n_estimators=100,
        random_state=42,
        n_jobs=-1
    )

    model.fit(X_train, y_train)

    return model


def evaluate_model(model, X_test, y_test):
    print("[INFO] Avaliando modelo...")

    predictions = model.predict(X_test)

    accuracy = accuracy_score(y_test, predictions)

    print(f"\n[RESULT] Accuracy: {accuracy:.4f}")

    print("\n[RESULT] Classification Report:\n")
    print(classification_report(y_test, predictions))

    print("\n[RESULT] Confusion Matrix:\n")
    print(confusion_matrix(y_test, predictions))


def save_model(model, X):
    print("[INFO] Salvando modelo...")

    # salva nomes das features
    feature_names = X.columns.tolist()

    joblib.dump(feature_names, "app/model/feature_names.pkl")

    # salva modelo
    joblib.dump(model, MODEL_PATH)

    print(f"[INFO] Modelo salvo em: {MODEL_PATH}")


def main():
    df = load_data()

    # USAR APENAS 10% inicialmente
    print("[INFO] Reduzindo dataset para 10%...")

    df = df.sample(frac=0.1, random_state=42)

    X, y = prepare_data(df)

    print("[INFO] Separando treino e teste...")

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.2,
        random_state=42,
        stratify=y
    )

    model = train_model(X_train, y_train)

    evaluate_model(model, X_test, y_test)

    save_model(model, X)

    print("[INFO] Treinamento concluído com sucesso.")


if __name__ == "__main__":
    main()