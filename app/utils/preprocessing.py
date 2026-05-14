import pandas as pd
import numpy as np
from pathlib import Path

# Caminho dos arquivos CSV
DATA_PATH = Path("app/data/raw/MachineLearningCSV/MachineLearningCVE")

# Lista de todos os CSVs
csv_files = list(DATA_PATH.glob("*.csv"))

def load_and_merge_data():
    dataframes = []

    print("[INFO] Carregando arquivos CSV...")

    for file in csv_files:
        print(f"[INFO] Lendo: {file.name}")

        df = pd.read_csv(file)
        dataframes.append(df)

    print("[INFO] Concatenando datasets...")

    merged_df = pd.concat(dataframes, ignore_index=True)

    return merged_df


def clean_data(df):
    print("[INFO] Limpando colunas...")

    # Remove espaços dos nomes das colunas
    df.columns = df.columns.str.strip()

    print("[INFO] Removendo duplicados...")
    df.drop_duplicates(inplace=True)

    print("[INFO] Substituindo valores infinitos...")
    df.replace([np.inf, -np.inf], np.nan, inplace=True)

    print("[INFO] Tratando valores nulos...")

    numeric_cols = df.select_dtypes(include=np.number).columns

    for col in numeric_cols:
        median = df[col].median()
        df[col].fillna(median, inplace=True)

    print("[INFO] Removendo colunas sem variação...")

    nunique = df.nunique()

    cols_to_drop = nunique[nunique <= 1].index

    df.drop(columns=cols_to_drop, inplace=True)

    print(f"[INFO] Colunas removidas: {list(cols_to_drop)}")

    return df


def save_processed_data(df):
    output_path = Path("app/data/processed")

    output_path.mkdir(parents=True, exist_ok=True)

    save_file = output_path / "cleaned_data.csv"

    print("[INFO] Salvando dataset processado...")

    df.to_csv(save_file, index=False)

    print(f"[INFO] Dataset salvo em: {save_file}")


def main():
    df = load_and_merge_data()

    print(f"[INFO] Dataset carregado: {df.shape}")

    df = clean_data(df)

    print(f"[INFO] Dataset após limpeza: {df.shape}")

    save_processed_data(df)

    print("[INFO] Pré-processamento concluído.")


if __name__ == "__main__":
    main()