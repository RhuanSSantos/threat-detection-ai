def log_detection(data):

    print("\n========================")
    print("PACOTE CAPTURADO")
    print(data)

    print(f"PREDIÇÃO IA: {data['prediction']}")
    print(f"SEVERIDADE: {data['severity']}")
    print(f"RISK SCORE: {data['risk_score']}")

    if data["alerts"] != "NONE":
        print(f"ALERTA: {data['alerts']}")

    print("========================")