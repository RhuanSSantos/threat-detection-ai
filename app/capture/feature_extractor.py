from scapy.layers.inet import IP, TCP, UDP


def extract_features(packet):

    # ignora pacotes sem camada IP
    if not packet.haslayer(IP):
        return None

    features = {}

    try:

        ip_layer = packet[IP]

        # =========================
        # FEATURES IP
        # =========================

        features["src_ip"] = ip_layer.src
        features["dst_ip"] = ip_layer.dst
        features["packet_length"] = len(packet)
        features["ttl"] = ip_layer.ttl
        features["protocol"] = ip_layer.proto

        # =========================
        # FEATURES TCP
        # =========================

        if packet.haslayer(TCP):

            tcp_layer = packet[TCP]

            features["src_port"] = tcp_layer.sport
            features["dst_port"] = tcp_layer.dport

            # Flags TCP
            features["tcp_flags"] = int(tcp_layer.flags)

            features["syn_flag"] = 1 if tcp_layer.flags.S else 0
            features["ack_flag"] = 1 if tcp_layer.flags.A else 0
            features["fin_flag"] = 1 if tcp_layer.flags.F else 0
            features["rst_flag"] = 1 if tcp_layer.flags.R else 0

        # =========================
        # FEATURES UDP
        # =========================

        elif packet.haslayer(UDP):

            udp_layer = packet[UDP]

            features["src_port"] = udp_layer.sport
            features["dst_port"] = udp_layer.dport

            # UDP não possui flags TCP
            features["tcp_flags"] = 0
            features["syn_flag"] = 0
            features["ack_flag"] = 0
            features["fin_flag"] = 0
            features["rst_flag"] = 0

        else:

            # fallback caso não seja TCP nem UDP
            features["src_port"] = 0
            features["dst_port"] = 0

            features["tcp_flags"] = 0
            features["syn_flag"] = 0
            features["ack_flag"] = 0
            features["fin_flag"] = 0
            features["rst_flag"] = 0

        return features

    except Exception as e:

        print(f"[ERRO extract_features] {e}")

        return None