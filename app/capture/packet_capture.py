from scapy.all import sniff, IP, TCP, UDP, ICMP

from app.database.db_logger import save_detection
from app.utils.logger import log_detection

from collections import defaultdict
from time import time

print("[INFO] Capturando tráfego em tempo real...")

# =========================================
# TRACKERS
# =========================================

port_scan_tracker = defaultdict(set)

brute_force_tracker = defaultdict(int)

dns_tracker = defaultdict(int)

ddos_tracker = defaultdict(int)

exfil_tracker = defaultdict(int)

timestamps = defaultdict(float)

WINDOW_TIME = 15


# =========================================
# RESET
# =========================================

def reset_if_needed(ip):

    current = time()

    if current - timestamps[ip] > WINDOW_TIME:

        port_scan_tracker[ip].clear()

        brute_force_tracker[ip] = 0

        dns_tracker[ip] = 0

        ddos_tracker[ip] = 0

        exfil_tracker[ip] = 0

    timestamps[ip] = current


# =========================================
# PROCESSAMENTO
# =========================================

def process_packet(packet):

    try:

        if not packet.haslayer(IP):
            return

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        packet_length = len(packet)

        protocol = packet[IP].proto

        ttl = packet[IP].ttl

        src_port = 0
        dst_port = 0

        prediction = "BENIGN"

        severity = "LOW"

        risk_score = 0

        alerts = []

        reset_if_needed(src_ip)

        # =========================================
        # TCP
        # =========================================

        if packet.haslayer(TCP):

            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport

            flags = packet[TCP].flags

            syn_flag = int(flags & 0x02 != 0)

            ack_flag = int(flags & 0x10 != 0)

            # =========================================
            # PORT SCAN
            # =========================================

            if syn_flag == 1 and ack_flag == 0:

                port_scan_tracker[src_ip].add(dst_port)

            if len(port_scan_tracker[src_ip]) >= 5:

                alerts.append("PORT_SCAN")

            # =========================================
            # BRUTE FORCE
            # =========================================

            if dst_port == 8000:

                brute_force_tracker[src_ip] += 1

            if brute_force_tracker[src_ip] >= 150:

                alerts.append("BRUTE_FORCE")

            # =========================================
            # SYN FLOOD
            # =========================================

            if syn_flag == 1 and ack_flag == 0:

                ddos_tracker[src_ip] += 1

            if ddos_tracker[src_ip] >= 200:

                alerts.append("SYN_FLOOD")

        # =========================================
        # UDP / DNS
        # =========================================

        if packet.haslayer(UDP):

            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

            if dst_port == 53 or src_port == 53:

                dns_tracker[src_ip] += 1

            if dns_tracker[src_ip] >= 50:

                alerts.append("DNS_SUSPICIOUS")

        # =========================================
        # ICMP
        # =========================================

        if packet.haslayer(ICMP):

            ddos_tracker[src_ip] += 1

            if ddos_tracker[src_ip] >= 100:

                alerts.append("DDOS")

        # =========================================
        # EXFILTRATION
        # =========================================

        if packet_length >= 1200:

            exfil_tracker[src_ip] += 1

        if exfil_tracker[src_ip] >= 15:

            alerts.append("EXFILTRATION")

        # =========================================
        # RESULTADO
        # =========================================

        if alerts:

            prediction = "ATTACK"

            risk_score = min(
                len(alerts) * 25,
                100
            )

            if risk_score >= 75:
                severity = "HIGH"

            elif risk_score >= 40:
                severity = "MEDIUM"

        alert_text = "NONE"

        if alerts:

            alert_text = " | ".join(
                sorted(set(alerts))
            )

        detection_data = {

            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "packet_length": packet_length,
            "ttl": ttl,
            "protocol": protocol,
            "src_port": src_port,
            "dst_port": dst_port,

            "prediction": prediction,
            "severity": severity,
            "risk_score": risk_score,
            "alerts": alert_text
        }

        save_detection(

            src_ip,
            dst_ip,
            prediction,
            severity,
            risk_score,
            alert_text

        )

        log_detection(detection_data)

    except Exception as e:

        print(f"[ERRO] {e}")


sniff(
    prn=process_packet,
    store=False
)