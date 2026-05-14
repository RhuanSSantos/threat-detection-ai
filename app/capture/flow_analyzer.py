import time

# Armazena informações dos fluxos
flows = {}

# Armazena portas acessadas por IP
port_scan_tracker = {}


def update_flow(features):

    src_ip = features.get("src_ip")
    dst_ip = features.get("dst_ip")
    src_port = features.get("src_port")
    dst_port = features.get("dst_port")

    flow_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"

    current_time = time.time()

    # =========================
    # FLOW TRACKING
    # =========================

    if flow_key not in flows:

        flows[flow_key] = {
            "start_time": current_time,
            "packet_count": 0,
            "total_bytes": 0
        }

    flow = flows[flow_key]

    flow["packet_count"] += 1
    flow["total_bytes"] += features.get("packet_length", 0)

    duration = current_time - flow["start_time"]

    if duration <= 0:
        duration = 1

    flow_features = {
        "flow_duration": duration,
        "flow_packets_per_sec": flow["packet_count"] / duration,
        "flow_bytes_per_sec": flow["total_bytes"] / duration,
        "packet_count": flow["packet_count"]
    }

    # =========================
    # PORT SCAN TRACKING
    # =========================

    if src_ip not in port_scan_tracker:

        port_scan_tracker[src_ip] = {
            "ports": set(),
            "start_time": current_time
        }

    tracker = port_scan_tracker[src_ip]

    tracker["ports"].add(dst_port)

    # reinicia após 10 segundos
    if current_time - tracker["start_time"] > 10:

        tracker["ports"] = set()
        tracker["start_time"] = current_time

    flow_features["unique_ports"] = len(tracker["ports"])

    return flow_features