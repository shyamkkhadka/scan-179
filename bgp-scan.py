import os
import socket
import csv
import time
from datetime import datetime
from multiprocessing import Pool, cpu_count

# ---------------------- CONFIG ----------------------
INPUT_FILE  = "/routersecurity/zmap_179_20260116155353.csv" # File with lists of IPs from Zmap scanned to port 179.
OUTPUT_FILE = "/routersecurity/results/bgp_scan_results_02_feb.csv"
PROCESSES   = cpu_count() * 3
BATCH_SIZE  = 1000
socket.setdefaulttimeout(3)

FIELDS = [
    "target_ip",
    "tcp_connected",
    "bgp_responded",
    "tcp_reset",
    "tcp_latency",
    "bgp_latency",
    "bgp_response_type",  # NEW FIELD
    "outcome",
    "error",
    "message_number",
    "type",
    "length",
    "version",
    "hold_time",
    "asn",
    "bgp_id",
    "opt_len",
    "opt_params_raw",
    "opt_params",
    "error_code",
    "error_subcode",
    "date"
 ]


# Ensure output folder exists
os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)

# ---------------------- BGP OPEN BUILDER ----------------------
def build_minimal_bgp_open(my_asn=1133, hold_time=90, bgp_id="145.90.8.11") -> bytes:
    marker = b'\xff' * 16
    payload = bytes([4, (my_asn >> 8) & 0xFF, my_asn & 0xFF,
                     (hold_time >> 8) & 0xFF, hold_time & 0xFF]) + \
              socket.inet_aton(bgp_id) + b'\x00'
    return marker + (19 + len(payload)).to_bytes(2, 'big') + b'\x01' + payload

# ---------------------- PARSE BGP MESSAGES ----------------------
def parse_bgp_messages(data: bytes):
    msgs = []
    i = 0
    while i + 19 <= len(data) and data[i:i+16] == b'\xff' * 16:
        length = int.from_bytes(data[i+16:i+18], 'big')
        typ = data[i+18]
        payload = data[i+19:i+length]
        name = {1:"OPEN", 2:"UPDATE", 3:"NOTIFICATION", 4:"KEEPALIVE"}.get(typ, "UNKNOWN")
        msgs.append({"type": typ, "name": name, "length": length, "payload": payload})
        i += length
    return msgs


# ---------------------- PARSE OPTIONAL PARAMETERS OF BGP OPEN ----------------------
# ---------------------- PARSE BGP OPTIONAL PARAMS ----------------------
def parse_bgp_optional_params(data: bytes):
    params = []
    i = 0

    while i + 2 <= len(data):
        p_type = data[i]
        p_len  = data[i + 1]
        p_val  = data[i + 2:i + 2 + p_len]

        param = {
            "param_type": p_type,
            "param_len": p_len,
            "param_val_hex": p_val.hex()
        }

        # Capabilities (Param Type 2)
        if p_type == 2:
            caps = []
            j = 0
            while j + 2 <= len(p_val):
                c_code = p_val[j]
                c_len  = p_val[j + 1]
                c_val  = p_val[j + 2:j + 2 + c_len]

                caps.append({
                    "capability_code": c_code,
                    "capability_len": c_len,
                    "capability_val_hex": c_val.hex()
                })
                j += 2 + c_len

            param["capabilities"] = caps

        params.append(param)
        i += 2 + p_len

    return params


# ---------------------- PARSE BGP OPEN ----------------------
def parse_bgp_open_payload(payload: bytes) -> dict:
    if len(payload) < 10:
        return {}

    opt_len = payload[9]
    opt_data = payload[10:10 + opt_len]

    return {
        "version": payload[0],
        "asn": int.from_bytes(payload[1:3], 'big'),
        "hold_time": int.from_bytes(payload[3:5], 'big'),
        "bgp_id": socket.inet_ntoa(payload[5:9]),
        "opt_len": opt_len,
        "opt_params_raw": opt_data.hex() if opt_len else None,
        "opt_params": parse_bgp_optional_params(opt_data) if opt_len else None
    }

# ---------------------- PROBE BGP TARGET ----------------------
def probe_bgp_target(ip: str, timeout=3):
    result = {
        "tcp_connected": False,
        "bgp_responded": False,
        "tcp_reset": False,
        "tcp_latency": None,
        "bgp_latency": None,
        "bgp_response_type": None,
        "messages": [],
        "error": None
    }

    try:
        s = socket.socket()
        s.settimeout(timeout)

        # TCP handshake
        t0 = time.monotonic()
        s.connect((ip, 179))
        t1 = time.monotonic()
        result["tcp_connected"] = True
        result["tcp_latency"] = round(t1 - t0, 3)

        # Send BGP OPEN
        s.send(build_minimal_bgp_open())

        # Measure BGP response
        t2 = time.monotonic()
        try:
            data = s.recv(4096)
            t3 = time.monotonic()
            result["bgp_latency"] = round(t3 - t2, 3)

            if data:
                result["bgp_responded"] = True
                result["bgp_response_type"] = "bgp_responded"
                result["messages"] = parse_bgp_messages(data)
            else:
                # Immediate zero bytes received
                result["bgp_response_type"] = "bgp_rejected_immediate" # Router closed or returned zero bytes immediately

        except socket.timeout:
            # Full timeout reached
            result["bgp_latency"] = round(time.monotonic() - t2, 3)
            result["bgp_response_type"] = "bgp_silent_timeout" # Router accepted TCP but ignored BGP (waited full timeout)

        s.close()

    except ConnectionResetError:
        t1 = time.monotonic()
        result["tcp_connected"] = True
        result["tcp_reset"] = True
        result["tcp_latency"] = round(t1 - t0, 3)
        result["bgp_response_type"] = "tcp_reset"
        result["error"] = "ConnectionResetError"

    except socket.timeout:
        t1 = time.monotonic()
        result["tcp_latency"] = round(t1 - t0, 3)
        result["error"] = "tcp_timeout"
        result["bgp_response_type"] = "tcp_failed"

    except ConnectionRefusedError:
        t1 = time.monotonic()
        result["tcp_latency"] = round(t1 - t0, 3)
        result["error"] = "tcp_refused"
        result["bgp_response_type"] = "tcp_failed"

    except Exception as e:
        t1 = time.monotonic()
        result["tcp_latency"] = round(t1 - t0, 3)
        result["error"] = str(type(e).__name__)
        result["bgp_response_type"] = "tcp_failed"

    return result
    """
    Probe a single IP for TCP + BGP.
    Returns:
        - tcp_connected: TCP handshake succeeded
        - tcp_reset: if TCP was reset
        - bgp_responded: BGP message received
        - tcp_latency: TCP handshake duration (s)
        - bgp_latency: time from sending BGP OPEN to first response (s)
    """
    result = {
        "tcp_connected": False,
        "bgp_responded": False,
        "tcp_reset": False,
        "tcp_latency": None,
        "bgp_latency": None,
        "messages": [],
        "error": None
    }

    try:
        s = socket.socket()
        s.settimeout(timeout)

        # Measure TCP handshake time
        t0 = time.monotonic()
        s.connect((ip, 179))
        t1 = time.monotonic()
        result["tcp_connected"] = True
        result["tcp_latency"] = round(t1 - t0, 3)

        # Send minimal BGP OPEN
        s.send(build_minimal_bgp_open())

        # Measure BGP response time
        t2 = time.monotonic()
        try:
            data = s.recv(4096)
            t3 = time.monotonic()
            result["bgp_latency"] = round(t3 - t2, 3)

            if data:
                result["bgp_responded"] = True
                result["messages"] = parse_bgp_messages(data)

        except socket.timeout:
            # TCP succeeded, but no BGP response
            result["bgp_latency"] = round(time.monotonic() - t2, 3)

        s.close()

    except ConnectionResetError:
        t1 = time.monotonic()
        result["tcp_connected"] = True
        result["tcp_reset"] = True
        result["tcp_latency"] = round(t1 - t0, 3)
        result["error"] = "ConnectionResetError"

    except socket.timeout:
        t1 = time.monotonic()
        result["tcp_latency"] = round(t1 - t0, 3)
        result["error"] = "tcp_timeout"

    except ConnectionRefusedError:
        t1 = time.monotonic()
        result["tcp_latency"] = round(t1 - t0, 3)
        result["error"] = "tcp_refused"

    except Exception as e:
        t1 = time.monotonic()
        result["tcp_latency"] = round(t1 - t0, 3)
        result["error"] = str(type(e).__name__)

    return result

# ---------------------- SCAN ONE IP ----------------------
def scan_ip(ip):
    scan_time = datetime.utcnow().isoformat()

    base = {
        "target_ip": ip,
        "tcp_connected": False,
        "bgp_responded": False,
        "tcp_reset": False,
        "tcp_latency": None,
        "bgp_latency": None,
        "bgp_response_type": None,
        "outcome": None,
        "error": None,
        "message_number": None,
        "type": None,
        "length": None,
        "version": None,
        "hold_time": None,
        "asn": None,
        "bgp_id": None,
        "opt_len": None,
        "error_code": None,
        "error_subcode": None,
        "date": scan_time
    }

    rows = []
    res = probe_bgp_target(ip)

    # Copy probe results
    base.update({
        "tcp_connected": res["tcp_connected"],
        "bgp_responded": res["bgp_responded"],
        "tcp_reset": res["tcp_reset"],
        "tcp_latency": res["tcp_latency"],
        "bgp_latency": res["bgp_latency"],
        "bgp_response_type": res["bgp_response_type"],
        "error": res["error"]
    })

    # Determine general outcome
    if base["bgp_responded"]:
        base["outcome"] = "bgp_responded"
    elif base["tcp_reset"]:
        base["outcome"] = "tcp_reset"
    elif base["tcp_connected"]:
        base["outcome"] = "tcp_ok_no_bgp"
    else:
        base["outcome"] = "tcp_failed"

    # Create CSV rows per message if BGP responded
    if base["bgp_responded"]:
        msgs = res.get("messages", [])
        for i, msg in enumerate(msgs, 1):
            row = base.copy()
            row["message_number"] = i
            row["type"] = msg["name"]
            row["length"] = msg["length"]

            if msg["type"] == 1:  # OPEN
                o = parse_bgp_open_payload(msg["payload"])
                row.update(o)

            if msg["type"] == 3 and len(msg["payload"]) >= 2: # NOTIFICATION
                row["error_code"] = msg["payload"][0]
                row["error_subcode"] = msg["payload"][1]

            rows.append(row)
    else:
        rows.append(base)

    return rows

# ---------------------- CSV ----------------------
def init_csv():
    with open(OUTPUT_FILE, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS)
        writer.writeheader()  

def append_rows(rows):
    with open(OUTPUT_FILE, "a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS)
        writer.writerows(rows)

# ---------------------- MAIN ----------------------
def run():
    init_csv()
    with open(INPUT_FILE) as f:
        next(f)  # skip header line
        ips = [line.strip() for line in f if line.strip()]
    with Pool(PROCESSES) as pool:
        for i in range(0, len(ips), BATCH_SIZE):
            batch = ips[i:i+BATCH_SIZE]
            results = pool.map(scan_ip, batch)
            for rows in results:
                append_rows(rows)

    print("✔ Scan completed")

if __name__ == "__main__":
    run()
