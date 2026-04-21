import threading
import queue
import time
import logging
import os
import platform
import random
from collections import defaultdict, Counter, deque
from concurrent.futures import ThreadPoolExecutor

# ───────────────────────────────────────────────────────────────────────────
# OPTIONAL DEPENDENCY GUARDS
# ───────────────────────────────────────────────────────────────────────────

try:
    from sklearn.ensemble import IsolationForest
    import numpy as np
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False
    logging.warning("[NADS] scikit-learn / numpy not available — ML detection disabled.")

try:
    from scapy.all import sniff, IP, TCP, get_if_list
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logging.warning("[NADS] Scapy not available — packet capture disabled.")


# ───────────────────────────────────────────────────────────────────────────
# LOGGING — file + console, but throttled to avoid I/O saturation
# ───────────────────────────────────────────────────────────────────────────

# File handler
_file_handler = logging.FileHandler("attack_logs.txt", encoding="utf-8")
_file_handler.setLevel(logging.INFO)
_file_handler.setFormatter(logging.Formatter("%(asctime)s - %(message)s"))

# Console handler (INFO only — suppress DEBUG spam in terminal)
_console_handler = logging.StreamHandler()
_console_handler.setLevel(logging.INFO)
_console_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))

_root_logger = logging.getLogger()
# Avoid adding duplicate handlers on reimport
if not _root_logger.handlers:
    _root_logger.setLevel(logging.DEBUG)
    _root_logger.addHandler(_file_handler)
    _root_logger.addHandler(_console_handler)

# Debug flag — set False to silence per-packet DEBUG noise
DEBUG_DETECTION = False


# ───────────────────────────────────────────────────────────────────────────
# SETTINGS
# ───────────────────────────────────────────────────────────────────────────

# ── Toggle demo mode ──
DEMO_MODE = True   # ← Set False for real packet capture

# ── Detection thresholds ──
DOS_THRESHOLD       = 8    # packets per TIME_WINDOW
PORT_SCAN_THRESHOLD = 6    # unique ports per TIME_WINDOW
TIME_WINDOW         = 5    # sliding window seconds
ALERT_COOLDOWN      = 5    # min seconds between alerts for same IP

# ── ML ──
ML_WINDOW_SIZE      = 100
ML_RETRAIN_INTERVAL = 50

# ── Buffer sizes ──
STATS_MAXLEN         = 5000
ALERTS_MAXLEN        = 200
TRAFFIC_BUCKET_WINDOW = 120
PACKET_QUEUE_MAXSIZE = 20000


# ───────────────────────────────────────────────────────────────────────────
# GLOBAL LOCK — RLock so same thread can re-enter safely
# ───────────────────────────────────────────────────────────────────────────

_lock = threading.RLock()


# ───────────────────────────────────────────────────────────────────────────
# SHARED STATE
# ───────────────────────────────────────────────────────────────────────────

dos_tracker      = defaultdict(deque)
port_tracker     = defaultdict(deque)

alerts           = deque(maxlen=ALERTS_MAXLEN)
attack_stats     = deque(maxlen=STATS_MAXLEN)
blocked_ips      = set()
last_alert_time  = {}
ip_counter       = Counter()

traffic_buckets  = {}      # {int_unix_ts: packet_count}

packet_queue     = queue.Queue(maxsize=PACKET_QUEUE_MAXSIZE)


# ───────────────────────────────────────────────────────────────────────────
# MACHINE LEARNING — disabled gracefully if sklearn missing
# ───────────────────────────────────────────────────────────────────────────

_ml_lock         = threading.Lock()
_ml_data         = deque(maxlen=ML_WINDOW_SIZE)
_ml_model        = None
_ml_trained      = False
_ml_training     = False
_ml_packet_count = 0
_ml_executor     = ThreadPoolExecutor(max_workers=1, thread_name_prefix="ml")

if ML_AVAILABLE:
    try:
        _ml_model = IsolationForest(contamination=0.05, random_state=42, n_jobs=1)
    except Exception as _e:
        logging.warning("[ML] IsolationForest init failed: %s", _e)
        ML_AVAILABLE = False


def _retrain_model():
    """Background ML retrain — never blocks the sniffer thread."""
    global _ml_model, _ml_trained, _ml_training

    if not ML_AVAILABLE:
        return

    with _ml_lock:
        if _ml_training:
            return
        _ml_training = True
        snapshot = list(_ml_data)

    if len(snapshot) < 20:
        with _ml_lock:
            _ml_training = False
        return

    try:
        X         = np.array(snapshot, dtype=float)
        new_model = IsolationForest(contamination=0.05, random_state=42, n_jobs=1)
        new_model.fit(X)
        with _ml_lock:
            _ml_model   = new_model
            _ml_trained = True
        logging.info("[ML] Model retrained on %d samples.", len(snapshot))
    except Exception as e:
        logging.warning("[ML] Retrain failed: %s", e)
    finally:
        with _ml_lock:
            _ml_training = False


def ml_predict(feature):
    """
    Feed sample to ML window; trigger async retrain periodically.
    Returns True if anomaly detected, False otherwise.
    Never raises.
    """
    global _ml_packet_count

    if not ML_AVAILABLE:
        return False

    try:
        with _ml_lock:
            _ml_data.append(feature)
            _ml_packet_count += 1
            should_retrain = (_ml_packet_count % ML_RETRAIN_INTERVAL == 0)
            trained        = _ml_trained
            model_snap     = _ml_model

        if should_retrain:
            try:
                _ml_executor.submit(_retrain_model)
            except Exception:
                pass  # executor might be shut down

        if not trained or model_snap is None:
            return False

        pred = model_snap.predict(np.array([feature], dtype=float))
        return bool(pred[0] == -1)

    except Exception as e:
        if DEBUG_DETECTION:
            logging.debug("[ML] predict error: %s", e)
        return False


# ───────────────────────────────────────────────────────────────────────────
# ALERT PERSISTENCE
# ───────────────────────────────────────────────────────────────────────────

def save_alert(message):
    """Append alert to alerts.txt — errors are logged but never propagated."""
    try:
        with open("alerts.txt", "a", encoding="utf-8") as f:
            f.write(str(message) + "\n")
    except Exception as e:
        logging.error("[NADS] save_alert error: %s", e)


# ───────────────────────────────────────────────────────────────────────────
# IP BLOCKING — platform-aware, sanitized
# ───────────────────────────────────────────────────────────────────────────

def block_ip(ip):
    """Add IP to block set and apply firewall rule. Never raises."""
    try:
        with _lock:
            if ip in blocked_ips:
                return
            blocked_ips.add(ip)

        # Sanitize: digits and dots only
        safe_ip = "".join(c for c in str(ip) if c.isdigit() or c == ".")
        if not safe_ip or len(safe_ip) > 15:
            return

        system = platform.system()
        try:
            if system == "Linux":
                os.system(f"iptables -A INPUT -s {safe_ip} -j DROP 2>/dev/null")
            elif system == "Windows":
                os.system(
                    f'netsh advfirewall firewall add rule name="Block_{safe_ip}" '
                    f'dir=in action=block remoteip={safe_ip} 2>nul'
                )
        except Exception as fw_err:
            logging.warning("[NADS] Firewall rule error for %s: %s", safe_ip, fw_err)

        msg = f"[BLOCK] Blocked IP: {ip}"
        with _lock:
            alerts.append(msg)
        logging.info(msg)
        save_alert(msg)

    except Exception as e:
        logging.error("[NADS] block_ip(%s) error: %s", ip, e)


# ───────────────────────────────────────────────────────────────────────────
# ALERT HANDLER — cooldown-gated
# ───────────────────────────────────────────────────────────────────────────

def handle_alert(ip, message):
    """Emit alert with per-IP cooldown. Never raises."""
    try:
        now = time.time()
        with _lock:
            last = last_alert_time.get(ip, 0)
            if now - last <= ALERT_COOLDOWN:
                return
            last_alert_time[ip] = now
            alerts.append(str(message))
        logging.info("[ALERT] %s", message)
        save_alert(message)
    except Exception as e:
        logging.error("[NADS] handle_alert error: %s", e)


# ───────────────────────────────────────────────────────────────────────────
# TRAFFIC BUCKET RECORDER
# ───────────────────────────────────────────────────────────────────────────

def record_traffic(ts):
    """Record one packet into the per-second bucket, expire old buckets."""
    try:
        bucket = int(ts)
        cutoff = bucket - TRAFFIC_BUCKET_WINDOW
        with _lock:
            traffic_buckets[bucket] = traffic_buckets.get(bucket, 0) + 1
            # Expire stale buckets in-place to avoid allocating a new list
            stale = [k for k in list(traffic_buckets) if k < cutoff]
            for k in stale:
                traffic_buckets.pop(k, None)
    except Exception as e:
        if DEBUG_DETECTION:
            logging.debug("[NADS] record_traffic error: %s", e)


# ───────────────────────────────────────────────────────────────────────────
# CORE PACKET PROCESSOR — runs on PacketProcessor thread only
# ───────────────────────────────────────────────────────────────────────────

def _process_packet(packet):
    """Full detection pipeline for one packet. Never raises unhandled."""
    try:
        if not SCAPY_AVAILABLE:
            return
        if not packet.haslayer(IP):
            return

        src_ip = packet[IP].src
        now    = time.time()

        record_traffic(now)

        with _lock:
            ip_counter[src_ip] += 1
            total_from_ip = ip_counter[src_ip]

        if DEBUG_DETECTION:
            logging.debug("[PKT] %s | total=%d", src_ip, total_from_ip)

        stat = {"ip": src_ip, "time": now, "type": "normal"}

        # ── DoS detection ──────────────────────────────────────────────────
        try:
            with _lock:
                dq = dos_tracker[src_ip]
                dq.append(now)
                while dq and now - dq[0] > TIME_WINDOW:
                    dq.popleft()
                packet_count = len(dq)

            if packet_count > DOS_THRESHOLD:
                handle_alert(src_ip,
                    f"[!] DoS Attack detected from {src_ip} ({packet_count} pkt/{TIME_WINDOW}s)")
                block_ip(src_ip)
                stat["type"] = "dos"
        except Exception as dos_err:
            logging.debug("[NADS] DoS check error: %s", dos_err)
            packet_count = 0

        # ── Port scan + DPI ────────────────────────────────────────────────
        unique_ports = 0
        try:
            if SCAPY_AVAILABLE and packet.haslayer(TCP):
                dst_port = packet[TCP].dport

                with _lock:
                    pdq = port_tracker[src_ip]
                    pdq.append((dst_port, now))
                    while pdq and now - pdq[0][1] > TIME_WINDOW:
                        pdq.popleft()
                    unique_ports = len(set(p for p, _ in pdq))

                if unique_ports > PORT_SCAN_THRESHOLD:
                    handle_alert(src_ip,
                        f"[!] Port Scan detected from {src_ip} ({unique_ports} ports/{TIME_WINDOW}s)")
                    block_ip(src_ip)
                    if stat["type"] == "normal":
                        stat["type"] = "port"

                # DPI payload inspection
                try:
                    raw_payload = bytes(packet[TCP].payload)
                    if raw_payload:
                        keywords = [
                            b"attack", b"malware", b"exploit",
                            b"sql",    b"cmd",     b"shell",    b"drop table"
                        ]
                        matched = [kw for kw in keywords if kw in raw_payload]
                        if matched:
                            handle_alert(src_ip,
                                f"[!] Suspicious Payload detected from {src_ip}")
                            block_ip(src_ip)
                            if stat["type"] == "normal":
                                stat["type"] = "payload"
                except Exception:
                    pass  # payload access can fail on malformed packets

        except Exception as tcp_err:
            logging.debug("[NADS] TCP/Port check error: %s", tcp_err)

        # ── ML anomaly detection ───────────────────────────────────────────
        try:
            feature = [float(packet_count), float(unique_ports)]
            if ml_predict(feature):
                handle_alert(src_ip, f"[ML] ML Anomaly detected from {src_ip}")
                block_ip(src_ip)
                if stat["type"] == "normal":
                    stat["type"] = "ml"
        except Exception as ml_err:
            logging.debug("[NADS] ML check error: %s", ml_err)

        with _lock:
            attack_stats.append(stat)

    except Exception as e:
        logging.error("[NADS] _process_packet fatal: %s", e)


# ───────────────────────────────────────────────────────────────────────────
# PROCESSOR THREAD LOOP — drains packet_queue continuously
# ───────────────────────────────────────────────────────────────────────────

def _processor_loop():
    """Worker thread: dequeue and process packets. Runs forever."""
    logging.info("[NADS] PacketProcessor thread running.")
    while True:
        try:
            pkt = packet_queue.get(timeout=1.0)
            try:
                _process_packet(pkt)
            except Exception as e:
                logging.error("[NADS] Processor item error: %s", e)
            finally:
                packet_queue.task_done()
        except queue.Empty:
            continue
        except Exception as e:
            logging.error("[NADS] Processor loop error: %s", e)
            time.sleep(0.1)  # brief back-off before retry


# ───────────────────────────────────────────────────────────────────────────
# SCAPY ENQUEUE CALLBACK — must never block
# ───────────────────────────────────────────────────────────────────────────

def _enqueue_packet(packet):
    try:
        packet_queue.put_nowait(packet)
    except queue.Full:
        pass  # intentional drop under load
    except Exception:
        pass


# ───────────────────────────────────────────────────────────────────────────
# DEMO MODE — synthetic alert / traffic generator
# ───────────────────────────────────────────────────────────────────────────

_DEMO_IPS = [
    "192.168.1.101", "10.0.0.55", "172.16.0.23",
    "203.0.113.42",  "198.51.100.7"
]
_DEMO_ATTACK_TYPES = ["dos", "port", "ml", "payload"]
_DEMO_MESSAGES = {
    "dos":     "[!] DoS Attack detected from {ip} ({count} pkt/5s) [DEMO]",
    "port":    "[!] Port Scan detected from {ip} ({count} ports/5s) [DEMO]",
    "ml":      "[ML] ML Anomaly detected from {ip} [DEMO]",
    "payload": "[!] Suspicious Payload detected from {ip} [DEMO]",
}


def _demo_loop():
    """
    Generate synthetic alerts, stats and traffic in demo mode.
    Runs on a dedicated daemon thread when DEMO_MODE = True.
    Sleep is always bounded to prevent tight spin.
    """
    logging.info("[DEMO] Demo mode active — generating synthetic alerts.")
    cycle = 0
    while True:
        try:
            sleep_s = random.uniform(2.5, 5.0)
            time.sleep(sleep_s)

            now   = time.time()
            ip    = random.choice(_DEMO_IPS)
            atype = _DEMO_ATTACK_TYPES[cycle % len(_DEMO_ATTACK_TYPES)]
            count = random.randint(10, 50)

            msg = _DEMO_MESSAGES[atype].format(ip=ip, count=count)

            with _lock:
                alerts.append(msg)
                attack_stats.append({"ip": ip, "time": now, "type": atype})
                ip_counter[ip] += random.randint(5, 20)
                bucket = int(now)
                traffic_buckets[bucket] = (
                    traffic_buckets.get(bucket, 0) + random.randint(15, 80)
                )

            save_alert(msg)
            logging.info("[DEMO] %s", msg)
            cycle += 1

        except Exception as e:
            logging.error("[DEMO] _demo_loop error: %s", e)
            time.sleep(5)  # back-off on error, never spin-die


# ───────────────────────────────────────────────────────────────────────────
# INTERFACE DETECTION
# ───────────────────────────────────────────────────────────────────────────

def _get_sniff_interface():
    """
    Return best list of interfaces for sniffing, or None to use Scapy default.
    Always includes loopback to catch local traffic.
    """
    if not SCAPY_AVAILABLE:
        return None

    try:
        available = get_if_list()
        logging.info("[NADS] Available interfaces: %s", available)
    except Exception as e:
        logging.warning("[NADS] get_if_list() failed: %s", e)
        return None

    preferred = []
    for name in ["eth0", "eth1", "wlan0", "wlan1"]:
        if name in available:
            preferred.append(name)

    for name in available:
        if (name.startswith("ens") or name.startswith("enp") or name.startswith("em")):
            if name not in preferred:
                preferred.append(name)

    for name in ["lo", "lo0", "Loopback Pseudo-Interface 1"]:
        if name in available and name not in preferred:
            preferred.append(name)

    if preferred:
        logging.info("[NADS] Sniffing on: %s", preferred)
        return preferred

    logging.warning("[NADS] No preferred interfaces found — using Scapy default.")
    return None


# ───────────────────────────────────────────────────────────────────────────
# START SNIFFING — called by app.py on a daemon thread
# ───────────────────────────────────────────────────────────────────────────
def _sniff_loop():
    """Runs Scapy sniff safely in its own thread (non-blocking for Flask)."""
    try:
        iface = _get_sniff_interface()
        iface_str = str(iface) if iface else "default"

        print(f"[NADS] Packet Sniffer active (Scapy) on: {iface_str}")
        print(
            f"[NADS] Thresholds → DoS: >{DOS_THRESHOLD} pkts/{TIME_WINDOW}s "
            f"| Port Scan: >{PORT_SCAN_THRESHOLD} ports/{TIME_WINDOW}s"
        )

        if iface:
            sniff(prn=_enqueue_packet, store=False, iface=iface)
        else:
            sniff(prn=_enqueue_packet, store=False)

    except Exception as e:
        logging.error("[NADS] Sniff error: %s — retrying...", e)
        time.sleep(5)

        try:
            sniff(prn=_enqueue_packet, store=False)
        except Exception as e2:
            logging.critical("[NADS] Sniffer failed completely: %s", e2)
def start_sniffing():
    """
    Fixed version:
    - Processor thread
    - Demo thread
    - Sniffer thread (non-blocking)
    """

    print("[NADS] Starting sniffer system...")

    # ── Packet processor ─────────────────────
    threading.Thread(
        target=_processor_loop,
        daemon=True,
        name="PacketProcessor"
    ).start()

    # ── Demo generator ───────────────────────
    if DEMO_MODE:
        threading.Thread(
            target=_demo_loop,
            daemon=True,
            name="DemoGenerator"
        ).start()
        print("[NADS] *** DEMO MODE ON — Synthetic alerts running ***")
    else:
        print("[NADS] Demo mode OFF")

    # ── FIXED: Run sniff in separate thread ──
    if SCAPY_AVAILABLE:
        threading.Thread(
            target=_sniff_loop,
            daemon=True,
            name="SnifferLoop"
        ).start()
    else:
        logging.warning("[NADS] Scapy unavailable — packet capture skipped.")
