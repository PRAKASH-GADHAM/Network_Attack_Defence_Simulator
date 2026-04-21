import threading
import time
import logging
import os

from flask import Flask, render_template, jsonify, request

# ---------------------------------------------------------------------------
# Lazy-import sniffer so Flask can still serve pages even if sniffer fails
# ---------------------------------------------------------------------------
try:
    import sniffer as _sniffer
    SNIFFER_OK = True
except Exception as _sniffer_import_err:
    logging.critical("[NADS] sniffer import failed: %s", _sniffer_import_err)
    _sniffer = None
    SNIFFER_OK = False

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Suppress noisy Werkzeug request logs in production
# ---------------------------------------------------------------------------
log = logging.getLogger("werkzeug")
log.setLevel(logging.ERROR)


# ───────────────────────────────────────────────────────────────────────────
# HELPERS
# ───────────────────────────────────────────────────────────────────────────

def _sniffer_attr(name, default):
    """Safely read any attribute from the sniffer module."""
    try:
        if _sniffer is None:
            return default
        return getattr(_sniffer, name, default)
    except Exception:
        return default


def _sniffer_call(func_name, *args, **kwargs):
    """Safely call a function on the sniffer module."""
    try:
        if _sniffer is None:
            return None
        fn = getattr(_sniffer, func_name, None)
        if callable(fn):
            return fn(*args, **kwargs)
    except Exception as e:
        logging.warning("[NADS] sniffer.%s() error: %s", func_name, e)
    return None


def _read_log_tail(path="attack_logs.txt", n=50):
    """Read the last n lines from a log file. Returns [] on any error."""
    try:
        if not os.path.exists(path):
            return []
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
        return lines[-n:] if lines else []
    except Exception as e:
        logging.warning("[NADS] log read error: %s", e)
        return []


# ───────────────────────────────────────────────────────────────────────────
# BACKGROUND SNIFFER — start once, never restart on reload
# ───────────────────────────────────────────────────────────────────────────

def start_background_sniffer():
    if not SNIFFER_OK:
        logging.warning("[NADS] Sniffer not available — skipping background start.")
        return
    if getattr(start_background_sniffer, "_started", False):
        return
    start_background_sniffer._started = True
    try:
        thread = threading.Thread(
            target=_sniffer.start_sniffing,
            daemon=True,
            name="SnifferThread"
        )
        thread.start()
        logging.info("[NADS] SnifferThread started.")
    except Exception as e:
        logging.error("[NADS] Could not start SnifferThread: %s", e)


# ───────────────────────────────────────────────────────────────────────────
# PAGE ROUTES — each returns a render_template, never raises unhandled
# ───────────────────────────────────────────────────────────────────────────

@app.route("/")
def home():
    try:
        return render_template("index.html")
    except Exception as e:
        logging.error("[NADS] / render error: %s", e)
        return "<h1 style='color:#3fb950;font-family:monospace;padding:2rem'>NADS — template error, check logs.</h1>", 500


@app.route("/alerts")
def alerts_page():
    try:
        return render_template("alerts.html")
    except Exception as e:
        logging.error("[NADS] /alerts render error: %s", e)
        return "<h1 style='color:#3fb950;font-family:monospace;padding:2rem'>NADS — template error.</h1>", 500


@app.route("/logs")
def logs_page():
    try:
        return render_template("logs.html")
    except Exception as e:
        logging.error("[NADS] /logs render error: %s", e)
        return "<h1 style='color:#3fb950;font-family:monospace;padding:2rem'>NADS — template error.</h1>", 500


@app.route("/analytics")
def analytics_page():
    try:
        return render_template("analytics.html")
    except Exception as e:
        logging.error("[NADS] /analytics render error: %s", e)
        return "<h1 style='color:#3fb950;font-family:monospace;padding:2rem'>NADS — template error.</h1>", 500


# ───────────────────────────────────────────────────────────────────────────
# API: /data — alerts snapshot + log tail
# ───────────────────────────────────────────────────────────────────────────

@app.route("/data")
def data():
    try:
        alerts_snapshot = []
        try:
            lock = _sniffer_attr("_lock", None)
            if lock:
                with lock:
                    raw = _sniffer_attr("alerts", [])
                    alerts_snapshot = list(raw)[-50:]
            else:
                raw = _sniffer_attr("alerts", [])
                alerts_snapshot = list(raw)[-50:] if raw else []
        except Exception as e:
            logging.warning("[NADS] /data alerts read error: %s", e)
            alerts_snapshot = []

        logs = _read_log_tail("attack_logs.txt", 50)

        return jsonify({
            "alerts":    [str(a) for a in alerts_snapshot],
            "logs":      [str(l) for l in logs],
            "demo_mode": bool(_sniffer_attr("DEMO_MODE", False))
        })
    except Exception as e:
        logging.error("[NADS] /data error: %s", e)
        return jsonify({"alerts": [], "logs": [], "demo_mode": False, "error": str(e)})


# ───────────────────────────────────────────────────────────────────────────
# API: /stats — cursor-based incremental stats
# ───────────────────────────────────────────────────────────────────────────

@app.route("/stats")
def stats():
    try:
        since = request.args.get("since", type=float, default=None)

        lock = _sniffer_attr("_lock", None)
        if lock:
            with lock:
                raw = _sniffer_attr("attack_stats", [])
                stats_snapshot = list(raw)
        else:
            raw = _sniffer_attr("attack_stats", [])
            stats_snapshot = list(raw) if raw else []

        if since is None:
            return jsonify(stats_snapshot[-50:])

        new_items  = [s for s in stats_snapshot if s.get("time", 0) > since]
        next_since = new_items[-1]["time"] if new_items else since

        return jsonify({
            "items":      new_items,
            "next_since": next_since
        })
    except Exception as e:
        logging.error("[NADS] /stats error: %s", e)
        return jsonify({"items": [], "next_since": 0, "error": str(e)})


# ───────────────────────────────────────────────────────────────────────────
# API: /traffic_buckets — per-second packet counts for line chart
# ───────────────────────────────────────────────────────────────────────────

@app.route("/traffic_buckets")
def traffic_buckets():
    try:
        lock = _sniffer_attr("_lock", None)
        if lock:
            with lock:
                raw = _sniffer_attr("traffic_buckets", {})
                buckets = dict(raw)
        else:
            raw = _sniffer_attr("traffic_buckets", {})
            buckets = dict(raw) if raw else {}

        return jsonify(sorted(buckets.items()))
    except Exception as e:
        logging.error("[NADS] /traffic_buckets error: %s", e)
        return jsonify([])


# ───────────────────────────────────────────────────────────────────────────
# API: /top_ips — top 5 attacking source IPs
# ───────────────────────────────────────────────────────────────────────────

@app.route("/top_ips")
def top_ips():
    try:
        lock = _sniffer_attr("_lock", None)
        ip_counter = _sniffer_attr("ip_counter", None)
        if ip_counter is None:
            return jsonify([])
        if lock:
            with lock:
                top = list(ip_counter.most_common(5))
        else:
            top = list(ip_counter.most_common(5))
        return jsonify(top)
    except Exception as e:
        logging.error("[NADS] /top_ips error: %s", e)
        return jsonify([])


# ───────────────────────────────────────────────────────────────────────────
# API: /summary — aggregated counters (1 s server-side cache)
# ───────────────────────────────────────────────────────────────────────────

_summary_cache = {"data": None, "expires": 0.0}
_summary_lock  = threading.Lock()


@app.route("/summary")
def summary():
    try:
        now = time.time()
        with _summary_lock:
            if _summary_cache["data"] and now < _summary_cache["expires"]:
                return jsonify(_summary_cache["data"])

        lock = _sniffer_attr("_lock", None)

        if lock:
            with lock:
                stats_snapshot = list(_sniffer_attr("attack_stats", []))
                blocked_count  = len(_sniffer_attr("blocked_ips", set()))
                alert_count    = len(_sniffer_attr("alerts", []))
                try:
                    queue_depth = _sniffer_attr("packet_queue", None)
                    queue_depth = queue_depth.qsize() if queue_depth else 0
                except Exception:
                    queue_depth = 0
        else:
            stats_snapshot = list(_sniffer_attr("attack_stats", []))
            blocked_count  = len(_sniffer_attr("blocked_ips", set()))
            alert_count    = len(_sniffer_attr("alerts", []))
            queue_depth    = 0

        counts = {"dos": 0, "port": 0, "ml": 0, "payload": 0, "normal": 0}
        for s in stats_snapshot:
            try:
                t = s.get("type", "normal")
                counts[t] = counts.get(t, 0) + 1
            except Exception:
                pass

        result = {
            "dos":         counts.get("dos", 0),
            "port":        counts.get("port", 0),
            "ml":          counts.get("ml", 0),
            "payload":     counts.get("payload", 0),
            "normal":      counts.get("normal", 0),
            "total":       len(stats_snapshot),
            "blocked_ips": blocked_count,
            "alert_count": alert_count,
            "queue_depth": queue_depth,
            "ml_trained":  bool(_sniffer_attr("_ml_trained", False)),
            "demo_mode":   bool(_sniffer_attr("DEMO_MODE", False))
        }

        with _summary_lock:
            _summary_cache["data"]    = result
            _summary_cache["expires"] = now + 1.0

        return jsonify(result)

    except Exception as e:
        logging.error("[NADS] /summary error: %s", e)
        return jsonify({
            "dos": 0, "port": 0, "ml": 0, "payload": 0, "normal": 0,
            "total": 0, "blocked_ips": 0, "alert_count": 0,
            "queue_depth": 0, "ml_trained": False, "demo_mode": False,
            "error": str(e)
        })


# ───────────────────────────────────────────────────────────────────────────
# API: /health — lightweight liveness probe
# ───────────────────────────────────────────────────────────────────────────

@app.route("/health")
def health():
    try:
        try:
            queue_depth = _sniffer_attr("packet_queue", None)
            queue_depth = queue_depth.qsize() if queue_depth else 0
        except Exception:
            queue_depth = 0

        return jsonify({
            "status":      "running",
            "sniffer_ok":  SNIFFER_OK,
            "queue_depth": queue_depth,
            "ml_trained":  bool(_sniffer_attr("_ml_trained", False)),
            "blocked_ips": len(_sniffer_attr("blocked_ips", set())),
            "stats_count": len(_sniffer_attr("attack_stats", [])),
            "alert_count": len(_sniffer_attr("alerts", [])),
            "demo_mode":   bool(_sniffer_attr("DEMO_MODE", False))
        })
    except Exception as e:
        logging.error("[NADS] /health error: %s", e)
        return jsonify({"status": "error", "error": str(e)})


# ───────────────────────────────────────────────────────────────────────────
# MAIN
# ───────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import webbrowser

    # Configure root logger once
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s"
    )

    start_background_sniffer()

    HOST = "127.0.0.1"
    PORT = 5050
    URL  = f"http://{HOST}:{PORT}"

    print("\n" + "=" * 52)
    print("  NADS — Network Anomaly Detection System")
    print(f"  Dashboard: {URL}")
    print(f"  Sniffer:   {'OK' if SNIFFER_OK else 'FAILED — check sniffer.py'}")
    print("=" * 52 + "\n")

    try:
        webbrowser.open(URL)
    except Exception:
        pass

    app.run(
        host=HOST,
        port=PORT,
        debug=False,
        use_reloader=False,
        threaded=True       # ensure concurrent request handling
    )
