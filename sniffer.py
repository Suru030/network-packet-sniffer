import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from scapy.all import sniff, ARP, IP, Ether, DNS, DNSQR, get_if_list, conf
from collections import defaultdict, deque
import threading
import subprocess
import platform
import csv
import time
import queue
import os

# ML imports
import numpy as np
try:
    from sklearn.ensemble import IsolationForest
    import joblib
except Exception:
    IsolationForest = None
    joblib = None

import matplotlib
matplotlib.use("TkAgg")
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.pyplot as plt

# -------------------- Global state --------------------
devices = {}  # mac -> latest ip
protocols_by_device = defaultdict(lambda: defaultdict(int))  # mac -> proto -> count
destinations_by_device = defaultdict(set)  # mac -> set(dest)
packet_counters = defaultdict(int)  # mac -> total packets
bytes_counters = defaultdict(int)  # mac -> total bytes
last_seen = {}  # mac -> timestamp

sniffing = False
sniff_thread = None
packet_queue = queue.Queue()  # thread-safe queue for packets

# For sliding-window feature extraction
WINDOW_SECONDS = 10
feature_windows = defaultdict(lambda: deque(maxlen=6))  # store up to 6 windows => 60s history
current_window = defaultdict(lambda: {"pkts": 0, "bytes": 0, "dests": set(), "tcp": 0, "udp": 0, "icmp": 0, "arp": 0, "dns": 0})
window_lock = threading.Lock()

# IDS model
ids_model = None
model_path = "ids_model.joblib"
ids_enabled = False
baseline_collection = []
collecting_baseline = False
BASELINE_PERIODS = 6  # number of windows to collect for baseline (WINDOW_SECONDS * BASELINE_PERIODS seconds)
CONTAMINATION = 0.02

# Alerts log
alerts = []

# -------------------- Utility functions --------------------
def get_connected_ssid():
    if platform.system() == "Windows":
        try:
            output = subprocess.check_output("netsh wlan show interfaces", shell=True).decode("utf-8", errors="ignore")
            ssid, interface = "Unknown", "Unknown"
            for line in output.splitlines():
                line = line.strip()
                if line.startswith("Name") and ':' in line:
                    interface = line.split(":", 1)[1].strip()
                if line.startswith("SSID") and "BSSID" not in line:
                    ssid = line.split(":", 1)[1].strip()
            return ssid, interface
        except Exception:
            return "Unknown", "Unknown"
    # basic Linux support
    if platform.system() == "Linux":
        try:
            output = subprocess.check_output(["iwgetid", "-r"], stderr=subprocess.DEVNULL).decode().strip()
            iface = "Unknown"
            return output if output else "Unknown", iface
        except Exception:
            return "Not available", "Not available"
    return "Not available", "Not available"

# -------------------- Packet processing --------------------

def packet_callback(packet):
    """Called in sniff thread. Only put a small summary into queue to be processed by main thread."""
    try:
        if not packet:
            return
        summary = {}
        if packet.haslayer(Ether):
            ether = packet[Ether]
            mac = ether.src
            summary['mac'] = mac
            summary['len'] = len(packet)

            if packet.haslayer(IP):
                ip = packet[IP].src
                dst_ip = packet[IP].dst
                proto = packet[IP].proto
                summary['ip'] = ip
                summary['dst'] = dst_ip
                summary['proto'] = proto
            elif packet.haslayer(ARP):
                summary['ip'] = packet[ARP].psrc
                summary['dst'] = None
                summary['proto'] = 'ARP'

            if packet.haslayer(DNS) and packet.haslayer(DNSQR):
                try:
                    dns_query = packet[DNSQR].qname.decode().strip('.')
                    summary['dns'] = dns_query
                except Exception:
                    summary['dns'] = None

            packet_queue.put(summary)
    except Exception:
        pass

# -------------------- Main-thread packet processor --------------------

def process_queued_packets(tree, info_labels, alerts_text):
    updated = False
    while True:
        try:
            summary = packet_queue.get_nowait()
        except queue.Empty:
            break
        mac = summary.get('mac')
        if not mac:
            continue
        ip = summary.get('ip')
        dst = summary.get('dst')
        proto = summary.get('proto')
        dns = summary.get('dns')
        plen = summary.get('len', 0)

        # update basic stores
        if ip:
            devices[mac] = ip
        last_seen[mac] = time.time()
        packet_counters[mac] += 1
        bytes_counters[mac] += plen
        if dst:
            destinations_by_device[mac].add(dst)
        if dns:
            destinations_by_device[mac].add(dns)

        # update protocol counts
        if proto == 6 or proto == '6':
            protocols_by_device[mac]['TCP'] += 1
        elif proto == 17 or proto == '17':
            protocols_by_device[mac]['UDP'] += 1
        elif proto == 1 or proto == '1':
            protocols_by_device[mac]['ICMP'] += 1
        elif proto == 'ARP':
            protocols_by_device[mac]['ARP'] += 1

        if dns:
            protocols_by_device[mac]['DNS'] += 1

        # update current window counters
        with window_lock:
            w = current_window[mac]
            w['pkts'] += 1
            w['bytes'] += plen
            if dst:
                w['dests'].add(dst)
            if proto == 6 or proto == '6':
                w['tcp'] += 1
            elif proto == 17 or proto == '17':
                w['udp'] += 1
            elif proto == 1 or proto == '1':
                w['icmp'] += 1
            elif proto == 'ARP':
                w['arp'] += 1
            if dns:
                w['dns'] += 1

        updated = True

    if updated:
        update_table(tree)
        update_info_labels(info_labels)

    # run IDS scoring on a schedule (we call this from mainloop every second)
    run_window_rollover_if_needed(tree, alerts_text)

# -------------------- Window rollover & feature extraction --------------------
last_window_time = time.time()

def run_window_rollover_if_needed(tree, alerts_text):
    global last_window_time, collecting_baseline
    now = time.time()
    if now - last_window_time >= WINDOW_SECONDS:
        # snapshot current_window into feature_windows
        with window_lock:
            for mac, data in list(current_window.items()):
                feat = [data['pkts'], data['bytes'], len(data['dests']), data['tcp'], data['udp'], data['icmp'], data['arp'], data['dns']]
                feature_windows[mac].append(feat)
                # reset current window
                current_window[mac] = {"pkts": 0, "bytes": 0, "dests": set(), "tcp": 0, "udp": 0, "icmp": 0, "arp": 0, "dns": 0}
        last_window_time = now

        # collect baseline if needed
        if collecting_baseline:
            collect_baseline_samples()

        # run IDS scoring
        if ids_enabled and ids_model is not None:
            score_and_flag_devices(tree, alerts_text)

# -------------------- IDS: baseline collection, training, scoring --------------------

def collect_baseline_samples():
    global baseline_collection, collecting_baseline
    # create dataset from feature_windows for all devices
    rows = []
    for mac, deq in feature_windows.items():
        # flatten last BASELINE_PERIODS windows if available, else skip
        if len(deq) >= BASELINE_PERIODS:
            # take last BASELINE_PERIODS windows and average them
            arr = np.array(list(deq)[-BASELINE_PERIODS:])
            avg = np.mean(arr, axis=0)
            rows.append(avg)
    if rows:
        baseline_collection.extend(rows)
    # stop collecting when we have enough samples
    if len(baseline_collection) >= 50:  # arbitrary threshold
        collecting_baseline = False
        train_ids_model()


def train_ids_model():
    global ids_model
    if IsolationForest is None:
        print("scikit-learn not available: cannot train IDS")
        return
    X = np.array(baseline_collection)
    if len(X) < 5:
        print("Not enough baseline data to train IDS")
        return
    model = IsolationForest(contamination=CONTAMINATION, random_state=42)
    model.fit(X)
    ids_model = model
    # persist model
    try:
        joblib.dump(model, model_path)
    except Exception:
        pass
    print("IDS model trained and saved.")


def load_ids_model_if_exists():
    global ids_model
    if joblib is None:
        return
    if os.path.exists(model_path):
        try:
            ids_model = joblib.load(model_path)
        except Exception:
            ids_model = None


def score_and_flag_devices(tree, alerts_text):
    # For each device, compute feature vector from last BASELINE_PERIODS windows (or use available)
    rows = []
    macs = []
    for mac, deq in feature_windows.items():
        if len(deq) == 0:
            continue
        arr = np.array(list(deq))
        # take mean across windows to form feature vector
        avg = np.mean(arr, axis=0)
        rows.append(avg)
        macs.append(mac)
    if not rows:
        return
    X = np.array(rows)
    try:
        preds = ids_model.predict(X)  # -1 for anomaly, 1 for normal
        scores = ids_model.decision_function(X)
    except Exception:
        return

    # mark anomalous devices
    for mac, pred, score in zip(macs, preds, scores):
        if pred == -1:
            msg = f"Anomaly detected on {mac} (score={score:.4f})"
            log_alert(msg, alerts_text)
            highlight_device_in_tree(tree, mac)

# -------------------- UI helpers --------------------

def highlight_device_in_tree(tree, mac):
    # find tree item by MAC and tag it as 'anomaly'
    for item in tree.get_children():
        vals = tree.item(item, 'values')
        if len(vals) >= 2 and vals[1] == mac:
            tree.item(item, tags=('anomaly',))
            tree.tag_configure('anomaly', background='#ffcccc')


def log_alert(msg, alerts_text):
    timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
    full = f"[{timestamp}] {msg}"
    alerts.append(full)
    try:
        alerts_text.config(state='normal')
        alerts_text.insert('end', full + "\n")
        alerts_text.see('end')
        alerts_text.config(state='disabled')
    except Exception:
        pass

# -------------------- GUI & controls --------------------

def update_table(tree):
    ssid, _ = get_connected_ssid()
    tree.delete(*tree.get_children())
    for mac, ip in devices.items():
        proto_counts = protocols_by_device[mac]
        proto_list = ', '.join([f"{k}:{v}" for k, v in sorted(proto_counts.items(), key=lambda x: x[0])])
        dest_list = ', '.join(sorted(list(destinations_by_device[mac]))[:5])
        tree.insert("", "end", values=[ip, mac, proto_list, dest_list if dest_list else "N/A", ssid])


def update_info_labels(labels):
    ssid, iface = get_connected_ssid()
    labels["ssid"].config(text=f"Wi-Fi SSID: {ssid}")
    labels["iface"].config(text=f"Interface: {iface}")
    labels["devices"].config(text=f"Connected Devices: {len(devices)}")


def start_sniffing(tree, info_labels):
    global sniff_thread, sniffing
    if not sniffing:
        sniffing = True
        sniff_thread = threading.Thread(
            target=lambda: sniff(prn=lambda pkt: packet_callback(pkt), store=False, stop_filter=lambda x: not sniffing),
            daemon=True
        )
        sniff_thread.start()


def stop_sniffing():
    global sniffing
    sniffing = False


def export_to_csv():
    file = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
    if file:
        with open(file, mode='w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["IP Address", "MAC Address", "Protocols", "Accessed Servers", "Wi-Fi SSID"])
            ssid, _ = get_connected_ssid()
            for mac, ip in devices.items():
                proto_list = ', '.join(sorted(protocols_by_device[mac].keys()))
                dest_list = ', '.join(sorted(destinations_by_device[mac]))
                writer.writerow([ip, mac, proto_list, dest_list if dest_list else "N/A", ssid])


def reset_data(tree, info_labels, alerts_text):
    global devices, protocols_by_device, destinations_by_device, packet_counters, bytes_counters, feature_windows, baseline_collection, ids_model, alerts
    devices.clear()
    protocols_by_device.clear()
    destinations_by_device.clear()
    packet_counters.clear()
    bytes_counters.clear()
    feature_windows.clear()
    baseline_collection = []
    alerts = []
    if alerts_text:
        alerts_text.config(state='normal')
        alerts_text.delete('1.0', 'end')
        alerts_text.config(state='disabled')
    update_table(tree)
    update_info_labels(info_labels)

# ========== Analytics Window Code ==========
def launch_analytics():
    analytics_window = tk.Toplevel()
    analytics_window.title("Data Visualization")
    analytics_window.geometry("700x500")
    analytics_window.configure(bg='#1e1e1e')

    heading = tk.Label(analytics_window, text="Network Traffic Analytics", font=("Arial", 16, "bold"), fg="white", bg="#1e1e1e")
    heading.pack(pady=10)

    fig, ax = plt.subplots(figsize=(5, 4))
    canvas = FigureCanvasTkAgg(fig, master=analytics_window)
    canvas.get_tk_widget().pack(pady=20)

    def update_chart_periodically():
        proto_counts = {"TCP": 0, "UDP": 0, "ICMP": 0, "ARP": 0, "DNS": 0}
        for plist in protocols_by_device.values():
            for proto, cnt in plist.items():
                if proto in proto_counts:
                    proto_counts[proto] += cnt

        labels = [k for k, v in proto_counts.items() if v > 0]
        sizes = [v for v in proto_counts.values() if v > 0]
        if not labels:
            labels = ["No Data"]
            sizes = [1]

        ax.clear()
        ax.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=90)
        ax.set_title("Protocol Distribution")
        canvas.draw()
        analytics_window.after(1000, update_chart_periodically)

    update_chart_periodically()
# ==============================================

# -------------------- IDS Control --------------------

def enable_ids(tree, alerts_text, baseline_seconds=WINDOW_SECONDS*BASELINE_PERIODS):
    global ids_enabled, collecting_baseline, baseline_collection
    if IsolationForest is None:
        messagebox.showerror("Dependency missing", "scikit-learn is required for IDS. Install via pip install scikit-learn joblib")
        return
    ids_enabled = True
    loading = False
    # if model exists, load, else collect baseline
    load_ids_model_if_exists()
    if ids_model is None:
        # start baseline collection
        collecting_baseline = True
        baseline_collection = []
        messagebox.showinfo("IDS Baseline", f"Collecting baseline for {baseline_seconds} seconds. Try to keep network idle for reliable baseline.")
    else:
        messagebox.showinfo("IDS", "Loaded existing IDS model. Real-time detection enabled.")


def disable_ids():
    global ids_enabled
    ids_enabled = False
    messagebox.showinfo("IDS", "IDS disabled.")

# -------------------- Periodic mainloop polling --------------------

def schedule_queue_processing(root, tree, info_labels, alerts_text):
    process_queued_packets(tree, info_labels, alerts_text)
    root.after(1000, schedule_queue_processing, root, tree, info_labels, alerts_text)

# -------------------- GUI Launcher --------------------

def launch_gui():
    root = tk.Tk()
    root.title("Network Packet Sniffer and Traffic Analyzer with IDS")
    root.geometry("1200x700")
    root.configure(bg='#1e1e1e')

    style = ttk.Style()
    style.theme_use("clam")
    style.configure("Treeview", background="#2e2e2e", foreground="white", fieldbackground="#2e2e2e", rowheight=28)
    style.configure("Treeview.Heading", background="#444", foreground="white")

    # Info Section
    info_frame = tk.Frame(root, bg='#1e1e1e')
    info_frame.pack(pady=(10, 5))

    ssid_label = tk.Label(info_frame, text="Wi-Fi SSID: N/A", font=("Arial", 12), bg="#1e1e1e", fg="white")
    ssid_label.grid(row=0, column=0, padx=20)
    iface_label = tk.Label(info_frame, text="Interface: N/A", font=("Arial", 12), bg="#1e1e1e", fg="white")
    iface_label.grid(row=0, column=1, padx=20)
    device_label = tk.Label(info_frame, text="Connected Devices: 0", font=("Arial", 12), bg="#1e1e1e", fg="white")
    device_label.grid(row=0, column=2, padx=20)

    info_labels = {
        "ssid": ssid_label,
        "iface": iface_label,
        "devices": device_label
    }

    # Add Reset button next to info labels
    reset_btn = tk.Button(info_frame, text="Reset", bg="#FF9800", fg="white", font=("Arial", 12, "bold"),
                          command=lambda: reset_data(tree, info_labels, alerts_text))
    reset_btn.grid(row=0, column=3, padx=20)

    columns = ("IP Address", "MAC Address", "Protocols", "Accessed Servers", "Wi-Fi SSID")
    tree = ttk.Treeview(root, columns=columns, show="headings")
    for col in columns:
        tree.heading(col, text=col)
        tree.column(col, width=200, anchor="center")
    tree.pack(fill="both", expand=True, padx=10, pady=10)

    # Alerts panel
    alerts_frame = tk.Frame(root, bg='#1e1e1e')
    alerts_frame.pack(fill='x', padx=10, pady=(0,10))
    alerts_label = tk.Label(alerts_frame, text="Alerts:", font=("Arial", 12), bg="#1e1e1e", fg="white")
    alerts_label.pack(side='left')
    alerts_text = tk.Text(alerts_frame, height=4, state='disabled')
    alerts_text.pack(fill='x', padx=10)

    button_frame = tk.Frame(root, bg='#1e1e1e')
    button_frame.pack(pady=10)

    tk.Button(button_frame, text="Start Sniffing", bg="#4CAF50", fg="white", font=("Arial", 12, "bold"),
              command=lambda: start_sniffing(tree, info_labels)).pack(side="left", padx=10)
    tk.Button(button_frame, text="Stop Sniffing", bg="#f44336", fg="white", font=("Arial", 12, "bold"),
              command=stop_sniffing).pack(side="left", padx=10)
    tk.Button(button_frame, text="Export to CSV", bg="#2196F3", fg="white", font=("Arial", 12, "bold"),
              command=export_to_csv).pack(side="left", padx=10)
    tk.Button(button_frame, text="Analytics", bg="#9C27B0", fg="white", font=("Arial", 12, "bold"),
              command=launch_analytics).pack(side="left", padx=10)

    tk.Button(button_frame, text="Enable IDS", bg="#607D8B", fg="white", font=("Arial", 12, "bold"),
              command=lambda: enable_ids(tree, alerts_text)).pack(side="left", padx=10)
    tk.Button(button_frame, text="Disable IDS", bg="#9E9E9E", fg="white", font=("Arial", 12, "bold"),
              command=disable_ids).pack(side="left", padx=10)

    update_info_labels(info_labels)

    # load model if exists
    load_ids_model_if_exists()

    # schedule queue processing
    schedule_queue_processing(root, tree, info_labels, alerts_text)

    root.mainloop()

if __name__ == "__main__":
    launch_gui()
