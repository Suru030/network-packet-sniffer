import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from scapy.all import sniff, ARP, IP, Ether, DNS, DNSQR
from collections import defaultdict, deque
import threading
import subprocess
import platform
import csv
import time
import queue
import os
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
devices = {}
protocols_by_device = defaultdict(lambda: defaultdict(int))
destinations_by_device = defaultdict(set)
packet_counters = defaultdict(int)
bytes_counters = defaultdict(int)
last_seen = {}
recent_packets = defaultdict(lambda: deque(maxlen=200))

sniffing = False
sniff_thread = None
packet_queue = queue.Queue()

WINDOW_SECONDS = 10
feature_windows = defaultdict(lambda: deque(maxlen=6))
current_window = defaultdict(lambda: {"pkts": 0, "bytes": 0, "dests": set(), "tcp": 0, "udp": 0, "icmp": 0, "arp": 0, "dns": 0})
window_lock = threading.Lock()

ids_model = None
model_path = "ids_model.joblib"
ids_enabled = False
baseline_collection = []
collecting_baseline = False
BASELINE_PERIODS = 6
CONTAMINATION = 0.02

alerts = []
anomaly_reasons = defaultdict(lambda: deque(maxlen=50))

Z_THRESHOLD = 2.0
MULTIPLIER_THRESHOLD = 3.0
FEATURE_LABELS = ["packets", "bytes", "unique_dests", "tcp", "udp", "icmp", "arp", "dns"]

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
    if platform.system() == "Linux":
        try:
            output = subprocess.check_output(["iwgetid", "-r"], stderr=subprocess.DEVNULL).decode().strip()
            return output if output else "Unknown", "Unknown"
        except Exception:
            return "Not available", "Not available"
    return "Not available", "Not available"

# -------------------- Packet processing --------------------
def packet_callback(packet):
    try:
        if not packet:
            return
        summary = {}
        if packet.haslayer(Ether):
            ether = packet[Ether]
            mac = ether.src
            summary['mac'] = mac
            summary['len'] = len(packet)
            summary['time'] = time.time()
            if packet.haslayer(IP):
                summary['ip'] = packet[IP].src
                summary['dst'] = packet[IP].dst
                summary['proto'] = packet[IP].proto
            elif packet.haslayer(ARP):
                summary['ip'] = packet[ARP].psrc
                summary['dst'] = None
                summary['proto'] = 'ARP'
            if packet.haslayer(DNS) and packet.haslayer(DNSQR):
                try:
                    summary['dns'] = packet[DNSQR].qname.decode().strip('.')
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
        ptime = summary.get('time', time.time())
        if ip:
            devices[mac] = ip
        last_seen[mac] = ptime
        packet_counters[mac] += 1
        bytes_counters[mac] += plen
        if dst:
            destinations_by_device[mac].add(dst)
        if dns:
            destinations_by_device[mac].add(dns)
        recent_packets[mac].appendleft({'time': ptime, 'ip': ip, 'dst': dst or dns, 'proto': proto, 'len': plen})
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
    run_window_rollover_if_needed(tree, alerts_text)

# -------------------- Window rollover & feature extraction --------------------
last_window_time = time.time()

def run_window_rollover_if_needed(tree, alerts_text):
    global last_window_time, collecting_baseline
    now = time.time()
    if now - last_window_time >= WINDOW_SECONDS:
        with window_lock:
            for mac, data in list(current_window.items()):
                feat = [data['pkts'], data['bytes'], len(data['dests']), data['tcp'], data['udp'], data['icmp'], data['arp'], data['dns']]
                feature_windows[mac].append(feat)
                current_window[mac] = {"pkts": 0, "bytes": 0, "dests": set(), "tcp": 0, "udp": 0, "icmp": 0, "arp": 0, "dns": 0}
        last_window_time = now
        if collecting_baseline:
            collect_baseline_samples()
        if ids_enabled and ids_model is not None:
            score_and_flag_devices(tree, alerts_text)

# -------------------- IDS baseline collection / training --------------------
def collect_baseline_samples():
    global baseline_collection, collecting_baseline
    rows = []
    for mac, deq in feature_windows.items():
        if len(deq) >= BASELINE_PERIODS:
            arr = np.array(list(deq)[-BASELINE_PERIODS:])
            avg = np.mean(arr, axis=0)
            rows.append(avg)
    if rows:
        baseline_collection.extend(rows)
    if len(baseline_collection) >= 50:
        collecting_baseline = False
        train_ids_model()

def train_ids_model():
    global ids_model
    if IsolationForest is None:
        return
    X = np.array(baseline_collection)
    if len(X) < 5:
        return
    model = IsolationForest(contamination=CONTAMINATION, random_state=42)
    model.fit(X)
    ids_model = model
    try:
        joblib.dump(model, model_path)
    except:
        pass

def load_ids_model_if_exists():
    global ids_model
    if joblib is None:
        return
    if os.path.exists(model_path):
        try:
            ids_model = joblib.load(model_path)
        except:
            ids_model = None

# -------------------- IDS scoring + reason extraction --------------------
def explain_anomaly(mac, deq):
    reasons = []
    try:
        arr = np.array(list(deq))
        if arr.size == 0:
            return reasons
        if arr.shape[0] == 1:
            return reasons
        hist = arr[:-1]
        last = arr[-1].astype(float)
        mu = np.mean(hist, axis=0)
        sigma = np.std(hist, axis=0, ddof=0)
        for i, feat_name in enumerate(FEATURE_LABELS):
            last_val = float(last[i])
            mean_val = float(mu[i]) if not np.isnan(mu[i]) else 0.0
            std_val = float(sigma[i]) if not np.isnan(sigma[i]) else 0.0
            if std_val > 0:
                z = (last_val - mean_val) / std_val
            else:
                z = None
            if z is not None and z >= Z_THRESHOLD:
                reasons.append(f"High {feat_name} (z={z:.2f}, last={int(last_val)}, mean={int(mean_val)})")
            elif mean_val > 0 and last_val >= mean_val * MULTIPLIER_THRESHOLD:
                reasons.append(f"Spike in {feat_name} (last={int(last_val)})")
        last_unique = int(arr[-1][2])
        if last_unique >= 20:
            reasons.append("Many unique destinations")
        last_dns = int(arr[-1][7])
        if last_dns >= 30:
            reasons.append("High DNS query rate")
    except:
        pass
    return reasons

def score_and_flag_devices(tree, alerts_text):
    rows = []
    macs = []
    for mac, deq in feature_windows.items():
        if len(deq) == 0:
            continue
        arr = np.array(list(deq))
        rows.append(np.mean(arr, axis=0))
        macs.append(mac)
    if not rows:
        return
    X = np.array(rows)
    try:
        preds = ids_model.predict(X)
        scores = ids_model.decision_function(X)
    except:
        return
    for mac, pred, score in zip(macs, preds, scores):
        if pred == -1:
            deq = feature_windows.get(mac, deque())
            reasons = explain_anomaly(mac, deq)
            if reasons:
                msg = f"Anomaly detected on {mac} (score={score:.4f}) - Reasons: " + " | ".join(reasons)
            else:
                msg = f"Anomaly detected on {mac} (score={score:.4f})"
            log_alert(msg, alerts_text)
            anomaly_reasons[mac].appendleft((time.strftime('%Y-%m-%d %H:%M:%S'), reasons))
            highlight_device_in_tree(tree, mac)

# -------------------- UI helpers --------------------
def highlight_device_in_tree(tree, mac):
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
    except:
        pass

# -------------------- Device detail window --------------------
def open_device_detail_window(mac):
    detail_win = tk.Toplevel()
    detail_win.title(f"Device Details - {mac}")
    detail_win.geometry("900x600")
    detail_win.configure(bg='#1e1e1e')
    summary_frame = tk.Frame(detail_win, bg='#1e1e1e')
    summary_frame.pack(fill='x', pady=8)
    ip = devices.get(mac, 'N/A')
    tk.Label(summary_frame, text=f"MAC: {mac}", bg='#1e1e1e', fg='white', font=("Arial", 12, "bold")).pack(side='left', padx=10)
    tk.Label(summary_frame, text=f"IP: {ip}", bg='#1e1e1e', fg='white', font=("Arial", 12)).pack(side='left', padx=10)
    anom_count = sum(1 for a in alerts if mac in a)
    tk.Label(summary_frame, text=f"Anomalies: {anom_count}", bg='#1e1e1e', fg='red' if anom_count > 0 else 'white', font=("Arial", 12, "bold")).pack(side='left', padx=10)
    reasons_frame = tk.LabelFrame(detail_win, text="Anomaly Reasons (recent)", bg='#1e1e1e', fg='white')
    reasons_frame.pack(fill='x', padx=10, pady=6)
    reasons_text = tk.Text(reasons_frame, height=6, wrap='word')
    reasons_text.pack(fill='x', padx=6, pady=6)
    reasons_text.delete('1.0', 'end')
    for ts, rlist in list(anomaly_reasons.get(mac, [])):
        if rlist:
            reasons_text.insert('end', f"[{ts}] " + "; ".join(rlist) + "\n")
        else:
            reasons_text.insert('end', f"[{ts}] Anomaly\n")
    reasons_text.config(state='disabled')
    dest_frame = tk.LabelFrame(detail_win, text="Accessed Servers / Destinations", bg='#1e1e1e', fg='white')
    dest_frame.pack(fill='both', expand=False, padx=10, pady=6)
    dest_tree = ttk.Treeview(dest_frame, columns=("Destination", "Count"), show='headings', height=6)
    dest_tree.heading('Destination', text='Destination')
    dest_tree.heading('Count', text='Count')
    dest_tree.pack(fill='both', expand=True, padx=6, pady=6)
    dest_counts = defaultdict(int)
    for pkt in recent_packets.get(mac, []):
        target = pkt.get('dst')
        if target:
            dest_counts[target] += 1
    for d, c in sorted(dest_counts.items(), key=lambda x: -x[1]):
        dest_tree.insert('', 'end', values=[d, c])
    pkt_frame = tk.LabelFrame(detail_win, text="Recent Packets (latest first)", bg='#1e1e1e', fg='white')
    pkt_frame.pack(fill='both', expand=True, padx=10, pady=6)
    pkt_tree = ttk.Treeview(pkt_frame, columns=("Time", "Src IP", "Dst", "Proto", "Len"), show='headings')
    for col in ("Time", "Src IP", "Dst", "Proto", "Len"):
        pkt_tree.heading(col, text=col)
        pkt_tree.column(col, width=140)
    pkt_tree.pack(fill='both', expand=True, padx=6, pady=6)
    for pkt in list(recent_packets.get(mac, []))[:200]:
        ts = time.strftime('%H:%M:%S', time.localtime(pkt.get('time', time.time())))
        pkt_tree.insert('', 'end', values=[ts, pkt.get('ip', 'N/A'), pkt.get('dst', 'N/A'), str(pkt.get('proto', 'N/A')), pkt.get('len', 0)])
    def save_device_activity():
        fname = filedialog.asksaveasfilename(defaultextension='.csv')
        if not fname:
            return
        with open(fname, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['time','src_ip','dst','proto','len'])
            for pkt in list(recent_packets.get(mac, [])):
                writer.writerow([time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(pkt.get('time', time.time()))), pkt.get('ip',''), pkt.get('dst',''), pkt.get('proto',''), pkt.get('len',0)])
        messagebox.showinfo('Saved', f'Device activity saved to {fname}')
    tk.Button(detail_win, text='Save Device Activity (CSV)', command=save_device_activity, bg='#2196F3', fg='white').pack(pady=6)

# -------------------- GUI / Controls --------------------
def update_table(tree):
    ssid, _ = get_connected_ssid()
    tree.delete(*tree.get_children())
    for mac, ip in devices.items():
        proto_counts = protocols_by_device[mac]
        proto_list = ', '.join([f"{k}:{v}" for k, v in sorted(proto_counts.items())])
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
        sniff_thread = threading.Thread(target=lambda: sniff(prn=lambda pkt: packet_callback(pkt), store=False, stop_filter=lambda x: not sniffing), daemon=True)
        sniff_thread.start()

def stop_sniffing():
    global sniffing
    sniffing = False

def export_to_csv():
    file = filedialog.asksaveasfilename(defaultextension=".csv")
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
    global devices, protocols_by_device, destinations_by_device, packet_counters, bytes_counters, feature_windows, baseline_collection, ids_model, alerts, recent_packets, anomaly_reasons
    devices.clear()
    protocols_by_device.clear()
    destinations_by_device.clear()
    packet_counters.clear()
    bytes_counters.clear()
    feature_windows.clear()
    baseline_collection = []
    alerts = []
    recent_packets.clear()
    anomaly_reasons.clear()
    if alerts_text:
        alerts_text.config(state='normal')
        alerts_text.delete('1.0', 'end')
        alerts_text.config(state='disabled')
    update_table(tree)
    update_info_labels(info_labels)

# -------------------- Analytics Window --------------------
def launch_analytics():
    analytics_window = tk.Toplevel()
    analytics_window.title("Data Visualization")
    analytics_window.geometry("700x500")
    analytics_window.configure(bg='#1e1e1e')
    tk.Label(analytics_window, text="Network Traffic Analytics", font=("Arial", 16, "bold"), fg="white", bg="#1e1e1e").pack(pady=10)
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

# -------------------- IDS Controls --------------------
def enable_ids(tree, alerts_text, baseline_seconds=WINDOW_SECONDS*BASELINE_PERIODS):
    global ids_enabled, collecting_baseline, baseline_collection
    if IsolationForest is None:
        messagebox.showerror("Missing", "Install scikit-learn & joblib")
        return
    ids_enabled = True
    load_ids_model_if_exists()
    if ids_model is None:
        collecting_baseline = True
        baseline_collection = []
        messagebox.showinfo("IDS", f"Collecting baseline for {baseline_seconds} seconds.")
    else:
        messagebox.showinfo("IDS", "Loaded model. Detection enabled.")

def disable_ids():
    global ids_enabled
    ids_enabled = False
    messagebox.showinfo("IDS", "IDS disabled.")

# -------------------- Mainloop queue scheduler --------------------
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
    info_frame = tk.Frame(root, bg='#1e1e1e')
    info_frame.pack(pady=(10, 5))
    ssid_label = tk.Label(info_frame, text="Wi-Fi SSID: N/A", font=("Arial", 12), bg="#1e1e1e", fg="white")
    ssid_label.grid(row=0, column=0, padx=20)
    iface_label = tk.Label(info_frame, text="Interface: N/A", font=("Arial", 12), bg="#1e1e1e", fg="white")
    iface_label.grid(row=0, column=1, padx=20)
    device_label = tk.Label(info_frame, text="Connected Devices: 0", font=("Arial", 12), bg="#1e1e1e", fg="white")
    device_label.grid(row=0, column=2, padx=20)
    info_labels = {"ssid": ssid_label, "iface": iface_label, "devices": device_label}
    reset_btn = tk.Button(info_frame, text="Reset", bg="#FF9800", fg="white", font=("Arial", 12, "bold"), command=lambda: reset_data(tree, info_labels, alerts_text))
    reset_btn.grid(row=0, column=3, padx=20)
    columns = ("IP Address", "MAC Address", "Protocols", "Accessed Servers", "Wi-Fi SSID")
    tree = ttk.Treeview(root, columns=columns, show="headings")
    for col in columns:
        tree.heading(col, text=col)
        tree.column(col, width=200, anchor="center")
    tree.pack(fill="both", expand=True, padx=10, pady=10)
    def on_tree_double_click(event):
        item = tree.identify_row(event.y)
        if not item:
            return
        vals = tree.item(item, 'values')
        if len(vals) >= 2:
            mac = vals[1]
            open_device_detail_window(mac)
    tree.bind('<Double-1>', on_tree_double_click)
    alerts_frame = tk.Frame(root, bg='#1e1e1e')
    alerts_frame.pack(fill='x', padx=10, pady=(0,10))
    alerts_label = tk.Label(alerts_frame, text="Alerts:", font=("Arial", 12), bg="#1e1e1e", fg="white")
    alerts_label.pack(side='left')
    alerts_text = tk.Text(alerts_frame, height=4, state='disabled')
    alerts_text.pack(fill='x', padx=10)
    button_frame = tk.Frame(root, bg='#1e1e1e')
    button_frame.pack(pady=10)
    tk.Button(button_frame, text="Start Sniffing", bg="#4CAF50", fg="white", font=("Arial", 12, "bold"), command=lambda: start_sniffing(tree, info_labels)).pack(side="left", padx=10)
    tk.Button(button_frame, text="Stop Sniffing", bg="#f44336", fg="white", font=("Arial", 12, "bold"), command=stop_sniffing).pack(side="left", padx=10)
    tk.Button(button_frame, text="Export to CSV", bg="#2196F3", fg="white", font=("Arial", 12, "bold"), command=export_to_csv).pack(side="left", padx=10)
    tk.Button(button_frame, text="Analytics", bg="#9C27B0", fg="white", font=("Arial", 12, "bold"), command=launch_analytics).pack(side="left", padx=10)
    tk.Button(button_frame, text="Enable IDS", bg="#607D8B", fg="white", font=("Arial", 12, "bold"), command=lambda: enable_ids(tree, alerts_text)).pack(side="left", padx=10)
    tk.Button(button_frame, text="Disable IDS", bg="#9E9E9E", fg="white", font=("Arial", 12, "bold"), command=disable_ids).pack(side="left", padx=10)
    update_info_labels(info_labels)
    load_ids_model_if_exists()
    schedule_queue_processing(root, tree, info_labels, alerts_text)
    root.mainloop()

if __name__ == "__main__":
    launch_gui()
