import tkinter as tk
from tkinter import ttk, filedialog
from scapy.all import sniff, ARP, IP, Ether, DNS, DNSQR, get_if_list, conf
from collections import defaultdict
import threading
import subprocess
import platform
import csv

import matplotlib
matplotlib.use("TkAgg")
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.pyplot as plt

devices = {}
protocols_by_device = defaultdict(set)
destinations_by_device = defaultdict(set)
sniffing = False
sniff_thread = None

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
    return "Not available", "Not available"

def packet_callback(packet, tree, info_labels):
    if not sniffing:
        return

    if packet.haslayer(Ether):
        ether = packet[Ether]
        mac = ether.src

        ip = None
        if packet.haslayer(IP):
            ip = packet[IP].src
            dst_ip = packet[IP].dst
            proto = packet[IP].proto

            if mac not in devices:
                devices[mac] = ip

            if proto == 6:
                protocols_by_device[mac].add("TCP")
            elif proto == 17:
                protocols_by_device[mac].add("UDP")
            elif proto == 1:
                protocols_by_device[mac].add("ICMP")

            destinations_by_device[mac].add(dst_ip)

        elif packet.haslayer(ARP):
            ip = packet[ARP].psrc
            if mac not in devices:
                devices[mac] = ip
            protocols_by_device[mac].add("ARP")

        if packet.haslayer(DNS) and packet.haslayer(DNSQR):
            dns_query = packet[DNSQR].qname.decode().strip('.')
            destinations_by_device[mac].add(dns_query)

        update_table(tree)
        update_info_labels(info_labels)

def update_table(tree):
    ssid, _ = get_connected_ssid()
    tree.delete(*tree.get_children())
    for mac, ip in devices.items():
        proto_list = ', '.join(sorted(protocols_by_device[mac]))
        dest_list = ', '.join(sorted(destinations_by_device[mac]))
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
            target=lambda: sniff(prn=lambda pkt: packet_callback(pkt, tree, info_labels),
                                store=False,
                                stop_filter=lambda x: not sniffing),
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
                proto_list = ', '.join(sorted(protocols_by_device[mac]))
                dest_list = ', '.join(sorted(destinations_by_device[mac]))
                writer.writerow([ip, mac, proto_list, dest_list if dest_list else "N/A", ssid])

def reset_data(tree, info_labels):
    global devices, protocols_by_device, destinations_by_device
    devices.clear()
    protocols_by_device.clear()
    destinations_by_device.clear()
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
        proto_counts = {"TCP": 0, "UDP": 0, "ICMP": 0, "ARP": 0}
        for plist in protocols_by_device.values():
            for proto in plist:
                if proto in proto_counts:
                    proto_counts[proto] += 1

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

def launch_gui():
    root = tk.Tk()
    root.title("Network Packet Sniffer and Traffic Analyzer")
    root.geometry("1120x550")
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
                          command=lambda: reset_data(tree, info_labels))
    reset_btn.grid(row=0, column=3, padx=20)

    columns = ("IP Address", "MAC Address", "Protocols", "Accessed Servers", "Wi-Fi SSID")
    tree = ttk.Treeview(root, columns=columns, show="headings")
    for col in columns:
        tree.heading(col, text=col)
        tree.column(col, width=200, anchor="center")
    tree.pack(fill="both", expand=True, padx=10, pady=10)

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

    update_info_labels(info_labels)
    root.mainloop()

if __name__ == "__main__":
    launch_gui()
