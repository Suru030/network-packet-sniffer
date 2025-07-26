# 🕵️‍♂️ Network Packet Sniffer and Traffic Analyzer 🚦

A Python-based application for real-time monitoring of network traffic, featuring a Tkinter GUI that captures connected devices, their protocols, and accessed servers. The tool includes live analytics with updating visualizations, CSV export, and a reset option for easy data management.

---

## ✨ Features

- ⚡ **Real-time packet sniffing using Scapy.**
- 🖥️ **Displays device IP, MAC, protocols (TCP, UDP, ICMP, ARP), and accessed servers.**
- 📶 **Shows Wi-Fi SSID and network interface on Windows.**
- ▶️⏸️ **Start and stop packet capture dynamically via GUI buttons.**
- 📁 **Export captured data to CSV files.**
- 📊 **Live-updating analytics dashboard with protocol distribution pie chart.**
- 🔄 **Reset button to clear all captured data and refresh the display.**

---

## ⚙️ Installation
pip install scapy matplotlib


**Note:**  
Run the script with administrator/root privileges for packet sniffing.

---

## 🚀 Usage

1. **Clone the repo:**

    git clone : https://github.com/Suru030/network-packet-sniffer.git
    
    cd network-packet-sniffer

2. **Run the tool:**

    sudo python3 sniffer.py # Linux/macOS
    
    or
    
    python sniffer.py # Windows (may require admin rights)


3. **Use the GUI** to start/stop sniffing, reset data, export CSV, or view analytics.

---

## ⚠️ Known Limitations

- 🪟 Wi-Fi SSID detection is currently Windows-only.
- 🛡️ Requires elevated privileges to sniff packets.
- 🌐 No interface selection; defaults to system default interface.
- 🐢 UI updates might slow on very high traffic.

---

## 🌟 Future Enhancements

- 💻 Cross-platform Wi-Fi detection.
- 🖱️ Interface selector in GUI.
- 🕵️ Intrusion and spoof detection.
- 🗺️ Additional visual analytics like geolocation and bandwidth.

---
