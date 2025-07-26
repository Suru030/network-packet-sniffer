# Network Packet Sniffer and Traffic Analyzer

A real-time network monitoring tool built with Python, Tkinter, and Scapy that captures live network traffic, analyzes connected devices, displays protocols and accessed servers per device, and provides data visualization and export features.

---

## Features

- **Real-time Packet Sniffing:**  
  Captures Ethernet, IP, ARP, and DNS packets to identify network devices and their communication patterns.

- **Device Summary Table:**  
  Lists detected devices with IP and MAC addresses, protocols used (TCP, UDP, ICMP, ARP), and accessed servers/domains.

- **Wi-Fi Info Display:**  
  Shows current Wi-Fi SSID and network interface (Windows only).

- **Start/Stop Sniffing Controls:**  
  Run and pause packet capture dynamically via GUI buttons.

- **Export to CSV:**  
  Save captured session data (devices, protocols, servers, SSID) to a CSV file.

- **Analytics Dashboard:**  
  Interactive window with live-updating protocol distribution pie chart.

- **Reset Button:**  
  Clears all captured data and resets the device list and info labels.

---

## Screenshots

*Add screenshots here to showcase your GUI, analytics window, and main features.*

---

## Requirements

- Python 3.x  
- [Scapy](https://scapy.net/)  
- [Tkinter](https://docs.python.org/3/library/tk.html) (usually included with Python)  
- [Matplotlib](https://matplotlib.org/)  

### Installation

