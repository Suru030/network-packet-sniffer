# 🛡️ Network Packet Sniffer and Traffic Analyzer

A real-time network packet sniffer and analyzer with a graphical interface built using **Python**, **Scapy**, and **Tkinter**. It captures network packets, displays connected devices, identifies protocols and accessed servers, and provides live traffic analytics with visualization.

---

## 🔧 Features

- 📡 Live Packet Sniffing  
- 🧑‍💻 Displays IP & MAC addresses, protocols (TCP/UDP/ICMP/ARP), and DNS queries  
- 📊 Real-time Analytics with Pie Chart  
- 🌐 Shows connected Wi-Fi SSID and interface  
- 💾 Export data to CSV  
- 🔁 Reset captured data instantly  
- 🖥️ Clean dark-themed GUI  

---

## 🚀 Getting Started

### 📦 Prerequisites

Make sure you have Python 3 installed with the following libraries:

```bash
pip install scapy matplotlib
▶️ Run the Application
bash
Copy
Edit
python main.py
Replace main.py with your filename if it's different.

📝 How It Works
Start Sniffing – Captures live packets from the default network interface.

Device Table – Displays:

IP Address

MAC Address

Protocols in use

Accessed servers (via DNS)

Wi-Fi SSID

Analytics – Real-time pie chart showing protocol distribution.

Export – Save data as a .csv file.

Reset – Clears all current data and resets the display.

📁 Project Structure
cpp
Copy
Edit
📦 NetworkPacketSniffer/
├── main.py
├── README.md
└── requirements.txt (optional)
📸 GUI Preview
(Add screenshots or GIF previews here if available)

🛑 Disclaimer
This tool is for educational and authorized testing purposes only. Unauthorized sniffing of networks is illegal and unethical. Use it only on networks you own or have permission to monitor.

📃 License
This project is licensed under the MIT License.

🙌 Acknowledgements
Scapy Documentation

Matplotlib

Tkinter Docs

🤝 Contributing
Feel free to fork, submit issues, or contribute improvements via pull requests.

yaml
Copy
Edit

---

Let me know if you'd also like me to generate the `requirements.txt` or `LICENSE`
