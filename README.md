# PacketSniffer++

A lightweight C++ network packet sniffer built using raw sockets on Linux. Captures and parses Ethernet, IP, TCP, UDP, and ICMP packets.

--- 

## 🚀 Features
- Capture all incoming network packets via raw sockets
- Parse and display:
  - Ethernet headers 
  - IP headers
  - TCP headers (port, sequence, ack, header length)
  - UDP headers (port, length)
- Real-time packet logging to the console

---

## 🛠️ Build Instructions
### Requirements
- Linux OS
- g++ compiler
- Root privileges

### Compilation & Execution
```bash
sudo g++ packet_sniffer.cpp -o sniffer
sudo ./sniffer
```

---

## 📂 File Structure
```
PacketSniffer++/
├── packet_sniffer.cpp   # Source code
├── README.md            # Project overview
├── LICENSE              # MIT License
└── .gitignore           # Build artifacts ignored
```

---

## 📃 License
This project is licensed under the [MIT License](LICENSE).

---

## 🤝 Contributing
Pull requests are welcome! Feel free to fork, improve, and submit a PR.

---

## ⚡ Fun Fact
Packet sniffing helps diagnose network issues, monitor traffic, and even powers cybersecurity tools. You’re now coding a hacker’s toolkit! 🕵️‍♂️💻

---

## 🧠 Author
Riju Rahaman  
[GitHub](https://github.com/Riju-Rahaman) | [LinkedIn](https://www.linkedin.com/in/riju-rahaman-ba5789343/)

---

## 🔮 Future Plans
- Payload analysis (hex & ASCII dump)
- Port filtering and packet statistics
- GUI version using Qt or GTK
- Logging to pcap file for Wireshark analysis
