# Network Packet Analyzer

## Description

The Network Packet Analyzer is a tool developed to capture and analyze network packets in real-time. It provides detailed information about each packet, including source and destination IP addresses, protocols, and payload data. This tool is designed for educational purposes and network troubleshooting, emphasizing ethical use and legal compliance.

## Features

- **Real-time Packet Capture**: Continuously captures network packets.
- **Detailed Analysis**: Displays source IP, destination IP, protocol, and payload data for each packet.
- **User-Friendly GUI**: Easy-to-use interface built with Tkinter.
- **Threading**: Ensures the GUI remains responsive during packet capture.

## Installation

### Prerequisites

1. **Python 3.x**: Ensure you have Python 3.x installed on your system.
2. **Scapy**: Install the Scapy library for packet capturing.
3. **Npcap**: Install Npcap for packet capturing on Windows.

### Steps

1. **Install Scapy**:
    ```bash
    pip install scapy
    ```

2. **Install Npcap**:
    - Download Npcap from the [Npcap website](https://nmap.org/npcap/).
    - Run the installer and check the option "Install Npcap in WinPcap API-compatible mode".

## Usage

1. **Clone the Repository**:
    ```bash
    git clone https://github.com/yourusername/PRODIGY_CYBER_05.git
    cd PRODIGY_CYBER_05
    ```

2. **Run the Script**:
    ```bash
    python network_packet_analyzer.py
    ```

3. **Using the Tool**:
    - Click "Start Sniffing" to begin capturing network packets.
    - Captured packet details will be displayed in the GUI.
    - Click "Stop Sniffing" to stop packet capture and close the GUI.

## Ethical Considerations

- **Legal Compliance**: Ensure you have permission to capture and analyze network traffic. Unauthorized sniffing can be illegal.
- **Privacy**: Respect user privacy. Avoid capturing or inspecting personal or sensitive information without explicit consent.
- **Educational Use**: Use this tool for educational and legitimate purposes, such as learning, troubleshooting, and improving network security.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request for any changes or improvements.


---

**Disclaimer**: This tool is intended for educational purposes and authorized network troubleshooting. The developer is not responsible for any misuse or illegal activities conducted with this tool.
