import tkinter as tk
from tkinter import scrolledtext
from scapy.all import sniff, IP
import threading

# Function to capture and display network packets
def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto
        payload = bytes(packet[IP].payload).hex()
        packet_info = f"Source IP: {src_ip}\nDestination IP: {dst_ip}\nProtocol: {proto}\nPayload: {payload}\n\n"
        
        # Insert packet info into the text area
        text_area.insert(tk.END, packet_info)

def start_sniffer():
    sniff(prn=packet_callback, store=0)

def start_sniffing():
    sniffer_thread = threading.Thread(target=start_sniffer)
    sniffer_thread.daemon = True
    sniffer_thread.start()
    status_label.config(text="Sniffer Status: Running", fg="green")

def stop_sniffing():
    status_label.config(text="Sniffer Status: Stopped", fg="red")
    root.destroy()

# Create the main window
root = tk.Tk()
root.title("Network Packet Analyzer")
root.geometry("600x400")

# Create and place the widgets
status_label = tk.Label(root, text="Sniffer Status: Stopped", font=("Helvetica", 12), fg="red")
status_label.pack(pady=10)

start_button = tk.Button(root, text="Start Sniffing", command=start_sniffing, font=("Helvetica", 12))
start_button.pack(pady=5)

stop_button = tk.Button(root, text="Stop Sniffing", command=stop_sniffing, font=("Helvetica", 12))
stop_button.pack(pady=5)

log_label = tk.Label(root, text="Captured Packets:", font=("Helvetica", 12))
log_label.pack(pady=10)

text_area = scrolledtext.ScrolledText(root, width=70, height=15, wrap=tk.WORD, font=("Helvetica", 10))
text_area.pack(pady=10)

# Run the main event loop
root.mainloop()
