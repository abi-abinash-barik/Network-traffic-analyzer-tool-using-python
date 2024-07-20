# capture/packet_capture.py
from scapy.all import sniff, wrpcap
import os

def packet_capture(interface, filter=None):
    try:
        # Specify the directory where you want to save the pcap file
        save_directory = r"C:\Users\abina\Desktop\Traffic_analyser"  # Update with your desired directory
        file_name = f"captured_packets_{interface}.pcap"
        file_path = os.path.join(save_directory, file_name)
        
        print(f"Capturing packets on interface {interface}. Press Ctrl+C to stop.")
        packets = sniff(iface=interface, filter=filter, prn=lambda x: wrpcap(file_path, x, append=True), store=True)
        print(f"Packet capture complete. {len(packets)} packets captured. Saved to: {file_path}")
        return packets
    except KeyboardInterrupt:
        print("Packet capture interrupted by user.")
        return []

# Example usage
if __name__ == "__main__":
    # Replace "your_network_interface" with the actual logic to get the selected network interface dynamically
    network_interface = input("Enter the name of the network interface to capture packets from: ")
    packet_capture(network_interface, filter="tcp or udp")
