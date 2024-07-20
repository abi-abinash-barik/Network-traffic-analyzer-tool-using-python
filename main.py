# main.py
import os
from capture.packet_capture import packet_capture
from capture.packet_processing import parse_packet
from analysis.traffic_analysis import traffic_analysis
from analysis.intrusion_detection import intrusion_detection
from analysis.protocol_analysis import protocol_analysis
from visualization.traffic_visualization import visualize_traffic
from interface.gui import TrafficAnalyzerGUI
from utils.alert_system import alert_system
from utils.filter_sort import filter_and_sort
from utils.report_generator import generate_report
from scapy.arch.windows import get_windows_if_list
import tkinter as tk

# Specify the path to the manuf file
manuf_path = r"C:\Users\abina\Desktop\Traffic_analyser\manuf"
os.environ["MANUF_PATH"] = manuf_path

def automatic_filter_criteria(packet):
    # Customize this function to dynamically determine filtering criteria
    return packet["protocol"] == "TCP" and packet["source_ip"] == "192.168.1.1"

def main():
    try:
        # Get a list of available network interfaces
        available_interfaces = [interface["name"] for interface in get_windows_if_list()]

        # Print the available interfaces
        print("Available Network Interfaces:")
        for interface in available_interfaces:
            print(interface)

        # Specify the desired network interface
        selected_interface = input("Enter the name of the network interface to capture packets from: ")

        # 1. Packet Capture
        packet_capture(selected_interface, filter="tcp or udp")

        # 2. Packet Processing
        data = parse_packet(f"captured_packets_{selected_interface}.pcap")

        # 3. Traffic Analysis
        traffic_analysis(data)

        # 4. Intrusion Detection
        intrusion_detection(data)

        # 5. Protocol Analysis
        protocol_analysis("tcp", data)

        # 6. Traffic Visualization
        visualize_traffic(data)

        # 7. User Interface
        root = tk.Tk()
        gui = TrafficAnalyzerGUI(root, data)  # Pass data to the GUI and create Tk root
        gui.run()  # Start the GUI
        root.mainloop()  # Ensure the Tkinter main loop is running

        # 8. Alert System
        alert_system("Suspicious activity detected!")

        # 9. Filtering and Sorting
        # Automatically filter packets based on dynamic criteria
        filtered_data = filter_and_sort(data, filter_criteria=automatic_filter_criteria)

        # 10. Logs and Reports
        generate_report()

    except KeyboardInterrupt:
        print("Packet capture interrupted by the user.")

if __name__ == "__main__":
    main()
