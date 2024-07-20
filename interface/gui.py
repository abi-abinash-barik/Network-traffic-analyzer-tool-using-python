# interface/gui.py
from ttkthemes import ThemedTk
import tkinter as tk
from tkinter import ttk
from tkinter import filedialog
from scapy.arch.windows import get_windows_if_list
from scapy.all import sniff, wrpcap, IP  # Add 'IP' to the import statement
from datetime import datetime
import matplotlib.pyplot as plt
import threading
import time
from PIL import Image, ImageTk

class TrafficAnalyzerGUI:
    def __init__(self, master, data):
        self.master = master
        self.data = data
        self.capture_status = False
        self.capture_thread = None  # Added to store the capture thread
        master.title("Traffic Analyser Tool  Build by- Abinash Barik")
        master.geometry("800x600")
        self.logs = []


        # Load and display the background image
        background_image = Image.open('Grass-Free-Download-PNG.png')
        background_image = ImageTk.PhotoImage(background_image)
        self.background_label = tk.Label(master, image=background_image)
        self.background_label.image = background_image
        self.background_label.place(relwidth=1, relheight=1)

        self.create_widgets()

    def create_widgets(self):
        # Add a label for the name and builder's information
        name_label = ttk.Label(self.master, text="Traffic Analyzer Tool\nBuilt by - Abinash Barik", font=("Helvetica", 12, "bold"))
        name_label.pack(pady=10)

        # Dropdown menu for selecting network interface
        interface_label = ttk.Label(self.master, text="Select Network Interface:")
        interface_label.pack()

        self.interface_var = tk.StringVar()
        interfaces = [interface["name"] for interface in get_windows_if_list()]
        self.interface_combobox = ttk.Combobox(self.master, textvariable=self.interface_var, values=interfaces, width=50)
        self.interface_combobox.pack()

        style = ttk.Style()
        style.configure("TButton", font=("Arial", 14))

        # Add more buttons and components as needed
        start_capture_button = ttk.Button(self.master, text="Start Capture", command=self.start_capture, width=20)
        start_capture_button.pack(pady=10)

        stop_capture_button = ttk.Button(self.master, text="Stop Capture", command=self.stop_capture, width=20)
        stop_capture_button.pack(pady=10)

        load_capture_button = ttk.Button(self.master, text="Load Capture", command=self.load_capture, width=20)
        load_capture_button.pack(pady=10)

        analyze_traffic_button = ttk.Button(self.master, text="Analyze Traffic", command=self.analyze_traffic, width=20)
        analyze_traffic_button.pack(pady=10)

        intrusion_detection_button = ttk.Button(self.master, text="Intrusion Detection", command=self.intrusion_detection, width=20)
        intrusion_detection_button.pack(pady=10)

        visualize_traffic_button = ttk.Button(self.master, text="Visualize Traffic", command=self.visualize_traffic, width=20)
        visualize_traffic_button.pack(pady=10)

        protocol_analysis_button = ttk.Button(self.master, text="Protocol Analysis", command=self.protocol_analysis, width=20)
        protocol_analysis_button.pack(pady=10)

        configure_alerts_button = ttk.Button(self.master, text="Configure Alerts", command=self.configure_alerts, width=20)
        configure_alerts_button.pack(pady=10)

        view_logs_button = ttk.Button(self.master, text="View Logs", command=self.view_logs, width=20)
        view_logs_button.pack(pady=10)

    def start_capture(self):
        if not self.capture_status:
            selected_interface = self.interface_var.get()
            self.capture_status = True
            self.capture_thread = threading.Thread(target=self.capture_packets, args=(selected_interface,))
            self.capture_thread.start()
            print(f"Capture started on interface: {selected_interface}")
        else:
            print("Capture is already running.")

    def stop_capture(self):
        if self.capture_status:
            self.capture_status = False
            self.capture_thread.join()  # Wait for the thread to finish
            print("Capture stopped.")
        else:
            print("Capture is not running.")

    def capture_packets(self, selected_interface):
        while self.capture_status:
            # Sniffing logic goes here
            packets = sniff(iface=selected_interface, timeout=2)  # Change the timeout as needed

        if packets:
            timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
            file_name = f"capture_{timestamp}.pcap"
            wrpcap(file_name, packets)
            print(f"Captured {len(packets)} packets. Saved to {file_name}")
        else:
            print(f"Captured 0 packets.")

        # Add a delay to control the rate of packet capture
        time.sleep(2)  # Adjust the sleep duration as needed


    def process_packet(self, packet):
        # TODO: Process each captured packet (you can add custom processing logic here)
        print(packet.summary())

    def load_capture(self):
        # TODO: Implement load capture functionality
        file_path = filedialog.askopenfilename(title="Select Capture File", filetypes=[("PCAP Files", "*.pcap")])
        if file_path:
            print(f"Selected file: {file_path}")

    def analyze_traffic(self):
        file_path = filedialog.askopenfilename(title="Select Capture File", filetypes=[("PCAP Files", "*.pcap")])
        if file_path:
            print(f"Selected file: {file_path}")
            self.process_capture_file(file_path)

    def process_capture_file(self, file_path):
        packets = sniff(offline=file_path)
        for packet in packets:
            # Process each packet (you can add custom processing logic here)
            self.process_packet(packet)

    def process_packet(self, packet):
        # TODO: Add your custom packet processing logic here
        print(packet.summary())

    def intrusion_detection(self):
        file_path = filedialog.askopenfilename(title="Select Capture File", filetypes=[("PCAP Files", "*.pcap")])
        if file_path:
            print(f"Selected file: {file_path}")
            self.detect_intrusions(file_path)

    def detect_intrusions(self, file_path):
        packets = sniff(offline=file_path)
        intrusion_detected = False

        for packet in packets:
            if self.detect_malicious_pattern(packet):
                intrusion_detected = True
                break

        if intrusion_detected:
            print("Intrusion detected!")
        else:
            print("No intrusion detected.")

    def detect_malicious_pattern(self, packet):
        # TODO: Implement your intrusion detection logic here
        # For example, check if a specific keyword is present in the payload
        keyword = "malicious_pattern"
        if hasattr(packet, "load") and keyword.encode() in packet.load:
            return True
        return False

    def visualize_traffic(self):
        file_path = filedialog.askopenfilename(title="Select Capture File", filetypes=[("PCAP Files", "*.pcap")])
        if file_path:
            print(f"Selected file: {file_path}")
            self.plot_packet_sizes(file_path)

    def plot_packet_sizes(self, file_path):
        packets = sniff(offline=file_path)

        # Extract packet sizes
        packet_sizes = [len(packet) for packet in packets if IP in packet]

        # Plotting
        plt.hist(packet_sizes, bins=20, color='blue', edgecolor='black')
        plt.title('Distribution of Packet Sizes')
        plt.xlabel('Packet Size (bytes)')
        plt.ylabel('Frequency')
        plt.show()

    def protocol_analysis(self):
        file_path = filedialog.askopenfilename(title="Select Capture File", filetypes=[("PCAP Files", "*.pcap")])
        if file_path:
            print(f"Selected file: {file_path}")
            self.analyze_protocols(file_path)

    def analyze_protocols(self, file_path):
        try:
            packets = sniff(offline=file_path)
            protocols = {}

            for packet in packets:
                if packet.haslayer(IP):
                    protocol = packet[IP].proto
                    if protocol in protocols:
                        protocols[protocol] += 1
                    else:
                        protocols[protocol] = 1

            # Display the protocol distribution
            print("Protocol Distribution:")
            for protocol, count in protocols.items():
                print(f"Protocol {protocol}: {count} packets")

            # You can further visualize or analyze the protocol distribution as needed

        except Exception as e:
            print(f"Error analyzing protocols: {e}")

    def configure_alerts(self):
        file_path = filedialog.askopenfilename(title="Select Capture File", filetypes=[("PCAP Files", "*.pcap")])
        if file_path:
            print(f"Selected file: {file_path}")
            self.detect_large_packets(file_path)

    def detect_large_packets(self, file_path):
        try:
            packets = sniff(offline=file_path)
            threshold_size = 1500  # Set your threshold size (adjust as needed)

            large_packets = [packet for packet in packets if len(packet) > threshold_size]

            if large_packets:
                print("Alert: Large Packets Detected!")
                for packet in large_packets:
                    print(f"Packet Size: {len(packet)}")

                # You can take further actions here, e.g., display a message, log the alert, etc.

            else:
                print("No large packets detected.")

        except Exception as e:
            print(f"Error configuring alerts: {e}")

    def view_logs(self):
        if self.logs:
            self.show_logs()
        else:
            print("No logs to display.")

    def show_logs(self):
        # Open a new window to display logs
        logs_window = tk.Toplevel(self.master)
        logs_window.title("Logs Viewer")

        self.logs_text = tk.Text(logs_window, wrap="word", height=20, width=80)
        self.logs_text.pack(padx=10, pady=10)

        # Insert logs into the Text widget
        for log_entry in self.logs:
            self.logs_text.insert(tk.END, log_entry + "\n")

        self.logs_text.config(state=tk.DISABLED)  # Make the Text widget read-only

    def update_logs(self, log_entry):
        # Update logs and display in the Text widget if it exists
        self.logs.append(log_entry)
        if self.logs_text:
            self.logs_text.config(state=tk.NORMAL)
            self.logs_text.insert(tk.END, log_entry + "\n")
            self.logs_text.config(state=tk.DISABLED)

    def run(self):
        self.master.mainloop()

def run_gui(data=None):
    root = tk.Tk()
    app = TrafficAnalyzerGUI(root, data)
    app.run()

if __name__ == "__main__":
    run_gui()
