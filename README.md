# Network Traffic Analyzer Tool

<p align="center">
  <img src="https://img.shields.io/badge/Language-Python-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/Packet%20Analysis-PyShark-1679A7?style=for-the-badge" alt="PyShark">
  <img src="https://img.shields.io/badge/License-GPLv3-blue?style=for-the-badge" alt="GPLv3 License">
  <img src="https://img.shields.io/badge/Status-Active%20Development-orange?style=for-the-badge" alt="Project Status">
</p>

<p align="center">
  <b>A Python-based tool for capturing, analyzing, and visualizing network traffic.</b>
</p>

---

## Overview

**Network Traffic Analyzer Tool** is a Python application designed to help users capture, monitor, analyze, and visualize network traffic.

The project is useful for cybersecurity learning, network troubleshooting, packet-analysis practice, and defensive security research. It provides a structured workflow for selecting a network interface, monitoring traffic, reviewing packets, and viewing traffic visualizations.

> **Use this tool only on networks, systems, and packet captures that you own or are explicitly authorized to monitor.**

---

## Features

- Live network traffic capture
- Network interface selection
- Packet and protocol analysis
- Traffic monitoring using PyShark
- Visualization support for captured traffic
- Modular project structure
- User interface for traffic analysis
- Configurable PyShark settings
- MAC vendor lookup resource through `manuf`

---

## Project Structure

```text
Network-traffic-analyzer-tool-using-python/
│
├── analysis/                 # Packet and traffic analysis modules
├── capture/                  # Live traffic capture functionality
├── interface/                # Application user-interface components
├── utils/                    # Utility functions and helpers
├── visualization/            # Traffic visualization components
├── Screenshots/              # Project screenshots
│
├── main.py                   # Main application entry point
├── requirements.txt          # Required Python dependencies
├── pysharkconfig.ini         # PyShark configuration file
├── manuf                     # MAC address vendor database/resource
├── LICENSE                   # GNU GPL v3.0 license
└── README.md                 # Project documentation
```

---

## Requirements

Install the following before running the project:

- Python 3.8 or later
- Wireshark or TShark
- Python dependencies from `requirements.txt`
- A supported and active network interface
- Administrator privileges on Windows or appropriate capture permissions on Linux/macOS for live packet capture

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/abi-abinash-barik/Network-traffic-analyzer-tool-using-python.git
```

### 2. Open the project folder

```bash
cd Network-traffic-analyzer-tool-using-python
```

### 3. Create a virtual environment

**Windows**

```bash
python -m venv venv
venv\Scripts\activate
```

**Linux/macOS**

```bash
python3 -m venv venv
source venv/bin/activate
```

### 4. Download additional libraries

Download the `Lib` archive from the following Google Drive link:

```text
https://drive.google.com/file/d/1y4F7m9X7gU6GgoFjwHBa4HiVPTBY9WkR/view?usp=sharing
```

Extract the archive and copy its contents into the project's `venv` directory if required by your local setup.

### 5. Install dependencies

```bash
pip install -r requirements.txt
```

### 6. Install Wireshark or TShark

Install Wireshark for your operating system and ensure the `tshark` command is available through your system PATH.

Verify the installation:

```bash
tshark --version
```

### 7. Configure PyShark

Review the `pysharkconfig.ini` file and update it when a custom TShark installation path or local network-interface configuration is required.

---

## Usage

Start the application from the project directory:

```bash
python main.py
```

On Linux systems, live packet capture may require elevated permissions:

```bash
sudo python3 main.py
```

Use only interfaces and traffic that you are authorized to inspect.

---

## Workflow

1. Start the application using `main.py`.
2. Select the active network interface or network card.
3. Start live traffic capture.
4. Monitor captured packets through the application interface.
5. Review the available analysis results.
6. Open the visualization section to inspect traffic patterns.
7. Stop the capture after completing the authorized analysis.

---

## Screenshots

### Home Screen

The home screen provides the main entry point for the Network Traffic Analyzer Tool.

<p align="center">
  <img src="https://github.com/user-attachments/assets/8d812b4b-2cd3-4c7c-92fb-62a5ec99e7a7" alt="Network Traffic Analyzer Home Screen" width="850">
</p>

### Network Interface Selection

Select the appropriate network card before starting a live packet-capture session.

<p align="center">
  <img src="https://github.com/user-attachments/assets/fe308944-9a33-47ad-876a-5b6f164dfaf6" alt="Network Card Selection Screen" width="850">
</p>

### Traffic Visualization

The visualization screen helps present captured network traffic in an understandable format.

<p align="center">
  <img src="https://github.com/user-attachments/assets/ac4bf5e4-ab08-4f27-9840-3838f4689059" alt="Network Traffic Visualization Screen" width="850">
</p>

---

## Troubleshooting

### TShark is not detected

- Confirm that Wireshark or TShark is installed.
- Run the following command to verify the installation:

```bash
tshark --version
```

- Add the Wireshark installation folder to the system PATH.
- Review `pysharkconfig.ini` and provide the correct TShark executable path if required.

### Permission denied during capture

- Run the application as Administrator on Windows.
- Use `sudo` only when necessary on Linux.
- Confirm that your user account has permission to capture packets.
- Check that the selected interface is active.

### No packets are displayed

- Confirm that you selected the correct network interface.
- Generate authorized network activity on the selected interface.
- Disable or review VPN settings and virtual adapters.
- Restart the application and try again.

### Dependency installation fails

Upgrade pip and retry the installation:

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
```

Confirm that the virtual environment is active before installing dependencies.

---

## Responsible Use

This project is intended for legitimate network administration, cybersecurity education, authorized traffic monitoring, and defensive security research.

Do not use this tool to:

- Monitor networks without permission
- Capture private or confidential communications
- Collect passwords, session cookies, tokens, or personal data
- Bypass access controls or security protections
- Violate privacy laws, institutional rules, or organizational policies

Always obtain proper authorization before capturing or analyzing network traffic.

---

## Contributing

Contributions, bug reports, and feature requests are welcome.

1. Fork this repository.
2. Create a new branch for your feature or fix.
3. Make and test your changes.
4. Maintain readable and well-organized Python code.
5. Open a pull request with a clear description of the update.

Please ensure all contributions support ethical, legal, and defensive use cases.

---

## License

This project is licensed under the **GNU General Public License v3.0 (GPL-3.0)**.

You may use, study, modify, and redistribute this software under the terms of the GPL-3.0. Any distributed modified version must also be released under GPL-3.0 and include the corresponding source code.

See the [LICENSE](LICENSE) file for complete license details.

---

## Author

**Abinash Barik**

- GitHub: [@abi-abinash-barik](https://github.com/abi-abinash-barik)

---

## Support

If this project helps your learning, research, or network-analysis work:

- Star the repository
- Report bugs through GitHub Issues
- Submit feature suggestions
- Share responsible feedback with the maintainer


---

## ☕ Support Our Work

<div align="center">


                                                                
   💡 Love Network-traffic-analyzer-tool-using-python?                                                                                             
   Help us continue developing high-quality security-awareness 
   tools and resources. Your support fuels innovation!         
                                                                
   ⭐ Every star is appreciated!                               
                                                                

### Make a Contribution

Your donation directly supports:

🛡️ Enhanced security features
📚 Better documentation and examples
🔬 Advanced lab capabilities
🤝 Community support and improvements

### Donation Options

<div align="center">

[![Donate via PayPal](https://img.shields.io/badge/PayPal-💳%20Donate%20Now-0070ba?style=for-the-badge&logo=paypal&logoColor=white)](https://www.paypal.com/paypalme/infomaticgeeks)
[![Buy Me Coffee](https://img.shields.io/badge/Buy%20Me%20a%20Coffee-☕%20Support%20Us-FFDD00?style=for-the-badge&logo=buy-me-a-coffee&logoColor=black)](https://buymeacoffee.com/abi.abinash)

</div>

Every contribution, no matter the size, makes a difference! 🙏 
 
</div>

