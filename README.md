# IoTFAS
IoT Forensic Analysis system

STEPTS TO FOLLOW

1) Understand how the printer works
2) Create basic forensic procedures to collect and analyze data from a printer or IoT device.
3) Test your procedures on the chosen device and make sure it wokes and its reliable.
4) Check if data collection wprked.

How the System Reads Data from the Printer
our forensic detection system will collect data from the printer using 
depending on the printer capabilities and our setup. The system will primarily rely on
Python scripts and tools like Wireshark to capture and process data, which can then be displayed
on a simple interface (e.g., a console output or a basic graphical interface).

Data Sources on an IoT Printer

1) Network Traffic: Data sent over Wi-Fi, such as print commands, status updates, or communication with 
apps/cloud services (e.g., HTTP, HTTPS, or IPP Internet Printing Protocol)

Methods to Read Data
Network Traffic Capture (Wi-Fi):
How It Works: Use a tool like Wireshark to monitor the printer�s 
Wi-Fi communication. When you send a print job or check the printer�s status, it generates network packets 
(e.g., HTTP or IPP) that contain data like job details, timestamps, or settings.
Setup: Connect the printer 
and your computer to the same Wi-Fi network. Use Wireshark to capture packets from the printer�s IP address.

No Cable Needed: Wi-Fi is the primary communication method for IoT printers, so you don�t need a physical 
cable for this

Steps to Capture and Display:

1) Capture Data
etwork Traffic: Use Wireshark to capture packets during a print job. Save the capture as a .pcap file, 
then use a Python script with scapy to parse and extract relevant data 
(e.g., print job details or timestamps).
App/Web Interface: Manually export logs from the HP Smart 
app or web interface, or use a Python script to automate API calls if available.
USB 
(if applicable): Use manufacturer software to retrieve logs, then parse them with Python.

2) Process Data
Write a Python script to filter and extract meaningful information (e.g., job names, timestamps, or 
IP addresses from network packets).
Use libraries like scapy for network data or json for API responses.

3) Display Data
 Create a simple web interface using Django
4) Verify Integrity
Use a Python script with hashlib to hash collected files (e.g., logs) and ensure they remain unchanged.



