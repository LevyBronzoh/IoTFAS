
'''import argparse
from capture import capture_network_traffic
from process import process_packet_data
from integrity import verify_data_integrity
from app import app
import os
import argparse
import io
import sys

# Force UTF-8 encoding
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

def main():
    parser = argparse.ArgumentParser(description="IoT Printer Forensic Tool")
    parser.add_argument("--ip", help="Printer IP", default=os.getenv("printer_ip", "192.168.1.177"))
    parser.add_argument("--interface", help="Network interface", default="Ethernet")
    parser.add_argument("--duration", help="Capture duration (seconds)", type=int, default=60)
    parser.add_argument("--web", help="Start Flask server", action="store_true")
    args = parser.parse_args()

    # Step 1: Capture traffic
    pcap_file = capture_network_traffic(args.ip, args.interface, args.duration)
    if not pcap_file:
        print("Capture failed. Check logs.")
        return

    # Step 2: Process data
    json_file = process_packet_data(pcap_file)
    if not json_file:
        print("Processing failed. Check logs.")
        return

    # Step 3: Verify integrity
    print(f"PCAP Hash: {verify_data_integrity(pcap_file)}")
    print(f"JSON Hash: {verify_data_integrity(json_file)}")

    # Step 4: Start Flask (optional)
    if args.web:
        print("Starting web server at http://127.0.0.1:5000")
        app.run(host="0.0.0.0", port=5000, debug=True) 

if __name__ == "__main__":
    main()'''
    
    
    
    
    
    ##########################################################################################################################################################
    
import argparse
from capture import capture_network_traffic
from process import process_packet_data
from integrity import verify_data_integrity
from app import app
import os
import argparse
import io
import sys

# Force UTF-8 encoding
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

def main():
    parser = argparse.ArgumentParser(description="IoT Printer Forensic Tool")
    parser.add_argument("--ip", help="Printer IP", default=os.getenv("printer_ip", "192.168.1.177"))
    parser.add_argument("--interface", help="Network interface", default=None)
    parser.add_argument("--duration", help="Capture duration (seconds)", type=int, default=60)
    parser.add_argument("--web", help="Start Flask server", action="store_true")
    args = parser.parse_args()

    # Step 1: Capture traffic - FIXED PARAMETER ORDER
    pcap_file = capture_network_traffic(
        target_ip=args.ip,
        interface=args.interface, 
        duration=args.duration,
        webcam_mode=True 
    )
    
    if not pcap_file:
        print("Capture failed. Check logs.")
        return

    # Step 2: Process data
    json_file = process_packet_data(pcap_file)
    if not json_file:
        print("Processing failed. Check logs.")
        return

    # Step 3: Verify integrity
    print(f"PCAP Hash: {verify_data_integrity(pcap_file)}")
    print(f"JSON Hash: {verify_data_integrity(json_file)}")

    # Step 4: Start Flask (optional)
    if args.web:
        print("Starting web server at http://127.0.0.1:5000")
        app.run(host="0.0.0.0", port=5000, debug=True) 

if __name__ == "__main__":
    main()