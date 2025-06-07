import scapy.all as scapy
import json
import logging
import os
from datetime import datetime

def process_packet_data(pcap_file, output_dir="output"):
    """Process PCAP file and extract printer communication data.
    
    Args:
        pcap_file (str): Path to input PCAP file
        output_dir (str): Directory to save JSON output
        
    Returns:
        str: Path to the generated JSON file or None if failed
    """
    try:
        # Validate input file
        if not os.path.exists(pcap_file):
            logging.error(f"Input file not found: {pcap_file}")
            print(f"Error: Input file not found - {pcap_file}")
            return None

        # Read packets with size validation
        file_size = os.path.getsize(pcap_file)
        if file_size == 0:
            logging.error("Empty PCAP file provided")
            print("Error: Empty PCAP file provided")
            return None

        logging.info(f"Processing {pcap_file} (size: {file_size/1024:.2f} KB)")
        print(f"Processing network capture from {pcap_file}...")

        packets = scapy.rdpcap(pcap_file)
        extracted_data = []
        
        # Process packets with enhanced filtering
        for i, packet in enumerate(packets, 1):
            if not packet.haslayer(scapy.IP):
                continue

            data = {
                "packet_number": i,
                "timestamp": datetime.fromtimestamp(float(packet.time)).isoformat(),
                "src_ip": packet[scapy.IP].src,
                "dst_ip": packet[scapy.IP].dst,
                "protocol": packet.sprintf("%IP.proto%"),
                "size": len(packet),
                "payload": None
            }

            # Enhanced payload extraction
            if packet.haslayer(scapy.Raw):
                try:
                    raw = packet[scapy.Raw].load
                    data["payload"] = {
                        "hex": raw.hex(),
                        "ascii": "".join([chr(x) if 32 <= x <= 126 else "." for x in raw]),
                        "length": len(raw)
                    }
                except Exception as e:
                    logging.warning(f"Packet {i} payload decode error: {e}")
                    data["payload_error"] = str(e)

            extracted_data.append(data)

        # Create output directory if needed
        os.makedirs(output_dir, exist_ok=True)
        
        # Generate output filename based on input
        base_name = os.path.splitext(os.path.basename(pcap_file))[0]
        output_file = os.path.join(output_dir, f"{base_name}_processed.json")
        
        # Write output with pretty formatting
        with open(output_file, "w") as f:
            json.dump(extracted_data, f, indent=2, ensure_ascii=False)
        
        logging.info(f"Successfully processed {len(extracted_data)} packets -> {output_file}")
        print(f"Processing complete. Saved {len(extracted_data)} packets to {output_file}")
        
        return output_file

    except scapy.Scapy_Exception as e:
        error_msg = f"Scapy processing error: {str(e)}"
        logging.error(error_msg)
        print(error_msg)
        return None
        
    except json.JSONEncodeError as e:
        error_msg = f"JSON encoding error: {str(e)}"
        logging.error(error_msg)
        print(error_msg)
        return None
        
    except Exception as e:
        error_msg = f"Unexpected processing error: {str(e)}"
        logging.error(error_msg)
        print(error_msg)
        return None