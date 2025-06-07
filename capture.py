'''import scapy.all as scapy
import logging
import os
import socket
import subprocess
from datetime import datetime

logging.basicConfig(
    filename='printer_forensics.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def get_default_gateway():
    """Get default gateway IP without netifaces"""
    try:
        if os.name == 'nt':  # Windows
            result = subprocess.run(['ipconfig'], capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if 'Default Gateway' in line:
                    return line.split(':')[-1].strip()
        else:  # Linux/Mac
            result = subprocess.run(['ip', 'route'], capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if 'default via' in line:
                    return line.split()[2]
        return None
    except Exception as e:
        logging.error(f"Failed to get gateway: {str(e)}")
        return None

def get_network_interface_ip(interface="Ethernet"):
    """Get IP address of a specific interface without netifaces"""
    try:
        if os.name == 'nt':  # Windows
            result = subprocess.run(['ipconfig'], capture_output=True, text=True)
            current_interface = None
            for line in result.stdout.split('\n'):
                if 'Ethernet adapter' in line or 'Wireless LAN adapter' in line:
                    current_interface = line.split(':')[0].strip()
                if current_interface and 'IPv4 Address' in line:
                    return line.split(':')[-1].strip()
        else:  # Linux/Mac
            result = subprocess.run(['ifconfig', interface], capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if 'inet ' in line:
                    return line.split()[1]
        return None
    except Exception as e:
        logging.error(f"Failed to get interface IP: {str(e)}")
        return None

def discover_webcam(interface="Ethernet", timeout=10):
    """Discover IP webcam on local network using ARP and port scanning"""
    try:
        # Get network information without netifaces
        gw_ip = get_default_gateway()
        if not gw_ip:
            logging.error("Could not determine default gateway")
            return None
            
        # Get local IP to determine subnet
        local_ip = get_network_interface_ip(interface)
        if not local_ip:
            logging.error("Could not determine local IP")
            return None
            
        # Create subnet (assuming /24)
        subnet = '.'.join(gw_ip.split('.')[:3]) + '.0/24'
        
        logging.info(f"Scanning {subnet} for webcam devices...")
        print(f"[SCANNING] Scanning network for webcams...")

        # ARP ping sweep (requires root)
        ans, _ = scapy.arping(subnet, iface=interface, timeout=timeout, verbose=False)
        
        # Check common webcam ports on discovered devices
        for res in ans.res:
            ip = res[0].payload.psrc
            try:
                # Test common IP webcam ports
                for port in [80, 8080, 8888, 554]:  # HTTP/RTSP ports
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                        sock.settimeout(1)
                        if sock.connect_ex((ip, port)) == 0:
                            logging.info(f"Found webcam service at {ip}:{port}")
                            print(f"🎥 Found webcam at {ip}")
                            return ip
            except Exception as e:
                logging.debug(f"Port check failed for {ip}: {str(e)}")
                continue
                
        logging.warning("No webcam found in network scan")
        return None
        
    except Exception as e:
        logging.error(f"Discovery failed: {str(e)}")
        return None

# The capture_network_traffic function remains unchanged
def capture_network_traffic(target_ip=None, interface="Ethernet", duration=60, output_dir="output"):
    """Capture network traffic with strict 1MB size limit"""
    try:
        # Auto-discover if no IP provided
        if target_ip is None:
            target_ip = discover_webcam(interface)
            if target_ip is None:
                error_msg = "No target IP provided and auto-discovery failed"
                logging.error(error_msg)
                print(f"[ERROR] {error_msg}")
                return None

        os.makedirs(output_dir, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        pcap_file = os.path.join(output_dir, f"webcam_{target_ip}_{timestamp}.pcap")
        
        print(f"[CAPTURING] Targeting {target_ip} on {interface} (Max: 1MB)...")

        # ===== STRICT 1MB LIMIT SETTINGS =====
        MAX_SIZE_MB = 1.0             # Hard limit (1MB)
        MAX_PACKETS = 700             # ~1MB at 1.5KB/packet
        PACKETS_PER_BURST = 100       # Process in chunks
        
        # Initialize counters
        total_size = 0
        packet_buffer = []
        
        # Custom packet handler
        def handle_packet(packet):
            nonlocal total_size
            packet_size = len(packet)
            
            # Check if limit reached
            if total_size + packet_size > MAX_SIZE_MB * 1024 * 1024:
                return False  # Stop capture
            
            packet_buffer.append(packet)
            total_size += packet_size
            
            # Save periodically
            if len(packet_buffer) >= PACKETS_PER_BURST:
                scapy.wrpcap(pcap_file, packet_buffer, append=True)
                packet_buffer.clear()
                print(f"Captured: {total_size/1024:.1f}KB/{MAX_SIZE_MB*1024:.1f}KB", end='\r')
            return True

        # Main capture with size monitoring
        scapy.sniff(
            iface=interface,
            filter=f"host {target_ip} and (port 80 or 8080 or 554)",
            prn=handle_packet,
            timeout=duration,
            store=False  # Critical for memory control
        )
        
        # Save any remaining packets
        if packet_buffer:
            scapy.wrpcap(pcap_file, packet_buffer, append=True)
        # ===== END 1MB LIMIT CODE =====

        # Verify results
        file_size = os.path.getsize(pcap_file) / (1024 * 1024)
        if file_size == 0:
            print("[WARNING] No packets captured")
            return None
            
        print(f"\n[SUCCESS] Saved {file_size:.2f}MB to {pcap_file}")
        return pcap_file

    except Exception as e:
        print(f"[ERROR] {str(e)}")
        return None'''
import scapy.all as scapy
import logging
import os
import socket
import subprocess
from datetime import datetime

# Setup logging
logging.basicConfig(
    filename='printer_forensics.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def get_default_gateway():
    """Get default gateway IP without netifaces"""
    try:
        if os.name == 'nt':  # Windows
            result = subprocess.run(['ipconfig'], capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if 'Default Gateway' in line:
                    return line.split(':')[-1].strip()
        else:  # Linux/Mac
            result = subprocess.run(['ip', 'route'], capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if 'default via' in line:
                    return line.split()[2]
        return None
    except Exception as e:
        logging.error(f"Failed to get gateway: {str(e)}")
        return None

def get_network_interface_ip(interface="Ethernet"):
    """Get IP address of a specific interface without netifaces"""
    try:
        if os.name == 'nt':  # Windows
            result = subprocess.run(['ipconfig'], capture_output=True, text=True)
            current_interface = None
            for line in result.stdout.split('\n'):
                if 'Ethernet adapter' in line or 'Wireless LAN adapter' in line:
                    current_interface = line.split(':')[0].strip()
                if current_interface and 'IPv4 Address' in line:
                    return line.split(':')[-1].strip()
        else:  # Linux/Mac
            result = subprocess.run(['ifconfig', interface], capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if 'inet ' in line:
                    return line.split()[1]
        return None
    except Exception as e:
        logging.error(f"Failed to get interface IP: {str(e)}")
        return None

def discover_webcam(interface="Ethernet", timeout=10):
    """Discover IP webcam on local network using ARP and port scanning"""
    try:
        # Get network information without netifaces
        gw_ip = get_default_gateway()
        if not gw_ip:
            logging.error("Could not determine default gateway")
            print("[ERROR] Could not determine default gateway")
            return None
            
        # Get local IP to determine subnet
        local_ip = get_network_interface_ip(interface)
        if not local_ip:
            logging.error("Could not determine local IP")
            print("[ERROR] Could not determine local IP")
            return None
            
        # Create subnet (assuming /24)
        subnet = '.'.join(gw_ip.split('.')[:3]) + '.0/24'
        
        logging.info(f"Scanning {subnet} for webcam devices...")
        print(f"[SCANNING] Scanning network for webcams on {subnet}...")

        # ARP ping sweep (requires root)
        ans, _ = scapy.arping(subnet, iface=interface, timeout=timeout, verbose=False)
        
        # Check common webcam ports on discovered devices
        discovered_devices = []
        for res in ans.res:
            ip = res[0].payload.psrc
            try:
                # Test common IP webcam ports
                for port in [80, 8080, 8888, 554]:  # HTTP/RTSP ports
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                        sock.settimeout(1)
                        if sock.connect_ex((ip, port)) == 0:
                            logging.info(f"Found webcam service at {ip}:{port}")
                            print(f"🎥 Found webcam at {ip}:{port}")
                            discovered_devices.append(ip)
                            break  # Found one port, move to next IP
            except Exception as e:
                logging.debug(f"Port check failed for {ip}: {str(e)}")
                continue
        
        if discovered_devices:
            return discovered_devices[0]  # Return first found device
        else:
            logging.warning("No webcam found in network scan")
            print("[WARNING] No webcam found in network scan")
            return None
        
    except Exception as e:
        logging.error(f"Discovery failed: {str(e)}")
        print(f"[ERROR] Discovery failed: {str(e)}")
        return None

import time
import os
import logging
from datetime import datetime
import scapy.all as scapy

def capture_network_traffic(target_ip=None, interface=None, duration=300, filename=None, 
                          webcam_mode=False, output_dir="output", max_size_kb=1000):
    """
    Capture network traffic for a specific target IP - fixed 5 minute duration
    
    Args:
        target_ip: IP address to monitor (None for auto-discovery in webcam mode)
        interface: Network interface to use (optional)
        duration: How long to capture in seconds (FIXED TO 300 SECONDS = 5 MINUTES)
        filename: Output filename (optional)
        webcam_mode: If True, uses webcam-specific filtering and auto-discovery
        output_dir: Output directory for files
        max_size_kb: Maximum capture size in KB (default: 1000KB)
    
    Returns:
        String: Path to saved pcap file, or None if failed
    """
    try:
        # FORCE 5 minutes duration regardless of input
        duration = 3000
        
        # Auto-discover webcam if needed
        if webcam_mode and target_ip is None:
            target_ip = discover_webcam(interface or "Ethernet")
            if target_ip is None:
                error_msg = "No target IP provided and webcam auto-discovery failed"
                logging.error(error_msg)
                print(f"[ERROR] {error_msg}")
                return None

        if target_ip is None:
            logging.error("No target IP specified")
            print("[ERROR] No target IP specified")
            return None

        print(f"[CAPTURING] Targeting {target_ip} for {duration} seconds (5 minutes) - max {max_size_kb}KB")
        if interface:
            print(f"[INTERFACE] Using interface: {interface}")
        
        # Create filter based on mode
        if webcam_mode:
            filter_str = f"host {target_ip} and (port 80 or port 8080 or port 8888 or port 554)"
            print(f"[FILTER] Webcam mode - HTTP/RTSP traffic only")
        else:
            filter_str = f"host {target_ip}"
            print(f"[FILTER] General mode - all traffic")
        
        logging.info(f"Starting 5-minute capture: {target_ip}, filter: {filter_str}, max_size: {max_size_kb}KB")
        
        # Create output directory
        os.makedirs(output_dir, exist_ok=True)
        
        # Generate filename if not provided
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            device_type = "webcam" if webcam_mode else "device"
            filename = os.path.join(output_dir, f"5min_{target_ip.replace('.', '_')}_{timestamp}.pcap")
        
        # Initialize packet storage - capture whatever we can in 1 minute
        packet_buffer = []
        packet_count = 0
        total_size = 0
        max_size_bytes = max_size_kb * 1024  # Convert KB to bytes
        capture_stopped = False
        start_time = time.time()
        
        def packet_handler(packet):
            nonlocal packet_count, total_size, capture_stopped
            
            # Check if 5 minutes has passed (safety check)
            elapsed = time.time() - start_time
            if elapsed >= 3000:
                print(f"\n[TIME LIMIT] 5 minutes completed")
                capture_stopped = True
                return
            
            # Check size limit before processing (optional - can be removed if you want ALL traffic)
            packet_size = len(packet)
            if total_size + packet_size > max_size_bytes:
                print(f"\n[SIZE LIMIT] Size limit of {max_size_kb}KB reached at {elapsed:.1f} seconds")
                capture_stopped = True
                return
            
            packet_buffer.append(packet)
            packet_count += 1
            total_size += packet_size
            
            # Save packets in batches every 50 packets
            if len(packet_buffer) >= 50:
                if packet_count == len(packet_buffer):  # First batch
                    scapy.wrpcap(filename, packet_buffer)
                else:
                    scapy.wrpcap(filename, packet_buffer, append=True)
                packet_buffer.clear()
                
                # Show progress with time remaining
                time_remaining = 300 - elapsed
                minutes_remaining = int(time_remaining // 60)
                seconds_remaining = int(time_remaining % 60)
                print(f"[PROGRESS] {packet_count} packets ({total_size/1024:.1f}KB) - {minutes_remaining}m {seconds_remaining}s remaining", end='\r')
        
        # Create a custom stop condition function
        def stop_filter(packet):
            return not capture_stopped
        
        print(f"[INFO] Starting 5-minute capture... Press Ctrl+C to stop early")
        
        # Capture packets for exactly 5 minutes
        try:
            if interface:
                scapy.sniff(iface=interface, filter=filter_str, timeout=300, 
                           prn=packet_handler, store=False, stop_filter=stop_filter)
            else:
                scapy.sniff(filter=filter_str, timeout=300, 
                           prn=packet_handler, store=False, stop_filter=stop_filter)
        except KeyboardInterrupt:
            print(f"\n[STOPPED] Capture stopped by user")
        except Exception as sniff_error:
            print(f"\n[INFO] Capture ended: {sniff_error}")
        
        # Calculate actual capture time
        actual_duration = time.time() - start_time
        
        # Save any remaining packets
        if packet_buffer:
            if packet_count == len(packet_buffer):  # Only batch captured
                scapy.wrpcap(filename, packet_buffer)
            else:
                scapy.wrpcap(filename, packet_buffer, append=True)
        
        print(f"\n[COMPLETED] Captured {packet_count} packets in {actual_duration:.1f} seconds ({actual_duration/60:.1f} minutes)")
        
        # Verify and report results
        if packet_count > 0 and os.path.exists(filename):
            file_size = os.path.getsize(filename) / 1024  # KB
            rate = packet_count / actual_duration if actual_duration > 0 else 0
            print(f"[SUCCESS] Saved {file_size:.2f}KB to {filename}")
            print(f"[STATS] Rate: {rate:.1f} packets/second")
            logging.info(f"5-minute capture successful: {packet_count} packets, {file_size:.2f}KB in {actual_duration:.1f}s")
            return filename
        else:
            print("[WARNING] No packets captured in 5 minutes")
            print("[TIP] Try generating traffic (ping, browse to device, etc.) during capture")
            logging.warning("No packets captured in 5-minute window")
            return None
        
    except Exception as e:
        error_msg = f"5-minute capture failed: {str(e)}"
        print(f"[ERROR] {error_msg}")
        logging.error(error_msg)
        return None


# Alternative version: Capture ALL traffic for 5 minutes (no size limit)
def capture_network_traffic_unlimited(target_ip=None, interface=None, filename=None, 
                                    webcam_mode=False, output_dir="output"):
    """
    Capture ALL network traffic for exactly 5 minutes - no size limits
    """
    try:
        duration = 300  # Fixed 5 minutes
        
        if webcam_mode and target_ip is None:
            target_ip = discover_webcam(interface or "Ethernet")
            if target_ip is None:
                print("[ERROR] No target IP provided and webcam auto-discovery failed")
                return None

        if target_ip is None:
            print("[ERROR] No target IP specified")
            return None

        print(f"[CAPTURING] Targeting {target_ip} for 5 MINUTES - NO SIZE LIMIT")
        
        # Create filter
        if webcam_mode:
            filter_str = f"host {target_ip} and (port 80 or port 8080 or port 8888 or port 554)"
        else:
            filter_str = f"host {target_ip}"
        
        # Create output directory and filename
        os.makedirs(output_dir, exist_ok=True)
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = os.path.join(output_dir, f"5min_unlimited_{target_ip.replace('.', '_')}_{timestamp}.pcap")
        
        print(f"[INFO] Capturing for 300 seconds (5 minutes)... ALL traffic will be saved")
        start_time = time.time()
        
        # Simple capture - get everything in 5 minutes
        if interface:
            packets = scapy.sniff(iface=interface, filter=filter_str, timeout=300)
        else:
            packets = scapy.sniff(filter=filter_str, timeout=300)
        
        actual_duration = time.time() - start_time
        
        # Save all packets
        if packets:
            scapy.wrpcap(filename, packets)
            file_size = os.path.getsize(filename) / 1024  # KB
            rate = len(packets) / actual_duration if actual_duration > 0 else 0
            print(f"[SUCCESS] Captured {len(packets)} packets in {actual_duration:.1f}s ({actual_duration/60:.1f} minutes)")
            print(f"[SUCCESS] Saved {file_size:.2f}KB to {filename}")
            print(f"[STATS] Rate: {rate:.1f} packets/second")
            return filename
        else:
            print("[WARNING] No packets captured in 5 minutes")
            return None
            
    except Exception as e:
        print(f"[ERROR] Unlimited capture failed: {str(e)}")
        return None

# Alternative approach: Limit by packet count instead of size
def capture_network_traffic_count_limited(target_ip=None, interface=None, duration=30, filename=None, 
                                        webcam_mode=False, output_dir="output", max_packets=100):
    """
    Capture network traffic with packet count limit (typically results in ~50KB or less)
    """
    try:
        # Same setup as before...
        if webcam_mode and target_ip is None:
            target_ip = discover_webcam(interface or "Ethernet")
            if target_ip is None:
                error_msg = "No target IP provided and webcam auto-discovery failed"
                logging.error(error_msg)
                print(f"[ERROR] {error_msg}")
                return None

        if target_ip is None:
            logging.error("No target IP specified")
            print("[ERROR] No target IP specified")
            return None

        print(f"[CAPTURING] Targeting {target_ip} (max {max_packets} packets)...")
        
        # Create filter
        if webcam_mode:
            filter_str = f"host {target_ip} and (port 80 or port 8080 or port 8888 or port 554)"
        else:
            filter_str = f"host {target_ip}"
        
        # Create output directory and filename
        os.makedirs(output_dir, exist_ok=True)
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = os.path.join(output_dir, f"webcam_{target_ip.replace('.', '_')}_{timestamp}.pcap")
        
        # Capture with count limit - this is simpler and more reliable
        if interface:
            packets = scapy.sniff(iface=interface, filter=filter_str, 
                                 timeout=duration, count=max_packets)
        else:
            packets = scapy.sniff(filter=filter_str, timeout=duration, count=max_packets)
        
        # Save packets
        if packets:
            scapy.wrpcap(filename, packets)
            file_size = os.path.getsize(filename) / 1024
            print(f"[SUCCESS] Captured {len(packets)} packets ({file_size:.2f}KB)")
            return filename
        else:
            print("[WARNING] No packets captured")
            return None
            
    except Exception as e:
        print(f"[ERROR] Capture failed: {str(e)}")
        return None

def test_basic_capture(duration=10):
    """Test basic packet capture functionality"""
    
    print("=== BASIC CAPTURE TEST ===")
    logging.info("Starting basic capture test")
    
    # Test 1: Capture ANY traffic (no filter)
    print(f"\n1. Testing capture of ANY traffic for {duration} seconds...")
    try:
        # Get available interfaces
        interfaces = scapy.get_if_list()
        print(f"Available interfaces: {interfaces}")
        logging.info(f"Available interfaces: {interfaces}")
        
        # Try default interface first
        print(f"Using default interface: {scapy.conf.iface}")
        
        packets = scapy.sniff(timeout=duration, store=True)
        print(f"✓ Captured {len(packets)} packets (any traffic)")
        logging.info(f"Basic capture successful: {len(packets)} packets")
        
        if len(packets) > 0:
            # Save test capture
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            test_file = f"test_capture_{timestamp}.pcap"
            scapy.wrpcap(test_file, packets)
            
            file_size = os.path.getsize(test_file) / 1024  # KB
            print(f"✓ Saved {file_size:.2f}KB to {test_file}")
            
            # Show packet summary
            print("\nPacket summary:")
            for i, pkt in enumerate(packets[:5]):  # First 5 packets
                if pkt.haslayer(scapy.IP):
                    print(f"  {i+1}: {pkt[scapy.IP].src} -> {pkt[scapy.IP].dst} ({len(pkt)} bytes)")
            
            return True
        else:
            print("✗ No packets captured")
            logging.warning("Basic capture: No packets captured")
            return False
            
    except Exception as e:
        error_msg = f"Basic capture failed: {str(e)}"
        print(f"✗ {error_msg}")
        logging.error(error_msg)
        return False

def test_filtered_capture(target_ip="192.168.1.177", duration=15):
    """Test filtered capture for specific target"""
    
    print(f"\n2. Testing filtered capture for {target_ip} for {duration} seconds...")
    logging.info(f"Testing filtered capture for {target_ip}")
    
    try:
        # Try with just host filter first
        filter_str = f"host {target_ip}"
        print(f"Filter: {filter_str}")
        
        packets = scapy.sniff(filter=filter_str, timeout=duration, store=True)
        print(f"Result: {len(packets)} packets captured with host filter")
        
        if len(packets) > 0:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            test_file = f"filtered_capture_{target_ip.replace('.', '_')}_{timestamp}.pcap"
            scapy.wrpcap(test_file, packets)
            
            file_size = os.path.getsize(test_file) / 1024  # KB
            print(f"✓ Saved {file_size:.2f}KB to {test_file}")
            logging.info(f"Filtered capture successful: {len(packets)} packets")
            
            # Test webcam-specific filter
            print(f"Testing webcam filter for {target_ip}...")
            webcam_filter = f"host {target_ip} and (port 80 or port 8080 or port 8888 or port 554)"
            webcam_packets = scapy.sniff(filter=webcam_filter, timeout=10, store=True)
            print(f"Webcam filter result: {len(webcam_packets)} packets")
            
            return True
        else:
            print(f"✗ No packets from {target_ip} during {duration}s window")
            print("This suggests:")
            print(f"  - {target_ip} is not generating network traffic")
            print(f"  - Device is not reachable/active")
            print(f"  - Wrong IP address")
            logging.warning(f"Filtered capture: No packets from {target_ip}")
            return False
            
    except Exception as e:
        error_msg = f"Filtered capture failed: {str(e)}"
        print(f"✗ {error_msg}")
        logging.error(error_msg)
        return False

def test_interface_specific(target_ip="192.168.1.177"):
    """Test capture on specific interfaces"""
    
    print(f"\n3. Testing different interfaces for {target_ip}...")
    logging.info(f"Testing interfaces for {target_ip}")
    
    interfaces = scapy.get_if_list()
    working_interfaces = []
    
    for iface in interfaces:
        try:
            print(f"Testing interface: {iface}")
            
            # Quick test - any traffic
            test_packets = scapy.sniff(iface=iface, timeout=3, count=5, store=True)
            
            if len(test_packets) > 0:
                print(f"  ✓ Interface {iface} can capture packets")
                working_interfaces.append(iface)
                logging.info(f"Interface {iface} working")
                
                # Test with target filter
                target_packets = scapy.sniff(
                    iface=iface, 
                    filter=f"host {target_ip}", 
                    timeout=5, 
                    store=True
                )
                
                if len(target_packets) > 0:
                    print(f"  ✓ Found {len(target_packets)} packets from {target_ip}")
                else:
                    print(f"  - No packets from {target_ip} on this interface")
                    
            else:
                print(f"  ✗ Interface {iface} captured no packets")
                
        except Exception as e:
            print(f"  ✗ Interface {iface} failed: {str(e)}")
            logging.debug(f"Interface {iface} failed: {str(e)}")
    
    print(f"\nWorking interfaces: {working_interfaces}")
    logging.info(f"Working interfaces: {working_interfaces}")
    return working_interfaces

def generate_traffic_test(target_ip="192.168.1.177"):
    """Try to generate traffic to target"""
    
    print(f"\n4. Attempting to generate traffic to {target_ip}...")
    logging.info(f"Generating test traffic to {target_ip}")
    
    # Try ping to generate ICMP traffic
    try:
        print("Sending ping...")
        if os.name == 'nt':
            result = subprocess.run(['ping', '-n', '3', target_ip], 
                                  capture_output=True, text=True)
        else:
            result = subprocess.run(['ping', '-c', '3', target_ip], 
                                  capture_output=True, text=True)
        
        if result.returncode == 0:
            print("✓ Ping successful - this should generate ICMP traffic")
            logging.info("Ping test successful")
        else:
            print("✗ Ping failed - no ICMP traffic generated")
            logging.warning("Ping test failed")
            
    except Exception as e:
        error_msg = f"Ping test failed: {str(e)}"
        print(error_msg)
        logging.error(error_msg)
    
    # Try HTTP/webcam connections to generate TCP traffic
    ports_to_try = [80, 8080, 8888, 554]
    for port in ports_to_try:
        try:
            print(f"Testing connection to port {port}...")
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((target_ip, port))
            
            if result == 0:
                print(f"✓ Connected to {target_ip}:{port} - should generate TCP traffic")
                logging.info(f"Connection successful to {target_ip}:{port}")
                sock.close()
                break  # Found working port
            else:
                print(f"✗ Port {port} closed")
                
            sock.close()
            
        except Exception as e:
            print(f"Connection test failed for port {port}: {str(e)}")
            logging.debug(f"Connection test failed for {target_ip}:{port}: {str(e)}")

def run_all_tests(target_ip="192.168.1.177"):
    """Run all diagnostic tests"""
    
    print(f"Testing packet capture for target: {target_ip}")
    print("="*50)
    logging.info(f"Starting comprehensive tests for {target_ip}")
    
    # Run tests
    basic_works = test_basic_capture(10)
    
    if basic_works:
        print("\n✓ Basic capture works - your Scapy setup is OK")
        
        # Test filtered capture
        filtered_works = test_filtered_capture(target_ip, 15)
        
        if not filtered_works:
            # If filtered doesn't work, test interfaces and generate traffic
            working_interfaces = test_interface_specific(target_ip)
            generate_traffic_test(target_ip)
            
            print(f"\n=== RECOMMENDATIONS ===")
            if working_interfaces:
                print(f"✓ Use one of these interfaces: {working_interfaces}")
            else:
                print("✗ No working interfaces found - permission issue?")
                
            print(f"- Try accessing {target_ip} in web browser to generate traffic")
            print(f"- Verify {target_ip} is correct and device is powered on")
            print(f"- Try capturing all traffic first (remove host filter)")
        else:
            print(f"\n✓ Filtered capture works for {target_ip}")
            
    else:
        print("\n✗ Basic capture failed - check:")
        print("- Run as Administrator/sudo")
        print("- Install WinPcap/Npcap (Windows)")
        print("- Check firewall/antivirus blocking")
    
    logging.info("Comprehensive tests completed")

def main():
    """Main function with menu options"""
    
    print("=== NETWORK TRAFFIC CAPTURE & TESTING TOOL ===")
    print("1. Run comprehensive tests")
    print("2. Capture general network traffic")
    print("3. Discover and capture webcam traffic")
    print("4. Capture specific IP traffic")
    print("5. Exit")
    
    choice = input("\nSelect option (1-5): ").strip()
    
    if choice == "1":
        target_ip = input("Enter target IP for testing (default: 192.168.1.177): ").strip()
        if not target_ip:
            target_ip = "192.168.1.177"
        run_all_tests(target_ip)
        
    elif choice == "2":
        target_ip = input("Enter target IP: ").strip()
        if not target_ip:
            print("Target IP required")
            return
        
        interface = input("Enter interface (optional): ").strip() or None
        duration = int(input("Duration in seconds (default: 30): ").strip() or "30")
        
        result = capture_network_traffic(target_ip, interface, duration, webcam_mode=False)
        if result:
            print(f"Capture saved to: {result}")
        
    elif choice == "3":
        interface = input("Enter interface (default: Ethernet): ").strip() or "Ethernet"
        duration = int(input("Duration in seconds (default: 60): ").strip() or "60")
        
        result = capture_network_traffic(None, interface, duration, webcam_mode=True)
        if result:
            print(f"Webcam capture saved to: {result}")
        
    elif choice == "4":
        target_ip = input("Enter target IP: ").strip()
        if not target_ip:
            print("Target IP required")
            return
            
        interface = input("Enter interface (optional): ").strip() or None
        duration = int(input("Duration in seconds (default: 30): ").strip() or "30")
        webcam_mode = input("Use webcam filtering? (y/n): ").strip().lower() == 'y'
        
        result = capture_network_traffic(target_ip, interface, duration, webcam_mode=webcam_mode)
        if result:
            print(f"Capture saved to: {result}")
        
    elif choice == "5":
        print("Exiting...")
        
    else:
        print("Invalid choice")

if __name__ == "__main__":
    main()