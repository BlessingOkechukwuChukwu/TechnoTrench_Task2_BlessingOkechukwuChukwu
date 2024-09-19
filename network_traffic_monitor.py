from scapy.all import sniff, IP, TCP, UDP
from collections import defaultdict
import time
import signal
import sys

# Dictionary to store traffic statistics
stats = defaultdict(lambda: {'bytes': 0, 'packets': 0})
start_time = time.time()
packet_count = 0

def packet_callback(packet):
    global packet_count
    packet_count += 1
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        length = len(packet)

        # Update statistics
        stats[ip_src]['bytes'] += length
        stats[ip_src]['packets'] += 1
        stats[ip_dst]['bytes'] += length
        stats[ip_dst]['packets'] += 1

        # Print packet information
        print(f"Source: {ip_src}, Destination: {ip_dst}, Length: {length} bytes")
        
        if TCP in packet:
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            print(f"Protocol: TCP, Source Port: {sport}, Destination Port: {dport}")
        elif UDP in packet:
            sport = packet[UDP].sport
            dport = packet[UDP].dport
            print(f"Protocol: UDP, Source Port: {sport}, Destination Port: {dport}")
        
        print("--------------------")

def print_stats():
    global start_time, packet_count
    end_time = time.time()
    duration = end_time - start_time
    
    print("\nTraffic Statistics:")
    print(f"Duration: {duration:.2f} seconds")
    print(f"Total Packets: {packet_count}")
    print(f"Packets per second: {packet_count / duration:.2f}")
    
    print("\nPer IP Statistics:")
    for ip, data in stats.items():
        print(f"IP: {ip}")
        print(f"  Bytes: {data['bytes']}")
        print(f"  Packets: {data['packets']}")
        print(f"  Bytes per second: {data['bytes'] / duration:.2f}")
        print(f"  Packets per second: {data['packets'] / duration:.2f}")
        print("--------------------")

def signal_handler(sig, frame):
    print("\nCapture stopped by user. Printing statistics...")
    print_stats()
    sys.exit(0)

def main():
    print("Starting Network Traffic Monitor...")
    print("Press Ctrl+C to stop and view statistics.")
    
    # Set up the signal handler for keyboard interrupt
    signal.signal(signal.SIGINT, signal_handler)
    
    try:
        # Start packet capture
        sniff(prn=packet_callback, store=0)
    except KeyboardInterrupt:
        # This block shouldn't be necessary now, but keeping it as a fallback
        print("\nCapture stopped by user.")
        print_stats()

if __name__ == "__main__":
    main()