import sys
from scapy.all import sniff, IP, TCP, UDP, Raw, IPv6

def packet_callback(packet):
    """
    This function is called for every packet captured.
    It analyzes the packet and prints relevant information.
    """
    print("\n--- New Packet Captured ---")

    # Check for IP layer
    if IP in packet:
        # Extract IP Header Information
        ip_layer = packet[IP]
        source_ip = ip_layer.src
        destination_ip = ip_layer.dst
        protocol = ip_layer.proto

        print(f"Source IP: {source_ip}")
        print(f"Destination IP: {destination_ip}")

        # Map protocol number to common names
        protocol_name = "Unknown"
        if protocol == 6:
            protocol_name = "TCP"
        elif protocol == 17:
            protocol_name = "UDP"
        elif protocol == 1:
            protocol_name = "ICMP"
        elif protocol == 50:
            protocol_name = "ESP (IPSec)"
        elif protocol == 51:
            protocol_name = "AH (IPSec)"
        elif protocol == 89:
            protocol_name = "OSPF"
        print(f"Protocol: {protocol_name} ({protocol})")

        # Extract Transport Layer Information (TCP/UDP)
        if TCP in packet:
            tcp_layer = packet[TCP]
            print(f" Source Port: {tcp_layer.sport}")
            print(f" Destination Port: {tcp_layer.dport}")
            print(f" Flags: {tcp_layer.flags}")
            print(f" Sequence Number: {tcp_layer.seq}")
            print(f" Acknowledgement Number: {tcp_layer.ack}")
        elif UDP in packet:
            udp_layer = packet[UDP]
            print(f" Source Port: {udp_layer.sport}")
            print(f" Destination Port: {udp_layer.dport}")
            print(f" Length: {udp_layer.len}")

        # Extract Raw Payload Data
        if Raw in packet:
            payload = packet[Raw].load
            print(f"Payload (Raw Data): {payload[:100]}...") # Print first 100 bytes of payload
        else:
            # If no Raw layer, check for application layer data in TCP/UDP
            if (TCP in packet or UDP in packet) and packet.payload:
                try:
                    # Attempt to decode as string if it looks like text
                    payload = bytes(packet.payload)
                    decoded_payload = payload.decode('utf-8', errors='ignore')
                    if len(decoded_payload.strip()) > 0:
                        print(f"Payload (Decoded Text): {decoded_payload[:100]}...")
                    else:
                        print(f"Payload (Hex): {payload.hex()[:200]}...") # Show hex if not text
                except Exception:
                    print(f"Payload (Hex): {bytes(packet.payload).hex()[:200]}...") # Show hex
            else:
                print("No obvious payload data found.")

    elif IPv6 in packet:
        # Handle IPv6 packets (basic)
        ipv6_layer = packet[IPv6]
        print(f"Source IPv6: {ipv6_layer.src}")
        print(f"Destination IPv6: {ipv6_layer.dst}")
        print(f"Next Header (Protocol): {ipv6_layer.nh}")
        if Raw in packet:
            payload = packet[Raw].load
            print(f"Payload (Raw Data): {payload[:100]}...")
        else:
            print("No obvious payload data found for IPv6.")

    else:
        # For non-IP packets (e.g., ARP, spanning tree, etc.)
        print(f"Non-IP Packet (Ethernet Type: {hex(packet.type)})")
        print(f" Summary: {packet.summary()}")


def start_sniffer(interface=None, count=0):
    """
    Starts the packet sniffer.
    :param interface: The network interface to sniff on (e.g., "eth0", "Wi-Fi").
                      If None, Scapy tries to find a suitable interface.
    :param count: Number of packets to capture. 0 for continuous sniffing.
    """
    print("\n--- Starting Packet Sniffer ---")
    print("Capturing packets. Press Ctrl+C to stop.\n")

    if interface:
        print(f"Sniffing on interface: {interface}")
    else:
        print("Sniffing on all available interfaces (may require 'sudo').")

    try:
        sniff(iface=interface, prn=packet_callback, store=0, count=count)
    except PermissionError:
        print("\nError: Permission denied. On Linux, try running with 'sudo'.")
        print("On Windows, ensure Npcap/WinPcap is installed and running.")
    except Exception as e:
        print(f"\nAn error occurred: {e}")
    finally:
        print("\n--- Packet Sniffer Stopped ---")


if __name__ == "__main__":
    # You can specify an interface here, e.g., 'eth0', 'wlan0', 'Wi-Fi', 'Ethernet'
    # To find your interfaces:
    # On Linux/macOS: 'ifconfig' or 'ip a'
    # On Windows: 'ipconfig' (look for names like "Ethernet", "Wi-Fi")
    # Alternatively, you can run 'scapy.all.show_interfaces()' in a Python interpreter

    # Example: sniff 10 packets on a specific interface
    # start_sniffer(interface="Wi-Fi", count=10)

    # Example: sniff continuously on all interfaces (requires sudo on Linux)
    # start_sniffer()

    # To make it interactive for educational purposes:
    print("Welcome to the Educational Packet Sniffer!")
    print("Please ensure ethical use. Do not use this tool maliciously.")

    # Get available interfaces from Scapy
    print("\nAvailable Network Interfaces:")
    try:
        from scapy.all import get_if_list
        interfaces = get_if_list()
        for i, iface in enumerate(interfaces):
            print(f" {i+1}. {iface}")
        print(" 0. Sniff on all interfaces (may require 'sudo')")

        choice = input("Enter the number of the interface to sniff on, or 0 for all: ")
        try:
            choice_idx = int(choice)
            if choice_idx > 0 and choice_idx <= len(interfaces):
                chosen_interface = interfaces[choice_idx - 1]
            elif choice_idx == 0:
                chosen_interface = None # Sniff on all
            else:
                print("Invalid choice. Sniffing on all interfaces.")
                chosen_interface = None
        except ValueError:
            print("Invalid input. Sniffing on all interfaces.")
            chosen_interface = None

    except Exception as e:
        print(f"Could not list interfaces: {e}. Defaulting to sniff on all.")
        chosen_interface = None

    num_packets_str = input("Enter number of packets to capture (0 for continuous): ")
    try:
        num_packets = int(num_packets_str)
    except ValueError:
        print("Invalid number. Capturing continuously.")
        num_packets = 0

    start_sniffer(interface=chosen_interface, count=num_packets)
