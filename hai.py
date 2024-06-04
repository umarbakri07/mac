from scapy.all import ARP, Ether, srp
import os

def get_local_ip():
    """Get the local IP address of the machine."""
    import socket
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    return local_ip

def get_mac_address(ip):
    """Get the MAC address of the IP address."""
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc

def scan_network(ip_range):
    """Scan the network and return a list of connected devices."""
    arp_request = ARP(pdst=ip_range)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = srp(arp_request_broadcast, timeout=2, verbose=False)[0]

    devices = []
    for sent, received in answered_list:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    
    return devices

if __name__ == "__main__":
    # Get the local IP address and create a network range to scan
    local_ip = get_local_ip()
    ip_base = '.'.join(local_ip.split('.')[:-1]) + '.0/24'
    
    print(f"Scanning network: {ip_base}")
    devices = scan_network(ip_base)
    
    if devices:
        print("Connected devices:")
        for device in devices:
            print(f"IP Address: {device['ip']} - MAC Address: {device['mac']}")
    else:
        print("No devices found.")

