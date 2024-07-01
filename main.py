import scapy.all as scapy
import socket


def scan_network(ip_address) -> list:
    #Make ARP request to broadcast addresses
    arp_request = scapy.ARP(pdst=ip_address)
    #Set to ff:ff... to match any MAC address
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    #Combine packets
    arp_request_broadcast = broadcast / arp_request
    #Send packet with custom ether to set mac address
    answered_list = scapy.srp(arp_request_broadcast, timeout=2)[0]

    #Get data from answered_list
    devices: list = []
    for item in answered_list:
        device_info = {
            #Get IP address from response
            "ip": item[1].psrc,
            #Get Mac address from response
            "mac": item[1].hwsrc,
            #Get device name
            "name": get_device_name(item[1].psrc)
        }
        devices.append(device_info)
    #return list of dicts with network data
    return devices


#Get device name by ip address
def get_device_name(ip_address):
    try:
        device_name: tuple = socket.gethostbyaddr(ip_address)
        return device_name[0]
    except socket.herror:
        return None


def print_devices(devices) -> None:
    print("IP Address\t\tMAC Address\t\t\tDevice Name")
    print("-------------------------------------------------------------------")
    for device in devices:
        print(f"{device['ip']}\t\t{device['mac']}\t\t{device['name']}")


if __name__ == "__main__":
    # Define the network IP range you want to scan (e.g., "192.168.1.1/24")
    ip_range = "192.168.1.1/24"
    devices = scan_network(ip_range)
    #print(devices)
    print_devices(devices)
