from socket import AF_INET6

from mac_vendor_lookup import MacLookup, VendorNotFoundError

from scapy.arch import *
from scapy.config import conf
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import ARP, getmacbyip, Ether
from scapy.pton_ntop import inet_pton
from scapy.sendrecv import srp, sniff, sr

print('\n############### \t\t Victim-host related information \t\t ###############\n')

# A)
host_ipv4 = get_if_addr(conf.iface)
print(f'A) Globally routable IPv4 address of victim-host: {host_ipv4}')

# B)
host_mac = get_if_hwaddr(conf.iface)
print(f'B) MAC address associated with the victim-host: {host_mac}')

# C)
host_ipv6 = get_if_addr6(conf.iface)
print(f'C) IPv6 address assigned to victim-host: {host_ipv6}')

# C2)
if host_ipv6 is not None:
    host_mac_1st_half = int(host_mac[0:8].replace(':', ''), 16)
    seventh_bit_flipper = int('0b000000100000000000000000', 2)
    host_mac_1st_half = bin(seventh_bit_flipper | host_mac_1st_half)[2:].zfill(24)
    host_mac_2nd_half = bin(int(host_mac[9:].replace(':', ''), 16))[2:].zfill(24)
    eui_64_format = bin(int('FFFE', 16))[2:].zfill(16)
    eui_64_interface_id = f'0b{host_mac_1st_half}{eui_64_format}{host_mac_2nd_half}'
    eui_64_interface_id = int(eui_64_interface_id, 2).to_bytes(8, byteorder='big')

    ipv6_state = 'stateful'
    if eui_64_interface_id == inet_pton(AF_INET6, host_ipv6)[8:]:
        ipv6_state = 'stateless'

    print(f'C2) IPv6 address is {ipv6_state}.')

# D)
host_nic_manufacturer = MacLookup().lookup(host_mac)
print(f'D) Manufacturer of the host-victim NIC: "{host_nic_manufacturer}"')

print("\n############### \t\t LAN's gateway related information \t\t ###############\n")

# E)
gw_ipv4 = conf.route.route("0.0.0.0")[2]
print(f'E) IPv4 address of the main/default gateway in the victim-host LAN: {gw_ipv4}')

# F)
gw_mac = getmacbyip(gw_ipv4)
gw_nic_manufacturer = MacLookup().lookup(gw_mac)
print(f'F) Manufacturer of the gateway: "{gw_nic_manufacturer}"')

print("\n############### \t\t Other hosts related information \t\t ###############\n")

# G)
netmask = 0xFFFFFF00
cidr = 24
a = host_ipv4.split('.')
a = [hex(int(x, 10))[2:].zfill(2) for x in a]
host_ipv4_int = int(''.join(a), 16)
network_address = host_ipv4_int & netmask
network_address = hex(network_address)[2:].zfill(8)
network_address = [network_address[i:j] for i, j in zip([0, 2, 4, 6], [0, 2, 4, 6][1:] + [None])]
network_address = [str(int(x, 16)) for x in network_address]
network_address = '.'.join(network_address)

responsive_hosts, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network_address + '/' + str(cidr)), timeout=2,
                              verbose=0)
print(f'G1) (ARP Sweep) Number of active/responsive hosts on victim-host LAN: {len(responsive_hosts)}')

monitored_macs = set()
monitored_ips = set()


def arp_monitor_callback(pkt):
    if ARP in pkt and pkt[ARP].op == 1:  # who-is
        monitored_macs.add(pkt[Ether].src)
        monitored_ips.add(pkt[ARP].psrc)


sniff_timeout = int(input('G2) How long (in seconds) do you want to sniff (passively scan) for hosts in the LAN? '
                          'Please enter an integer: '))
sniff(prn=arp_monitor_callback, filter="arp", store=1, timeout=sniff_timeout)
num_monitored_macs = len(monitored_macs)
num_monitored_ips = len(monitored_ips)
print(f'G2) (ARP Monitor) Number of monitored MACs on victim-host LAN in {sniff_timeout} seconds: '
      f'{num_monitored_macs}')
print(f'G2) (ARP Monitor) Number of monitored IPs on victim-host LAN in {sniff_timeout} seconds: '
      f'{num_monitored_ips}')

# H) & I)
apple_device_counter = 0
cisco_device_counter = 0
for host in responsive_hosts:
    reply = host[1]
    mac = reply[ARP].hwsrc
    vendor = "Unknown"
    try:
        vendor = MacLookup().lookup(mac)
    except VendorNotFoundError:
        continue
    if 'Apple' in vendor:
        apple_device_counter += 1
    if 'Cisco' in vendor:
        cisco_device_counter += 1

print(f'H) Number of Apple devices: {apple_device_counter}')
print(f'I) Number of Cisco devices: {cisco_device_counter}')

# J)
http_port_open_counter = 0
https_port_open_counter = 0
http_and_https_port_open_counter = 0
for host in responsive_hosts:
    reply = host[1]
    ip = reply[ARP].psrc
    pkt = IP(dst=ip) / TCP(dport=[80, 443], flags="S")
    ans, unans = sr(pkt, timeout=2, verbose=0)
    http_open = False
    https_open = False
    for a in ans:
        tcp_reply = a[1][TCP].summary()
        if 'https' in tcp_reply:
            https_port_open_counter += 1
            https_open = True
            continue
        if 'http' in tcp_reply:
            http_port_open_counter += 1
            http_open = True
            continue
    if http_open and https_open:
        http_and_https_port_open_counter += 1

print(f'J1) Number of devices with port 80 open: {http_port_open_counter}')
print(f'J2) Number of devices with port 443 open: {https_port_open_counter}')
print(f'J3) Number of devices with port 80 and 443 open: {http_and_https_port_open_counter}')
