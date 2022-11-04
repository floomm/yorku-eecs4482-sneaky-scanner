from socket import AF_INET6

import requests

from time import sleep

from scapy.arch import *
from scapy.layers.inet import *
from scapy.sendrecv import sr1

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
url = 'https://api.macvendors.com/'
#sleep(1)
#response = requests.get(url + host_mac)  # 1000 calls per day are free, max 1 per second
#host_nic_manufacturer = response.text
#print(f'D) Manufacturer of the host-victim NIC: "{host_nic_manufacturer}"')

print("\n############### \t\t LAN's gateway related information \t\t ###############\n")

# E)
gw_ipv4 = conf.route.route("0.0.0.0")[2]
print(f'E) IPv4 address of the main/default gateway in the victim-host LAN: {gw_ipv4}')

# F)
gw_mac = getmacbyip(gw_ipv4)
#sleep(1)
#response = requests.get(url + gw_mac)  # 1000 calls per day are free, max 1 per second
#gw_nic_manufacturer = response.text
#print(f'F) Manufacturer of the gateway: "{gw_nic_manufacturer}"')

print("\n############### \t\t Other hosts related information \t\t ###############\n")

# G)
netmask = 0xFFFFFF00
cidr = 24
a = host_ipv4.split('.')
a = [hex(int(x, 10))[2:].zfill(2) for x in a]
host_ipv4_int = int(''.join(a), 16)
network_address = host_ipv4_int & netmask
network_address = hex(network_address)[2:].zfill(8)
network_address = [network_address[i:j] for i, j in zip([0, 2, 4, 6], [0, 2, 4, 6][1:]+[None])]
network_address = [str(int(x, 16)) for x in network_address]
network_address = '.'.join(network_address)

pkt = IP(dst=network_address + '/' + str(cidr))/TCP(dport=[80, 443, 777], flags='S')
resp = sr(pkt)
print(resp)
