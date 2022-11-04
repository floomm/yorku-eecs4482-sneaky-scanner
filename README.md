# YorkU EECS4482 Sneaky Scanner

A simple Scapy-based network reconnaissance tool

## Instruction

1. Make sure that the python packages `mac-vendor-lookup` and `scapy` are installed. If not, run `pip3 install mac-vendor-lookup` and `pip3 install scapy` in a console.
2. To execute the Sneaky Scanner, run `python SneakyScanner.py` in a console.
3. The program will output the information in the console. For G) it will also ask for how many **seconds** you want to sniff (passively scan) the LAN for hosts. Please enter an integer here.
4. Please be patient at task J) as it will execute a SYN scan for every single detected host. Also, there may be a few warnings, ignore them.

**Be aware that the ARP sweep (on a rare basis) doesn't seem to work. Just run the program again and it should work.**

## Brief Code Description

The code is procedural and there is only one helper method. The comments indicate which task the following code is solving.

Make sure that the python package `mac-vendor-lookup` is installed. If not, run `pip3 install mac-vendor-lookup`.

### C)

To determine if the address is stateless, I check if the IPv6 address follows the EUI-64 format. Otherwise, the address is stateful.

### G)

Here, I implemented both ARP sweep (active probing) and ARP monitoring (passive scanning).

To get the network address for the ARP sweep, I didn't just replace the last byte of the IP address with a 0, but dynamically calculated the network address according the constant netmask (0xFFFFFF00) and the victim-host's IP. This way, you only need to adjust the netmask and CIDR if they change and you don't need to calculate the network address manually.

Obviously, it would be even better to get the netmask and cidr dynamically but I didn't want to deviate from the given task.

For the ARP monitoring, the program sniffs for ARP requests for as long as the user defined.

### J)

A SYN scan on ports 80 and 443 on every detected responsive host in the LAN is executed.
