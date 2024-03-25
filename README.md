# Tusk
Tusk is a network scanning tool, that retrieves private internet protocol (IP) addresses from a network, with a corresponding Media Access Control (MAC) address and any open ports. Tusk is also a port scanner, which can scan all possible 65535 ports relatively quickly.

## Features

- **IP Range Scanning**: Scans a range of IP addresses for active hosts on a network.
- **MAC Address Retrieval**: Retrieves the MAC address of discovered hosts.
- **Ping Scan**: Uses ICMP ping to check the availability of hosts.
- **Port Scanning**: Scans a range of ports on a target host.

## Configuration

- Set the highest octet number when prompted. An octet is every number separated by a period. For example, for the IP address 127.0.0.1, the first octet is 127, second is 0, third is 0, and last octet is 1. When an input of the highest octet is being asked, all its asking is for the last octet, so in the case of 127.0.0.1, it would be 1. because almost all Local Area Networks (LAN) have a subnet of 255.255.255.0, which means only the last octet can be from 1 to 255 (excluding the broadcast address and default gateway it would actually only be 253).
- Adjust the timeout and sleep values in the script as needed.
