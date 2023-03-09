# PCOM-Tema1

## Sorting the routing tabe & binary search:
In order to sort the routing table, I used a function that first compares IPs, and then masks. The result will be a sorted table in ascending order. First, I tried to compare the prefixes first, but that didn't work unfortunately and the issue was fixed by comparing IP values.  

The binary search is done recursively and the position of the maximum found mask will be remembered. Once a matching routing table entry is found, the search continues in order to get the entry with the greatest mask value. When searching, I used the formula provided in the homework document: ip.destination & entry.mask == entry.prefix, checking if an address is part of a network. In the end, the index of the matching route with maximum mask value.


## IPv4 protocol:
First, I check if the packet is an ICMP message and then I search the destination IP in the router's interfaces' IPs. In case it was found, I then verify its type of message. In case it's an Echo request, then I will send an Echo reply ICMP packet and then continue waiting for the next packet. Then, the checksum will be checked, but if it's equal to 0, then I'll drop the package and cotinue to the next packet. If it's correct, I will check the TTL. For a value of 0 or 1, I will send a "Time exceeded" ICMP message and go on. For any other value, I will go to the next step, which is performing a binary search to find the best matching route/ next hop based on the IP destination address. Once again, if the route is not found, I will send an ICMP package of type "Destination unreachable" and move on. Otherwise, the TTL is updated and the Checksum is recalulated. After making some changes to the Ethernet header and packet's interface, a matching ARP entry is searched. If not found, then an ARP request is generated and I continue to wait for the next package. If found, the Ethernet header destination host is updated and the package is sent.


## ARP protocol: 
- ARP request:
In the case of an ARP request, there will be some changes made to the package so that it will become an ARP reply. In order to do that, the opcode will be replaced with the value specific to that of an ARP reply, and the sender/source and target/destination addresses will be swapped. After the packet is converted to an ARP reply, it will be sent.

- Generate ARP request:
This function will be used if no matching ARP entry was found for the IPv4 packet. Thus, we create a new packet, set its Ether destination address as a broadcast address and its sender address as th best matching route's interface. The ARP header will be formatted as an ARP reply and the sender and target addresses will be set as the best route's interface IP and next hop. The newly created packet's interface will be set as the best route's interface. After, the old packet will be enqueued in a pair with the best route's next hop. In the end, the newly created ARP request packet will be sent.

- ARP reply:
In case of receiving an ARP reply, I search the sender IP address in the ARP table. If an entry is found, then I continue to wait for new packets. Otherwise, a new ARP entry is created using the sender IP and MAC addresses of the packet. Then, I will dequeue all the pairs containing a next hop that is already in the ARP table and send the packet from the pair after changin the Ether header destination address with the corresponding ARP entry's MAC.


## ICMP protocol:
First, I check if the message is supposed to be an Echo reply or not based on the provided type. If it's not, then I will move 64 bytes after the IP header in order to fit in the ICMP header. In order to do this, I will copy the first 64 bytes after the IP header into a buffer and then put them back after the allocated space for an ICMP header. I then readjust the length of the packet and set the IP header protocol to match that of an ICMP protocol. Then, in both cases (error message and echo reply), I set the type and the code specific to the message and switch the destination and source IP addresses. The checksum is recalculated and the Ether header addresses will be changed. Finally, the newly formatted ICMP packet will be sent.
