#include <stdbool.h>
#include "include/queue.h"
#include "include/skel.h"

/* Array of router interfaces (e.g. 0,1,2,3) */
int interfaces[ROUTER_NUM_INTERFACES];

/* Routing table */
struct route_table_entry *rtable;
int rtable_len;

/* ARP table */
struct arp_entry *arp_table;
int arp_table_len;

// Queue of pairs made up of a package andd a next hop
queue pair_queue;

/*
 Function printing an IP address
*/
void print_ip_address(uint32_t ip) {
	ip = ntohl(ip);
	printf("%u.%u.%u.%u\n", ((ip & 0xff000000) >> 24), ((ip & 0x00ff0000) >> 16),
			((ip & 0x0000ff00) >> 8), ((ip & 0x000000ff) >> 0));
}

/*
 Function comparing Route table entries based on prefix and mask
 for sorting in ascending order
*/
int compare_table_entries(const void *entry1, const void *entry2) {
	struct route_table_entry *e1 = (struct route_table_entry*) entry1;
	struct route_table_entry *e2 = (struct route_table_entry*) entry2;

	// Equal IPs, so compare masks
	if ((e1->prefix & e1->mask) == (e2->prefix & e2->mask)) {
		return (ntohl(e1->mask) > ntohl(e2->mask));
	}

	// Compare IPs
	return ntohl(e1->prefix & e1->mask) > ntohl(e2->prefix & e2->mask);
}

/*
 Function searching a destination IP in the route table using a binary search algorithm.
 The function returns the position in the table if the IP is found, -1 otherwise.
*/
int binary_search(int left, int right, uint32_t dest_ip, struct route_table_entry *rtable, int pos_max_mask) {
	if (left > right) {
		return pos_max_mask;
	}

	int middle = (left + right) / 2;

	uint32_t dest_mask = dest_ip & ntohl(rtable[middle].mask);
	uint32_t prefix = ntohl(rtable[middle].prefix);

	if (dest_mask == prefix) {
		if (pos_max_mask < 0 || ntohl(rtable[middle].mask) > ntohl(rtable[pos_max_mask].mask)) {
			// Better match can be found in the right side of middle
			return binary_search(middle + 1, right, dest_ip, rtable, middle);
		}
	}

	if (dest_mask < prefix) {
		// Destination IP could be found in the left side of middle
		return binary_search(left, middle - 1, dest_ip, rtable, pos_max_mask);
	} else if (dest_mask > prefix) {
		// Destination IP could be found in the right side of middle
		return binary_search(middle + 1, right, dest_ip, rtable, pos_max_mask);
	}

	return pos_max_mask;
}

/*
 Linear search for the best matching route for the given destination address.
 Returns NULL if there is no matching route.
*/
struct route_table_entry *get_best_route_linear(uint32_t dest_ip) {
	struct route_table_entry *best_route = NULL;

	for (int i = 0; i < rtable_len; i++) {
		if ((dest_ip & ntohl(rtable[i].mask)) == ntohl(rtable[i].prefix)) {
			if (best_route == NULL) {
				best_route = &rtable[i];
			} else if (ntohl(best_route->mask) < ntohl(rtable[i].mask)) {
				// Get route with the greatest mask in value  
				best_route = &rtable[i];
			} else if (rtable[i].mask == best_route->mask) {
				best_route = &rtable[i];
			}
		}
	}

	return best_route;
}

/*
 Based on a binary search, returns a pointer (eg. &rtable[i])
 to the best matching route for the given destination address.
 Or NULL if there is no matching route. 
*/
struct route_table_entry *get_best_route(uint32_t dest_ip) {
	int index = binary_search(0, rtable_len, dest_ip, rtable, -1);

	if (index == -1) {
		return NULL;
	}

	return &rtable[index];
}

/*
 Returns a pointer (eg. &arp_table[i]) to the best matching ARP table entry.
 for the given protocol and destination address. Or NULL if there is no matching route.
*/
struct arp_entry *get_arp_entry(uint32_t dest_ip) {
	// Search the best matching ARP entry
	for (int i = 0; i < arp_table_len; i++) {
		// Compare IPs
        if (dest_ip == arp_table[i].ip) {
            return &arp_table[i];
        }
	}

	// ARP entry not found
    return NULL;
}

/*
 Function that handles an ARP request packet, modifying it to an ARP reply packet and sending it
*/
void arp_request(packet m) {
	struct ether_header *eth_hdr = (struct ether_header *) m.payload;

	// Change the ARP request into an ARP reply
	struct arp_header *arp_hdr = (struct arp_header *)(m.payload + sizeof(struct ether_header));

	arp_hdr->op = htons(2); // opcode for reply

	// Set the target hardware address as the sender hardware address
	memcpy(arp_hdr->tha, arp_hdr->sha, 6);
	// Set the sender hardware address as the interface's MAC
	get_interface_mac(m.interface, arp_hdr->sha);

	// Swap the target and sender IP addresses
	arp_hdr->tpa = arp_hdr->spa;
	arp_hdr->spa = inet_addr(get_interface_ip(m.interface));

	// The destination ether address now becomes the source ether address
	memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
	// The source ether adress will have the packet's interface MAC address
	get_interface_mac(m.interface, eth_hdr->ether_shost);

	// Send the ARP reply
	send_packet(&m);
}

/*
 Function generating an ARP request packet because no matching ARP table entry was found.
 The packet will be sent after.
*/
void generate_arp_request(packet m, struct route_table_entry *best_route) {
	// Create new packet
	packet *p = malloc(sizeof(packet));

	struct ether_header *eth_hdr = (struct ether_header *)p->payload;

	// Ether Header destination adress will be a broadcast address (FFFFFF)
	for (int i = 0; i < 6; i++) {
		eth_hdr->ether_dhost[i] = 0xFF;
	}

	// packet is of type ARP
	eth_hdr->ether_type = htons(ETHERTYPE_ARP);

	// Ether Header souce adress will become the initial packet's interface MAC
	get_interface_mac(best_route->interface, eth_hdr->ether_shost);

	// Format ARP header
	struct arp_header *arp_hdr = (struct arp_header *)(p->payload + sizeof(struct ether_header));
	arp_hdr->htype = htons(1);
	arp_hdr->ptype = htons(ETHERTYPE_IP);
	arp_hdr->hlen = 6;
	arp_hdr->plen = 4;
	arp_hdr->op = htons(1); // opcode for ARP request

	// The sender IP address will become the best route's interface IP
	arp_hdr->spa = inet_addr(get_interface_ip(best_route->interface));
	// The target IP address will become the next hop
	arp_hdr->tpa = best_route->next_hop;

	// Set the sender hardware address as the best route's interface MAC
	get_interface_mac(best_route->interface, arp_hdr->sha);

	// Packet's interface will be the same as the best route's
	p->interface = best_route->interface;
	// Set the length
	p->len = sizeof(struct ether_header) + sizeof(struct arp_header);

	// Create a pair with the initial packet and the next hop
	struct queue_pair* pair = malloc(sizeof(struct queue_pair));
	// Copy initial packet
	memcpy(&(pair->packet), &m, sizeof(packet));
	// Next hop is the IP of best route's interface IP
	pair->next_hop = best_route->next_hop;

	// Enqueue the pair
	queue_enq(pair_queue, pair);

	// Send the newly created packet
	send_packet(p);

	// Free the packet
	free(p);
}

/*
 Function that handles an ARP reply packet, adding a new entry to the ARP table
 and sending queued packages that are already in the ARP table
*/
void arp_reply(packet p) {
	struct arp_header *arp_hdr = (struct arp_header *)(p.payload + sizeof(struct ether_header));

	int found = 0;
	// Check if the Sender IP address is in the ARP table
	for (int i = 0; i < arp_table_len; i++) {
		if (arp_table[i].ip == arp_hdr->spa) {
			found = 1;
			break;
		}
	}

	if (found == 1) {
		// IP address is already in ARP table
		return;
	} else {
		// Add new ARP table entry
		// IP corresponds to sender IP address and MAC to sender hardware address
		arp_table[arp_table_len].ip = arp_hdr->spa;
		memcpy(arp_table[arp_table_len].mac, arp_hdr->sha, 6);
		// increment ARP table length
		arp_table_len++;

		// Traverse queue
		while (!queue_empty(pair_queue)) {
			// Get top pair
			struct queue_pair *pair = queue_front(pair_queue);
			found = 0;
			int index = -1;

			// Check if pair's next hop appears in ARP table
			for (int i = 0; i < arp_table_len; i++) {
				if (arp_table[i].ip == pair->next_hop) {
					index = i;
					break;
				}
			}

			if (index >= 0) {
				struct ether_header *eth_hdr_pair_packet =
								(struct ether_header *) pair->packet.payload;
				// Pair packet's Ether header destination address becomes the ARP entry's MAC
				memcpy(eth_hdr_pair_packet->ether_dhost, arp_table[index].mac, 6);
				// Send the pair packet
				send_packet(&(pair->packet));

				// Dequeue and free the front pair 
				struct queue_pair *deq_pair = queue_deq(pair_queue);
				free(deq_pair);
			} else {
				// Top pair's next hop isn't in ARP table
				break;
			}
		}
	}
}

/*
 Function generating and sending an ICMP packet, handling both error cases and echo reply
*/
void send_icmp_message(packet m, int type, int code) {
	struct iphdr *ip_hdr = (struct iphdr *)(m.payload + sizeof(struct ether_header));

	// Destination unreachable or time exceeded cases
	if (type != 0) {
		// Get the first 64 bytes after the IP header to make way for the ICMP header
		uint8_t buffer[64];
		memcpy(buffer, (uint8_t *)ip_hdr + sizeof(struct iphdr), 64);
		// Shift the saved bytes to the right, leaving space for ICMP header
		memcpy((uint8_t *)ip_hdr + sizeof(struct iphdr) + sizeof(struct icmphdr), buffer, 64);
		// Readjust length
		ip_hdr->tot_len = htons(ntohs(ip_hdr->tot_len) + sizeof(struct icmphdr));
		ip_hdr->protocol = IPPROTO_ICMP;

		// Increase length
		m.len += sizeof(struct icmphdr);
	}

	// Format the ICMP header
	struct icmphdr *icmp_hdr =
			(struct icmphdr *)(m.payload + sizeof(struct ether_header) + sizeof(struct iphdr));
	icmp_hdr->type = type;
	icmp_hdr->code = code;
	icmp_hdr->checksum = 0;

	// Switch the IP header's destination with source IP addresses
	ip_hdr->daddr = ip_hdr->saddr;
	// IP header's source address becomes the interface IP
	ip_hdr->saddr = inet_addr(get_interface_ip(m.interface));
	
	// Compute checksum
	icmp_hdr->checksum = icmp_checksum((uint16_t *)icmp_hdr,
				m.len - sizeof(struct ether_header) - sizeof(struct iphdr));

	struct ether_header *eth_hdr = (struct ether_header *) m.payload;
	// Switch the ether header's destination address with the source address
	memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
	// Ether header's source address becomes the interface MAC
	get_interface_mac(m.interface, eth_hdr->ether_shost);
	eth_hdr->ether_type = htons(ETHERTYPE_IP);

	// Send packet
	send_packet(&m);
}

/*
 Function handling an IPv4 packet according to the protocol
*/
void ipv4_protocol(packet m) {
	struct ether_header *eth_hdr = (struct ether_header *) m.payload;
	// Extract the IPv4 header from the Ethernet header
    struct iphdr *ip_hdr = (struct iphdr *)(m.payload + sizeof(struct ether_header));
	uint32_t destination_ip;

	// Check if ICMP message
	if (ip_hdr->protocol == IPPROTO_ICMP) {
		// search for IP header's destination IP within router's interfaces
		for (int i = 0; i < ROUTER_NUM_INTERFACES; i++) {
			// check if interface's IP coincides with the destination IP 
			if (ip_hdr->daddr == inet_addr(get_interface_ip(i))) {
				struct icmphdr *icmp_hdr = (struct icmphdr *)(m.payload +
						sizeof(struct ether_header) + sizeof(struct iphdr));
				// check if pakage is of type Echo request in order to send a reply back
				if (icmp_hdr->type == 8 && icmp_hdr->code == 0) {
					send_icmp_message(m, 0, 0);
					return;
				}
			}
		}
	}

	// Check the checksum as required by IPv4
	if (ip_checksum((void *) ip_hdr, sizeof(struct iphdr)) != 0) {
		return;
	}

	// Check TTL >= 1 */
	if (ip_hdr->ttl == 0 || ip_hdr->ttl == 1) {
		// Send ICMP message
		send_icmp_message(m, 11, 0);
		return;
	}
	
	// Get the destination IP
	destination_ip = ntohl(ip_hdr->daddr);

	// Find best route/next hop
	struct route_table_entry *best_route = get_best_route(destination_ip);

	// Best route couldn't be found
	if (best_route == NULL) {
		// Send ICMP message
		send_icmp_message(m, 3, 0);
		return;
	}

	// Ether Header's source adress will have the value of the best route's MAC
	get_interface_mac(best_route->interface, eth_hdr->ether_shost);
	// Packet interface becomes that of the best route's
	m.interface = best_route->interface;

	// Update TTL and recalculate the checksum */
	ip_hdr->ttl--;
	ip_hdr->check = 0;
	ip_hdr->check = ip_checksum((void *) ip_hdr, sizeof(struct iphdr));

	// Find matching ARP entry
	struct arp_entry *arp_best_route = get_arp_entry(best_route->next_hop);

	// ARP entry not found
	if (arp_best_route == NULL) {
		// Send an ARP request
		generate_arp_request(m, best_route);
		return;
	}

	// Ether Header's destination adress will have the value of the ARP entry's MAC
	memcpy(eth_hdr->ether_dhost, arp_best_route->mac, 6);

	// Send packet
	send_packet(&m);
}

int main(int argc, char *argv[])
{
	packet m;
	int rc;

	init(argc - 2, argv + 2);

	rtable = malloc(sizeof(struct route_table_entry) * 100000);
	DIE(rtable == NULL, "memory");
	arp_table = malloc(sizeof(struct  arp_entry) *  100000);
	DIE(arp_table == NULL, "memory");

	/* Read the static routing table and the MAC table */
	rtable_len = read_rtable(argv[1], rtable);

	qsort(rtable, rtable_len, sizeof(struct route_table_entry), compare_table_entries);

	// Create pair queue
	pair_queue = queue_create();

	while (1) {
		// Receive a packet from an interface
		rc = get_packet(&m);
		DIE(rc < 0, "get_message");
		
		// Extract the Ethernet header from the packet
		struct ether_header *eth_hdr = (struct ether_header *) m.payload;

		// Check if this is an IPv4 or ARP packet and route accordingly
		if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IP) {
			ipv4_protocol(m);
        } else if (ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP) {
			// Extract the ARP header from the Ethernet header
			struct arp_header *arp_hdr =
						(struct arp_header *)(m.payload + sizeof(struct ether_header));

			// Check whether it is an ARP reply or request
			if (arp_hdr->op == htons(1)) {
				arp_request(m);
			} else {
				arp_reply(m);
			}
		}
	}
}
