#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include "router.h"
#include "arp.h"
#include "icmp.h"
#include "trie.h"
#include "utils.h"

#include <stdbool.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>

#define MAC_ADR_SIZE_BYTES 6
#define IP_TYPE 0x0800
#define ARP_TYPE 0x0806
#define OG_PAYLOAD_SIZE 8
#define SZ_ETH_HDR (sizeof(struct ether_header))
#define SZ_IP_HDR (sizeof(struct iphdr))
#define SZ_ICMP_HDR 8
#define TTL_TYPE 11
#define HOST_UNREC_TYPE 3

struct arp_queue packets_arp_queue;
struct arp_table arp_tbl; 

void handle_ip_packet(struct ether_header *eth_hdr, char *frame, int len_frame, int interface) {
	printf("[LOG] Received an IPv4 packet\n");
	struct iphdr *ip_hdr = (struct iphdr *)(frame + sizeof(struct ether_header));

	// compare checksums
	uint16_t received_check = ip_hdr->check;
	received_check = ntohs(received_check);
	ip_hdr->check = 0;

	uint16_t new_check = checksum((uint16_t*)ip_hdr, sizeof(struct iphdr));

	if (received_check != new_check) {
		// drop the packet
		printf("[LOG] Bad checksum\n");
		return;
	}

	if (am_i_destination_ip(interface, ip_hdr)) {
		printf("[LOG] Packet destination IP it's me, sending echo reply\n");
		handle_icmp(frame, len_frame, 0, 0, interface);
		return;
	}
	int rc = update_ttl(frame, len_frame, interface);
	if (rc)
		return; // the packet has been dropped and a reply has been sent

	// search for the next hoop
	struct route_table_entry *next_hoop = search_next_hoop(ip_hdr->daddr);
	if (next_hoop == NULL) {
		printf("[LOG] Destination unreachable\n");
		handle_icmp(frame, len_frame, HOST_UNREC_TYPE, 0, interface);
		return;
	}

	// modify the existing packet to send it forward
	update_checksum(ip_hdr);
	struct arp_entry *arp_dest = find_mac_address_in_arp(next_hoop->next_hop);
	if (arp_dest == NULL) {
		// it means there's no entry in the arp table for the ip to send to
		printf("[LOG] No entry in the ARP table found, creating ARP request\n");
		struct arp_queue_entry entry = create_arp_queue_entry(frame, len_frame, *next_hoop);
		arp_enq(entry);

		generate_arp_request(next_hoop->next_hop, next_hoop->interface);
		return;
	}

	// replace the data in old ethernet header
	eth_hdr->ether_type = htons(IP_TYPE);
	get_interface_mac(interface, eth_hdr->ether_shost);
	memcpy(eth_hdr->ether_dhost, arp_dest->mac, MAC_ADR_SIZE_BYTES);
	
	// send forward the packet
	send_to_link(next_hoop->interface, frame, len_frame);
}

int main(int argc, char *argv[])
{
	setvbuf(stdout, NULL, _IONBF, 0);
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	init_rtable_trie(argv[1]);
	init_arp_table();
	init_arp_queue();
	while (1) {
		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *) buf;
		convert_to_host_eth_header(eth_hdr);
		if (am_i_destination_mac(eth_hdr, interface) == 0) {
			printf("[LOG] received a frame which is not for me\n");
			continue; // drop the eth frame, it's not for me
		}

		printf("[LOG] Received a frame\n");
		if (eth_hdr->ether_type == ARP_TYPE)
			handle_arp_packet(eth_hdr, buf, interface);
		else
			handle_ip_packet(eth_hdr, buf, len, interface);
	
		/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */
	}
}
