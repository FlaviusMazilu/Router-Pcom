#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include "router.h"
#include "arp.h"
#include "icmp.h"
#include "trie.h"

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

void reverse_bytes(uint8_t *data_in, int size) {
	uint8_t buffer[10];
	int k = 0;
	for (int i = MAC_ADR_SIZE_BYTES - 1; i >= 0; i--) {
		buffer[k++] = data_in[i];
	}
	
	memcpy(data_in, buffer, MAC_ADR_SIZE_BYTES);
}

void convert_to_host_eth_header(struct ether_header *eth_hdr) {
	
	reverse_bytes(eth_hdr->ether_dhost, MAC_ADR_SIZE_BYTES);
	reverse_bytes(eth_hdr->ether_shost, MAC_ADR_SIZE_BYTES);

	eth_hdr->ether_type = ntohs(eth_hdr->ether_type);
}

int am_i_destination_mac(struct ether_header *eth_hdr, int interface) {
	
	uint8_t my_mac[MAC_ADR_SIZE_BYTES];
	get_interface_mac(interface, my_mac);

	char ok_broadcast = 1;
	for (int i = 0; i < MAC_ADR_SIZE_BYTES; i++) {
		if (eth_hdr->ether_dhost[i] != 0xFF)
			ok_broadcast = 0;
	}
	if (ok_broadcast == 1)
		return 1;

	reverse_bytes(my_mac, MAC_ADR_SIZE_BYTES);

	for (int i = 0; i < MAC_ADR_SIZE_BYTES; i++) {
		if (eth_hdr->ether_dhost[i] != my_mac[i])
			return 0;
	}
	return 1;
}

void add_eth_header_ip(char *frame, int interface_source, uint8_t *mac_dest) {
	struct ether_header *eth_hdr = (struct ether_header *)frame;
	eth_hdr->ether_type = htons(IP_TYPE);
	get_interface_mac(interface_source, eth_hdr->ether_shost);
	memcpy(eth_hdr->ether_dhost, mac_dest, MAC_ADR_SIZE_BYTES);
}

int	am_i_destination_ip(int interface, struct iphdr *ip_hdr) {

	struct in_addr addr;
	addr.s_addr = ip_hdr->daddr;
	char destination_ip[30];
	strcpy(destination_ip, inet_ntoa(addr));

	char *interface_ip = get_interface_ip(interface);
	if (strcmp(interface_ip, destination_ip) == 0)
		return 1;
	return 0;
}

uint32_t convert_ip_aton(char *ascii_address) {
	int i = 0;
	uint32_t ret_val = 0;
	int val_index = 0;
	while (ascii_address[i] != '\0') {
		char buffer[10];
		int k = 0;
		while (ascii_address[i] != '.' && ascii_address[i] != '\0') {
			buffer[k++] = ascii_address[i];
			i++;
		}
		buffer[k] = '\0';
		int nr = atoi(buffer);
		printf("nr: %d\n", nr);
		*((char*)&ret_val + val_index) = (char)nr;
		if (ascii_address[i] == '\0')
			break;
		i++;
		val_index++;
	}
	return ret_val;
}

int update_ttl(char *frame, int len_frame, int interface) {
	struct iphdr *ip_hdr = (struct iphdr*)(frame + SZ_ETH_HDR);
	printf("TTL:%d\n", ip_hdr->ttl);
	if (ip_hdr->ttl == 0 || ip_hdr->ttl == 1) {
		//time limit exceeded
		printf("handle ttl 0/1\n");
		handle_icmp(frame, len_frame, TTL_TYPE, 0, interface);
		return -1;
	}
	ip_hdr->ttl = ip_hdr->ttl - 1;
	return 0;
}

void update_checksum(struct iphdr *ip_hdr) {
	ip_hdr->check = 0;
	ip_hdr->check = htons(checksum((uint16_t*)ip_hdr, sizeof(struct iphdr)));
}


void handle_ip_packet(struct ether_header *eth_hdr, char *frame, int len_frame, int interface) {
	struct iphdr *ip_hdr = (struct iphdr *)(frame + sizeof(struct ether_header));

	uint16_t received_check = ip_hdr->check;
	received_check = ntohs(received_check);
	ip_hdr->check = 0;

	uint16_t new_check = checksum((uint16_t*)ip_hdr, sizeof(struct iphdr));

	if (received_check != new_check) {
		// drop the packet
		// TODO send ICMP reply
		printf("checksum BAD\n");
		return;
	}
	printf("checksum GOOD\n");
	// char *og_payload = frame + SZ_ETH_HDR + SZ_IP_HDR;
	// int len_pld = len_frame - SZ_ETH_HDR + SZ_IP_HDR;
	if (am_i_destination_ip(interface, ip_hdr)) {
		printf("IP: the packet is for me: Echo reply\n");
		handle_icmp(frame, len_frame, 0, 0, interface);
		return;
	}
	int rc = update_ttl(frame, len_frame, interface);
	if (rc)
		return; // the packet has been dropped and a reply has been sent

	// struct route_table_entry *next_hoop = find_next_hoop(ip_hdr->daddr);
	struct route_table_entry *next_hoop = search(ip_hdr->daddr);
	if (next_hoop == NULL) {
		printf("destination unreachable :(\n");
		handle_icmp(frame, len_frame, HOST_UNREC_TYPE, 0, interface);
		return;
	}

	update_checksum(ip_hdr);
	printf("[HANDLE IP PACKET] find mac address in arp\n");
	struct arp_entry *arp_dest = find_mac_address_in_arp(next_hoop->next_hop);
	if (arp_dest == NULL) {
		// it means there's no entry in the arp table for the ip to send to

		struct arp_queue_entry entry = create_arp_queue_entry(frame, len_frame, *next_hoop);
		arp_enq(entry);

		printf("[HANDLE IP PACKET] generate arp request\n");
		generate_arp_request(next_hoop->next_hop, next_hoop->interface);
		return;
	}

	// replace the data in old eth header
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
		printf("I got eth header\n");
		if (am_i_destination_mac(eth_hdr, interface) == 0) {
			printf("its not for me");
			continue; // drop the eth frame, it's not for me
		}

		printf("Received a frame\n");
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
