#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include "router.h"
#include "arp.h"
#include "icmp.h"

#include <stdbool.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>

#define MAC_ADR_SIZE_BYTES 6
#define IP_TYPE 0x0800
#define ARP_TYPE 0x0806
#define OG_PAYLOAD_SIZE 8
#define SZ_ETH_HDR (sizeof(struct ether_header))
#define SZ_IP_HDR (sizeof(struct iphdr))
#define SZ_ICMP_HDR 8
#define TTL_TYPE 11
#define HOST_UNREC_TYPE 3

#define MAX_PACKET_LEN 1600

void handle_icmp(char *frame, int len_frame, uint8_t type, uint8_t code, int interface)
{
	struct ether_header *eth_hdr_recv = (struct ether_header *)frame;
	struct iphdr *ip_hdr_recv = (struct iphdr*)(frame + SZ_ETH_HDR);

	uint8_t *mac_dest = eth_hdr_recv->ether_shost;
	uint32_t ip_dest = ip_hdr_recv->saddr;

	char new_message[MAX_PACKET_LEN];
	struct ether_header *eth_hdr = (struct ether_header *)new_message;

	memcpy(eth_hdr->ether_dhost, mac_dest, MAC_ADR_SIZE_BYTES);
	get_interface_mac(interface, eth_hdr->ether_shost);
	eth_hdr->ether_type = htons(IP_TYPE);

	struct iphdr *ip_hdr = (struct iphdr *)(new_message + sizeof(struct ether_header));
	ip_hdr->daddr = ip_dest;
	ip_hdr->saddr = convert_ip_aton(get_interface_ip(interface));

	ip_hdr->check = 0;
	ip_hdr->frag_off = 0;
	ip_hdr->tos = 0;
	ip_hdr->version = 4;
	ip_hdr->ihl = 5;
	ip_hdr->id = htons(1);

	ip_hdr->ttl = 64;
	char *og_payload;
	int len_pld = 0;
	if (type == TTL_TYPE || type == HOST_UNREC_TYPE) {
		// in this case, as a payload after icmp header should be sent the ip header
		// received + 8 bytes after that
		og_payload = frame + SZ_ETH_HDR;

		// the length of the payload its sizeof(ip header) + 8
		len_pld = SZ_IP_HDR + 8;

		// beside the payload, ip header total len is equal to it's size + the size of icmp header
		// + the payload
		ip_hdr->tot_len = htons(sizeof(struct iphdr) + SZ_ICMP_HDR + len_pld);

	} else {
		// in the payload should be just the message afther the icmp header received 
		// i let the icmp header in the original payload for further use
		og_payload = frame + SZ_ETH_HDR + SZ_IP_HDR;
		len_pld = len_frame - SZ_ETH_HDR - SZ_IP_HDR - SZ_ICMP_HDR;

		ip_hdr->tot_len = htons(sizeof(struct iphdr) + SZ_ICMP_HDR + len_pld);
	}

	ip_hdr->protocol = 1;

	ip_hdr->check = htons(checksum((uint16_t*)ip_hdr, sizeof(struct iphdr)));
	printf("handle icmp this far?\n");
	if (type == TTL_TYPE || type == HOST_UNREC_TYPE)
		icmp_ttl_or_unrec(og_payload, len_pld, interface, type, new_message);
	else
		icmp_echo_reply(og_payload, len_pld, interface, new_message);
}

void icmp_echo_reply(char *og_payload, int len_pld, int interface, char *new_message) {
	printf("LEN_PLD: %d\n", len_pld);
	
	struct icmphdr *icmp_hdr = (struct icmphdr *)(new_message + sizeof(struct ether_header) + sizeof(struct iphdr));
	struct icmphdr *icmp_hdr_recv = (struct icmphdr *)og_payload;
	icmp_hdr->code = 0;
	icmp_hdr->type = 0;
	
	icmp_hdr->un.echo.id = icmp_hdr_recv->un.echo.id;
	icmp_hdr->un.echo.sequence = icmp_hdr_recv->un.echo.sequence;
	og_payload += SZ_ICMP_HDR;
	printf("icmp ECHO REPLY?\n");

	int offset = SZ_ETH_HDR + SZ_IP_HDR + SZ_ICMP_HDR;
	memcpy(new_message + offset, og_payload, len_pld);

	icmp_hdr->checksum = 0;
	icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr, SZ_ICMP_HDR + len_pld));

	send_to_link(interface, new_message, offset + len_pld);
} 

void icmp_ttl_or_unrec(char *og_payload, int len_pld, int interface, uint8_t type, char *new_message) {
	struct icmphdr *icmp_hdr = (struct icmphdr *)(new_message + sizeof(struct ether_header) + sizeof(struct iphdr));

	icmp_hdr->un.echo.id = 0;
	icmp_hdr->un.echo.sequence = 0;

	icmp_hdr->code = 0;
	icmp_hdr->type = type;

	int offset = SZ_ETH_HDR + SZ_IP_HDR + SZ_ICMP_HDR;
	memcpy(new_message + offset, og_payload, len_pld);

	icmp_hdr->checksum = 0;
	icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr, SZ_ICMP_HDR + len_pld));

	send_to_link(interface, new_message, offset + len_pld);
}
