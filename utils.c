#include "protocols.h"
#include "lib.h"
#include "icmp.h"
#include "router.h"
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>

void reverse_bytes(uint8_t *data_in, int size) {
	// function to transform from little endian->big endian data of more than 2/4
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
	// tests if the destination mac on ethernet header received is broadcast
	// or its the mac of the router's interface
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
	// when you don't know about the existance of inet_pton you implement your own
	// function that transforms ASCII ipv4 address to big endian number
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
