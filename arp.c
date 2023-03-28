#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

#include "include/queue.h"
#include "include/lib.h"
#include "include/protocols.h"
#include "router.h"

#define MAC_ADR_SIZE_BYTES 6
#define IP_TYPE 0x0800
#define ARP_TYPE 0x0806

extern struct arp_queue packets_arp_queue;
extern struct arp_table arp_tbl;

void init_arp_queue() {
	packets_arp_queue.actual_size = 0;
	packets_arp_queue.capacity = 10;
	packets_arp_queue.array = malloc(sizeof(struct arp_queue_entry) * 10);
	DIE (!packets_arp_queue.array, "arp table init failed\n");
}

void init_arp_table() {
	arp_tbl.actual_size = 0;
	arp_tbl.capacity = 10;
	arp_tbl.array = malloc(sizeof(struct arp_entry) * 10);
	DIE (!arp_tbl.array, "arp table init failed\n");
}

void arp_enq(struct arp_queue_entry entry) {
	if (packets_arp_queue.actual_size == packets_arp_queue.capacity - 2) {
		struct arp_queue_entry *aux = realloc(packets_arp_queue.array,
											packets_arp_queue.capacity * 2);
		packets_arp_queue.capacity *= 2;

		DIE (!aux, "realloc failed\n");
		packets_arp_queue.array = aux;
	}
	packets_arp_queue.array[packets_arp_queue.actual_size++] = entry;
}

struct arp_queue_entry create_arp_queue_entry(void *frame, int len, struct route_table_entry entry) {
	struct arp_queue_entry p;
	p.next_hoop = entry;
	p.packet = frame; // TODO MEMCPY
	p.packet_len = len;
	p.packet = malloc(MAX_PACKET_LEN);
	memcpy(p.packet, frame, len);
	return p;
}

void add_entry_arp(struct arp_entry entry) {
	// resize the table if the new size exceeds the array capacity
	if (arp_tbl.actual_size == arp_tbl.capacity - 2) {
		struct arp_entry *aux = realloc(arp_tbl.array, arp_tbl.capacity * 2);
		arp_tbl.capacity *= 2;
		DIE (!aux, "realloc failed\n");
		arp_tbl.array = aux;
	}
	arp_tbl.array[arp_tbl.actual_size++] = entry;
}

void generate_arp_request(uint32_t ip_dest, int interface) {
	char buf[MAX_PACKET_LEN];
	struct ether_header *eth_hdr = (struct ether_header*)buf;
	get_interface_mac(interface, eth_hdr->ether_shost);

	for (int i = 0; i < MAC_ADR_SIZE_BYTES; i++) {
		eth_hdr->ether_dhost[i] = 0xFF;
	}
	eth_hdr->ether_type = htons(ARP_TYPE);

	struct arp_header *arp_hdr = (struct arp_header*)(buf + sizeof(struct ether_header));
	arp_hdr->hlen = 6;
	
	arp_hdr->htype = 1;
	arp_hdr->htype = htons(arp_hdr->htype);
	
	arp_hdr->op = 1;
	arp_hdr->op = htons(arp_hdr->op);
	
	arp_hdr->plen = 4;

	arp_hdr->ptype = IP_TYPE;
	arp_hdr->ptype = htons(arp_hdr->ptype);

	get_interface_mac(interface, arp_hdr->sha);
	arp_hdr->spa = convert_ip_aton(get_interface_ip(interface));
	arp_hdr->tpa = ip_dest;
	
	for (int i = 0; i < MAC_ADR_SIZE_BYTES; i++)
		arp_hdr->tha[i] = 0;

	int len = sizeof(struct ether_header) + sizeof(struct arp_header);
	send_to_link(interface, buf, len);

}

struct arp_entry* find_mac_address_in_arp(uint32_t ip_address) {
	for (int i = 0; i < arp_tbl.actual_size; i++) {
		if (arp_tbl.array[i].ip == ip_address)
			return &arp_tbl.array[i];
	}
	return NULL;
}

void remove_arp_entry_from_queue(int index) {
	free(packets_arp_queue.array[index].packet);
	for (int i = index; i < packets_arp_queue.actual_size - 1; i++) {
		packets_arp_queue.array[i] = packets_arp_queue.array[i + 1]; 
	}
	packets_arp_queue.actual_size = packets_arp_queue.actual_size - 1;
}

void handle_arp_recv_reply(struct arp_header *arp_hdr) {
	struct arp_entry arp_entry;
	arp_entry.ip = arp_hdr->spa;
	memcpy(arp_entry.mac, arp_hdr->sha, MAC_ADR_SIZE_BYTES);
	add_entry_arp(arp_entry);
	// send the packets that were waiting for arp reply
	for (int i = 0; i < packets_arp_queue.actual_size; i++) {
		if (packets_arp_queue.array[i].next_hoop.next_hop == arp_hdr->spa) {

			add_eth_header_ip(packets_arp_queue.array[i].packet,
							packets_arp_queue.array[i].next_hoop.interface,
							arp_entry.mac);
			send_to_link(packets_arp_queue.array[i].next_hoop.interface,
						packets_arp_queue.array[i].packet,
						packets_arp_queue.array[i].packet_len);
			
			remove_arp_entry_from_queue(i);
			// given the fact that the entry on pos i was replaced by the next
			// we shall test for the next too
			i--; 
		}
	}
}

void handle_arp_recv_request(struct arp_header *arp_hdr_recv, int interface) {
	uint32_t my_ip = convert_ip_aton(get_interface_ip(interface)); 
	if (my_ip != arp_hdr_recv->tpa) {
		printf("[handle arp received request] not my ip\n");
		return; // sender wasn't looking for my ip
	}

	char my_message[MAX_PACKET_LEN];
	struct ether_header *eth_hdr = (struct ether_header*)my_message;
	
	get_interface_mac(interface, eth_hdr->ether_shost);
	memcpy(eth_hdr->ether_dhost, arp_hdr_recv->sha, MAC_ADR_SIZE_BYTES);

	eth_hdr->ether_type = htons(ARP_TYPE);

	struct arp_header *arp_hdr_send = (struct arp_header*)(my_message + sizeof(struct ether_header));
	arp_hdr_send->hlen = 6;
	arp_hdr_send->plen = 4;

	arp_hdr_send->op = htons(2);
	arp_hdr_send->ptype = htons(IP_TYPE);
	arp_hdr_send->htype = htons(1);

	arp_hdr_send->spa = my_ip;
	arp_hdr_send->tpa = arp_hdr_recv->spa;

	get_interface_mac(interface, arp_hdr_send->sha);
	memcpy(arp_hdr_send->tha, arp_hdr_recv->sha, MAC_ADR_SIZE_BYTES);
	
	send_to_link(interface, my_message, sizeof(struct ether_header) + sizeof(struct arp_header));
}

void handle_arp_packet(struct ether_header *ether_header, char *frame, int interface) {
	printf("Im in handle ARP packet\n");
	struct arp_header *arp_hdr = (struct arp_header*)(frame + sizeof(struct ether_header));
	if (arp_hdr->op == htons(1))
		handle_arp_recv_request(arp_hdr, interface);
	else
		handle_arp_recv_reply(arp_hdr);
}
