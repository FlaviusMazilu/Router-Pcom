#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include "router.h"
#include "arp.h"

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

struct route_table_entry *rtable;
int rtable_len;

// struct arp_entry *arp_table;
// int arp_table_len;
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
	
	//TODO modify to different endianess
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

void reverse_ip_hdr_struct(struct iphdr *ip_hdr) {
	ip_hdr->check = ntohs(ip_hdr->check);
	ip_hdr->daddr = ntohl(ip_hdr->daddr);
	ip_hdr->saddr = ntohl(ip_hdr->saddr);
	ip_hdr->frag_off = ntohs(ip_hdr->frag_off);
	ip_hdr->id = ntohs(ip_hdr->id);
	ip_hdr->tot_len = ntohs(ip_hdr->tot_len);
}

int	am_i_destination_ip(int interface, struct iphdr *ip_hdr) {

	struct in_addr addr;
	addr.s_addr = ip_hdr->daddr;
	char destination_ip[30];
	strcpy(destination_ip, inet_ntoa(addr));

	char *interface_ip = get_interface_ip(interface);
	printf("interface_ip: %s\n", interface_ip);
	printf("destination ip: %s\n", destination_ip);
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


struct route_table_entry find_next_hoop(uint32_t destination_ip) {
	// both are in network order
	// printf("mask off = %0x\n", rtable[0].mask);
	// printf("destination = %0x\n", destination_ip);

	struct route_table_entry next_hoop;
	next_hoop.next_hop = -1;
	uint32_t max_mask = 0;
	for (int i = 0; i < rtable_len; i++) {
		if ((destination_ip & rtable[i].mask) == rtable[i].prefix) {

			if (rtable[i].mask > max_mask) {
				max_mask = rtable[i].mask;
				next_hoop = rtable[i];
			}
		}
	}

	struct in_addr addr;
	addr.s_addr = next_hoop.next_hop;
	printf("NEXT_HOOP: %s %0x\n", inet_ntoa(addr), next_hoop.mask);

	return next_hoop;
}
#define TTL_TYPE 11
#define HOST_UNREC_TYPE 3

int update_ttl(char *frame, int len_frame, int interface) {
	struct iphdr *ip_hdr = (struct iphdr*)(frame + SZ_ETH_HDR);
	printf("TTL:%d\n", ip_hdr->ttl);
	if (ip_hdr->ttl == 0 || ip_hdr->ttl == 1) {
		//time limit exceeded
		printf("handle ttl 0/1\n");
		handle_icmp(frame, len_frame, TTL_TYPE, 0, interface);
		// icmp_ttl_or_unrec(og_payload, interface, ip_hdr->saddr, eth_hdr->ether_shost, TTL_TYPE);
		return -1;
	}
	ip_hdr->ttl = ip_hdr->ttl - 1;
	return 0;
}

void update_checksum(struct iphdr *ip_hdr) {
	ip_hdr->check = 0;
	ip_hdr->check = htons(checksum((uint16_t*)ip_hdr, sizeof(struct iphdr)));
}

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

void handle_ip_packet(struct ether_header *eth_hdr, char *frame, int len_frame, int interface) {
	printf("Im in handle ip packet\n");
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

	struct route_table_entry next_hoop = find_next_hoop(ip_hdr->daddr);
	if (next_hoop.next_hop == (uint32_t)-1) {
		printf("destination unreachable\n");
		handle_icmp(frame, len_frame, HOST_UNREC_TYPE, 0, interface);
		return;
	}

	update_checksum(ip_hdr);
	printf("[HANDLE IP PACKET] find mac address in arp\n");
	struct arp_entry *arp_dest = find_mac_address_in_arp(next_hoop.next_hop);
	if (arp_dest == NULL) {
		// it means there's no entry in the arp table for the ip to send to

		struct arp_queue_entry entry = create_arp_queue_entry(frame, len_frame, next_hoop);
		arp_enq(entry);

		printf("[HANDLE IP PACKET] generate arp request\n");
		generate_arp_request(next_hoop.next_hop, next_hoop.interface);
		return;
	}

	// replace the data in old eth header
	eth_hdr->ether_type = htons(IP_TYPE);
	get_interface_mac(interface, eth_hdr->ether_shost);
	memcpy(eth_hdr->ether_dhost, arp_dest->mac, MAC_ADR_SIZE_BYTES);
	
	// send forward the packet
	send_to_link(next_hoop.interface, frame, len_frame);
}

void init_rtable(char *pathname) {
	rtable = malloc(sizeof(struct route_table_entry) * 100000);
	DIE(rtable == NULL, "malloc rtable failed\n");
	int rc = read_rtable(pathname, rtable);
	DIE(rc < 0, "read rtable failed\n");
	rtable_len = rc;
}

int main(int argc, char *argv[])
{
	setvbuf(stdout, NULL, _IONBF, 0);
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	init_rtable(argv[1]);
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
