#include "include/lib.h"
#include "include/protocols.h"
#include "router.h"

#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>

#define MAC_ADR_SIZE_BYTES 6
#define IP_TYPE 0x0800
#define ARP_TYPE 0x0806


struct route_table_entry *rtable;
int rtable_len;

struct arp_entry *arp_table;
int arp_table_len;

// struct queue packets_arp_queue;
struct arp_table arp_tbl;

void init_arp_tables() {
	arp_tbl.capacity = 10;
	arp_tbl.array = (struct arp_entry*) malloc(sizeof(struct arp_entry) * 10);
	DIE (!arp_tbl.array, "arp table init failed\n");
}

void add_entry_arp(struct arp_entry entry) {
	// resize the table if the new size exceeds the array capacity
	if (arp_tbl.actual_size == arp_tbl.capacity - 2) {
		struct arp_entry *aux = (struct arp_entry*)realloc(arp_tbl.array, arp_tbl.capacity * 2);
		arp_tbl.capacity *= 2;
		DIE (!aux, "realloc failed\n");
		arp_tbl.array = aux;
	}
	arp_tbl.array[arp_tbl.actual_size++] = entry;
}


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

void handle_arp_packet(struct ether_header *ether_header, char *frame, int interface) {

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

void handle_icmp()
{
	
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

int update_ttl(struct iphdr *ip_hdr) {
	printf("TTL:%d\n", ip_hdr->ttl);
	if (ip_hdr->ttl == 0 || ip_hdr->ttl == 1) {
		// drop it and
		//time limit exceeded
		printf("handle ttl 0/1\n");
		handle_icmp();
		return -1;
	}
	ip_hdr->ttl = ip_hdr->ttl - 1;
	return 0;
}

void update_checksum(struct iphdr *ip_hdr) {
	ip_hdr->check = 0;
	ip_hdr->check = htons(checksum((uint16_t*)ip_hdr, sizeof(struct iphdr)));
}

struct arp_entry find_mac_address_in_arp(uint32_t ip_address) {
	// printf("IP ADDRESS i'm looking for:%0x\n", ip_address);
	for (int i = 0; i < arp_table_len; i++) {
		// printf("entry:%0x\n", arp_table[i].ip);
		if (arp_table[i].ip == ip_address)
			return arp_table[i];
	}
	struct arp_entry null;
	null.ip = 0;
	memset(null.mac, 0, MAC_ADR_SIZE_BYTES);
	return null;
}

void handle_ip_packet(struct ether_header *eth_hdr, char *frame, int len_frame, int interface) {
	printf("Im in handle ip packet\n");
	struct iphdr *ip_hdr = (struct iphdr *)(frame + sizeof(struct ether_header));

	// struct iphdr my_ip_hdr;
	// memcpy(&my_ip_hdr, ip_hdr, sizeof(struct iphdr));
	// reverse_ip_hdr_struct(&my_ip_hdr);

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
	if (am_i_destination_ip(interface, ip_hdr)) {
		printf("IP: the packet is for me: Echo reply\n");
		handle_icmp();
		return;
	}
	int rc = update_ttl(ip_hdr);
	if (rc)
		return; // the packet has been dropped and a reply has been sent

	struct route_table_entry next_hoop = find_next_hoop(ip_hdr->daddr);
	if (next_hoop.next_hop == (uint32_t)-1) {
		printf("destination unreachable\n");
		handle_icmp();
		return;
	}

	update_checksum(ip_hdr);
	struct arp_entry arp_dest = find_mac_address_in_arp(next_hoop.next_hop);

	// replace the data in old eth header
	eth_hdr->ether_type = htons(IP_TYPE);
	get_interface_mac(interface, eth_hdr->ether_shost);
	memcpy(eth_hdr->ether_dhost, arp_dest.mac, MAC_ADR_SIZE_BYTES);
	
	// send forward the packet
	printf("next_hoop mac address:");
	for (int i = 0; i < MAC_ADR_SIZE_BYTES; i++) {
		printf("%x:",  eth_hdr->ether_dhost[i]);
	}
	printf("\n");
	send_to_link(next_hoop.interface, frame, len_frame);
}

void init_rtable(char *pathname) {
	rtable = (struct route_table_entry*)malloc(sizeof(struct route_table_entry) * 100000);
	DIE(rtable == NULL, "malloc rtable failed\n");
	int rc = read_rtable(pathname, rtable);
	if (rc < 0) {
		printf("read rtable failed\n");
		DIE(rc < 0, "read rtable failed\n");
	}
	rtable_len = rc;
}

void init_arp_table() {
	arp_table = (struct arp_entry*)malloc(sizeof(struct arp_entry) * 100);
    char buffer[] = "arp_table.txt";
	arp_table_len = parse_arp_table(buffer, arp_table);
}

int main(int argc, char *argv[])
{
	setvbuf(stdout, NULL, _IONBF, 0);
	printf("hei mama\n"); 
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	init_rtable(argv[1]);
	init_arp_table();
	while (1) {
		printf("in the loop\n");
		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *) buf;
		convert_to_host_eth_header(eth_hdr);
		printf("I got eth header\n");
		if (am_i_destination_mac(eth_hdr, interface) == 0) {
			printf("its not for me apparently");
			continue; // drop the eth frame, it's not for me
		}

		printf("It's for me\n");
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
/*
	struct ether_header eth_hdr;
	char addr[] = "ABCDEF";
	memcpy(eth_hdr.ether_dhost, addr, 6);

	strcpy(addr, "MNPQST");
	memcpy(eth_hdr.ether_shost, addr, 6);
	eth_hdr.ether_type = 0x0800;

	convert_to_host_eth_header(&eth_hdr);
	for (int i = 0; i < MAC_ADR_SIZE_BYTES; i++) {
		char *p = (char*)(eth_hdr.ether_dhost + i);
		printf("%c", *p);
	}
	printf("\n");
	for (int i = 0; i < MAC_ADR_SIZE_BYTES; i++) {
		char *p = (char*)(eth_hdr.ether_shost + i);
		printf("%c", *p);
	}
	printf("\n");
	printf("%hd\n", eth_hdr.ether_type);
	return 0;

*/

	// struct in_addr addr;
	// addr.s_addr = 0x00000001;
	// char *bufir = inet_ntoa(addr);
	// printf("%s\n", bufir);
	// return 0;



		
	// uint8_t my_mac[6];
	// uint8_t dest[6];

	// for (int i = 0; i < MAC_ADR_SIZE_BYTES; i++) {
	// 	my_mac[i] = 'A' + i;
	// }
	// for (int i = 0; i < MAC_ADR_SIZE_BYTES; i++) {
	// 	dest[i] = 'A' + i;
	// }

	// printf("%d\n", am_i_destination_mac(my_mac, dest));
