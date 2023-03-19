#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include "router.h"

#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>

#define MAC_ADR_SIZE_BYTES 6
#define ETH_TYPE_IP 0x8000
#define ARP_TYPE 0x0806

struct route_table_entry *rtable;
FILE *loging;

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

char* get_destination_ip_ascii(struct iphdr *ip_hdr) {
	struct in_addr addr;
	addr.s_addr = ip_hdr->daddr;
	return inet_ntoa(addr);
}

int	am_i_destination_ip(int interface, char *destination_ip) {
	char *interface_ip = get_interface_ip(interface);
	if (strcmp(interface_ip, destination_ip) == 0)
		return 1;
	return 0; 	
}

void handle_icmp()
{
	
}

void handle_ip_packet(struct ether_header *eth_hdr, char *frame, int interface) {
	printf("Im in handle ip packet\n");
	struct iphdr *ip_hdr = (struct iphdr *)(frame + sizeof(struct ether_header));

	struct iphdr my_ip_hdr;
	memcpy(&my_ip_hdr, ip_hdr, sizeof(struct iphdr));
	// reverse_ip_hdr_struct(&my_ip_hdr);

	uint16_t received_check = my_ip_hdr.check;
	received_check = ntohs(received_check);
	my_ip_hdr.check = 0;

	uint16_t new_check = checksum((uint16_t*)&my_ip_hdr, sizeof(struct iphdr));

	if (received_check != new_check) {
		// drop the packet
		// TODO send ICMP reply
		printf("checksum BAD\n");
		return;
	}
	printf("checksum GOOD\n");
	char *destination_ip_ascii = get_destination_ip_ascii(&my_ip_hdr);
	if (am_i_destination_ip(interface, destination_ip_ascii)) {
		printf("IP: the packet is for me\n");
		handle_icmp();
		return;
	}
}

void init_rtable(char *pathname) {
	rtable = malloc(sizeof(struct route_table_entry) * 100000);
	DIE(rtable == NULL, "malloc rtable failed\n");
	int rc = read_rtable(pathname, rtable);
	if (rc < 0) {
		fprintf(loging, "read rtable failed\n");
		DIE(rc < 0, "read rtable failed\n");
	}
}

int main(int argc, char *argv[])
{
	setvbuf(stdout, NULL, _IONBF, 0);
	printf("hei mama\n"); 
	loging = fopen("log.txt", "a");
	fprintf(loging, "skr\n");
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	init_rtable(argv[1]);
	
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
			handle_ip_packet(eth_hdr, buf, interface);
	
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
