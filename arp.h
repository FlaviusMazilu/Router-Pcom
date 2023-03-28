#ifndef ARP_H
#define ARP_H
void init_arp_queue();

void init_arp_table();

void arp_enq(struct arp_queue_entry entry);

struct arp_queue_entry create_arp_queue_entry(void *frame, int len, struct route_table_entry entry);

void add_entry_arp(struct arp_entry entry);

void generate_arp_request(uint32_t ip_dest, int interface);

struct arp_entry* find_mac_address_in_arp(uint32_t ip_address);

void remove_arp_entry_from_queue(int index);

void handle_arp_recv_reply(struct arp_header *arp_hdr);

void handle_arp_recv_request(struct arp_header *arp_hdr_recv, int interface);

void handle_arp_packet(struct ether_header *ether_header, char *frame, int interface);
#endif
