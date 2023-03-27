void init_arp_queue();
void init_arp_table();
void arp_enq(struct arp_queue_entry entry);
struct arp_queue_entry create_arp_queue_entry(void *frame, int len, struct route_table_entry entry);
void add_entry_arp(struct arp_entry entry);
void generate_arp_request(uint32_t ip_dest, int interface);
struct arp_entry* find_mac_address_in_arp(uint32_t ip_address);
