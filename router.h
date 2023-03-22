void init_rtable();
uint32_t convert_ip_aton(char *ascii_address);
void icmp_ttl_or_unrec(char *og_payload, int interface, uint32_t ip_dest, uint8_t *mac_dest, uint8_t type);

struct arp_table {
    struct arp_entry *array;
    int capacity;
    int actual_size;
};

struct arp_queue_entry {
    void *packet;
    int packet_len;
    struct route_table_entry next_hoop;
};

struct arp_queue {
    struct arp_queue_entry* array;
    int actual_size;
    int capacity;
};