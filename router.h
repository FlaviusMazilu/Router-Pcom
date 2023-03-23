void init_rtable();
uint32_t convert_ip_aton(char *ascii_address);
void icmp_echo_reply(char *og_payload, int len_pld, int interface, char *new_message);
void icmp_ttl_or_unrec(char *og_payload, int len_pld, int interface, uint8_t type, char *new_message);
void handle_icmp(char *frame, int len_frame, uint8_t type, uint8_t code, int interface);


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