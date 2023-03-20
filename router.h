void init_rtable();

struct arp_table {
    struct arp_entry *array;
    int capacity;
    int actual_size;
};

struct arp_queue_entry {
    void *packet;
    struct route_table_entry next_hoop;
};

struct arp_queue {
    struct arp_queue_entry* array;
    int actual_size;
    int capacity;
};