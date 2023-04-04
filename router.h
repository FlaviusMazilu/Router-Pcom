#ifndef ROUTER_H
#define ROUTER_H

#define MAC_ADR_SIZE_BYTES 6
#define IP_TYPE 0x0800
#define ARP_TYPE 0x0806
#define OG_PAYLOAD_SIZE 8
#define SZ_ETH_HDR (sizeof(struct ether_header))
#define SZ_IP_HDR (sizeof(struct iphdr))
#define SZ_ICMP_HDR 8
#define TTL_TYPE 11
#define HOST_UNREC_TYPE 3

void init_rtable();
uint32_t convert_ip_aton(char *ascii_address);
void add_eth_header_ip(char *frame, int interface_source, uint8_t *mac_dest);

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
#endif