#ifndef UTILS_H
#define UTILS_H
void reverse_bytes(uint8_t *data_in, int size);

void convert_to_host_eth_header(struct ether_header *eth_hdr);

int am_i_destination_mac(struct ether_header *eth_hdr, int interface);

void add_eth_header_ip(char *frame, int interface_source, uint8_t *mac_dest);

int	am_i_destination_ip(int interface, struct iphdr *ip_hdr);

uint32_t convert_ip_aton(char *ascii_address);

int update_ttl(char *frame, int len_frame, int interface);

void update_checksum(struct iphdr *ip_hdr);
#endif
