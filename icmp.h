#ifndef ICMP_H
#define ICMP_H
void handle_icmp(char *frame, int len_frame, uint8_t type, uint8_t code, int interface);

void icmp_echo_reply(char *og_payload, int len_pld, int interface, char *new_message);

void icmp_ttl_or_unrec(char *og_payload, int len_pld, int interface, uint8_t type, char *new_message);
#endif