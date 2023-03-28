#ifndef TRIE_H
#define TRIE_H
void insert(struct route_table_entry *trie_entry);

struct route_table_entry* search_next_hoop(uint32_t ip_dest);

void init_rtable_trie(char *pathname);
#endif