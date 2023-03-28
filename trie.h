void insert(struct route_table_entry *trie_entry);
struct route_table_entry* search(uint32_t ip_dest);
void init_rtable_trie(char *pathname);