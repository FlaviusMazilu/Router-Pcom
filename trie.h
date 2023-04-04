#ifndef TRIE_H
#define TRIE_H
#include <stdbool.h>

#define ALPHABET_SIZE (3)

struct TrieNode
{
    struct TrieNode *children[ALPHABET_SIZE];
 
    // isEndOfWord is true if the node represents
    // end of a word
    struct route_table_entry *payload;
    bool isEndOfWord;
};
 

void insert(struct route_table_entry *trie_entry);

struct route_table_entry* search_next_hoop(uint32_t ip_dest);

void init_rtable_trie(char *pathname);
#endif