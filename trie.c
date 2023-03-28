#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <arpa/inet.h>

#include "include/lib.h"

// Alphabet size (# of symbols)
#define ALPHABET_SIZE (3)

struct route_table_entry *rtable;
int rtable_len;

struct TrieNode
{
    struct TrieNode *children[ALPHABET_SIZE];
 
    // isEndOfWord is true if the node represents
    // end of a word
    struct route_table_entry *payload;
    bool isEndOfWord;
};
 
// Returns new trie node (initialized to NULLs)
struct TrieNode *getNode(void)
{
    struct TrieNode *pNode = NULL;
 
    pNode = (struct TrieNode *)malloc(sizeof(struct TrieNode));
 
    if (pNode)
    {
        int i;
 
        pNode->isEndOfWord = false;
		pNode->payload = NULL;
 
        for (i = 0; i < ALPHABET_SIZE; i++)
            pNode->children[i] = NULL;
    }
 
    return pNode;
}
struct TrieNode *trie_root; 

// If not present, inserts key into trie
// If the key is prefix of trie node, just marks leaf node
char aux[20];
void replace_dot_with_smth(char *ip) {
	memcpy(aux, ip, strlen(ip) + 1);
	for (int i = 0; i < strlen(aux); i++) {
		if (aux[i] == '.')
			aux[i] = 58;
	}
}
void insert(struct route_table_entry *trie_entry)
{
    uint32_t index;
	uint32_t key = trie_entry->prefix;
	uint32_t mask = ntohl(trie_entry->mask);
    struct TrieNode *pCrawl = trie_root;
	char one = 0x80;

	for (int i = 0; i < 4 && mask != 0; i++)
	{
		char aux = *((char*)&key + i);  
		for (int i = 0; i < 8 && mask != 0; i++) {
			index = aux & one;
			if (index != 0)
				index = 1;

			if (!pCrawl->children[index])
            pCrawl->children[index] = getNode();
 
        	pCrawl = pCrawl->children[index];

			aux = aux << 1;	
			mask = mask << 1;

		}
	}

	pCrawl->payload = trie_entry;
    pCrawl->isEndOfWord = true;
}
// Returns true if key presents in trie, else false
struct route_table_entry* search_next_hoop(uint32_t ip_dest)
{
    uint32_t index = 2;
    struct TrieNode *pCrawl = trie_root;
	
	struct route_table_entry *next_hoop = NULL;
	uint32_t ip = ip_dest;
	char one = 0x80;

	for (int i = 0; i < 4; i++)
	{
		char aux = *((char*)&ip + i);  
		for (int i = 0; i < 8; i++) {
			if (pCrawl->isEndOfWord == true) {
				next_hoop = pCrawl->payload;
			}
			index = aux & one;
			if (index != 0)
				index = 1;
			printf("%d", index);

			if (!pCrawl->children[index]) {
				printf("cant go nowhere\n");
				return next_hoop;
			}
			aux = aux << 1;
        	pCrawl = pCrawl->children[index];
		}
	}

    return next_hoop;
}

void init_rtable_trie(char *pathname) {
	rtable = malloc(sizeof(struct route_table_entry) * 100000);
	DIE(rtable == NULL, "malloc rtable failed\n");
	int rc = read_rtable(pathname, rtable);
	DIE(rc < 0, "read rtable failed\n");
	rtable_len = rc;

	trie_root = getNode();
	printf("before inserting in trie\n");
	for (int i = 0; i < rtable_len; i++) {
		insert(&rtable[i]);
	}
	printf("after inserting in trie\n");
}