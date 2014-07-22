#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include "hashmap.h"
#include "log.h"

/*
 * Return an empty hashmap, or NULL on failure.
 */
hashmap *hashmap_new(int bucket_size) {
	hashmap* hm = (hashmap*) malloc(sizeof(hashmap));
	int i;
	if (hm == NULL) {
		log_err("Failed to create hasmap");
		return NULL;
	}

	hm->bucket_size = bucket_size;
	hm->in_use = 0;
	hm->bucket = (hashmap_element**)malloc(sizeof(hashmap_element*) * bucket_size);

	if (hm->bucket == NULL) {
		log_err("Failed to create bucket");
		free(hm);
		return NULL;
	}

	for (i = 0; i < bucket_size; i++)
		hm->bucket[i] = NULL;

	return hm;
}

/*
 * Hashing function for an integer
 */
unsigned int hashmap_hash_int(hashmap * m, uint32_t key){
	/* Robert Jenkins' 32 bit Mix Function */
	key += (key << 12);
	key ^= (key >> 22);
	key += (key << 4);
	key ^= (key >> 9);
	key += (key << 10);
	key ^= (key >> 2);
	key += (key << 7);
	key ^= (key >> 12);

	/* Knuth's Multiplicative Method */
	key = (key >> 3) * 2654435761;

	return key % m->bucket_size;
}

void *hashmap_search(hashmap *m, uint32_t key)
{
	unsigned int index = hashmap_hash_int(m, key);

	if (m->bucket[index] == NULL)
		return NULL;
	hashmap_element *he = m->bucket[index];
	while (he) {
		if (he->key == key) 
			return he;
		he = he->next;
	}

	return NULL;
}

int hashmap_put(hashmap *m, uint32_t key, void *elem, int elem_size)
{
	int index = hashmap_hash_int(m, key);
	hashmap_element *he = NULL;
	if ((he = (hashmap_element*)hashmap_search(m, key)) != NULL) {
		memcpy(he->value, elem, elem_size);
		return 0;
	}
	he = (hashmap_element*)malloc(sizeof(hashmap_element));
	if (he == NULL) {
		log_err("Failed to create hashmap_element");
		return -1;
	}
	he->key = key;
	he->value = malloc(elem_size);
	if (he->value == NULL) {
		log_err("Failed to create hashmap_element's value");
		free(he);
		return -1;
	}
	memcpy(he->value, elem, elem_size);
	he->next = m->bucket[index];
	m->bucket[index] = he;

	return 0;
}

int hashmap_get(hashmap *m, uint32_t key, void *elem, int elem_size)
{
	hashmap_element *he = NULL;
	if ((he = (hashmap_element*)hashmap_search(m, key)) != NULL) {
		memcpy(elem, he->value, elem_size);
		return 1;
	}

	return 0;
}

int hasmap_free(hashmap *m)
{
	int i;
	hashmap_element *he = NULL;
	for (i = 0; i < m->bucket_size; i++) {
		he = m->bucket[i];
		while (he) {
			hashmap_element *next = he->next;
			free(he->value);
			free(he);
			he = next;
		}
	}
	free(m->bucket);
	free(m);
	return 0;
}