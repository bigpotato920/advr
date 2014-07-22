#ifndef HASHMAP_H
#define HASHMAP_H

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include "hashmap.h"
#include "log.h"

// We need to keep keys and values
typedef struct _hashmap_element{
	uint32_t key;
	void *value;
	struct _hashmap_element *next;
} hashmap_element;

// A hashmap has some maximum size and current size,
// as well as the data to hold.
typedef struct _hashmap_map{
	int bucket_size;
	int in_use;
	hashmap_element **bucket;
} hashmap;
/*
 * Return an empty hashmap, or NULL on failure.
 */
hashmap *hashmap_new(int bucket_size);
void *hashmap_search(hashmap *m, uint32_t key);
int hashmap_put(hashmap *m, uint32_t key, void *elem, int elem_size);
int hashmap_get(hashmap *m, uint32_t key, void *elem, int elem_size);
int hasmap_free(hashmap *m);

#endif