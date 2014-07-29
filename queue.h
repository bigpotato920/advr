#ifndef QUEUE_H
#define QUEUE_H

#include <pthread.h>

#define MAX_FILENAME_LEN 255
/**
 * Queue entry
 */
typedef struct queue_entry
{

	//subsequent node
	struct queue_entry* next;
	//value
	char value[MAX_FILENAME_LEN];

} queue_entry;


/**
 * Queue
 */

typedef struct
{
	//head of the queue
	queue_entry* head;

	//tail of the queue
	queue_entry* tail;

	// mutex lock
	pthread_mutex_t h_lock;
	pthread_mutex_t t_lock;
} queue;

/* Prototypes */
queue* queue_create(void);
void queue_release(queue* queue);

int en_queue(queue* queue, char* value);
int de_queue(queue*queue, char* value);

#endif