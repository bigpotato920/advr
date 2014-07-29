#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "queue.h"

queue* queue_create(void) {
	queue* m_queue;
	queue_entry* dummy;
	
	if ((m_queue = (queue*)malloc(sizeof(queue))) == NULL) {
		return NULL;
	}
	if ((dummy =(queue_entry*)malloc(sizeof(queue_create()))) == NULL) {
		free(m_queue);
		return NULL;
	}
	dummy->next = NULL;
	m_queue->head = m_queue->tail = dummy;

	if (pthread_mutex_init(&m_queue->h_lock, NULL) != 0) {
		free(m_queue);
		free(dummy);
		return NULL;
	}
	if (pthread_mutex_init(&m_queue->t_lock, NULL) != 0) {
		free(m_queue);
		free(dummy);
		return NULL;
	}
	return m_queue;
}	

int en_queue(queue* queue, char* value){
	//printf("enqueue\n");
	
	queue_entry* entry;
	int len = strlen(value);
	if ((entry = malloc(sizeof(queue_entry))) == NULL) {
		perror("malloc");
		return -1;
	}
	strncpy(entry->value, value, len);
	entry->value[len] = '\0';
	entry->next = NULL;
	pthread_mutex_lock(&queue->t_lock);
	queue->tail->next = entry;
	queue->tail = entry;
	pthread_mutex_unlock(&queue->t_lock);

	return 1;
}

int de_queue(queue *queue, char* value) {
	
	queue_entry* new_head;
	queue_entry* entry;
	int len = 0;

	pthread_mutex_lock(&queue->h_lock);
	entry = queue->head;
	new_head = entry->next;

	if (new_head == NULL) {
		pthread_mutex_unlock(&queue->h_lock);
		return 0;
	}

	len = strlen(new_head->value);
	strncpy(value, new_head->value, len);
	value[len] = '\0';
	queue->head = new_head;

	pthread_mutex_unlock(&queue->h_lock);
	printf("dequeue\n");
	free(entry);
	
	return 1;
}

void queue_release(queue* queue) {
	queue_entry* tmp = queue->head;
	while (queue->head) {
		tmp = queue->head->next;
		free(queue->head);
		queue->head = tmp;
	}
	free(queue);
}


