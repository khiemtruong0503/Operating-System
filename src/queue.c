#include <stdio.h>
#include <stdlib.h>
#include "queue.h"

int empty(struct queue_t * q) {
	return (q->size == 0);
}

void enqueue(struct queue_t * q, struct pcb_t * proc) {
	/* TODO: put a new process to queue [q] */	
	if (q->size == MAX_QUEUE_SIZE) {
		printf("Queue is full!\n");
	}
	else if(empty(q) == 1) {
		q->proc[0] = proc;
		q->size++;
	}
	else {
		for(int i = q->size - 1; i >= 0; i--) {
			if(q->proc[i]->priority <= proc->priority) {
				q->proc[i + 1] = proc;
				q->size++;
				return;
			}
			else {
				q->proc[i + 1] = q->proc[i];
			}
			if(i == 0) {
				q->proc[0] = proc;
				q->size++;
			}
		}
	}
	return;
}

struct pcb_t * dequeue(struct queue_t * q) {
	/* TODO: return a pcb whose prioprity is the highest
	 * in the queue [q] and remember to remove it from q
	 * */
	if(q->size == 0) return NULL;
	else if(q->size < MAX_QUEUE_SIZE) {
		struct pcb_t *tmp = q->proc[0];
		for(int i = 0; i < q->size - 1; i++) {
			q->proc[i] = q->proc[i + 1];
		}
		q->size--;
		q->proc[q->size] = NULL;
		return tmp;
	}
	else {
		// overflow - never happen
		return NULL;
	}
}

