#include "transmission_queue.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int transmission_queue_create(transmission_queue *dq, uint32_t cap) {
    dq->size = 0;
    dq->data = malloc(cap);
    return 0;
}

int transmission_queue_front(transmission_queue *dq, uint8_t *buf,
                             uint32_t len) {
    if (len > dq->size) {
        len = dq->size;
    }
    memcpy(buf, dq->data + dq->head, len);
    return len;
}

int transmission_queue_push_back(transmission_queue *dq, uint8_t *buf,
                                 uint32_t seq, uint32_t len) {
    if (dq->size == 0) {
    }
    dq->tail += len;
    return 0;
}

int transmission_queue_pop_front(transmission_queue *dq, uint32_t seq,
                                 uint32_t len) {
    dq->head++;
    return 0;
}

int transmission_queue_realloc(transmission_queue *dq) {
    uint32_t new_cap = 2 * dq->cap;
    uint8_t *new_dq_data = malloc(new_cap);
    transmission_queue_front(dq, new_dq_data, dq->size);
    dq->cap = new_cap;
    free(dq->data);
    dq->data = new_dq_data;
    return 0;
}

int transmission_queue_destroy(transmission_queue *dq) {
    dq->size = 0;
    free(dq->data);
    return 0;
}
