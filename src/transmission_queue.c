#include "transmission_queue.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int transmission_queue_create(transmission_queue *tq, uint32_t cap) {
    tq->size = 0;
    tq->data = malloc(cap);
    return 0;
}

int transmission_queue_front(transmission_queue *tq, uint8_t *buf,
                             uint32_t len) {
    if (len > tq->size) {
        len = tq->size;
    }
    memcpy(buf, tq->data + tq->head, len);
    return len;
}

int transmission_queue_push_back(transmission_queue *tq, uint8_t *buf,
                                 uint32_t len) {
    if (tq->size == 0) {
    }
    tq->tail += len;
    return 0;
}

int transmission_queue_pop_front(transmission_queue *tq, uint32_t len) {
    tq->head++;
    return 0;
}

int transmission_queue_realloc(transmission_queue *tq) {
    uint32_t new_cap = 2 * tq->cap;
    uint8_t *new_tq_data = malloc(new_cap);
    transmission_queue_front(tq, new_tq_data, tq->size);
    tq->cap = new_cap;
    free(tq->data);
    tq->data = new_tq_data;
    return 0;
}

int transmission_queue_destroy(transmission_queue *tq) {
    tq->size = 0;
    free(tq->data);
    return 0;
}
