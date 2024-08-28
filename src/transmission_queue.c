#include "transmission_queue.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int transmission_queue_create(transmission_queue *tq, uint32_t cap) {
    tq->size = 0;
    tq->head = 0;
    tq->head_seq = 0;
    tq->cap = cap;
    tq->data = malloc(cap);
    return 0;
}

int transmission_queue_front(transmission_queue *tq, uint8_t *buf,
                             uint32_t len) {
    if (tq->size == 0) {
        return 0;
    }
    if (len > tq->size) {
        len = tq->size;
    }
    int limit = tq->head + len >= tq->cap ? tq->cap - len : len;
    memcpy(tq->data + tq->head, buf, limit);
    if (limit < len) {
        memcpy(tq->data, buf + limit, len - limit);
    }
    return len;
}

int transmission_queue_push_back(transmission_queue *tq, uint8_t *buf,
                                 uint32_t len) {
    if (tq->size + len > tq->cap) {
        transmission_queue_realloc(tq);
    }
    int limit = ((tq->head + tq->size) % tq->cap) + len > (tq->cap - 1)
                    ? (tq->cap - 1) - (tq->head + tq->size)
                    : len;
    memcpy(tq->data + tq->head + tq->size, buf, limit);
    if (limit < len) {
        memcpy(tq->data, buf + limit, len - limit);
    }

    tq->size += len;

    return 0;
}

int transmission_queue_pop_front(transmission_queue *tq, uint32_t len) {
    if (len > tq->size) {
        printf("Trying to pop more than size: size: %u len: %u\n", tq->size,
               len);
        return 1;
    }
    tq->head += len;
    tq->head %= tq->cap;
    tq->head_seq += len;
    tq->size -= len;
    return 0;
}

int transmission_queue_realloc(transmission_queue *tq) {
    if (tq->data == NULL) {
        printf("Cannot reallocate non-allocated tq\n");
        return 1;
    }
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
    if (tq->data != NULL) {
        free(tq->data);
    }
    return 0;
}
