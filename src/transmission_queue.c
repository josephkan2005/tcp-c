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
    tq->send_times = malloc(sizeof(time_t) * cap);
    tq->syn = 0;
    tq->fin = 0;
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
    int limit = tq->head + len >= tq->cap ? tq->cap - tq->head : len;
    memcpy(buf, tq->data + tq->head, limit);
    if (limit < len) {
        memcpy(buf + limit, tq->data, len - limit);
    }
    return len;
}

int transmission_queue_times_front(transmission_queue *tq, time_t *buf,
                                   uint32_t len) {
    if (tq->size == 0) {
        return 0;
    }
    if (len > tq->size) {
        len = tq->size;
    }
    int limit = tq->head + len >= tq->cap ? tq->cap - tq->head : len;
    memcpy(buf, tq->send_times + tq->head, limit * sizeof(time_t));
    if (limit < len) {
        memcpy(buf + limit, tq->send_times, (len - limit) * sizeof(time_t));
    }
    return len;
}

int transmission_queue_push_back(transmission_queue *tq, uint8_t *buf,
                                 uint32_t len, time_t sent_at) {
    printf("Push sent at: %ld\n", sent_at);
    if (tq->size + len > tq->cap) {
        transmission_queue_realloc(tq);
    }
    int limit = ((tq->head + tq->size) % tq->cap) + len > (tq->cap - 1)
                    ? (tq->cap - 1) - (tq->head + tq->size)
                    : len;
    memcpy(tq->data + tq->head + tq->size, buf, limit);
    for (int i = 0; i < limit; i++) {
        tq->send_times[tq->head + tq->size + i] = sent_at;
    }
    if (limit < len) {
        memcpy(tq->data, buf + limit, len - limit);
        for (int i = 0; i < len - limit; i++) {
            tq->send_times[i] = sent_at;
        }
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

int transmission_queue_set_times(transmission_queue *tq, uint32_t len,
                                 time_t sent_at) {
    if (tq->size == 0) {
        return 0;
    }
    printf("Set sent at: %ld\n", sent_at);
    if (len > tq->size) {
        len = tq->size;
    }
    int limit = tq->head + len >= tq->cap ? tq->cap - len : len;
    for (int i = 0; i < limit; i++) {
        tq->send_times[tq->head + i] = sent_at;
    }
    if (limit < len) {
        for (int i = 0; i < len - limit; i++) {
            tq->send_times[i] = sent_at;
        }
    }
    return len;
}

int transmission_queue_realloc(transmission_queue *tq) {
    if (tq->data == NULL || tq->send_times == NULL) {
        printf("Cannot reallocate non-allocated tq\n");
        return 1;
    }
    uint32_t new_cap = 2 * tq->cap;
    uint8_t *new_tq_data = malloc(new_cap);
    time_t *new_tq_send_times = malloc(new_cap);
    transmission_queue_front(tq, new_tq_data, tq->size);
    transmission_queue_times_front(tq, new_tq_send_times, tq->size);
    tq->cap = new_cap;
    free(tq->data);
    free(tq->send_times);
    tq->data = new_tq_data;
    tq->send_times = new_tq_send_times;
    return 0;
}

int transmission_queue_destroy(transmission_queue *tq) {
    tq->size = 0;
    if (tq->data != NULL) {
        free(tq->data);
    }
    if (tq->send_times != NULL) {
        free(tq->send_times);
    }
    return 0;
}
