#include <stdint.h>
#include <time.h>

typedef struct transmission_queue {
    uint32_t head;
    uint32_t head_seq;
    uint32_t cap;
    uint32_t size;
    uint8_t *data;
    time_t *send_times;
    uint8_t syn;
    uint8_t fin;

} transmission_queue;

int transmission_queue_create(transmission_queue *tq, uint32_t cap);

int transmission_queue_front(transmission_queue *tq, uint8_t *buf,
                             uint32_t len);

int transmission_queue_times_front(transmission_queue *tq, time_t *buf,
                                   uint32_t len);

int transmission_queue_push_back(transmission_queue *tq, uint8_t *buf,
                                 uint32_t len, time_t sent_at);

int transmission_queue_pop_front(transmission_queue *tq, uint32_t len);

int transmission_queue_set_times(transmission_queue *tq, uint32_t len,
                                 time_t sent_at);

int transmission_queue_realloc(transmission_queue *tq);

int transmission_queue_destroy(transmission_queue *tq);
