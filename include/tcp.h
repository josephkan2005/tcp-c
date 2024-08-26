#pragma once

#include "header.h"
#include <stdint.h>
#include <sys/poll.h>

#define TCP_FD_DEV 0
#define TCP_FD_TIMER 1
#define TCP_FD_READ 2
#define MAX_BUF_SIZE 4096

enum tcp_state {
    TCP_LISTEN,
    TCP_SYN_SENT,
    TCP_SYN_RECEIVED,
    TCP_ESTABLISHED,
    TCP_FIN_WAIT_1,
    TCP_FIN_WAIT_2,
    TCP_CLOSE_WAIT,
    TCP_CLOSING,
    TCP_LAST_ACK,
    TCP_TIME_WAIT,
    TCP_CLOSED,
};

enum tcp_event_type {
    TCP_EVENT_OPEN = 0,
    TCP_EVENT_SEND = 1,
    TCP_EVENT_RECEIVE = 2,
    TCP_EVENT_CLOSE = 3,
    TCP_EVENT_ABORT = 4,
    TCP_EVENT_STATUS = 5,

    TCP_EVENT_SEGMENT_ARRIVES = 6,

    TCP_EVENT_USER_TIMEOUT = 7,
    TCP_EVENT_RETRANSMISSION_TIMEOUT = 8,
    TCP_EVENT_TIME_WAIT_TIMEOUT = 9
};

typedef struct tcp_event {
    enum tcp_event_type type;
    uint16_t len;
    uint8_t data[];
} tcp_event;

typedef struct tcp_tcb_snd {
    uint32_t una;
    uint32_t nxt;
    uint32_t wnd;
    uint32_t up;
    uint32_t wl1;
    uint32_t wl2;
    uint32_t iss;
} tcp_tcb_snd;

typedef struct tcp_tcb_rcv {
    uint32_t nxt;
    uint32_t wnd;
    uint32_t up;
    uint32_t irs;
} tcp_tcb_rcv;

typedef struct endpoint {
    uint32_t addr;
    uint16_t port;
} endpoint;

typedef struct tcp_connection {
    enum tcp_state state;
    tcp_tcb_snd snd;
    tcp_tcb_rcv rcv;
    int (*state_func)(struct tcp_connection *, tcp_event *);

    struct pollfd in_r_fds[3];
    int in_w_fds[3];
    struct pollfd ex_r_fds[1];
    int ex_w_fds[1];

    endpoint src;
    endpoint dest;
} tcp_connection;

endpoint create_endpoint(uint32_t addr, uint16_t port);

int tcp_connect(tcp_connection *connection, endpoint src, endpoint dest,
                int tun_fd);

int tcp_write(tcp_connection *connection, uint8_t *buf, int len);

int tcp_read(tcp_connection *connection, uint8_t *buf, int len);

int tcp_disconnect(tcp_connection *connection);

int tcp_open(uint16_t port, uint32_t addr, uint8_t active);

int tcp_send();

int tcp_receive();

int tcp_close();

int tcp_abort();

int tcp_status();

int tcp_create_connection(tcp_connection *connection, int dev_fd, endpoint src,
                          endpoint dest);

int tcp_create_tcb(tcp_tcb_snd *snd, tcp_tcb_rcv *rcv);

int tcp_loop(tcp_connection *connection);

int tcp_check_acceptability(tcp_connection *connection, tcp_header *tcph,
                            uint16_t payload_len);

int tcp_state_closed(tcp_connection *connection);
int tcp_state_syn_received(tcp_connection *connection, tcp_event *event);
int tcp_state_syn_sent(tcp_connection *connection, tcp_event *event);
int tcp_state_established(tcp_connection *connection, tcp_event *event);
int tcp_state_close_wait(tcp_connection *connection, tcp_event *event);
