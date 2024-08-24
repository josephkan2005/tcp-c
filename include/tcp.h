#pragma once

#include "header.h"
#include <stdint.h>
#include <sys/poll.h>

#define TCP_FD_DEV 0
#define TCP_FD_TIMER 1
#define TCP_FD_READ 2
#define TCP_FD_WRITE 3

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

typedef struct tcp_snd {
    uint32_t una;
    uint32_t nxt;
    uint32_t wnd;
    uint32_t up;
    uint32_t wl1;
    uint32_t wl2;
    uint32_t iss;
} tcp_snd;

typedef struct tcp_rcv {
    uint32_t nxt;
    uint32_t wnd;
    uint32_t up;
    uint32_t irs;
} tcp_rcv;

typedef struct endpoint {
    uint32_t addr;
    uint16_t port;
} endpoint;

typedef struct tcp_connection {
    enum tcp_state state;
    tcp_snd snd;
    tcp_rcv rcv;
    int (*state_func)(struct tcp_connection *);

    struct pollfd rw_pipes[4];

    endpoint src;
    endpoint dest;
} tcp_connection;

int tcp_connect(int *read_stream, int *write_stream);

int tcp_write();

int tcp_read();

int tcp_disconnect();

int tcp_open(uint16_t port, uint32_t addr, uint8_t active);

int tcp_send();

int tcp_receive();

int tcp_close();

int tcp_abort();

int tcp_status();

int tcp_state_closed(tcp_connection *tcb);
int tcp_state_syn_sent(tcp_connection *tcb);
int tcp_state_established(tcp_connection *tcb);
