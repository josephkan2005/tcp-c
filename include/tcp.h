#pragma once

#include <stdint.h>

enum tcp_states {
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

enum tcp_options {
    TCP_EOL = 0,
    TCP_NOOP = 1,
    TCP_MSS = 2,
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

int tcp_connect();

int tcp_write();

int tcp_read();

int tcp_disconnect();

int tcp_open(uint16_t port, uint32_t addr, uint8_t active);

int tcp_send();

int tcp_receive();

int tcp_close();

int tcp_abort();

int tcp_status();
