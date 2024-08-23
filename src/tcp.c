#include "tcp.h"
#include "header.h"
#include <stdint.h>
#include <stdio.h>
#include <sys/poll.h>
#include <unistd.h>

int tcp_connect(int *read_stream, int *write_stream) {
    printf("Connect");
    int input[2];
    int output[2];
    pipe(input);
    pipe(output);
    return 0;
}

int tcp_write() {
    printf("Write");
    return 0;
}

int tcp_read() {
    printf("Read");
    return 0;
}

int tcp_disconnect() {
    printf("Disconnect");
    return 0;
}

int tcp_open(uint16_t port, uint32_t addr, uint8_t active) {
    if (!active) {
        return -1;
    }
    return 0;
}

int tcp_send() {
    printf("Send");
    return 0;
}

int tcp_receive() {
    printf("Receive");
    return 0;
}

int tcp_close() {
    printf("Close");
    return 0;
}

int tcp_abort() {
    printf("Abort");
    return 0;
}

int tcp_status() {
    printf("Status");
    return 0;
}

int tcp_loop(tcp_connection *tcb) {
    int ready;
    while (1) {
        ready = poll(tcb->rw_pipes,
                     sizeof(tcb->rw_pipes) / sizeof(struct pollfd), 10);
        if (ready == -1) {
            printf("Poll errored");
            break;
        }
        tcb->state_func(tcb);
    }
    return 0;
}

int tcp_state_closed(tcp_connection *tcb) {
    printf("Closed state");
    tcb->state = TCP_SYN_SENT;
    tcb->state_func = tcp_state_syn_sent;

    return 0;
}

int tcp_state_syn_sent(tcp_connection *tcb) {
    printf("Syn sent state");

    return 0;
}

int tcp_state_established(tcp_connection *tcb) {
    printf("Established state");

    return 0;
}
