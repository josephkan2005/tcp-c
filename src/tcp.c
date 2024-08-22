#include "tcp.h"
#include "header.h"
#include <stdint.h>
#include <stdio.h>

int tcp_connect() {
    printf("Connect");
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
