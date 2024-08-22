#pragma once
#include <stdbool.h>
#include <stdint.h>

#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PSH 0x08
#define TCP_ACK 0x10
#define TCP_URG 0x20

typedef struct tcp_header {
    uint32_t src_port;
    uint16_t dest_port;

    uint32_t seq;
    uint32_t seq_ack;

    uint8_t doff : 4;
    uint8_t res : 6;

    // Flags
    uint8_t urg : 1, ack : 1, psh : 1, rst : 1, syn : 1, fin : 1;

    uint16_t wnd;

    uint16_t check;
    uint16_t urg_ptr;

    char opts[];

} __attribute__((packed)) tcp_header;

typedef struct tcp_ip_header {
    uint32_t src_addr;
    uint32_t dest_addr;
    uint8_t zero;
    uint8_t protocol;
    uint8_t tcp_len;
} __attribute__((packed)) tcp_ip_header;

int to_tcp_header(tcp_header *header, uint8_t *buffer);

int calculate_checksum(tcp_ip_header *iph, tcp_header *tcph, uint8_t *payload);

int from_tcp_header(tcp_header *header, uint8_t *buffer);
