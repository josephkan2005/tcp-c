#pragma once
#include <stdint.h>

#define TCP_FLAG_FIN 0x01
#define TCP_FLAG_SYN 0x02
#define TCP_FLAG_RST 0x04
#define TCP_FLAG_PSH 0x08
#define TCP_FLAG_ACK 0x10
#define TCP_FLAG_URG 0x20

#define TCP_HEADER_SIZE 20

#define IP_PROTO_TCP 6
#define IP_HEADER_SIZE 20

enum tcp_option_kind {
    TCP_EOL = 0,
    TCP_NOOP = 1,
    TCP_MSS = 2,
};

typedef struct tcp_option {
    enum tcp_option_kind kind;
    uint8_t len;
    uint8_t data[];
} tcp_option;

typedef struct tcp_header {
    uint16_t src_port;
    uint16_t dest_port;

    uint32_t seq;
    uint32_t seq_ack;

    uint8_t res : 4;
    uint8_t doff : 4;
    uint8_t flags;

    uint16_t wnd;

    uint16_t check;
    uint16_t urg_ptr;

    uint8_t opts[];

} __attribute__((packed)) tcp_header;

typedef struct tcp_ip_header {
    uint32_t src_addr;
    uint32_t dest_addr;
    uint8_t zero;
    uint8_t protocol;
    uint8_t tcp_len;
} __attribute__((packed)) tcp_ip_header;

typedef struct ip_header {
    uint8_t ihl : 4;
    uint8_t ver : 4;
    uint8_t tos;
    uint16_t len;
    uint16_t id;
    uint16_t frag;
    uint8_t ttl;
    uint8_t proto;
    uint16_t check;
    uint32_t src_addr;
    uint32_t dest_addr;
} __attribute__((packed)) ip_header;

tcp_header create_tcp_header(uint16_t src_port, uint16_t dest_port);

int to_tcp_header(tcp_header *header, uint8_t *buffer);

int from_tcp_header(tcp_header *header, uint8_t *buffer);

int tcp_read_options(tcp_header *header, uint8_t *buffer);

int tcp_write_options(tcp_header *header, uint8_t *buffer);

ip_header create_ip_header(uint32_t src_addr, uint32_t dest_addr,
                           uint16_t data_len);

int to_ip_header(ip_header *header, uint8_t *buffer);

int from_ip_header(ip_header *header, uint8_t *buffer);

uint16_t checksum(uint16_t *payload, uint32_t count, uint32_t start);

int tcp_checksum(tcp_ip_header *iph, tcp_header *tcph, uint8_t *payload);

int ip_checksum(ip_header *iph);