#include "header.h"
#include "tcp.h"

void print_tcp_header(tcp_header *tcph);

void print_ip_header(ip_header *iph);

void print_tcp_ip_header(tcp_ip_header *piph);

void print_tcp_tcb(tcp_tcb_snd *snd, tcp_tcb_rcv *rcv);

void print_tq(transmission_queue *tq);

void print_tcp_event_type(enum tcp_event_type type);

void print_hex(uint8_t *buf, int count);
