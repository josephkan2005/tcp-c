#include "tcp.h"
#include "header.h"
#include "utils.h"
#include <fcntl.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/poll.h>
#include <unistd.h>

endpoint create_endpoint(uint32_t addr, uint16_t port) {
    endpoint e;
    e.addr = addr;
    e.port = port;
    return e;
}

int tcp_connect(tcp_connection *connection, endpoint src, endpoint dest,
                int tun_fd) {
    printf("Connect\n");
    tcp_create_connection(connection, tun_fd, src, dest);
    tcp_state_closed(connection);

    pthread_t main_loop;
    int ret;

    ret = pthread_create(&main_loop, NULL, (void *)tcp_loop, connection);
    return 0;
}

int tcp_write(tcp_connection *connection, uint8_t *buf, int len) {
    if (connection->state == TCP_CLOSED)
        return -1;
    printf("Write\n");
    int fd = connection->ex_w_fds[0];
    int res = write(fd, buf, len);
    if (res < 0) {
        printf("Write failed\n");
        return -1;
    }

    return 0;
}

int tcp_read(tcp_connection *connection, uint8_t *buf, int nbytes) {
    if (connection->state == TCP_CLOSED)
        return -1;
    printf("Read\n");
    int ready = poll(connection->ex_r_fds, 1, -1);
    if (ready == -1) {
        printf("Poll timed out");
        return -1;
    }

    int num_read = read(connection->ex_r_fds[0].fd, buf, nbytes);

    return num_read;
}

int tcp_disconnect(tcp_connection *connection) {
    printf("Disconnect\n");
    return 0;
}

int tcp_open(uint16_t port, uint32_t addr, uint8_t active) {
    if (!active) {
        return -1;
    }
    return 0;
}

int tcp_send() {
    printf("Send\n");
    return 0;
}

int tcp_receive() {
    printf("Receive\n");
    return 0;
}

int tcp_close() {
    printf("Close\n");
    return 0;
}

int tcp_abort() {
    printf("Abort\n");
    return 0;
}

int tcp_status() {
    printf("Status\n");
    return 0;
}

int parse_event(tcp_connection *connection, tcp_event *event) {
    int fd_idx = -1;
    int num_fd = sizeof(connection->in_r_fds) / sizeof(struct pollfd);
    for (int i = 0; i < num_fd; i++) {
        if (connection->in_r_fds[i].revents & POLLIN) {
            fd_idx = i;
            break;
        }
    }

    int fd = connection->in_r_fds[fd_idx].fd;

    switch (fd_idx) {
    case TCP_FD_DEV:
        event->type = TCP_EVENT_SEGMENT_ARRIVES;
        uint8_t buf[MAX_BUF_SIZE];
        int bytes_read = read(fd, buf, MAX_BUF_SIZE);
        ip_header iph;
        to_ip_header(&iph, buf);
        if (iph.ver != 4 || iph.proto != (uint8_t)IP_PROTO_TCP ||
            (iph.ihl << 2) != IP_HEADER_SIZE) {
            return -1;
        }
        if (iph.src_addr != connection->dest.addr ||
            iph.dest_addr != connection->src.addr) {

            printf("Addr mismatch: %d %d %d %d\n", iph.src_addr, iph.dest_addr,
                   connection->src.addr, connection->dest.addr);

            return -1;
        }

        tcp_header tcph;
        to_tcp_header(&tcph, buf + (iph.ihl << 2));

        if (tcph.src_port != connection->dest.port ||
            tcph.dest_port != connection->src.port) {

            printf("Ports mismatch: %d %d %d %d\n", tcph.src_port,
                   tcph.dest_port, connection->src.port, connection->dest.port);

            return -1;
        }
        event->len = iph.len - (iph.ihl << 2);
        memcpy(event->data, &tcph, event->len);
        break;
    case TCP_FD_READ:
        printf("TCP_FD_READ\n");
        read(fd, &event->type, 1);
        read(fd, &event->len, 4);
        read(fd, &event->data, event->len);
        break;
    case TCP_FD_TIMER:
        break;
    default:
        printf("No event found\n");
        return -1;
    }

    return 0;
}

int tcp_loop(tcp_connection *connection) {
    int ready = 0;
    printf("Looping\n");
    while (1) {
        ready = poll(connection->in_r_fds,
                     sizeof(connection->in_r_fds) / sizeof(struct pollfd), -1);
        if (ready == -1) {
            printf("Poll errored\n");
            return -1;
        }
        for (int i = 0; i < 3; i++) {
            printf("fd %d: revents: %hu pollin: %hu\n", i,
                   connection->in_r_fds[i].revents,
                   connection->in_r_fds[i].revents & POLLIN);
        }

        printf("Polled: %d\n", ready);

        tcp_event *event;
        event = malloc(MAX_BUF_SIZE + sizeof(tcp_event));

        if (parse_event(connection, event) == -1) {
            free(event);
            sleep(1);
            continue;
        }

        if (event->type == TCP_EVENT_ABORT) {
            free(event);
            break;
        }

        int res = 0;
        do {
            res = connection->state_func(connection, event);
            if (connection->state == TCP_CLOSED) {
                free(event);
                break;
            }
        } while (res == 1);
        free(event);
        sleep(1);
    }
    return 0;
}

int tcp_create_connection(tcp_connection *connection, int dev_fd, endpoint src,
                          endpoint dest) {
    int input[2];
    int output[2];

    if (pipe(input) == -1) {
        printf("Pipe input failed\n");
    }
    if (pipe(output) == -1) {
        printf("Pipe input failed\n");
    }

    connection->in_r_fds[TCP_FD_DEV].fd = dev_fd;
    connection->in_r_fds[TCP_FD_READ].fd = input[0];

    connection->in_w_fds[TCP_FD_DEV] = dev_fd;
    connection->in_w_fds[TCP_FD_READ] = output[1];

    connection->ex_r_fds[0].fd = output[0];

    connection->ex_w_fds[0] = input[1];

    for (int i = 0; i < sizeof(connection->in_r_fds) / sizeof(struct pollfd);
         i++) {
        connection->in_r_fds[i].events = POLLIN;
    }

    for (int i = 0; i < sizeof(connection->ex_r_fds) / sizeof(struct pollfd);
         i++) {
        connection->ex_r_fds[i].events = POLLIN;
    }

    connection->src = src;
    connection->dest = dest;

    return 0;
}

int tcp_transmit_dev(tcp_connection *connection, tcp_header *tcph,
                     uint8_t *payload, int payload_len) {
    int dev_fd = connection->in_r_fds[TCP_FD_DEV].fd;
    uint8_t buf[MAX_BUF_SIZE];

    ip_header iph =
        create_ip_header(connection->src.addr, connection->dest.addr,
                         (tcph->doff << 2) + payload_len + IP_HEADER_SIZE);
    tcp_ip_header piph;
    piph.tcp_len = iph.len - IP_HEADER_SIZE;
    piph.src_addr = iph.src_addr;
    piph.dest_addr = iph.dest_addr;
    piph.protocol = (uint16_t)IP_PROTO_TCP;

    int offset = from_ip_header(&iph, buf);
    offset += from_tcp_header(tcph, &piph, payload, buf + offset);
    memcpy(buf + offset, payload, payload_len);

    write(dev_fd, buf, offset + payload_len);
    return 0;
}

int tcp_create_tcb(tcp_tcb_snd *snd, tcp_tcb_rcv *rcv) {
    snd->iss = 0;
    snd->nxt = snd->iss + 1;
    snd->una = snd->iss;
    snd->up = 0;
    snd->wl1 = 0;
    snd->wl2 = 0;
    snd->wnd = 1024;

    rcv->irs = 0;
    rcv->up = 0;
    rcv->wnd = 1024;
    rcv->nxt = rcv->irs + 1;

    return 0;
}

int tcp_send_rst(tcp_connection *connection) {
    tcp_header tcph =
        create_tcp_header(connection->src.port, connection->dest.port);
    tcph.seq = connection->snd.iss;
    tcph.flags = 0 & TCP_FLAG_RST;

    tcp_transmit_dev(connection, &tcph, NULL, 0);
    return 0;
}

int tcp_check_acceptability(tcp_connection *connection, tcp_header *tcph,
                            uint16_t payload_len) {
    int acceptable = 1;
    if (connection->rcv.wnd == 0) {
        acceptable = payload_len == 0;
    } else {
        if (payload_len == 0) {
            acceptable =
                wrapping_between(connection->rcv.nxt - 1, tcph->seq,
                                 connection->rcv.nxt + connection->rcv.wnd);
        } else {
            acceptable =
                wrapping_between(connection->rcv.nxt - 1, tcph->seq,
                                 connection->rcv.nxt + connection->rcv.wnd) ||
                wrapping_between(connection->rcv.nxt - 1,
                                 tcph->seq + payload_len - 1,
                                 connection->rcv.nxt + connection->rcv.wnd);
        }
    }

    return acceptable;
}

int tcp_state_closed(tcp_connection *connection) {
    printf("Closed state\n");
    //
    // Only support active, always send SYN
    tcp_create_tcb(&connection->snd, &connection->rcv);
    tcp_header tcph =
        create_tcp_header(connection->src.port, connection->dest.port);
    tcph.seq = connection->snd.iss;
    tcph.flags |= TCP_FLAG_SYN;

    uint8_t dummy;

    tcp_transmit_dev(connection, &tcph, &dummy, 0);

    connection->state = TCP_SYN_SENT;
    connection->state_func = tcp_state_syn_sent;
    printf("State func: %p\n", connection->state_func);

    return 0;
}

int tcp_state_syn_sent(tcp_connection *connection, tcp_event *event) {
    printf("Syn sent state\n");
    switch (event->type) {
    case TCP_EVENT_SEGMENT_ARRIVES: {
        tcp_header *tcph = (tcp_header *)event->data;
        print_tcp_header(tcph);
        if (tcph->flags & TCP_FLAG_ACK) {
            if (wrapping_lt(tcph->seq_ack, connection->snd.iss - 1) ||
                wrapping_lt(connection->snd.nxt, tcph->seq_ack)) {
                printf("Ack not acceptable\n");
                if (!(tcph->flags & TCP_FLAG_RST)) {
                    tcp_send_rst(connection);
                }
                break;
            }
            if (!wrapping_between(connection->snd.una - 1, tcph->seq_ack,
                                  connection->snd.nxt + 1)) {
                printf("Ack not acceptable\n");
                break;
            }
        }
        if (tcph->flags & TCP_FLAG_RST) {
            printf("Reset connection\n");
            connection->state = TCP_CLOSED;
            break;
        }

        if (tcph->flags & TCP_FLAG_SYN) {
            connection->rcv.nxt = tcph->seq + 1;
            connection->rcv.irs = tcph->seq;
            connection->snd.una = tcph->seq_ack;
            // Remove appropriate retransmission segments

            if (wrapping_lt(connection->snd.iss, connection->snd.una)) {
                connection->state = TCP_ESTABLISHED;
                connection->state_func = tcp_state_established;
                tcp_header new_tcph = create_tcp_header(connection->src.port,
                                                        connection->dest.port);
                new_tcph.seq = connection->snd.nxt;
                new_tcph.seq_ack = connection->rcv.nxt;
                new_tcph.flags |= TCP_FLAG_ACK;
                tcp_transmit_dev(connection, &new_tcph, NULL, 0);
                break;
            } else {
                connection->state = TCP_SYN_RECEIVED;
                connection->state_func = tcp_state_syn_received;
                tcp_header new_tcph = create_tcp_header(connection->src.port,
                                                        connection->dest.port);
                new_tcph.seq = connection->snd.iss;
                new_tcph.seq_ack = connection->rcv.nxt;
                tcp_transmit_dev(connection, &new_tcph, NULL, 0);
                break;
            }
        }
    } break;
    case TCP_EVENT_CLOSE:
        connection->state = TCP_CLOSED;
        break;
    default:
        break;
    }
    return 0;
}

int tcp_state_syn_received(tcp_connection *connection, tcp_event *event) {
    printf("Syn received state\n");
    return 0;
}

int tcp_state_established(tcp_connection *connection, tcp_event *event) {
    printf("Established state\n");
    switch (event->type) {
    case TCP_EVENT_SEGMENT_ARRIVES: {
        tcp_header *tcph = (tcp_header *)event->data;
        int payload_len = event->len - (tcph->doff << 2);
        int acceptable = tcp_check_acceptability(connection, tcph, payload_len);
        if (!acceptable) {
            if (tcph->flags & TCP_FLAG_RST) {
                break;
            }
            tcp_header new_tcph =
                create_tcp_header(connection->src.port, connection->dest.port);
            new_tcph.seq = connection->snd.nxt;
            new_tcph.seq_ack = connection->rcv.nxt;
            new_tcph.flags |= TCP_FLAG_ACK;
            tcp_transmit_dev(connection, &new_tcph, NULL, 0);
            break;
        }
        if (tcph->flags & TCP_FLAG_RST) {
            connection->state = TCP_CLOSED;
            break;
        }
        if (tcph->flags & TCP_FLAG_SYN) {
            tcp_send_rst(connection);
            break;
        }
        if (tcph->flags & TCP_FLAG_ACK) {
            if (wrapping_between(connection->snd.una, tcph->seq_ack,
                                 connection->snd.nxt + 1)) {
                connection->snd.una = tcph->seq_ack;
                // dump segments before una in retransmission queue

                if (wrapping_lt(connection->snd.wl1, tcph->seq) ||
                    (connection->snd.wl1 == tcph->seq &&
                     wrapping_lt(connection->snd.wl2, tcph->seq_ack))) {
                    connection->snd.wnd = tcph->wnd;
                    connection->snd.wl1 = tcph->seq;
                    connection->snd.wl2 = tcph->seq_ack;
                }
            } else if (wrapping_lt(tcph->seq_ack, connection->snd.una)) {
                break;
            } else if (wrapping_lt(connection->snd.nxt, tcph->seq_ack)) {
                tcp_header new_tcph = create_tcp_header(connection->src.port,
                                                        connection->dest.port);
                new_tcph.seq = connection->snd.nxt;
                new_tcph.seq_ack = tcph->seq + 1;
                new_tcph.flags |= TCP_FLAG_ACK;
                tcp_transmit_dev(connection, &new_tcph, NULL, 0);
                break;
            }
        }
        if (tcph->flags & TCP_FLAG_URG) {
            connection->rcv.up = connection->rcv.up > tcph->urg_ptr
                                     ? connection->rcv.up
                                     : tcph->urg_ptr;
        }
        if (payload_len > 0) {
            tcp_header new_tcph =
                create_tcp_header(connection->src.port, connection->dest.port);
            connection->rcv.nxt = tcph->seq + payload_len;
            // write data to local buffers
            new_tcph.seq = connection->snd.nxt;
            new_tcph.seq_ack = connection->rcv.nxt;
            new_tcph.flags |= TCP_FLAG_ACK;
            tcp_transmit_dev(connection, &new_tcph, NULL, 0);
        }
        if (tcph->flags & TCP_FLAG_FIN) {
            // signal user closing
            connection->rcv.nxt = tcph->seq + payload_len + 1;
            tcp_header new_tcph =
                create_tcp_header(connection->src.port, connection->dest.port);
            new_tcph.seq = connection->snd.nxt;
            new_tcph.seq_ack = connection->rcv.nxt;
            new_tcph.flags |= TCP_FLAG_ACK;
            tcp_transmit_dev(connection, &new_tcph, NULL, 0);
            connection->state = TCP_CLOSE_WAIT;
            connection->state_func = tcp_state_close_wait;
        }

    } break;
    case TCP_EVENT_OPEN:
    case TCP_EVENT_SEND:
    case TCP_EVENT_RECEIVE:
    case TCP_EVENT_CLOSE:
    case TCP_EVENT_ABORT:
    case TCP_EVENT_STATUS:
    case TCP_EVENT_USER_TIMEOUT:
    case TCP_EVENT_RETRANSMISSION_TIMEOUT:
    case TCP_EVENT_TIME_WAIT_TIMEOUT:
        break;
    }

    return 0;
}

int tcp_state_close_wait(tcp_connection *connection, tcp_event *event) {
    printf("Close wait state\n");

    return 0;
}
