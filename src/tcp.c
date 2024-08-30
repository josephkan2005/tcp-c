#include "tcp.h"
#include "header.h"
#include "utils.h"
#include <arpa/inet.h>
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
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <time.h>
#include <unistd.h>

endpoint create_endpoint(char *addr, uint16_t port) {
    endpoint e;
    int res = inet_pton(AF_INET, addr, &e.addr);
    if (res != 1) {
        printf("Address format could not be parsed\n");
        return e;
    }
    e.addr = ntohl(e.addr);
    e.port = port;
    return e;
}

int tcp_create_event(enum tcp_event_type type, uint32_t len, uint8_t *payload,
                     uint8_t *event_buf) {
    tcp_event *event = (tcp_event *)event_buf;
    event->type = type;
    event->len = len;
    memcpy(event_buf + EVENT_DOFF, payload, len);
    return 0;
}

tcp_header create_tcp_header_from_connection(tcp_connection *connection) {
    return create_tcp_header(connection->src.port, connection->dest.port);
}

int tcp_connect(tcp_connection *connection, pthread_t *jh, endpoint src,
                endpoint dest, int tun_fd) {
    printf("Connect\n");
    tcp_create_connection(connection, tun_fd, src, dest);
    tcp_state_closed(connection);

    pthread_t main_loop;
    int ret;

    ret = pthread_create(&main_loop, NULL, (void *)tcp_loop, connection);
    *jh = main_loop;
    return ret;
}

int tcp_write(tcp_connection *connection, uint8_t *buf, uint16_t len) {
    connection->user_timeout = time(NULL) + USER_TIMEOUT;
    if (connection->state == TCP_CLOSED)
        return -1;
    printf("Write\n");
    int fd = connection->ex_w_fds[0];
    uint8_t event_buf[MAX_BUF_SIZE + EVENT_DOFF];
    tcp_create_event(TCP_EVENT_SEND, len, buf, event_buf);

    int res = write(fd, event_buf, len + EVENT_DOFF);
    if (res < 0) {
        printf("Write failed\n");
        return -1;
    }

    return 0;
}

int tcp_read(tcp_connection *connection, uint8_t *buf, int nbytes) {
    connection->user_timeout = time(NULL) + USER_TIMEOUT;
    if (connection->state == TCP_CLOSED)
        return -1;
    int ready = poll(connection->ex_r_fds, 1, 1000);
    if (ready == 0) {
        printf("Poll timed out\n");
        return ready;
    }
    if (ready == -1) {
        printf("Poll errored\n");
        return ready;
    }

    printf("Read\n");

    int num_read = read(connection->ex_r_fds[0].fd, buf, nbytes);

    return num_read;
}

int tcp_disconnect(tcp_connection *connection) {
    printf("Disconnect\n");
    tcp_close(connection);
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

int tcp_close(tcp_connection *connection) {
    printf("Close\n");
    uint8_t event_buf[MAX_BUF_SIZE + EVENT_DOFF];
    tcp_create_event(TCP_EVENT_CLOSE, 0, NULL, event_buf);
    write(connection->ex_w_fds[0], event_buf, 8);

    return 0;
}

int tcp_abort(tcp_connection *connection) {
    printf("Abort\n");
    uint8_t event_buf[MAX_BUF_SIZE + EVENT_DOFF];
    tcp_create_event(TCP_EVENT_ABORT, 0, NULL, event_buf);
    write(connection->ex_w_fds[0], event_buf, 8);
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
        event->data = malloc(event->len);
        memcpy(event->data, &tcph, tcph.doff << 2);
        memcpy(event->data + (tcph.doff << 2),
               buf + (iph.ihl << 2) + (tcph.doff << 2),
               event->len - (tcph.doff << 2));
        break;
    case TCP_FD_PIPE:
        printf("TCP_FD_PIPE\n");
        read(fd, &event->type, 4);
        read(fd, &event->len, 4);
        event->data = malloc(event->len);
        read(fd, event->data, event->len);
        break;
    case TCP_FD_TIMER:
        printf("TCP_FD_TIMER\n");
        uint64_t res = read(fd, NULL, sizeof(uint64_t));
        time_t now = time(NULL);
        if (connection->msl_timeout >= 0) {
            int msl_diff = difftime(now, connection->msl_timeout);
            if (msl_diff >= 0) {
                event->type = TCP_EVENT_TIME_WAIT_TIMEOUT;
                event->len = 0;
                break;
            }
        }
        if (connection->user_timeout >= 0) {
            int user_diff = difftime(now, connection->user_timeout);
            if (user_diff >= 0) {
                event->type = TCP_EVENT_USER_TIMEOUT;
                event->len = 0;
                break;
            }
        }
        double rto = 1.5 * connection->srtt;
        rto = rto < 1 ? 1 : rto;
        rto = rto > 60 ? 60 : rto;
        print_tcp_tcb(&connection->snd, &connection->rcv);
        print_tq_send_times(&connection->tq);
        printf("now: %ld, head: %ld, rto: %f", now,
               connection->tq.send_times[connection->tq.head], rto);
        ;
        if (connection->snd.nxt - connection->snd.una > 0) {
            if (now - connection->tq.send_times[connection->tq.head] > rto) {
                event->type = TCP_EVENT_RETRANSMISSION_TIMEOUT;
                event->len = 0;
                break;
            }
        }
        return -1;
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
            printf("fd %d: revents: %hu events: %hu pollin: %hu val: %d\n", i,
                   connection->in_r_fds[i].revents,
                   connection->in_r_fds[i].events,
                   connection->in_r_fds[i].revents & POLLIN,
                   connection->in_r_fds[i].fd);
            if (connection->in_r_fds[i].revents & POLLHUP) {
                printf("Hang up\n");
            }
        }

        printf("Polled: %d\n", ready);

        tcp_event event;
        event.data = NULL;

        if (parse_event(connection, &event) == -1) {
            if (event.data != NULL) {
                free(event.data);
            }
            continue;
        }

        if (event.type == TCP_EVENT_ABORT) {
            if (event.data != NULL) {
                free(event.data);
            }
            break;
        }

        int res = 0;
        do {
            res = connection->state_func(connection, &event);
            if (connection->state == TCP_CLOSED) {
                break;
            }
        } while (res == 1);
        if (event.data != NULL) {
            free(event.data);
        }
        if (connection->state == TCP_CLOSED) {
            printf("Close & return\n");
            break;
        }
    }
    sleep(1);
    tcp_destroy_connection(connection);
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
        printf("Pipe output failed\n");
    }

    connection->in_r_fds[TCP_FD_DEV].fd = dev_fd;
    connection->in_r_fds[TCP_FD_TIMER].fd = timerfd_create(CLOCK_REALTIME, 0);
    connection->in_r_fds[TCP_FD_PIPE].fd = input[0];

    connection->in_w_fds[TCP_FD_DEV] = dev_fd;
    connection->in_w_fds[TCP_FD_TIMER] = connection->in_r_fds[TCP_FD_TIMER].fd;
    connection->in_w_fds[TCP_FD_PIPE] = output[1];

    connection->ex_r_fds[0].fd = output[0];

    connection->ex_w_fds[0] = input[1];

    struct itimerspec utmr;
    utmr.it_value.tv_sec = 1;
    utmr.it_value.tv_nsec = 0;
    utmr.it_interval.tv_sec = 1;
    utmr.it_interval.tv_nsec = 0;
    timerfd_settime(connection->in_r_fds[TCP_FD_TIMER].fd, 0, &utmr, NULL);

    for (int i = 0; i < sizeof(connection->in_r_fds) / sizeof(struct pollfd);
         i++) {
        connection->in_r_fds[i].events = POLLIN;
    }

    for (int i = 0; i < sizeof(connection->ex_r_fds) / sizeof(struct pollfd);
         i++) {
        connection->ex_r_fds[i].events = POLLIN;
    }

    time_t now;
    time(&now);

    connection->user_timeout = now + USER_TIMEOUT;
    connection->msl_timeout = -1;
    connection->srtt = 0.5;

    connection->src = src;
    connection->dest = dest;

    transmission_queue_create(&connection->tq, MAX_BUF_SIZE);

    return 0;
}

int tcp_destroy_connection(tcp_connection *connection) {
    for (int i = 0; i < sizeof(connection->in_r_fds) / sizeof(struct pollfd);
         i++) {
        if (connection->in_w_fds[i] != connection->in_r_fds[i].fd) {
            close(connection->in_w_fds[i]);
        }
        close(connection->in_r_fds[i].fd);
    }
    for (int i = 0; i < sizeof(connection->ex_r_fds) / sizeof(struct pollfd);
         i++) {
        close(connection->ex_r_fds[i].fd);
        close(connection->ex_w_fds[i]);
    }

    transmission_queue_destroy(&connection->tq);
    return 0;
}

int tcp_transmit_dev(tcp_connection *connection, tcp_header *tcph,
                     uint8_t *payload, int payload_len) {
    printf("Sending message\n");
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
    snd->nxt = snd->iss;
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

int tcp_requeue_send(tcp_connection *connection) {
    // TODO: Use separate event queue
    return 0;
}

int tcp_send_rst(tcp_connection *connection) {
    tcp_header tcph = create_tcp_header_from_connection(connection);
    tcph.seq = connection->snd.iss;
    tcph.flags |= TCP_FLAG_RST;

    tcp_transmit_dev(connection, &tcph, NULL, 0);
    return 0;
}

int tcp_send_fin(tcp_connection *connection) {
    printf("Sending fin\n");
    tcp_header new_tcph = create_tcp_header_from_connection(connection);
    new_tcph.seq = connection->snd.nxt;
    new_tcph.seq_ack = connection->rcv.nxt;
    new_tcph.flags |= TCP_FLAG_ACK;
    new_tcph.flags |= TCP_FLAG_FIN;

    uint8_t buf[1];
    buf[0] = 0;
    transmission_queue_push_back(&connection->tq, buf, 1, time(NULL));
    connection->tq.fin = 1;

    connection->snd.nxt += 1;

    tcp_transmit_dev(connection, &new_tcph, NULL, 0);
    printf("Sent fin\n");
    return 0;
}

int tcp_send_syn(tcp_connection *connection) {
    printf("Sending syn\n");
    tcp_header tcph = create_tcp_header_from_connection(connection);
    tcph.seq = connection->snd.nxt;
    tcph.flags |= TCP_FLAG_SYN;

    connection->tq.head_seq = connection->snd.nxt;

    uint8_t buf[1];
    buf[0] = 0;

    transmission_queue_push_back(&connection->tq, buf, 1, time(NULL));
    connection->tq.syn = 1;

    connection->snd.nxt += 1;

    tcp_transmit_dev(connection, &tcph, NULL, 0);

    return 0;
}

int tcp_retransmit(tcp_connection *connection) {
    uint32_t limit =
        connection->snd.wnd > (connection->snd.nxt - connection->snd.una)
            ? (connection->snd.nxt - connection->snd.una)
            : connection->snd.wnd;
    time_t now = time(NULL);
    uint8_t raw_payload[MAX_BUF_SIZE];
    uint8_t *payload = raw_payload;
    transmission_queue_front(&connection->tq, raw_payload, limit);
    tcp_header tcph = create_tcp_header_from_connection(connection);
    if (connection->tq.size == limit && connection->tq.fin) {
        limit -= 1;
        tcph.flags |= TCP_FLAG_FIN;
    }
    tcph.seq = connection->tq.head_seq;
    tcph.seq_ack = connection->rcv.nxt;
    tcph.flags |= TCP_FLAG_ACK;
    if (connection->snd.iss == connection->tq.head_seq && connection->tq.syn) {
        limit -= 1;
        payload += 1;
        tcph.flags = TCP_FLAG_SYN;
        tcph.seq_ack = 0;
    }
    transmission_queue_set_times(&connection->tq, limit, now);

    tcp_transmit_dev(connection, &tcph, payload, limit);
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
    // Only support active, always send SYN
    tcp_create_tcb(&connection->snd, &connection->rcv);
    tcp_send_syn(connection);

    connection->state = TCP_SYN_SENT;
    connection->state_func = tcp_state_syn_sent;

    return 0;
}

int tcp_state_syn_sent(tcp_connection *connection, tcp_event *event) {
    printf("Syn sent state\n");
    switch (event->type) {
    case TCP_EVENT_SEGMENT_ARRIVES: {
        tcp_header *tcph = (tcp_header *)event->data;
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
            transmission_queue_pop_front(
                &connection->tq,
                wrapping_len(connection->tq.head_seq, connection->snd.una));

            if (wrapping_lt(connection->snd.iss, connection->snd.una)) {
                connection->state = TCP_ESTABLISHED;
                connection->state_func = tcp_state_established;
                tcp_header new_tcph =
                    create_tcp_header_from_connection(connection);
                new_tcph.seq = connection->snd.nxt;
                new_tcph.seq_ack = connection->rcv.nxt;
                new_tcph.flags |= TCP_FLAG_ACK;
                tcp_transmit_dev(connection, &new_tcph, NULL, 0);
                tcp_requeue_send(connection);
                break;
            } else {
                connection->state = TCP_SYN_RECEIVED;
                connection->state_func = tcp_state_syn_received;
                tcp_header new_tcph =
                    create_tcp_header_from_connection(connection);
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
    case TCP_EVENT_SEND:
        // TODO: Use separate event queue
        break;
    case TCP_EVENT_ABORT:
        connection->state = TCP_CLOSED;
        break;
    case TCP_EVENT_RETRANSMISSION_TIMEOUT:
        tcp_retransmit(connection);
        break;
    default:
        break;
    }
    return 0;
}

int tcp_state_syn_received(tcp_connection *connection, tcp_event *event) {
    printf("Syn received state\n");
    switch (event->type) {
    case TCP_EVENT_SEGMENT_ARRIVES:
        break;
    case TCP_EVENT_OPEN:
        printf("Connection already exists\n");
        break;
    case TCP_EVENT_SEND:
        // TODO: Use separate event queue
        break;
    case TCP_EVENT_RECEIVE:
    case TCP_EVENT_CLOSE:
        if (connection->snd.nxt -
                (connection->tq.head_seq + connection->tq.size) >
            1) {
            // TODO: Use separate event queue
        } else {
            tcp_send_fin(connection);
            connection->state = TCP_FIN_WAIT_1;
            connection->state_func = tcp_state_fin_wait_1;
        }
        break;
    case TCP_EVENT_STATUS:
        break;
    case TCP_EVENT_ABORT:
        connection->state = TCP_CLOSED;
        break;
    case TCP_EVENT_USER_TIMEOUT:
        printf("Connection aborted due to timeout\n");
        connection->state = TCP_CLOSED;
        break;
    case TCP_EVENT_RETRANSMISSION_TIMEOUT:
        tcp_retransmit(connection);
        break;
    case TCP_EVENT_TIME_WAIT_TIMEOUT:
        break;
    }
    return 0;
}

int tcp_state_established(tcp_connection *connection, tcp_event *event) {
    printf("Established state\n");
    print_tcp_event_type(event->type);
    switch (event->type) {
    case TCP_EVENT_SEGMENT_ARRIVES: {
        tcp_header *tcph = (tcp_header *)event->data;
        int payload_len = event->len - (tcph->doff << 2);
        int acceptable = tcp_check_acceptability(connection, tcph, payload_len);
        if (!acceptable) {
            if (tcph->flags & TCP_FLAG_RST) {
                break;
            }
            tcp_header new_tcph = create_tcp_header_from_connection(connection);
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
                time_t now = time(NULL);
                connection->srtt =
                    (0.9 * connection->srtt) +
                    ((1 - 0.9) *
                     (now - connection->tq.send_times[connection->snd.una]));

                connection->snd.una = tcph->seq_ack;

                transmission_queue_pop_front(
                    &connection->tq,
                    wrapping_len(connection->tq.head_seq, connection->snd.una));

                if (wrapping_lt(connection->snd.wl1, tcph->seq) ||
                    (connection->snd.wl1 == tcph->seq &&
                     wrapping_lt(connection->snd.wl2, tcph->seq_ack))) {
                    connection->snd.wnd = tcph->wnd;
                    connection->snd.wl1 = tcph->seq;
                    connection->snd.wl2 = tcph->seq_ack;
                }
                tcp_requeue_send(connection);
            } else if (wrapping_lt(tcph->seq_ack, connection->snd.una)) {
                break;
            } else if (wrapping_lt(connection->snd.nxt, tcph->seq_ack)) {
                tcp_header new_tcph =
                    create_tcp_header_from_connection(connection);
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
            tcp_header new_tcph = create_tcp_header_from_connection(connection);
            connection->rcv.nxt = tcph->seq + payload_len;
            write(connection->in_w_fds[TCP_FD_PIPE],
                  ((uint8_t *)tcph) + (tcph->doff << 2), payload_len);
            new_tcph.seq = connection->snd.nxt;
            new_tcph.seq_ack = connection->rcv.nxt;
            new_tcph.flags |= TCP_FLAG_ACK;
            tcp_transmit_dev(connection, &new_tcph, NULL, 0);
        }
        if (tcph->flags & TCP_FLAG_FIN) {
            // signal user closing
            connection->rcv.nxt = tcph->seq + payload_len + 1;
            tcp_header new_tcph = create_tcp_header_from_connection(connection);
            new_tcph.seq = connection->snd.nxt;
            new_tcph.seq_ack = connection->rcv.nxt;
            new_tcph.flags |= TCP_FLAG_ACK;
            tcp_transmit_dev(connection, &new_tcph, NULL, 0);
            connection->state = TCP_CLOSE_WAIT;
            connection->state_func = tcp_state_close_wait;
            printf("CHANGED CONNECTION TO CLOSING\n");
        }
    } break;
    case TCP_EVENT_OPEN:
        printf("Connection already exists\n");
        break;
    case TCP_EVENT_SEND: {
        uint32_t len = event->len;
        uint8_t *payload = event->data;
        uint32_t limit =
            connection->snd.una + connection->snd.wnd - connection->snd.nxt;
        len = len > limit ? limit : len;
        printf("Pushing %ub to tq, time: %ld\n", len, time(NULL));
        transmission_queue_push_back(&connection->tq, payload, len, time(NULL));
        // TODO: Use separate event queue
        tcp_header new_tcph = create_tcp_header_from_connection(connection);
        new_tcph.seq = connection->snd.nxt;
        new_tcph.seq_ack = connection->rcv.nxt;
        new_tcph.flags |= TCP_FLAG_ACK;

        connection->snd.nxt += len;
        tcp_transmit_dev(connection, &new_tcph, payload, len);
    } break;
    case TCP_EVENT_RECEIVE:
    case TCP_EVENT_CLOSE: {
        tcp_send_fin(connection);

        connection->state = TCP_FIN_WAIT_1;
        connection->state_func = tcp_state_fin_wait_1;
    } break;
    case TCP_EVENT_ABORT:
    case TCP_EVENT_STATUS:
    case TCP_EVENT_USER_TIMEOUT:
        printf("Connection aborted due to timeout\n");
        connection->state = TCP_CLOSED;
        break;
    case TCP_EVENT_RETRANSMISSION_TIMEOUT: {
        tcp_retransmit(connection);
    } break;
    case TCP_EVENT_TIME_WAIT_TIMEOUT:
        break;
    }

    return 0;
}

int tcp_state_close_wait(tcp_connection *connection, tcp_event *event) {
    printf("Close wait state\n");
    print_tcp_event_type(event->type);
    switch (event->type) {
    case TCP_EVENT_OPEN:
        printf("Connection already exists\n");
        break;
    case TCP_EVENT_SEND: {
        uint32_t len = event->len;
        uint8_t *payload = event->data;
        tcp_header new_tcph = create_tcp_header_from_connection(connection);
        new_tcph.seq = connection->snd.nxt;
        new_tcph.seq_ack = connection->rcv.nxt;
        new_tcph.flags |= TCP_FLAG_ACK;

        connection->snd.nxt += len;
        tcp_transmit_dev(connection, &new_tcph, payload, len);
    } break;
    case TCP_EVENT_RECEIVE:
    case TCP_EVENT_CLOSE: {
        tcp_send_fin(connection);

        connection->state = TCP_LAST_ACK;
        connection->state_func = tcp_state_last_ack;
    } break;
    case TCP_EVENT_ABORT:
    case TCP_EVENT_STATUS:
    case TCP_EVENT_SEGMENT_ARRIVES:
    case TCP_EVENT_USER_TIMEOUT:
        printf("Connection aborted due to timeout\n");
        connection->state = TCP_CLOSED;
        break;
    case TCP_EVENT_RETRANSMISSION_TIMEOUT:
        tcp_retransmit(connection);
        break;
    case TCP_EVENT_TIME_WAIT_TIMEOUT:
        break;
    }
    return 0;
}

int tcp_state_last_ack(tcp_connection *connection, tcp_event *event) {
    printf("Last ack state\n");
    switch (event->type) {
    case TCP_EVENT_SEGMENT_ARRIVES: {
        tcp_header *tcph = (tcp_header *)event->data;
        if (tcph->flags & TCP_FLAG_ACK) {
            if (tcph->seq_ack == connection->snd.nxt) {
                connection->state = TCP_CLOSED;
                break;
            }
        }
    } break;
    case TCP_EVENT_OPEN:
        printf("Connection already exists\n");
        break;
    case TCP_EVENT_SEND:
    case TCP_EVENT_RECEIVE:
    case TCP_EVENT_CLOSE:
        printf("Error: connnection closing\n");
        break;
    case TCP_EVENT_ABORT:
        connection->state = TCP_CLOSED;
        break;
    case TCP_EVENT_STATUS:
        break;
    case TCP_EVENT_USER_TIMEOUT:
        printf("Connection aborted due to timeout\n");
        connection->state = TCP_CLOSED;
        break;
    case TCP_EVENT_RETRANSMISSION_TIMEOUT:
        tcp_retransmit(connection);
        break;
    case TCP_EVENT_TIME_WAIT_TIMEOUT:
        break;
    }
    return 0;
}

int tcp_state_fin_wait_1(tcp_connection *connection, tcp_event *event) {
    printf("Fin wait 1 state\n");
    switch (event->type) {
    case TCP_EVENT_SEGMENT_ARRIVES: {
        tcp_header *tcph = (tcp_header *)event->data;
        if (tcph->flags & TCP_FLAG_ACK) {
            if (tcph->seq_ack == connection->snd.nxt) {
                connection->state = TCP_FIN_WAIT_2;
                connection->state_func = tcp_state_fin_wait_2;
                break;
            }
        }
    } break;
    case TCP_EVENT_OPEN:
        printf("Connection already exists\n");
        break;
    case TCP_EVENT_RECEIVE:
        break;
    case TCP_EVENT_SEND:
    case TCP_EVENT_CLOSE:
        printf("Error: connnection closing\n");
        break;
    case TCP_EVENT_ABORT:
    case TCP_EVENT_STATUS:
    case TCP_EVENT_USER_TIMEOUT:
        printf("Connection aborted due to timeout\n");
        connection->state = TCP_CLOSED;
        break;
    case TCP_EVENT_RETRANSMISSION_TIMEOUT:
        tcp_retransmit(connection);
        break;
    case TCP_EVENT_TIME_WAIT_TIMEOUT:
        break;
    }
    return 0;
}

int tcp_state_fin_wait_2(tcp_connection *connection, tcp_event *event) {
    printf("Fin wait 2 state\n");
    switch (event->type) {
    case TCP_EVENT_SEGMENT_ARRIVES: {
        tcp_header *tcph = (tcp_header *)event->data;
        if (tcph->flags & TCP_FLAG_FIN) {
            if (tcph->seq_ack == connection->snd.nxt) {
                connection->rcv.nxt++;
                tcp_header tcph = create_tcp_header_from_connection(connection);
                tcph.seq = connection->snd.nxt;
                tcph.seq_ack = connection->rcv.nxt;
                tcph.flags |= TCP_FLAG_ACK;
                tcp_transmit_dev(connection, &tcph, NULL, 0);
                connection->state = TCP_TIME_WAIT;
                connection->state_func = tcp_state_time_wait;
                break;
            }
        }
    } break;
    case TCP_EVENT_OPEN:
        printf("Connection already exists\n");
        break;
    case TCP_EVENT_SEND:
        printf("Error: connnection closing\n");
        break;
    case TCP_EVENT_RECEIVE:
    case TCP_EVENT_CLOSE:
    case TCP_EVENT_ABORT:
    case TCP_EVENT_STATUS:
    case TCP_EVENT_USER_TIMEOUT:
        printf("Connection aborted due to timeout\n");
        connection->state = TCP_CLOSED;
        break;
    case TCP_EVENT_RETRANSMISSION_TIMEOUT:
        tcp_retransmit(connection);
        break;
    case TCP_EVENT_TIME_WAIT_TIMEOUT:
        break;
    }
    return 0;
}

int tcp_state_time_wait(tcp_connection *connection, tcp_event *event) {
    printf("Time wait\n");
    switch (event->type) {
    case TCP_EVENT_RETRANSMISSION_TIMEOUT: {

    } break;
    case TCP_EVENT_OPEN:
        printf("Connection already exists\n");
        break;
    case TCP_EVENT_SEND:
    case TCP_EVENT_RECEIVE:
    case TCP_EVENT_CLOSE:
        printf("Error: connnection closing\n");
        break;
    case TCP_EVENT_ABORT:
        connection->state = TCP_CLOSED;
        break;
    case TCP_EVENT_STATUS:
    case TCP_EVENT_SEGMENT_ARRIVES: {
        tcp_header *tcph = (tcp_header *)event->data;
        if (tcph->flags & TCP_FLAG_FIN) {
            tcp_header tcph = create_tcp_header_from_connection(connection);
            tcph.seq = connection->snd.nxt;
            tcph.seq_ack = connection->rcv.nxt;
            tcph.flags |= TCP_FLAG_ACK;
            tcp_transmit_dev(connection, &tcph, NULL, 0);
            connection->msl_timeout = time(NULL) + MSL;
            break;
        }
    } break;
    case TCP_EVENT_USER_TIMEOUT:
        printf("Connection aborted due to timeout\n");
        connection->state = TCP_CLOSED;
        break;
    case TCP_EVENT_TIME_WAIT_TIMEOUT:
        printf("Time-wait timeout has expired\n");
        connection->state = TCP_CLOSED;
        break;
    }
    return 0;
}

int tcp_state_closing(tcp_connection *connection, tcp_event *event) {
    printf("Closing\n");
    switch (event->type) {
    case TCP_EVENT_RETRANSMISSION_TIMEOUT: {

    } break;
    case TCP_EVENT_OPEN:
        printf("Connection already exists\n");
        break;
    case TCP_EVENT_ABORT:
        connection->state = TCP_CLOSED;
        break;
    case TCP_EVENT_STATUS:
    case TCP_EVENT_SEGMENT_ARRIVES:
        break;
    case TCP_EVENT_USER_TIMEOUT:
        printf("Connection aborted due to timeout\n");
        connection->state = TCP_CLOSED;
        break;
        break;
    case TCP_EVENT_TIME_WAIT_TIMEOUT:
        break;
    case TCP_EVENT_SEND:
    case TCP_EVENT_RECEIVE:
    case TCP_EVENT_CLOSE:
        printf("Error: connnection closing\n");
        break;
    }
    return 0;
}
