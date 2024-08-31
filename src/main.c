#include "tcp.h"
#include "utils.h"
#include <arpa/inet.h>
#include <bits/pthreadtypes.h>
#include <fcntl.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

int tun_alloc(char *dev, int flags) {
    struct ifreq ifr;
    int fd, err;
    char *clonedev = "/dev/net/tun";
    if ((fd = open(clonedev, O_RDWR)) < 0) {
        perror("Opening /dev/net/tun");
        return fd;
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = flags;

    if (*dev) {
        strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    }

    if ((err = ioctl(fd, TUNSETIFF, (void *)&ifr))) {
        perror("ioctl(TUNSETIFF)");
        close(fd);
        return err;
    }

    strcpy(dev, ifr.ifr_name);

    return fd;
}

int main(int argc, char **argv) {
    int sender = 0;
    if (argc > 0) {
        sender = atoi(argv[1]);
    }

    int tun_fd;
    char tun_name[IFNAMSIZ];
    strcpy(tun_name, "tun0");
    tun_fd = tun_alloc(tun_name, IFF_TUN | IFF_NO_PI);
    if (tun_fd < 0) {
        perror("Allocating interface");
        _exit(1);
    }

    printf("TUN TAP FD: %d\n", tun_fd);

    sleep(5);

    printf("Sending\n");

    tcp_connection connection;
    endpoint src, dest;
    src = create_endpoint("192.168.0.3", 8000);
    dest = create_endpoint("192.168.0.1", 9006);
    pthread_t jh;
    tcp_connect(&connection, &jh, src, dest, tun_fd);
    char *data = "Hello";
    tcp_write(&connection, data, 6);

    /* uint32_t buf = 0x00110011;
    tcp_write(&connection, (uint8_t *)&buf, 4); */

    uint8_t buf[MAX_BUF_SIZE];
    int count = 0;
    while (1) {
        if (count == 3) {
            tcp_disconnect(&connection);
            pthread_join(jh, NULL);
            return 0;
        }
        if (connection.state == TCP_CLOSE_WAIT) {
            break;
        }
        memset(buf, 0, MAX_BUF_SIZE);
        int nbytes = tcp_read(&connection, buf, MAX_BUF_SIZE);
        if (nbytes == 0) {
            continue;
        }
        printf("Reading: %s\n", buf);
        count++;
    }
    printf("Disconnecting\n");
    tcp_disconnect(&connection);
    pthread_join(jh, NULL);

    return 0;
}
