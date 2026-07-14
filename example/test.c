#include <stdint.h>
#include <stdio.h>

#include "sock.h"

extern int microps_setup(void);
extern int microps_cleanup(void);

static int conn_main(int soc) {
    uint8_t buf[128];
    ssize_t n;

    for (;;) {
        n = sock_recv(soc, buf, sizeof(buf));
        if (n == -1) {
            fprintf(stderr, "sock_recv() failure\n");
            return -1;
        }
        if (n == 0) {
            fprintf(stderr, "connection closed\n");
            break;
        }
        fprintf(stderr, "%zd bytes received\n", n);
        if (sock_send(soc, buf, n) == -1) {
            fprintf(stderr, "sock_send() failure\n");
            return -1;
        }
    }
    return 0;
}

int main(void) {
    int soc, acc;
    struct sockaddr_in local = {0};

    if (microps_setup() == -1) {
        fprintf(stderr, "microps_setup() failure\n");
        return 1;
    }

    soc = sock_open(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (soc == -1) {
        fprintf(stderr, "sock_open() failure\n");
        return 1;
    }

    local.sin_addr.s_addr = INADDR_ANY;
    local.sin_port = hton16(7);
    if (sock_bind(soc, (struct sockaddr *)&local, sizeof(local)) == -1) {
        fprintf(stderr, "sock_bind() failure\n");
        return 1;
    }
    if (sock_listen(soc, 1) == -1) {
        fprintf(stderr, "sock_listen() failure\n");
        return 1;
    }

    for (;;) {
        acc = sock_accept(soc, NULL, NULL);
        if (acc == -1) {
            fprintf(stderr, "sock_accept() failure\n");
            break;
        }
        fprintf(stderr, "connection accepted\n");
        conn_main(acc);
        sock_close(acc);
    }

    sock_close(soc);
    microps_cleanup();
    return 0;
}
