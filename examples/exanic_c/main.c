#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <exanic/exanic.h>
#include <exanic/fifo_rx.h>
#include <exanic/filter.h>
#include <exanic/time.h>

#include <tcpip/headers.h>

int main()
{
    char *src = "exanic0";
    int port = 0;

    exanic_t *dev = exanic_acquire_handle(src);
    if (dev == NULL)
    {
        fprintf(stderr, "require handler failed.\n");
        fflush(stderr);
        return 1;
    }

    exanic_rx_t *rx = exanic_acquire_rx_buffer(dev, port, 0);
    if (rx == NULL)
    {
        fprintf(stderr, "require rx buffer failed.\n");
        fflush(stderr);
        goto RELEASE_HANDLER;
    }

    char buffer[4096] = {0};
    exanic_cycles32_t timestamp = 0;
    exanic_cycles_t ts = 0;
    struct timespec tsps = {0};

    int i = 0;

    for (; i < 1000;)
    {
        ssize_t size = exanic_receive_frame(rx, buffer, 4096, &timestamp);

        if (size <= 0)
        {
            continue;
        }

        ts = exanic_expand_timestamp(dev, timestamp);
        exanic_cycles_to_timespec(dev, ts, &tsps);

        EtherHeader *eh = (EtherHeader *)buffer;

        uint16_t proto = ntohs(eh->ether_type);
        if (proto != PROTO_IP)
        {
            continue;
        }

        IPHeader *ih = (IPHeader *)(buffer + ETHER_HEADER_LEN);
        // int ih_len = IH_OFF(ih);

        // TCPHeader *th = buffer + ETHER_HEADER_LEN + ih_len;

        fprintf(
            stdout, "[%ld.%ld] recevied[%ld]: %d.%d.%d.%d -> %d.%d.%d.%d\n",
            tsps.tv_sec, tsps.tv_nsec, size,
            ih->saddr.byte1, ih->saddr.byte2, ih->saddr.byte3, ih->saddr.byte4,
            ih->daddr.byte1, ih->daddr.byte2, ih->daddr.byte3, ih->daddr.byte4);

        i++;
    }

    fflush(stdout);

RELEASE_BUFFER:
    exanic_release_rx_buffer(rx);

RELEASE_HANDLER:
    exanic_release_handle(dev);
}
