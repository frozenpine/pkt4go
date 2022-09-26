#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <exanic/exanic.h>
#include <exanic/fifo_rx.h>
#include <exanic/filter.h>
#include <exanic/time.h>

int main()
{
    char *src = "ens2";
    int port = 0;

    exanic_t *dev = exanic_acquire_handle(src);
    if (dev == NULL)
    {
        fprintf(stderr, "require handler failed.\n");
        return 1;
    }

    exanic_rx_t *rx = exanic_acquire_rx_buffer(dev, port, 0);
    if (rx == NULL)
    {
        fprintf(stderr, "require rx buffer failed.\n");
        goto RELEASE_HANDLER;
    }

    char buffer[4096] = {0};
    exanic_cycles32_t timestamp = 0;
    exanic_cycles_t ts = 0;
    struct timespec tsps = {0};

    int i;

    for (i = 0; i < 1000; i++)
    {
        ssize_t size = exanic_receive_frame(rx, buffer, 4096, &timestamp);

        if (size <= 0)
        {
            continue;
        }

        ts = exanic_expand_timestamp(dev, timestamp);
        exanic_cycles_to_timespec(dev, ts, &tsps);

        fprintf(stdout, "[%ld.%ld] recevied frame size: %ld", tsps.tv_sec, tsps.tv_nsec, size);
    }

RELEASE_BUFFER:
    exanic_release_rx_buffer(rx);

RELEASE_HANDLER:
    exanic_release_handle(dev);
}
