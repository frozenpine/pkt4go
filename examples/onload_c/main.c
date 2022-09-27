#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

#include <etherfabric/base.h>
#include <etherfabric/ef_vi.h>
#include <etherfabric/pd.h>
#include <etherfabric/vi.h>

int main()
{
    char *iface = "ens2f0";
    ef_driver_handle dh = 0;
    struct ef_pd pd = {0};
    struct ef_vi vi = {0};
    unsigned int flags = EF_VI_RX_PACKED_STREAM | EF_VI_RX_PS_BUF_SIZE_64K | EF_VI_RX_TIMESTAMPS;

    if (ef_driver_open(&dh) != 0)
    {
        fprintf(stderr, "driver open failed.\n");
        return -1;
    }

    if (ef_pd_alloc_by_name(&pd, dh, iface, EF_PD_RX_PACKED_STREAM) != 0)
    {
        fprintf(stderr, "alloc protect domain failed.\n");
        goto RELEASE_DH;
    }

    if (ef_vi_alloc_from_pd(&vi, dh, &pd, dh, -1, -1, -1, NULL, -1, flags) < 0)
    {
        fprintf(stderr, "alloc virtual interface failed.\n");
        goto RELEASE_DH;
    }

RELEASE_DH:
    ef_driver_close(dh);
}