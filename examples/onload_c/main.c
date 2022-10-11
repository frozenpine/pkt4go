#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>

#include <etherfabric/ef_vi.h>
#include <etherfabric/pd.h>
#include <etherfabric/vi.h>
#include <etherfabric/packedstream.h>
#include <etherfabric/memreg.h>

#ifndef MAP_HUGETLB
/* Not always defined in glibc headers.  If the running kernel does not
 * understand this flag it will ignore it and you may not get huge pages.
 * (In that case ef_memreg_alloc() may fail when using packed-stream mode).
 */
#define MAP_HUGETLB 0x40000
#endif

#ifdef __PPC__
#define huge_page_size (16ll * 1024 * 1024)
#elif defined(__x86_64__) || defined(__i386__)
#define huge_page_size (2ll * 1024 * 1024)
#elif defined(__aarch64__)
#define huge_page_size (2ll * 1024 * 1024)
#else
#error "Please define huge_page_size"
#endif

int main()
{
    char *iface = "ens2f0";
    ef_driver_handle dh = 0;
    struct ef_pd pd = {0};
    struct ef_vi vi = {0};
    unsigned int flags = EF_VI_RX_PACKED_STREAM | EF_VI_RX_PS_BUF_SIZE_64K | EF_VI_RX_TIMESTAMPS;
    struct ef_memreg memreg = {0};
    ef_packed_stream_params psp = {0};

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
        goto RELEASE_PD;
    }

    if (ef_vi_packed_stream_get_params(&vi, &psp) != 0)
    {
        fprintf(stderr, "get params failed.\n");
        goto RELEASE_VI;
    }

    int n_bufs = psp.psp_max_usable_buffers;

    fprintf(stderr, "rxq_size=%d\n", ef_vi_receive_capacity(&vi));
    fprintf(stderr, "evq_size=%d\n", ef_eventq_capacity(&vi));
    fprintf(stderr, "max_fill=%d\n", n_bufs);
    fprintf(stderr, "psp_buffer_size=%d\n", psp.psp_buffer_size);
    fprintf(stderr, "psp_buffer_align=%d\n", psp.psp_buffer_align);
    fprintf(stderr, "psp_start_offset=%d\n", psp.psp_start_offset);
    fprintf(stderr, "psp_max_usable_buffers=%d\n", psp.psp_max_usable_buffers);

    size_t buf_size = psp.psp_buffer_size;
    size_t alloc_size = n_bufs * buf_size;
    alloc_size = ROUND_UP(alloc_size, huge_page_size);

    void *p;
    p = mmap(NULL, alloc_size, PROT_READ | PROT_WRITE,
             /*MAP_ANONYMOUS |*/ MAP_PRIVATE | MAP_HUGETLB, -1, 0);
    if (p == MAP_FAILED)
    {
        fprintf(stderr, "ERROR: mmap failed.  You probably need to allocate some "
                        "huge pages.\n");
        goto RELEASE_VI;
    }

    if (ef_memreg_alloc(&memreg, dh, &pd, dh, p, alloc_size) < 0)
    {
    }

RELEASE_VI:
    ef_vi_free(&vi, dh);

RELEASE_PD:
    ef_pd_free(&pd, dh);

RELEASE_DH:
    ef_driver_close(dh);
}