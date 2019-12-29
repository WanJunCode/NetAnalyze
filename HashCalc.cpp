#include "HashCalc.h"

void HashCalc::Getrnd()
{
    struct timeval s;
    uint32_t *ptr;
    int fd = open ("/dev/urandom", O_RDONLY);
    if (fd != -1)
    {
        read (fd, xorr, 12);
        read (fd, perm, 12);
        close (fd);
        return;
    }

    gettimeofday (&s, 0);
    srand (s.tv_usec);
    ptr = (u_int *) xorr;
    *ptr = rand ();
    *(ptr + 1) = rand ();
    *(ptr + 2) = rand ();
    ptr = (u_int *) perm;
    *ptr = rand ();
    *(ptr + 1) = rand ();
    *(ptr + 2) = rand ();
}

int HashCalc::Init(uint64_t iSize)
{
    iHashTableSize = iSize;
    printf("HashCalc iHashTableSize = %lu\n",iHashTableSize);
    int i, n, j;
    int p[12];
    Getrnd();
    for (i = 0; i < 12; i++)
    {
        p[i] = i;
    }

    for (i = 0; i < 12; i++)
    {
        n = perm[i] % (12 - i);
        perm[i] = p[n];
        for (j = 0; j < 11 - n; j++)
        {
            p[n + j] = p[n + j + 1];
        }
    }

    return 0;
}

uint32_t HashCalc::CalcHashValue(uint32_t saddr, uint32_t daddr, uint16_t sport, uint16_t dport)
{
    uint32_t iHashValue;
    u_int res = 0;
    int i;
    u_char data[12];
    u_int *stupid_strict_aliasing_warnings=(u_int*)data;
    *stupid_strict_aliasing_warnings = saddr;
    *(u_int *) (data + 4) = daddr;
    *(u_short *) (data + 8) = sport;
    *(u_short *) (data + 10) = dport;
    for (i = 0; i < 12; i++)
    {
        res = ( (res << 8) + (data[perm[i]] ^ xorr[i])) % 0xff100f;  
    }
    iHashValue = res & (iHashTableSize - 1);
    return iHashValue;
}