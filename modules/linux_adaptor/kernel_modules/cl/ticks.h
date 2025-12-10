#ifndef _CL_TICKS_H_
#define _CL_TICKS_H_

#define CSR_TIME		0xc01

static inline uint64_t get_ticks(void)
{
    return csr_read(CSR_TIME);
}

#endif /* _CL_TICKS_H_ */
