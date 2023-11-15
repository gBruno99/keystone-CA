#ifndef _CUSTOM_RISCV_TIME_
#define _CUSTOM_RISCV_TIME_

#ifdef __cplusplus
extern "C" {
#endif

#define PERFORMANCE_TEST 1

typedef unsigned long ticks_t;

ticks_t get_time_inline(void);

#ifdef __cplusplus
}
#endif

#endif
