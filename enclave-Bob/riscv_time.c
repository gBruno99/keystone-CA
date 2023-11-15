#include "riscv_time.h"

ticks_t get_time_inline(void)
{
	ticks_t n;

	__asm__ __volatile__ (
		"rdtime %0"
		: "=r" (n));
	return n;
}
