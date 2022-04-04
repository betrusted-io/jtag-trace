#include <sys/types.h>
#include <stdint.h>
uintptr_t pi_mmio_init(off_t base);
int jtag_pins(int tdi, int tms, uintptr_t gpio);
int jtag_prog(char *bitstream, uintptr_t gpio);
void jtag_prog_rbk(char *bitstream, uintptr_t gpio, char *readback);
