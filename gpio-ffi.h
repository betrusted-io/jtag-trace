#include <sys/types.h>
#include <stdint.h>
uintptr_t pi_mmio_init(off_t base);
int jtag_pins(int tdi, int tms, unsigned int gpio);
int jtag_prog(char *bitstream, unsigned int gpio);
void jtag_prog_rbk(char *bitstream, unsigned int gpio, char *readback);
