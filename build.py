#!/usr/bin/python3

# sudo apt-get install python3-cffi
from cffi import FFI

ffibuilder = FFI()
ffibuilder.cdef("volatile uint32_t *pi_mmio_init(uint32_t base); int jtag_pins(int tdi, int tms, volatile uint32_t *gpio); int jtag_prog(char *bitstream, volatile uint32_t *gpio); void jtag_prog_rbk(char *bitstream, volatile uint32_t *gpio, char *readback);")
ffibuilder.set_source("gpioffi", '#include "gpio-ffi.h"', sources=["gpio-ffi.c"])
ffibuilder.compile()
