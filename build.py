#!/usr/bin/python3

# sudo apt-get install python3-cffi
from cffi import FFI

ffibuilder = FFI()
ffibuilder.cdef("unsigned int pi_mmio_init(unsigned int base); int jtag_pins(int tdi, int tms, unsigned int gpio); int jtag_prog(char *bitstream, unsigned int gpio); void jtag_prog_rbk(char *bitstream, unsigned int gpio, char *readback);")
ffibuilder.set_source("gpioffi", '#include "gpio-ffi.h"', sources=["gpio-ffi.c"])
ffibuilder.compile()
