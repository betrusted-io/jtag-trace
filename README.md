A collection of utilities to help manipulate and parse through JTAG traces.

These traces are captured on an MDO4104B-6 using the configuration as documented at https://github.com/betrusted-io/betrusted-wiki/wiki/Spartan7-JTAG-Notes and exported as an "event table" on the "parallel bus".

There is also a script, jtag-gpio.py, which can be used to execute scripted
JTAG commands, and to configure the FPGA. With FFI bindings, it can configure
an FPGA in about 3 seconds on a Rapsberry Pi.
