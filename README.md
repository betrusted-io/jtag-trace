# jtag tools

An increasingly misnamed collection of utilities to help manipulate
JTAG and parse through recorded traces.

## Tracing
Traces are captured on an MDO4104B-6 using the configuration as
documented at
https://github.com/betrusted-io/betrusted-wiki/wiki/Spartan7-JTAG-Notes
and exported as an "event table" on the "parallel bus".

Traces that match this configuration can be processed with `jtag_trace.py`
to extract the sequence of JTAG commands being executed. Useful for debugging
complicated home-rolled JTAG implementations.

# jtag_gpio

`jtag_gpio` is a collection of tools to manipulate a Xilinx JTAG port
using a Raspberry Pi. The scripts were tested on a Raspberry Pi 3, but
it has a chance of working on other versions since there is an attempt
to detect the version and adjust GPIO block offsets accordingly. This
script relies on CFFI bindings that should auto-build the first time
you run it by running `build.py`. However, if you have trouble with these,
you can always use the `-c` flag to turn on compatibility mode, which
is about 100x slower but is pure-Python.

## Dependencies

The following packages (at least) are needed on an Rpi over a base raspbian install:

```
   sudo apt-get install python3-dev python3-rpi.gpio python3-pip python3-cffi
   pip3 install progressbar2 cffi pycryptodome
```

This package will work best (perhaps relies upon?) a later version of cffi
than shipped in raspbian. Older versions would take ~10ms to allocate an ffi
object and this is punitive when doing page programs.

## FPGA Configuration

`jtag_gpio.py -b` can configure an FPGA. It's reasonably fast,
configuring a XC7A35T in about 3 seconds on a Raspberry Pi 3 using the
default CFFI bindings (a couple minutes using the fallback
compatibility native Python calls only). This compares well to
~1 second to configure the same device using openocd. The advantage
of `jtag_gpio.py` is that it's lightweight and easier to bundle into
a distro of utilities, it's easier to extend and integrate into scripts,
and we're not as fussy about accepting pull requests.

## SPI ROM burning

`jtag_gpio.py --bitstream --spi-mode` or `jtag_gpio.py --raw_binary` can
be used to write a bitstream or a raw binary file to a SPI ROM using
the [bscan_spi_bitstreams](https://github.com/quartiq/bscan_spi_bitstreams)
library. The SPI ROM protocols were adapted from [pyspiflash](https://github.com/eblot/pyspiflash)
but integrated directly in because the PHY isn't an FTDI, it's GPIO on
a Raspberry Pi and also significant modifications are expected to
support the 4-word addressing in the future required by the SPIROM.

The routines are competitive in speed with openocd, and allows us
to get rid of the OpenOCD dependency, with the faustian bargain
of having to deal with a bunch of non-default Python dependencies.
The OpenOCD scripts are left behind in case it turns out that going
the route of Python dependencies was a bad choice compared to going
the route of pulling and building OpenOCD from source to apply
specific patches that allow it to work in our configuration.

## JTAG Scripting

`jtag_gpio.py` runs a small scripting language that can execute
JTAG commands. It's capable of loading commands into the IR,
writing data into the DR, reading data from the DR, as well as
some pseudo-commands such as wait delays, idling, and directives
that modify IR/DR behavior. Here's the short list of verbs supported:

* dr -- load data register (default timings)
* ir -- load instructior register (default timings)
* rs -- push several TMS=1 cycles to bring state machine into "TEST-LOGIC-RESET"
* dl -- pause a few milliseconds
* id -- idle a cycle in "RUN-TEST/IDLE" (undefined behavior if inserted not in idle state)
* irp -- load IR, but pause for one cycle
* ird -- load IR, and transition directly to DR state without going through RUN-TEST/IDLE
* drc -- MSB-to-LSB ordering of DR data; optimize for speed by skipping tdo readout
* drr -- recover DR register into a special global holding register

All commands have a format of

`verb, bits, payload, note`

* `verb` is the verb from the above list
* `bits` is the number of bits in the payload
* `payload` is the data or instruction to be shifted in by the corresponding verb
* `note` is an arbitrary string used to describe the command to aid with debugging

`jtag.jtg` and `readout.jtg` contain examples of how to write JTAG scripts.

The `bbramtest.jtg` contains an example of how to burn the BBRAM with
the encryption key described in `bbramtest.nky` (provided so it's easy to
see the mapping of key bits to `ISC_PROGRAM` arguments). Note that the BBRAM key
burning procedure setup (from JPROGRAM to PROGRAM_KEY) is very sensitive
to timing: some commands need to go through a pause state, while others
require extra wait states in between command sequences. The pauses are
accomplished using the `irp` and `id` command verbs. 

## WBSTAR (Starbleed) Exploiting

AES encrypted bitstream and no key? No problem (unfortunately, or
fortunately, depending on which hat you happen to be wearing
today). Read about the "Starbleed" exploit (which is referred to as
the "WBSTAR" exploit in this code) at
https://www.usenix.org/system/files/sec20fall_ender_prepub.pdf.

In a nutshell, it uses a register that persists across reboots (WBSTAR) to recover
data decrypted by the FPGA's AES engine. This is possible thanks to:

1. Known and reliable plaintext patterns in the config setup for the WBSTAR register load
2. AES CBC malleability allowing the offset of the WBSTAR regsiter load to be adjusted
3. The FPGA not fully authenticating config commands before running them: partial
corruption of the bitstream does not prevent command execution
4. The ability to execute unencrypted config commands to readout WBSTAR even on
encrypted devices (this allowed because they also use the config command to
readout ID codes, config status, etc.)

If you have a copy of the encrypted binary, and an FPGA that has been fused
with a key to decrypt it, you can recover the plantext of the binary (without
knowing the key -- you just use the FPGA as a decryption oracle) using the
`jtag_gpio -w` command (you also have to specify the AES block number and
the encrypted filename, see the command help).

The current implementation is an "effective PoC" in that it can
quickly recover any 128-bit AES block, but it's probably too slow to
be practically used to decrypt an entire bitstream (it's pretty easy
to speed it up substantially, but the purpose for writing the tool is
to test the efficacy of WBSTAR mitigations). However, it's certainly
more than sufficient to extract LUT and BRAM init data that are in
well-known locations.

There is also a `-i` command modifier which takes in a `.nky` key
specifier file to produce encrypted readout commands. Normally this is
not available to attackers, but was implemented as a PoC to confirm
that an omniscient attacker that can craft any readback bitstream can
not work around certain fuse settings. The `-p` command identifier
also does some fuzzing around readback timings; partial disclosure of
some non-confidential pieces of data seem possible with the right
timing parameters, discoverable through fuzzing.
