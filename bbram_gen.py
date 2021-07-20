#!/usr/bin/python3

import sys
import argparse
import os
from textwrap import wrap

def main():
    parser = argparse.ArgumentParser(description="Generate a `.jtg` format BBRAM programming script from a `.nky` file")
    parser.add_argument(
        "-k", "--key-file", required=True, help=".nky file containing the desired BBRAM key. Must end in .nky.", type=str
    )
    args = parser.parse_args()

    basename = os.path.splitext(args.key_file)[0]

    with open(basename + '.jtg', 'w') as ofile:
        with open(args.key_file, 'r') as nky:
            for lines in nky:
                line = lines.split(' ')
                if line[1] == '0':
                    nky_key = line[2].rstrip().rstrip(';')
            #print(nky_key)
            keyfrags = wrap(nky_key, 8) # split key into 8 x 8 groups of words

            if len(keyfrags) != 8:
                print("Key has wrong length in .nky, please check format.")
                exit(1)
            for frag in keyfrags:
                #print("{}".format(frag))
                if len(frag) != 8:
                    print("Key fragment '{}' has wrong length, please check .nky format.".format(frag))
                    exit(1)

            ofile.write("""
rs, 0, 0
dl, 0, 0

ir, 6, 0b001011, jpgrogram
ir, 6, 0b010100, isc_noop
ir, 6, 0b010100, isc_noop
# the pause in the IR state for isc_enable is critical
irp, 6, 0b010000, isc_enable
dr, 5, 0b10101
id, 0, 0
id, 0, 0
id, 0, 0
id, 0, 0
id, 0, 0
id, 0, 0
id, 0, 0
id, 0, 0
id, 0, 0
id, 0, 0
id, 0, 0
id, 0, 0
dr, 5, 0b10101

ir, 6, 0b010010, program_key
# the one-cycle delay between program_key and dr is critical
id, 0, 0
dr, 32, 0xffffffff
id, 0, 0
id, 0, 0
id, 0, 0
id, 0, 0
id, 0, 0
id, 0, 0
id, 0, 0
id, 0, 0
id, 0, 0
id, 0, 0
id, 0, 0
id, 0, 0

ir, 6, 0b010001, isc_program
dr, 32, 0x557b
""")
            for frag in keyfrags:
                ofile.write("ir, 6, 0b010001, isc_program\n")
                ofile.write("dr, 32, 0x{}\n".format(frag))
            ofile.write("""
ir, 6, 0b010101, bbkey_rbk
dr, 37, 0x1fffffffff
ir, 6, 0b010101, bbkey_rbk
dr, 37, 0x1fffffffff
ir, 6, 0b010101, bbkey_rbk
dr, 37, 0x1fffffffff
ir, 6, 0b010101, bbkey_rbk
dr, 37, 0x1fffffffff
ir, 6, 0b010101, bbkey_rbk
dr, 37, 0x1fffffffff
ir, 6, 0b010101, bbkey_rbk
dr, 37, 0x1fffffffff
ir, 6, 0b010101, bbkey_rbk
dr, 37, 0x1fffffffff
ir, 6, 0b010101, bbkey_rbk
dr, 37, 0x1fffffffff
ir, 6, 0b010101, bbkey_rbk
dr, 37, 0x1fffffffff

ir, 6, 0b010110, isc_disable
id, 0, 0
id, 0, 0
id, 0, 0
id, 0, 0
id, 0, 0
id, 0, 0
id, 0, 0
id, 0, 0
id, 0, 0
id, 0, 0
id, 0, 0
id, 0, 0
rs, 0, 0
id, 0, 0,
id, 0, 0,
id, 0, 0,
id, 0, 0,
id, 0, 0,
ir, 6, 0b111111, bypass
dl, 0, 0
ir, 6, 0b111111, bypass
            """)
            print("`.jtg` script generation successful")
            print("run `jtag_gpio.py -f {}` to apply the bbram key to the FPGA".format(basename + '.jtg'))

if __name__ == "__main__":
    main()
