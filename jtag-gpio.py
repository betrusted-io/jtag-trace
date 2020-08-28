#!/usr/bin/python3

try:
    import RPi.GPIO as GPIO
except RuntimeError:
    print("Error importing RPi.GPIO! Did you run as root?")

import csv
import argparse
import time

from enum import Enum

class JtagLeg(Enum):
    DR = 0
    IR = 1
    RS = 2 # reset
    DL = 3 # long delay
    ID = 4 # idle in run-test
    IRP = 5  # IR with pause
    IRD = 6  # transition to IR directly

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
in_cfg = False

TCK_pin = 4
TMS_pin = 17
TDI_pin = 27  # TDI on FPGA, out for this script
TDO_pin = 22  # TDO on FPGA, in for this script


def phy_sync(tdi, tms):
    global TCK_pin, TMS_pin, TDI_pin, TDO_pin
    tdo = GPIO.input(TDO_pin) # grab the TDO value before the clock changes
    
    GPIO.output( (TCK_pin, TDI_pin, TMS_pin), (0, tdi, tms) )
    GPIO.output( (TCK_pin, TDI_pin, TMS_pin), (1, tdi, tms) )
    GPIO.output( (TCK_pin, TDI_pin, TMS_pin), (0, tdi, tms) )

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
    global in_cfg
    
    if len(cur_leg[1]) < 384:
        print("start: ", cur_leg, "(", decode_ir(int(cur_leg[1],2)), ") / ", cur_leg[2] )
        if decode_ir(int(cur_leg[1],2)) == 'CFG_IN' or decode_ir(int(cur_leg[1],2)) == 'CFG_OUT':
            print("in config")
            in_cfg = True
        else:
            if cur_leg[0] != JtagLeg.DR:
                print("out of config")
                in_cfg = False
    else:
        print("start: ", cur_leg[0], ' large data of length ', str(len(cur_leg[1])))

# take a trace and attempt to extract IR, DR values
# assume: at the start of each 'trace' we are coming from TEST-LOGIC-RESET
def jtag_step():
    global state
    global cur_leg
    global jtag_legs
    global jtag_results
    global tdo_vect
    global do_pause
    global in_cfg

    # print(state)
    if state == JtagState.TEST_LOGIC_RESET:
        phy_sync(0, 0)
        state = JtagState.RUN_TEST_IDLE

    elif state == JtagState.RUN_TEST_IDLE:
        if len(cur_leg):
            # print(cur_leg[0])
            if cur_leg[0] == JtagLeg.DR:
                phy_sync(0, 1)
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
                print("tms reset")
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
                state = JtagState.TEST_LOGIC_RESET
                cur_leg = jtag_legs.pop(0)
                debug_spew(cur_leg)
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
        if in_cfg and cur_leg[0] == JtagLeg.DR:
            print('in config, shifting in MSB order')
            # print(cur_leg[1])
            for bit in cur_leg[1][:-1]:
                if bit == '1':
                    tdi = 1
                else:
                    tdi = 0
                phy_sync(tdi, 0) # skip recording the output
                state = JtagState.SHIFT

            if cur_leg[-1:] == '1':
                tdi = 1
            else:
                tdi = 0
            cur_leg = ''
            phy_sync(tdi, 0) # skip recording the output
            tdo_vect = '0'
            state = JtagState.EXIT1
            print('leaving config')
            
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
        print("pause")
        # we could put more pauses in here but we haven't seen this needed yet
        phy_sync(0, 1)        
        state = JtagState.EXIT2

    elif state == JtagState.EXIT2:
        phy_sync(0, 1)        
        state = JtagState.UPDATE

    elif state == JtagState.UPDATE:
        phy_sync(0, 0)        
        jtag_results.append(int(tdo_vect, 2)) # interpret the vector and save it
        print("result: ", hex(int(tdo_vect, 2)) )
        tdo_vect = ''

        state = JtagState.RUN_TEST_IDLE
        # handle case of "shortcut" to DR
        if len(jtag_legs):
            if (jtag_legs[0][0] == JtagLeg.DR) or (jtag_legs[0][0] == JtagLeg.IRP) or (jtag_legs[0][0] == JtagLeg.IRD):
                if jtag_legs[0][0] == JtagLeg.IRP or jtag_legs[0][0] == JtagLeg.IRD:
                    phy_sync(0, 1)  # +1 cycle on top of the DR cycle below
                    print("IR bypassing wait state")
                if jtag_legs[0][0] == JtagLeg.IRP:
                    do_pause = True
                    
                cur_leg = jtag_legs.pop(0)
                debug_spew(cur_leg)
                phy_sync(0,1)
                state = JtagState.SELECT_SCAN

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
        
        jtag_legs.append([JtagLeg.IR, '001001', 'idcode'])
        jtag_legs.append([JtagLeg.DR, '00000000000000000000000000000000', ' '])
        jtag_legs.append([JtagLeg.RS, '0', 'reset'])
        jtag_legs.append([JtagLeg.IRD, '000101', 'cfg_in'])
        jtag_legs.append([JtagLeg.DR, config_data, 'config_data'])
        jtag_legs.append([JtagLeg.RS, '0', 'reset'])
        jtag_legs.append([JtagLeg.IR, '001001', 'idcode'])
        jtag_legs.append([JtagLeg.DR, '00000000000000000000000000000000', ' '])

        
        
def main():
    global TCK_pin, TMS_pin, TDI_pin, TDO_pin
    global jtag_legs, jtag_results
    
    parser = argparse.ArgumentParser(description="Drive JTAG via Rpi GPIO")
    parser.add_argument(
        "-f", "--file", required=True, help="file containing jtag command list", type=str
    )
    parser.add_argument(
        "-b", "--bitstream", default=False, action="store_true", help="input file is a bitstream, not a JTAG command set"
    )
    args = parser.parse_args()

    ifile = args.file

    GPIO.setmode(GPIO.BCM)

    GPIO.setup((TCK_pin, TMS_pin, TDI_pin), GPIO.OUT)
    GPIO.setup(TDO_pin, GPIO.IN)

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
               (chain != 'id') & (chain != 'irp') & (chain != 'ird'):
                print('unknown chain type ', chain, ' aborting!')
                GPIO.cleanup()
                exit(1)

            # print('found JTAG chain ', chain, ' with len ', str(length), ' and data ', hex(value))
            if chain == 'rs':
                jtag_legs.append([JtagLeg.RS, '0', '0'])
            elif chain == 'dl':
                jtag_legs.append([JtagLeg.DL, '0', '0'])
            elif chain == 'id':
                jtag_legs.append([JtagLeg.ID, '0', '0'])

            else:
                if chain == 'dr':
                    code = JtagLeg.DR
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
    # print(jtag_legs)

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
