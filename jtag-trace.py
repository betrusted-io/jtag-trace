#!/usr/bin/python3

import csv
import argparse

from enum import Enum

class JtagLeg(Enum):
    DR = 0
    IR = 1

class JtagState(Enum):
    TEST_LOGIC_RESET = 0
    RUN_TEST_IDLE = 1
    SELECT_DR_SCAN = 2
    CAPTURE = 3
    SHIFT = 4
    EXIT1 = 5
    PAUSE = 6
    EXIT2 = 7
    UPDATE = 8
    SELECT_IR_SCAN = 9

state = JtagState.RUN_TEST_IDLE

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
    elif ir == 0b110000:
        return 'EFUSE_CMD'
    else:
        return ''  # unknown just leave blank for now

def debug_jtag(jtag_trace, index=0):
    print('tms: ', end='')
    for cycle in jtag_trace[index:]:
        if cycle['tms']:
            print('1', end='')
        else:
            print('0', end='')
    print(' ')
    print('tdi: ', end='')
    for cycle in jtag_trace[index:]:
        if cycle['tdi']:
            print('1', end='')
        else:
            print('0', end='')
    print(' ')


def format_output(jtag_trace, cycle, departing_index, pause, loopbacks, leg, reg_in, reg_out):
    #            if len(reg_in) < 6:
    #debug_jtag(jtag_trace, departing_index)

    if pause > 0 | loopbacks > 0:
        print('Pauses: ', str(pause), '; loopbacks: ', str(loopbacks))
    if leg == JtagLeg.DR:
        print('Host->DR: ', end='')
    else:
        print('Host->IR: ', end='')

    ir = 0
    for bit in reversed(reg_in):  # this assumes data appears on JTAG TDI in LSB-first order
        ir <<= 1
        if bit:
            print('1', end='')
            ir |= 1
        else:
            print('0', end='')
    if leg == JtagLeg.IR:
        print(' (', decode_ir(ir), ')', end='')
    else:
        print(' (', hex(ir), ')', end='')
    if cycle:
        print(" ({:.3f}".format(cycle['time'] * 1000), 'ms)', end='')
    print(' ')

    if leg == JtagLeg.DR:
        print('DR->Host: ', end='')
    else:
        print('IR->Host: ', end='')
    reg = 0
    for bit in reversed(reg_out):
        reg <<= 1
        if bit:
            print('1', end='')
            reg |= 1
        else:
            print('0', end='')
    if leg == JtagLeg.DR:
        print(' (', hex(reg), ')', end='')
    print(' ')

# take a trace and attempt to extract IR, DR values
# assume: at the start of each 'trace' we are coming from TEST-LOGIC-RESET
def jtag_mach(jtag_trace):
    global state

    reg_in = []
    reg_out = []
    leg = JtagLeg.DR
    pause = 0
    loopbacks = 0
    index = -1
    departing_index = 0

    for cycle in jtag_trace:
        # print(state)
        index = index + 1
        if state == JtagState.TEST_LOGIC_RESET:
            if cycle['tms']:
                continue
            else:
                state = JtagState.RUN_TEST_IDLE
                continue

        elif state == JtagState.RUN_TEST_IDLE:
            reg_in = []  # reset all state variables
            reg_out = []
            pause = 0
            loopbacks = 0
            leg = JtagLeg.DR
            departing_index = index
            if cycle['tms']:
                state = JtagState.SELECT_DR_SCAN
                continue
            else:
                continue

        elif state == JtagState.SELECT_DR_SCAN:
            leg = JtagLeg.DR
            if cycle['tms']:
                state = JtagState.SELECT_IR_SCAN
                continue
            else:
                state = JtagState.CAPTURE
                continue

        elif state == JtagState.SELECT_IR_SCAN:
            leg = JtagLeg.IR
            if cycle['tms']:
                state = JtagState.TEST_LOGIC_RESET
                continue
            else:
                state = JtagState.CAPTURE
                continue

        elif state == JtagState.CAPTURE:
            if cycle['tms']:
                state = JtagState.EXIT1
                continue
            else:
                state = JtagState.SHIFT
                continue

        elif state == JtagState.SHIFT:
            reg_in += [cycle['tdi']]
            reg_out += [cycle['tdo']]
            if cycle['tms']:
                state = JtagState.EXIT1
            continue

        elif state == JtagState.EXIT1:
            if cycle['tms']:
                state = JtagState.UPDATE
                continue
            else:
                state = JtagState.PAUSE
                continue

        elif state == JtagState.PAUSE:
            pause += 1
            if cycle['tms']:
                state = JtagState.EXIT2
            continue

        elif state == JtagState.EXIT2:
            if cycle['tms']:
                state = JtagState.UPDATE
            else:
                state = JtagState.SHIFT
                loopbacks += 1
            continue

        elif state == JtagState.UPDATE:
            format_output(jtag_trace, cycle, departing_index, pause, loopbacks, leg, reg_in, reg_out)
            if cycle['tms']:
                state = JtagState.SELECT_DR_SCAN
                # recycle all parameters as we are entering a leg select again
                reg_in = []
                reg_out = []
                pause = 0
                loopbacks = 0
                leg = JtagLeg.DR
                departing_index = index
                continue
            else:
                state = JtagState.RUN_TEST_IDLE
                continue

        else:
            print("Illegal state encountered!")
            continue

    if state == JtagState.UPDATE:
        format_output(jtag_trace, False, departing_index, pause, loopbacks, leg, reg_in, reg_out)
        # From a TMS standpoint, it's isomorphic to move to RUN_IDLE; but if we leave it in UPDATE then the
        # next call into the loop will print all the output again, which is incorrect
        state = JtagState.RUN_TEST_IDLE


def main():
    global state

    parser = argparse.ArgumentParser(description="Parse JTAG waveform")
    parser.add_argument(
        "-f", "--file", required=True, help="filename to process", type=str
    )
    parser.add_argument(
        "-s", "--salae-format", default=False, action="store_true", help="Use Salae logic analyzer format"
    )
    args = parser.parse_args()

    ifile = args.file

    # I think we want a format like {tdi: 0, tdo: 1, tms: 0}  for a jtag trace
    # And traces should be stored as a format of {start: 13.36e-4, series: {jtag_series}} (this is a packet)
    jtag_packets = []
    with open(ifile) as csvfile:
        reader = csv.reader(csvfile, delimiter=',')
        last_time = 0.0
        last_series = 0.0
        first = True
        jtag_trace = []

        if args.salae_format == False:
            print("CSV header data:")
            print(reader.__next__())
            print(reader.__next__())
            print(reader.__next__())

            for row in reader:
                if first:
                    first = False
                    last_time = float(row[0])
                    last_series = last_time

                # store the packet if a new one is found, and create a new packet
                if float(row[0]) > (float(last_time) + 350.0e-6):  # greater than 350us "gap" is a heuristic for the start of a new JTAG series
                    jtag_packets += [{'start' : last_series, 'trace' : jtag_trace}]
                    last_series = float(row[0])
                    jtag_trace = []

                # otherwise add on to the current packet
                bus = int(row[1])
                if bus & 4:
                    tdi = True
                else:
                    tdi = False
                if bus & 2:
                    tms = True
                else:
                    tms = False
                if bus & 1:
                    tdo = True
                else:
                    tdo = False

                jtag_trace += [{'tdi': tdi, 'tms': tms, 'tdo': tdo, 'time': float(row[0])}]
                last_time = float(row[0])
        else:
            print("Salae format CSV header data:")
            print(reader.__next__())

            tclk_last = False
            for row in reader:
                if first:
                    first = False
                    last_time = float(row[0])
                    last_series = last_time
                    if int(row[1]) == 1:
                        tclk_last = True
                    else:
                        tclk_last = False

                # store the packet if a new one is found, and create a new packet
                if float(row[0]) > (float(
                        last_time) + 350.0e-6):  # greater than 350us "gap" is a heuristic for the start of a new JTAG series
                    jtag_packets += [{'start': last_series, 'trace': jtag_trace}]
                    last_series = float(row[0])
                    jtag_trace = []

                if (int(row[1]) == 1) and tclk_last == False:
                    tclk_last = True

                    # otherwise add on to the current packet
                    if int(row[4]) == 1:
                        tdi = True
                    else:
                        tdi = False
                    if int(row[3]) == 1:
                        tms = True
                    else:
                        tms = False
                    if int(row[2]) == 1:
                        tdo = True
                    else:
                        tdo = False

                    jtag_trace += [{'tdi': tdi, 'tms': tms, 'tdo': tdo, 'time': float(row[0])}]
                    last_time = float(row[0])
                elif (int(row[1]) == 0) and tclk_last == True: # falling edge
                    tclk_last = False

    for packet in jtag_packets:
        #print('\n**** Start packet at ', "{:.3f}".format(packet['start'] * 1000), 'ms')
        #print(packet['trace'])
        jtag_mach(packet['trace'])



if __name__ == "__main__":
    main()
