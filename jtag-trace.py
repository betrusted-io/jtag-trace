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

# take a trace and attempt to extract IR, DR values
# assume: at the start of each 'trace' we are coming from TEST-LOGIC-RESET
def jtag_mach(jtag_trace):
    global state

    reg_in = []
    reg_out = []
    leg = JtagLeg.DR
    pause = 0
    loopbacks = 0

    for cycle in jtag_trace:
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

        elif state == JtagState.SELECT_IR_SCAN:
            leg = JtagLeg.IR
            if cycle['tms']:
                state = JtagState.TEST_LOGIC_RESET
                continue
            else:
                state = JtagState.CAPTURE

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
            if pause > 0 | loopbacks > 0:
                print('Pauses: ', str(pause), '; loopbacks: ', str(loopbacks))
            if leg == JtagLeg.DR:
                print( 'Host -> DR: ', end='')
            else:
                print( 'Host -> IR: ', end='')
            for bit in reversed(reg_in):  # this assumes data appears on JTAG TDI in LSB-first order
                if bit:
                    print('1', end='')
                else:
                    print('0', end='')
            print(' ')

            if leg == JtagLeg.DR:
                print( 'DR -> Host: ', end='')
            else:
                print( 'IR -> Host: ', end='')
            for bit in reversed(reg_out):
                if bit:
                    print('1', end='')
                else:
                    print('0', end='')
            print(' ')

            if cycle['tms']:
                state = JtagState.SELECT_DR_SCAN
            else:
                state = JtagState.RUN_TEST_IDLE
            continue

        else:
            print("Illegal state encountered!")
            continue

def main():
    parser = argparse.ArgumentParser(description="Parse JTAG waveform")
    parser.add_argument(
        "-f", "--file", required=True, help="filename to process", type=str
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

            jtag_trace += [{'tdi': tdi, 'tms': tms, 'tdo': tdo}]
            last_time = float(row[0])

    for packet in jtag_packets:
        print('\n**** Start packet at ', "{:.3f}".format(packet['start'] * 1000), 'ms')
        jtag_mach(packet['trace'])



if __name__ == "__main__":
    main()