#! /usr/bin/env python3

import sys
import time

from toniebox.pb.rtnl_pb2 import TonieRtnlLog2, TonieRtnlLog3
import serial

from cobs import cobs

import grpc

# For example : ./serial_decoder.py /dev/ttyUSB0 19200
if len(sys.argv) != 3 and len(sys.argv) != 4:
    print('Usage:')
    print('    {} [Serial Port] [baudrate] (reset-timeout) (serial-timeout)'.format(sys.argv[0]))
    sys.exit(1)

port = sys.argv[1]
baud = int(sys.argv[2])
tReset = 0.0001
tOut = None

if len(sys.argv) >= 4:
    tReset = float(sys.argv[3])

if len(sys.argv) == 5:
    tOut = int(sys.argv[4])


def printData(data):
    try:
        log = TonieRtnlLog2()
        log.ParseFromString(data)
        print(f"{log.field1}, {log.field2}, {log.field3}, {log.field4}, {log.field5}, {log.field6}")
    except Exception as err:
        print(f"printData error len={len(data)}: " + str(err))
        return False
    return True
    


with serial.Serial(port, baud, timeout=tOut) as ser:
    while True:
        data = bytes()
        foundData = False
        while foundData == False:
            timeStart = time.time()
            c = ser.read()
            duration = time.time() - timeStart
            if duration > tReset:
                data = bytes()
                print(f"Timeout reset {duration}s")
            if c == b'':
                data = bytes()
                continue
            with open("serialout.bin", "ab") as file:
                file.write(c)
            dataArray = bytearray(data)
            dataArray.extend(c)
            data = bytes(dataArray)
            message_count = 0
            newData = data
            for restData, pb_message in grpc.parse_grpc_messages(data=data):
                headline = (
                    "###########gRPC message "
                    + str(message_count)
                )
                try:
                    result = grpc.ProtoParser(data=pb_message, parser_options=grpc.ProtoParser.ParserOptions(), rules=[])
                    print(headline)
                    for col1, col2, col3, col4 in result.gen_str_rows():
                    #col1, col2, col3, col4 = grpc.format_table(result).gen_str_rows()
                        print(f"{col1} {col2} {col3} {col4}")
                    #print(result)
                    message_count += 1
                    newData = restData
                except Exception as err:
                    print(f"Error parsing pbm {len(data)}: " + str(err))
                    #data = data[1:]
                    break
            data = newData
