#! /usr/bin/env python
#
# Echoes the serial terminal via XBee

import logging
import serial
import sys
from collections import defaultdict
import asyncio
import time
import binascii
import struct
import signal

from xbee import ZigBee

out_logger = logging.getLogger('sent')
in_logger = logging.getLogger('received')
input_buffers = defaultdict(list)
serial_port = None

def print_output(data):
    in_logger.info(data)

XBEE_DEVICES = {
    0x0013A200409F3F0C: {
    },
    0x0013A20040D96797: {
        "handler": print_output,
        "buffer_input": True,
    },
}

class MsgCounterHandler(logging.StreamHandler):
    """Logging handler which keeps an internal count of messages.
    """
    def __init__(self, *args, **kwargs):
        super(MsgCounterHandler, self).__init__(*args, **kwargs)
        self._counts = defaultdict(lambda: defaultdict(int))

    def emit(self, record):
        record.count = self._counts[record.name][record.levelname]
        super(MsgCounterHandler, self).emit(record)
        self._counts[record.name][record.levelname] += 1

def buffer_input_data(addr, data, cb):
    """Buffers the incoming data in an array buffer until a newline character is encountered, then
    calls the provided callback function with the resulting data
    """
    str_data = data.decode()
    for c in str_data:
        input_buffers[addr].append(c)
        if c == '\n' or c == '\r':
            cb("".join(input_buffers[addr]))
            del input_buffers[addr]

def connect(port, handler, baud=9600):
    """Serial connects to the `port` specified, then starts the Zigbee link

    Args:
        port (String): serial port to connect to
        handler (Function): handler to call when data frames are received from xbee
        baud (Int): serial baud rate to communicate with Xbee with

    Returns:
        tuple of `(serial_port, xbee)`
    """
    serial_port = serial.Serial(port, baud)
    xbee = ZigBee(serial_port, callback=handler)
    return serial_port, xbee

def process_frame(data):
    """Async handler to process a received Zigbee API frame

    Args:
        data (Dict): received data frame
    """
    if data['id'] == 'rx':
        source = struct.unpack('>Q', data["source_addr_long"])[0]
        try:
            dev = XBEE_DEVICES[source]
            handler = dev["handler"]

            if dev["buffer_input"] is True:
                buffer_input_data(source, data["rf_data"], handler)
            else:
                handler(data["rf_data"])
        except KeyError:
            in_logger.error("No xbee device with address {:016X}found, unable to process received "
                            "frame".format(source))

def configure_logging():
    """Configure custom format logging for input and output messages.
    """
    formatter = logging.Formatter('%(name)s (%(asctime)s.%(msecs)03d) [%(count)s]: %(message)s',
                                  datefmt='%Y-%m-%dT%H:%M:%S')

    stdout_handler = MsgCounterHandler(sys.stdout)
    stdout_handler.setFormatter(formatter)

    out_logger.addHandler(stdout_handler)
    in_logger.addHandler(stdout_handler)

    out_logger.setLevel(logging.INFO)
    in_logger.setLevel(logging.INFO)

def process_input(q):
    """Simply processes stdin and adds to a queue to be sent
    """
    asyncio.async(q.put(sys.stdin.readline()))

async def send_data(xbee, addr, q, buffer_time=500):
    """Sends data over the radio
    """
    byte_addr = binascii.unhexlify("{:016X}".format(addr))
    print("Echoing input to 0x{:016X}...".format(addr))

    def _send(data):
        out_logger.info(''.join(data))
        xbee.send("tx", dest_addr=bytes([0xFF, 0xFE]), dest_addr_long=byte_addr,
                  data=bytes(data, 'utf8'))

    while 1:
        new_data = await q.get()
        _send(new_data)

def start_event_loop(xbee, receiving_device):
    """Starts the main event loop to listen for input over the radios & handle data
    """
    send_queue = asyncio.Queue()
    received_queue = asyncio.Queue()

    loop = asyncio.get_event_loop()
    loop.add_reader(sys.stdin, process_input, send_queue)

    loop.add_signal_handler(signal.SIGINT, exit)

    #loop.run_forever()
    loop.run_until_complete(send_data(xbee, receiving_device, send_queue))

def exit():
    """Exit the program
    """
    serial_port.close()
    print("Well, that was fun. Exiting now...")
    sys.exit(0)

def main():
    """Main program function
    """
    global serial_port

    # TODO: parse CLI args
    opts = {
        "port": "/dev/tty.usbserial-AD01SUG5",
        "baud_rate": 9600,
    }
    configure_logging()
    serial_port, xbee = connect(opts["port"], process_frame, opts["baud_rate"])
    start_event_loop(xbee, 0x0013A20040D96797)

if __name__ == '__main__':
    main()
