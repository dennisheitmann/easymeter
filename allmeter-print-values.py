#!/usr/bin/python3
import sys
import re
import serial
import logging
import time
import json
import datetime
import os
import binascii
from typing import Tuple, Optional, Union, Any

CONFIG = {'dev': '/dev/ttyUSB0',
          'utc': True,
         } 

TS_FORMAT = '%Y-%m-%d %H:%M:%S'

logging.basicConfig(
    level = logging.INFO,
    format = '%(asctime)s - %(levelname)s - %(message)s',
    datefmt = TS_FORMAT
)

def signed_conversion(value: int, bits: int) -> int:
    """ Converts an unsigned integer (from hex) to a signed integer using two's complement. """
    if value is None:
        return None
    # Check if the MSB is set (i.e., value is negative)
    if value & (1 << (bits - 1)):
        # Calculate the negative value: value - 2^bits
        return value - (1 << bits)
    return value

# CRC class definition
class SmlCrc:
    """ Class for Smart Message Language (SML) CRC calculation. """
    def __init__(self):
        self.crc_table = [] 
        self.crc_init()
    def crc_init(self):
        """ Init the crc look-up table for byte-wise crc calculation. """
        polynom = 0x8408     # CCITT Polynom reflected
        self.crc_table = []
        for byte in range(256):
            crcsum = byte
            for bit in range(8):  # for all 8 bits
                if crcsum & 0x01:
                    crcsum = (crcsum >> 1) ^ polynom
                else:
                    crcsum >>= 1
            self.crc_table.append(crcsum)
    def crc(self, data):
        """ Calculate CCITT-CRC16 checksum byte by byte. """
        crcsum = 0xFFFF
        for byte in data:
            idx = byte ^ (crcsum & 0xFF)
            crcsum = self.crc_table[idx] ^ (crcsum >> 8)
        return crcsum ^ 0xFFFF
        
sml = SmlCrc()

# Define the SML markers
SML_START = b'\x1b\x1b\x1b\x1b\x01\x01\x01\x01'
SML_END = b'\x1b\x1b\x1b\x1b\x01'

def read() -> Tuple[bool, bytes]:
    """
    Reads a complete SML datagram by searching for its start and end markers.
    """
    try:
        with serial.Serial(
            port=CONFIG['dev'],
            baudrate=9600,
            parity=serial.PARITY_NONE,
            stopbits=serial.STOPBITS_ONE,
            bytesize=serial.EIGHTBITS,
            timeout=5.0,  # Increased timeout for reliable reading
            exclusive=True
        ) as ser:
            # Search for the SML START sequence
            # Read enough data to ensure the buffer is current, looking for the start
            partial_reading = ser.read(100)
            if not partial_reading:
                return (False, b"Error: No data read from serial port.")
            # Find the position of the actual SML start marker
            start_index = partial_reading.find(SML_START)
            if start_index == -1:
                # Did not find the start sequence in the initial buffer check
                time.sleep(0.25)
                ser.reset_input_buffer()
                return (False, b"No SML start detected")
            # Extract and store the starting chunk
            # The start sequence might be preceded by garbage, so capture from the start index
            start_data = partial_reading[start_index:]
            # Read the rest of the message until the SML END sequence
            # We must use read_until on the *rest* of the message after the start sequence.
            # We use an alternative approach for robustness: read_until the END marker.
            # Flush existing data if any, and read everything up to the END marker
            # This read will include the END marker itself.
            body_and_end = ser.read_until(SML_END)
            if not body_and_end.endswith(SML_END):
                # The read_until timed out before finding the END marker.
                return (False, start_data + body_and_end)
            # Assemble the complete datagram
            complete_datagram = start_data + body_and_end
            # Reset buffer for the next call
            ser.reset_input_buffer()
            return (True, complete_datagram)
    except serial.SerialException as e:
        return (False, str(e).encode('utf-8'))

def extract_sml_reading(message: str, obis_pattern: str, length: int) -> Optional[int]:
    """
    Finds the 8/16-digit (4/8-byte) hex value associated with an OBIS code
    and converts it to a decimal integer.
    """
    # Pattern: OBIS ID + up to 30 hex characters (variable header) + 8/16 hex characters (the value)
    pattern = obis_pattern + r'([a-f0-9]{' + str(length) + '})'
    match = re.search(pattern, message)
    if match:
        hex_value = match.group(1)
        return int(hex_value, 16)
    return None

def process_datagram(logger: logging.Logger, reading: bytes):
    # Strip End Marker Bytes
    bytes_to_check = reading[:-5] 
    received_crc_bytes = bytes_to_check[-2:]
    received_crc_int = int.from_bytes(received_crc_bytes, byteorder='little')
    # Calculate CRC (on all bytes EXCEPT the last 2 CRC bytes)
    calculated_crc_int = sml.crc(bytes_to_check[:-2])
    # Only if CRC matches
    if calculated_crc_int == received_crc_int:
        if CONFIG['utc']:
            ts = datetime.datetime.now(datetime.UTC)
        else:
            ts = datetime.datetime.now()
        ts_str = ts.strftime(TS_FORMAT)
        message_str = str(binascii.hexlify(reading), encoding='utf-8')
        if message_str:
            print(f"--- SML Datagram ---")
            print(ts_str)
            print(message_str)
            print(f"--- ------------ ---")
            # Use the robust extraction function. If the value isn't found, it returns None.
            V1_8_0 = extract_sml_reading(message_str, r'77070100010800ff[a-f0-9]*?621e52..59', 16)
            V2_8_0 = extract_sml_reading(message_str, r'77070100020800ff[a-f0-9]*?621e52..59', 16)
            V1_7_0 = extract_sml_reading(message_str, r'77070100100700ff[a-f0-9]*?621b52..55', 8)
            # Convert to signed integers
            if V1_8_0 is not None:
                # 1.8.0 is an 8-byte value -> 64 bits
                V1_8_0 = signed_conversion(V1_8_0, 64) 
            if V2_8_0 is not None:
                # 2.8.0 is an 8-byte value -> 64 bits
                V2_8_0 = signed_conversion(V2_8_0, 64) 
            if V1_7_0 is not None:
                # 1.7.0 is a 4-byte value -> 32 bits
                V1_7_0 = signed_conversion(V1_7_0, 32)
            # Handle the case where the reading is None
            V1_8_0_str = str(int(V1_8_0)/10000.0) if V1_8_0 is not None else 'None'
            V2_8_0_str = str(int(V2_8_0)/10000.0) if V2_8_0 is not None else 'None'
            V1_7_0_str = str(V1_7_0) if V1_7_0 is not None else 'None'
            if V1_8_0_str != 'None':
                print('1.8.0: ' + V1_8_0_str + ' kWh')
            if V2_8_0_str != 'None':
                print('2.8.0: ' + V2_8_0_str + ' kWh')
            if V1_7_0_str != 'None':
                print('1.7.0: ' + V1_7_0_str + ' W')
            print(f"--- ------------ ---")
    else:
        logger.error("CRC mismatch")

def read_meter(test_message=None):
    logger = logging.getLogger(__name__)
    if test_message:
        # If in test mode, simply process the provided message once
        process_datagram(logger, test_message)
        return
    while True:
        try:
            success, reading = read()
            logger.debug(f'reading: {reading}, len: {len(reading)}')
            if success:
                if len(reading) < 7:
                    logger.error("Datagram too short for CRC check.")
                    time.sleep(1)
                    continue
                process_datagram(logger, reading)
        except Exception as e:
            logger.exception(f'Error in worker_read_meter: {e}')
            time.sleep(5)

if __name__ == '__main__':
    if len(sys.argv) > 1:
        # Command-line argument provided: Assume it's the hex message string
        hex_message_str = sys.argv[1]
        try:
            # Convert hex string argument back to a bytes object
            test_bytes = binascii.unhexlify(hex_message_str)
            print(f"*** Running in Testing Mode with {len(test_bytes)} bytes ***")
            read_meter(test_bytes)
        except binascii.Error:
            print(f"Error: Invalid hex string provided.")
            sys.exit(1)
    else:
        # No command-line argument: Run in production serial reading mode
        print("*** Running in Production Mode (Serial Port) ***")
        read_meter()
