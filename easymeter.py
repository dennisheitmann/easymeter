#!/usr/bin/python3
import sys
import re
import serial
import logging
import time
import multiprocessing
import json
import datetime
import os
import binascii
from typing import Tuple, Optional, Union, Any

CONFIG = {'dev': '/dev/ttyUSB0',
          'loglevel': 'ERROR',
          'utc': True,
          'mqtt': {'enabled': True,
                   'host': 'localhost',
                   'port': 1883,
                   'keepalive': 60,
                   'auth': {'enabled': True, 'username': 'powermeter', 'password': 'password' },
                   'topic': 'HOME/POWER/powermeter',
                   'retain': False,
                   'qos': 0 } ,
         } 

TS_FORMAT = '%Y-%m-%d %H:%M:%S'

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

def process_datagram(logger: logging.Logger, reading: bytes, crc: bool = True, crcoffset: int = -5):
    # crcoffset: Easymeter = 0, Iskra = -5
    # Strip End Marker Bytes
    bytes_to_check = reading[:crcoffset] 
    received_crc_bytes = bytes_to_check[-2:]
    received_crc_int = int.from_bytes(received_crc_bytes, byteorder='little')
    # Calculate CRC (on all bytes EXCEPT the last 2 CRC bytes)
    calculated_crc_int = sml.crc(bytes_to_check[:-2])
    # Process if CRC check is disabled (crc=False) OR if CRC check is enabled and it matches.
    crc_ok_or_check_disabled = (not crc) or (calculated_crc_int == received_crc_int)
    # If the CRC check is enabled and failed, log the error and stop.
    if crc and calculated_crc_int != received_crc_int:
        logger.error(f"CRC Mismatch! Received: {received_crc_int:04X}, Calculated: {calculated_crc_int:04X}")
        return # Stop execution if CRC fails and check is mandatory
    # Proceed with Data Processing (Unconditional if crc=False, or if CRC matched)
    if crc_ok_or_check_disabled:
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
            if V1_8_0 != None:
                print('1.8.0: ' + str(V1_8_0))
            if V2_8_0 != None:
                print('2.8.0: ' + str(V2_8_0))
            if V1_7_0 != None:
                print('1.7.0: ' + str(V1_7_0))
            #print(f"--- ------------ ---")
    else:
        logger.error("CRC mismatch")

def worker_read_meter(task_queues):
    task_queues = task_queues[:-1]  #remove last entry because is a list with all other queues (=the argument for this worker)
    logger = multiprocessing.get_logger()
    while True:
        try:
            success, reading = read()
            logger.debug(f'reading: {reading}, len: {len(reading)}')
            if success:
                if CONFIG['utc']:
                    ts = datetime.datetime.utcnow()
                else:
                    ts = datetime.datetime.now()
                reading_dict ={'ts': ts.strftime(TS_FORMAT)} 
                reading_dict['message'] = str(binascii.hexlify(reading), encoding='utf-8')
                # process datagram here
                # process_datagram(logger, reading)
                # put the reading_dict into all publishing queues
                for queue in task_queues:
                    queue.put(reading_dict)
            else:
                logger.warning(f'reading failed {reading}')
        except:
            logger.exception('Error in worker_read_meter')

def worker_publish_mqtt(task_queue):
    import paho.mqtt.client as mqtt
    logger = multiprocessing.get_logger()
    client = mqtt.Client()

    def mqtt_connect():
        if CONFIG['mqtt']['auth']['enabled']:
            client.username_pw_set(CONFIG['mqtt']['auth']['username'],CONFIG['mqtt']['auth']['password'])
            client.connect(host=CONFIG['mqtt']['host'],port=CONFIG['mqtt']['port'],keepalive=CONFIG['mqtt']['keepalive'],bind_address="")
 
    def mqtt_publish(payload):
        mqtt_connect()
        return client.publish(topic=CONFIG['mqtt']['topic'], 
                              payload=json.dumps(reading),
                              qos=CONFIG['mqtt']['qos'],
                              retain=CONFIG['mqtt']['retain'])

    while True:
        try:
            if not task_queue.empty():
                reading = task_queue.get()
                mqtt_publish(reading)
                logger.debug('worker_publish_mqtt' + json.dumps(reading))
        except:
            logger.exception('Error in worker_publish_mqtt')
        time.sleep(0.1)

def run():
    multiprocessing.log_to_stderr(CONFIG['loglevel'])
    multiprocessing.get_logger().setLevel(CONFIG['loglevel'])

    #target functions for publishing services
    targets ={'mqtt': worker_publish_mqtt} 

    #prepare workers (create queues, link target functions)
    worker_args = [] 
    worker_targets = [] 
    for key in targets:
        if CONFIG[key]['enabled']:
            worker_args.append(multiprocessing.Queue())
            worker_targets.append(targets[key])
    #now add worker_read_meter and give him a ref to all queues as argument
    worker_args.append(worker_args)
    worker_targets.append(worker_read_meter)

    #start workers
    processes = [] 
    for idx,_ in enumerate(worker_targets):
        p = multiprocessing.Process(target=worker_targets[idx],
                                    args=(worker_args[idx],))
        p.daemon = True #main process kills children before it will be terminated
        p.start()
        processes.append(p)

    # because we use deamon=True, the main process has to be kept alive
    while True:
        time.sleep(1)

if __name__ == '__main__':
    run()
