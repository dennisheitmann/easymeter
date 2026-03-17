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

# ------------------------------------------------------------------------
# CONFIGURATION
# ------------------------------------------------------------------------
CONFIG = {'dev': '/dev/ttyUSB0',  # Serial port connected to the IR optical head
          'loglevel': 'ERROR',
          'utc': True,            # Use UTC time to avoid local daylight saving time overlaps
          'mqtt': {'enabled': True,
                   'host': 'localhost',
                   'port': 1883,
                   'keepalive': 60,
                   'auth': {'enabled': True, 'username': 'powermeter', 'password': 'password' },
                   'topic': 'HOME/POWER/powermeter',
                   'retain': False,       # Do not retain the message on the broker after delivery
                   'qos': 0 } ,           # Quality of Service 0 (Fire and forget)
         } 

TS_FORMAT = '%Y-%m-%d %H:%M:%S'

# ------------------------------------------------------------------------
# UTILITY FUNCTIONS
# ------------------------------------------------------------------------
def signed_conversion(value: int, bits: int) -> int:
    """ 
    Converts an unsigned integer (from hex) to a signed integer using two's complement. 
    Smart meters often send negative values (e.g., when feeding power back to the grid).
    """
    if value is None:
        return None
    # Check if the Most Significant Bit (MSB) is set. If so, the value is negative.
    if value & (1 << (bits - 1)):
        # Calculate the negative value by subtracting 2^bits
        return value - (1 << bits)
    return value

class SmlCrc:
    """ 
    Class for Smart Message Language (SML) CRC16-CCITT calculation.
    Used to verify the integrity of the data stream coming from the meter.
    """
    def __init__(self):
        self.crc_table = [] 
        self.crc_init()
        
    def crc_init(self):
        """ Initialize the CRC look-up table for faster byte-wise calculation. """
        polynom = 0x8408     # CCITT Polynom reflected
        self.crc_table = []
        for byte in range(256):
            crcsum = byte
            for bit in range(8):  # Process all 8 bits
                if crcsum & 0x01:
                    crcsum = (crcsum >> 1) ^ polynom
                else:
                    crcsum >>= 1
            self.crc_table.append(crcsum)
            
    def crc(self, data):
        """ Calculate CCITT-CRC16 checksum byte by byte against the lookup table. """
        crcsum = 0xFFFF
        for byte in data:
            idx = byte ^ (crcsum & 0xFF)
            crcsum = self.crc_table[idx] ^ (crcsum >> 8)
        return crcsum ^ 0xFFFF
        
sml = SmlCrc()

# ------------------------------------------------------------------------
# SML PARSING CONSTANTS
# ------------------------------------------------------------------------
# SML messages always begin and end with specific escape sequences
SML_START = b'\x1b\x1b\x1b\x1b\x01\x01\x01\x01'
SML_END = b'\x1b\x1b\x1b\x1b\x01'

def read() -> Tuple[bool, bytes]:
    """
    Reads a complete SML datagram from the serial port.
    It searches for the start marker, then reads continuously until the end marker.
    """
    try:
        with serial.Serial(
            port=CONFIG['dev'],
            baudrate=9600,
            parity=serial.PARITY_NONE,
            stopbits=serial.STOPBITS_ONE,
            bytesize=serial.EIGHTBITS,
            timeout=5.0,  # 5 second timeout to prevent infinite hanging
            exclusive=True
        ) as ser:
            
            # 1. Grab an initial chunk of data to find the starting sequence
            partial_reading = ser.read(100)
            if not partial_reading:
                return (False, b"Error: No data read from serial port.")
            
            # 2. Locate the SML START sequence in the byte stream
            start_index = partial_reading.find(SML_START)
            if start_index == -1:
                # Start sequence not found. Sleep briefly and clear the buffer to try again cleanly.
                time.sleep(0.25)
                ser.reset_input_buffer()
                return (False, b"No SML start detected")
            
            # 3. Discard any garbage bytes before the start marker
            start_data = partial_reading[start_index:]
            
            # 4. Read the rest of the stream until the SML END marker is found
            body_and_end = ser.read_until(SML_END)
            
            if not body_and_end.endswith(SML_END):
                # We timed out before receiving the full datagram
                return (False, start_data + body_and_end)
            
            # 5. Assemble the complete payload and flush the port for the next read
            complete_datagram = start_data + body_and_end
            ser.reset_input_buffer()
            return (True, complete_datagram)
            
    except serial.SerialException as e:
        return (False, str(e).encode('utf-8'))

def extract_sml_reading(message: str, obis_pattern: str, length: int) -> Optional[int]:
    """
    Uses Regular Expressions to find specific OBIS codes in the hex string 
    and extracts their corresponding values.
    """
    # Build regex: Match the OBIS pattern, then capture a specific number of hex characters
    pattern = obis_pattern + r'([a-f0-9]{' + str(length) + '})'
    match = re.search(pattern, message)
    if match:
        hex_value = match.group(1)
        return int(hex_value, 16) # Convert the captured hex string into a base-10 integer
    return None

def process_datagram(logger: logging.Logger, reading: bytes, crc: bool = True, crcoffset: int = -5):
    """
    Validates the SML datagram CRC checksum, extracts meter readings (OBIS codes),
    and converts them from hex strings into human-readable numbers.
    """
    # Meter-specific offset for where the CRC bytes are located at the end of the message.
    # Easymeter = 0, Iskra = -5
    bytes_to_check = reading[:crcoffset] 
    
    # Extract the last two bytes as the provided CRC, and compute our own CRC to compare
    received_crc_bytes = bytes_to_check[-2:]
    received_crc_int = int.from_bytes(received_crc_bytes, byteorder='little')
    calculated_crc_int = sml.crc(bytes_to_check[:-2])
    
    # Verify the checksum
    crc_ok_or_check_disabled = (not crc) or (calculated_crc_int == received_crc_int)
    if crc and calculated_crc_int != received_crc_int:
        logger.error(f"CRC Mismatch! Received: {received_crc_int:04X}, Calculated: {calculated_crc_int:04X}")
        return
    
    if crc_ok_or_check_disabled:
        # Use timezone-aware UTC datetime for accuracy, preventing Python 3.12+ deprecation warnings
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
            
            # Extract common OBIS codes. The regex targets the OBIS ID and variable headers.
            # OBIS 1.8.0 = Total Energy Consumed (Grid to Home)
            V1_8_0 = extract_sml_reading(message_str, r'77070100010800ff[a-f0-9]*?621e52..59', 16)
            # OBIS 2.8.0 = Total Energy Delivered (Home to Grid / Solar export)
            V2_8_0 = extract_sml_reading(message_str, r'77070100020800ff[a-f0-9]*?621e52..59', 16)
            # OBIS 1.7.0 = Current Active Power (Real-time consumption in Watts)
            V1_7_0 = extract_sml_reading(message_str, r'77070100100700ff[a-f0-9]*?621b52..55', 8)
            
            # Convert raw hex integers to signed integers based on their byte length
            if V1_8_0 is not None:
                V1_8_0 = signed_conversion(V1_8_0, 64) # 8 bytes = 64 bits
            if V2_8_0 is not None:
                V2_8_0 = signed_conversion(V2_8_0, 64) # 8 bytes = 64 bits
            if V1_7_0 is not None:
                V1_7_0 = signed_conversion(V1_7_0, 32) # 4 bytes = 32 bits
                
            if V1_8_0 is not None:
                print('1.8.0: ' + str(V1_8_0))
            if V2_8_0 is not None:
                print('2.8.0: ' + str(V2_8_0))
            if V1_7_0 is not None:
                print('1.7.0: ' + str(V1_7_0))
    else:
        logger.error("CRC mismatch")

# ------------------------------------------------------------------------
# MULTIPROCESSING WORKERS
# ------------------------------------------------------------------------
def worker_read_meter(task_queues):
    """
    Dedicated background process for continuously reading the serial port.
    When a reading is successful, it pushes the data into all available target queues (e.g., MQTT).
    """
    # The last element in task_queues is actually the list of queues itself (passed in run()).
    # We slice it off so we only iterate over actual Queue objects.
    task_queues = task_queues[:-1]  
    logger = multiprocessing.get_logger()
    
    while True:
        try:
            success, reading = read()
            logger.debug(f'reading: {reading}, len: {len(reading)}')
            
            if success:
                if CONFIG['utc']:
                    ts = datetime.datetime.now(datetime.UTC)
                else:
                    ts = datetime.datetime.now()
                    
                reading_dict ={'ts': ts.strftime(TS_FORMAT)} 
                reading_dict['message'] = str(binascii.hexlify(reading), encoding='utf-8')
                
                # Push the structured dictionary into every configured publishing queue
                for queue in task_queues:
                    queue.put(reading_dict)
            else:
                logger.warning(f'reading failed {reading}')
        except:
            logger.exception('Error in worker_read_meter')

def worker_publish_mqtt(task_queue):
    """
    Dedicated background process for handling MQTT publishing.
    Pulls meter readings out of the task_queue and sends them to the broker.
    """
    import paho.mqtt.client as mqtt
    logger = multiprocessing.get_logger()
    
    # PAHO MQTT V2: Explicitly declare we are using the Version 2 callback API to avoid deprecation errors.
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)

    def mqtt_connect():
        """ Handles authentication and connection to the MQTT broker. """
        if CONFIG['mqtt']['auth']['enabled']:
            client.username_pw_set(CONFIG['mqtt']['auth']['username'], CONFIG['mqtt']['auth']['password'])
        client.connect(
            host=CONFIG['mqtt']['host'],
            port=CONFIG['mqtt']['port'],
            keepalive=CONFIG['mqtt']['keepalive'],
            bind_address=""
        )

    def mqtt_publish(payload):
        """ Publishes the JSON payload to the configured topic. """
        return client.publish(
            topic=CONFIG['mqtt']['topic'], 
            payload=json.dumps(payload), 
            qos=CONFIG['mqtt']['qos'],
            retain=CONFIG['mqtt']['retain']
        )

    try:
        # Establish the TCP connection once at startup
        mqtt_connect()
        # loop_start() spins up a background thread that manages Paho's network traffic, 
        # auto-reconnections, and keepalive pings without blocking our queue listener below.
        client.loop_start() 
    except Exception as e:
        logger.error(f"Failed to connect to MQTT Broker: {e}")

    # Continuously monitor the task queue for new readings
    while True:
        try:
            if not task_queue.empty():
                reading = task_queue.get()  # Pull the reading off the multiprocessing queue
                mqtt_publish(reading)       # Send it to the broker
                logger.debug('worker_publish_mqtt published: ' + json.dumps(reading))
        except Exception as e:
            logger.exception('Error in worker_publish_mqtt')
        time.sleep(0.1) # Brief sleep to prevent the while loop from maxing out the CPU

def run():
    """ Main entry point. Initializes logging, queues, and starts the worker processes. """
    multiprocessing.log_to_stderr(CONFIG['loglevel'])
    multiprocessing.get_logger().setLevel(CONFIG['loglevel'])

    # Dictionary mapping service names to their respective worker functions
    targets = {'mqtt': worker_publish_mqtt} 

    worker_args = [] 
    worker_targets = [] 
    
    # Loop through configured targets. If enabled, create a Queue for it.
    for key in targets:
        if CONFIG[key]['enabled']:
            worker_args.append(multiprocessing.Queue())
            worker_targets.append(targets[key])
            
    # Add the meter reading worker. We pass `worker_args` to it so it knows which queues to feed.
    worker_args.append(worker_args)
    worker_targets.append(worker_read_meter)

    processes = [] 
    # Start all worker functions as separate OS processes
    for idx,_ in enumerate(worker_targets):
        p = multiprocessing.Process(target=worker_targets[idx], args=(worker_args[idx],))
        # daemon=True ensures that if the main script crashes or is stopped by the user,
        # these background processes will be forcefully killed rather than becoming zombies.
        p.daemon = True 
        p.start()
        processes.append(p)

    # Keep the main process alive so the daemon threads can continue working
    while True:
        time.sleep(1)

if __name__ == '__main__':
    run()
