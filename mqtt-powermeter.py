#!/usr/bin/env python3
import os
import re
import csv
import json
import time
import datetime
from influxdb import InfluxDBClient
import paho.mqtt.client

username = 'user'
password = 'pass'
topic_tree = 'HOME/POWER/#'
topics = ['powermeter']
V1_8_0 = 0
V1_8_0_long = 0
V2_8_0 = 0
V2_8_0_long = 0
V16_7_0 = 0
V1_8_0_prev_timestamp = datetime.datetime.utcnow()
V2_8_0_prev_timestamp = datetime.datetime.utcnow()
V16_7_0_prev_timestamp = datetime.datetime.utcnow()

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

def signed_conversion(value: int, bits: int) -> int:
    """ Converts an unsigned integer (from hex) to a signed integer using two's complement. """
    if value is None:
        return None
    # Check if the MSB is set (i.e., value is negative)
    if value & (1 << (bits - 1)):
        # Calculate the negative value: value - 2^bits
        return value - (1 << bits)
    return value

# Set up a client for InfluxDB
dbclient = InfluxDBClient('127.0.0.1', 8086, 'root', 'root', 'all-data')

def save_to_db(topic: str, val: float):
    valtime = datetime.datetime.utcnow()
    json_body = [
            {
                "measurement": topic,
                "time": valtime,
                "fields": {
                    "value": val
                }
            }
        ]
    dbclient.write_points(json_body, time_precision='s')

def on_connect(client, userdata, flags, rc):
    print("Connected with result code " + str(rc))
    client.subscribe(topic_tree)

def on_message(client, userdata, msg):
    global V1_8_0
    global V1_8_0_long
    global V2_8_0
    global V2_8_0_long
    global V16_7_0
    global V16_7_0_prev_timestamp
    global V1_8_0_prev_timestamp
    global V2_8_0_prev_timestamp
    for topic in topics:
        if topic in msg.topic:
            message = json.loads(msg.payload.decode('ascii'))['message']
            # cut end message bytes
            message = message[:-10]
            # reverse order for crc comparison
            c_message = message[-2] + message[-1] + message[-4] + message[-3] 
            c_int = int(('0x' + c_message), 16)
            # message without crc as bytearray for crc calculation
            bytes_message = bytearray.fromhex(message)[:-2]
            crc = sml.crc(bytes_message)
            crc = f'{crc:#x}'
            crc_int = int(crc, 16)
            # compare received crc with calculated crc
            if c_int == crc_int:
                V1_8_0_prev = V1_8_0
                V2_8_0_prev = V2_8_0
                V16_7_0_prev = V16_7_0
                # for short messages
                V1_8_0 = extract_sml_reading(message, r'77070100010800ff[a-f0-9]*?621e520359', 16)
                V2_8_0 = extract_sml_reading(message, r'77070100020800ff[a-f0-9]*?621e520359', 16)
                V1_8_0_long = extract_sml_reading(message, r'77070100010800ff[a-f0-9]*?621e52fc59', 16)
                V2_8_0_long = extract_sml_reading(message, r'77070100020800ff[a-f0-9]*?621e52fc59', 16)
                V16_7_0 = extract_sml_reading(message, r'77070100100700ff[a-f0-9]*?621b52fe59', 16)
                # Convert to signed integers
                if V16_7_0 is not None:
                    # 16.7.0 is an 8-byte value -> 64 bits
                    V16_7_0 = signed_conversion(V16_7_0, 64)
                # Scale correctly
                if V1_8_0_long is not None:
                    V1_8_0 = V1_8_0_long/10000000.0
                if V2_8_0_long is not None:
                    V2_8_0 = V2_8_0_long/10000000.0
                if V16_7_0 is not None:
                    V16_7_0 = V16_7_0/100.0
                #print(V1_8_0)
                #print(V2_8_0)
                #print(V16_7_0)
                if V1_8_0 != V1_8_0_prev:
                    if V1_8_0 is not None:
                        if V1_8_0 < 99999:
                            save_to_db('HOME/POWER/powermeter/1_8_0_float', float(V1_8_0))
                            V1_8_0_prev_timestamp = datetime.datetime.utcnow()
                            client.publish('HOME/powermeter/1_8_0', str(V1_8_0).encode('utf-8').strip())
                            #print('1.8.0: ' + str(V1_8_0))
                if V2_8_0 != V2_8_0_prev:
                    if V2_8_0 is not None:
                        if V2_8_0 < 99999:
                            save_to_db('HOME/POWER/powermeter/2_8_0_float', float(V2_8_0))
                            V2_8_0_prev_timestamp = datetime.datetime.utcnow()
                            client.publish('HOME/powermeter/2_8_0', str(V2_8_0).encode('utf-8').strip())
                            #print('2.8.0: ' + str(V2_8_0))
                if V16_7_0 != V16_7_0_prev:
                    if V16_7_0 is not None:
                        if V16_7_0 < 99999:
                            save_to_db('HOME/POWER/powermeter/16_7_0_float', float(V16_7_0))
                            V16_7_0_prev_timestamp = datetime.datetime.utcnow()
                            client.publish('HOME/powermeter/16_7_0', str(V16_7_0).encode('utf-8').strip())
                            #print('16.7.0: ' + str(V16_7_0))
                if V1_8_0_prev_timestamp < datetime.datetime.utcnow() - datetime.timedelta(minutes=1):
                    if V1_8_0 is not None:
                        if V1_8_0 < 99999:
                            save_to_db('HOME/POWER/powermeter/1_8_0_float', float(V1_8_0))
                            V1_8_0_prev_timestamp = datetime.datetime.utcnow()
                            client.publish('HOME/powermeter/1_8_0', str(V1_8_0).encode('utf-8').strip())
                            #print('1.8.0: ' + str(V1_8_0))
                if V2_8_0_prev_timestamp < datetime.datetime.utcnow() - datetime.timedelta(minutes=1):
                    if V2_8_0 is not None:
                        if V2_8_0 < 99999:
                            save_to_db('HOME/POWER/powermeter/2_8_0_float', float(V2_8_0))
                            V2_8_0_prev_timestamp = datetime.datetime.utcnow()
                            client.publish('HOME/powermeter/2_8_0', str(V2_8_0).encode('utf-8').strip())
                            #print('2.8.0: ' + str(V2_8_0))
                if V16_7_0_prev_timestamp < datetime.datetime.utcnow() - datetime.timedelta(minutes=1):
                    if V16_7_0 is not None:
                        if V16_7_0 < 99999:
                            save_to_db('HOME/POWER/powermeter/16_7_0_float', float(V16_7_0))
                            V16_7_0_prev_timestamp = datetime.datetime.utcnow()
                            client.publish('HOME/powermeter/16_7_0', str(V16_7_0).encode('utf-8').strip())
                            #print('16.7.0: ' + str(V16_7_0))

client = paho.mqtt.client.Client()
client.username_pw_set(username, password)
client.on_connect = on_connect
client.on_message = on_message

try:
    client.connect("localhost", 1883, 60)
except:
    raise

client.loop_forever()
