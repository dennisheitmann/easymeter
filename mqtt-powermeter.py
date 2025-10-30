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
V2_8_0 = 0
V1_8_0_prev_timestamp = datetime.datetime.utcnow()
V2_8_0_prev_timestamp = datetime.datetime.utcnow()

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

# Set up a client for InfluxDB
dbclient = InfluxDBClient('127.0.0.1', 8086, 'root', 'root', 'all-data')

def save_to_db(topic: str, val: int):
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
    global V2_8_0
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
                # for short messages
                V1_8_0 = int(re.sub('.*77070100010800ff[a-f0-9]{8}01621e520359', '', message)[0:16], 16)
                V2_8_0 = int(re.sub('.*77070100020800ff[a-f0-9]{8}01621e520359', '', message)[0:16], 16)
                if V1_8_0 != V1_8_0_prev:
                    if V1_8_0 < 99999:
                        save_to_db('HOME/POWER/powermeter/1_8_0', V1_8_0)
                        V1_8_0_prev_timestamp = datetime.datetime.utcnow()
                        client.publish('HOME/powermeter/1_8_0', str(V1_8_0).encode('utf-8').strip())
                        #print('1.8.0: ' + str(V1_8_0))
                if V2_8_0 != V2_8_0_prev:
                    if V2_8_0 < 99999:
                        save_to_db('HOME/POWER/powermeter/2_8_0', V2_8_0)
                        V2_8_0_prev_timestamp = datetime.datetime.utcnow()
                        client.publish('HOME/powermeter/2_8_0', str(V2_8_0).encode('utf-8').strip())
                        #print('2.8.0: ' + str(V2_8_0))
                if V1_8_0_prev_timestamp < datetime.datetime.utcnow() - datetime.timedelta(minutes=5):
                    if V1_8_0 < 99999:
                        save_to_db('HOME/POWER/powermeter/1_8_0', V1_8_0)
                        V1_8_0_prev_timestamp = datetime.datetime.utcnow()
                        client.publish('HOME/powermeter/1_8_0', str(V1_8_0).encode('utf-8').strip())
                        #print('1.8.0: ' + str(V1_8_0))
                if V2_8_0_prev_timestamp < datetime.datetime.utcnow() - datetime.timedelta(minutes=5):
                    if V2_8_0 < 99999:
                        save_to_db('HOME/POWER/powermeter/2_8_0', V2_8_0)
                        V2_8_0_prev_timestamp = datetime.datetime.utcnow()
                        client.publish('HOME/powermeter/2_8_0', str(V2_8_0).encode('utf-8').strip())
                        #print('2.8.0: ' + str(V2_8_0))

client = paho.mqtt.client.Client()
client.username_pw_set(username, password)
client.on_connect = on_connect
client.on_message = on_message

try:
    client.connect("localhost", 1883, 60)
except:
    raise

client.loop_forever()
