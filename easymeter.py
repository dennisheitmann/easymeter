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

KEYWORDS = {
    'A+': {'keyword': '1-0:1.8.0', 'dtype': float}, # Meter reading import
    'A-': {'keyword': '1-0:2.8.0', 'dtype': float}, # Meter reading export
    'L1': {'keyword': '1-0:21.7.255', 'dtype': float}, # Power L1
    'L2': {'keyword': '1-0:41.7.255', 'dtype': float}, # Power L2
    'L3': {'keyword': '1-0:61.7.255', 'dtype': float}, # Power L3
    'In': {'keyword': '1-0:1.7.255', 'dtype': float}, # Power total in
    'SERIAL': {'keyword': '0-0:96.1.255', 'dtype': str}, # Serial number
    'Out': {'keyword': '1-0:1.7.255', 'dtype': float}, # Power total out
}

TS_FORMAT = '%Y-%m-%d %H:%M:%S'

def read():
    with serial.Serial(port=CONFIG['dev'], baudrate=9600, parity=serial.PARITY_NONE, stopbits=serial.STOPBITS_ONE, bytesize=serial.EIGHTBITS, timeout=2.5, exclusive=True) as ser:
        #reading = ser.read_until(b'\x1b\x1b\x1b\x1b\03')
        reading = ser.read(312)
        ser.reset_input_buffer()
        if reading.startswith(b'\x1b\x1b\x1b\x1b\x01\x01\x01\x01'):
            return (True, reading)
        time.sleep(0.5) #wait to reach the right cycle
        return (False, reading)

def worker_read_meter(task_queues):
    task_queues = task_queues[:-1]  #remove last entry because is a list with all other queues (=the argument for this worker)
    logger = multiprocessing.get_logger()
    while True:
        try:
            success, reading = read()
            logger.debug(f'reading: {reading}, len: {len(reading)}')
            if success: # and len(reading) == 270:
                if CONFIG['utc']:
                    ts = datetime.datetime.utcnow()
                else:
                    ts = datetime.datetime.now()
                reading_dict ={'ts': ts.strftime(TS_FORMAT)} 
                reading_dict['message'] = str(binascii.hexlify(reading), encoding='utf-8')
                #put the reading_dict into all publishing queues
                for queue in task_queues:
                    queue.put(reading_dict)
            else:
                logger.error(f'reading failed {reading}')
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
        #print(json.dumps(reading))
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


""" 
/ESY5Q3DA1004 V3.02

1-0:0.0.0*255(0273011003684)
1-0:1.8.0*255(00026107.7034231*kWh)
1-0:21.7.255*255(000200.13*W)
1-0:41.7.255*255(000122.31*W)
1-0:61.7.255*255(000014.01*W)
1-0:1.7.255*255(000336.45*W)
1-0:96.5.5*255(82)
0-0:96.1.255*255(1ESY1011003684) """
