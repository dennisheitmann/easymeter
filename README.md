## EasyMeter (INFO-DSS, SML V1.04) to MQTT / InfluxDB

`easymeter.py`: Reads SML messages from USB sensor on /dev/ttyUSB0 and sends messages to MQTT server.

`mqtt-powermeter.py`: Reads SML messages from MQTT and saves 1.8.0 (Bezug) and 2.8.0 (Einspeisung) to InfluxDB on localhost.

`mqtt-print-raw-powermeter.py`: Print SML messages from MQTT.

### Links
- https://www.easymeter.com/products/zaehler/q3a
- https://de.elv.com/easymeter-tastkopfblech-q3a-msb-und-info-schnittstellen-fuer-es-iec-253355
- https://de.elv.com/elv-lesekopf-mit-usb-schnittstelle-fuer-digitale-zaehler-usb-iec-158713
