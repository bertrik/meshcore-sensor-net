# meshcore-sensor-net
Transferring citizen science sensor data over meshcore

This is a proof-of-concept for transferring sensor data over meshcore, pick it up on the internet and forward it to a citizen science data collection/processing service.

The system consists of 3 parts:
1) A sensor node, sends sensor data in meshcore compatible packets over LoRa. This data is picked up by the meshcore repeater network. 
2) A gateway node, listens on the meshcore LoRa radio channel and forwards any received data over MQTT to the bridge. It can also be instructed to transmit a LoRa packet.
3) A bridge, receives data from MQTT, forwards the sensor data to citizen science collection service and provides replies to the sensor through the gateway.

The interaction between these components works like this:
* The sensor sends a packet with sensor data (e.g. noise levels, particulate matter, etc). Initially, it sends these in 'flood' mode, meaning it travels over the entire meshcore network.
* The gateway node will at some point pick up this data, forward it over MQTT to the bridge.
* The bridge determines the 'best' route back to the node (it may have arrived over several routes). It also sends a kind of 'acknowledgement' message back to the node in 'direct' mode, telling the node the best route towards the gateway. The sensor data is forwarded to the citizen science data collection service.
* When the sensor receives the 'acknowledgement' from the bridge with the direct route, it switches from 'flood' to 'direct' mode for further packets. Using 'direct' mode is much more efficient on the network, since the packet is repeated only on the best (probably shortest) path towards the gateway. Once every 10 packets or so, the sensor expects to receive an acknowledgment, otherwise it switches back to 'flood' mode in order to reach a gateway and trigger a response from the bridge.

