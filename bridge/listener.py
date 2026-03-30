#!/usr/bin/env python3
import argparse
import base64
import hashlib
import json
import logging
from dataclasses import dataclass

import paho.mqtt.client as mqtt
from meshcoredecoder import MeshCoreDecoder, MeshCorePacketDecoder
from meshcoredecoder.types import DecryptionOptions, CryptoKeyStore

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


@dataclass
class DeviceData:
    id: str
    time: int
    rssi: int
    snr: float
    data: bytes

    @classmethod
    def from_bytes(cls, raw: bytes) -> "DeviceData":
        # Step 1: bytes -> dict
        parsed = json.loads(raw.decode("utf-8"))

        # Step 2: decode base64 field
        parsed["data"] = base64.b64decode(parsed["data"])

        # Step 3: construct dataclass
        return cls(**parsed)


class MqttListener:
    def __init__(self, broker: str, username: str, password: str, base_topic: str, callback):
        self.broker = broker
        self.client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
        self.client.username_pw_set(username, password)
        self.base_topic = base_topic
        self.client.on_connect = self.on_connect
        self.client.on_message = self.on_message
        self.handle_packet = callback

    def on_connect(self, client, _userdata, _flags, _rc, _properties):
        try:
            # msh/REGION/2/e/CHANNELNAME/USERID
            # see https://meshtastic.org/docs/software/integrations/mqtt/#mqtt-topics
            topic = f"{self.base_topic}/+/uplink"
            logger.info(f"Connected, subscribing to uplink topic {topic}...")
            client.subscribe(topic)
        except Exception as e:
            print(e)

    def on_message(self, client, _userdata, msg):
        try:
            logger.info(f"{msg.topic}")
            self.handle_packet(msg.payload)
        except Exception as e:
            logger.warning(f"Caught exception: {e}")

    def run(self):
        logger.info(f"Connecting to '{self.broker}' as user '{self.client.username}'...")
        self.client.connect(self.broker)
        self.client.loop_forever()


class PacketHandler:
    def __init__(self):
        secrets = []
        secrets.append(self.create_channel_key("#sensornet").hex())
        secrets.append(self.create_channel_key("#test").hex())
        secrets.append(self.create_channel_key("#bot").hex())
        secrets.append(self.create_channel_key("#mc-radar").hex())
        keystore = MeshCorePacketDecoder.create_key_store({'channel_secrets': secrets})
        self.options = DecryptionOptions(keystore)
        self.decoder = MeshCoreDecoder()

    def create_channel_key(self, name: str) -> bytes:
        return hashlib.sha256(name.encode('utf-8')).digest()[0:16]

    def handle_packet(self, data: bytes) -> None:
        # print(f"Data received: {data}")
        devicedata = DeviceData.from_bytes(data)
        logger.info(f"Device data received: {devicedata}")
        decoded = self.decoder.decode_to_json(devicedata.data.hex(), self.options)
        logger.info(f"Decoded: {decoded}")


def main():
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("-b", "--broker", help="The MQTT broker URL",
                        default="stofradar.nl")
    parser.add_argument("-u", "--username", help="The MQTT user name",
                        default="")
    parser.add_argument("-p", "--password", help="The MQTT password",
                        default="")
    parser.add_argument("-t", "--topic", help="The MQTT base topic",
                        default="sensornet")
    args = parser.parse_args()

    handler = PacketHandler()
    listener = MqttListener(args.broker, args.username, args.password, args.topic,
                            handler.handle_packet)
    listener.run()


if __name__ == "__main__":
    main()
