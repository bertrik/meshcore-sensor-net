#include <stdint.h>
#include <stdbool.h>
#include <atomic>

#include "mbedtls/base64.h"

#include <Arduino.h>
#include <WiFi.h>
#include <LittleFS.h>

#include <ESPmDNS.h>
#include <PubSubClient.h>

#include <RadioLib.h>
#include <MiniShell.h>

#include "config.h"

#define printf Serial.printf

// LoRa settings
#define LORA_CARRIER_FREQ 869.618
#define LORA_BANDWIDTH 62.5
#define LORA_SF 8
#define LORA_CR 8
#define LORA_SYNC_WORD 0x12
#define LORA_POWER 22
#define LORA_PREAMBLE 16
#define LORA_USE_CRC true

static AsyncWebServer server(80);

static MiniShell shell(&Serial);
static SX1262 radio = new Module(41, 39, 42, 40);
static std::atomic_bool rf_event;
static uint8_t rf_buffer[256];
static WiFiClient espClient;
static PubSubClient mqtt(espClient);
static char mqtt_host[128];
static char mqtt_user[32];
static char mqtt_pass[32];
static int mqtt_err = 0;
static char device_id[32];

// shared JSON buffers
static StaticJsonDocument < 1024 > doc;
static char json[1024];

static void handle_radio_interrupt(void)
{
    rf_event = true;
}

static void printhex(const char *title, const uint8_t *buf, size_t len, int rowsize = 16)
{
    printf("%s", title);
    for (size_t i = 0; i < len; i++) {
        if ((rowsize > 0) && (i % rowsize) == 0) {
            printf("\n%04X:", i);
        }
        printf(" %02X", buf[i]);
    }
    printf("\n");
}

static bool lora_init(void)
{
    int16_t result = radio.begin(LORA_CARRIER_FREQ);
    if (result < 0) {
        return false;
    }
    radio.setSpreadingFactor(LORA_SF);
    radio.setBandwidth(LORA_BANDWIDTH);
    radio.setCodingRate(LORA_CR);
    radio.setSyncWord(LORA_SYNC_WORD);
    radio.setPreambleLength(LORA_PREAMBLE);
    radio.explicitHeader();
    radio.setCRC(1);
    radio.invertIQ(false);

    rf_event = false;
    radio.setDio1Action(handle_radio_interrupt);
    radio.startReceive();
    return true;
}

static void mqtt_keep_connected(void)
{
    mqtt.loop();

    if ((WiFi.status() != WL_CONNECTED) || mqtt.connected()) {
        // not online or already connected
        return;
    }

    strcpy(mqtt_host, config_get_value("mqtt_broker_host").c_str());
    uint16_t mqtt_port = config_get_value("mqtt_broker_port").toInt();

    char will_topic[64];
    sprintf(will_topic, "%s/%s/status", config_get_value("mqtt_topic").c_str(), device_id);
    strcpy(mqtt_user, config_get_value("mqtt_user").c_str());
    strcpy(mqtt_pass, config_get_value("mqtt_pass").c_str());

    // attempt connect
    printf("Connecting to '%s:%d' ...\n", mqtt_host, mqtt_port);
    mqtt.setServer(mqtt_host, mqtt_port);
    if (mqtt.connect("meshcore-gw", mqtt_pass, mqtt_pass, will_topic, 0, true, "", true)) {
        printf("Announcing status on topic '%s'...", will_topic);
        doc.clear();
        doc["id"] = device_id;
        JsonObject lora = doc.createNestedObject("lora");
        lora["freq"] = config_get_value("lora_freq");
        lora["sf"] = config_get_value("lora_sf");
        lora["bw"] = config_get_value("lora_bw");
        lora["cr"] = config_get_value("lora_cr");
        lora["sync"] = config_get_value("lora_sync");
        serializeJson(doc, json, sizeof(json));
        bool result = mqtt.publish(will_topic, json, true);
        printf("%s\n", result ? "OK" : "FAIL");
    }
}

static boolean mqtt_uplink(const uint8_t *data, size_t size, float rssi, float snr)
{
    char topic[64];
    unsigned char b64[512];

    // build topic
    sprintf(topic, "%s/%s/uplink", config_get_value("mqtt_topic").c_str(), device_id);

    // build payload
    size_t b64_len = 0;
    int res = mbedtls_base64_encode(b64, sizeof(b64), &b64_len, data, size);
    b64[b64_len] = 0;

    doc.clear();
    doc["id"] = device_id;
    doc["time"] = time(NULL);
    doc["rssi"] = rssi;
    doc["snr"] = snr;
    doc["data"] = b64;
    size_t len = serializeJson(doc, json, sizeof(json));
    return mqtt.publish(topic, json);
}

static int do_reboot(int argc, char *arg[])
{
    ESP.restart();
    return 0;
}

static int do_datetime(int argc, char *argv[])
{
    time_t now = time(NULL);
    struct tm *info = localtime(&now);

    char buf[20];
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", info);
    printf("Date/time is now %s\n", buf);

    return 0;
}

static int do_wifi(int argc, char *argv[])
{
    if (argc > 1) {
        char *ssid = argv[1];
        const char *pass = (argc > 2) ? argv[2] : "";
        WiFi.begin(ssid, pass);
    }
    return (WiFi.status() == WL_CONNECTED) ? 0 : -2;
}

const cmd_t commands[] = {
    { "reboot", do_reboot, "Reboot" },
    { "datetime", do_datetime, "Show current date/time" },
    { "wifi", do_wifi, "[<ssid> [pass]] Configure WiFi" },
    { NULL, NULL, NULL }
};

void setup(void)
{
    Serial.begin(115200);

    uint64_t chipid = ESP.getEfuseMac();
    sprintf(device_id, "esp32-%04x%08x", (uint16_t) (chipid >> 32), (uint32_t) chipid);
    printf("Hello gateway: %s!\n", device_id);

    WiFi.mode(WIFI_AP_STA);
    WiFi.begin();

    // NTP
    configTzTime("CET-1CEST,M3.5.0/02,M10.5.0/03", "nl.pool.ntp.org");

    printf("lora_init()...");
    if (!lora_init()) {
        printf("FAILED!\n");
    } else {
        printf("OK!\n");
    }

    LittleFS.begin(true);

    // load settings, save defaults if necessary
    config_begin(LittleFS, "/config.json");
    if (!config_load()) {
        config_set_value("mqtt_broker_host", "stofradar.nl");
        config_set_value("mqtt_broker_port", "1883");
        config_set_value("mqtt_user", "");
        config_set_value("mqtt_pass", "");
        config_set_value("mqtt_topic", "sensornet");
        config_set_value("lora_freq", "869.618");
        config_set_value("lora_bw", "62.5");
        config_set_value("lora_sf", "8");
        config_set_value("lora_cr", "8");
        config_set_value("lora_sync", "12");
        config_save();
    }
    config_serve(server, "/config", "/config.html");
    server.serveStatic("/", LittleFS, "/").setDefaultFile("index.html");

    server.begin();

    MDNS.begin("meshcore-gw");
    MDNS.addService("_http", "_tcp", 80);
}

void loop(void)
{
    // handle shell
    shell.process(">", commands);

    // check radio
    if (rf_event.exchange(false)) {
        uint32_t irq_status = radio.getIrqFlags();

        // handle transmit
        if (irq_status & RADIOLIB_SX126X_IRQ_TX_DONE) {
            radio.finishTransmit();
        }
        // handle receive
        if (irq_status & RADIOLIB_SX126X_IRQ_RX_DONE) {
            int num_bytes = radio.getPacketLength();
            radio.readData(rf_buffer, num_bytes);
            float rssi = radio.getRSSI();
            float snr = radio.getSNR();
            printf("### Got %d bytes (RSSI: %d, SNR: %d), ", num_bytes, (int) rssi, (int) snr);
            printhex("Raw:", rf_buffer, num_bytes, 0);

            if (mqtt.connected()) {
                if (!mqtt_uplink(rf_buffer, num_bytes, rssi, snr)) {
                    mqtt_err++;
                    if (mqtt_err > 3) {
                        esp_restart();
                    }
                } else {
                    mqtt_err = 0;
                }
            }
        }
        // clear all interrupts
        radio.clearIrqFlags(irq_status);

        // restart receive
        radio.startReceive();
    }

    mqtt_keep_connected();
}
