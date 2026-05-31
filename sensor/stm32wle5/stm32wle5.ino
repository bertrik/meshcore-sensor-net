#include <stdint.h>
#include <stdbool.h>
#include <atomic>

#include <Arduino.h>
#include <EEPROM.h>

#include <RadioLib.h>
#include <MiniShell.h>

#include <Crypto.h>
#include <BLAKE2s.h>
#include <SHA256.h>
#include <AES.h>

#define printf Serial.printf

// LoRa settings
#define LORA_CARRIER_FREQ 869.618
#define LORA_BANDWIDTH 62.5
#define LORA_SF 7
#define LORA_CR 5
#define LORA_SYNC_WORD 0x12
#define LORA_POWER 22
#define LORA_PREAMBLE 16
#define LORA_USE_CRC true

// structure for non-volatile data, restored on bootup
typedef struct {
    uint32_t app_counter;
    uint8_t app_hashkey[32];
    uint8_t mc_channel_key[16];
    uint8_t mc_channel_hash;
    uint8_t mc_region_key[16];
} nvdata_t;

static MiniShell shell(&Serial);
static STM32WLx radio = new STM32WLx_Module();
static uint8_t rf_buffer[256];
static nvdata_t nvdata;
static uint8_t device_id[4];
static std::atomic_bool rf_event {
false};
static int mc_routing = 3;      // 0 = transport flood, 1 = flood, 2 = direct, 3 = transport direct

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
    radio.setRfSwitchPins(PA4, PA5);
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
    radio.setDio1Action(handle_radio_interrupt);

    return true;
}

static size_t put_u32(uint8_t *buf, uint32_t value)
{
    uint8_t *ptr = buf;
    *ptr++ = value >> 24;
    *ptr++ = value >> 16;
    *ptr++ = value >> 8;
    *ptr++ = value;
    return ptr - buf;
}

static int encrypt(uint8_t *dest, const uint8_t *key, const uint8_t *src, int src_len)
{
    SHA256 sha;
    sha.resetHMAC(key, 16);

    AES128 aes;
    aes.setKey(key, 16);

    uint8_t *dp = dest + 2;
    while (src_len >= 16) {
        aes.encryptBlock(dp, src);
        sha.update(dp, 16);
        dp += 16;
        src += 16;
        src_len -= 16;
    }
    if (src_len > 0) {          // remaining partial block
        uint8_t tmp[16];
        memset(tmp, 0, 16);
        memcpy(tmp, src, src_len);
        aes.encryptBlock(dp, tmp);
        sha.update(dp, 16);
        dp += 16;
    }
    sha.finalizeHMAC(key, 16, dest, 2);
    return dp - dest;
}

static int build_app_payload(uint8_t *dest, const uint8_t *id, uint32_t counter, const uint8_t *key,
                             const uint8_t *data, int len)
{
    uint8_t *ptr = dest;

    // id
    memcpy(ptr, id, 4);
    ptr += 4;

    // counter
    ptr += put_u32(ptr, counter);

    // data
    memcpy(ptr, data, len);
    ptr += len;

    // MAC
    BLAKE2s blake;
    blake.reset(key, 32);
    blake.update(dest, ptr - dest);
    blake.finalize(ptr, 4);
    ptr += 4;

    return ptr - dest;
}

static int build_group_payload(uint8_t *dest, const uint8_t *key, uint8_t channel_hash,
                               const uint8_t *data, int len)
{
    uint8_t *ptr = dest;
    *ptr++ = channel_hash;
    ptr += encrypt(ptr, nvdata.mc_channel_key, data, len);
    return ptr - dest;
}

static int calc_transport_code(uint8_t *code, const uint8_t *key, uint8_t payload_type,
                               const uint8_t *buf, int len)
{
    SHA256 sha;

    sha.resetHMAC(key, 16);
    sha.update(&payload_type, 1);
    sha.update(buf, len);
    sha.finalizeHMAC(key, 16, code, 2);
    code[2] = 0;
    code[3] = 0;
    return 4;
}

static size_t decrypt(uint8_t *dest, const uint8_t *key, const uint8_t *src, size_t len)
{
    SHA256 sha;
    AES128 aes;
    uint8_t buf[16];

    if (len < 2) {
        return -2;
    }

    sha.resetHMAC(key, 16);
    aes.setKey(key, 16);
    uint8_t *dp = dest;
    const uint8_t *sp = src + 2;
    size_t remain = len - 2;
    while (remain > 0) {
        int bsize = (remain > 16) ? 16 : remain;
        sha.update(sp, bsize);
        aes.decryptBlock(buf, sp);
        memcpy(dp, buf, bsize);
        dp += bsize;
        sp += bsize;
        remain -= bsize;
    }

    byte hash[2];
    sha.finalizeHMAC(key, 16, &hash, sizeof(hash));

    return memcmp(src, hash, 2) == 0 ? dp - dest : 0;
}

static void analyse(const uint8_t *data, size_t len)
{
    const uint8_t *ptr = data;
    static const char *payload_types[] =
        { "REQ", "RESPONSE", "TXT_MSG", "ACK", "ADVERT", "GRP_TXT", "GRP_DATA", "ANON_REQ",
        "PATH", "TRACE", "MULTIPART", "CONTROL", "rsvd-0x0C", "rsvd-0x0D", "rsvd-0x0E", "RAW_CUSTOM"
    };
    static const char *route_types[] = { "TRANSPORT_FLOOD", "FLOOD", "DIRECT", "TRANSPORT_DIRECT" };

    printhex("Raw:", data, len, 0);
    uint8_t header = *ptr++;
    uint8_t payload_type = (header >> 2) & 0xF;
    uint8_t route_type = header & 3;
    printf("Header: %s, %s\n", payload_types[payload_type], route_types[route_type]);
    uint8_t path_len = *ptr++;
    if ((ptr + path_len) < (data + len)) {
        printhex("Path:", ptr, path_len, 0);
    }
    ptr += path_len;
    if (ptr < (data + len)) {
        int payload_len = len + data - ptr;
        printhex("Payload:", ptr, payload_len);
        if ((payload_type == 5) || (payload_type == 6)) {
            // try to decode
            uint8_t channel_hash = *ptr++;
            if (channel_hash == nvdata.mc_channel_hash) {
                int crypt_size = data + len - ptr;
                printf("Channel hash 0x%02X match, decoding %d bytes...\n", channel_hash, crypt_size);
                uint8_t plain[255];
                size_t plain_size = decrypt(plain, nvdata.mc_channel_key, ptr, crypt_size);
                if (plain_size > 0) {
                    printhex("Plaintext:", plain, plain_size);
                } else {
                    printf("No decode ... %d\n", plain_size);
                }
            }
        }
    }
}

static int do_init(int argc, char *argv[])
{
    printf("Initialise LoRa\n");
    lora_init();
    return 0;
}

static int do_routing(int argc, char *argv[])
{
    if (argc == 2) {
        mc_routing = atoi(argv[1]);
    }
    const char *desc;
    switch (mc_routing) {
    case 0:
        desc = "TRANSPORT_FLOOD";
        break;
    case 1:
        desc = "FLOOD";
        break;
    case 2:
        desc = "DIRECT";
        break;
    case 3:
        desc = "TRANSPORT_DIRECT";
        break;
    default:
        desc = "unknown";
        break;
    }
    printf("Routing mode set to %d (%s)\n", mc_routing, desc);
    return 0;
}

static int do_data(int argc, char *argv[])
{
    uint8_t raw[128];
    uint8_t app_buf[256];
    uint8_t grp_buf[256];

    if (argc < 2) {
        return -1;
    }
    int raw_len = atoi(argv[1]);
    if (raw_len > sizeof(raw)) {
        return -2;
    }
    printf("Sending %d bytes...\n", raw_len);
    memset(raw, raw_len, raw_len);

    // build app payload
    int app_len =
        build_app_payload(app_buf, device_id, nvdata.app_counter++, nvdata.app_hashkey, raw,
                          raw_len);
    printhex("App payload", app_buf, app_len);

    // build mc buffer
    int grp_len =
        build_group_payload(grp_buf, nvdata.mc_channel_key, nvdata.mc_channel_hash, app_buf,
                            app_len);

    uint8_t *ptr = rf_buffer;
    *ptr++ = (0 << 6) | (6 << 2) | mc_routing;  // version(0) | group data (0x6)
    if ((mc_routing == 0) || (mc_routing == 3)) {
        ptr += calc_transport_code(ptr, nvdata.mc_region_key, 6, grp_buf, grp_len);
    }
    *ptr++ = 0;                 // path
    memcpy(ptr, grp_buf, grp_len);
    ptr += grp_len;
    int rf_len = ptr - rf_buffer;

    // transmit
    printhex("Transmit", rf_buffer, rf_len);
    int16_t result = radio.startTransmit(rf_buffer, rf_len);

    // debug print analysis
    analyse(rf_buffer, rf_len);

    return result;
}

static int do_text(int argc, char *argv[])
{
    uint8_t app_buf[256];
    uint8_t grp_buf[256];

    const char *user;
    const char *text;
    if (argc < 2) {
        return -1;
    }
    if (argc == 2) {
        user = "user";
        text = argv[1];
    } else {
        user = argv[1];
        text = argv[2];
    }

    // build text payload
    uint8_t *ptr = app_buf;
    memset(ptr, 0, 4);
    ptr += 4;
    *ptr++ = 0;
    ptr += sprintf((char *) ptr, "%s: %s", user, text);
    int app_len = ptr - app_buf;

    // build mc payload
    int grp_len =
        build_group_payload(grp_buf, nvdata.mc_channel_key, nvdata.mc_channel_hash, app_buf,
                            app_len);

    // build rf packet
    ptr = rf_buffer;
    *ptr++ = (0 << 6) | (5 << 2) | mc_routing;  // version(0) | group text (0x5)
    if ((mc_routing == 0) || (mc_routing == 3)) {
        ptr += calc_transport_code(ptr, nvdata.mc_region_key, 5, grp_buf, grp_len);
    }
    *ptr++ = 0;                 // path
    memcpy(ptr, grp_buf, grp_len);
    ptr += grp_len;
    int rf_len = ptr - rf_buffer;

    // transmit
    printhex("Transmit", rf_buffer, rf_len);
    int16_t result = radio.startTransmit(rf_buffer, rf_len);
    return result;
}

static void derive_mc_key(const char *value, uint8_t *dest, size_t dest_len)
{
    SHA256 sha;
    sha.reset();
    sha.update(value, strlen(value));
    sha.finalize(dest, dest_len);
}

static int do_key(int argc, char *argv[])
{
    SHA256 sha;
    if (argc > 1) {
        char *keytype = argv[1];
        if (strcmp(keytype, "app") == 0) {
            if (argc > 3) {
                char *name = argv[2];
                char *secret = argv[3];
                BLAKE2s blake;
                uint8_t device_key[32];
                blake.reset(secret, strlen(secret));
                blake.update(name, strlen(name));
                blake.update(device_id, sizeof(device_id));
                blake.finalize(nvdata.app_hashkey, 32);
            } else {
                printf("Syntax: key app <name> <secret>\n");
            }
        } else if (strcmp(keytype, "mc") == 0) {
            if (argc > 3) {
                char *region = argv[2];
                derive_mc_key(region, nvdata.mc_region_key, sizeof(nvdata.mc_region_key));
                char *channel = argv[3];
                derive_mc_key(channel, nvdata.mc_channel_key, sizeof(nvdata.mc_channel_key));
                sha.reset();
                sha.update(nvdata.mc_channel_key, 16);
                sha.finalize(&nvdata.mc_channel_hash, 1);
            } else {
                printf("Syntax: key mc <region> <channel>\n");
            }
        } else {
            printf("Need either 'app' or 'mc' argument.\n");
        }
    }
    printhex("App device id:", device_id, sizeof(device_id), 0);
    printhex("App hash key:", nvdata.app_hashkey, sizeof(nvdata.app_hashkey), 0);
    printhex("MC region key:", nvdata.mc_region_key, sizeof(nvdata.mc_region_key), 0);
    printhex("MC channel key:", nvdata.mc_channel_key, sizeof(nvdata.mc_channel_key), 0);
    printhex("MC channel hash:", &nvdata.mc_channel_hash, 1, 0);
    return 0;
}

static int do_reboot(int argc, char *argv[])
{
    NVIC_SystemReset();
    return 0;
}

static int do_save(int argc, char *argv[])
{
    printf("Saving ...");
    // save nvdata to flash
    EEPROM.put(0, nvdata);
    printf("OK\n");
    return 0;
}

const cmd_t commands[] = {
    { "init", do_init, "Initialise the radio" },
    { "routing", do_routing, "<mode> Configure routing mode" },
    { "data", do_data, "<length> Send group data" },
    { "text", do_text, "[user] <text> Send group text" },
    { "key", do_key, "<app|mc> Get/set keys" },
    { "save", do_save, "Save non-volatile data" },
    { "reboot", do_reboot, "Reboot" },
    { NULL, NULL, NULL }
};

void setup(void)
{
    Serial.begin(115200);
    printf("\nSTM32WLE5 started\n");

    // get device id
    uint32_t deviceid = HAL_GetUIDw0() ^ HAL_GetUIDw1() ^ HAL_GetUIDw2();
    put_u32(device_id, deviceid);

    // restore nvdata from flash
    EEPROM.get(0, nvdata);

    // init radio
    if (lora_init()) {
        radio.startReceive();
    } else {
        printf("lora_init failed!\n");
    }
}

void loop(void)
{
    shell.process(">", commands);

    // check radio
    if (rf_event.exchange(false)) {
        uint32_t irq_status = radio.getIrqFlags();

        // handle receive
        if (irq_status & RADIOLIB_SX126X_IRQ_RX_DONE) {
            int num_bytes = radio.getPacketLength();
            radio.readData(rf_buffer, num_bytes);
            int rssi = radio.getRSSI();
            int snr = radio.getSNR();
            printf("### Got %d bytes (RSSI: %d, SNR: %d), ", num_bytes, rssi, snr);
            analyse(rf_buffer, num_bytes);
        }
        // handle transmit
        if (irq_status & RADIOLIB_SX126X_IRQ_TX_DONE) {
            radio.finishTransmit();
        }
        // clear all interrupts
        radio.clearIrqFlags(irq_status);

        // restart receive
        radio.startReceive();
    }
}
