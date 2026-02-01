#include <Arduino.h>

#include <MiniShell.h>

static MiniShell shell(&Serial);

const cmd_t commands[] = {
    { NULL, NULL, NULL }
};

void setup(void)
{
    Serial.begin(115200);
}

void loop(void)
{
    shell.process(">", commands);
}
