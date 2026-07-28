# Hardware and firmware

chatbit talks to a LoRa radio over a serial port. Two options, depending on whether you
want to flash anything.

---

## Option 1: RYLR modules, no flashing

[Reyax RYLR896 / RYLR998](https://reyax.com/products/rylr998/) are LoRa modules with an
AT-command interface over UART. Around $10, no soldering, no toolchain. Wire one to a
USB-serial adapter and you are done.

| RYLR pin | Connect to |
|---|---|
| VDD | 3.3 V (**not** 5 V) |
| GND | GND |
| RXD | adapter TXD |
| TXD | adapter RXD |
| RST | leave floating |

```bash
pip install pyserial
chatbit chat --transport lora --driver rylr --port /dev/ttyUSB0 \
    --region EU868 --freq 868.1 --sf 7
```

chatbit configures the module on startup — this is the code that replaces everything
Bluetooth would not let you touch:

```
AT+NETWORKID=6
AT+BAND=868100000            frequency, in Hz
AT+PARAMETER=7,7,1,8         spreading factor, bandwidth index, coding rate, preamble
AT+CRFOP=14                  transmit power, dBm
AT+ADDRESS=0
```

**MTU caveat.** The AT interface is text-only, so binary frames are hex-encoded and each
byte costs two characters. RYLR accepts 240 bytes per `AT+SEND`, giving a usable binary
payload of 120 bytes. chatbit halves the MTU automatically for this driver; you do not
need to configure it, but it does mean more fragmentation than the SLIP driver.

Both ends must agree on `NETWORKID`, frequency, and modulation parameters or they will
not hear each other.

---

## Option 2: SLIP firmware, full payload

If you can flash the board, a raw framed byte pipe is better: the full 255-byte SX127x
payload, no hex expansion, lower latency.

Works with any board carrying an SX1276/77/78/79 — Heltec WiFi LoRa 32, TTGO LoRa32,
Adafruit Feather M0 RFM95, or a bare RFM95W on an ESP32/RP2040.

The firmware's whole job is to move bytes between the serial port and the radio, with
[SLIP framing](https://datatracker.ietf.org/doc/html/rfc1055) so frame boundaries survive
the byte stream. It does no crypto, no addressing, and no retries — all of that lives in
chatbit.

```cpp
// Arduino sketch using the arduino-LoRa library.
// Serial <-> radio bridge with SLIP framing. Nothing else.
#include <SPI.h>
#include <LoRa.h>

#define SLIP_END     0xC0
#define SLIP_ESC     0xDB
#define SLIP_ESC_END 0xDC
#define SLIP_ESC_ESC 0xDD

// Match these to your chatbit --freq / --sf / --bw / --cr / --power flags.
static const long  FREQUENCY = 868100000;
static const int   SF        = 7;
static const long  BW        = 125000;
static const int   CR        = 5;   // denominator of 4/n
static const int   POWER     = 14;  // dBm
static const int   SYNC_WORD = 0x12;

static uint8_t rxBuf[256];
static size_t  rxLen = 0;
static bool    escaped = false;

void setup() {
  Serial.begin(115200);
  while (!Serial) { }
  if (!LoRa.begin(FREQUENCY)) {
    while (true) { }  // radio not responding: check wiring
  }
  LoRa.setSpreadingFactor(SF);
  LoRa.setSignalBandwidth(BW);
  LoRa.setCodingRate4(CR);
  LoRa.setTxPower(POWER);
  LoRa.setSyncWord(SYNC_WORD);
  LoRa.enableCrc();
  LoRa.receive();
}

static void writeSlip(const uint8_t *data, size_t len) {
  Serial.write(SLIP_END);
  for (size_t i = 0; i < len; i++) {
    if (data[i] == SLIP_END) {
      Serial.write(SLIP_ESC); Serial.write(SLIP_ESC_END);
    } else if (data[i] == SLIP_ESC) {
      Serial.write(SLIP_ESC); Serial.write(SLIP_ESC_ESC);
    } else {
      Serial.write(data[i]);
    }
  }
  Serial.write(SLIP_END);
}

void loop() {
  // Radio -> host.
  int packetSize = LoRa.parsePacket();
  if (packetSize > 0 && packetSize <= (int)sizeof(rxBuf)) {
    uint8_t buf[256];
    int n = 0;
    while (LoRa.available() && n < packetSize) buf[n++] = (uint8_t)LoRa.read();
    writeSlip(buf, n);
  }

  // Host -> radio.
  while (Serial.available()) {
    uint8_t b = (uint8_t)Serial.read();
    if (escaped) {
      if (b == SLIP_ESC_END)      rxBuf[rxLen++] = SLIP_END;
      else if (b == SLIP_ESC_ESC) rxBuf[rxLen++] = SLIP_ESC;
      else                        rxLen = 0;  // protocol violation, resync
      escaped = false;
    } else if (b == SLIP_ESC) {
      escaped = true;
    } else if (b == SLIP_END) {
      if (rxLen > 0) {
        LoRa.beginPacket();
        LoRa.write(rxBuf, rxLen);
        LoRa.endPacket();
        LoRa.receive();
        rxLen = 0;
      }
    } else if (rxLen < sizeof(rxBuf)) {
      rxBuf[rxLen++] = b;
    } else {
      rxLen = 0;  // oversized frame, drop it
    }
  }
}
```

```bash
chatbit chat --transport lora --driver slip --port /dev/ttyUSB0 \
    --region EU868 --freq 868.1 --sf 7 --mtu 255
```

The firmware's `FREQUENCY`, `SF`, `BW`, `CR` and `POWER` must match the chatbit flags —
the SLIP driver does not configure the radio, it only moves frames.

---

## Choosing settings

Run `chatbit plan` first. It computes time on air, checks the config against the band
plan, and shows the whole SF ladder so you can see the trade-off.

Rules of thumb:

- **SF7** — fastest, shortest range. Start here. The only sensible choice on US915,
  where higher SFs blow through the 400 ms dwell limit at these frame sizes.
- **SF9** — the default. Good balance on EU868, but ~1 s per full frame, so the 1% duty
  cycle limits you to roughly 35 frames/hour with strict padding.
- **SF12** — maximum range, ~7 s per full frame. On EU868 that is one frame every twelve
  minutes. Useful for a beacon, not for conversation.
- **Bandwidth 250 kHz** halves airtime and costs about 3 dB of sensitivity.
- **Padding** — `strict` hides message length completely and costs the most airtime;
  `bucket` leaks roughly log₂(length) and is much cheaper. On a duty-cycle-limited band
  this is the decision that most affects whether the thing feels usable.

## Antennas

Use one matched to your band. Transmitting without an antenna, or with one cut for the
wrong frequency, can destroy the power amplifier — the reflected power has nowhere to go.
Connect the antenna before powering the board.

## Troubleshooting

**Nothing received.** Check both ends agree on frequency, SF, bandwidth, coding rate and
sync word. For RYLR, `NETWORKID` must also match. A single mismatched parameter means
total silence, not degraded performance.

**`cannot open /dev/ttyUSB0`.** Add yourself to the `dialout` group
(`sudo usermod -a -G dialout $USER`, then log out and back in).

**Transmissions stop after a while.** The duty-cycle governor is doing its job. Run
`chatbit plan` to see the budget, or move to a region without a duty-cycle limit if you
are entitled to use one.

**Garbled frames on the SLIP driver.** Baud mismatch, or the board is printing debug
output to the same serial port. The bridge must emit nothing but SLIP frames.
