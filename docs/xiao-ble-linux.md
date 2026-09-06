# XIAO ESP32-S3 battery + BLE prototype

This branch adds an optional BLE transport for HID mode while retaining the original USB CDC/HID/CCID path.

## Hardware

Use:

- Seeed Studio XIAO ESP32-S3
- ZW101-style 3.3 V UART fingerprint sensor
- protected 3.7 V LiPo cell
- optional hard power switch

The current unified firmware already uses pins that map cleanly to the XIAO:

| tinyTouch signal | ESP32-S3 GPIO | XIAO pin |
| --- | ---: | --- |
| fingerprint TX | 43 | D6 / TX |
| fingerprint RX | 44 | D7 / RX |
| fingerprint touch/interrupt | 2 | D1 |
| sensor VCC | 3V3 | 3V3 |
| sensor GND | GND | GND |

Power the fingerprint sensor from 3V3, never directly from the LiPo. A charged single-cell LiPo can be above the sensor's allowed supply voltage.

Connect the LiPo to the XIAO battery pads with correct polarity. USB-C remains available for charging, flashing, configuration, and wired authentication.

## BLE transport

The BLE link does not carry a stored password in plaintext. HID mode reuses protocol 6:

1. fingerprint match on the ESP32-S3
2. ESP sends an authenticated EV/EV2 frame
3. Linux helper verifies HMAC and replay state
4. Linux helper encrypts the password using the per-event session key
5. ESP verifies/decrypts the PW/PW2 response in RAM and types it over USB HID

The BLE service UUID is 54a10000-7469-6e79-746f-756368000001.

This first battery branch enables NimBLE modem/power-management support, but intentionally does not enter ESP32 deep sleep. Deep sleep should only be enabled after validating the exact ZW101 interrupt polarity and wake behavior on the physical sensor, otherwise the device can become difficult to wake or configure.

## Linux helper

Create a venv:

    cd software/linux-helper
    python3 -m venv .venv
    . .venv/bin/activate
    pip install -r requirements.txt

Pair the ESP with a HID host key over the existing USB setup flow first. Then store the same pairing key and the Linux password in the desktop keyring:

    python tinytouch_linux_helper.py --device AA:BB:CC:DD:EE:FF --set-pairing-key <64-hex-key>
    python tinytouch_linux_helper.py --device AA:BB:CC:DD:EE:FF --set-password 'your-password'

Run:

    python tinytouch_linux_helper.py

For automatic startup, copy tinytouch-linux.service to ~/.config/systemd/user/ and adjust the install paths if necessary, then:

    systemctl --user daemon-reload
    systemctl --user enable --now tinytouch-linux.service

On desktops using GNOME Keyring, KWallet, or another Secret Service backend, Python keyring stores credentials in the user's encrypted desktop credential store.

## Power notes

BLE is started alongside USB and uses NimBLE. The ESP-IDF configuration enables dynamic power management/tickless idle and Bluetooth sleep support where available. The remaining large battery optimization is converting the fingerprint/background task from a 10 ms presence poll to GPIO-interrupt-driven wake and then validating deep sleep on real hardware.
