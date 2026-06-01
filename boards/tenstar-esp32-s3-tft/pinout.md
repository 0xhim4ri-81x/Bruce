# Pinouts diagram to use Bruce

## TENSTAR TS-ESP32-S3 Board Pinouts

### SPI Devices & Display Mapping
The display uses a dedicated SPI bus (FSPI), while the SD Card and external hardware modules (CC1101/NRF24) share a separate SPI expansion bus.

| Device  | SCK   | MISO  | MOSI  | CS    | GDO0/CE | TFT_DC | TFT_RST | TFT_BL |
| ---     | :---: | :---: | :---: | :---: | :---:   | :---:  | :---:   | :---:  |
| Display | 36    | 37    | 35    | 7     | ---     | 39     | 40      | 45     |
| SD Card | 13    | 12    | 11    | 10    | ---     | ---    | ---     | ---    |
| CC1101  | 13    | 12    | 11    | 10* | Slot* | ---    | ---     | ---    |
| NRF24   | 13    | 12    | 11    | 10* | Slot* | ---    | ---     | ---    |

> **Note on Display Power:** GPIO 21 (`TFT_I2C_POWER`) acts as the main power enable rail for both the TFT display and the onboard I2C sensors. It must be driven **HIGH** for them to function (`interface.cpp` handles this automatically).
>
> **(*) Shared SPI Bus:** The SD Card, CC1101, and NRF24 modules share the same SPI lines (11, 12, 13). If you hook up multiple external SPI devices simultaneously alongside the SD card slot, you must use physical toggle switches or isolate separate GPIOs for individual Chip Select (`CS`) signals to prevent data collision.

### Navigation Buttons
The board utilizes 3 navigation buttons configured as **Active LOW** with internal pull-ups enabled.

| Buttons | GPIO  | Default Label / Action |
| ---     | :---: | :---:                  |
| Prev    | 8     | UP                     |
| Sel     | 14    | SELECT                 |
| Next    | 15    | DOWN                   |

### Auxiliary Modules & Onboard Peripherals

| Device   | RX    | TX    | GPIO  | Notes                                      |
| ---      | :---: | :---: | :---: | :---                                       |
| IR RX    | ---   | ---   | 16/17 | Configurable pin pairs for external modules |
| IR TX    | ---   | ---   | 16/17 | Configurable pin pairs for external modules |
| RF RX    | ---   | ---   | 6     | For external sub-GHz receivers             |
| RF TX    | ---   | ---   | 5     | For external sub-GHz transmitters            |
| Status LED | --- | ---   | 13    | Onboard standard LED (Active HIGH)         |
| RGB LED  | ---   | ---   | 33    | Onboard WS2812 NeoPixel (GRB order)        |

### Shared I2C Interface
The main I2C interface hosts the onboard sensors and is exposed for external expansions (like Grooves or physical modules).

* **I2C SDA:** 42
* **I2C SCL:** 41

**Onboard Built-In Sensors:**
* **BMP280** (Barometric Pressure/Temperature) @ I2C address `0x76`
* **QMI8658C** (6-Axis IMU/Accelerometer) @ I2C address `0x77`

### USB Features & BadUSB
Unlike older architectures or lower-tier chips, the **ESP32-S3 natively supports USB-OTG**.
* **BadUSB / USB HID** functions directly over the internal USB-Serial peripheral configuration via firmware.
* **No external hardware (like a CH9329 module) is required** to execute BadUSB keystrokes or scripts; just plug a USB cable straight from the ESP32-S3 native port into your target machine.
