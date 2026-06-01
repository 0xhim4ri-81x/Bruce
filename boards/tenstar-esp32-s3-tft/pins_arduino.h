// ============================================================
// pins_arduino.h — TENSTAR TS-ESP32-S3 (1.14" TFT)
// Bruce Firmware port
//
// Board: ESP32-S3FH4R2
// Display: ST7789, 240x135, SPI
// Sensors: BMP280 @ I2C 0x76, QMI8658C @ I2C 0x77
// NeoPixel: GPIO33
// Nav Buttons: SEL=GPIO14, DW=GPIO15  (wire to GND via momentary switch)
// SD Card: external module, SPI on GPIO10/11/12/13
// ============================================================

#ifndef Pins_Arduino_h
#define Pins_Arduino_h

#include <stdint.h>

static const uint8_t SDA  = 42;
static const uint8_t SCL  = 41;
static const uint8_t SS   = 10;
static const uint8_t MOSI = 11;
static const uint8_t MISO = 12;
static const uint8_t SCK  = 13;

// ── TFT Display (ST7789, SPI FSPI bus) ──────────────────────
// IMPORTANT: TFT_I2C_POWER (GPIO21) must be pulled HIGH before
// the display or I2C sensors will work. interface.cpp handles this.
#ifndef TFT_I2C_POWER
#define TFT_I2C_POWER   21  // Power enable for TFT + I2C rail
#endif
#ifndef TFT_MISO
#define TFT_MISO        37  // FSPIID  (not needed for write-only, kept for SPI bus)
#endif
#ifndef TFT_MOSI
#define TFT_MOSI        35  // FSPID   (data out)
#endif
#ifndef TFT_SCLK
#define TFT_SCLK        36  // FSPICLK (clock)
#endif
#ifndef TFT_CS
#define TFT_CS           7  // Chip select
#endif
#ifndef TFT_DC
#define TFT_DC          39  // Data/Command
#endif
#ifndef TFT_RST
#define TFT_RST         40  // Reset
#endif
#ifndef TFT_BL
#define TFT_BL          45  // Backlight (active HIGH)
#endif

// ── ST7789 driver flags ──────────────────────────────────────
#ifndef ST7789_DRIVER
#define ST7789_DRIVER       1
#endif
#ifndef TFT_RGB_ORDER
#define TFT_RGB_ORDER       TFT_RGB   // correct color order for this panel
#endif
#ifndef TFT_WIDTH
#define TFT_WIDTH         135
#endif
#ifndef TFT_HEIGHT
#define TFT_HEIGHT        240
#endif
#ifndef TFT_BACKLIGHT_ON
#define TFT_BACKLIGHT_ON    1         // backlight is active HIGH
#endif
#ifndef SMOOTH_FONT
#define SMOOTH_FONT         1
#endif
#ifndef SPI_FREQUENCY
#define SPI_FREQUENCY       40000000
#endif
#ifndef SPI_READ_FREQUENCY
#define SPI_READ_FREQUENCY  20000000
#endif
#ifndef SPI_TOUCH_FREQUENCY
#define SPI_TOUCH_FREQUENCY  2500000
#endif
#ifndef TOUCH_CS
#define TOUCH_CS           -1         // no touch
#endif

// ── I2C (BMP280 + QMI8658C + QWIIC/SH1.0-4P) ───────────────
#ifndef SDA_PIN
#define SDA_PIN             42
#endif
#ifndef SCL_PIN
#define SCL_PIN             41
#endif
// Sensor addresses (informational, used in code):
//   BMP280   → 0x76
//   QMI8658C → 0x77

// ── NeoPixel RGB LED ─────────────────────────────────────────
#ifndef PIN_NEOPIXEL
#define PIN_NEOPIXEL        33
#endif
#ifndef NEOPIXEL_NUM
#define NEOPIXEL_NUM         1
#endif
#ifndef NEOPIXEL_POWER
#define NEOPIXEL_POWER      -1   // always powered, no enable pin
#endif

// ── Built-in LED (red, GPIO13) ───────────────────────────────
#ifndef LED_BUILTIN
#define LED_BUILTIN         13
#endif
#ifndef LED
#define LED                 13
#endif
#ifndef LED_ON
#define LED_ON            HIGH
#endif
#ifndef LED_OFF
#define LED_OFF            LOW
#endif

// ── Navigation Buttons ───────────────────────────────────────
// Wire each button between the GPIO and GND (internal pull-up used).
// SEL (select/OK) = GPIO14
// DW  (back/down) = GPIO15
// BOOT button on GPIO0 can be used as an additional input if needed.
#ifndef HAS_3_BUTTONS
#define HAS_3_BUTTONS   1
#endif
#ifndef UP_BTN
#define UP_BTN          8   // BOOT button
#endif
#ifndef SEL_BTN
#define SEL_BTN        14
#endif
#ifndef DW_BTN
#define DW_BTN         15
#endif
#ifndef BTN_ACT
#define BTN_ACT           LOW   // buttons pull to GND
#endif
#ifndef BTN_ALIAS
#define BTN_ALIAS         "SEL"
#endif

// ── SD Card (external SPI module) ────────────────────────────
// Default wiring suggestion using free GPIOs:
//   CS   → GPIO10
//   MOSI → GPIO11
//   MISO → GPIO12
//   SCK  → GPIO13  (shares with LED_BUILTIN — LED unusable when SD active)
// Override in bruce.conf or .ini if you use different pins.
#ifndef SDCARD_CS
#define SDCARD_CS          10
#endif
#ifndef SDCARD_MOSI
#define SDCARD_MOSI        11
#endif
#ifndef SDCARD_MISO
#define SDCARD_MISO        12
#endif
#ifndef SDCARD_SCK
#define SDCARD_SCK         13
#endif

// ── IR TX/RX (external module, optional) ─────────────────────
// Suggested free pins; change to whatever you wire up.
// Defined here so they appear in Bruce's pin picker.
#ifndef IR_TX_PINS
#define IR_TX_PINS  { {"GPIO16", 16}, {"GPIO17", 17} }
#endif
#ifndef IR_RX_PINS
#define IR_RX_PINS  { {"GPIO16", 16}, {"GPIO17", 17} }
#endif

// ── RF TX/RX (one-pin external module, optional) ─────────────
#ifndef RF_TX_PINS
#define RF_TX_PINS  { {"GPIO16", 16}, {"GPIO17", 17} }
#endif
#ifndef RF_RX_PINS
#define RF_RX_PINS  { {"GPIO18", 18}, {"GPIO8",   8} }
#endif

// ── UART (exposed header) ────────────────────────────────────
#ifndef TX
#define TX                   1
#endif
#ifndef RX
#define RX                   2
#endif

// ── Battery ADC ──────────────────────────────────────────────
// The board has no dedicated BAT ADC pin exposed.
// If you tap VBAT through a voltage divider to a free ADC pin, set here.
// Leave -1 to disable battery percentage in Bruce UI.
#ifndef BAT_PIN
#define BAT_PIN            -1
#endif

// ── Screen geometry & font sizes ─────────────────────────────
// Bruce uses these for layout calculations.
// ROTATION=1  →  landscape with USB-C on the right (135 wide, 240 tall → 240w x 135h)
#ifndef HAS_SCREEN
#define HAS_SCREEN          1
#endif
#ifndef ROTATION
#define ROTATION            1
#endif
#ifndef WIDTH
#define WIDTH             240
#endif
#ifndef HEIGHT
#define HEIGHT            135
#endif
#ifndef MINBRIGHT
#define MINBRIGHT          10   // minimum backlight duty cycle (0-255)
#endif


// ── RGB LED (FastLED) ────────────────────────────────────────
#ifndef HAS_RGB_LED
#define HAS_RGB_LED         1
#endif
#ifndef RGB_LED
#define RGB_LED             33
#endif
#ifndef LED_TYPE
#define LED_TYPE            WS2812
#endif
#ifndef LED_ORDER
#define LED_ORDER           GRB
#endif
#ifndef LED_COUNT
#define LED_COUNT           1
#endif
#ifndef LED_COLOR_STEP
#define LED_COLOR_STEP      15
#endif

// ── Font scale presets ───────────────────────────────────────
#ifndef FP
#define FP                  1   // small
#endif
#ifndef FM
#define FM                  2   // medium
#endif
#ifndef FG
#define FG                  3   // large
#endif

// ── SPI bus aliases (shared with SD card) ────────────────────
// These may be defined by the framework or .ini before this header.
#ifndef SPI_SCK_PIN
#define SPI_SCK_PIN        13
#endif
#ifndef SPI_MOSI_PIN
#define SPI_MOSI_PIN       11
#endif
#ifndef SPI_MISO_PIN
#define SPI_MISO_PIN       12
#endif
#ifndef SPI_SS_PIN
#define SPI_SS_PIN         10
#endif

// ── Device identity ──────────────────────────────────────────
#ifndef DEVICE_NAME
#define DEVICE_NAME        "TENSTAR ESP32-S3 TFT"
#endif

#endif // Pins_Arduino_h
