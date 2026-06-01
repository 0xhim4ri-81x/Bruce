// ============================================================
// interface.cpp — TENSTAR TS-ESP32-S3 (1.14" TFT)
// ============================================================
#include "core/powerSave.h"
#include "core/utils.h"
#include "interface.h"

#ifndef TFT_I2C_POWER
#define TFT_I2C_POWER 21
#endif

static const uint32_t BL_FREQ     = 5000;
static const uint8_t  BL_RES_BITS = 8;

void _setup_gpio() {
    // Power up the TFT + I2C rail
    pinMode(TFT_I2C_POWER, OUTPUT);
    digitalWrite(TFT_I2C_POWER, HIGH);
    delay(100);  // give the LDO/rail time to stabilize

    // Backlight via LEDC
    ledcAttach(TFT_BL, BL_FREQ, BL_RES_BITS);
    ledcWrite(TFT_BL, 255);

    // Navigation buttons (active LOW, internal pull-up)
    pinMode(SEL_BTN, INPUT_PULLUP);
    pinMode(DW_BTN,  INPUT_PULLUP);
#ifdef UP_BTN
    pinMode(UP_BTN,  INPUT_PULLUP);
#endif
}

void _post_setup_gpio() { }

/*********************************************************************
** Function: InputHandler
** Handles PrevPress, NextPress, SelPress, AnyKeyPress, EscPress
** Pattern: follow Bruce's template — set flags directly here,
**          no separate check*Press() logic needed by the framework.
**********************************************************************/
void InputHandler(void) {
    checkPowerSaveTime();

    // Reset all flags
    PrevPress    = false;
    NextPress    = false;
    SelPress     = false;
    AnyKeyPress  = false;
    EscPress     = false;

    bool selPressed = (digitalRead(SEL_BTN) == BTN_ACT);
    bool dwPressed  = (digitalRead(DW_BTN)  == BTN_ACT);
#ifdef UP_BTN
    bool upPressed  = (digitalRead(UP_BTN)  == BTN_ACT);
#else
    bool upPressed  = false;
#endif

    bool anyPressed = selPressed || dwPressed || upPressed;

    // Wake screen first if sleeping; don't process nav on wake event
    if (anyPressed) {
        if (!wakeUpScreen()) AnyKeyPress = true;
        else goto END;
    }

    PrevPress = upPressed;
    NextPress = dwPressed && !selPressed;   // DW alone = next
    EscPress  = dwPressed && selPressed;    // DW + SEL = escape/back
    SelPress  = selPressed && !dwPressed;   // SEL alone = select

END:
    // Debounce: hold until buttons released or 200 ms passed
    if (AnyKeyPress) {
        long tmp = millis();
        while ((millis() - tmp) < 200 &&
               ((digitalRead(SEL_BTN) == BTN_ACT) ||
                (digitalRead(DW_BTN)  == BTN_ACT)
#ifdef UP_BTN
                || (digitalRead(UP_BTN) == BTN_ACT)
#endif
               ));
    }
}

/*********************************************************************
** Function: _setBrightness
** Sets backlight brightness (0–100)
**********************************************************************/
void _setBrightness(uint8_t brightval) {
    if (brightval == 0) {
        ledcWrite(TFT_BL, 0);
    } else {
        uint32_t duty = MINBRIGHT + round((255 - MINBRIGHT) * brightval / 100.0);
        ledcWrite(TFT_BL, duty);
    }
}

int  getBattery()   { return 0; }
bool isCharging()   { return false; }
void powerOff()     { }

void checkReboot() {
    if ((digitalRead(SEL_BTN) == BTN_ACT) &&
        (digitalRead(DW_BTN)  == BTN_ACT)) {
        delay(2000);
        if ((digitalRead(SEL_BTN) == BTN_ACT) &&
            (digitalRead(DW_BTN)  == BTN_ACT)) {
            ESP.restart();
        }
    }
}
