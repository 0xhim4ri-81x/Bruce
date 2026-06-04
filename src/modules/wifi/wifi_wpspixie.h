// wifi_wpspixie.h
#pragma once

#include <Arduino.h>
#include "wifi_atks.h"

struct PixieData {
    bool    valid    = false;
    uint8_t pke[192];
    uint8_t pkr[192];
    uint8_t e_nonce[16];
    uint8_t r_nonce[16];
    uint8_t e_hash1[32];
    uint8_t e_hash2[32];
    uint8_t authkey[32];
    uint8_t bssid[6];
    char    essid[33];
};

extern PixieData pixieCapture;  // populated by sniffer + active probe

// Menu entry points
void wps_attack_menu();
void wps_target_menu(String tssid, String mac, uint8_t channel);
void wps_pixie_dust_attack(String tssid, String mac, uint8_t channel, bool preDeauth = false);

// Called after capture to compute the PIN from captured fields
String runPixieDustCalculation(const String &bssid);

// Helpers used by sniffer.cpp
bool   hasWpsEnabled(int networkIndex);
String bytesToHex(const uint8_t *data, size_t len);
String macToHex(const uint8_t *mac);
void   savePixieData();
