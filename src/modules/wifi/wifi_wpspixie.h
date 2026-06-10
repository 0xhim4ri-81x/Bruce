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

    bool pke_set     = false;
    bool pkr_set     = false;
    bool e_nonce_set = false;
    bool r_nonce_set = false;
    bool e_hash1_set = false;   // ← Add
    bool e_hash2_set = false;   // ← Add
    bool authkey_set = false;   // ← Add

    // Raw M1 body for Authenticator calculation
    static const int M1_BODY_MAX = 512;
    uint8_t m1Body[M1_BODY_MAX];
    int     m1BodyLen = 0;
};

extern PixieData pixieCapture;  // populated by sniffer + active probe

// Menu entry points
void wps_attack_menu();
void wps_target_menu(String tssid, String mac, uint8_t channel);
void wps_pixie_dust_attack(String tssid, String mac, uint8_t channel, bool preDeauth = false);
void wps_clean_m1_body(uint8_t *buf, int *len);

// Called after capture to compute the PIN from captured fields
String runPixieDustCalculation(const String &bssid);

// Helpers used by sniffer.cpp
bool   hasWpsEnabled(int networkIndex);
String bytesToHex(const uint8_t *data, size_t len);
String macToHex(const uint8_t *mac);
void   savePixieData();
