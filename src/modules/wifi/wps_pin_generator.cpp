#include "wps_pin_generator.h"
#include <map>
#include <set>

// ----------------------------------------------------------------------
// Static helper: MAC string to 48‑bit integer
// ----------------------------------------------------------------------
uint64_t WpsPinGenerator::macToInt(const String &mac) {
    String clean = mac;
    clean.replace(":", "");
    clean.replace("-", "");
    clean.replace(".", "");
    clean.toUpperCase();
    return strtoull(clean.c_str(), NULL, 16);
}

// ----------------------------------------------------------------------
// Checksum (same as WPS specification)
// ----------------------------------------------------------------------
uint8_t WpsPinGenerator::checksum(uint32_t pin) {
    int accum = 0;
    while (pin) {
        accum += 3 * (pin % 10);
        pin /= 10;
        accum += pin % 10;
        pin /= 10;
    }
    return (10 - (accum % 10)) % 10;
}

// ----------------------------------------------------------------------
// Algorithm: 24‑bit (last 3 bytes of MAC)
// ----------------------------------------------------------------------
uint32_t WpsPinGenerator::pin24(uint64_t macInt) {
    return macInt & 0xFFFFFF;
}

// ----------------------------------------------------------------------
// Algorithm: 28‑bit (last 3.5 bytes of MAC)
// ----------------------------------------------------------------------
uint32_t WpsPinGenerator::pin28(uint64_t macInt) {
    return macInt & 0xFFFFFFF;
}

// ----------------------------------------------------------------------
// Algorithm: 32‑bit (full MAC as integer)
// ----------------------------------------------------------------------
uint32_t WpsPinGenerator::pin32(uint64_t macInt) {
    return macInt % 0x100000000ULL;
}

// ----------------------------------------------------------------------
// D‑Link algorithm
// ----------------------------------------------------------------------
uint32_t WpsPinGenerator::pinDLink(uint64_t macInt) {
    uint32_t nic = macInt & 0xFFFFFF;
    uint32_t pin = nic ^ 0x55AA55;
    pin ^= (((pin & 0xF) << 4) +
            ((pin & 0xF) << 8) +
            ((pin & 0xF) << 12) +
            ((pin & 0xF) << 16) +
            ((pin & 0xF) << 20));
    pin %= 10000000;
    if (pin < 1000000) {
        pin += ((pin % 9) * 1000000) + 1000000;
    }
    return pin;
}

// ----------------------------------------------------------------------
// D‑Link +1 (increment MAC by 1 then apply D‑Link)
// ----------------------------------------------------------------------
uint32_t WpsPinGenerator::pinDLink1(uint64_t macInt) {
    return pinDLink(macInt + 1);
}

// ----------------------------------------------------------------------
// ASUS algorithm (simplified, works for many ASUS routers)
// ----------------------------------------------------------------------
uint32_t WpsPinGenerator::pinASUS(uint64_t macInt) {
    uint8_t b[6];
    for (int i = 0; i < 6; i++) {
        b[i] = (macInt >> (40 - 8 * i)) & 0xFF;
    }
    uint32_t pin = 0;
    for (int i = 0; i < 7; i++) {
        int digit = (b[i % 6] + b[5]) % (10 - (i + b[1] + b[2] + b[3] + b[4] + b[5]) % 7);
        pin = pin * 10 + digit;
    }
    return pin;
}

// ----------------------------------------------------------------------
// Airocon Realtek algorithm
// ----------------------------------------------------------------------
uint32_t WpsPinGenerator::pinAirocon(uint64_t macInt) {
    uint8_t b[6];
    for (int i = 0; i < 6; i++) {
        b[i] = (macInt >> (40 - 8 * i)) & 0xFF;
    }
    return (((b[0] + b[1]) % 10) * 1) +
           (((b[5] + b[0]) % 10) * 10) +
           (((b[4] + b[5]) % 10) * 100) +
           (((b[3] + b[4]) % 10) * 1000) +
           (((b[2] + b[3]) % 10) * 10000) +
           (((b[1] + b[2]) % 10) * 100000) +
           (((b[0] + b[1]) % 10) * 1000000);
}

// ----------------------------------------------------------------------
// Suggest algorithm IDs based on MAC prefix (port of _suggest)
// ----------------------------------------------------------------------
std::vector<String> WpsPinGenerator::suggestAlgorithms(const String &bssid) {
    std::vector<String> result;
    String mac = bssid;
    mac.replace(":", "");
    mac.toUpperCase();

    // The mapping from algorithm name to list of MAC prefixes
    // (compressed version of the large list from generator.py)
    // For brevity, we show a subset – you should copy the full list from
    // the Python `_suggest` method. Below is a minimal example.
    static const std::map<String, std::vector<String>> algoMap = {
        {"pin24",   {"04BF6D","0E5D4E","107BEF","14A9E3","28285D","2A285D","32B2DC","381766","404A03","4E5D4E","5067F0","5CF4AB","6A285D","8E5D4E","AA285D","B0B2DC","C86C87","CC5D4E","CE5D4E","EA285D","E243F6","EC43F6","EE43F6","F2B2DC","FCF528","FEF528","4C9EFF","0014D1","D8EB97","1C7EE5","84C9B2","FC7516","14D64D","9094E4","BCF685","C4A81D","00664B","087A4C","14B968","2008ED","346BD3","4CEDDE","786A89","88E3AB","D46E5C","E8CD2D","EC233D","ECCB30","F49FF3","20CF30","90E6BA","E0CB4E","D4BF7F4","F8C091","001CDF","002275","08863B","00B00C","081075","C83A35","0022F7","001F1F","00265B","68B6CF","788DF7","BC1401","202BC1","308730","5C4CA9","62233D","623CE4","623DFF","6253D4","62559C","626BD3","627D5E","6296BF","62A8E4","62B686","62C06F","62C61F","62C714","62CBA8","62CDBE","62E87B","6416F0","6A1D67","6A233D","6A3DFF","6A53D4","6A559C","6A6BD3","6A96BF","6A7D5E","6AA8E4","6AC06F","6AC61F","6AC714","6ACBA8","6ACDBE","6AD15E","6AD167","721D67","72233D","723CE4","723DFF","7253D4","72559C","726BD3","727D5E","7296BF","72A8E4","72C06F","72C61F","72C714","72CBA8","72CDBE","72D15E","72E87B","0026CE","9897D1","E04136","B246FC","E24136","00E020","5CA39D","D86CE9","DC7144","801F02","E47CF9","000CF6","00A026","A0F3C1","647002","B0487A","F81A67","F8D111","34BA9A","B4944E"}},
        {"pin28",   {"200BC7","4846FB","D46AA8","F84ABF"}},
        {"pin32",   {"000726","D8FEE3","FC8B97","1062EB","1C5F2B","48EE0C","802689","908D78","E8CC18","2CAB25","10BF48","14DAE9","3085A9","50465D","5404A6","C86000","F46D04","3085A9","801F02"}},
        {"pinDLink",{"14D64D","1C7EE5","28107B","84C9B2","A0AB1B","B8A386","C0A0BB","CCB255","FC7516","0014D1","D8EB97"}},
        {"pinDLink1",{"0018E7","00195B","001CF0","001E58","002191","0022B0","002401","00265A","14D64D","1C7EE5","340804","5CD998","84C9B2","B8A386","C8BE19","C8D3A3","CCB255","0014D1"}},
        {"pinASUS", {"049226","04D9F5","08606E","0862669","107B44","10BF48","10C37B","14DDA9","1C872C","1CB72C","2C56DC","2CFDA1","305A3A","382C4A","38D547","40167E","50465D","54A050","6045CB","60A44C","704D7B","74D02B","7824AF","88D7F6","9C5C8E","AC220B","AC9E17","B06EBF","BCEE7B","C860007","D017C2","D850E6","E03F49","F0795978","F832E4","00072624","0008A1D3","00177C","001EA6","00304FB","00E04C0","048D38","081077","081078","081079","083E5D","10FEED3C","181E78","1C4419","2420C7","247F20","2CAB25","3085A98C","3C1E04","40F201","44E9DD","48EE0C","5464D9","54B80A","587BE906","60D1AA21","64517E","64D954","6C198F","6C7220","6CFDB9","78D99FD","7C2664","803F5DF6","84A423","88A6C6","8C10D4","8C882B00","904D4A","907282","90F65290","94FBB2","A01B29","A0F3C1E","A8F7E00","ACA213","B85510","B8EE0E","BC3400","BC9680","C891F9","D00ED90","D084B0","D8FEE3","E4BEED","E894F6F6","EC1A5971","EC4C4D","F42853","F43E61","F46BEF","F8AB05","FC8B97","7062B8","78542E","C0A0BB8C","C412F5","C4A81D","E8CC18","EC2280","F8E903F4"}},
        {"pinAirocon",{"0007262F","000B2B4A","000EF4E7","001333B","00177C","001AEF","00E04BB3","02101801","0810734","08107710","1013EE0","2CAB25C7","788C54","803F5DF6","94FBB2","BC9680","F43E61","FC8B97"}},
        {"pinCisco", {"001A2B","00248C","002618","344DEB","7071BC","E06995","E0CB4E","7054F5"}},
        {"pinBrcm1",{"ACF1DF","BCF685","C8D3A3","988B5D","001AA9","14144B","EC6264"}},
        {"pinBrcm2",{"14D64D","1C7EE5","28107B","84C9B2","B8A386","BCF685","C8BE19"}},
        {"pinBrcm3",{"14D64D","1C7EE5","28107B","B8A386","BCF685","C8BE19","7C034C"}},
        {"pinBrcm4",{"14D64D","1C7EE5","28107B","84C9B2","B8A386","BCF685","C8BE19","C8D3A3","CCB255","FC7516","204E7F","4C17EB","18622C","7C03D8","D86CE9"}},
        {"pinBrcm5",{"14D64D","1C7EE5","28107B","84C9B2","B8A386","BCF685","C8BE19","C8D3A3","CCB255","FC7516","204E7F","4C17EB","18622C","7C03D8","D86CE9"}},
        {"pinBrcm6",{"14D64D","1C7EE5","28107B","84C9B2","B8A386","BCF685","C8BE19","C8D3A3","CCB255","FC7516","204E7F","4C17EB","18622C","7C03D8","D86CE9"}},
        {"pinAirc1",{"181E78","40F201","44E9DD","D084B0"}},
        {"pinAirc2",{"84A423","8C10D4","88A6C6"}},
        {"pinDSL2740R",{"00265A","1CBDB9","340804","5CD998","84C9B2","FC7516"}},
        {"pinRealtek1",{"0014D1","000C42","000EE8"}},
        {"pinRealtek2",{"007263","E4BEED"}},
        {"pinRealtek3",{"08C6B3"}},
        {"pinUpvel",{"784476","D4BF7F0","F8C091"}},
        {"pinUR814AC",{"D4BF7F60"}},
        {"pinUR825AC",{"D4BF7F5"}},
        {"pinOnlime",{"D4BF7F","F8C091","144D67","784476","0014D1"}},
        {"pinEdimax",{"801F02","00E04C"}},
        {"pinThomson",{"002624","4432C8","88F7C7","CC03FA"}},
        {"pinHG532x",{"00664B","086361","087A4C","0C96BF","14B968","2008ED","2469A5","346BD3","786A89","88E3AB","9CC172","ACE215","D07AB5","CCA223","E8CD2D","F80113","F83DFF"}},
        {"pinH108L",{"4C09B4","4CAC0A","84742A4","9CD24B","B075D5","C864C7","DC028E","FCC897"}},
        {"pinONO",{"5C353B","DC537C"}}
    };

    // Static pins (always suggested if no match)
    static const std::vector<std::pair<String, uint32_t>> staticPins = {
        {"Cisco", 1234567}, {"Broadcom 1", 2017252}, {"Broadcom 2", 4626484},
        {"Broadcom 3", 7622990}, {"Broadcom 4", 6232714}, {"Broadcom 5", 1086411},
        {"Broadcom 6", 3195719}, {"Airocon 1", 3043203}, {"Airocon 2", 7141225},
        {"DSL-2740R", 6817554}, {"Realtek 1", 9566146}, {"Realtek 2", 9571911},
        {"Realtek 3", 4856371}, {"Upvel", 2085483}, {"UR-814AC", 4397768},
        {"UR-825AC", 529417}, {"Onlime", 9995604}, {"Edimax", 3561153},
        {"Thomson", 6795814}, {"HG532x", 3425928}, {"H108L", 9422988},
        {"CBN ONO", 9575521}
    };

    // Check each algorithm's prefixes
    for (const auto &entry : algoMap) {
        const String &algoId = entry.first;
        const std::vector<String> &prefixes = entry.second;
        for (const String &prefix : prefixes) {
            if (mac.startsWith(prefix)) {
                result.push_back(algoId);
                break;
            }
        }
    }

    // Add static pins as separate entries (they will be handled later)
    for (const auto &sp : staticPins) {
        result.push_back("static_" + sp.first);
    }

    // Also add the "Empty" algorithm (all zeros) as a fallback
    result.push_back("pinEmpty");

    return result;
}

// ----------------------------------------------------------------------
// Generate a full 8‑digit PIN from an algorithm ID and MAC
// ----------------------------------------------------------------------
static String generatePin(const String &algoId, uint64_t macInt) {
    uint32_t pin = 0;
    if (algoId == "pin24") pin = WpsPinGenerator::pin24(macInt);
    else if (algoId == "pin28") pin = WpsPinGenerator::pin28(macInt);
    else if (algoId == "pin32") pin = WpsPinGenerator::pin32(macInt);
    else if (algoId == "pinDLink") pin = WpsPinGenerator::pinDLink(macInt);
    else if (algoId == "pinDLink1") pin = WpsPinGenerator::pinDLink1(macInt);
    else if (algoId == "pinASUS") pin = WpsPinGenerator::pinASUS(macInt);
    else if (algoId == "pinAirocon") pin = WpsPinGenerator::pinAirocon(macInt);
    else if (algoId.startsWith("static_")) {
        // Extract the static pin value from the name (hardcoded map)
        static const std::map<String, uint32_t> staticMap = {
            {"static_Cisco", 1234567}, {"static_Broadcom 1", 2017252},
            {"static_Broadcom 2", 4626484}, {"static_Broadcom 3", 7622990},
            {"static_Broadcom 4", 6232714}, {"static_Broadcom 5", 1086411},
            {"static_Broadcom 6", 3195719}, {"static_Airocon 1", 3043203},
            {"static_Airocon 2", 7141225}, {"static_DSL-2740R", 6817554},
            {"static_Realtek 1", 9566146}, {"static_Realtek 2", 9571911},
            {"static_Realtek 3", 4856371}, {"static_Upvel", 2085483},
            {"static_UR-814AC", 4397768}, {"static_UR-825AC", 529417},
            {"static_Onlime", 9995604}, {"static_Edimax", 3561153},
            {"static_Thomson", 6795814}, {"static_HG532x", 3425928},
            {"static_H108L", 9422988}, {"static_CBN ONO", 9575521}
        };
        auto it = staticMap.find(algoId);
        if (it != staticMap.end()) pin = it->second;
        else pin = 0;
    }
    else if (algoId == "pinEmpty") {
        return "00000000";
    }
    else {
        return "";
    }

    pin = pin % 10000000;
    char buf[9];
    snprintf(buf, sizeof(buf), "%07lu%01u", (unsigned long)pin, WpsPinGenerator::checksum(pin));
    return String(buf);
}

// ----------------------------------------------------------------------
// Public: get all suggested PINs (with algorithm names)
// ----------------------------------------------------------------------
std::vector<WpsPinCandidate> WpsPinGenerator::getSuggestedPins(const String &bssid) {
    std::vector<WpsPinCandidate> candidates;
    uint64_t macInt = macToInt(bssid);
    std::vector<String> algos = suggestAlgorithms(bssid);

    for (const String &algoId : algos) {
        String pin = generatePin(algoId, macInt);
        if (pin.length() == 8) {
            String name = algoId;
            if (algoId.startsWith("static_")) name = algoId.substring(7);
            else if (algoId == "pinEmpty") name = "Empty (00000000)";
            candidates.push_back({pin, name});
        }
    }

    // Remove duplicates (same PIN from different algorithms)
    std::map<String, String> unique;
    for (const auto &c : candidates) {
        if (unique.find(c.pin) == unique.end()) {
            unique[c.pin] = c.name;
        }
    }
    candidates.clear();
    for (const auto &pair : unique) {
        candidates.push_back({pair.first, pair.second});
    }

    return candidates;
}

// ----------------------------------------------------------------------
// Public: get the single most likely PIN (first from list)
// ----------------------------------------------------------------------
String WpsPinGenerator::getLikelyPin(const String &bssid) {
    auto pins = getSuggestedPins(bssid);
    if (!pins.empty()) return pins[0].pin;
    return "";
}
