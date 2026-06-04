#ifndef WPS_PIN_GENERATOR_H
#define WPS_PIN_GENERATOR_H

#include <Arduino.h>
#include <vector>

struct WpsPinCandidate {
    String pin;      // 8‑digit WPS PIN
    String name;     // algorithm name
};

class WpsPinGenerator {
public:
    // Public API
    std::vector<WpsPinCandidate> getSuggestedPins(const String &bssid);
    String getLikelyPin(const String &bssid);
    static uint8_t checksum(uint32_t pin);

    // Algorithm methods (made public so they can be used by the helper)
    static uint32_t pin24(uint64_t macInt);
    static uint32_t pin28(uint64_t macInt);
    static uint32_t pin32(uint64_t macInt);
    static uint32_t pinDLink(uint64_t macInt);
    static uint32_t pinDLink1(uint64_t macInt);
    static uint32_t pinASUS(uint64_t macInt);
    static uint32_t pinAirocon(uint64_t macInt);

private:
    static uint64_t macToInt(const String &mac);
    std::vector<String> suggestAlgorithms(const String &bssid);
};

#endif
