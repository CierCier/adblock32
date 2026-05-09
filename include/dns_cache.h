#pragma once

#include <Arduino.h>

#include "app_config.h"

namespace adblock32 {

struct DnsCacheEntry {
  String key;
  uint8_t response[config::kDnsPacketBufferSize];
  size_t responseLen;
  uint32_t expiresAt;  // millis() deadline
  bool valid;
};

class DnsCache {
 public:
  DnsCache();

  const DnsCacheEntry* lookup(const String& domain, uint16_t qtype) const;
  void insert(const String& domain, uint16_t qtype, const uint8_t* response,
              size_t len, uint32_t ttlSecs);
  void insertNegative(const String& domain, uint16_t qtype);
  void flush();
  size_t count() const;
  size_t capacity() const;

 private:
  size_t evictSlot();
  static String makeKey(const String& domain, uint16_t qtype);

  DnsCacheEntry entries_[config::kDnsCacheSize];
  size_t insertIndex_;
};

}  // namespace adblock32
