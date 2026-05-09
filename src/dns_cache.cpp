#include "dns_cache.h"

#include <string.h>

namespace adblock32 {
namespace {
bool dnsResponseHasRcode(const uint8_t* response, size_t len,
                         uint8_t expectedRcode) {
  if (len < 4) return false;
  return (response[3] & 0x0F) == expectedRcode;
}
}  // namespace

DnsCache::DnsCache() {
  for (auto& entry : entries_) {
    entry.valid = false;
  }
  insertIndex_ = 0;
}

const DnsCacheEntry* DnsCache::lookup(const String& domain,
                                      uint16_t qtype) const {
  const String key = makeKey(domain, qtype);
  const uint32_t now = millis();

  for (size_t i = 0; i < config::kDnsCacheSize; ++i) {
    const DnsCacheEntry& entry = entries_[i];
    if (!entry.valid) continue;
    if (entry.key != key) continue;
    if (now >= entry.expiresAt) continue;
    return &entry;
  }

  return nullptr;
}

void DnsCache::insert(const String& domain, uint16_t qtype,
                      const uint8_t* response, size_t len, uint32_t ttlSecs) {
  if (len == 0 || len > config::kDnsPacketBufferSize) return;

  // Clamp TTL
  if (ttlSecs == 0 || ttlSecs > config::kDnsCacheMaxTtlMs / 1000) {
    ttlSecs = config::kDnsCacheMaxTtlMs / 1000;
  }
  // Don't cache server failure responses
  if (dnsResponseHasRcode(response, len, 2)) return;

  const size_t slot = evictSlot();
  DnsCacheEntry& entry = entries_[slot];
  entry.key = makeKey(domain, qtype);
  memcpy(entry.response, response, len);
  entry.responseLen = len;
  entry.expiresAt = millis() + ttlSecs * 1000;
  entry.valid = true;
}

void DnsCache::insertNegative(const String& domain, uint16_t qtype) {
  const size_t slot = evictSlot();
  DnsCacheEntry& entry = entries_[slot];
  entry.key = makeKey(domain, qtype);
  entry.responseLen = 0;
  entry.expiresAt = millis() + config::kDnsCacheNegTtlMs;
  entry.valid = true;
}

void DnsCache::flush() {
  for (auto& entry : entries_) {
    entry.valid = false;
  }
}

size_t DnsCache::count() const {
  size_t n = 0;
  for (const auto& entry : entries_) {
    if (entry.valid) ++n;
  }
  return n;
}

size_t DnsCache::capacity() const { return config::kDnsCacheSize; }

size_t DnsCache::evictSlot() {
  const size_t slot = insertIndex_;
  insertIndex_ = (insertIndex_ + 1) % config::kDnsCacheSize;
  return slot;
}

String DnsCache::makeKey(const String& domain, uint16_t qtype) {
  String key = domain;
  key += '|';
  key += String(qtype);
  return key;
}

}  // namespace adblock32
