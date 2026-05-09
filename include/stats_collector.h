#pragma once

#include <Arduino.h>
#include <IPAddress.h>

#include "app_config.h"

namespace adblock32 {

enum class QueryAction : uint8_t {
  ALLOWED = 0,
  BLOCKED = 1,
  CACHED = 2,
  ERROR = 3,
};

struct QueryLogEntry {
  uint32_t timestampMs;
  uint32_t clientIp;
  char domain[80];
  QueryAction action;
  uint16_t responseTimeMs;
};

struct DomainFreq {
  char domain[80];
  uint32_t count;
};

struct ClientStat {
  uint32_t clientIp;
  uint32_t queryCount;
};

class StatsCollector {
 public:
  StatsCollector();

  void recordQuery(const String& domain, uint32_t clientIp,
                   QueryAction action, uint16_t responseTimeMs);

  uint32_t total() const { return total_; }
  uint32_t blocked() const { return blocked_; }
  uint32_t allowed() const { return allowed_; }
  uint32_t cached() const { return cached_; }
  uint32_t failed() const { return failed_; }

  size_t logCount() const;
  const QueryLogEntry* logEntry(size_t index) const;

  size_t topBlockedCount() const;
  const DomainFreq* topBlockedEntry(size_t index) const;

  size_t clientStatCount() const;
  const ClientStat* clientStatEntry(size_t index) const;

  void reset();

  String formatLogLine(const QueryLogEntry& entry) const;

 private:
  void trackTopDomain(const String& domain);
  void trackClient(uint32_t clientIp);

  uint32_t total_;
  uint32_t blocked_;
  uint32_t allowed_;
  uint32_t cached_;
  uint32_t failed_;

  QueryLogEntry log_[config::kQueryLogCapacity];
  size_t logHead_;
  size_t logSize_;

  DomainFreq topDomains_[config::kTopDomainsTracked];
  size_t topCount_;

  ClientStat clientStats_[config::kMaxTrackedClients];
  size_t clientCount_;
};

}  // namespace adblock32
