#pragma once

#include <Arduino.h>
#include <IPAddress.h>
#include <WiFiUdp.h>

#include "blocklist_store.h"
#include "dns_cache.h"
#include "display_status.h"
#include "filter_engine.h"
#include "stats_collector.h"

namespace adblock32 {

class DnsFilter {
 public:
  DnsFilter(BlocklistStore& blocklist, FilterEngine& filterEngine,
            DnsCache& cache, StatsCollector& stats,
            DisplayStatus& display);

  bool begin(const IPAddress& upstreamDnsServer);
  void stop();
  void poll();
  bool isRunning() const;
  const IPAddress& upstreamServer() const;

 private:
  bool extractQueryDomain(const uint8_t* packet, size_t packetLength,
                          String& domain) const;
  bool readDomainName(const uint8_t* packet, size_t packetLength, size_t& offset,
                      String& domain, uint8_t recursionDepth = 0) const;
  bool sendBlockedResponse(const uint8_t* request, size_t requestLength,
                           IPAddress remoteIp, uint16_t remotePort);
  size_t questionEndOffset(const uint8_t* packet, size_t packetLength) const;
  uint16_t extractQtype(const uint8_t* packet, size_t packetLength) const;

  BlocklistStore& blocklist_;
  FilterEngine& filterEngine_;
  DnsCache& cache_;
  StatsCollector& stats_;
  DisplayStatus& display_;
  WiFiUDP listener_;
  WiFiUDP upstream_;
  IPAddress upstreamServer_;
  bool running_ = false;
};

}  // namespace adblock32
