#include "dns_filter.h"

#include <WiFi.h>

#include "app_config.h"

namespace adblock32 {
namespace {
constexpr uint8_t kDnsFlagQrResponse = 0x80;
constexpr uint8_t kDnsFlagRecursionAvailable = 0x80;
constexpr uint8_t kDnsRcodeNxDomain = 0x03;
constexpr uint8_t kDnsRcodeSuccess = 0x00;
constexpr uint8_t kMaxCompressionDepth = 8;
constexpr uint16_t kDnsQtypeA = 1;
constexpr uint16_t kDnsQtypeAaaa = 28;

uint32_t readU32(const uint8_t* p) {
  return (static_cast<uint32_t>(p[0]) << 24) |
         (static_cast<uint32_t>(p[1]) << 16) |
         (static_cast<uint32_t>(p[2]) << 8) | static_cast<uint32_t>(p[3]);
}
}  // namespace

DnsFilter::DnsFilter(BlocklistStore& blocklist, FilterEngine& filterEngine,
                     DnsCache& cache, StatsCollector& stats,
                     DisplayStatus& display)
    : blocklist_(blocklist),
      filterEngine_(filterEngine),
      cache_(cache),
      stats_(stats),
      display_(display) {}

bool DnsFilter::begin(const IPAddress& upstreamDnsServer) {
  stop();

  upstreamServer_ = upstreamDnsServer;
  if (!listener_.begin(config::kDnsListenPort)) {
    return false;
  }

  if (!upstream_.begin(0)) {
    listener_.stop();
    return false;
  }

  running_ = true;
  return true;
}

void DnsFilter::stop() {
  if (running_) {
    listener_.stop();
    upstream_.stop();
  }
  running_ = false;
}

void DnsFilter::poll() {
  if (!running_) return;

  const int packetLength = listener_.parsePacket();
  if (packetLength <= 0 ||
      packetLength > static_cast<int>(config::kDnsPacketBufferSize)) {
    return;
  }

  uint8_t packet[config::kDnsPacketBufferSize];
  const int bytesRead = listener_.read(packet, sizeof(packet));
  if (bytesRead <= 0) return;

  String domain;
  if (!extractQueryDomain(packet, bytesRead, domain)) return;

  const IPAddress remoteIp = listener_.remoteIP();
  const uint16_t remotePort = listener_.remotePort();
  const uint32_t clientIp = static_cast<uint32_t>(remoteIp);
  const uint16_t qtype = extractQtype(packet, bytesRead);

  const uint32_t startMs = millis();

  // 1. Cache lookup
  const DnsCacheEntry* cached = cache_.lookup(domain, qtype);
  if (cached) {
    if (cached->responseLen > 0) {
      listener_.beginPacket(remoteIp, remotePort);
      listener_.write(cached->response, cached->responseLen);
      listener_.endPacket();
    } else {
      sendBlockedResponse(packet, bytesRead, remoteIp, remotePort);
    }
    stats_.recordQuery(domain, clientIp, QueryAction::CACHED,
                       static_cast<uint16_t>(millis() - startMs));
    return;
  }

  // 2. Filter evaluation
  const FilterAction action = filterEngine_.evaluate(domain, clientIp);

  if (action == FilterAction::BLOCK) {
    sendBlockedResponse(packet, bytesRead, remoteIp, remotePort);
    cache_.insertNegative(domain, qtype);
    display_.onBlocked(domain);
    stats_.recordQuery(domain, clientIp, QueryAction::BLOCKED,
                       static_cast<uint16_t>(millis() - startMs));
    return;
  }

  // 3. Forward upstream (socket kept open across queries)
  //    Drain any stale response left in the socket
  while (upstream_.parsePacket() > 0) {
    uint8_t trash[config::kDnsPacketBufferSize];
    upstream_.read(trash, sizeof(trash));
  }

  upstream_.beginPacket(upstreamServer_, config::kDnsUpstreamPort);
  upstream_.write(packet, bytesRead);
  if (upstream_.endPacket() != 1) {
    stats_.recordQuery(domain, clientIp, QueryAction::ERROR,
                       static_cast<uint16_t>(millis() - startMs));
    return;
  }

  const uint32_t timeoutMs = millis();
  while (millis() - timeoutMs < config::kDnsForwardTimeoutMs) {
    const int responseLength = upstream_.parsePacket();
    if (responseLength <= 0) {
      delay(5);
      continue;
    }

    if (responseLength > static_cast<int>(config::kDnsPacketBufferSize)) {
      stats_.recordQuery(domain, clientIp, QueryAction::ERROR,
                         static_cast<uint16_t>(millis() - startMs));
      return;
    }

    uint8_t response[config::kDnsPacketBufferSize];
    const int responseBytes = upstream_.read(response, sizeof(response));
    if (responseBytes <= 0) {
      stats_.recordQuery(domain, clientIp, QueryAction::ERROR,
                         static_cast<uint16_t>(millis() - startMs));
      return;
    }

    listener_.beginPacket(remoteIp, remotePort);
    listener_.write(response, responseBytes);
    listener_.endPacket();

    // Cache the response with TTL from first answer record
    uint32_t ttl = 60;
    if (responseBytes > 12 && (response[3] & 0x0F) == kDnsRcodeSuccess) {
      // Skip header (12) and question section to find first answer
      size_t offset = 12;
      // Read through the question domain name
      while (offset < static_cast<size_t>(responseBytes)) {
        const uint8_t len = response[offset];
        if (len == 0) { ++offset; break; }
        if ((len & 0xC0) == 0xC0) { offset += 2; break; }
        offset += 1 + len;
      }
      // Skip type (2) and class (2) of question
      offset += 4;
      // Parse first answer: skip name (compressed), type (2), class (2)
      if (offset + 12 <= static_cast<size_t>(responseBytes)) {
        // Check for compression in answer name
        if ((response[offset] & 0xC0) == 0xC0) {
          offset += 2;
        } else {
          while (offset < static_cast<size_t>(responseBytes)) {
            const uint8_t alen = response[offset];
            if (alen == 0) { ++offset; break; }
            offset += 1 + alen;
          }
        }
        offset += 4;  // skip type + class
        if (offset + 4 <= static_cast<size_t>(responseBytes)) {
          ttl = readU32(response + offset);
          if (ttl > config::kDnsCacheMaxTtlMs / 1000) {
            ttl = config::kDnsCacheMaxTtlMs / 1000;
          }
        }
      }
    }

    cache_.insert(domain, qtype, response, responseBytes, ttl);
    stats_.recordQuery(domain, clientIp, QueryAction::ALLOWED,
                       static_cast<uint16_t>(millis() - startMs));
    return;
  }

  // Timeout
  stats_.recordQuery(domain, clientIp, QueryAction::ERROR,
                     static_cast<uint16_t>(millis() - startMs));
}

bool DnsFilter::isRunning() const { return running_; }

const IPAddress& DnsFilter::upstreamServer() const { return upstreamServer_; }

uint16_t DnsFilter::extractQtype(const uint8_t* packet,
                                 size_t packetLength) const {
  if (packetLength < 12) return 0;
  const uint16_t questionCount = (packet[4] << 8) | packet[5];
  if (questionCount == 0) return 0;

  // Skip the question domain name to find qtype
  size_t offset = 12;
  String dummy;
  if (!readDomainName(packet, packetLength, offset, dummy)) return 0;
  if (offset + 4 > packetLength) return 0;
  return (packet[offset] << 8) | packet[offset + 1];
}

bool DnsFilter::extractQueryDomain(const uint8_t* packet, size_t packetLength,
                                   String& domain) const {
  if (packetLength < 12) return false;

  const uint16_t questionCount = (packet[4] << 8) | packet[5];
  if (questionCount == 0) return false;

  size_t offset = 12;
  return readDomainName(packet, packetLength, offset, domain);
}

bool DnsFilter::readDomainName(const uint8_t* packet, size_t packetLength,
                               size_t& offset, String& domain,
                               uint8_t recursionDepth) const {
  if (recursionDepth > kMaxCompressionDepth || offset >= packetLength) {
    return false;
  }

  String result;
  bool jumped = false;
  size_t localOffset = offset;

  while (localOffset < packetLength) {
    const uint8_t length = packet[localOffset];
    if (length == 0) {
      localOffset += 1;
      if (!jumped) offset = localOffset;
      domain = result;
      domain.toLowerCase();
      return !domain.isEmpty();
    }

    if ((length & 0xC0) == 0xC0) {
      if (localOffset + 1 >= packetLength) return false;
      const uint16_t pointer =
          ((length & 0x3F) << 8) | packet[localOffset + 1];
      if (!jumped) offset = localOffset + 2;
      localOffset = pointer;
      jumped = true;
      ++recursionDepth;
      if (recursionDepth > kMaxCompressionDepth) return false;
      continue;
    }

    if (localOffset + 1 + length > packetLength) return false;

    if (!result.isEmpty()) result += '.';
    for (uint8_t i = 0; i < length; ++i) {
      result += static_cast<char>(tolower(packet[localOffset + 1 + i]));
    }
    localOffset += 1 + length;
  }

  return false;
}

size_t DnsFilter::questionEndOffset(const uint8_t* packet,
                                    size_t packetLength) const {
  if (packetLength < 12) return 0;
  const uint16_t qdcount = (packet[4] << 8) | packet[5];
  if (qdcount == 0) return 0;

  size_t offset = 12;
  String dummy;
  if (!readDomainName(packet, packetLength, offset, dummy)) return 0;
  // Skip QTYPE (2) + QCLASS (2)
  if (offset + 4 > packetLength) return 0;
  return offset + 4;
}

bool DnsFilter::sendBlockedResponse(const uint8_t* request,
                                    size_t requestLength, IPAddress remoteIp,
                                    uint16_t remotePort) {
  if (requestLength < 12) return false;

  const size_t qEnd = questionEndOffset(request, requestLength);
  if (qEnd == 0 || qEnd > requestLength) return false;

  uint8_t response[config::kDnsPacketBufferSize];
  memcpy(response, request, qEnd);
  response[2] |= kDnsFlagQrResponse;
  response[3] |= kDnsFlagRecursionAvailable;
  response[3] = (response[3] & 0xF0) | kDnsRcodeNxDomain;
  response[6] = 0;
  response[7] = 0;
  response[8] = 0;
  response[9] = 0;
  response[10] = 0;
  response[11] = 0;

  listener_.beginPacket(remoteIp, remotePort);
  listener_.write(response, qEnd);
  return listener_.endPacket() == 1;
}

}  // namespace adblock32
