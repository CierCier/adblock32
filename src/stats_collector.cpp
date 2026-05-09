#include "stats_collector.h"

#include <string.h>

namespace adblock32 {

StatsCollector::StatsCollector()
    : total_(0),
      blocked_(0),
      allowed_(0),
      cached_(0),
      failed_(0),
      logHead_(0),
      logSize_(0),
      topCount_(0),
      clientCount_(0) {
  for (auto& entry : log_) {
    entry.domain[0] = '\0';
  }
  for (auto& freq : topDomains_) {
    freq.domain[0] = '\0';
    freq.count = 0;
  }
  for (auto& stat : clientStats_) {
    stat.clientIp = 0;
    stat.queryCount = 0;
  }
}

void StatsCollector::recordQuery(const String& domain, uint32_t clientIp,
                                 QueryAction action, uint16_t responseTimeMs) {
  ++total_;

  switch (action) {
    case QueryAction::BLOCKED:
      ++blocked_;
      trackTopDomain(domain);
      break;
    case QueryAction::ALLOWED:
      ++allowed_;
      break;
    case QueryAction::CACHED:
      ++cached_;
      break;
    case QueryAction::ERROR:
      ++failed_;
      break;
  }

  trackClient(clientIp);

  QueryLogEntry& entry = log_[logHead_];
  entry.timestampMs = millis();
  entry.clientIp = clientIp;
  size_t len = domain.length();
  if (len >= sizeof(entry.domain)) len = sizeof(entry.domain) - 1;
  memcpy(entry.domain, domain.c_str(), len);
  entry.domain[len] = '\0';
  entry.action = action;
  entry.responseTimeMs = responseTimeMs;

  logHead_ = (logHead_ + 1) % config::kQueryLogCapacity;
  if (logSize_ < config::kQueryLogCapacity) ++logSize_;
}

size_t StatsCollector::logCount() const { return logSize_; }

const QueryLogEntry* StatsCollector::logEntry(size_t index) const {
  if (index >= logSize_) return nullptr;
  const size_t physicalIndex =
      (logHead_ + config::kQueryLogCapacity - logSize_ + index) %
      config::kQueryLogCapacity;
  return &log_[physicalIndex];
}

void StatsCollector::trackTopDomain(const String& domain) {
  // Check if already tracked
  for (size_t i = 0; i < topCount_; ++i) {
    if (domain == topDomains_[i].domain) {
      ++topDomains_[i].count;
      return;
    }
  }

  // Add new entry
  if (topCount_ < config::kTopDomainsTracked) {
    size_t len = domain.length();
    if (len >= sizeof(topDomains_[topCount_].domain))
      len = sizeof(topDomains_[topCount_].domain) - 1;
    memcpy(topDomains_[topCount_].domain, domain.c_str(), len);
    topDomains_[topCount_].domain[len] = '\0';
    topDomains_[topCount_].count = 1;
    ++topCount_;
  }
}

void StatsCollector::trackClient(uint32_t clientIp) {
  for (size_t i = 0; i < clientCount_; ++i) {
    if (clientStats_[i].clientIp == clientIp) {
      ++clientStats_[i].queryCount;
      return;
    }
  }

  if (clientCount_ < config::kMaxTrackedClients) {
    clientStats_[clientCount_].clientIp = clientIp;
    clientStats_[clientCount_].queryCount = 1;
    ++clientCount_;
  }
}

size_t StatsCollector::topBlockedCount() const { return topCount_; }

const DomainFreq* StatsCollector::topBlockedEntry(size_t index) const {
  if (index >= topCount_) return nullptr;

  // Find the index-th largest count via selection
  size_t best = topCount_;
  for (size_t i = 0; i < topCount_; ++i) {
    bool skip = false;
    for (size_t j = 0; j < index; ++j) {
      const DomainFreq* prev = topBlockedEntry(j);
      if (prev == &topDomains_[i]) { skip = true; break; }
    }
    if (skip) continue;

    if (best == topCount_ ||
        topDomains_[i].count > topDomains_[best].count ||
        (topDomains_[i].count == topDomains_[best].count &&
         strcmp(topDomains_[i].domain, topDomains_[best].domain) < 0)) {
      best = i;
    }
  }
  return &topDomains_[best];
}

// Simple descending sort by count
size_t StatsCollector::clientStatCount() const { return clientCount_; }

const ClientStat* StatsCollector::clientStatEntry(size_t index) const {
  if (index >= clientCount_) return nullptr;
  return &clientStats_[index];
}

void StatsCollector::reset() {
  total_ = 0;
  blocked_ = 0;
  allowed_ = 0;
  cached_ = 0;
  failed_ = 0;
  logHead_ = 0;
  logSize_ = 0;
  topCount_ = 0;
  clientCount_ = 0;
  for (auto& entry : log_) entry.domain[0] = '\0';
  for (auto& freq : topDomains_) {
    freq.domain[0] = '\0';
    freq.count = 0;
  }
  for (auto& stat : clientStats_) {
    stat.clientIp = 0;
    stat.queryCount = 0;
  }
}

String StatsCollector::formatLogLine(const QueryLogEntry& entry) const {
  String line;
  line += IPAddress(entry.clientIp).toString();
  line += ' ';
  switch (entry.action) {
    case QueryAction::ALLOWED:
      line += "ALLOW ";
      break;
    case QueryAction::BLOCKED:
      line += "BLOCK ";
      break;
    case QueryAction::CACHED:
      line += "CACHE ";
      break;
    case QueryAction::ERROR:
      line += "ERROR ";
      break;
  }
  line += entry.domain;
  line += ' ';
  line += String(entry.responseTimeMs);
  line += "ms";
  return line;
}

}  // namespace adblock32
