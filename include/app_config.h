#pragma once

#ifndef ADBLOCK32_ENABLE_DISPLAY
#define ADBLOCK32_ENABLE_DISPLAY 0
#endif

namespace adblock32::config {
constexpr uint32_t kSerialBaudRate = 115200;
constexpr uint32_t kStartupDelayMs = 250;
constexpr uint32_t kReconnectTimeoutMs = 15000;
constexpr uint16_t kDnsListenPort = 53;
constexpr uint16_t kDnsUpstreamPort = 53;
constexpr uint16_t kDnsForwardTimeoutMs = 2000;
constexpr size_t kDnsPacketBufferSize = 512;
constexpr size_t kMaxCustomBlockRules = 64;
constexpr size_t kMaxAllowRules = 64;
constexpr size_t kMaxCustomPolicies = 16;
constexpr size_t kMaxRemoteBlockRules = 2048;
constexpr size_t kMaxRemoteSources = 8;
constexpr size_t kDnsCacheSize = 64;
constexpr uint32_t kDnsCacheMaxTtlMs = 3600000;
constexpr uint32_t kDnsCacheNegTtlMs = 30000;
constexpr size_t kQueryLogCapacity = 200;
constexpr size_t kTopDomainsTracked = 50;
constexpr size_t kTopBlockedReturned = 10;
constexpr size_t kMaxTrackedClients = 16;
constexpr uint32_t kRemoteRefreshIntervalSeconds = 24 * 60 * 60;
constexpr uint32_t kRemoteRefreshRetrySeconds = 15 * 60;
constexpr char kPreferencesNamespace[] = "adblock32";
constexpr char kSsidKey[] = "wifi_ssid";
constexpr char kPasswordKey[] = "wifi_pass";
constexpr char kBlocklistKey[] = "blocklist";
constexpr char kAllowlistKey[] = "allowlist";
constexpr char kRemoteBlocklistKey[] = "remote_bl";
constexpr char kRemoteRefreshTimeKey[] = "remote_ts";
constexpr char kRemoteSourcesKey[] = "remote_src";
constexpr char kPoliciesKey[] = "policies";
}  // namespace adblock32::config
