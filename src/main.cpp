#include <Arduino.h>
#include <IPAddress.h>
#include <WiFi.h>

#include "app_config.h"
#include "blocklist_store.h"
#include "dns_cache.h"
#include "dns_filter.h"
#include "display_status.h"
#include "filter_engine.h"
#include "remote_filter_updater.h"
#include "stats_collector.h"
#include "wifi_credentials.h"

namespace adblock32 {
namespace {
constexpr const char* kMagicPrefix = "\x02\xAD\x32";

DisplayStatus g_display;
WiFiCredentialStore g_credentialStore;
BlocklistStore g_blocklistStore;
FilterEngine g_filterEngine(g_blocklistStore);
DnsCache g_dnsCache;
StatsCollector g_stats;
DnsFilter g_dnsFilter(g_blocklistStore, g_filterEngine, g_dnsCache, g_stats,
                      g_display);
RemoteFilterUpdater g_remoteFilterUpdater(g_blocklistStore);
String g_serialBuffer;
const IPAddress kDefaultUpstreamDns(1, 1, 1, 1);

RuleType parseRuleType(const String& s) {
  if (s == "exact" || s == "E") return RuleType::EXACT;
  if (s == "glob" || s == "G" || s == "wildcard") return RuleType::GLOB;
  return RuleType::SUFFIX;
}

void printHelp() {
  Serial.println("commands:");
  Serial.println("  filter add <domain> [exact|suffix|glob]");
  Serial.println("  filter remove <domain>");
  Serial.println("  filter allow <domain> [exact|suffix|glob]");
  Serial.println("  filter unallow <domain>");
  Serial.println("  filter list");
  Serial.println("  filter cache flush");
  Serial.println("  filter policy add <cidr> <name>");
  Serial.println("  filter policy remove <name>");
  Serial.println("  filter policy add-rule <name> <domain> [allow|block] [type]");
  Serial.println("  filter policy remove-rule <name> <domain> [allow|block]");
  Serial.println("  filter policy list");
  Serial.println("  filter refresh");
  Serial.println("  source add <url>");
  Serial.println("  source remove <url>");
  Serial.println("  source list");
  Serial.println("  stats");
  Serial.println("  stats log [n]");
  Serial.println("  stats top [n]");
  Serial.println("  stats reset");
  Serial.println("  help");
}

void stopDnsFilter() {
  if (g_dnsFilter.isRunning()) {
    g_dnsFilter.stop();
    Serial.println("dns: filter stopped");
    g_display.showMessage("DNS filter", "Stopped");
  }
}

void startDnsFilter() {
  if (WiFi.status() != WL_CONNECTED) {
    Serial.println("dns: wifi not connected");
    return;
  }

  if (g_dnsFilter.begin(kDefaultUpstreamDns)) {
    Serial.printf("dns: listening on port %u, upstream=%s\n",
                  config::kDnsListenPort,
                  g_dnsFilter.upstreamServer().toString().c_str());
    g_display.showMessage("DNS filter", "Active");
    g_remoteFilterUpdater.poll();
  } else {
    Serial.println("dns: failed to start listener");
    g_display.showMessage("DNS filter", "Start failed");
  }
}

bool connectToWiFi(const WiFiCredentials& credentials) {
  if (!credentials.isValid()) {
    Serial.println("wifi: no saved credentials");
    g_display.showMessage("WiFi", "No credentials");
    return false;
  }

  WiFi.mode(WIFI_STA);
  WiFi.begin(credentials.ssid.c_str(), credentials.password.c_str());

  Serial.printf("wifi: connecting to %s\n", credentials.ssid.c_str());
  g_display.showMessage("WiFi connect", credentials.ssid);

  const uint32_t startMs = millis();
  while (WiFi.status() != WL_CONNECTED &&
         millis() - startMs < config::kReconnectTimeoutMs) {
    delay(250);
    Serial.print('.');
  }
  Serial.println();

  if (WiFi.status() != WL_CONNECTED) {
    Serial.println("wifi: connect failed");
    g_display.showMessage("WiFi failed", credentials.ssid);
    stopDnsFilter();
    return false;
  }

  Serial.printf("wifi: connected, ip=%s\n", WiFi.localIP().toString().c_str());
  g_display.showMessage("WiFi connected", WiFi.localIP().toString());
  startDnsFilter();
  return true;
}

void attemptAutoReconnect() {
  WiFiCredentials credentials;
  if (!g_credentialStore.load(credentials)) {
    Serial.println("wifi: no credentials found, use setup-wifi.py");
    g_display.showMessage("adblock32", "Run setup-wifi.py");
    return;
  }

  connectToWiFi(credentials);
}

// Hidden wifi provisioning – only reachable via magic prefix
void handleWifiSetCommand(const String& payload) {
  const int separator = payload.indexOf('|');
  if (separator <= 0) {
    Serial.println("wifi: usage wifi set <ssid>|<password>");
    return;
  }

  WiFiCredentials credentials;
  credentials.ssid = payload.substring(0, separator);
  credentials.password = payload.substring(separator + 1);

  if (!g_credentialStore.save(credentials)) {
    Serial.println("wifi: failed to save credentials");
    return;
  }

  WiFi.disconnect(true, true);
  delay(300);

  Serial.println("wifi: credentials saved, connecting...");
  connectToWiFi(credentials);
}

void handleHiddenWifiCommand(const String& command) {
  if (command == "wifi clear") {
    WiFi.disconnect(true, true);
    stopDnsFilter();
    Serial.println(g_credentialStore.clear() ? "wifi: credentials cleared"
                                             : "wifi: clear failed");
    g_display.showMessage("WiFi", "Credentials cleared");
    return;
  }

  if (command == "wifi status") {
    Serial.printf("wifi: status=%d ssid=%s ip=%s\n", WiFi.status(),
                  WiFi.SSID().c_str(), WiFi.localIP().toString().c_str());
    return;
  }

  if (command.startsWith("wifi set ")) {
    handleWifiSetCommand(command.substring(9));
    return;
  }

  Serial.println("wifi: unknown hidden command");
}

void handleFilterCommand(const String& command) {
  if (command == "list" || command == "status") {
    Serial.printf("filter: %s\n", g_blocklistStore.describeRules().c_str());
    Serial.printf("filter remote: %s\n",
                  g_remoteFilterUpdater.describeStatus().c_str());
    Serial.printf("filter sources: %s\n",
                  g_remoteFilterUpdater.describeSources().c_str());
    Serial.printf("filter policies: %s\n",
                  g_filterEngine.describePolicies().c_str());
    Serial.printf("dns: %s, cache: %u/%u\n",
                  g_dnsFilter.isRunning() ? "running" : "stopped",
                  static_cast<unsigned>(g_dnsCache.count()),
                  static_cast<unsigned>(g_dnsCache.capacity()));
    return;
  }

  if (command == "refresh") {
    const bool refreshed = g_remoteFilterUpdater.refreshNow();
    Serial.println(refreshed ? "filter: remote refresh complete"
                             : "filter: remote refresh failed");
    return;
  }

  if (command == "cache flush") {
    g_dnsCache.flush();
    Serial.println("filter: cache flushed");
    return;
  }

  if (command.startsWith("allow ")) {
    String rest = command.substring(6);
    String domain = rest;
    RuleType type = RuleType::SUFFIX;
    const int spaceIdx = rest.indexOf(' ');
    if (spaceIdx > 0) {
      domain = rest.substring(0, spaceIdx);
      type = parseRuleType(rest.substring(spaceIdx + 1));
    }
    if (g_blocklistStore.addAllowRule(domain, type)) {
      Serial.printf("filter: allowed %s\n", domain.c_str());
      return;
    }
    Serial.println("filter: allow failed");
    return;
  }

  if (command.startsWith("unallow ")) {
    const String domain = command.substring(8);
    if (g_blocklistStore.removeAllowRule(domain)) {
      Serial.printf("filter: unallowed %s\n", domain.c_str());
      return;
    }
    Serial.println("filter: unallow failed");
    return;
  }

  if (command.startsWith("policy ")) {
    String rest = command.substring(7);

    if (rest == "list") {
      Serial.printf("filter policies: %s\n",
                    g_filterEngine.describePolicies().c_str());
      return;
    }

    if (rest.startsWith("add ")) {
      String args = rest.substring(4);
      const int spaceIdx = args.indexOf(' ');
      if (spaceIdx <= 0) {
        Serial.println("filter: usage policy add <cidr> <name>");
        return;
      }
      const String cidr = args.substring(0, spaceIdx);
      const String name = args.substring(spaceIdx + 1);
      if (g_filterEngine.addPolicy(cidr, name)) {
        Serial.printf("filter: policy added %s %s\n", cidr.c_str(),
                      name.c_str());
        return;
      }
      Serial.println("filter: policy add failed");
      return;
    }

    if (rest.startsWith("remove ")) {
      const String name = rest.substring(7);
      if (g_filterEngine.removePolicy(name)) {
        Serial.printf("filter: policy removed %s\n", name.c_str());
        return;
      }
      Serial.println("filter: policy remove failed");
      return;
    }

    if (rest.startsWith("add-rule ")) {
      String args = rest.substring(9);
      const int nameEnd = args.indexOf(' ');
      if (nameEnd <= 0) {
        Serial.println("filter: usage policy add-rule <name> <domain> [allow|block] [type]");
        return;
      }
      String name = args.substring(0, nameEnd);
      String rest2 = args.substring(nameEnd + 1);
      const int domainEnd = rest2.indexOf(' ');
      String domain = rest2;
      bool isAllow = true;
      RuleType rtype = RuleType::SUFFIX;
      if (domainEnd > 0) {
        domain = rest2.substring(0, domainEnd);
        String rest3 = rest2.substring(domainEnd + 1);
        const int modeEnd = rest3.indexOf(' ');
        if (rest3.startsWith("block")) isAllow = false;
        if (modeEnd > 0) rtype = parseRuleType(rest3.substring(modeEnd + 1));
      }
      if (g_filterEngine.policyAddRule(name, domain, rtype, isAllow)) {
        Serial.printf("filter: policy rule added %s\n", domain.c_str());
        return;
      }
      Serial.println("filter: policy add-rule failed");
      return;
    }

    if (rest.startsWith("remove-rule ")) {
      String args = rest.substring(12);
      const int nameEnd = args.indexOf(' ');
      if (nameEnd <= 0) {
        Serial.println("filter: usage policy remove-rule <name> <domain> [allow|block]");
        return;
      }
      String name = args.substring(0, nameEnd);
      String rest2 = args.substring(nameEnd + 1);
      const int domainEnd = rest2.indexOf(' ');
      String domain = rest2;
      bool isAllow = true;
      if (domainEnd > 0) {
        domain = rest2.substring(0, domainEnd);
        if (rest2.substring(domainEnd + 1) == "block") isAllow = false;
      }
      if (g_filterEngine.policyRemoveRule(name, domain, isAllow)) {
        Serial.printf("filter: policy rule removed %s\n", domain.c_str());
        return;
      }
      Serial.println("filter: policy remove-rule failed");
      return;
    }

    Serial.println("filter: unknown policy command");
    printHelp();
    return;
  }

  if (command.startsWith("add ")) {
    String rest = command.substring(4);
    String domain = rest;
    RuleType type = RuleType::SUFFIX;
    const int spaceIdx = rest.indexOf(' ');
    if (spaceIdx > 0) {
      domain = rest.substring(0, spaceIdx);
      type = parseRuleType(rest.substring(spaceIdx + 1));
    }
    if (g_blocklistStore.addRule(domain, type)) {
      Serial.printf("filter: added %s\n", domain.c_str());
      return;
    }
    Serial.println("filter: add failed");
    return;
  }

  if (command.startsWith("remove ")) {
    const String domain = command.substring(7);
    if (g_blocklistStore.removeRule(domain)) {
      Serial.printf("filter: removed %s\n", domain.c_str());
      return;
    }
    Serial.println("filter: remove failed");
    return;
  }

  Serial.println("filter: unknown command");
  printHelp();
}

void handleSourceCommand(const String& command) {
  if (command == "list") {
    Serial.printf("source: %s\n", g_remoteFilterUpdater.describeSources().c_str());
    return;
  }

  if (command.startsWith("add ")) {
    const String url = command.substring(4);
    if (g_remoteFilterUpdater.addSource(url)) {
      Serial.println("source: added");
      return;
    }
    Serial.println("source: add failed");
    return;
  }

  if (command.startsWith("remove ")) {
    const String url = command.substring(7);
    if (g_remoteFilterUpdater.removeSource(url)) {
      Serial.println("source: removed");
      return;
    }
    Serial.println("source: remove failed");
    return;
  }

  Serial.println("source: unknown command");
  printHelp();
}

void handleStatsCommand(const String& command) {
  if (command.isEmpty() || command == "show") {
    Serial.printf("stats: total=%u blocked=%u allowed=%u cached=%u failed=%u\n",
                  static_cast<unsigned>(g_stats.total()),
                  static_cast<unsigned>(g_stats.blocked()),
                  static_cast<unsigned>(g_stats.allowed()),
                  static_cast<unsigned>(g_stats.cached()),
                  static_cast<unsigned>(g_stats.failed()));
    Serial.printf("stats: clients=%u log=%u/%u\n",
                  static_cast<unsigned>(g_stats.clientStatCount()),
                  static_cast<unsigned>(g_stats.logCount()),
                  static_cast<unsigned>(config::kQueryLogCapacity));
    return;
  }

  if (command == "reset") {
    g_stats.reset();
    Serial.println("stats: reset");
    return;
  }

  if (command.startsWith("log")) {
    int n = 20;
    if (command.length() > 4) {
      n = command.substring(4).toInt();
      if (n <= 0) n = 20;
    }
    const size_t count = g_stats.logCount();
    if (count == 0) {
      Serial.println("stats: no log entries");
      return;
    }
    if (static_cast<size_t>(n) > count) n = static_cast<int>(count);
    const size_t start = count - n;
    for (size_t i = start; i < count; ++i) {
      const QueryLogEntry* entry = g_stats.logEntry(i);
      if (entry) Serial.println(g_stats.formatLogLine(*entry));
    }
    return;
  }

  if (command.startsWith("top")) {
    int n = config::kTopBlockedReturned;
    if (command.length() > 4) {
      n = command.substring(4).toInt();
      if (n <= 0) n = config::kTopBlockedReturned;
    }
    const size_t count = g_stats.topBlockedCount();
    if (count == 0) {
      Serial.println("stats: no blocked domains tracked");
      return;
    }
    if (static_cast<size_t>(n) > count) n = static_cast<int>(count);
    Serial.printf("stats: top %d blocked domains:\n", n);
    for (int i = 0; i < n; ++i) {
      const DomainFreq* freq = g_stats.topBlockedEntry(i);
      if (freq) {
        Serial.printf("  %u %s\n", static_cast<unsigned>(freq->count),
                      freq->domain);
      }
    }
    return;
  }

  Serial.println("stats: unknown command");
  printHelp();
}

void processCommand(const String& rawCommand) {
  String command = rawCommand;
  command.trim();
  if (command.isEmpty()) return;

  // Hidden wifi protocol – used by setup-wifi.py
  if (command.startsWith(kMagicPrefix)) {
    handleHiddenWifiCommand(command.substring(3));
    return;
  }

  if (command == "help") {
    printHelp();
    return;
  }

  if (command.startsWith("filter ")) {
    handleFilterCommand(command.substring(7));
    return;
  }

  if (command.startsWith("source ")) {
    handleSourceCommand(command.substring(7));
    return;
  }

  if (command.startsWith("stats")) {
    String rest = command.substring(5);
    rest.trim();
    handleStatsCommand(rest);
    return;
  }

  Serial.println("unknown command");
  printHelp();
}

void pollSerialCommands() {
  while (Serial.available() > 0) {
    const char ch = static_cast<char>(Serial.read());
    if (ch == '\r') continue;
    if (ch == '\n') {
      processCommand(g_serialBuffer);
      g_serialBuffer = "";
      continue;
    }
    g_serialBuffer += ch;
  }
}
}  // namespace
}  // namespace adblock32

void setup() {
  Serial.begin(adblock32::config::kSerialBaudRate);
  delay(adblock32::config::kStartupDelayMs);

  adblock32::g_display.begin();
  adblock32::g_display.showBootBanner();
  adblock32::g_blocklistStore.begin();
  adblock32::g_filterEngine.begin();
  adblock32::g_remoteFilterUpdater.begin();

  Serial.println();
  Serial.println("adblock32");
  Serial.printf("display: %s\n",
                adblock32::g_display.isEnabled() ? "enabled" : "disabled");
  Serial.println("boot: firmware scaffold ready");
  Serial.printf("filter: %s\n",
                adblock32::g_blocklistStore.describeRules().c_str());
  Serial.printf("policies: %s\n",
                adblock32::g_filterEngine.describePolicies().c_str());
  Serial.printf("cache: %u/%u\n",
                static_cast<unsigned>(adblock32::g_dnsCache.count()),
                static_cast<unsigned>(adblock32::g_dnsCache.capacity()));
  adblock32::printHelp();
  adblock32::attemptAutoReconnect();
}

void loop() {
  adblock32::pollSerialCommands();
  adblock32::g_dnsFilter.poll();
  adblock32::g_remoteFilterUpdater.poll();
  adblock32::g_display.refresh(adblock32::g_stats.total(),
                                adblock32::g_stats.blocked(),
                                adblock32::g_stats.cached());
  delay(20);
}
