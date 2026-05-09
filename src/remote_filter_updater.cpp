#include "remote_filter_updater.h"

#include <ArduinoJson.h>
#include <HTTPClient.h>
#include <Preferences.h>
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <time.h>

#include "app_config.h"

namespace adblock32 {
namespace {
constexpr const char* kDefaultSources[] = {
    "https://adguardteam.github.io/AdguardFilters/BaseFilter/sections/adservers.txt",
    "https://adguardteam.github.io/AdguardFilters/BaseFilter/sections/adservers_firstparty.txt",
};
constexpr size_t kSourceJsonCapacity = 2048;
}

RemoteFilterUpdater::RemoteFilterUpdater(BlocklistStore& blocklist)
    : blocklist_(blocklist) {}

bool RemoteFilterUpdater::begin() {
  configTzTime("UTC0", "pool.ntp.org", "time.nist.gov");
  loadSources();
  nextAttemptAtMs_ = 0;
  bootRefreshAttempted_ = false;
  return true;
}

void RemoteFilterUpdater::poll() {
  if (WiFi.status() != WL_CONNECTED) {
    return;
  }

  const uint32_t nowMs = millis();
  if (nowMs < nextAttemptAtMs_) {
    return;
  }

  if (!shouldRefresh()) {
    nextAttemptAtMs_ = nowMs + 60000;
    return;
  }

  refreshNow();
}

bool RemoteFilterUpdater::refreshNow() {
  bootRefreshAttempted_ = true;

  std::vector<String> allRules;
  allRules.reserve(config::kMaxRemoteBlockRules);

  for (const String& source : sources_) {
    String filterText;
    if (!fetchFilterText(source, filterText)) {
      nextAttemptAtMs_ = millis() + config::kRemoteRefreshRetrySeconds * 1000UL;
      return false;
    }

    std::vector<String> parsedRules;
    if (!parseRemoteRules(filterText, parsedRules)) {
      nextAttemptAtMs_ = millis() + config::kRemoteRefreshRetrySeconds * 1000UL;
      return false;
    }

    for (const String& rule : parsedRules) {
      bool exists = false;
      for (const String& existing : allRules) {
        if (existing == rule) {
          exists = true;
          break;
        }
      }
      if (!exists && allRules.size() < config::kMaxRemoteBlockRules) {
        allRules.push_back(rule);
      }
    }
  }

  const time_t now = currentTime();
  if (!blocklist_.replaceRemoteRules(allRules, now)) {
    nextAttemptAtMs_ = millis() + config::kRemoteRefreshRetrySeconds * 1000UL;
    return false;
  }

  nextAttemptAtMs_ = millis() + config::kRemoteRefreshIntervalSeconds * 1000UL;
  return true;
}

String RemoteFilterUpdater::describeStatus() const {
  String status = "remote_rules=";
  status += String(blocklist_.remoteRuleCount());
  status += ", sources=";
  status += String(sources_.size());
  status += ", last_refresh=";
  status += String(static_cast<unsigned long>(blocklist_.lastRemoteRefreshTime()));
  status += ", next_attempt_ms=";
  status += String(nextAttemptAtMs_);
  return status;
}

String RemoteFilterUpdater::describeSources() const {
  String description = "sources=";
  description += String(sources_.size());
  if (!sources_.empty()) {
    description += " [";
    for (size_t i = 0; i < sources_.size(); ++i) {
      if (i > 0) {
        description += ", ";
      }
      description += sources_[i];
    }
    description += "]";
  }
  return description;
}

bool RemoteFilterUpdater::addSource(const String& url) {
  const String normalized = normalizeUrl(url);
  if (normalized.isEmpty() || hasSource(normalized) ||
      sources_.size() >= config::kMaxRemoteSources) {
    return false;
  }

  sources_.push_back(normalized);
  return saveSources();
}

bool RemoteFilterUpdater::removeSource(const String& url) {
  const String normalized = normalizeUrl(url);
  for (auto it = sources_.begin(); it != sources_.end(); ++it) {
    if (*it == normalized) {
      sources_.erase(it);
      return saveSources();
    }
  }

  return false;
}

bool RemoteFilterUpdater::shouldRefresh() const {
  if (!bootRefreshAttempted_ && blocklist_.remoteRuleCount() == 0) {
    return true;
  }

  const time_t now = currentTime();
  const time_t lastRefresh = blocklist_.lastRemoteRefreshTime();
  if (now > 0 && lastRefresh > 0) {
    return now - lastRefresh >= config::kRemoteRefreshIntervalSeconds;
  }

  return !bootRefreshAttempted_;
}

bool RemoteFilterUpdater::fetchFilterText(const String& url,
                                          String& filterText) const {
  WiFiClientSecure client;
  client.setInsecure();

  HTTPClient http;
  if (!http.begin(client, url)) {
    Serial.println("filter: failed to init remote request");
    return false;
  }

  http.setTimeout(15000);
  const int status = http.GET();
  if (status != HTTP_CODE_OK) {
    Serial.printf("filter: remote fetch failed status=%d\n", status);
    http.end();
    return false;
  }

  filterText = http.getString();
  http.end();
  return !filterText.isEmpty();
}

bool RemoteFilterUpdater::parseRemoteRules(
    const String& filterText, std::vector<String>& rules) const {
  rules.clear();
  rules.reserve(config::kMaxRemoteBlockRules);

  size_t tokenStart = 0;
  while (tokenStart < filterText.length() &&
         rules.size() < config::kMaxRemoteBlockRules) {
    while (tokenStart < filterText.length() &&
           isspace(static_cast<unsigned char>(filterText[tokenStart]))) {
      ++tokenStart;
    }

    if (tokenStart >= filterText.length()) {
      break;
    }

    size_t tokenEnd = tokenStart;
    while (tokenEnd < filterText.length() &&
           !isspace(static_cast<unsigned char>(filterText[tokenEnd]))) {
      ++tokenEnd;
    }

    String token = filterText.substring(tokenStart, tokenEnd);
    String rule;
    if (BlocklistStore::extractDnsRule(token, rule)) {
      bool exists = false;
      for (const String& existing : rules) {
        if (existing == rule) {
          exists = true;
          break;
        }
      }
      if (!exists) {
        rules.push_back(rule);
      }
    }

    tokenStart = tokenEnd + 1;
  }

  Serial.printf("filter: parsed %u remote dns rules\n",
                static_cast<unsigned>(rules.size()));
  return !rules.empty();
}

time_t RemoteFilterUpdater::currentTime() const {
  time_t now = 0;
  time(&now);
  return now;
}

bool RemoteFilterUpdater::loadSources() {
  sources_.clear();

  Preferences preferences;
  if (!preferences.begin(config::kPreferencesNamespace, true)) {
    return false;
  }

  const String rawJson = preferences.getString(config::kRemoteSourcesKey, "");
  preferences.end();

  if (rawJson.isEmpty()) {
    for (const char* source : kDefaultSources) {
      sources_.push_back(String(source));
    }
    saveSources();
    return true;
  }

  DynamicJsonDocument document(kSourceJsonCapacity);
  const DeserializationError error = deserializeJson(document, rawJson);
  if (error || !document.is<JsonArray>()) {
    return false;
  }

  for (JsonVariant value : document.as<JsonArray>()) {
    if (!value.is<const char*>()) {
      continue;
    }

    const String normalized = normalizeUrl(String(value.as<const char*>()));
    if (!normalized.isEmpty() && !hasSource(normalized) &&
        sources_.size() < config::kMaxRemoteSources) {
      sources_.push_back(normalized);
    }
  }

  if (sources_.empty()) {
    for (const char* source : kDefaultSources) {
      sources_.push_back(String(source));
    }
  }

  return true;
}

bool RemoteFilterUpdater::saveSources() const {
  DynamicJsonDocument document(kSourceJsonCapacity);
  JsonArray array = document.to<JsonArray>();
  for (const String& source : sources_) {
    array.add(source);
  }

  String rawJson;
  serializeJson(document, rawJson);

  Preferences preferences;
  if (!preferences.begin(config::kPreferencesNamespace, false)) {
    return false;
  }

  const bool saved = preferences.putString(config::kRemoteSourcesKey, rawJson) >= 0;
  preferences.end();
  return saved;
}

String RemoteFilterUpdater::normalizeUrl(String url) {
  url.trim();
  if (!url.startsWith("https://")) {
    return "";
  }
  return url;
}

bool RemoteFilterUpdater::hasSource(const String& url) const {
  for (const String& existing : sources_) {
    if (existing == url) {
      return true;
    }
  }
  return false;
}

}  // namespace adblock32
