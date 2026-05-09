#include "blocklist_store.h"

#include <ArduinoJson.h>
#include <Preferences.h>

#include "app_config.h"

namespace adblock32 {
namespace {
constexpr const char* kBuiltInRules[] = {
    "doubleclick.net",
    "googleadservices.com",
    "googlesyndication.com",
    "adservice.google.com",
    "amazon-adsystem.com",
    "ads-twitter.com",
};
constexpr size_t kBlocklistJsonCapacity = 2048;
constexpr size_t kRemoteBlocklistJsonCapacity = 65536;
}  // namespace

bool BlocklistStore::begin() {
  const bool loadedCustom = loadCustomRules();
  const bool loadedAllow = loadAllowRules();
  const bool loadedRemote = loadRemoteRules();
  return loadedCustom && loadedAllow && loadedRemote;
}

bool BlocklistStore::addRule(const String& domain, RuleType type) {
  const String normalized = normalizeDomain(domain);
  if (normalized.isEmpty() || hasRule(normalized) ||
      customRules_.size() >= config::kMaxCustomBlockRules) {
    return false;
  }
  customRules_.push_back({normalized, type});
  return saveCustomRules();
}

bool BlocklistStore::removeRule(const String& domain) {
  const String normalized = normalizeDomain(domain);
  for (auto it = customRules_.begin(); it != customRules_.end(); ++it) {
    if (it->domain == normalized) {
      customRules_.erase(it);
      return saveCustomRules();
    }
  }
  return false;
}

bool BlocklistStore::hasRule(const String& domain) const {
  const String normalized = normalizeDomain(domain);
  for (const auto& rule : customRules_) {
    if (rule.domain == normalized) return true;
  }
  return false;
}

bool BlocklistStore::addAllowRule(const String& domain, RuleType type) {
  const String normalized = normalizeDomain(domain);
  if (normalized.isEmpty() || hasAllowRule(normalized) ||
      allowRules_.size() >= config::kMaxAllowRules) {
    return false;
  }
  allowRules_.push_back({normalized, type});
  return saveAllowRules();
}

bool BlocklistStore::removeAllowRule(const String& domain) {
  const String normalized = normalizeDomain(domain);
  for (auto it = allowRules_.begin(); it != allowRules_.end(); ++it) {
    if (it->domain == normalized) {
      allowRules_.erase(it);
      return saveAllowRules();
    }
  }
  return false;
}

bool BlocklistStore::hasAllowRule(const String& domain) const {
  const String normalized = normalizeDomain(domain);
  for (const auto& rule : allowRules_) {
    if (rule.domain == normalized) return true;
  }
  return false;
}

bool BlocklistStore::replaceRemoteRules(const std::vector<String>& rules,
                                        time_t refreshedAt) {
  remoteRules_.clear();
  remoteRules_.reserve(rules.size());

  for (const String& candidate : rules) {
    const String normalized = normalizeDomain(candidate);
    if (normalized.isEmpty() || remoteRules_.size() >= config::kMaxRemoteBlockRules) {
      continue;
    }
    bool exists = false;
    for (const String& existing : remoteRules_) {
      if (existing == normalized) { exists = true; break; }
    }
    if (!exists) {
      remoteRules_.push_back(normalized);
    }
  }

  lastRemoteRefreshTime_ = refreshedAt;
  return saveRemoteRules();
}

bool BlocklistStore::isAllowed(const String& domain) const {
  const String normalizedDomain = normalizeDomain(domain);
  if (normalizedDomain.isEmpty()) return false;
  return matchesAnyRule(allowRules_, normalizedDomain);
}

bool BlocklistStore::isBlocked(const String& domain) const {
  const String normalizedDomain = normalizeDomain(domain);
  if (normalizedDomain.isEmpty()) return false;

  for (const char* rule : kBuiltInRules) {
    if (domainMatchesRule(normalizedDomain, String(rule))) {
      return true;
    }
  }

  if (matchesAnyRule(customRules_, normalizedDomain)) return true;

  for (const String& rule : remoteRules_) {
    if (domainMatchesRule(normalizedDomain, rule)) {
      return true;
    }
  }

  return false;
}

String BlocklistStore::describeRules() const {
  String description = "built-in: ";
  description += String(sizeof(kBuiltInRules) / sizeof(kBuiltInRules[0]));
  description += ", custom: ";
  description += String(customRules_.size());
  description += ", allow: ";
  description += String(allowRules_.size());
  description += ", remote: ";
  description += String(remoteRules_.size());
  description += ", refreshed_at: ";
  description += String(static_cast<unsigned long>(lastRemoteRefreshTime_));

  if (!customRules_.empty()) {
    description += " block[";
    for (size_t i = 0; i < customRules_.size(); ++i) {
      if (i > 0) description += ", ";
      description += customRules_[i].domain;
    }
    description += "]";
  }
  if (!allowRules_.empty()) {
    description += " allow[";
    for (size_t i = 0; i < allowRules_.size(); ++i) {
      if (i > 0) description += ", ";
      description += allowRules_[i].domain;
    }
    description += "]";
  }

  return description;
}

size_t BlocklistStore::customRuleCount() const { return customRules_.size(); }
size_t BlocklistStore::allowRuleCount() const { return allowRules_.size(); }
size_t BlocklistStore::remoteRuleCount() const { return remoteRules_.size(); }
time_t BlocklistStore::lastRemoteRefreshTime() const {
  return lastRemoteRefreshTime_;
}

bool BlocklistStore::loadCustomRules() {
  customRules_.clear();

  Preferences preferences;
  if (!preferences.begin(config::kPreferencesNamespace, true)) return false;
  const String rawJson = preferences.getString(config::kBlocklistKey, "[]");
  preferences.end();

  DynamicJsonDocument document(kBlocklistJsonCapacity);
  const DeserializationError error = deserializeJson(document, rawJson);
  if (error || !document.is<JsonArray>()) return false;

  for (JsonVariant value : document.as<JsonArray>()) {
    if (!value.is<const char*>()) continue;
    const String stored(value.as<const char*>());
    const FilterRule parsed = storedToRule(stored);
    if (!parsed.domain.isEmpty() && !hasRule(parsed.domain) &&
        customRules_.size() < config::kMaxCustomBlockRules) {
      customRules_.push_back(parsed);
    }
  }

  return true;
}

bool BlocklistStore::saveCustomRules() const {
  DynamicJsonDocument document(kBlocklistJsonCapacity);
  JsonArray rules = document.to<JsonArray>();
  for (const FilterRule& rule : customRules_) {
    rules.add(ruleToStored(rule));
  }

  String rawJson;
  serializeJson(document, rawJson);

  Preferences preferences;
  if (!preferences.begin(config::kPreferencesNamespace, false)) return false;
  const bool saved = preferences.putString(config::kBlocklistKey, rawJson) >= 0;
  preferences.end();
  return saved;
}

bool BlocklistStore::loadAllowRules() {
  allowRules_.clear();

  Preferences preferences;
  if (!preferences.begin(config::kPreferencesNamespace, true)) return false;
  const String rawJson = preferences.getString(config::kAllowlistKey, "[]");
  preferences.end();

  DynamicJsonDocument document(kBlocklistJsonCapacity);
  const DeserializationError error = deserializeJson(document, rawJson);
  if (error || !document.is<JsonArray>()) return false;

  for (JsonVariant value : document.as<JsonArray>()) {
    if (!value.is<const char*>()) continue;
    const String stored(value.as<const char*>());
    const FilterRule parsed = storedToRule(stored);
    if (!parsed.domain.isEmpty() && !hasAllowRule(parsed.domain) &&
        allowRules_.size() < config::kMaxAllowRules) {
      allowRules_.push_back(parsed);
    }
  }

  return true;
}

bool BlocklistStore::saveAllowRules() const {
  DynamicJsonDocument document(kBlocklistJsonCapacity);
  JsonArray rules = document.to<JsonArray>();
  for (const FilterRule& rule : allowRules_) {
    rules.add(ruleToStored(rule));
  }

  String rawJson;
  serializeJson(document, rawJson);

  Preferences preferences;
  if (!preferences.begin(config::kPreferencesNamespace, false)) return false;
  const bool saved = preferences.putString(config::kAllowlistKey, rawJson) >= 0;
  preferences.end();
  return saved;
}

bool BlocklistStore::loadRemoteRules() {
  remoteRules_.clear();
  lastRemoteRefreshTime_ = 0;

  Preferences preferences;
  if (!preferences.begin(config::kPreferencesNamespace, true)) return false;
  const String rawJson = preferences.getString(config::kRemoteBlocklistKey, "[]");
  lastRemoteRefreshTime_ =
      static_cast<time_t>(preferences.getULong64(config::kRemoteRefreshTimeKey, 0));
  preferences.end();

  DynamicJsonDocument document(kRemoteBlocklistJsonCapacity);
  const DeserializationError error = deserializeJson(document, rawJson);
  if (error || !document.is<JsonArray>()) {
    remoteRules_.clear();
    return false;
  }

  for (JsonVariant value : document.as<JsonArray>()) {
    if (!value.is<const char*>()) continue;
    const String normalized = normalizeDomain(String(value.as<const char*>()));
    if (!normalized.isEmpty() && remoteRules_.size() < config::kMaxRemoteBlockRules) {
      bool exists = false;
      for (const String& existing : remoteRules_) {
        if (existing == normalized) { exists = true; break; }
      }
      if (!exists) remoteRules_.push_back(normalized);
    }
  }

  return true;
}

bool BlocklistStore::saveRemoteRules() const {
  DynamicJsonDocument document(kRemoteBlocklistJsonCapacity);
  JsonArray rules = document.to<JsonArray>();
  for (const String& rule : remoteRules_) {
    rules.add(rule);
  }

  String rawJson;
  serializeJson(document, rawJson);

  Preferences preferences;
  if (!preferences.begin(config::kPreferencesNamespace, false)) return false;
  const bool saved =
      preferences.putString(config::kRemoteBlocklistKey, rawJson) >= 0 &&
      preferences.putULong64(config::kRemoteRefreshTimeKey,
                             static_cast<uint64_t>(lastRemoteRefreshTime_)) > 0;
  preferences.end();
  return saved;
}

String BlocklistStore::normalizeDomain(String domain) {
  domain.trim();
  domain.toLowerCase();
  while (domain.endsWith(".")) {
    domain.remove(domain.length() - 1);
  }
  return domain;
}

bool BlocklistStore::extractDnsRule(const String& token, String& rule) {
  rule = "";
  if (!token.startsWith("||")) return false;

  String candidate = token.substring(2);
  const int modifierIndex = candidate.indexOf('$');
  if (modifierIndex >= 0) candidate = candidate.substring(0, modifierIndex);
  const int caretIndex = candidate.indexOf('^');
  if (caretIndex >= 0) candidate = candidate.substring(0, caretIndex);

  if (candidate.indexOf('/') >= 0 || candidate.indexOf('*') >= 0 ||
      candidate.indexOf('?') >= 0 || candidate.indexOf('|') >= 0 ||
      candidate.indexOf('=') >= 0 || candidate.indexOf(':') >= 0) {
    return false;
  }

  candidate = normalizeDomain(candidate);
  if (candidate.isEmpty()) return false;

  bool hasAlpha = false;
  for (size_t i = 0; i < candidate.length(); ++i) {
    const char ch = candidate[i];
    if (isalpha(static_cast<unsigned char>(ch))) hasAlpha = true;
    if (!(isalnum(static_cast<unsigned char>(ch)) || ch == '.' || ch == '-')) {
      return false;
    }
  }

  if (!hasAlpha) return false;

  rule = candidate;
  return true;
}

bool BlocklistStore::domainMatchesRule(const String& domain,
                                       const String& rule) {
  if (domain == rule) return true;
  if (domain.length() <= rule.length()) return false;
  const int suffixIndex = domain.length() - rule.length();
  return domain.substring(suffixIndex) == rule && domain[suffixIndex - 1] == '.';
}

bool BlocklistStore::domainMatchesRule(const String& domain,
                                       const FilterRule& rule) {
  switch (rule.type) {
    case RuleType::EXACT:
      return domain == rule.domain;
    case RuleType::SUFFIX:
      if (domain == rule.domain) return true;
      if (domain.length() <= rule.domain.length()) return false;
      {
        const int suffixIndex = domain.length() - rule.domain.length();
        return domain.substring(suffixIndex) == rule.domain &&
               domain[suffixIndex - 1] == '.';
      }
    case RuleType::GLOB:
      return globMatches(rule.domain.c_str(), domain.c_str());
  }
  return false;
}

bool BlocklistStore::globMatches(const char* pattern, const char* str) {
  while (*pattern) {
    if (*pattern == '*') {
      ++pattern;
      if (*pattern == '\0') return true;
      while (*str) {
        if (globMatches(pattern, str)) return true;
        ++str;
      }
      return globMatches(pattern, str);
    }

    if (*str == '\0') return false;

    if (*pattern == '?') {
      ++pattern;
      ++str;
    } else if (*pattern == '[') {
      ++pattern;
      bool negate = false;
      if (*pattern == '!' || *pattern == '^') {
        negate = true;
        ++pattern;
      }
      bool matched = false;
      while (*pattern && *pattern != ']') {
        if (pattern[1] == '-' && pattern[2] && pattern[2] != ']') {
          if (*str >= pattern[0] && *str <= pattern[2]) matched = true;
          pattern += 3;
        } else {
          if (*str == *pattern) matched = true;
          ++pattern;
        }
      }
      if (*pattern == ']') ++pattern;
      if (negate) matched = !matched;
      if (!matched) return false;
      ++str;
    } else {
      if (*pattern != *str) return false;
      ++pattern;
      ++str;
    }
  }
  return *str == '\0';
}

String BlocklistStore::ruleToStored(const FilterRule& rule) {
  switch (rule.type) {
    case RuleType::EXACT:
      return "E:" + rule.domain;
    case RuleType::GLOB:
      return "G:" + rule.domain;
    default:
      return rule.domain;
  }
}

FilterRule BlocklistStore::storedToRule(const String& stored) {
  FilterRule rule{stored, RuleType::SUFFIX};
  if (stored.length() >= 2 && stored[1] == ':') {
    switch (stored[0]) {
      case 'E':
        rule.type = RuleType::EXACT;
        rule.domain = stored.substring(2);
        break;
      case 'G':
        rule.type = RuleType::GLOB;
        rule.domain = stored.substring(2);
        break;
    }
  }
  return rule;
}

bool BlocklistStore::matchesAnyRule(const std::vector<FilterRule>& rules,
                                    const String& domain) {
  for (const FilterRule& rule : rules) {
    if (domainMatchesRule(domain, rule)) return true;
  }
  return false;
}

}  // namespace adblock32
