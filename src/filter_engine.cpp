#include "filter_engine.h"

#include <ArduinoJson.h>
#include <Preferences.h>
#include <esp32-hal.h>

#include "app_config.h"

namespace adblock32 {
namespace {
bool domainMatchesClientRule(const String& domain,
                             const ClientPolicyRule& rule) {
  switch (rule.type) {
    case RuleType::EXACT:
      return domain == rule.domain;
    case RuleType::SUFFIX:
      if (domain == rule.domain) return true;
      if (domain.length() <= rule.domain.length()) return false;
      {
        const int idx = domain.length() - rule.domain.length();
        return domain.substring(idx) == rule.domain && domain[idx - 1] == '.';
      }
    case RuleType::GLOB:
      return BlocklistStore::globMatches(rule.domain.c_str(), domain.c_str());
  }
  return false;
}
}  // namespace

FilterEngine::FilterEngine(BlocklistStore& blocklist) : blocklist_(blocklist) {}

bool FilterEngine::begin() {
  loadPolicies();
  return true;
}

FilterAction FilterEngine::evaluate(const String& domain,
                                    uint32_t clientIp) const {
  if (domain.isEmpty()) return FilterAction::NOMATCH;

  // 1. Global allowlist check
  if (blocklist_.isAllowed(domain)) return FilterAction::ALLOW;

  // 2. Per-client policy check
  const ClientPolicy* policy = findPolicyForClient(clientIp);
  if (policy) {
    for (const ClientPolicyRule& rule : policy->allowRules) {
      if (domainMatchesClientRule(domain, rule)) return FilterAction::ALLOW;
    }
    for (const ClientPolicyRule& rule : policy->blockRules) {
      if (domainMatchesClientRule(domain, rule)) return FilterAction::BLOCK;
    }
  }

  // 3. Global blocklist check
  if (blocklist_.isBlocked(domain)) return FilterAction::BLOCK;

  return FilterAction::NOMATCH;
}

bool FilterEngine::addPolicy(const String& cidr, const String& name) {
  if (name.isEmpty() || policies_.size() >= config::kMaxCustomPolicies) {
    return false;
  }
  for (const auto& p : policies_) {
    if (p.name == name) return false;
  }

  ClientPolicy policy;
  if (!parseCidr(cidr, policy.cidrIp, policy.cidrMask)) return false;
  policy.name = name;
  policies_.push_back(policy);
  return savePolicies();
}

bool FilterEngine::removePolicy(const String& name) {
  for (auto it = policies_.begin(); it != policies_.end(); ++it) {
    if (it->name == name) {
      policies_.erase(it);
      return savePolicies();
    }
  }
  return false;
}

bool FilterEngine::policyAddRule(const String& name, const String& domain,
                                 RuleType type, bool isAllow) {
  String normalized = BlocklistStore::normalizeDomain(domain);
  if (normalized.isEmpty()) return false;

  for (auto& policy : policies_) {
    if (policy.name == name) {
      ClientPolicyRule rule{normalized, type};
      auto& rules = isAllow ? policy.allowRules : policy.blockRules;
      for (const auto& r : rules) {
        if (r.domain == normalized) return false;
      }
      rules.push_back(rule);
      return savePolicies();
    }
  }
  return false;
}

bool FilterEngine::policyRemoveRule(const String& name, const String& domain,
                                    bool isAllow) {
  String normalized = BlocklistStore::normalizeDomain(domain);
  if (normalized.isEmpty()) return false;

  for (auto& policy : policies_) {
    if (policy.name == name) {
      auto& rules = isAllow ? policy.allowRules : policy.blockRules;
      for (auto it = rules.begin(); it != rules.end(); ++it) {
        if (it->domain == normalized) {
          rules.erase(it);
          return savePolicies();
        }
      }
    }
  }
  return false;
}

String FilterEngine::describePolicies() const {
  if (policies_.empty()) return "none";

  String desc;
  for (size_t i = 0; i < policies_.size(); ++i) {
    if (i > 0) desc += "; ";
    desc += policies_[i].name;
    desc += "=";
    desc += IPAddress(policies_[i].cidrIp).toString();
    desc += "/";
    desc += String(32 - __builtin_popcount(policies_[i].cidrMask));
    desc += " allow:";
    desc += String(policies_[i].allowRules.size());
    desc += " block:";
    desc += String(policies_[i].blockRules.size());
  }
  return desc;
}

size_t FilterEngine::policyCount() const { return policies_.size(); }

bool FilterEngine::loadPolicies() {
  policies_.clear();

  Preferences preferences;
  if (!preferences.begin(config::kPreferencesNamespace, true)) return false;
  const String rawJson = preferences.getString(config::kPoliciesKey, "[]");
  preferences.end();

  DynamicJsonDocument document(4096);
  const DeserializationError error = deserializeJson(document, rawJson);
  if (error || !document.is<JsonArray>()) return false;

  for (JsonVariant val : document.as<JsonArray>()) {
    JsonObject obj = val.as<JsonObject>();
    ClientPolicy policy;
    policy.name = obj["name"].as<String>();
    const String cidr = obj["cidr"].as<String>();
    if (!parseCidr(cidr, policy.cidrIp, policy.cidrMask)) continue;

    if (obj["allow"].is<JsonArray>()) {
      for (JsonVariant r : obj["allow"].as<JsonArray>()) {
        JsonObject ro = r.as<JsonObject>();
        ClientPolicyRule rule;
        rule.domain = ro["d"].as<String>();
        rule.type = static_cast<RuleType>(ro["t"].as<uint8_t>());
        if (!rule.domain.isEmpty()) policy.allowRules.push_back(rule);
      }
    }
    if (obj["block"].is<JsonArray>()) {
      for (JsonVariant r : obj["block"].as<JsonArray>()) {
        JsonObject ro = r.as<JsonObject>();
        ClientPolicyRule rule;
        rule.domain = ro["d"].as<String>();
        rule.type = static_cast<RuleType>(ro["t"].as<uint8_t>());
        if (!rule.domain.isEmpty()) policy.blockRules.push_back(rule);
      }
    }

    policies_.push_back(policy);
  }

  return true;
}

bool FilterEngine::savePolicies() const {
  DynamicJsonDocument document(4096);
  JsonArray arr = document.to<JsonArray>();

  for (const ClientPolicy& policy : policies_) {
    JsonObject obj = arr.createNestedObject();
    obj["name"] = policy.name;
    const IPAddress ip(policy.cidrIp);
    const int bits = 32 - __builtin_popcount(policy.cidrMask);
    obj["cidr"] = ip.toString() + "/" + String(bits);

    JsonArray allowArr = obj.createNestedArray("allow");
    for (const auto& rule : policy.allowRules) {
      JsonObject ro = allowArr.createNestedObject();
      ro["d"] = rule.domain;
      ro["t"] = static_cast<uint8_t>(rule.type);
    }

    JsonArray blockArr = obj.createNestedArray("block");
    for (const auto& rule : policy.blockRules) {
      JsonObject ro = blockArr.createNestedObject();
      ro["d"] = rule.domain;
      ro["t"] = static_cast<uint8_t>(rule.type);
    }
  }

  String rawJson;
  serializeJson(document, rawJson);

  Preferences preferences;
  if (!preferences.begin(config::kPreferencesNamespace, false)) return false;
  const bool saved = preferences.putString(config::kPoliciesKey, rawJson) >= 0;
  preferences.end();
  return saved;
}

bool FilterEngine::parseCidr(const String& cidr, uint32_t& ip,
                             uint32_t& mask) {
  const int slash = cidr.indexOf('/');
  if (slash <= 0) return false;

  IPAddress addr;
  if (!addr.fromString(cidr.substring(0, slash))) return false;
  ip = static_cast<uint32_t>(addr);

  const int bits = cidr.substring(slash + 1).toInt();
  if (bits < 0 || bits > 32) return false;
  mask = bits == 0 ? 0 : (0xFFFFFFFFUL << (32 - bits));
  return true;
}

bool FilterEngine::ipInRange(uint32_t ip, uint32_t cidrIp, uint32_t cidrMask) {
  return (ip & cidrMask) == (cidrIp & cidrMask);
}

const ClientPolicy* FilterEngine::findPolicyForClient(
    uint32_t clientIp) const {
  for (const ClientPolicy& policy : policies_) {
    if (ipInRange(clientIp, policy.cidrIp, policy.cidrMask)) {
      return &policy;
    }
  }
  return nullptr;
}

}  // namespace adblock32
