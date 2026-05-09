#pragma once

#include <Arduino.h>

#include <vector>

namespace adblock32 {

enum class RuleType : uint8_t {
  SUFFIX = 0,
  EXACT = 1,
  GLOB = 2,
};

struct FilterRule {
  String domain;
  RuleType type;
};

class BlocklistStore {
 public:
  bool begin();

  bool addRule(const String& domain, RuleType type = RuleType::SUFFIX);
  bool removeRule(const String& domain);
  bool hasRule(const String& domain) const;

  bool addAllowRule(const String& domain, RuleType type = RuleType::SUFFIX);
  bool removeAllowRule(const String& domain);
  bool hasAllowRule(const String& domain) const;

  bool replaceRemoteRules(const std::vector<String>& rules, time_t refreshedAt);

  bool isAllowed(const String& domain) const;
  bool isBlocked(const String& domain) const;

  String describeRules() const;
  size_t customRuleCount() const;
  size_t allowRuleCount() const;
  size_t remoteRuleCount() const;
  time_t lastRemoteRefreshTime() const;

  static bool extractDnsRule(const String& token, String& rule);
  static String normalizeDomain(String domain);
  static bool globMatches(const char* pattern, const char* str);

 private:
  bool loadCustomRules();
  bool saveCustomRules() const;
  bool loadAllowRules();
  bool saveAllowRules() const;
  bool loadRemoteRules();
  bool saveRemoteRules() const;

  static bool domainMatchesRule(const String& domain, const String& rule);
  static bool domainMatchesRule(const String& domain, const FilterRule& rule);
  static String ruleToStored(const FilterRule& rule);
  static FilterRule storedToRule(const String& stored);
  static bool matchesAnyRule(const std::vector<FilterRule>& rules,
                             const String& domain);

  std::vector<FilterRule> customRules_;
  std::vector<FilterRule> allowRules_;
  std::vector<String> remoteRules_;
  time_t lastRemoteRefreshTime_ = 0;
};

}  // namespace adblock32
