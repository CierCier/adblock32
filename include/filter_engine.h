#pragma once

#include <Arduino.h>
#include <IPAddress.h>

#include <vector>

#include "blocklist_store.h"

namespace adblock32 {

enum class FilterAction : uint8_t { ALLOW, BLOCK, NOMATCH };

struct ClientPolicyRule {
  String domain;
  RuleType type;
};

struct ClientPolicy {
  uint32_t cidrIp;
  uint32_t cidrMask;
  String name;
  std::vector<ClientPolicyRule> allowRules;
  std::vector<ClientPolicyRule> blockRules;
};

class FilterEngine {
 public:
  explicit FilterEngine(BlocklistStore& blocklist);

  bool begin();
  FilterAction evaluate(const String& domain, uint32_t clientIp) const;

  bool addPolicy(const String& cidr, const String& name);
  bool removePolicy(const String& name);
  bool policyAddRule(const String& name, const String& domain,
                     RuleType type, bool isAllow);
  bool policyRemoveRule(const String& name, const String& domain,
                        bool isAllow);
  String describePolicies() const;
  size_t policyCount() const;

 private:
  bool loadPolicies();
  bool savePolicies() const;
  static bool parseCidr(const String& cidr, uint32_t& ip, uint32_t& mask);
  static bool ipInRange(uint32_t ip, uint32_t cidrIp, uint32_t cidrMask);
  const ClientPolicy* findPolicyForClient(uint32_t clientIp) const;

  BlocklistStore& blocklist_;
  std::vector<ClientPolicy> policies_;
};

}  // namespace adblock32
