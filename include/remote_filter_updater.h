#pragma once

#include <Arduino.h>

#include "blocklist_store.h"

namespace adblock32 {

class RemoteFilterUpdater {
 public:
  explicit RemoteFilterUpdater(BlocklistStore& blocklist);

  bool begin();
  void poll();
  bool refreshNow();
  String describeStatus() const;
  String describeSources() const;
  bool addSource(const String& url);
  bool removeSource(const String& url);

 private:
  bool shouldRefresh() const;
  bool fetchFilterText(const String& url, String& filterText) const;
  bool parseRemoteRules(const String& filterText, std::vector<String>& rules) const;
  time_t currentTime() const;
  bool loadSources();
  bool saveSources() const;
  static String normalizeUrl(String url);
  bool hasSource(const String& url) const;

  BlocklistStore& blocklist_;
  std::vector<String> sources_;
  uint32_t nextAttemptAtMs_ = 0;
  bool bootRefreshAttempted_ = false;
};

}  // namespace adblock32
