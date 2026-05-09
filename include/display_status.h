#pragma once

#include <Arduino.h>

namespace adblock32 {

class DisplayStatus {
 public:
  void begin();
  void showBootBanner();
  void showMessage(const String& line1, const String& line2 = "");
  void onBlocked(const String& domain);
  void refresh(uint32_t totalQueries, uint32_t totalBlocked,
               uint32_t totalCached);
  bool isEnabled() const;

 private:
  static constexpr size_t kMaxLog = 20;

  void drawTerminal();
  String truncateDomain(const String& domain, size_t maxLen) const;

  String log_[kMaxLog];
  size_t logHead_ = 0;
  size_t logCount_ = 0;
  bool enabled_ = false;
  bool terminalMode_ = false;
  uint32_t lastRefreshMs_ = 0;
};

}  // namespace adblock32
