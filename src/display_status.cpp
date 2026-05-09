#include "display_status.h"

#include "app_config.h"

#if ADBLOCK32_ENABLE_DISPLAY
#include <Adafruit_GFX.h>
#include <Adafruit_SH110X.h>
#include <Wire.h>
#endif

namespace adblock32 {
namespace {
#if ADBLOCK32_ENABLE_DISPLAY
constexpr uint8_t kDisplayWidth = 128;
constexpr uint8_t kDisplayHeight = 64;
constexpr int8_t kDisplayResetPin = -1;
constexpr uint8_t kDisplayAddress = 0x3C;
constexpr uint8_t kSeparatorY = 55;

Adafruit_SH1106G g_display(kDisplayWidth, kDisplayHeight, &Wire,
                            kDisplayResetPin);
#endif
}  // namespace

void DisplayStatus::begin() {
#if ADBLOCK32_ENABLE_DISPLAY
  Wire.begin();
  enabled_ = g_display.begin(kDisplayAddress, true);
  if (!enabled_) return;

  g_display.clearDisplay();
  g_display.setRotation(0);
  g_display.setTextColor(SH110X_WHITE);
  g_display.display();
#else
  enabled_ = false;
#endif
}

void DisplayStatus::showBootBanner() { showMessage("adblock32", "Booting..."); }

void DisplayStatus::showMessage(const String& line1, const String& line2) {
#if ADBLOCK32_ENABLE_DISPLAY
  if (!enabled_) return;

  g_display.clearDisplay();
  g_display.setTextSize(1);
  g_display.setCursor(0, 0);
  g_display.println(line1);
  if (!line2.isEmpty()) {
    g_display.println();
    g_display.println(line2);
  }
  g_display.display();
  terminalMode_ = false;
#else
  (void)line1;
  (void)line2;
#endif
}

void DisplayStatus::onBlocked(const String& domain) {
#if ADBLOCK32_ENABLE_DISPLAY
  if (!enabled_) return;

  terminalMode_ = true;
  const String truncated = truncateDomain(domain, 18);

  log_[logHead_] = truncated;
  logHead_ = (logHead_ + 1) % kMaxLog;
  if (logCount_ < kMaxLog) ++logCount_;
#else
  (void)domain;
#endif
}

void DisplayStatus::refresh(uint32_t totalQueries, uint32_t totalBlocked,
                            uint32_t totalCached) {
#if ADBLOCK32_ENABLE_DISPLAY
  if (!enabled_) return;

  const uint32_t now = millis();
  if (now - lastRefreshMs_ < 200) return;
  lastRefreshMs_ = now;

  if (!terminalMode_) return;

  drawTerminal();

  g_display.setCursor(0, 57);
  g_display.print("BLK ");
  g_display.print(totalBlocked);
  g_display.print(" | QRY ");
  g_display.print(totalQueries);
  g_display.print(" | CAC ");
  g_display.print(totalCached);

  g_display.display();
#else
  (void)totalQueries;
  (void)totalBlocked;
  (void)totalCached;
#endif
}

void DisplayStatus::drawTerminal() {
#if ADBLOCK32_ENABLE_DISPLAY
  g_display.clearDisplay();

  g_display.setTextSize(1);
  g_display.setCursor(0, 0);

  const size_t lines = logCount_ < 7 ? logCount_ : 7;
  size_t idx = (logHead_ + kMaxLog - logCount_) % kMaxLog;

  for (size_t i = 0; i < lines; ++i) {
    if (i > 0) g_display.println();
    g_display.print('>');
    g_display.print(' ');
    g_display.print(log_[idx]);
    idx = (idx + 1) % kMaxLog;
  }

  g_display.drawFastHLine(0, kSeparatorY, kDisplayWidth, SH110X_WHITE);
#endif
}

String DisplayStatus::truncateDomain(const String& domain,
                                     size_t maxLen) const {
  if (domain.length() <= maxLen) return domain;
  return domain.substring(0, maxLen - 2) + "..";
}

bool DisplayStatus::isEnabled() const { return enabled_; }

}  // namespace adblock32
