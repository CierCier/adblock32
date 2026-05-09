#include "wifi_credentials.h"

#include <Preferences.h>

#include "app_config.h"

namespace adblock32 {

bool WiFiCredentials::isValid() const { return !ssid.isEmpty(); }

bool WiFiCredentialStore::load(WiFiCredentials& credentials) const {
  Preferences preferences;
  if (!preferences.begin(config::kPreferencesNamespace, true)) {
    return false;
  }

  credentials.ssid = preferences.getString(config::kSsidKey, "");
  credentials.password = preferences.getString(config::kPasswordKey, "");
  preferences.end();

  return credentials.isValid();
}

bool WiFiCredentialStore::save(const WiFiCredentials& credentials) const {
  if (!credentials.isValid()) {
    return false;
  }

  Preferences preferences;
  if (!preferences.begin(config::kPreferencesNamespace, false)) {
    return false;
  }

  const bool saved = preferences.putString(config::kSsidKey, credentials.ssid) > 0 &&
                     preferences.putString(config::kPasswordKey, credentials.password) >= 0;
  preferences.end();
  return saved;
}

bool WiFiCredentialStore::clear() const {
  Preferences preferences;
  if (!preferences.begin(config::kPreferencesNamespace, false)) {
    return false;
  }

  const bool cleared = preferences.clear();
  preferences.end();
  return cleared;
}

}  // namespace adblock32
