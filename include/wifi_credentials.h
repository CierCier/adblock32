#pragma once

#include <Arduino.h>

namespace adblock32 {

struct WiFiCredentials {
  String ssid;
  String password;

  bool isValid() const;
};

class WiFiCredentialStore {
 public:
  bool load(WiFiCredentials& credentials) const;
  bool save(const WiFiCredentials& credentials) const;
  bool clear() const;
};

}  // namespace adblock32
