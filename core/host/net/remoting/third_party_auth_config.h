// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_NET_THIRD_PARTY_AUTH_CONFIG_H_
#define MUMBA_HOST_NET_THIRD_PARTY_AUTH_CONFIG_H_

#include <ostream>
#include <string>

#include "base/gtest_prod_util.h"
#include "url/gurl.h"

namespace base {
class DictionaryValue;
}  // namespace base

namespace host {

struct ThirdPartyAuthConfig {
  GURL token_url;
  GURL token_validation_url;
  std::string token_validation_cert_issuer;

  inline bool is_null() const {
    return token_url.is_empty() && token_validation_url.is_empty();
  }

  // Status of Parse method call.
  enum ParseStatus {
    // |policy_dict| contains invalid entries (i.e. malformed urls).
    // |result| has not been modified.
    InvalidPolicy,

    // |policy_dict| doesn't contain any ThirdPartyAuthConfig-related entries.
    // |result| has not been modified.
    NoPolicy,

    // |policy_dict| contains valid entries that have been stored into |result|.
    ParsingSuccess,
  };
  static ParseStatus Parse(const base::DictionaryValue& policy_dict,
                           ThirdPartyAuthConfig* result);

 private:
  // Returns false and doesn't modify |result| if parsing fails (i.e. some input
  // values are invalid).
  static bool ParseStrings(const std::string& token_url,
                           const std::string& token_validation_url,
                           const std::string& token_validation_cert_issuer,
                           ThirdPartyAuthConfig* result);
  FRIEND_TEST_ALL_PREFIXES(InvalidUrlTest, ParseInvalidUrl);
  FRIEND_TEST_ALL_PREFIXES(ThirdPartyAuthConfig, ParseEmpty);
  FRIEND_TEST_ALL_PREFIXES(ThirdPartyAuthConfig, ParseValidAll);
  FRIEND_TEST_ALL_PREFIXES(ThirdPartyAuthConfig, ParseValidNoCert);
  FRIEND_TEST_ALL_PREFIXES(ThirdPartyAuthConfig, ParseInvalidCombination);
  FRIEND_TEST_ALL_PREFIXES(ThirdPartyAuthConfig, ParseHttp);

  // Extracts raw (raw = as strings) policy values from |policy_dict|.
  // Missing policy values are set to an empty string.
  // Returns false if no ThirdPartyAuthConfig-related policies were present.
  static bool ExtractStrings(const base::DictionaryValue& policy_dict,
                             std::string* token_url,
                             std::string* token_validation_url,
                             std::string* token_validation_cert_issuer);
  FRIEND_TEST_ALL_PREFIXES(ThirdPartyAuthConfig, ExtractEmpty);
  FRIEND_TEST_ALL_PREFIXES(ThirdPartyAuthConfig, ExtractUnknown);
  FRIEND_TEST_ALL_PREFIXES(ThirdPartyAuthConfig, ExtractAll);
  FRIEND_TEST_ALL_PREFIXES(ThirdPartyAuthConfig, ExtractPartial);
};

std::ostream& operator<<(std::ostream& os, const ThirdPartyAuthConfig& cfg);

}  // namespace remoting

#endif  // REMOTING_HOST_THIRD_PARTY_AUTH_CONFIG_H_
