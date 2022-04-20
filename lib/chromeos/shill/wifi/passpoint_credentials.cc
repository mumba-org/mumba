// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/wifi/passpoint_credentials.h"

#include <string>
#include <vector>

#include <base/strings/string_number_conversions.h>
#include <base/strings/string_util.h>
#include <chromeos/dbus/shill/dbus-constants.h>
#include <uuid/uuid.h>

#include "shill/data_types.h"
#include "shill/dbus/dbus_control.h"
#include "shill/eap_credentials.h"
#include "shill/error.h"
#include "shill/profile.h"
#include "shill/refptr_types.h"
#include "shill/store/key_value_store.h"
#include "shill/store/store_interface.h"
#include "shill/supplicant/wpa_supplicant.h"

namespace shill {

namespace {

// Retrieve the list of OIs encoded as decimal strings from the given DBus
// property dictionary |args| (as a shill's KeyValueStore), convert them to
// uint64 values and add them to |parsed_ois|. If a string-to-number conversion
// error happens, populate |error| and return false.
bool ParsePasspointOiList(const KeyValueStore& args,
                          const std::string& property,
                          std::vector<uint64_t>* parsed_ois,
                          Error* error) {
  const auto raw_ois = args.Lookup<std::vector<std::string>>(property, {});
  for (const auto& raw_oi : raw_ois) {
    uint64_t oi;
    if (!base::StringToUint64(raw_oi, &oi)) {
      Error::PopulateAndLog(FROM_HERE, error, Error::kInvalidArguments,
                            "invalid " + property + " list: \"" + raw_oi +
                                "\" was not a valid decimal string");
      parsed_ois->clear();
      return false;
    }
    parsed_ois->push_back(oi);
  }
  return true;
}

}  // namespace

// Size of an UUID string.
constexpr size_t kUUIDStringLength = 37;

PasspointCredentials::PasspointCredentials(
    const std::string& id,
    const std::vector<std::string>& domains,
    const std::string& realm,
    const std::vector<uint64_t>& home_ois,
    const std::vector<uint64_t>& required_home_ois,
    const std::vector<uint64_t>& roaming_consortia,
    bool metered_override,
    const std::string& android_package_name)
    : domains_(domains),
      realm_(realm),
      home_ois_(home_ois),
      required_home_ois_(required_home_ois),
      roaming_consortia_(roaming_consortia),
      metered_override_(metered_override),
      android_package_name_(android_package_name),
      id_(id),
      profile_(nullptr),
      supplicant_id_(DBusControl::NullRpcIdentifier()) {}

bool PasspointCredentials::ToSupplicantProperties(
    KeyValueStore* properties) const {
  CHECK(properties);
  // A set of passpoint credentials is validated at insertion time in Shill,
  // it is expected to be valid now.
  CHECK(!domains_.empty() && !domains_[0].empty());
  CHECK(!realm_.empty());

  if (domains_.size() > 1) {
    // TODO(b/162105998) add support for multiple domains in wpa_supplicant
    // D-Bus interface.
    LOG(WARNING) << "Passpoint credentials does not support multiple domains "
                 << "yet, only the first one will be used.";
  }
  properties->Set<std::string>(WPASupplicant::kCredentialsPropertyDomain,
                               domains_[0]);
  properties->Set<std::string>(WPASupplicant::kCredentialsPropertyRealm,
                               realm_);

  // As supplicant lacks the support for matching multiple Home Organization
  // Identifiers (Home OIs), we need to handle them carefully. It leads to two
  // different situations:
  //  - "required" Home OIs: only one OI is supported. If there's more, we
  //    can't use the credentials or we would take the risk to match with
  //    networks we're not supposed to (see §9.1.2 from the specification).
  //  - there's no "required" Home OIs: we take the first one of the OIs
  //    list, but we may miss some matches.
  // The full OIs lists are stored, so we'll be able add the support to
  // supplicant later without breaking the credentials providers (apps, ...).
  if (!required_home_ois_.empty()) {
    if (required_home_ois_.size() > 1) {
      // TODO(b/162105998) add support for multiple Home OIs in wpa_supplicant.
      LOG(ERROR) << "Passpoint credentials does not support multiple "
                 << "required Home OIs yet (" << required_home_ois_.size()
                 << " found).";
      properties->Clear();
      return false;
    }
    properties->Set<std::string>(
        WPASupplicant::kCredentialsPropertyRequiredRoamingConsortium,
        EncodeOI(required_home_ois_[0]));
  } else if (!home_ois_.empty()) {
    if (home_ois_.size() > 1) {
      // TODO(b/162105998) add support for multiple Home OIs in wpa_supplicant.
      LOG(WARNING) << "Passpoint credentials does not support multiple "
                   << "Home OIs yet, only the first one will be used.";
    }
    properties->Set<std::string>(
        WPASupplicant::kCredentialsPropertyRoamingConsortium,
        EncodeOI(home_ois_[0]));
  }

  if (!roaming_consortia_.empty()) {
    properties->Set<std::string>(
        WPASupplicant::kCredentialsPropertyRoamingConsortiums,
        EncodeOIList(roaming_consortia_));
  }

  // Supplicant requires the EAP method for interworking selection.
  properties->Set<std::string>(WPASupplicant::kNetworkPropertyEapEap,
                               eap_.method());
  // Supplicant requires the credentials to perform matches using the realm
  // (see b/225170348).
  if (eap_.method() == kEapMethodTLS) {
    properties->Set<std::string>(WPASupplicant::kNetworkPropertyEapCertId,
                                 eap_.cert_id());
    properties->Set<std::string>(WPASupplicant::kNetworkPropertyEapKeyId,
                                 eap_.key_id());
  } else if (eap_.method() == kEapMethodTTLS) {
    properties->Set<std::string>(WPASupplicant::kCredentialsPropertyUsername,
                                 eap_.identity());
    properties->Set<std::string>(WPASupplicant::kCredentialsPropertyPassword,
                                 eap_.password());
  } else {
    LOG(ERROR) << "Passpoint credentials does not support EAP method '"
               << eap_.method() << "'";
    properties->Clear();
    return false;
  }

  return true;
}

void PasspointCredentials::Load(const StoreInterface* storage) {
  CHECK(storage);
  CHECK(!id_.empty());

  storage->GetStringList(id_, kStorageDomains, &domains_);
  storage->GetString(id_, kStorageRealm, &realm_);
  storage->GetUint64List(id_, kStorageHomeOIs, &home_ois_);
  storage->GetUint64List(id_, kStorageRequiredHomeOIs, &required_home_ois_);
  storage->GetUint64List(id_, kStorageRoamingConsortia, &roaming_consortia_);
  storage->GetBool(id_, kStorageMeteredOverride, &metered_override_);
  storage->GetString(id_, kStorageAndroidPackageName, &android_package_name_);
  eap_.Load(storage, id_);
}

bool PasspointCredentials::Save(StoreInterface* storage) {
  CHECK(storage);
  CHECK(!id_.empty());

  // The credentials identifier is unique, we can use it as storage identifier.
  storage->SetString(id_, kStorageType, kTypePasspoint);
  storage->SetStringList(id_, kStorageDomains, domains_);
  storage->SetString(id_, kStorageRealm, realm_);
  storage->SetUint64List(id_, kStorageHomeOIs, home_ois_);
  storage->SetUint64List(id_, kStorageRequiredHomeOIs, required_home_ois_);
  storage->SetUint64List(id_, kStorageRoamingConsortia, roaming_consortia_);
  storage->SetBool(id_, kStorageMeteredOverride, metered_override_);
  storage->SetString(id_, kStorageAndroidPackageName, android_package_name_);
  eap_.Save(storage, id_, /*save_credentials=*/true);

  return true;
}

std::string PasspointCredentials::GenerateIdentifier() {
  uuid_t uuid_bytes;
  uuid_generate_random(uuid_bytes);
  std::string uuid(kUUIDStringLength, '\0');
  uuid_unparse(uuid_bytes, &uuid[0]);
  // Remove the null terminator from the string.
  uuid.resize(kUUIDStringLength - 1);
  return uuid;
}

PasspointCredentialsRefPtr PasspointCredentials::CreatePasspointCredentials(
    const KeyValueStore& args, Error* error) {
  std::vector<std::string> domains;
  std::string realm;
  std::vector<uint64_t> home_ois, required_home_ois, roaming_consortia;
  bool metered_override;
  std::string android_package_name;

  domains = args.Lookup<std::vector<std::string>>(
      kPasspointCredentialsDomainsProperty, std::vector<std::string>());
  if (domains.empty()) {
    Error::PopulateAndLog(
        FROM_HERE, error, Error::kInvalidArguments,
        "at least one FQDN is required in " +
            std::string(kPasspointCredentialsDomainsProperty));
    return nullptr;
  }
  for (const auto& domain : domains) {
    if (!EapCredentials::ValidDomainSuffixMatch(domain)) {
      Error::PopulateAndLog(FROM_HERE, error, Error::kInvalidArguments,
                            "domain '" + domain + "' is not a valid FQDN");
      return nullptr;
    }
  }

  if (!args.Contains<std::string>(kPasspointCredentialsRealmProperty)) {
    Error::PopulateAndLog(FROM_HERE, error, Error::kInvalidArguments,
                          std::string(kPasspointCredentialsRealmProperty) +
                              " property is mandatory");
    return nullptr;
  }
  realm = args.Get<std::string>(kPasspointCredentialsRealmProperty);
  if (!EapCredentials::ValidDomainSuffixMatch(realm)) {
    Error::PopulateAndLog(FROM_HERE, error, Error::kInvalidArguments,
                          "realm '" + realm + "' is not a valid FQDN");
    return nullptr;
  }

  if (!ParsePasspointOiList(args, kPasspointCredentialsHomeOIsProperty,
                            &home_ois, error)) {
    return nullptr;
  }

  if (!ParsePasspointOiList(args, kPasspointCredentialsRequiredHomeOIsProperty,
                            &required_home_ois, error)) {
    return nullptr;
  }

  if (!ParsePasspointOiList(args, kPasspointCredentialsRoamingConsortiaProperty,
                            &roaming_consortia, error)) {
    return nullptr;
  }

  metered_override =
      args.Lookup<bool>(kPasspointCredentialsMeteredOverrideProperty, false);
  android_package_name = args.Lookup<std::string>(
      kPasspointCredentialsAndroidPackageNameProperty, std::string());

  // Create the set of credentials with a unique identifier.
  std::string id = GenerateIdentifier();
  PasspointCredentialsRefPtr creds = new PasspointCredentials(
      id, domains, realm, home_ois, required_home_ois, roaming_consortia,
      metered_override, android_package_name);

  // Load EAP credentials from the set of properties.
  creds->eap_.Load(args);

  // Server authentication: if the caller specify a CA certificate, disable
  // system CAs. Otherwise, verify that with the trusted system CAs an
  // alternative name match list is specified or that a subject name match and a
  // domain suffix match list are specified.
  if (!creds->eap_.ca_cert_pem().empty()) {
    creds->eap_.set_use_system_cas(false);
  } else {
    creds->eap_.set_use_system_cas(true);
    bool noNameMatch = creds->eap_.subject_match().empty();
    bool noAltnameMatchList =
        creds->eap_.subject_alternative_name_match_list().empty();
    bool noSuffixMatchList = creds->eap_.domain_suffix_match_list().empty();
    if (noAltnameMatchList && (noNameMatch || noSuffixMatchList)) {
      Error::PopulateAndLog(FROM_HERE, error, Error::kInvalidArguments,
                            "EAP credentials with no CA certificate must have "
                            "a Subject Alternative Name match list");
      return nullptr;
    }
  }

  // Check the set of credentials is consistent.
  if (!creds->eap().IsConnectable()) {
    Error::PopulateAndLog(FROM_HERE, error, Error::kInvalidArguments,
                          "EAP credendials not connectable");
    return nullptr;
  }

  // Our Passpoint implementation only supports EAP TLS or TTLS. SIM based EAP
  // methods are not supported on ChromeOS yet.
  std::string method = creds->eap().method();
  if (method != kEapMethodTLS && method != kEapMethodTTLS) {
    Error::PopulateAndLog(
        FROM_HERE, error, Error::kInvalidArguments,
        "EAP method '" + method + "' is not supported by Passpoint");
    return nullptr;
  }

  // The only valid inner EAP method for TTLS is MSCHAPv2
  std::string inner_method = creds->eap().inner_method();
  if (method == kEapMethodTTLS && inner_method != kEapPhase2AuthTTLSMSCHAPV2) {
    Error::PopulateAndLog(FROM_HERE, error, Error::kInvalidArguments,
                          "TTLS inner EAP method '" + inner_method +
                              "' is not supported by Passpoint");
    return nullptr;
  }

  return creds;
}

std::string PasspointCredentials::GetFQDN() {
  if (domains_.empty())
    return std::string();

  return domains_[0];
}

std::string PasspointCredentials::GetOrigin() {
  return android_package_name_;
}

// static
std::string PasspointCredentials::EncodeOI(uint64_t oi) {
  static const char kHexChars[] = "0123456789ABCDEF";
  // Each input byte creates two output hex characters.
  static const size_t size = sizeof(uint64_t) * 2;

  std::string ret(size, '\0');
  size_t i = size;
  // wpa_supplicant expects an even number of char as a byte is filled by two
  // of them.
  do {
    ret[--i] = kHexChars[oi & 0x0f];
    ret[--i] = kHexChars[(oi & 0xf0) >> 4];
    oi = oi >> 8;
  } while (oi > 0);

  return ret.substr(i);
}

// static
std::string PasspointCredentials::EncodeOIList(
    const std::vector<uint64_t>& ois) {
  std::vector<std::string> strings;
  for (const auto& oi : ois) {
    strings.push_back(EncodeOI(oi));
  }
  return base::JoinString(strings, ",");
}

}  // namespace shill
