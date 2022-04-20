// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_CELLULAR_CELLULAR_SERVICE_H_
#define SHILL_CELLULAR_CELLULAR_SERVICE_H_

#include <memory>
#include <set>
#include <string>
#include <utility>

#include <base/time/time.h>
#include <gtest/gtest_prod.h>  // for FRIEND_TEST

#include "shill/cellular/cellular.h"
#include "shill/cellular/subscription_state.h"
#include "shill/mockable.h"
#include "shill/refptr_types.h"
#include "shill/service.h"

namespace shill {

class Error;
class Manager;

class CellularService : public Service {
 public:
  enum ActivationType {
    kActivationTypeNonCellular,  // For future use
    kActivationTypeOMADM,        // For future use
    kActivationTypeOTA,
    kActivationTypeOTASP,
    kActivationTypeUnknown
  };

  // A CellularService is associated with a single SIM Profile, uniquely
  // identified by |iccid|. For pSIM profiles this also identifies the SIM card.
  // For eSIM profiles, |eid| is non-empty and identifies the eSIM card.
  // A CellularService may not be the active service for the associated
  // device, so its eID, ICCID and IMSI properties may not match the device
  // properties.
  CellularService(Manager* manager,
                  const std::string& imsi,
                  const std::string& iccid,
                  const std::string& eid);
  CellularService(const CellularService&) = delete;
  CellularService& operator=(const CellularService&) = delete;

  ~CellularService() override;

  void SetDevice(Cellular* device);

  // Public Service overrides
  void CompleteCellularActivation(Error* error) override;
  std::string GetStorageIdentifier() const override;
  std::string GetLoadableStorageIdentifier(
      const StoreInterface& storage) const override;
  bool IsLoadableFrom(const StoreInterface& storage) const override;
  bool Load(const StoreInterface* storage) override;
  bool Unload() override;
  bool Save(StoreInterface* storage) override;
  bool IsVisible() const override;

  // See matching method in cellular.h for details.
  const std::string& GetSimCardId() const;

  const std::string& imsi() const { return imsi_; }
  const std::string& iccid() const { return iccid_; }
  const std::string& eid() const { return eid_; }
  const CellularRefPtr& cellular() const { return cellular_; }

  void SetActivationType(ActivationType type);
  std::string GetActivationTypeString() const;

  mockable void SetActivationState(const std::string& state);
  mockable const std::string& activation_state() const {
    return activation_state_;
  }

  void SetOLP(const std::string& url,
              const std::string& method,
              const std::string& post_data);
  const Stringmap& olp() const { return olp_; }

  void SetUsageURL(const std::string& url);
  const std::string& usage_url() const { return usage_url_; }

  void SetServingOperator(const Stringmap& serving_operator);
  const Stringmap& serving_operator() const { return serving_operator_; }

  // Sets network technology to |technology| and broadcasts the property change.
  void SetNetworkTechnology(const std::string& technology);
  const std::string& network_technology() const { return network_technology_; }

  // Sets roaming state to |state| and broadcasts the property change.
  void SetRoamingState(const std::string& state);
  const std::string& roaming_state() const { return roaming_state_; }
  // Checks device rules as well as service rules and returns if roaming is
  // allowed for this service.
  bool IsRoamingAllowed();
  // Returns true if we are registered on a roaming network, but roaming is
  // disallowed.
  bool IsRoamingRuleViolated();

  const std::string& ppp_username() const { return ppp_username_; }
  const std::string& ppp_password() const { return ppp_password_; }

  Stringmap* GetUserSpecifiedApn();
  Stringmap* GetLastGoodApn();
  virtual void SetLastGoodApn(const Stringmap& apn_info);
  virtual void ClearLastGoodApn();
  Stringmap* GetLastAttachApn();
  virtual void SetLastAttachApn(const Stringmap& apn_info);
  virtual void ClearLastAttachApn();

  void NotifySubscriptionStateChanged(SubscriptionState subscription_state);

  static const char kStorageIccid[];
  static const char kStorageImsi[];
  static const char kStoragePPPUsername[];
  static const char kStoragePPPPassword[];
  static const char kStorageSimCardId[];
  static const char kStorageAllowRoaming[];

  // Used to copy the value of Device.AllowRoaming by service_provider for
  // SIM's inserted before M94. Also used by unit tests.
  void set_allow_roaming(bool allow_roaming) { allow_roaming_ = allow_roaming; }

  void set_activation_state_for_testing(const std::string& activation_state) {
    activation_state_ = activation_state;
  }
  void set_apn_info_for_testing(const Stringmap& apn_info) {
    apn_info_ = apn_info;
  }

 protected:
  // Protected Service overrides
  void OnConnect(Error* error) override;
  void OnDisconnect(Error* error, const char* reason) override;
  bool IsAutoConnectable(const char** reason) const override;
  base::TimeDelta GetMaxAutoConnectCooldownTime() const override;
  bool IsDisconnectable(Error* error) const override;
  bool IsMeteredByServiceProperties() const override;
  RpcIdentifier GetDeviceRpcId(Error* error) const override;

 private:
  friend class CellularCapability3gppTest;
  friend class CellularCapabilityCdmaTest;
  friend class CellularServiceTest;
  friend class CellularTest;

  template <typename key_type, typename value_type>
  friend class ContainsCellularPropertiesMatcherP2;

  FRIEND_TEST(CellularTest, Connect);
  FRIEND_TEST(CellularTest, FriendlyServiceName);
  FRIEND_TEST(CellularTest, GetLogin);  // ppp_username_, ppp_password_
  FRIEND_TEST(CellularServiceTest, SetApn);
  FRIEND_TEST(CellularServiceTest, SetAttachApn);
  FRIEND_TEST(CellularServiceTest, ClearApn);
  FRIEND_TEST(CellularServiceTest, LastGoodApn);
  FRIEND_TEST(CellularServiceTest, IsAutoConnectable);
  FRIEND_TEST(CellularServiceTest, LoadResetsPPPAuthFailure);
  FRIEND_TEST(CellularServiceTest, SaveAndLoadApn);
  FRIEND_TEST(CellularServiceTest, MergeDetailsFromApnList);
  FRIEND_TEST(CellularServiceTest, CustomSetterNoopChange);
  FRIEND_TEST(CellularServiceTest, SetAllowRoaming);

  // Used in CellularServiceTest
  static const char kAutoConnActivating[];
  static const char kAutoConnSimUnselected[];
  static const char kAutoConnBadPPPCredentials[];
  static const char kAutoConnDeviceDisabled[];
  static const char kAutoConnNotRegistered[];
  static const char kAutoConnOutOfCredits[];
  static const char kAutoConnConnectFailed[];
  static const char kAutoConnInhibited[];

  void HelpRegisterDerivedString(
      const std::string& name,
      std::string (CellularService::*get)(Error* error),
      bool (CellularService::*set)(const std::string& value, Error* error));
  void HelpRegisterDerivedStringmap(
      const std::string& name,
      Stringmap (CellularService::*get)(Error* error),
      bool (CellularService::*set)(const Stringmap& value, Error* error));
  void HelpRegisterDerivedBool(const std::string& name,
                               bool (CellularService::*get)(Error* error),
                               bool (CellularService::*set)(const bool&,
                                                            Error*));
  std::set<std::string> GetStorageGroupsWithProperty(
      const StoreInterface& storage,
      const std::string& key,
      const std::string& value) const;
  std::string CalculateActivationType(Error* error);
  Stringmap GetApn(Error* error);
  bool SetApn(const Stringmap& value, Error* error);
  KeyValueStore GetStorageProperties() const;
  std::string GetDefaultStorageIdentifier() const;
  bool IsOutOfCredits(Error* /*error*/);
  bool SetAllowRoaming(const bool& value, Error* error);
  bool GetAllowRoaming(Error* /*error*/);

  // The IMSI for the SIM. This is saved in the Profile and emitted as a
  // property so that it is available for non primary SIM Profiles.
  // This is set on construction when available, or may be loaded from a saved
  // Profile entry.
  std::string imsi_;

  // ICCID uniquely identifies a SIM profile.
  const std::string iccid_;

  // EID of the associated eSIM card, or empty for a SIM profile associated with
  // a physical SIM card.
  const std::string eid_;

  ActivationType activation_type_ = kActivationTypeUnknown;
  std::string activation_state_;
  Stringmap serving_operator_;
  std::string network_technology_;
  std::string roaming_state_;
  Stringmap olp_;
  std::string usage_url_;
  Stringmap apn_info_;
  Stringmap last_good_apn_info_;
  // Stores the attach APN used for the initial EPS settings
  Stringmap last_attach_apn_info_;
  std::string ppp_username_;
  std::string ppp_password_;
  bool allow_roaming_ = false;
  bool provider_requires_roaming_ = false;

  // The storage identifier defaults to cellular_{iccid}.
  std::string storage_identifier_;

  // The Cellular Device associated with this Service. Note: This may not be
  // the active service for |cellular_| if there are multiple SIM profiles for
  // |cellular_|.
  CellularRefPtr cellular_;

  // Flag indicating if the user has run out of data credits.
  bool out_of_credits_ = false;
};

}  // namespace shill

#endif  // SHILL_CELLULAR_CELLULAR_SERVICE_H_
