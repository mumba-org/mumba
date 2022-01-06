// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/net/ssl_config_service_manager.h"

#include <stdint.h>

#include <algorithm>
#include <string>
#include <vector>

#include "base/bind.h"
//#include "base/location.h"
#include "base/macros.h"
#include "base/metrics/field_trial_params.h"
#include "base/single_thread_task_runner.h"
#include "base/strings/string_util.h"
#include "base/values.h"
//#include "components/content_settings/core/browser/content_settings_utils.h"
//#include "components/content_settings/core/common/content_settings.h"
#include "components/prefs/pref_change_registrar.h"
#include "components/prefs/pref_member.h"
#include "components/prefs/pref_registry_simple.h"
#include "components/prefs/pref_service.h"
#include "net/ssl/ssl_cipher_suite_names.h"
#include "net/ssl/ssl_config_service.h"

namespace host {

class SSLConfigServicePref : public net::SSLConfigService {
 public:
  explicit SSLConfigServicePref(
      const scoped_refptr<base::SingleThreadTaskRunner>& io_task_runner);

  // Store SSL config settings in |config|. Must only be called from IO thread.
  void GetSSLConfig(net::SSLConfig* config) override;

 private:
  // Allow the pref watcher to update our internal state.
  friend class SSLConfigServiceManagerImpl;

  ~SSLConfigServicePref() override {}

  // This method is posted to the IO thread from the browser thread to carry the
  // new config information.
  void SetNewSSLConfig(const net::SSLConfig& new_config);

  // Cached value of prefs, should only be accessed from IO thread.
  net::SSLConfig cached_config_;

  scoped_refptr<base::SingleThreadTaskRunner> io_task_runner_;

  DISALLOW_COPY_AND_ASSIGN(SSLConfigServicePref);
};

SSLConfigServicePref::SSLConfigServicePref(
    const scoped_refptr<base::SingleThreadTaskRunner>& io_task_runner)
    : io_task_runner_(io_task_runner) {}

void SSLConfigServicePref::GetSSLConfig(net::SSLConfig* config) {
  DCHECK(io_task_runner_->BelongsToCurrentThread());
  *config = cached_config_;
}

void SSLConfigServicePref::SetNewSSLConfig(const net::SSLConfig& new_config) {
  net::SSLConfig orig_config = cached_config_;
  cached_config_ = new_config;
  ProcessConfigUpdate(orig_config, new_config);
}

////////////////////////////////////////////////////////////////////////////////
//  SSLConfigServiceManagerImpl

// The manager for holding and updating an SSLConfigServicePref instance.
class SSLConfigServiceManagerImpl : public SSLConfigServiceManager {
 public:
  SSLConfigServiceManagerImpl(
      const scoped_refptr<base::SingleThreadTaskRunner>& io_task_runner);
  ~SSLConfigServiceManagerImpl() override {}

  net::SSLConfigService* Get() override;

 private:

  // Store SSL config settings in |config|, directly from the preferences. Must
  // only be called from UI thread.
  void GetSSLConfigFromPrefs(net::SSLConfig* config);

  // Processes changes to the disabled cipher suites preference, updating the
  // cached list of parsed SSL/TLS cipher suites that are disabled.
  void OnDisabledCipherSuitesChange();//PrefService* local_state);

  // PrefChangeRegistrar local_state_change_registrar_;

  // // The local_state prefs (should only be accessed from UI thread)
  // BooleanPrefMember rev_checking_enabled_;
  // BooleanPrefMember rev_checking_required_local_anchors_;
  // BooleanPrefMember sha1_local_anchors_enabled_;
  // BooleanPrefMember symantec_legacy_infrastructure_enabled_;
  // StringPrefMember ssl_version_min_;
  // StringPrefMember ssl_version_max_;
  // StringPrefMember tls13_variant_;

  // The cached list of disabled SSL cipher suites.
  std::vector<uint16_t> disabled_cipher_suites_;

  scoped_refptr<SSLConfigServicePref> ssl_config_service_;

  scoped_refptr<base::SingleThreadTaskRunner> io_task_runner_;

  DISALLOW_COPY_AND_ASSIGN(SSLConfigServiceManagerImpl);
};

SSLConfigServiceManagerImpl::SSLConfigServiceManagerImpl(
    const scoped_refptr<base::SingleThreadTaskRunner>& io_task_runner)
    : ssl_config_service_(new SSLConfigServicePref(io_task_runner)),
      io_task_runner_(io_task_runner) {

  OnDisabledCipherSuitesChange();
  GetSSLConfigFromPrefs(&ssl_config_service_->cached_config_);
}

net::SSLConfigService* SSLConfigServiceManagerImpl::Get() {
  return ssl_config_service_.get();
}

void SSLConfigServiceManagerImpl::GetSSLConfigFromPrefs(
    net::SSLConfig* config) {
  
  config->rev_checking_enabled = false;
  config->rev_checking_required_local_anchors = false;
  config->sha1_local_anchors_enabled = true;
  config->symantec_enforcement_disabled = true;
  config->version_min = net::kDefaultSSLVersionMin;
  config->version_max = net::kDefaultSSLVersionMax;
  config->tls13_variant = net::kTLS13VariantDraft23;
  config->disabled_cipher_suites = disabled_cipher_suites_;
}

void SSLConfigServiceManagerImpl::OnDisabledCipherSuitesChange(
  ) {
  //disabled_cipher_suites_ = ParseCipherSuites(ListValueToStringVector(value));
}


SSLConfigServiceManager* SSLConfigServiceManager::CreateDefaultManager(
    const scoped_refptr<base::SingleThreadTaskRunner>& io_task_runner) {
  return new SSLConfigServiceManagerImpl(io_task_runner);
}

}