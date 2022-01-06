// Copyright 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/prefs/host_prefs.h"

#include <string>

#include "base/metrics/histogram_macros.h"
#include "base/prefs/pref_registry_simple.h"
#include "base/prefs/pref_service.h"
#include "base/prefs/scoped_user_pref_update.h"
#include "base/trace_event/trace_event.h"
#include "core/host/host.h"
//#include "modules/host/host_shutdown.h"
#include "core/host/host_client.h"
//#include "core/host/custom_handlers/protocol_handler_registry.h"
//#include "modules/host/external_protocol/external_protocol_handler.h"
//#include "modules/host/first_run/first_run.h"
//#include "modules/host/geolocation/geolocation_prefs.h"
//#include "modules/host/gpu/gl_string_manager.h"
// #include "modules/host/gpu/gpu_mode_manager.h"
//#include "modules/host/intranet_redirect_detector.h"
#include "core/host/io_thread.h"
//#include "modules/host/media/media_capture_devices_dispatcher.h"
//#include "modules/host/media/media_device_id_salt.h"
//#include "modules/host/media/media_stream_devices_controller.h"
//#include "modules/host/net/http_server_properties_manager_factory.h"
//#include "modules/host/net/net_pref_observer.h"
//#include "modules/host/net/prediction_options.h"
//#include "modules/host/net/predictor.h"
//#include "modules/host/net/pref_proxy_config_tracker_impl.h"
//#include "modules/host/net/ssl_config_service_manager.h"
//#include "modules/host/prefs/chrome_pref_service_factory.h"
//#include "modules/host/prefs/pref_service_syncable.h"
//#include "modules/host/prefs/session_startup_pref.h"
//#include "modules/host/task_manager/task_manager.h"
//#include "core/common/pref_names.h"
//#include "components/content_settings/core/host/host_content_settings_map.h"
//#include "components/pref_registry/pref_registry_syncable.h"
//#include "core/host/galaxy/app/process.h"
//#include "net/http/http_server_properties_manager.h"

//#if defined(USE_ASH)
//#include "modules/host/ui/ash/chrome_launcher_prefs.h"
//#endif

namespace {

#if !defined(OS_ANDROID)
// The AutomaticProfileResetter service used this preference to save that the
// profile reset prompt had already been shown, however, the preference has been
// renamed in Local State. We keep the name here for now so that we can clear
// out legacy values.
// TODO(engedy): Remove this and usages in M42 or later. See crbug.com/398813.
const char kLegacyProfileResetPromptMemento[] = "profile.reset_prompt_memento";
#endif

}  // namespace

namespace host {

void RegisterLocalState(PrefRegistrySimple* registry) {

  // Please keep this list alphabetized.
  //AppListService::RegisterPrefs(registry);
  //host_shutdown::RegisterPrefs(registry);
  //HostContext::RegisterPrefs(registry);
  //chrome_prefs::RegisterPrefs(registry);
  //ExternalProtocolHandler::RegisterPrefs(registry);
  //geolocation::RegisterPrefs(registry);
  //GLStringManager::RegisterPrefs(registry);
  //GpuModeManager::RegisterPrefs(registry);
  //IntranetRedirectDetector::RegisterPrefs(registry);
  IOThread::RegisterPrefs(registry);
  //network_time::NetworkTimeTracker::RegisterPrefs(registry);
  //PrefProxyConfigTrackerImpl::RegisterPrefs(registry);
  //ProfileInfoCache::RegisterPrefs(registry);
  //profiles::RegisterPrefs(registry);
  //PromoResourceService::RegisterPrefs(registry);
  //rappor::RapporService::RegisterPrefs(registry);
  //RegisterScreenshotPrefs(registry);
  //SigninManagerFactory::RegisterPrefs(registry);
  //SSLConfigServiceManager::RegisterPrefs(registry);
  //UpgradeDetector::RegisterPrefs(registry);
}

}  // namespace host
