// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/tracing/host_tracing_delegate.h"

#include <string>
#include <utility>
#include <vector>

#include "base/strings/string_piece.h"
#include "base/time/time.h"
#include "base/values.h"
#include "build/build_config.h"
// #include "chrome/browser/browser_process.h"
// #include "chrome/browser/profiles/profile.h"
// #include "chrome/browser/profiles/profile_manager.h"
// #include "chrome/browser/tracing/crash_service_uploader.h"
// #include "chrome/browser/ui/browser.h"
// #include "chrome/browser/ui/browser_list.h"
// #include "chrome/browser/ui/browser_otr_state.h"
// #include "chrome/common/pref_names.h"
// #include "chrome/common/trace_event_args_whitelist.h"
#include "components/metrics/metrics_pref_names.h"
#include "components/prefs/pref_registry_simple.h"
#include "components/prefs/pref_service.h"
#include "components/variations/active_field_trials.h"
#include "components/version_info/version_info.h"
#include "core/host/background_tracing_config.h"
#include "core/host/host_thread.h"
#include "core/host/trace_uploader.h"

namespace host {

namespace {

class TraceUploaderImpl : public TraceUploader {
public:
  TraceUploaderImpl() {}
  ~TraceUploaderImpl() override {}
  // Compresses and uploads the given file contents.
  void DoUpload(const std::string& file_contents,
                TraceUploader::UploadMode upload_mode,
                std::unique_ptr<const base::DictionaryValue> metadata,
                const TraceUploader::UploadProgressCallback& progress_callback,
                const TraceUploader::UploadDoneCallback& done_callback) override {}
};

//const int kMinDaysUntilNextUpload = 7;

}  // namespace

void HostTracingDelegate::RegisterPrefs(PrefRegistrySimple* registry) {
  //registry->RegisterInt64Pref(prefs::kBackgroundTracingLastUpload, 0);
}

HostTracingDelegate::HostTracingDelegate() {//: incognito_launched_(false) {
  CHECK(HostThread::CurrentlyOn(HostThread::UI));
}

HostTracingDelegate::~HostTracingDelegate() {
  CHECK(HostThread::CurrentlyOn(HostThread::UI));
}

std::unique_ptr<TraceUploader> HostTracingDelegate::GetTraceUploader(
    net::URLRequestContextGetter* request_context) {
  //return std::unique_ptr<TraceUploader>(
  //    new TraceCrashServiceUploader(request_context));
  NOTREACHED();
  return std::unique_ptr<TraceUploader>(new TraceUploaderImpl());
}

//namespace {

//enum PermitMissingProfile { PROFILE_REQUIRED, PROFILE_NOT_REQUIRED };

//Profile* GetProfile() {
  //ProfileManager* profile_manager = g_browser_process->profile_manager();
//  if (!profile_manager)
 //   return nullptr;

 // return profile_manager->GetProfileByPath(
 //     profile_manager->GetLastUsedProfileDir(profile_manager->user_data_dir()));
//}

//bool ProfileAllowsScenario(const BackgroundTracingConfig& config,
//                           PermitMissingProfile profile_permission) {
//   // If the profile hasn't loaded or been created yet, we allow the scenario
//   // to start up, but not be finalized.
//   Profile* profile = GetProfile();
//   if (!profile) {
//     if (profile_permission == PROFILE_REQUIRED)
//       return false;
//     else
//       return true;
//   }

// #if !defined(OS_ANDROID)
//   // Safeguard, in case background tracing is responsible for a crash on
//   // startup.
//   if (profile->GetLastSessionExitType() == Profile::EXIT_CRASHED)
//     return false;
// #else
//   // In case of Android the exit state is always set as EXIT_CRASHED. So,
//   // preemptive mode cannot be used safely.
//   if (config.tracing_mode() == BackgroundTracingConfig::PREEMPTIVE)
//     return false;
// #endif

//   PrefService* local_state = g_browser_process->local_state();
//   DCHECK(local_state);

// #if !defined(OS_CHROMEOS) && defined(OFFICIAL_BUILD)
//   if (!local_state->GetBoolean(metrics::prefs::kMetricsReportingEnabled))
//     return false;
// #endif // !OS_CHROMEOS && OFFICIAL_BUILD

//   if (config.tracing_mode() == BackgroundTracingConfig::PREEMPTIVE) {
//     const base::Time last_upload_time = base::Time::FromInternalValue(
//         local_state->GetInt64(prefs::kBackgroundTracingLastUpload));
//     if (!last_upload_time.is_null()) {
//       base::Time computed_next_allowed_time =
//           last_upload_time + base::TimeDelta::FromDays(kMinDaysUntilNextUpload);
//       if (computed_next_allowed_time > base::Time::Now()) {
//         return false;
//       }
//     }
//   }

  //return true;
//}

//}  // namespace

bool HostTracingDelegate::IsAllowedToBeginBackgroundScenario(
    const BackgroundTracingConfig& config,
    bool requires_anonymized_data) {
// #if defined(OS_ANDROID)
//   // TODO(oysteine): Support preemptive mode safely in Android.
//   if (config.tracing_mode() == BackgroundTracingConfig::PREEMPTIVE)
//     return false;
// #endif

//   if (!ProfileAllowsScenario(config, PROFILE_NOT_REQUIRED))
//     return false;

//   if (requires_anonymized_data && chrome::IsIncognitoSessionActive())
//     return false;

  return true;
}

bool HostTracingDelegate::IsAllowedToEndBackgroundScenario(
    const BackgroundTracingConfig& config,
    bool requires_anonymized_data) {
  // if (requires_anonymized_data &&
  //     (incognito_launched_ || chrome::IsIncognitoSessionActive())) {
  //   return false;
  // }

  // if (!ProfileAllowsScenario(config, PROFILE_REQUIRED))
  //   return false;

  // if (config.tracing_mode() == BackgroundTracingConfig::PREEMPTIVE) {
  //   PrefService* local_state = g_browser_process->local_state();
  //   DCHECK(local_state);
  //   local_state->SetInt64(prefs::kBackgroundTracingLastUpload,
  //                         base::Time::Now().ToInternalValue());

  //   // We make sure we've persisted the value in case finalizing the tracing
  //   // causes a crash.
  //   local_state->CommitPendingWrite();
  // }

  return true;
}

bool HostTracingDelegate::IsProfileLoaded() {
  //return GetProfile() != nullptr;
  return false;
}

std::unique_ptr<base::DictionaryValue>
HostTracingDelegate::GenerateMetadataDict() {
  auto metadata_dict = std::make_unique<base::DictionaryValue>();
  std::vector<std::string> variations;
  variations::GetFieldTrialActiveGroupIdsAsStrings(base::StringPiece(),
                                                   &variations);

  std::unique_ptr<base::ListValue> variations_list(new base::ListValue());
  for (const auto& it : variations)
    variations_list->AppendString(it);

  metadata_dict->Set("field-trials", std::move(variations_list));
  metadata_dict->SetString("revision", version_info::GetLastChange());
  return metadata_dict;
}

MetadataFilterPredicate
HostTracingDelegate::GetMetadataFilterPredicate() {
  //return base::Bind(&IsMetadataWhitelisted);
  return MetadataFilterPredicate();
}


} // host