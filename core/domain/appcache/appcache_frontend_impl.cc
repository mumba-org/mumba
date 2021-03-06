// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/domain/appcache/appcache_frontend_impl.h"

#include "base/logging.h"
#include "core/domain/appcache/web_application_cache_host_impl.h"
#include "third_party/blink/public/web/web_console_message.h"

using blink::WebApplicationCacheHost;
using blink::WebConsoleMessage;

namespace domain {

// Inline helper to keep the lines shorter and unwrapped.
inline WebApplicationCacheHostImpl* GetHost(int id) {
  return WebApplicationCacheHostImpl::FromId(id);
}

void AppCacheFrontendImpl::OnCacheSelected(int host_id,
                                           const common::AppCacheInfo& info) {
  WebApplicationCacheHostImpl* host = GetHost(host_id);
  if (host)
    host->OnCacheSelected(info);
}

void AppCacheFrontendImpl::OnStatusChanged(const std::vector<int>& host_ids,
                                           common::AppCacheStatus status) {
  for (std::vector<int>::const_iterator i = host_ids.begin();
       i != host_ids.end(); ++i) {
    WebApplicationCacheHostImpl* host = GetHost(*i);
    if (host)
      host->OnStatusChanged(status);
  }
}

void AppCacheFrontendImpl::OnEventRaised(const std::vector<int>& host_ids,
                                         common::AppCacheEventID event_id) {
  DCHECK_NE(
      event_id,
      common::AppCacheEventID::APPCACHE_PROGRESS_EVENT);  // See OnProgressEventRaised.
  DCHECK_NE(event_id,
            common::AppCacheEventID::APPCACHE_ERROR_EVENT);  // See OnErrorEventRaised.
  for (std::vector<int>::const_iterator i = host_ids.begin();
       i != host_ids.end(); ++i) {
    WebApplicationCacheHostImpl* host = GetHost(*i);
    if (host)
      host->OnEventRaised(event_id);
  }
}

void AppCacheFrontendImpl::OnProgressEventRaised(
    const std::vector<int>& host_ids,
    const GURL& url,
    int num_total,
    int num_complete) {
  for (std::vector<int>::const_iterator i = host_ids.begin();
       i != host_ids.end(); ++i) {
    WebApplicationCacheHostImpl* host = GetHost(*i);
    if (host)
      host->OnProgressEventRaised(url, num_total, num_complete);
  }
}

void AppCacheFrontendImpl::OnErrorEventRaised(
    const std::vector<int>& host_ids,
    const common::AppCacheErrorDetails& details) {
  for (std::vector<int>::const_iterator i = host_ids.begin();
       i != host_ids.end(); ++i) {
    WebApplicationCacheHostImpl* host = GetHost(*i);
    if (host)
      host->OnErrorEventRaised(details);
  }
}

void AppCacheFrontendImpl::OnLogMessage(int host_id,
                                        common::AppCacheLogLevel log_level,
                                        const std::string& message) {
  WebApplicationCacheHostImpl* host = GetHost(host_id);
  if (host)
    host->OnLogMessage(log_level, message);
}

void AppCacheFrontendImpl::OnContentBlocked(int host_id,
                                            const GURL& manifest_url) {
  WebApplicationCacheHostImpl* host = GetHost(host_id);
  if (host)
    host->OnContentBlocked(manifest_url);
}

void AppCacheFrontendImpl::OnSetSubresourceFactory(
    int host_id,
    network::mojom::URLLoaderFactoryPtr url_loader_factory) {
  WebApplicationCacheHostImpl* host = GetHost(host_id);
  if (host)
    host->SetSubresourceFactory(std::move(url_loader_factory));
}

// Ensure that enum values never get out of sync with the
// ones declared for use within the WebKit api

#define STATIC_ASSERT_ENUM(a, b)                            \
  static_assert(static_cast<int>(a) == static_cast<int>(b), \
                "mismatched enum: " #a)

STATIC_ASSERT_ENUM(WebApplicationCacheHost::kUncached,
                   common::AppCacheStatus::APPCACHE_STATUS_UNCACHED);
STATIC_ASSERT_ENUM(WebApplicationCacheHost::kIdle,
                   common::AppCacheStatus::APPCACHE_STATUS_IDLE);
STATIC_ASSERT_ENUM(WebApplicationCacheHost::kChecking,
                   common::AppCacheStatus::APPCACHE_STATUS_CHECKING);
STATIC_ASSERT_ENUM(WebApplicationCacheHost::kDownloading,
                   common::AppCacheStatus::APPCACHE_STATUS_DOWNLOADING);
STATIC_ASSERT_ENUM(WebApplicationCacheHost::kUpdateReady,
                   common::AppCacheStatus::APPCACHE_STATUS_UPDATE_READY);
STATIC_ASSERT_ENUM(WebApplicationCacheHost::kObsolete,
                   common::AppCacheStatus::APPCACHE_STATUS_OBSOLETE);

STATIC_ASSERT_ENUM(WebApplicationCacheHost::kCheckingEvent,
                   common::AppCacheEventID::APPCACHE_CHECKING_EVENT);
STATIC_ASSERT_ENUM(WebApplicationCacheHost::kErrorEvent,
                   common::AppCacheEventID::APPCACHE_ERROR_EVENT);
STATIC_ASSERT_ENUM(WebApplicationCacheHost::kNoUpdateEvent,
                   common::AppCacheEventID::APPCACHE_NO_UPDATE_EVENT);
STATIC_ASSERT_ENUM(WebApplicationCacheHost::kDownloadingEvent,
                   common::AppCacheEventID::APPCACHE_DOWNLOADING_EVENT);
STATIC_ASSERT_ENUM(WebApplicationCacheHost::kProgressEvent,
                   common::AppCacheEventID::APPCACHE_PROGRESS_EVENT);
STATIC_ASSERT_ENUM(WebApplicationCacheHost::kUpdateReadyEvent,
                   common::AppCacheEventID::APPCACHE_UPDATE_READY_EVENT);
STATIC_ASSERT_ENUM(WebApplicationCacheHost::kCachedEvent,
                   common::AppCacheEventID::APPCACHE_CACHED_EVENT);
STATIC_ASSERT_ENUM(WebApplicationCacheHost::kObsoleteEvent,
                   common::AppCacheEventID::APPCACHE_OBSOLETE_EVENT);

STATIC_ASSERT_ENUM(WebApplicationCacheHost::kManifestError,
                   common::AppCacheErrorReason::APPCACHE_MANIFEST_ERROR);
STATIC_ASSERT_ENUM(WebApplicationCacheHost::kSignatureError,
                   common::AppCacheErrorReason::APPCACHE_SIGNATURE_ERROR);
STATIC_ASSERT_ENUM(WebApplicationCacheHost::kResourceError,
                   common::AppCacheErrorReason::APPCACHE_RESOURCE_ERROR);
STATIC_ASSERT_ENUM(WebApplicationCacheHost::kChangedError,
                   common::AppCacheErrorReason::APPCACHE_CHANGED_ERROR);
STATIC_ASSERT_ENUM(WebApplicationCacheHost::kAbortError,
                   common::AppCacheErrorReason::APPCACHE_ABORT_ERROR);
STATIC_ASSERT_ENUM(WebApplicationCacheHost::kQuotaError,
                   common::AppCacheErrorReason::APPCACHE_QUOTA_ERROR);
STATIC_ASSERT_ENUM(WebApplicationCacheHost::kPolicyError,
                   common::AppCacheErrorReason::APPCACHE_POLICY_ERROR);
STATIC_ASSERT_ENUM(WebApplicationCacheHost::kUnknownError,
                   common::AppCacheErrorReason::APPCACHE_UNKNOWN_ERROR);

STATIC_ASSERT_ENUM(WebConsoleMessage::kLevelVerbose, common::APPCACHE_LOG_VERBOSE);
STATIC_ASSERT_ENUM(WebConsoleMessage::kLevelInfo, common::APPCACHE_LOG_INFO);
STATIC_ASSERT_ENUM(WebConsoleMessage::kLevelWarning, common::APPCACHE_LOG_WARNING);
STATIC_ASSERT_ENUM(WebConsoleMessage::kLevelError, common::APPCACHE_LOG_ERROR);

#undef STATIC_ASSERT_ENUM

}  // namespace content
