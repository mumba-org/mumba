// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/appcache/appcache_navigation_handle.h"

#include "base/bind.h"
#include "core/host/appcache/appcache_navigation_handle_core.h"
#include "core/host/appcache/chrome_appcache_service.h"
#include "core/host/host_thread.h"
#include "core/shared/common/appcache_info.h"

namespace {
// PlzNavigate: Used to generate the host id for a navigation initiated by the
// browser. Starts at -2 and keeps going down.
static int g_next_appcache_host_id = -1;
}

namespace host {

AppCacheNavigationHandle::AppCacheNavigationHandle(
    ChromeAppCacheService* appcache_service)
    : appcache_host_id_(common::kAppCacheNoHostId),
      core_(nullptr),
      weak_factory_(this) {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  appcache_host_id_ = g_next_appcache_host_id--;
  core_.reset(new AppCacheNavigationHandleCore(
      weak_factory_.GetWeakPtr(), appcache_service, appcache_host_id_));
  HostThread::PostTask(
      HostThread::IO, FROM_HERE,
      base::BindOnce(&AppCacheNavigationHandleCore::Initialize,
                     base::Unretained(core_.get())));
}

AppCacheNavigationHandle::~AppCacheNavigationHandle() {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  // Delete the AppCacheNavigationHandleCore on the IO thread.
  HostThread::DeleteSoon(HostThread::IO, FROM_HERE, core_.release());
}

}  // namespace host
