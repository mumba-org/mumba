// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/service_worker/service_worker_content_settings_proxy_impl.h"

#include "base/threading/thread.h"
#include "core/host/host_thread.h"
#include "core/host/host_client.h"
#include "core/shared/common/client.h"
#include "core/host/service_worker/origin_utils.h"
#include "mojo/public/cpp/bindings/strong_binding.h"

namespace host {

ServiceWorkerContentSettingsProxyImpl::ServiceWorkerContentSettingsProxyImpl(
    const GURL& script_url,
    base::WeakPtr<ServiceWorkerContextCore> context,
    blink::mojom::WorkerContentSettingsProxyRequest request)
    : origin_(CreateUrlOrigin(script_url)),
      context_(context),
      binding_(this, std::move(request)) {}

ServiceWorkerContentSettingsProxyImpl::
    ~ServiceWorkerContentSettingsProxyImpl() = default;

void ServiceWorkerContentSettingsProxyImpl::AllowIndexedDB(
    const base::string16& name,
    AllowIndexedDBCallback callback) {
  DCHECK_CURRENTLY_ON(HostThread::IO);
  // if (origin_.unique()) {
  //   std::move(callback).Run(false);
  //   return;
  // }
  // |render_frames| is used to show UI for the frames affected by the
  // content setting. However, service worker is not necessarily associated
  // with frames or making the request on behalf of frames,
  // so just pass an empty |render_frames|.
  std::vector<std::pair<int, int>> render_frames;
  std::move(callback).Run(true);
  // std::move(callback).Run(GetContentClient()->browser()->AllowWorkerIndexedDB(
  //     origin_.GetURL(), name, context_->wrapper()->resource_context(),
  //     render_frames));
}

void ServiceWorkerContentSettingsProxyImpl::RequestFileSystemAccessSync(
    RequestFileSystemAccessSyncCallback callback) {
  mojo::ReportBadMessage(
      "The FileSystem API is not exposed to service workers "
      "but somehow a service worker requested access.");
}

}  // namespace host
