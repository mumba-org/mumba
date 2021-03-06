// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/service_worker/service_worker_installed_scripts_sender.h"

#include "base/memory/ref_counted.h"
#include "base/trace_event/trace_event.h"
#include "core/host/service_worker/service_worker_context_core.h"
#include "core/host/service_worker/service_worker_disk_cache.h"
#include "core/host/service_worker/service_worker_script_cache_map.h"
#include "core/host/service_worker/service_worker_storage.h"

namespace host {

ServiceWorkerInstalledScriptsSender::ServiceWorkerInstalledScriptsSender(
    ServiceWorkerVersion* owner)
    : owner_(owner),
      main_script_url_(owner_->script_url()),
      main_script_id_(
          owner_->script_cache_map()->LookupResourceId(main_script_url_)),
      sent_main_script_(false),
      binding_(this),
      state_(State::kNotStarted),
      last_finished_reason_(
          ServiceWorkerInstalledScriptReader::FinishedReason::kNotFinished) {
  DCHECK(ServiceWorkerVersion::IsInstalled(owner_->status()));
  DCHECK_NE(common::kInvalidServiceWorkerResourceId, main_script_id_);
}

ServiceWorkerInstalledScriptsSender::~ServiceWorkerInstalledScriptsSender() {}

blink::mojom::ServiceWorkerInstalledScriptsInfoPtr
ServiceWorkerInstalledScriptsSender::CreateInfoAndBind() {
  DCHECK_EQ(State::kNotStarted, state_);

  std::vector<ServiceWorkerDatabase::ResourceRecord> resources;
  owner_->script_cache_map()->GetResources(&resources);
  std::vector<GURL> installed_urls;
  for (const auto& resource : resources) {
    installed_urls.emplace_back(resource.url);
    if (resource.url == main_script_url_)
      continue;
    pending_scripts_.emplace(resource.resource_id, resource.url);
  }
  DCHECK(!installed_urls.empty())
      << "At least the main script should be installed.";

  auto info = blink::mojom::ServiceWorkerInstalledScriptsInfo::New();
  info->manager_request = mojo::MakeRequest(&manager_);
  info->installed_urls = std::move(installed_urls);
  binding_.Bind(mojo::MakeRequest(&info->manager_host_ptr));
  return info;
}

void ServiceWorkerInstalledScriptsSender::Start() {
  DCHECK_EQ(State::kNotStarted, state_);
  DCHECK_NE(common::kInvalidServiceWorkerResourceId, main_script_id_);
  TRACE_EVENT_NESTABLE_ASYNC_BEGIN1("ServiceWorker",
                                    "ServiceWorkerInstalledScriptsSender", this,
                                    "main_script_url", main_script_url_.spec());
  StartSendingScript(main_script_id_, main_script_url_);
}

void ServiceWorkerInstalledScriptsSender::StartSendingScript(
    int64_t resource_id,
    const GURL& script_url) {
  DCHECK(!reader_);
  DCHECK(current_sending_url_.is_empty());
  state_ = State::kSendingScripts;
  current_sending_url_ = script_url;

  std::unique_ptr<ServiceWorkerResponseReader> response_reader =
      owner_->context()->storage()->CreateResponseReader(resource_id);
  TRACE_EVENT_NESTABLE_ASYNC_BEGIN1("ServiceWorker", "SendingScript", this,
                                    "script_url", current_sending_url_.spec());
  reader_ = std::make_unique<ServiceWorkerInstalledScriptReader>(
      std::move(response_reader), this);
  reader_->Start();
}

void ServiceWorkerInstalledScriptsSender::OnStarted(
    std::string encoding,
    base::flat_map<std::string, std::string> headers,
    mojo::ScopedDataPipeConsumerHandle body_handle,
    uint64_t body_size,
    mojo::ScopedDataPipeConsumerHandle meta_data_handle,
    uint64_t meta_data_size) {
  DCHECK(reader_);
  DCHECK_EQ(State::kSendingScripts, state_);
  TRACE_EVENT_NESTABLE_ASYNC_INSTANT2("ServiceWorker", "OnStarted", this,
                                      "body_size", body_size, "meta_data_size",
                                      meta_data_size);
  auto script_info = blink::mojom::ServiceWorkerScriptInfo::New();
  script_info->script_url = current_sending_url_;
  script_info->headers = std::move(headers);
  script_info->encoding = std::move(encoding);
  script_info->body = std::move(body_handle);
  script_info->body_size = body_size;
  script_info->meta_data = std::move(meta_data_handle);
  script_info->meta_data_size = meta_data_size;
  manager_->TransferInstalledScript(std::move(script_info));
}

void ServiceWorkerInstalledScriptsSender::OnHttpInfoRead(
    scoped_refptr<HttpResponseInfoIOBuffer> http_info) {
  DCHECK(reader_);
  DCHECK_EQ(State::kSendingScripts, state_);
  if (IsSendingMainScript())
    owner_->SetMainScriptHttpResponseInfo(*http_info->http_info);
}

void ServiceWorkerInstalledScriptsSender::OnFinished(
    ServiceWorkerInstalledScriptReader::FinishedReason reason) {
  DCHECK(reader_);
  DCHECK_EQ(State::kSendingScripts, state_);
  TRACE_EVENT_NESTABLE_ASYNC_END0("ServiceWorker", "SendingScript", this);
  reader_.reset();
  current_sending_url_ = GURL();

  if (IsSendingMainScript())
    sent_main_script_ = true;

  if (reason != ServiceWorkerInstalledScriptReader::FinishedReason::kSuccess) {
    Abort(reason);
    return;
  }

  if (pending_scripts_.empty()) {
    UpdateFinishedReasonAndBecomeIdle(
        ServiceWorkerInstalledScriptReader::FinishedReason::kSuccess);
    TRACE_EVENT_NESTABLE_ASYNC_END0(
        "ServiceWorker", "ServiceWorkerInstalledScriptsSender", this);
    return;
  }

  // Start sending the next script.
  int64_t next_id = pending_scripts_.front().first;
  GURL next_url = pending_scripts_.front().second;
  pending_scripts_.pop();
  StartSendingScript(next_id, next_url);
}

void ServiceWorkerInstalledScriptsSender::Abort(
    ServiceWorkerInstalledScriptReader::FinishedReason reason) {
  DCHECK_EQ(State::kSendingScripts, state_);
  DCHECK_NE(ServiceWorkerInstalledScriptReader::FinishedReason::kSuccess,
            reason);
  TRACE_EVENT_NESTABLE_ASYNC_END1("ServiceWorker",
                                  "ServiceWorkerInstalledScriptsSender", this,
                                  "FinishedReason", static_cast<int>(reason));

  // Remove all pending scripts.
  // Note that base::queue doesn't have clear(), and also base::STLClearObject
  // is not applicable for base::queue since it doesn't have reserve().
  base::queue<std::pair<int64_t, GURL>> empty;
  pending_scripts_.swap(empty);

  UpdateFinishedReasonAndBecomeIdle(reason);

  switch (reason) {
    case ServiceWorkerInstalledScriptReader::FinishedReason::kNotFinished:
    case ServiceWorkerInstalledScriptReader::FinishedReason::kSuccess:
      NOTREACHED();
      return;
    case ServiceWorkerInstalledScriptReader::FinishedReason::kNoHttpInfoError:
    case ServiceWorkerInstalledScriptReader::FinishedReason::
        kResponseReaderError:
      owner_->SetStartWorkerStatusCode(common::SERVICE_WORKER_ERROR_DISK_CACHE);
      // Abort the worker by deleting from the registration since the data was
      // corrupted.
      if (owner_->context()) {
        ServiceWorkerRegistration* registration =
            owner_->context()->GetLiveRegistration(owner_->registration_id());
        // This ends up with destructing |this|.
        registration->DeleteVersion(owner_);
      }
      return;
    case ServiceWorkerInstalledScriptReader::FinishedReason::
        kCreateDataPipeError:
    case ServiceWorkerInstalledScriptReader::FinishedReason::kConnectionError:
    case ServiceWorkerInstalledScriptReader::FinishedReason::
        kMetaDataSenderError:
      // Notify the renderer that a connection failure happened. Usually the
      // failure means the renderer gets killed, and the error handler of
      // EmbeddedWorkerInstance is invoked soon.
      manager_.reset();
      binding_.Close();
      return;
  }
}

void ServiceWorkerInstalledScriptsSender::UpdateFinishedReasonAndBecomeIdle(
    ServiceWorkerInstalledScriptReader::FinishedReason reason) {
  DCHECK_EQ(State::kSendingScripts, state_);
  DCHECK_NE(ServiceWorkerInstalledScriptReader::FinishedReason::kNotFinished,
            reason);
  DCHECK(current_sending_url_.is_empty());
  state_ = State::kIdle;
  last_finished_reason_ = reason;
}

void ServiceWorkerInstalledScriptsSender::RequestInstalledScript(
    const GURL& script_url) {
  TRACE_EVENT1("ServiceWorker",
               "ServiceWorkerInstalledScriptsSender::RequestInstalledScript",
               "script_url", script_url.spec());
  int64_t resource_id =
      owner_->script_cache_map()->LookupResourceId(script_url);

  if (resource_id == common::kInvalidServiceWorkerResourceId) {
    mojo::ReportBadMessage("Requested script was not installed.");
    return;
  }

  if (state_ == State::kSendingScripts) {
    // The sender is now sending other scripts. Push the requested script into
    // the waiting queue.
    pending_scripts_.emplace(resource_id, script_url);
    return;
  }

  DCHECK_EQ(State::kIdle, state_);
  TRACE_EVENT_NESTABLE_ASYNC_BEGIN1("ServiceWorker",
                                    "ServiceWorkerInstalledScriptsSender", this,
                                    "main_script_url", main_script_url_.spec());
  StartSendingScript(resource_id, script_url);
}

bool ServiceWorkerInstalledScriptsSender::IsSendingMainScript() const {
  // |current_sending_url_| could match |main_script_url_| even though
  // |sent_main_script_| is false if calling importScripts for the main
  // script.
  return !sent_main_script_ && current_sending_url_ == main_script_url_;
}

}  // namespace host
