// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/application/url_data_source_impl.h"

#include <utility>

#include "base/bind.h"
#include "base/memory/ref_counted_memory.h"
#include "base/strings/string_util.h"
#include "core/host/application/url_data_manager_backend.h"
#include "core/host/host_thread.h"
#include "core/host/application/url_data_source.h"

namespace host {

URLDataSourceImpl::URLDataSourceImpl(const std::string& source_name,
                                     URLDataSource* source)
    : source_name_(source_name), backend_(nullptr), source_(source) {}

URLDataSourceImpl::~URLDataSourceImpl() {
}

void URLDataSourceImpl::SendResponse(
    int request_id,
    scoped_refptr<base::RefCountedMemory> bytes) {
  if (URLDataManager::IsScheduledForDeletion(this)) {
    // We're scheduled for deletion. Servicing the request would result in
    // this->AddRef being invoked, even though the ref count is 0 and 'this' is
    // about to be deleted. If the AddRef were allowed through, when 'this' is
    // released it would be deleted again.
    //
    // This scenario occurs with DataSources that make history requests. Such
    // DataSources do a history query in |StartDataRequest| and the request is
    // live until the object is deleted (history requests don't up the ref
    // count). This means it's entirely possible for the DataSource to invoke
    // |SendResponse| between the time when there are no more refs and the time
    // when the object is deleted.
    return;
  }
  HostThread::PostTask(
      HostThread::IO, FROM_HERE,
      base::BindOnce(&URLDataSourceImpl::SendResponseOnIOThread, this,
                     request_id, std::move(bytes)));
}

bool URLDataSourceImpl::IsAppDataSourceImpl() const {
  return false;
}

void URLDataSourceImpl::SendResponseOnIOThread(
    int request_id,
    scoped_refptr<base::RefCountedMemory> bytes) {
  DCHECK_CURRENTLY_ON(HostThread::IO);
  if (backend_)
    backend_->DataAvailable(request_id, bytes.get());
}

const ui::TemplateReplacements* URLDataSourceImpl::GetReplacements() const {
  return nullptr;
}

}  // namespace host
