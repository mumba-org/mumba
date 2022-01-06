// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/streams/stream_context.h"

#include "base/bind.h"
#include "core/host/streams/stream_registry.h"
#include "core/host/application/domain.h"
#include "core/host/host_thread.h"

//using base::UserDataAdapter;

// namespace {

// const char kStreamContextKeyName[] = "content_stream_context";

// }  // namespace

namespace host {

StreamContext::StreamContext() {}

StreamContext* StreamContext::GetFor(Domain* context) {
  //if (!context->GetUserData(kStreamContextKeyName)) {
  if (!context->GetStreamContext()) {  
    scoped_refptr<StreamContext> stream = new StreamContext();
    context->SetStreamContext(stream);
    //context->SetUserData(
    //    kStreamContextKeyName,
    //    std::make_unique<UserDataAdapter<StreamContext>>(stream.get()));
    // Check first to avoid memory leak in unittests.
    if (HostThread::IsThreadInitialized(HostThread::IO)) {
      HostThread::PostTask(
          HostThread::IO, FROM_HERE,
          base::BindOnce(&StreamContext::InitializeOnIOThread, stream));
    }
  }

  return context->GetStreamContext();//UserDataAdapter<StreamContext>::Get(context, kStreamContextKeyName);
}

void StreamContext::InitializeOnIOThread() {
  DCHECK_CURRENTLY_ON(HostThread::IO);
  registry_.reset(new StreamRegistry());
}

StreamContext::~StreamContext() {}

void StreamContext::DeleteOnCorrectThread() const {
  // In many tests, there isn't a valid IO thread.  In that case, just delete on
  // the current thread.
  // TODO(zork): Remove this custom deleter, and fix the leaks in all the
  // tests.
  if (HostThread::IsThreadInitialized(HostThread::IO) &&
      !HostThread::CurrentlyOn(HostThread::IO)) {
    HostThread::DeleteSoon(HostThread::IO, FROM_HERE, this);
    return;
  }
  delete this;
}

}  // namespace host
