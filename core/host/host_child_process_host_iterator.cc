// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/host_child_process_host_iterator.h"

#include "base/logging.h"
#include "core/host/host_child_process_host_impl.h"
#include "core/host/host_thread.h"

namespace host {

HostChildProcessHostIterator::HostChildProcessHostIterator()
    : all_(true), process_type_(common::PROCESS_TYPE_UNKNOWN) {
  CHECK(HostThread::CurrentlyOn(HostThread::IO)) <<
      "HostChildProcessHostIterator must be used on the IO thread.";
  iterator_ = HostChildProcessHostImpl::GetIterator()->begin();
}

HostChildProcessHostIterator::HostChildProcessHostIterator(int type)
    : all_(false), process_type_(type) {
  CHECK(HostThread::CurrentlyOn(HostThread::IO)) <<
      "HostChildProcessHostIterator must be used on the IO thread.";
  //DCHECK_NE(PROCESS_TYPE_RENDERER, type) <<
   //   "HostChildProcessHostIterator doesn't work for renderer processes; "
   //   "try RenderProcessHost::AllHostsIterator() instead.";
  iterator_ = HostChildProcessHostImpl::GetIterator()->begin();
  if (!Done() && (*iterator_)->GetData().process_type != process_type_)
    ++(*this);
}

HostChildProcessHostIterator::~HostChildProcessHostIterator() {
}

bool HostChildProcessHostIterator::operator++() {
  CHECK(!Done());
  do {
    ++iterator_;
    if (Done())
      break;

    if (!all_ && (*iterator_)->GetData().process_type != process_type_)
      continue;

    return true;
  } while (true);

  return false;
}

bool HostChildProcessHostIterator::Done() {
  return iterator_ == HostChildProcessHostImpl::GetIterator()->end();
}

const ChildProcessData& HostChildProcessHostIterator::GetData() {
  CHECK(!Done());
  return (*iterator_)->GetData();
}

bool HostChildProcessHostIterator::Send(IPC::Message* message) {
  CHECK(!Done());
  return (*iterator_)->Send(message);
}

HostChildProcessHostDelegate*
    HostChildProcessHostIterator::GetDelegate() {
  return (*iterator_)->delegate();
}

common::ChildProcessHost* HostChildProcessHostIterator::GetHost() {
  CHECK(!Done());
  return (*iterator_)->GetHost();
}

}  // namespace host
