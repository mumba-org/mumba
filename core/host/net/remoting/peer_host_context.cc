// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/net/peer_host_context.h"

#include "base/bind.h"
#include "base/bind_helpers.h"
#include "base/memory/ptr_util.h"
#include "base/message_loop/message_loop.h"
#include "base/single_thread_task_runner.h"
#include "base/threading/thread_restrictions.h"
#include "build/build_config.h"
#include "net/url_request/url_request_context_getter.h"
#include "core/host/net/url_request_context_getter.h"
#include "core/host/net/auto_thread.h"

namespace host {

// static 
std::unique_ptr<PeerHostContext> PeerHostContext::Create(
    scoped_refptr<base::SingleThreadTaskRunner> io_task_runner,
    scoped_refptr<base::SingleThreadTaskRunner> ui_task_runner) {

  scoped_refptr<AutoThreadTaskRunner> io_auto_task_runner =
      new AutoThreadTaskRunner(io_task_runner, base::DoNothing());
  scoped_refptr<AutoThreadTaskRunner> ui_auto_task_runner =
      new AutoThreadTaskRunner(ui_task_runner, base::DoNothing());

  scoped_refptr<AutoThreadTaskRunner> file_auto_task_runner =
    AutoThread::CreateWithType("ChromotingFileThread", ui_auto_task_runner,
      base::MessageLoop::TYPE_IO);

  return base::WrapUnique(
    new PeerHostContext(
      ui_auto_task_runner,
      io_auto_task_runner,
      file_auto_task_runner,
      base::MakeRefCounted<URLRequestContextGetter>(
        io_task_runner,
        file_auto_task_runner->task_runner())));
  
}

// static 
std::unique_ptr<PeerHostContext> PeerHostContext::Create(
    scoped_refptr<net::URLRequestContextGetter> url_request_context_getter,
    scoped_refptr<base::SingleThreadTaskRunner> io_task_runner,
    scoped_refptr<base::SingleThreadTaskRunner> ui_task_runner,
    scoped_refptr<base::SingleThreadTaskRunner> file_task_runner) {

  scoped_refptr<AutoThreadTaskRunner> io_auto_task_runner =
      new AutoThreadTaskRunner(io_task_runner, base::DoNothing());
  scoped_refptr<AutoThreadTaskRunner> ui_auto_task_runner =
      new AutoThreadTaskRunner(ui_task_runner, base::DoNothing());
  scoped_refptr<AutoThreadTaskRunner> file_auto_task_runner =
      new AutoThreadTaskRunner(file_task_runner, base::DoNothing());

  return base::WrapUnique(
    new PeerHostContext(
      ui_auto_task_runner,
      io_auto_task_runner,
      file_auto_task_runner,
      url_request_context_getter));
}

PeerHostContext::PeerHostContext(
    scoped_refptr<AutoThreadTaskRunner> ui_task_runner,
    scoped_refptr<AutoThreadTaskRunner> network_task_runner,
    scoped_refptr<AutoThreadTaskRunner> file_task_runner,
    scoped_refptr<net::URLRequestContextGetter> url_request_context_getter):
   ui_task_runner_(ui_task_runner),
   network_task_runner_(network_task_runner),
   file_task_runner_(file_task_runner),
   url_request_context_getter_(url_request_context_getter) {
  
}

PeerHostContext::~PeerHostContext() {

}

scoped_refptr<AutoThreadTaskRunner> PeerHostContext::ui_task_runner() const {
  return ui_task_runner_;
}

scoped_refptr<AutoThreadTaskRunner> PeerHostContext::network_task_runner() const {
  return network_task_runner_;
}

scoped_refptr<AutoThreadTaskRunner> PeerHostContext::file_task_runner() const {
  return file_task_runner_;
}

scoped_refptr<net::URLRequestContextGetter> PeerHostContext::url_request_context_getter() const {
  return url_request_context_getter_;
}

}