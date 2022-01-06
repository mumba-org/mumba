// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_NET_PEER_HOST_CONTEXT_H_
#define MUMBA_HOST_NET_PEER_HOST_CONTEXT_H_

#include "base/macros.h"
#include "base/single_thread_task_runner.h"
#include "net/base/url_util.h"
#include "core/host/net/auto_thread.h"
#include "core/host/net/rsa_key_pair.h"

namespace base {
class SingleThreadTaskRunner;
}  // namespace base

namespace net {
class URLRequestContextGetter;
}  // namespace net

namespace host {

class PeerHostContext {
public:
  static std::unique_ptr<PeerHostContext> Create(
    scoped_refptr<base::SingleThreadTaskRunner> io_task_runner,
    scoped_refptr<base::SingleThreadTaskRunner> ui_task_runner);

  static std::unique_ptr<PeerHostContext> Create(
    scoped_refptr<net::URLRequestContextGetter> url_request_context_getter,
    scoped_refptr<base::SingleThreadTaskRunner> io_task_runner,
    scoped_refptr<base::SingleThreadTaskRunner> ui_task_runner,
    scoped_refptr<base::SingleThreadTaskRunner> file_task_runner);

  PeerHostContext(
    scoped_refptr<AutoThreadTaskRunner> ui_task_runner,
    scoped_refptr<AutoThreadTaskRunner> network_task_runner,
    scoped_refptr<AutoThreadTaskRunner> file_task_runner,
    scoped_refptr<net::URLRequestContextGetter> url_request_context_getter);
  
  ~PeerHostContext();

    // Task runner for the thread that is used for the UI.
  scoped_refptr<AutoThreadTaskRunner> ui_task_runner() const;

  // Task runner for the thread used for network IO. This thread runs
  // a libjingle message loop, and is the only thread on which
  // libjingle code may be run.
  scoped_refptr<AutoThreadTaskRunner> network_task_runner() const;

  scoped_refptr<AutoThreadTaskRunner> file_task_runner() const;

  scoped_refptr<net::URLRequestContextGetter> url_request_context_getter() const;

private:
  scoped_refptr<AutoThreadTaskRunner> ui_task_runner_;
  scoped_refptr<AutoThreadTaskRunner> network_task_runner_;
  scoped_refptr<AutoThreadTaskRunner> file_task_runner_;

  scoped_refptr<net::URLRequestContextGetter> url_request_context_getter_;

  DISALLOW_COPY_AND_ASSIGN(PeerHostContext);
};

}

#endif