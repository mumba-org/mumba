// Copyright (c) 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_URL_REQUEST_RPC_PROTOCOL_HANDLER_H_
#define NET_URL_REQUEST_RPC_PROTOCOL_HANDLER_H_

#include "base/compiler_specific.h"
#include "base/macros.h"
#include "base/sequenced_task_runner.h"
#include "net/base/net_export.h"
#include "net/url_request/url_request_job_factory.h"

namespace net {
class URLRequestContextStorage;
class URLRequestJob;

// Implements a ProtocolHandler for RPC jobs.
class NET_EXPORT RpcProtocolHandler
    : public URLRequestJobFactory::ProtocolHandler {
 public:
  // RpcProtocolHandler();
  RpcProtocolHandler(scoped_refptr<base::SequencedTaskRunner> rpc_task_runner);
  URLRequestJob* MaybeCreateJob(
      URLRequest* request,
      NetworkDelegate* network_delegate) const override;
  bool IsSafeRedirectTarget(const GURL& location) const override;

 private:
    
    scoped_refptr<base::SequencedTaskRunner> rpc_task_runner_;
    
    DISALLOW_COPY_AND_ASSIGN(RpcProtocolHandler);
};

}  // namespace net

#endif  // NET_URL_REQUEST_RPC_PROTOCOL_HANDLER_H_