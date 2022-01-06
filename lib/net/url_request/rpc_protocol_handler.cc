// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/url_request/rpc_protocol_handler.h"

#include "base/message_loop/message_loop.h"
#include "base/single_thread_task_runner.h"
#include "base/strings/string_util.h"
#include "base/task_scheduler/post_task.h"
#include "net/url_request/url_request_rpc_job.h"

namespace net {

//RpcProtocolHandler::RpcProtocolHandler() {//:scoped_refptr<base::SequencedTaskRunner> rpc_task_runner):
 //rpc_task_runner_(std::move(rpc_task_runner)) {
//}

RpcProtocolHandler::RpcProtocolHandler(scoped_refptr<base::SequencedTaskRunner> rpc_task_runner):
 rpc_task_runner_(std::move(rpc_task_runner)) {

}

// URLRequestJob* RpcProtocolHandler::MaybeCreateJob(
//     URLRequest* request, NetworkDelegate* network_delegate) const {
//   return new URLRequestRpcJob(
//      base::CreateSequencedTaskRunnerWithTraits(
//        {base::MayBlock(), 
//         base::WithBaseSyncPrimitives(), 
//         base::TaskPriority::USER_BLOCKING,
//         base::TaskShutdownBehavior::SKIP_ON_SHUTDOWN}),
//     request, 
//     network_delegate);
// }

URLRequestJob* RpcProtocolHandler::MaybeCreateJob(
    URLRequest* request, NetworkDelegate* network_delegate) const {
  return new URLRequestRpcJob(rpc_task_runner_, request, network_delegate);
}

bool RpcProtocolHandler::IsSafeRedirectTarget(const GURL& location) const {
  return false;
}

}  // namespace net
