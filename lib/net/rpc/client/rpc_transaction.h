// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_RPC_RPC_TRANSACTION_H_
#define NET_RPC_RPC_TRANSACTION_H_

#include <stdint.h>
#include <memory>

#include "base/threading/thread.h"
#include "base/sequenced_task_runner.h"
#include "base/synchronization/waitable_event.h"
#include "net/base/completion_callback.h"
#include "net/base/load_states.h"
#include "net/base/net_error_details.h"
#include "net/base/net_export.h"
#include "net/base/request_priority.h"
#include "net/base/upload_progress.h"
#include "net/base/request_priority.h"
#include "net/http/http_response_info.h"
#include "net/http/http_raw_request_headers.h"
#include "net/http/http_response_headers.h"
#include "net/socket/connection_attempts.h"
#include "url/gurl.h"

namespace net {
class RpcStream;
class HttpRequestHeaders;
struct RpcRequestInfo;
class HttpResponseInfo;
class IOBuffer;
struct LoadTimingInfo;
class NetLogWithSource;
class ProxyInfo;
class URLRequestContextStorage;
class RpcNetworkSession;
class RpcMessageEncoder;
// this is a HttpTransaction like wrapper around 
// a RpcSingleCaller or RpcContinuousCaller
// the idea is that they have a similar interface
// so in the near future gRpc might be wrapped over
// the traditional HttpNetworkTransaction
// given gRpc use http 2 as its transport layer

// TODO: if transaction gets killed once the request/reply
//       returns, we might create a RpcSession instead
//       so in a 'continuous' stream, the session will
//       outlive the transaction and move accordingly

class NET_EXPORT_PRIVATE RpcTransaction {//: public net::RpcStream::Delegate {
public:
  enum State {
    STATE_NONE = 0,
    STATE_NOTIFY_BEFORE_CREATE_STREAM = 1,
    STATE_CREATE_STREAM = 2,
    STATE_CREATE_STREAM_COMPLETE = 3,
    STATE_SEND_REQUEST = 4,
    STATE_REPLY_RECEIVED = 5,
    STATE_CLOSE_STREAM = 6,
  };

  typedef base::Callback<void(bool* defer)> BeforeNetworkStartCallback;
  typedef base::Callback<void(const ProxyInfo& proxy_info,
                              HttpRequestHeaders* request_headers)>
      BeforeHeadersSentCallback;

  RpcTransaction(RpcNetworkSession* session,
                 const scoped_refptr<base::SequencedTaskRunner>& rpc_task_runner,
                 RequestPriority priority);
  ~RpcTransaction();
  
  int Start(RpcRequestInfo* request_info,
            CompletionCallback callback,
            const NetLogWithSource& net_log);

  const HttpResponseInfo* GetResponseInfo() const;
  bool GetLoadTimingInfo(LoadTimingInfo* load_timing_info) const;
  
  void SetPriority(RequestPriority priority);
  RpcStream* stream() const {
    return stream_.get();
  }

  int64_t GetTotalReceivedBytes() const;
  int64_t GetTotalSentBytes() const;
  int Read(IOBuffer* buf,
           int buf_len,
           CompletionCallback callback);
  void DoneReading();
  void CloseStreamIfNeeded();

  void SetBeforeNetworkStartCallback(BeforeNetworkStartCallback callback);
  void SetBeforeHeadersSentCallback(BeforeHeadersSentCallback callback);
  void SetRequestHeadersCallback(RequestHeadersCallback callback);
  void SetResponseHeadersCallback(ResponseHeadersCallback callback);

private:

  scoped_refptr<net::HttpResponseHeaders> GetHeaders();
  void OnStreamAvailable(Error code, std::unique_ptr<RpcStream> stream);
  void OnStreamReadDataAvailable(int code);
  int NotifyBeforeCreateStream();
  int CreateStream();
  void SendHeadersAndReplyStart(int code);
  void CloseStream();
  
  RpcNetworkSession* session_;
  RpcMessageEncoder* encoder_;
  base::Thread rpc_thread_;
  scoped_refptr<base::SequencedTaskRunner> rpc_task_runner_;
  const RpcRequestInfo* request_info_;
  std::unique_ptr<RpcStream> stream_;
  BeforeNetworkStartCallback before_network_start_callback_;
  BeforeHeadersSentCallback before_headers_sent_callback_;
  RequestHeadersCallback request_headers_callback_;
  ResponseHeadersCallback response_headers_callback_;
  CompletionCallback pending_read_callback_;
  CompletionCallback start_callback_;
  GURL url_;
  RequestPriority priority_;
  HttpResponseInfo response_;
  State state_;
  std::string encoding_;
  int64_t total_received_bytes_;
  int64_t total_sent_bytes_;
  int64_t total_readed_bytes_;
  int64_t content_lenght_;
  bool encoded_;
  bool first_call_;
  bool pending_read_;

  base::WeakPtrFactory<RpcTransaction> weak_factory_;

  DISALLOW_COPY_AND_ASSIGN(RpcTransaction);
};

}

#endif