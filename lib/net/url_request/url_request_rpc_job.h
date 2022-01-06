// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_URL_REQUEST_URL_REQUEST_RPC_JOB_H_
#define NET_URL_REQUEST_URL_REQUEST_RPC_JOB_H_

#include <memory>
#include <string>

#include "base/macros.h"
#include "base/memory/weak_ptr.h"
#include "net/base/auth.h"
#include "net/base/net_export.h"
#include "net/rpc/rpc_request_info.h"
#include "net/proxy_resolution/proxy_info.h"
#include "net/proxy_resolution/proxy_resolution_service.h"
#include "net/url_request/url_request_job.h"

namespace net {
class HttpRequestHeaders;
class HttpResponseHeaders;
class HttpResponseInfo;
class RpcTransaction;
class URLRequestContextStorage;
class URLRequestThrottlerEntryInterface;

class NET_EXPORT_PRIVATE URLRequestRpcJob : public URLRequestJob {
public:
  URLRequestRpcJob(const scoped_refptr<base::SequencedTaskRunner>& rpc_task_runner,
                   URLRequest* request,
                   NetworkDelegate* network_delegate);
  ~URLRequestRpcJob() override;

  void SetRequestHeadersCallback(RequestHeadersCallback callback) override;
  void SetResponseHeadersCallback(ResponseHeadersCallback callback) override;

  bool IsSafeRedirect(const GURL& location) override;
  bool GetMimeType(std::string* mime_type) const override;
  void GetResponseInfo(HttpResponseInfo* info) override;
  //HostPortPair GetSocketAddress() const override;
  void SetPriority(RequestPriority priority) override;
  void Start() override;
  void Kill() override;

private:
  enum CompletionCause {
    ABORTED,
    FINISHED
  };
  
  // Overridden from URLRequestJob:
  void SetUpload(UploadDataStream* upload) override;
  void SetExtraRequestHeaders(const HttpRequestHeaders& headers) override;
  LoadState GetLoadState() const override;
  bool GetCharset(std::string* charset) override;
  void GetLoadTimingInfo(LoadTimingInfo* load_timing_info) const override;
  bool GetRemoteEndpoint(IPEndPoint* endpoint) const override;
  int GetResponseCode() const override;
  void PopulateNetErrorDetails(NetErrorDetails* details) const override;
  bool CopyFragmentOnRedirect(const GURL& location) const override;
  bool NeedsAuth() override;
  void GetAuthChallengeInfo(scoped_refptr<AuthChallengeInfo>*) override;
  void SetAuth(const AuthCredentials& credentials) override;
  void CancelAuth() override;
  void ContinueWithCertificate(
      scoped_refptr<X509Certificate> client_cert,
      scoped_refptr<SSLPrivateKey> client_private_key) override;
  void ContinueDespiteLastError() override;
  int ReadRawData(IOBuffer* buf, int buf_size) override;
  void StopCaching() override;
  bool GetFullRequestHeaders(HttpRequestHeaders* headers) const override;
  int64_t GetTotalReceivedBytes() const override;
  int64_t GetTotalSentBytes() const override;
  void DoneReading() override;
  void DoneReadingRedirectResponse() override;
  
  void StartTransaction();
  void ResetTimer();
  void DoneWithRequest(CompletionCause reason);
  void NotifyBeforeStartTransactionCallback(int result);
  void StartTransactionInternal(int result);
  void NotifyBeforeSendHeadersCallback(
    const ProxyInfo& proxy_info,
    HttpRequestHeaders* request_headers);
  void NotifyHeadersComplete();

  void OnStartCompleted(int result);
  void OnHeadersReceivedCallback(int result);
  void OnReadCompleted(int result);

  void RecordTimer();
  HttpResponseHeaders* GetResponseHeaders() const;
  void DestroyTransaction();
  void OnSafeTransactionDestroy();

  const scoped_refptr<base::SequencedTaskRunner>& rpc_task_runner_;
  RequestPriority priority_;
  bool done_;
  bool awaiting_callback_;
  bool read_in_progress_;
  int64_t total_received_bytes_from_previous_transactions_;
  int64_t total_sent_bytes_from_previous_transactions_;
  RpcRequestInfo request_info_;
  GURL allowed_unsafe_redirect_url_;
  const HttpResponseInfo* response_info_;
  scoped_refptr<HttpResponseHeaders> response_headers_;
  scoped_refptr<HttpResponseHeaders> override_response_headers_;
  // This is used to supervise traffic and enforce exponential
  // back-off. May be NULL.
  scoped_refptr<URLRequestThrottlerEntryInterface> throttling_entry_;
  std::unique_ptr<RpcTransaction> transaction_;
  base::Time request_creation_time_;
  base::TimeTicks start_time_;
  base::TimeTicks receive_headers_end_;
  RequestHeadersCallback request_headers_callback_;
  ResponseHeadersCallback response_headers_callback_;

  base::WeakPtrFactory<URLRequestRpcJob> weak_factory_;

  DISALLOW_COPY_AND_ASSIGN(URLRequestRpcJob);
};

}

#endif