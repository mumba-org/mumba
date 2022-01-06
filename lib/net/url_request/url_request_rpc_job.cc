// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/url_request/url_request_rpc_job.h"

#include <vector>

#include "base/bind.h"
#include "base/compiler_specific.h"
#include "base/location.h"
#include "base/memory/ref_counted_memory.h"
#include "base/single_thread_task_runner.h"
#include "base/strings/string_split.h"
#include "base/strings/string_number_conversions.h"
#include "base/task_scheduler/post_task.h"
#include "base/threading/thread_task_runner_handle.h"
#include "net/base/io_buffer.h"
#include "net/base/net_errors.h"
#include "net/log/net_log.h"
#include "net/http/http_request_headers.h"
#include "net/http/http_util.h"
#include "net/url_request/url_request_status.h"
#include "net/url_request/url_request.h"
#include "net/url_request/url_request_context.h"
#include "net/rpc/client/rpc_transaction.h"
#include "net/url_request/url_request_throttler_manager.h"
#include "net/url_request/url_request_context_storage.h"

namespace net {

namespace {

std::string FormatMethod(const std::string& full_name) {
   std::string method_name;
   auto pos = full_name.find_last_of(".");
   if (pos != std::string::npos) {
     method_name = "/" + full_name.substr(0, pos) + "/" + full_name.substr(pos+1);
     return method_name;
   }
   return full_name;
}

std::string FormatPath(const std::string& input) {
  std::string result;
  base::ReplaceChars(input, "/", ".", &result);
  if (result.size() > 0 && result[0] == '.') {
    result = result.substr(1);
  }
  return result;
}

std::string GetServiceFromPath(const std::string& path) {
  std::string result = path;
  
  size_t start = result.find_first_of(".");
  if (start != std::string::npos) {
    result = result.substr(start+1);
  }
  size_t end = result.find_first_of(".");
  if (end != std::string::npos) {
    result = result.substr(0, end);
  }

  return result;
}

std::string GetMethodFromPath(const std::string& path) {
  std::string result;
  
  size_t start = path.find_last_of(".");

  if (start != std::string::npos) {
    result = path.substr(start+1);
  }

  return result;
}

RpcMethodType GetMethodTypeFromString(const std::string& method) {
  if (method == "NORMAL") {
    return RpcMethodType::kNORMAL;
  } else if (method == "CLIENT_STREAM") { 
    return RpcMethodType::kCLIENT_STREAM;
  } else if (method == "SERVER_STREAM") {
    return RpcMethodType::kSERVER_STREAM;
  } else if (method == "BIDIRECTIONAL") {
    return RpcMethodType::kBIDI_STREAM;
  }
  // unreacheable, but just for the compiler
  return RpcMethodType::kNORMAL;
}

bool CreateKVMapFromURL(const GURL& url, std::map<std::string, std::string>* kvmap) {
  //size_t offset = path.find("?");
  //if (offset != std::string::npos) {
  const url::Parsed& parsed = url.parsed_for_possibly_invalid_spec();
  // there are no params on url
  if (parsed.query.len <= 0) {
    return true;
  }
  int offset = parsed.CountCharactersBefore(url::Parsed::QUERY, false);
  std::string params_str = url.spec().substr(offset);
  std::vector<std::string> params = base::SplitString(params_str, "&", base::TRIM_WHITESPACE, base::SPLIT_WANT_NONEMPTY);
  for (const auto& param : params) {
    std::vector<std::string> kv = base::SplitString(param, "=", base::TRIM_WHITESPACE, base::SPLIT_WANT_ALL);
    if (kv.size() == 1) {
      kvmap->emplace(std::make_pair(kv[0], ""));
    } else if (kv.size() == 2) {
      kvmap->emplace(std::make_pair(kv[0], kv[1]));
    } else {
      DLOG(ERROR) << "invalid key-value separator in '" << param << "'";
    }
  }
  return true;
}

}

URLRequestRpcJob::URLRequestRpcJob(const scoped_refptr<base::SequencedTaskRunner>& rpc_task_runner,
                                   URLRequest* request,
                                   NetworkDelegate* network_delegate)
    : URLRequestJob(request, network_delegate),
      rpc_task_runner_(rpc_task_runner),
      priority_(DEFAULT_PRIORITY),
      done_(false),
      awaiting_callback_(false),
      read_in_progress_(false),
      total_received_bytes_from_previous_transactions_(0),
      total_sent_bytes_from_previous_transactions_(0),
      response_info_(nullptr),
      weak_factory_(this) {
  URLRequestThrottlerManager* manager = request->context()->throttler_manager();
  if (manager)
    throttling_entry_ = manager->RegisterRequestUrl(request->url());

  ResetTimer();
}

URLRequestRpcJob::~URLRequestRpcJob() {
  //DoneWithRequest(ABORTED);
}

void URLRequestRpcJob::Start() {
  DCHECK(!transaction_.get());
  GURL referrer(request_->referrer());

  request_info_.url = request_->url();
  std::string path = FormatPath(request_->url().path());
  request_info_.method_type = GetMethodTypeFromString(request_->method());
  request_info_.fullname = FormatMethod(path);
  request_info_.service = GetServiceFromPath(path);
  request_info_.method = GetMethodFromPath(path);
  request_info_.load_flags = request_->load_flags();
  request_info_.extra_headers = request_->extra_request_headers();

  CreateKVMapFromURL(request_info_.url, &request_info_.input_params);

  //request_info_.traffic_annotation =
  //    net::MutableNetworkTrafficAnnotationTag(request_->traffic_annotation());
  //request_info_.socket_tag = request_->socket_tag();
  //request_info_.token_binding_referrer = request_->token_binding_referrer();

  StartTransaction();
}

void URLRequestRpcJob::StartTransaction() {
  if (network_delegate()) {
    OnCallToDelegate();
    // The NetworkDelegate must watch for OnRequestDestroyed and not modify
    // |extra_headers| or invoke the callback after it's called. Not using a
    // WeakPtr here because it's not enough, the consumer has to watch for
    // destruction regardless, due to the headers parameter.
    int rv = network_delegate()->NotifyBeforeStartTransaction(
        request_,
        base::Bind(&URLRequestRpcJob::NotifyBeforeStartTransactionCallback,
                   base::Unretained(this)),
        &request_info_.extra_headers);
    // If an extension blocks the request, we rely on the callback to
    // MaybeStartTransactionInternal().
    if (rv == ERR_IO_PENDING)
      return;
  }
  StartTransactionInternal(OK);
}

void URLRequestRpcJob::NotifyBeforeStartTransactionCallback(int result) {
  //DLOG(INFO) << "URLRequestRpcJob::NotifyBeforeStartTransactionCallback";
  // Check that there are no callbacks to already canceled requests.
  DCHECK_NE(URLRequestStatus::CANCELED, GetStatus().status());

  StartTransactionInternal(result);
}

void URLRequestRpcJob::StartTransactionInternal(int result) {
  int rv = OK;
  OnCallToDelegateComplete();
  transaction_.reset(new RpcTransaction(
    request()->context()->rpc_network_session(),
    rpc_task_runner_,
    MEDIUM));
  
  transaction_->SetBeforeHeadersSentCallback(
      base::Bind(&URLRequestRpcJob::NotifyBeforeSendHeadersCallback,
                  base::Unretained(this)));
  transaction_->SetRequestHeadersCallback(request_headers_callback_);
  transaction_->SetResponseHeadersCallback(response_headers_callback_);

  if (!throttling_entry_.get() ||
      !throttling_entry_->ShouldRejectRequest(*request_)) {
    rv = transaction_->Start(
        &request_info_, base::Bind(&URLRequestRpcJob::OnStartCompleted,
                                    base::Unretained(this)),
        request_->net_log());
    start_time_ = base::TimeTicks::Now();
  } else {
    // Special error code for the exponential back-off module.
    rv = ERR_TEMPORARILY_THROTTLED;
  }

  if (rv == ERR_IO_PENDING)
    return;

  // The transaction started synchronously, but we need to notify the
  // URLRequest delegate via the message loop.
  base::ThreadTaskRunnerHandle::Get()->PostTask(
      FROM_HERE, base::Bind(&URLRequestRpcJob::OnStartCompleted,
                            weak_factory_.GetWeakPtr(), rv));
}

// HostPortPair URLRequestRpcJob::GetSocketAddress() const {

// }

void URLRequestRpcJob::SetPriority(RequestPriority priority) {
  priority_ = priority;
}

void URLRequestRpcJob::Kill() {
  //DLOG(INFO) << "URLRequestRpcJob::Kill";
  weak_factory_.InvalidateWeakPtrs();
  if (transaction_) {
    DestroyTransaction();
  }
  URLRequestJob::Kill();
}

void URLRequestRpcJob::SetUpload(UploadDataStream* upload) {

}

void URLRequestRpcJob::SetExtraRequestHeaders(const HttpRequestHeaders& headers) {
  //DLOG(INFO) << "URLRequestRpcJob::SetExtraRequestHeaders: NOT IMPLEMENTED";
}

LoadState URLRequestRpcJob::GetLoadState() const {
 DLOG(INFO) << "URLRequestRpcJob::GetLoadState: NOT IMPLEMENTED";
  /*
    LOAD_STATE_IDLE
    LOAD_STATE_CONNECTING
    LOAD_STATE_SENDING_REQUEST
    LOAD_STATE_WAITING_FOR_RESPONSE
    LOAD_STATE_READING_RESPONSE
  */
  return LOAD_STATE_IDLE;
}

bool URLRequestRpcJob::GetMimeType(std::string* mime_type) const {
  //DLOG(INFO) << "URLRequestRpcJob::GetMimeType";
  DCHECK(transaction_.get());

  if (!response_info_)
    return false;

  HttpResponseHeaders* headers = GetResponseHeaders();
  if (!headers)
    return false;

  bool r = headers->GetMimeType(mime_type);
  //DLOG(INFO) << "URLRequestRpcJob::GetMimeType: " << *mime_type;
  return r;
}

bool URLRequestRpcJob::GetCharset(std::string* charset) {
  //DLOG(INFO) << "URLRequestRpcJob::GetCharset";
  
  DCHECK(transaction_.get());

  if (!response_info_)
    return false;

  bool r = GetResponseHeaders()->GetCharset(charset);
  //DLOG(INFO) << "URLRequestRpcJob::GetCharset: " << *charset;
  return r;
}

void URLRequestRpcJob::GetResponseInfo(HttpResponseInfo* info) {
  //DLOG(INFO) << "URLRequestRpcJob::GetResponseInfo";
  if (response_info_) {
    DCHECK(transaction_.get());

    *info = *response_info_;
    if (override_response_headers_.get())
      info->headers = override_response_headers_;
  }
}

void URLRequestRpcJob::GetLoadTimingInfo(LoadTimingInfo* load_timing_info) const {
  if (!transaction_ || receive_headers_end_.is_null())
    return;
  if (transaction_->GetLoadTimingInfo(load_timing_info))
    load_timing_info->receive_headers_end = receive_headers_end_;
}

bool URLRequestRpcJob::GetRemoteEndpoint(IPEndPoint* endpoint) const {
  return false;
}

int URLRequestRpcJob::GetResponseCode() const {
  DLOG(INFO) << "URLRequestRpcJob::GetResponseCode: ALWAYS RETURNING 200. FIX!"; 
  return 200;
}

void URLRequestRpcJob::PopulateNetErrorDetails(NetErrorDetails* details) const {

}

bool URLRequestRpcJob::CopyFragmentOnRedirect(const GURL& location) const {
  return false;
}

bool URLRequestRpcJob::IsSafeRedirect(const GURL& location) {
  return false;
}

bool URLRequestRpcJob::NeedsAuth() {
  return false;
}

void URLRequestRpcJob::GetAuthChallengeInfo(scoped_refptr<AuthChallengeInfo>*) {

}

void URLRequestRpcJob::SetAuth(const AuthCredentials& credentials) {

}

void URLRequestRpcJob::CancelAuth() {

}

void URLRequestRpcJob::ContinueWithCertificate(
    scoped_refptr<X509Certificate> client_cert,
    scoped_refptr<SSLPrivateKey> client_private_key) {

}

void URLRequestRpcJob::ContinueDespiteLastError() {

}

int URLRequestRpcJob::ReadRawData(IOBuffer* buf, int buf_size) {
  //DLOG(INFO) << "URLRequestRpcJob::ReadRawData";
  if (!transaction_) {
    //DLOG(INFO) << "URLRequestRpcJob::ReadRawData: transaction_ is gone. returning ERR_FAILED";
    return ERR_FAILED;
  }
  int rv = transaction_->Read(
      buf, buf_size,
      base::Bind(&URLRequestRpcJob::OnReadCompleted, base::Unretained(this)));

  //DLOG(INFO) << "URLRequestRpcJob::ReadRawData: transaction_->Read() => " << rv;
  if (rv == 0 || (rv < 0 && rv != ERR_IO_PENDING)) {
    //DLOG(INFO) << "URLRequestRpcJob::ReadRawData: DoneWithRequest(FINISHED)";
    DoneWithRequest(FINISHED);
  }

  if (rv == ERR_IO_PENDING) {
    //DLOG(INFO) << "URLRequestRpcJob::ReadRawData: read_in_progress_ = true";
    read_in_progress_ = true;
  }

  //DLOG(INFO) << "URLRequestRpcJob::ReadRawData: return rv = " << rv;
  return rv;
}

void URLRequestRpcJob::StopCaching() {

}

bool URLRequestRpcJob::GetFullRequestHeaders(HttpRequestHeaders* headers) const {
  //DLOG(INFO) << "URLRequestRpcJob::GetFullRequestHeaders";
  return false;
}

int64_t URLRequestRpcJob::GetTotalReceivedBytes() const {
  //DLOG(INFO) << "URLRequestRpcJob::GetTotalReceivedBytes";
  int64_t total_received_bytes =
      total_received_bytes_from_previous_transactions_;
  if (transaction_)
    total_received_bytes += transaction_->GetTotalReceivedBytes();
  //DLOG(INFO) << "URLRequestRpcJob::GetTotalReceivedBytes: " << total_received_bytes;
  return total_received_bytes;
}

int64_t URLRequestRpcJob::GetTotalSentBytes() const {
  //DLOG(INFO) << "URLRequestRpcJob::GetTotalSentBytes";
  int64_t total_sent_bytes =
      total_sent_bytes_from_previous_transactions_;
  if (transaction_)
    total_sent_bytes += transaction_->GetTotalSentBytes();
  //DLOG(INFO) << "URLRequestRpcJob::GetTotalSentBytes: " << total_sent_bytes;
  return total_sent_bytes;
}

void URLRequestRpcJob::DoneReading() {
  //DLOG(INFO) << "URLRequestRpcJob::DoneReading";
  if (transaction_) {
    transaction_->DoneReading();
  }
  DoneWithRequest(FINISHED);
}

void URLRequestRpcJob::DoneReadingRedirectResponse() {
  //DLOG(INFO) << "URLRequestRpcJob::DoneReadingRedirectResponse";
}

//void URLRequestRpcJob::OnCallReply() {
//  response_headers_ = new net::HttpResponseHeaders("HTTP/1.1 200 OK");
//}

void URLRequestRpcJob::ResetTimer() {
  if (!request_creation_time_.is_null()) {
    NOTREACHED()
        << "The timer was reset before it was recorded.";
    return;
  }
  request_creation_time_ = base::Time::Now();
}

void URLRequestRpcJob::DoneWithRequest(CompletionCause reason) {
 // DLOG(INFO) << "URLRequestRpcJob::DoneWithRequest";

  if (done_) {
    //DLOG(INFO) << "URLRequestRpcJob::DoneWithRequest: done_ already = true. cancelling";
    return;
  }

  done_ = true;
  //DLOG(INFO) << "URLRequestRpcJob::DoneWithRequest: request()->set_received_response_content_length()";
  request()->set_received_response_content_length(transaction_->GetTotalReceivedBytes());//prefilter_bytes_read());
  //DLOG(INFO) << "URLRequestRpcJob::DoneWithRequest: DestroyTransaction()";
  DestroyTransaction();
  //DLOG(INFO) << "URLRequestRpcJob::DoneWithRequest END";
}

void URLRequestRpcJob::NotifyBeforeSendHeadersCallback(
    const ProxyInfo& proxy_info,
    HttpRequestHeaders* request_headers) {
  //DLOG(INFO) << "URLRequestRpcJob::NotifyBeforeSendHeadersCallback";
  if (network_delegate()) {
    network_delegate()->NotifyBeforeSendHeaders(
        request_, proxy_info,
        request_->context()->proxy_resolution_service()->proxy_retry_info(),
        request_headers);
  }
}

void URLRequestRpcJob::OnStartCompleted(int result) {
  //DLOG(INFO) << "URLRequestRpcJob::OnStartCompleted: " << result;
  RecordTimer();

  // If the job is done (due to cancellation), can just ignore this
  // notification.
  if (done_) {
    return;
  }

  receive_headers_end_ = base::TimeTicks::Now();
  if (result == OK) {
    scoped_refptr<HttpResponseHeaders> headers = GetResponseHeaders();

    if (network_delegate()) {
      // Note that |this| may not be deleted until
      // |URLRequestRpcJob::OnHeadersReceivedCallback()| or
      // |NetworkDelegate::URLRequestDestroyed()| has been called.
      OnCallToDelegate();
      allowed_unsafe_redirect_url_ = GURL();
      // The NetworkDelegate must watch for OnRequestDestroyed and not modify
      // any of the arguments or invoke the callback after it's called. Not
      // using a WeakPtr here because it's not enough, the consumer has to watch
      // for destruction regardless, due to the pointer parameters.
      int error = network_delegate()->NotifyHeadersReceived(
          request_, base::Bind(&URLRequestRpcJob::OnHeadersReceivedCallback,
                               base::Unretained(this)),
          headers.get(), &override_response_headers_,
          &allowed_unsafe_redirect_url_);
      if (error != OK) {
        if (error == ERR_IO_PENDING) {
          awaiting_callback_ = true;
        } else {
          std::string source("delegate");
          request_->net_log().AddEvent(
              NetLogEventType::CANCELLED,
              NetLog::StringCallback("source", &source));
          OnCallToDelegateComplete();
          NotifyStartError(URLRequestStatus(URLRequestStatus::FAILED, error));
        }
        return;
      }
    }
    NotifyHeadersComplete();
  } else {
    // Even on an error, there may be useful information in the response
    // info (e.g. whether there's a cached copy).
    if (transaction_.get()) {
      response_info_ = transaction_->GetResponseInfo();
    }
    if (transaction_) {
      DestroyTransaction();
    }
    NotifyStartError(URLRequestStatus(URLRequestStatus::FAILED, result));
    // mumba: force Kill after this point given its an error..
    // and url_request wont call Kill() giving is_pending == false
    // after the former notification
  }
}

void URLRequestRpcJob::NotifyHeadersComplete() {
  //DLOG(INFO) << "URLRequestRpcJob::NotifyHeadersComplete";    
  DCHECK(!response_info_);

  OnCallToDelegateComplete();

  response_info_ = transaction_->GetResponseInfo();

  if (throttling_entry_.get()) {
    throttling_entry_->UpdateWithResponse(GetResponseCode());
  }

  URLRequestJob::NotifyHeadersComplete();
}

void URLRequestRpcJob::SetRequestHeadersCallback(
    RequestHeadersCallback callback) {
  //DLOG(INFO) << "URLRequestRpcJob::SetRequestHeadersCallback";
  DCHECK(!transaction_);
  DCHECK(!request_headers_callback_);
  request_headers_callback_ = std::move(callback);
}

void URLRequestRpcJob::SetResponseHeadersCallback(
    ResponseHeadersCallback callback) {
  //DLOG(INFO) << "URLRequestRpcJob::SetResponseHeadersCallback";
  DCHECK(!transaction_);
  DCHECK(!response_headers_callback_);
  response_headers_callback_ = std::move(callback);
}

void URLRequestRpcJob::RecordTimer() {
  if (request_creation_time_.is_null()) {
    NOTREACHED()
        << "The same transaction shouldn't start twice without new timing.";
    return;
  }

  request_creation_time_ = base::Time();
}

HttpResponseHeaders* URLRequestRpcJob::GetResponseHeaders() const {
  //DLOG(INFO) << "URLRequestRpcJob::GetResponseHeaders";
  DCHECK(transaction_.get());
  DCHECK(transaction_->GetResponseInfo());
  return transaction_->GetResponseInfo()->headers.get();
}

void URLRequestRpcJob::OnHeadersReceivedCallback(int result) {
  //DLOG(INFO) << "URLRequestRpcJob::OnHeadersReceivedCallback";
  
  awaiting_callback_ = false;

  // Check that there are no callbacks to already canceled requests.
  //DCHECK_NE(URLRequestStatus::CANCELED, GetStatus().status());

  NotifyHeadersComplete();
}

void URLRequestRpcJob::OnReadCompleted(int result) {
  //DLOG(INFO) << "URLRequestRpcJob::OnReadCompleted: " << result;
  
  read_in_progress_ = false;

  DCHECK_NE(ERR_IO_PENDING, result);

  // EOF or error, done with this job.
  if (result <= 0)
    DoneWithRequest(FINISHED);

  ReadRawDataComplete(result);
}

void URLRequestRpcJob::DestroyTransaction() {
  //DLOG(INFO) << "URLRequestRpcJob::DestroyTransaction";
  if (transaction_) {
    total_received_bytes_from_previous_transactions_ +=
      transaction_->GetTotalReceivedBytes();
    total_sent_bytes_from_previous_transactions_ +=
      transaction_->GetTotalSentBytes();
    //DLOG(INFO) << "URLRequestRpcJob::DestroyTransaction: transaction_->CloseStreamIfNeeded()";
    transaction_->CloseStreamIfNeeded();
    response_info_ = nullptr;
    override_response_headers_ = nullptr;
    receive_headers_end_ = base::TimeTicks();
    //DLOG(INFO) << "URLRequestRpcJob::DestroyTransaction: OnSafeTransactionDestroy()";
    OnSafeTransactionDestroy();
  }
  //DLOG(INFO) << "URLRequestRpcJob::DestroyTransaction END";
}

void URLRequestRpcJob::OnSafeTransactionDestroy() {
  //DLOG(INFO) << "URLRequestRpcJob::OnSafeTransactionDestroy";
  transaction_.reset();
  //DLOG(INFO) << "URLRequestRpcJob::OnSafeTransactionDestroy END";
}

}  // namespace net
