// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/rpc/client/rpc_transaction.h"

#include "base/bind.h"
#include "base/compiler_specific.h"
#include "base/location.h"
#include "base/memory/ref_counted_memory.h"
#include "base/strings/string_number_conversions.h"
#include "base/single_thread_task_runner.h"
#include "base/strings/string_split.h"
#include "base/strings/string_util.h"
#include "base/task_scheduler/post_task.h"
#include "base/threading/thread_task_runner_handle.h"
#include "base/sequenced_task_runner.h"
#include "net/base/io_buffer.h"
#include "net/base/net_errors.h"
#include "net/http/http_request_headers.h"
#include "net/http/http_util.h"
#include "net/url_request/url_request_status.h"
#include "net/url_request/url_request_context.h"
#include "net/url_request/url_request_context_storage.h"
#include "net/rpc/rpc_service_method.h"
#include "net/rpc/client/rpc_stream.h"
#include "net/rpc/client/rpc_unidirectional_stream.h"
#include "net/rpc/client/rpc_bidirectional_stream.h"
#include "net/rpc/rpc_network_session.h"
#include "net/rpc/rpc_request_info.h"
#include "net/base/mime_util.h"

namespace net {

namespace {

const char kChromeURLContentSecurityPolicyHeaderBase[] =
    "Content-Security-Policy: ";
//const char kChromeURLXFrameOptionsHeader[] = "X-Frame-Options: DENY";
// rpc flags/headers

// OUTPUT HEADERS

// "grpc" in our case
const char kMumbaRpcServiceType[] = "Rpc-Service-Type: ";
// the service name
const char kMumbaRpcServiceName[] = "Rpc-Service-Name: ";
// host name
const char kMumbaRpcServiceHost[] = "Rpc-Service-Host: ";
// tcp port
const char kMumbaRpcServicePort[] = "Rpc-Service-Port: ";
// transport
const char kMumbaRpcServiceTransport[] = "Rpc-Service-Transport: ";
// the full service-method url
const char kMumbaRpcServiceMethodURL[] = "Rpc-Service-Method-Url: ";
// the service-method type (normal, server-stream, client-stream or bidi-stream)
const char kMumbaRpcServiceMethodType[] = "Rpc-Service-Method-Type: ";
// encoding, basically 'protobuf-grpc'
const char kMumbaRpcMessageEncodingHeader[] = "Rpc-Message-Encoding: ";

// the method output type name
const char kMumbaRpcServiceMethodOutput[] = "Rpc-Service-Method-Output: ";

// // TODO: use StringPiece here for efficiency
// bool CreateKVMapFromPath(const GURL& url, std::map<std::string, std::string>* kvmap) {
//   //size_t offset = path.find("?");
//   //if (offset != std::string::npos) {
//   const url::Parsed& parsed = url.parsed_for_possibly_invalid_spec();
//   // there are no params on url
//   if (parsed.query.len <= 0) {
//     return true;
//   }
//   int offset = parsed.CountCharactersBefore(url::Parsed::QUERY, false);
//   std::string params_str = url.spec().substr(offset);
//   std::vector<std::string> params = base::SplitString(params_str, "&", base::TRIM_WHITESPACE, base::SPLIT_WANT_NONEMPTY);
//   for (const auto& param : params) {
//     std::vector<std::string> kv = base::SplitString(param, "=", base::TRIM_WHITESPACE, base::SPLIT_WANT_ALL);
//     if (kv.size() == 1) {
//       kvmap->emplace(std::make_pair(kv[0], ""));
//     } else if (kv.size() == 2) {
//       kvmap->emplace(std::make_pair(kv[0], kv[1]));
//     } else {
//       DLOG(ERROR) << "invalid key-value separator in '" << param << "'";
//     }
//   }
//   return true;
// }

}

RpcTransaction::RpcTransaction(RpcNetworkSession* session,
                               const scoped_refptr<base::SequencedTaskRunner>& rpc_task_runner,
                               RequestPriority priority):
  session_(session),
  encoder_(nullptr),
  rpc_thread_("RpcContinuationThread"),
  //rpc_task_runner_(rpc_task_runner),
  request_info_(nullptr),
  priority_(priority),
  state_(STATE_NONE),
  encoding_("protobuf"),
  total_received_bytes_(0),
  total_sent_bytes_(0),
  total_readed_bytes_(0),
  content_lenght_(0),
  encoded_(true),
  first_call_(true),
  pending_read_(false),
  weak_factory_(this) {
  
  base::Thread::Options options;
  options.message_loop_type = base::MessageLoop::TYPE_IO;
  rpc_thread_.StartWithOptions(options);
  rpc_task_runner_ = rpc_thread_.task_runner();

}

RpcTransaction::~RpcTransaction() {
  //DLOG(INFO) << "~RpcTransaction";
  base::ScopedAllowBlockingForTesting allow;
  
  rpc_thread_.Stop();

  if (stream_ && !stream_->was_cleanly_shutdown()) {
    CloseStream();
  }
}

const HttpResponseInfo* RpcTransaction::GetResponseInfo() const {
  return &response_;
}

bool RpcTransaction::GetLoadTimingInfo(
    LoadTimingInfo* load_timing_info) const {
  //if (!stream_ || !stream_->GetLoadTimingInfo(load_timing_info))
  //  return false;

  // load_timing_info->proxy_resolve_start =
  //     proxy_info_.proxy_resolve_start_time();
  // load_timing_info->proxy_resolve_end = proxy_info_.proxy_resolve_end_time();
  // load_timing_info->send_start = send_start_time_;
  // load_timing_info->send_end = send_end_time_;
  //return true;
  return false;
}

int RpcTransaction::Start(
  RpcRequestInfo* request_info,
  CompletionCallback callback,
  const NetLogWithSource& net_log) {
  
  start_callback_ = std::move(callback);
  
  // DLOG(INFO) << "RpcTransaction::Start:\n" << 
  //     " url: " << request_info->url <<
  //     "\n fullname: " << request_info->fullname << 
  //     "\n service: " << request_info->service << 
  //     "\n method: " << request_info->method << 
  //     "\n headers: " << request_info->extra_headers.ToString();

  // TODO: 
  // The ideal:
  // know if its single ou continuous(bidi)

  if (!request_info->url.has_host()) {
    DLOG(ERROR) << "RpcTransaction::Start: url '" << request_info->url.host() << "' dont have a host";
    return ERR_FAILED;
  }

  if (!request_info->url.has_port()) {
    DLOG(ERROR) << "RpcTransaction::Start: url '" << request_info->url << "' dont have a port";
    return ERR_FAILED; 
  }

  if (!request_info->url.has_path()) {
    DLOG(ERROR) << "RpcTransaction::Start: url '" << request_info->url << "' dont have path";
    return ERR_FAILED; 
  }

  encoder_ = session_->GetEncoder(request_info->service, request_info->method);
  if (!encoder_) {
    DLOG(ERROR) << "RpcTransaction::Start: url '" << request_info->url << "' dont have encoder";
    return ERR_FAILED;
  }

  if (!encoder_->EncodeArguments(request_info->service, request_info->method, request_info->input_params, &request_info->encoded_input_params)) {
    DLOG(ERROR) << "RpcTransaction::Start: url '" << request_info->url << "' failed to encode arguments";
    return ERR_FAILED;
  }

  // DLOG(INFO) << "calling " << request_info->url.host() << 
  //   " " << request_info->url.port() << 
  //   " " << request_info->fullname;

  state_ = STATE_NOTIFY_BEFORE_CREATE_STREAM;
  request_info_ = request_info;
  int rv = NotifyBeforeCreateStream();
  return rv;
}

void RpcTransaction::SetPriority(RequestPriority priority) {
  priority_ = priority;
}

int64_t RpcTransaction::GetTotalReceivedBytes() const {
  return total_received_bytes_;
}

int64_t RpcTransaction::GetTotalSentBytes() const {
  return total_sent_bytes_;
}

void RpcTransaction::SetBeforeNetworkStartCallback(BeforeNetworkStartCallback callback) {
  before_network_start_callback_ = callback;
}

void RpcTransaction::SetBeforeHeadersSentCallback(BeforeHeadersSentCallback callback) {
  before_headers_sent_callback_ = callback;
}

void RpcTransaction::SetRequestHeadersCallback(RequestHeadersCallback callback) {
  request_headers_callback_ = std::move(callback);
}

void RpcTransaction::SetResponseHeadersCallback(ResponseHeadersCallback callback) {
  response_headers_callback_ = std::move(callback);
}

int RpcTransaction::NotifyBeforeCreateStream() {
  state_ = STATE_CREATE_STREAM;
  bool defer = false;
  if (!before_network_start_callback_.is_null())
    before_network_start_callback_.Run(&defer);
  if (!defer) {
    return CreateStream();
  }
  return ERR_IO_PENDING;
}

int RpcTransaction::CreateStream() {
  if (request_info_->method_type == RpcMethodType::kNORMAL) {
    //DLOG(INFO) << "CreateHttpUnidirectionalStream";
    session_->CreateHttpUnidirectionalStream(
      request_info_->url.host(),
      request_info_->url.port(),
      request_info_->fullname, 
      request_info_->encoded_input_params, 
      rpc_task_runner_,
      base::Bind(&RpcTransaction::OnStreamAvailable,
        base::Unretained(this)));
  } else {
    //DLOG(INFO) << "CreateHttpBidirectionalStream";
    session_->CreateHttpBidirectionalStream(
      request_info_->url.host(),
      request_info_->url.port(),
      request_info_->fullname, 
      request_info_->encoded_input_params, 
      rpc_task_runner_,
      request_info_->method_type,
      base::Bind(&RpcTransaction::OnStreamAvailable,
        base::Unretained(this)));
  }
  return ERR_IO_PENDING;
}

int RpcTransaction::Read(IOBuffer* buf,
                         int buf_len,
                         CompletionCallback callback) {
  //if (!stream_->DataAvailable()) {
 //DLOG(INFO) << "RpcTransaction::Read";
  //  return OK;
  //}
  int readed = stream_->Read(buf, buf_len);
  total_readed_bytes_ += readed;
  if (readed == ERR_IO_PENDING) {
 //   DLOG(INFO) << "RpcTransaction::Read: readed = ERR_IO_PENDING";
    pending_read_ = true;
    pending_read_callback_ = std::move(callback);
  } else {
 //   DLOG(INFO) << "RpcTransaction::Read: readed = " << readed;
    pending_read_ = false;
  }
  return readed;
}

void RpcTransaction::DoneReading() {
  DLOG(INFO) << "RpcTransaction::DoneReading";
}

void RpcTransaction::CloseStreamIfNeeded() {
  // FIXME: check if is keepalive.. also if single or continuous call
  if (stream_) {
    CloseStream();
  }
}

scoped_refptr<net::HttpResponseHeaders> RpcTransaction::GetHeaders() {
  scoped_refptr<net::HttpResponseHeaders> headers = new net::HttpResponseHeaders("HTTP/1.1 200 OK");
  //std::string mime_type = "text/html";//GetMimeType(scheme, path);
  std::string mime_type;
  request_info_->extra_headers.GetHeader("mime-type", &mime_type);

  //std::string mime_type = GetMimeType(request_info_->url);//scheme, path);

  ////DLOG(INFO) << "RpcTransaction::GetHeaders: mime_type = " << mime_type;
  //if (ShouldServeMimeTypeAsContentTypeHeader() && !mime_type.empty()) {
  //  std::string content_type = base::StringPrintf(
  //      "%s:%s", net::HttpRequestHeaders::kContentType, mime_type.c_str());
  //  headers->AddHeader(content_type);
  //}
  std::string content_type = base::StringPrintf(
        "%s:%s", net::HttpRequestHeaders::kContentType, mime_type.c_str());
  headers->AddHeader(content_type);
  
  std::string content_length = base::StringPrintf(
        "%s:%s", net::HttpRequestHeaders::kContentLength, base::NumberToString(content_lenght_).c_str());

  headers->AddHeader(content_length);

  // if (!origin.empty()) {
  //   std::string header = GetAccessControlAllowOriginForOrigin(origin);
  //   DCHECK(header.empty() || header == origin || header == "*" ||
  //          header == "null");
  //   if (!header.empty()) {
  //     headers->AddHeader("Access-Control-Allow-Origin: " + header);
  //     headers->AddHeader("Vary: Origin");
  //   }
  // }

  // NOTE: added here. this is fixed, as for now its the only way we are serving
  // those requests. (through Rpc with protobuf encoding)

  // the application clients will act upon seeing this header
  // luckily a customized protobuf decoder will launch and 
  // decode the data back to the IDL designed the developer 
  std::string base = kChromeURLContentSecurityPolicyHeaderBase;
  base.append("script-src chrome://resources 'self' 'unsafe-eval';");
  base.append("object-src 'none';");
  base.append("child-src 'none';");
  //base.append(GetContentSecurityPolicyStyleSrc());
  //base.append(GetContentSecurityPolicyImgSrc());
  headers->AddHeader(base);


  headers->AddHeader(kMumbaRpcServiceType + std::string("grpc"));
  headers->AddHeader(kMumbaRpcServiceName + std::string(request_info_->service));//service->name());
  headers->AddHeader(kMumbaRpcServiceHost + std::string(request_info_->url.host()));//service->host());
  headers->AddHeader(kMumbaRpcServicePort + std::string(request_info_->url.port()));//base::NumberToString(service->port()));
  headers->AddHeader(kMumbaRpcServiceTransport + std::string("HTTP"));//GetTransportTypeName(service->transport_type()));
  
  
  // TODO: see if theres a inexpensive way (eg. how about cache those in the net::RpcService instance?)  
  // const google::protobuf::ServiceDescriptor* service_descr = service->service_descriptor();
  // for (int i = 0; i < service_descr->method_count(); ++i) {
  //   const google::protobuf::MethodDescriptor* method_descr = service_descr->method(i);
  //   if (method_name == base::ToLowerASCII(method_descr->name())) {
  //     headers->AddHeader(kMumbaRpcServiceMethodURL + method_descr->full_name());
  //     headers->AddHeader(kMumbaRpcServiceMethodType + GetMethodTypeName(method_descr));
  //     break;
  //   }
  // }
  const google::protobuf::Descriptor* output_type = encoder_->GetMethodOutputType(request_info_->service, request_info_->method);
  if (output_type) {
    headers->AddHeader(kMumbaRpcServiceMethodOutput + output_type->name());  
  }
  headers->AddHeader(kMumbaRpcServiceMethodURL + request_info_->fullname);//method_descr->full_name());
  headers->AddHeader(kMumbaRpcServiceMethodType + std::string("normal"));//GetMethodTypeName(method_descr));

  // this header is a way to flag, the message is of that kind.
  // TODO: see if theres a better/proper way for this eg. (whats used for gzip for instance)
  // 'protobuf-grpc' -> protobuf with grpc plugins
  if (encoded_ && encoding_ == "protobuf") {
    headers->AddHeader(kMumbaRpcMessageEncodingHeader + std::string("protobuf-grpc"));
  }
  return headers;
}

void RpcTransaction::OnStreamAvailable(Error code, std::unique_ptr<RpcStream> stream) {
  state_ = STATE_CREATE_STREAM_COMPLETE;
  if (code != OK) {
    start_callback_.Run(code);
    return;
  }
  stream_ = std::move(stream);
  // StreamReadDataAvailable
  stream_->BindStreamReadDataAvailable(
    base::Bind(&RpcTransaction::OnStreamReadDataAvailable, 
      weak_factory_.GetWeakPtr()));  
  stream_->Init();
  //RunStreamLoop();
  state_ = STATE_SEND_REQUEST;
}

void RpcTransaction::OnStreamReadDataAvailable(int code) {
  state_ = STATE_REPLY_RECEIVED;
  // fill headers up
  if (code == net::OK) {
    total_sent_bytes_ = stream_->input_length();
    total_received_bytes_ = stream_->output_length();
    //DLOG(INFO) << "RpcTransaction::OnStreamReadDataAvailable:\n" << 
    //  " total_sent_bytes: " << total_sent_bytes_ << "\n" << 
    //  " total_received_bytes: " << total_received_bytes_;
  }

  if (first_call_) {
    //DLOG(INFO) << "RpcTransaction::OnStreamReadDataAvailable: first call => stream_->total_content_length() =" << stream_->total_content_length();
    content_lenght_ = stream_->total_content_length();
    encoded_ = stream_->is_encoded();
    encoding_ = stream_->encoding();
    SendHeadersAndReplyStart(code);
  } else {
    //DLOG(INFO) << "RpcTransaction::OnStreamReadDataAvailable: not first_call";
    if (pending_read_) {
      pending_read_callback_.Run(code);
      //pending_read_ = false;
    } else {
      DCHECK(false);
    }
    //CloseStream();
  }
  //size_t readed = stream_->output_length();
  //stream_->output(), 
  //should_complete
  //EndCall();
}

void RpcTransaction::SendHeadersAndReplyStart(int code) {
  response_.headers = GetHeaders();
  if (!response_headers_callback_.is_null()) {
    response_headers_callback_.Run(response_.headers);
  }

  start_callback_.Run(code);
  first_call_ = false;
  //DLOG(INFO) << "RpcTransaction::SendHeadersAndReplyStart END";
}

void RpcTransaction::CloseStream() {
  if (stream_) {
    state_ = STATE_CLOSE_STREAM;
    session_->RpcStreamFinished(stream_.get());
    stream_->Shutdown();
    //stream_.reset();
  }
}

}