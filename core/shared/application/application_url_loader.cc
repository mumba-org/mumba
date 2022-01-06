// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/application/application_url_loader.h"

#define INSIDE_BLINK 1

#include "base/strings/string_number_conversions.h"
#include "core/shared/common/referrer.h"
#include "core/shared/common/request_context_type.h"
#include "core/shared/common/previews_state.h"
#include "core/shared/application/navigation_response_override_parameters.h"
#include "core/shared/application/fixed_received_data.h"
#include "core/shared/application/resource_dispatcher.h"
#include "core/shared/application/shared_memory_data_consumer_handle.h"
#include "net/base/net_errors.h"
#include "net/base/data_url.h"
#include "net/base/filename_util.h"
#include "net/base/load_flags.h"
#include "net/base/net_errors.h"
#include "net/cert/cert_status_flags.h"
#include "net/cert/ct_sct_to_string.h"
#include "net/cert/x509_certificate.h"
#include "net/cert/x509_util.h"
#include "net/http/http_request_headers.h"
#include "net/http/http_response_headers.h"
#include "net/http/http_util.h"
#include "net/ssl/ssl_cipher_suite_names.h"
#include "net/ssl/ssl_connection_status_flags.h"
#include "net/ssl/ssl_info.h"
#include "net/url_request/url_request_data_job.h"
#include "services/network/loader_util.h"
#include "services/network/public/cpp/resource_request_body.h"
#include "services/network/public/mojom/request_context_frame_type.mojom.h"
#include "services/network/public/cpp/features.h"
#include "services/network/public/mojom/data_pipe_getter.mojom.h"
#include "services/network/public/mojom/request_context_frame_type.mojom.h"
#include "services/service_manager/public/cpp/connector.h"
#include "services/service_manager/public/cpp/interface_provider.h"
#include "third_party/blink/public/common/mime_util/mime_util.h"
#include "third_party/blink/public/mojom/blob/blob_registry.mojom.h"
#include "third_party/blink/public/platform/file_path_conversion.h"
#include "third_party/blink/public/platform/interface_provider.h"
#include "third_party/blink/public/platform/modules/fetch/fetch_api_request.mojom-shared.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/web_data.h"
#include "third_party/blink/public/platform/web_http_header_visitor.h"
#include "third_party/blink/public/platform/web_mixed_content.h"
#include "third_party/blink/public/platform/web_string.h"
#include "third_party/blink/public/platform/web_thread.h"
#include "third_party/blink/public/platform/web_url_load_timing.h"
#include "third_party/blink/public/mojom/blob/blob_registry.mojom.h"
#include "third_party/blink/public/platform/web_mixed_content_context_type.h"
#include "third_party/blink/public/platform/web_url_request.h"
#include "third_party/blink/public/platform/web_http_load_info.h"
#include "third_party/blink/public/platform/web_url_request.h"
#include "third_party/blink/public/platform/web_url_response.h"
#include "third_party/blink/public/platform/web_url_loader_client.h"
#include "third_party/blink/public/platform/web_data_consumer_handle.h"
#include "third_party/blink/renderer/platform/network/http_names.h"
#include "third_party/blink/renderer/platform/heap/handle.h"
#include "third_party/blink/renderer/platform/wtf/type_traits.h"
#include "third_party/blink/renderer/platform/weborigin/kurl.h"
#include "core/shared/application/application_window_dispatcher.h"

using HeadersVector = network::HttpRawRequestResponseInfo::HeadersVector;

namespace application {

namespace {

//const char kBodyContent[] = "<html><body><div id=\"head\">hello world</div><div id=\"title\">hey, are you there?</div><div id=\"foot\">goodbye cruel world</div></body></html>";
//const char kBodyContent[] = "hello world";

//const char kBodyContent[] = "<html><head><style>.editing {border: 2px solid red;padding: 12px;font-size: 24px;}</style><title>Autocorrection Cancellation By ESC Test</title></head><body><div><p>This test verifies that autocorrection is not applied when user dismisses correction panel by pressing ESC key.</p><p>After seeing the correction panel, press ESC key, then press space. You should see the phrase \"the collaps\" where \"collaps\" has red mispell underline. </p> <p style=\"color:green\">Note, this test can fail due to user specific spell checking data. If the user has previously dismissed 'collapse' as the correct spelling of 'collaps' several times, the spell checker will not provide 'collapse' as a suggestion anymore. To fix this, remove all files in ~/Library/Spelling.</p><div contenteditable id=\"root\" class=\"editing\"><span id=\"test\"></span></div></body></html>";

//const char kBodyContent[] = "<!DOCTYPE html><html><head><title>Line breaking performance test</title></head><body bgcolor='#990044'><pre id='log'></pre><div id='target' style='width: 250px; color: #00000'><p>Lorem ipsum dolor sit amet, consectetur adipiscing elit. Mauris ut elit lacus, non convallis odio. Integer facilisis, dolor quis porttitor auctor, nisi tellus aliquet urna, a dignissim orci nisl in nunc. Vivamus elit risus, sagittis et lacinia quis, blandit ac elit. Suspendisse non turpis vitae lorem molestie imperdiet sit amet in justo. Pellentesque habitant morbi tristique senectus et netus et malesuada fames ac turpis egestas. In at quam sapien. Nam nunc eros, interdum ut commodo nec, sollicitudin ultrices magna. Mauris eu fringilla massa. Phasellus facilisis augue in lectus luctus scelerisque. Proin quis facilisis lacus. Morbi tempor, mauris vitae posuere scelerisque, turpis massa pulvinar tortor, quis congue dolor eros iaculis elit. Quisque blandit blandit elit, sed suscipit justo scelerisque ut. Aenean sed diam at ligula bibendum rhoncus quis in nunc. Suspendisse semper auctor dui vitae gravida. Fusce et risus in velit ullamcorper placerat. Pellentesque sollicitudin commodo porta. Nam eu enim orci, at euismod ipsum.</p></div></body></html>";

constexpr char kStylesheetAcceptHeader[] = "text/css,*/*;q=0.1";
constexpr char kImageAcceptHeader[] = "image/webp,image/apng,image/*,*/*;q=0.8";

class ReceivedDataImpl : public application::RequestPeer::ReceivedData {
public:
  ReceivedDataImpl():
   payload_(nullptr), length_(0) {}

  ReceivedDataImpl(char* payload, int length):
   payload_(payload), length_(length) {

  }

  ~ReceivedDataImpl() {
    if (payload_) {
      free(payload_);
    }
  }

  const char* payload() const override {
    return payload_;
  } 

  int length() const override {
    return length_;
  }

private:
  char* payload_;
  int length_;
};

class ApplicationResponseHandler : public application::ResponseHandler {
public:
  ApplicationResponseHandler(void* state, CResponseHandler cbs):
   state_(state),
   callbacks_(std::move(cbs)) {
     //DLOG(INFO) << "ApplicationResponseHandler (constructor): calling callbacks_.GetName()";
     name_ = std::string(callbacks_.GetName(state_));
   }

  ~ApplicationResponseHandler() override {}

  const std::string& name() const {
    return name_;
  }

  bool WillHandleResponse(blink::WebURLResponse* response) override {
    //DLOG(INFO) << "ApplicationResponseHandler::WillHandleResponse";
    return callbacks_.WillHandleResponse(state_, response) != 0;
  }

  int OnDataAvailable(const char* input, int input_len) override {
    //DLOG(INFO) << "ApplicationResponseHandler::OnDataAvailable";
    return callbacks_.OnDataAvailable(state_, input, input_len); 
  }

  int OnFinishLoading(int error_code, int total_transfer_size) override {
    //DLOG(INFO) << "ApplicationResponseHandler::OnFinishLoading";
    return callbacks_.OnFinishLoading(state_, error_code, total_transfer_size);
  }

  std::unique_ptr<application::RequestPeer::ReceivedData> GetResult() override {
    //DLOG(INFO) << "ApplicationResponseHandler::GetResult";
    char* data = nullptr;
    int len = 0;
    callbacks_.GetResult(state_, &data, &len);
    return std::make_unique<ReceivedDataImpl>(data, len);
  }

private:
  void* state_;
  CResponseHandler callbacks_;
  std::string name_;

  DISALLOW_COPY_AND_ASSIGN(ApplicationResponseHandler);
};

scoped_refptr<network::ResourceRequestBody> GetRequestBodyForWebHTTPBody(
    const blink::WebHTTPBody& httpBody) {
  scoped_refptr<network::ResourceRequestBody> request_body =
      new network::ResourceRequestBody();
  size_t i = 0;
  blink::WebHTTPBody::Element element;
  while (httpBody.ElementAt(i++, element)) {
    switch (element.type) {
      case blink::WebHTTPBody::Element::kTypeData:
        element.data.ForEachSegment([&request_body](const char* segment,
                                                    size_t segment_size,
                                                    size_t segment_offset) {
          request_body->AppendBytes(segment, static_cast<int>(segment_size));
          return true;
        });
        break;
      case blink::WebHTTPBody::Element::kTypeFile:
        if (element.file_length == -1) {
          request_body->AppendFileRange(
              blink::WebStringToFilePath(element.file_path), 0,
              std::numeric_limits<uint64_t>::max(), base::Time());
        } else {
          request_body->AppendFileRange(
              blink::WebStringToFilePath(element.file_path),
              static_cast<uint64_t>(element.file_start),
              static_cast<uint64_t>(element.file_length),
              base::Time::FromDoubleT(element.modification_time));
        }
        break;
      case blink::WebHTTPBody::Element::kTypeBlob: {
        if (base::FeatureList::IsEnabled(network::features::kNetworkService)) {
          DCHECK(element.optional_blob_handle.is_valid());
          blink::mojom::BlobPtr blob_ptr(
              blink::mojom::BlobPtrInfo(std::move(element.optional_blob_handle),
                                        blink::mojom::Blob::Version_));

          network::mojom::DataPipeGetterPtr data_pipe_getter_ptr;
          blob_ptr->AsDataPipeGetter(MakeRequest(&data_pipe_getter_ptr));

          request_body->AppendDataPipe(std::move(data_pipe_getter_ptr));
        } else {
          request_body->AppendBlob(element.blob_uuid.Utf8());//,
                                   //element.blob_length);
        }
        break;
      }
      case blink::WebHTTPBody::Element::kTypeDataPipe: {
        // Convert the raw message pipe to network::mojom::DataPipeGetterPtr.
        network::mojom::DataPipeGetterPtr data_pipe_getter;
        data_pipe_getter.Bind(network::mojom::DataPipeGetterPtrInfo(
            std::move(element.data_pipe_getter), 0u));

        // Set the cloned DataPipeGetter to the output |request_body|, while
        // keeping the original message pipe back in the input |httpBody|. This
        // way the consumer of the |httpBody| can retrieve the data pipe
        // multiple times (e.g. during redirects) until the request is finished.
        network::mojom::DataPipeGetterPtr cloned_getter;
        data_pipe_getter->Clone(mojo::MakeRequest(&cloned_getter));
        request_body->AppendDataPipe(std::move(cloned_getter));
        element.data_pipe_getter =
            data_pipe_getter.PassInterface().PassHandle();
        break;
      }
    }
  }
  request_body->set_identifier(httpBody.Identifier());
  request_body->set_contains_sensitive_info(httpBody.ContainsPasswordData());
  return request_body;
}

scoped_refptr<network::ResourceRequestBody> GetRequestBodyForWebURLRequest(
    const blink::WebURLRequest& request) {
  scoped_refptr<network::ResourceRequestBody> request_body;

  if (request.HttpBody().IsNull()) {
    return request_body;
  }

  const std::string& method = request.HttpMethod().Latin1();
  // GET and HEAD requests shouldn't have http bodies.
  DCHECK(method != "GET" && method != "HEAD");

  return GetRequestBodyForWebHTTPBody(request.HttpBody());
}

// Converts timing data from |load_timing| to the format used by WebKit.
void PopulateURLLoadTiming(const net::LoadTimingInfo& load_timing,
                           blink::WebURLLoadTiming* url_timing) {
  DCHECK(!load_timing.request_start.is_null());

  url_timing->Initialize();
  url_timing->SetRequestTime(load_timing.request_start.ToInternalValue());
  url_timing->SetProxyStart(load_timing.proxy_resolve_start.ToInternalValue());
  url_timing->SetProxyEnd(load_timing.proxy_resolve_end.ToInternalValue());
  url_timing->SetDNSStart(load_timing.connect_timing.dns_start.ToInternalValue());
  url_timing->SetDNSEnd(load_timing.connect_timing.dns_end.ToInternalValue());
  url_timing->SetConnectStart(load_timing.connect_timing.connect_start.ToInternalValue());
  url_timing->SetConnectEnd(load_timing.connect_timing.connect_end.ToInternalValue());
  url_timing->SetSSLStart(load_timing.connect_timing.ssl_start.ToInternalValue());
  url_timing->SetSSLEnd(load_timing.connect_timing.ssl_end.ToInternalValue());
  url_timing->SetSendStart(load_timing.send_start.ToInternalValue());
  url_timing->SetSendEnd(load_timing.send_end.ToInternalValue());
  url_timing->SetReceiveHeadersEnd(load_timing.receive_headers_end.ToInternalValue());
  url_timing->SetPushStart(load_timing.push_start.ToInternalValue());
  url_timing->SetPushEnd(load_timing.push_end.ToInternalValue());
}

blink::WebString CryptoBufferAsWebString(const CRYPTO_BUFFER* buffer) {
  base::StringPiece sp = net::x509_util::CryptoBufferAsStringPiece(buffer);
  return blink::WebString::FromLatin1(
      reinterpret_cast<const blink::WebLChar*>(sp.begin()), sp.size());
}

std::vector<blink::KURL> ToKURLVector(const std::vector<GURL>& input) {
  std::vector<blink::KURL> result;
  for (auto it = input.begin(); it != input.end(); ++it) {
    result.push_back(blink::KURL(it->possibly_invalid_spec().data()));
  }
  return result;
}

std::string GetFetchIntegrityForWebURLRequest(const blink::WebURLRequest& request) {
  return request.GetFetchIntegrity().Utf8();
}

common::RequestContextType GetRequestContextTypeForWebURLRequest(
    const blink::WebURLRequest& request) {
  return static_cast<common::RequestContextType>(request.GetRequestContext());
}

std::string TrimLWSAndCRLF(const base::StringPiece& input) {
  base::StringPiece string = net::HttpUtil::TrimLWS(input);
  const char* begin = string.data();
  const char* end = string.data() + string.size();
  while (begin < end && (end[-1] == '\r' || end[-1] == '\n'))
    --end;
  return std::string(base::StringPiece(begin, end - begin));
}

class HttpRequestHeadersVisitor : public blink::WebHTTPHeaderVisitor {
 public:
  explicit HttpRequestHeadersVisitor(net::HttpRequestHeaders* headers)
      : headers_(headers) {}
  ~HttpRequestHeadersVisitor() override = default;

  void VisitHeader(const blink::WebString& name, const blink::WebString& value) override {
    std::string name_latin1 = name.Latin1();
    std::string value_latin1 = TrimLWSAndCRLF(value.Latin1());

    // Skip over referrer headers found in the header map because we already
    // pulled it out as a separate parameter.
    if (base::LowerCaseEqualsASCII(name_latin1, "referer"))
      return;

    DCHECK(net::HttpUtil::IsValidHeaderName(name_latin1)) << name_latin1;
    DCHECK(net::HttpUtil::IsValidHeaderValue(value_latin1)) << value_latin1;
    headers_->SetHeader(name_latin1, value_latin1);
  }

 private:
  net::HttpRequestHeaders* const headers_;
};

int GetLoadFlagsForWebURLRequest(const blink::WebURLRequest& request) {
  int load_flags = net::LOAD_NORMAL;

  GURL url(request.Url().GetString().Utf8().data(), request.Url().GetParsed(), request.Url().IsValid());
  switch (request.GetCacheMode()) {
    case blink::mojom::FetchCacheMode::kNoStore:
      load_flags |= net::LOAD_DISABLE_CACHE;
      break;
    case blink::mojom::FetchCacheMode::kValidateCache:
      load_flags |= net::LOAD_VALIDATE_CACHE;
      break;
    case blink::mojom::FetchCacheMode::kBypassCache:
      load_flags |= net::LOAD_BYPASS_CACHE;
      break;
    case blink::mojom::FetchCacheMode::kForceCache:
      load_flags |= net::LOAD_SKIP_CACHE_VALIDATION;
      break;
    case blink::mojom::FetchCacheMode::kOnlyIfCached:
      load_flags |= net::LOAD_ONLY_FROM_CACHE | net::LOAD_SKIP_CACHE_VALIDATION;
      break;
    case blink::mojom::FetchCacheMode::kUnspecifiedOnlyIfCachedStrict:
      load_flags |= net::LOAD_ONLY_FROM_CACHE;
      break;
    case blink::mojom::FetchCacheMode::kDefault:
      break;
    case blink::mojom::FetchCacheMode::kUnspecifiedForceCacheMiss:
      load_flags |= net::LOAD_ONLY_FROM_CACHE | net::LOAD_BYPASS_CACHE;
      break;
  }

  if (!request.AllowStoredCredentials()) {
    load_flags |= net::LOAD_DO_NOT_SAVE_COOKIES;
    load_flags |= net::LOAD_DO_NOT_SEND_COOKIES;
    load_flags |= net::LOAD_DO_NOT_SEND_AUTH_DATA;
  }

  if (request.GetRequestContext() == blink::WebURLRequest::kRequestContextPrefetch)
    load_flags |= net::LOAD_PREFETCH;

  //if (request.GetExtraData()) {
  //  RequestExtraData* extra_data =
  //      static_cast<RequestExtraData*>(request.GetExtraData());
  //  if (extra_data->is_for_no_state_prefetch())
  //    load_flags |= net::LOAD_PREFETCH;
  //}

  return load_flags;
}

// Extracts info from a data scheme URL |url| into |info| and |data|. Returns
// net::OK if successful. Returns a net error code otherwise.
int GetInfoFromDataURL(const GURL& url,
                       network::ResourceResponseInfo* info,
                       std::string* data) {
  // Assure same time for all time fields of data: URLs.
  base::Time now = base::Time::Now();
  info->load_timing.request_start = base::TimeTicks::Now();
  info->load_timing.request_start_time = now;
  info->request_time = now;
  info->response_time = now;

  std::string mime_type;
  std::string charset;
  scoped_refptr<net::HttpResponseHeaders> headers(
      new net::HttpResponseHeaders(std::string()));
  int result = net::URLRequestDataJob::BuildResponse(
      url, &mime_type, &charset, data, headers.get());
  if (result != net::OK)
    return result;

  info->headers = headers;
  info->mime_type.swap(mime_type);
  info->charset.swap(charset);
  info->content_length = data->length();
  info->encoded_data_length = 0;
  info->encoded_body_length = 0;
  info->previews_state = common::PREVIEWS_OFF;

  return net::OK;
}

blink::WebSecurityStyle GetSecurityStyleForResource(
    const GURL& url,
    net::CertStatus cert_status) {
  if (!url.SchemeIsCryptographic())
    return blink::kWebSecurityStyleNeutral;

  // Minor errors don't lower the security style to
  // WebSecurityStyleAuthenticationBroken.
  if (net::IsCertStatusError(cert_status) &&
      !net::IsCertStatusMinorError(cert_status)) {
    return blink::kWebSecurityStyleInsecure;
  }

  return blink::kWebSecurityStyleSecure;
}

// Convert a net::SignedCertificateTimestampAndStatus object to a
// blink::WebURLResponse::SignedCertificateTimestamp object.
blink::WebURLResponse::SignedCertificateTimestamp NetSCTToBlinkSCT(
    const net::SignedCertificateTimestampAndStatus& sct_and_status) {
  return blink::WebURLResponse::SignedCertificateTimestamp(
      blink::WebString::FromASCII(net::ct::StatusToString(sct_and_status.status)),
      blink::WebString::FromASCII(net::ct::OriginToString(sct_and_status.sct->origin)),
      blink::WebString::FromUTF8(sct_and_status.sct->log_description),
      blink::WebString::FromASCII(
          base::HexEncode(sct_and_status.sct->log_id.c_str(),
                          sct_and_status.sct->log_id.length())),
      sct_and_status.sct->timestamp.ToJavaTime(),
      blink::WebString::FromASCII(net::ct::HashAlgorithmToString(
          sct_and_status.sct->signature.hash_algorithm)),
      blink::WebString::FromASCII(net::ct::SignatureAlgorithmToString(
          sct_and_status.sct->signature.signature_algorithm)),
      blink::WebString::FromASCII(base::HexEncode(
          sct_and_status.sct->signature.signature_data.c_str(),
          sct_and_status.sct->signature.signature_data.length())));
}

net::HttpRequestHeaders GetWebURLRequestHeaders(
    const blink::WebURLRequest& request) {
  net::HttpRequestHeaders headers;
  HttpRequestHeadersVisitor visitor(&headers);
  request.VisitHTTPHeaderFields(&visitor);
  return headers;
}


void SetSecurityStyleAndDetails(const GURL& url,
                                const network::ResourceResponseInfo& info,
                                blink::WebURLResponse* response,
                                bool report_security_info) {
  if (!report_security_info) {
    response->SetSecurityStyle(blink::kWebSecurityStyleUnknown);
    return;
  }
  if (!url.SchemeIsCryptographic()) {
    response->SetSecurityStyle(blink::kWebSecurityStyleNeutral);
    return;
  }

  // The resource loader does not provide a guarantee that requests always have
  // security info (such as a certificate) attached. Use WebSecurityStyleUnknown
  // in this case where there isn't enough information to be useful.
  if (!info.ssl_info.has_value()) {
    response->SetSecurityStyle(blink::kWebSecurityStyleUnknown);
    return;
  }

  const net::SSLInfo& ssl_info = *info.ssl_info;

  const char* protocol = "";
  const char* key_exchange = "";
  const char* cipher = "";
  const char* mac = "";
  const char* key_exchange_group = "";

  if (ssl_info.connection_status) {
    int ssl_version =
        net::SSLConnectionStatusToVersion(ssl_info.connection_status);
    net::SSLVersionToString(&protocol, ssl_version);

    bool is_aead;
    bool is_tls13;
    uint16_t cipher_suite =
        net::SSLConnectionStatusToCipherSuite(ssl_info.connection_status);
    net::SSLCipherSuiteToStrings(&key_exchange, &cipher, &mac, &is_aead,
                                 &is_tls13, cipher_suite);
    if (key_exchange == nullptr) {
      DCHECK(is_tls13);
      key_exchange = "";
    }

    if (mac == nullptr) {
      DCHECK(is_aead);
      mac = "";
    }

    // if (ssl_info.key_exchange_group != 0) {
    //   // Historically the field was named 'curve' rather than 'group'.
    //   key_exchange_group = SSL_get_curve_name(ssl_info.key_exchange_group);
    //   if (!key_exchange_group) {
    //     NOTREACHED();
    //     key_exchange_group = "";
    //   }
    // }
  }

  response->SetSecurityStyle(
      GetSecurityStyleForResource(url, info.cert_status));

  blink::WebURLResponse::SignedCertificateTimestampList sct_list(
      ssl_info.signed_certificate_timestamps.size());

  for (size_t i = 0; i < sct_list.size(); ++i)
    sct_list[i] = NetSCTToBlinkSCT(ssl_info.signed_certificate_timestamps[i]);

  if (!ssl_info.cert) {
    NOTREACHED();
    response->SetSecurityStyle(blink::kWebSecurityStyleUnknown);
    return;
  }

  std::vector<std::string> san_dns;
  std::vector<std::string> san_ip;
  ssl_info.cert->GetSubjectAltName(&san_dns, &san_ip);
  blink::WebVector<blink::WebString> web_san(san_dns.size() + san_ip.size());
  std::transform(
      san_dns.begin(), san_dns.end(), web_san.begin(),
      [](const std::string& h) { return blink::WebString::FromLatin1(h); });
  std::transform(san_ip.begin(), san_ip.end(), web_san.begin() + san_dns.size(),
                 [](const std::string& h) {
                   net::IPAddress ip(reinterpret_cast<const uint8_t*>(h.data()),
                                     h.size());
                   return blink::WebString::FromLatin1(ip.ToString());
                 });

  blink::WebVector<blink::WebString> web_cert;
  web_cert.reserve(ssl_info.cert->intermediate_buffers().size() + 1);
  web_cert.emplace_back(CryptoBufferAsWebString(ssl_info.cert->cert_buffer()));
  for (const auto& cert : ssl_info.cert->intermediate_buffers())
    web_cert.emplace_back(CryptoBufferAsWebString(cert.get()));

  blink::WebURLResponse::WebSecurityDetails webSecurityDetails(
      blink::WebString::FromASCII(protocol), blink::WebString::FromASCII(key_exchange),
      blink::WebString::FromASCII(key_exchange_group), blink::WebString::FromASCII(cipher),
      blink::WebString::FromASCII(mac),
      blink::WebString::FromUTF8(ssl_info.cert->subject().common_name), web_san,
      blink::WebString::FromUTF8(ssl_info.cert->issuer().common_name),
      ssl_info.cert->valid_start().ToDoubleT(),
      ssl_info.cert->valid_expiry().ToDoubleT(), web_cert, sct_list);

  response->SetSecurityDetails(webSecurityDetails);
}

common::ResourceType WebURLRequestContextToResourceType(
    blink::WebURLRequest::RequestContext request_context) {
  switch (request_context) {
    // CSP report
    case blink::WebURLRequest::kRequestContextCSPReport:
      return common::RESOURCE_TYPE_CSP_REPORT;

    // Favicon
    case blink::WebURLRequest::kRequestContextFavicon:
      return common::RESOURCE_TYPE_FAVICON;

    // Font
    case blink::WebURLRequest::kRequestContextFont:
      return common::RESOURCE_TYPE_FONT_RESOURCE;

    // Image
    case blink::WebURLRequest::kRequestContextImage:
    case blink::WebURLRequest::kRequestContextImageSet:
      return common::RESOURCE_TYPE_IMAGE;

    // Media
    case blink::WebURLRequest::kRequestContextAudio:
    case blink::WebURLRequest::kRequestContextVideo:
      return common::RESOURCE_TYPE_MEDIA;

    // Object
    case blink::WebURLRequest::kRequestContextEmbed:
    case blink::WebURLRequest::kRequestContextObject:
      return common::RESOURCE_TYPE_OBJECT;

    // Ping
    case blink::WebURLRequest::kRequestContextBeacon:
    case blink::WebURLRequest::kRequestContextPing:
      return common::RESOURCE_TYPE_PING;

    // Subresource of plugins
    case blink::WebURLRequest::kRequestContextPlugin:
      return common::RESOURCE_TYPE_PLUGIN_RESOURCE;

    // Prefetch
    case blink::WebURLRequest::kRequestContextPrefetch:
      return common::RESOURCE_TYPE_PREFETCH;

    // Script
    case blink::WebURLRequest::kRequestContextImport:
    case blink::WebURLRequest::kRequestContextScript:
      return common::RESOURCE_TYPE_SCRIPT;

    // Style
    case blink::WebURLRequest::kRequestContextXSLT:
    case blink::WebURLRequest::kRequestContextStyle:
      return common::RESOURCE_TYPE_STYLESHEET;

    // Subresource
    case blink::WebURLRequest::kRequestContextDownload:
    case blink::WebURLRequest::kRequestContextManifest:
    case blink::WebURLRequest::kRequestContextSubresource:
      return common::RESOURCE_TYPE_SUB_RESOURCE;

    // TextTrack
    case blink::WebURLRequest::kRequestContextTrack:
      return common::RESOURCE_TYPE_MEDIA;

    // Workers
    case blink::WebURLRequest::kRequestContextServiceWorker:
      return common::RESOURCE_TYPE_SERVICE_WORKER;
    case blink::WebURLRequest::kRequestContextSharedWorker:
      return common::RESOURCE_TYPE_SHARED_WORKER;
    case blink::WebURLRequest::kRequestContextWorker:
      return common::RESOURCE_TYPE_WORKER;

    // Unspecified
    case blink::WebURLRequest::kRequestContextInternal:
    case blink::WebURLRequest::kRequestContextUnspecified:
      return common::RESOURCE_TYPE_SUB_RESOURCE;

    // XHR
    case blink::WebURLRequest::kRequestContextEventSource:
    case blink::WebURLRequest::kRequestContextFetch:
    case blink::WebURLRequest::kRequestContextXMLHttpRequest:
      return common::RESOURCE_TYPE_XHR;

    // These should be handled by the FrameType checks at the top of the
    // function.
    case blink::WebURLRequest::kRequestContextForm:
    case blink::WebURLRequest::kRequestContextHyperlink:
    case blink::WebURLRequest::kRequestContextLocation:
    case blink::WebURLRequest::kRequestContextFrame:
    case blink::WebURLRequest::kRequestContextIframe:
      NOTREACHED();
      return common::RESOURCE_TYPE_SUB_RESOURCE;

    default:
      NOTREACHED();
      return common::RESOURCE_TYPE_SUB_RESOURCE;
  }
}

common::ResourceType WebURLRequestToResourceType(const blink::WebURLRequest& request) {
  blink::WebURLRequest::RequestContext request_context = request.GetRequestContext();
  if (request.GetFrameType() !=
      network::mojom::RequestContextFrameType::kNone) {
    DCHECK(request_context == blink::WebURLRequest::kRequestContextForm ||
           request_context == blink::WebURLRequest::kRequestContextFrame ||
           request_context == blink::WebURLRequest::kRequestContextHyperlink ||
           request_context == blink::WebURLRequest::kRequestContextIframe ||
           request_context == blink::WebURLRequest::kRequestContextInternal ||
           request_context == blink::WebURLRequest::kRequestContextLocation);
    if (request.GetFrameType() ==
            network::mojom::RequestContextFrameType::kTopLevel ||
        request.GetFrameType() ==
            network::mojom::RequestContextFrameType::kAuxiliary) {
      return common::RESOURCE_TYPE_MAIN_FRAME;
    }
    if (request.GetFrameType() ==
        network::mojom::RequestContextFrameType::kNested)
      return common::RESOURCE_TYPE_SUB_FRAME;
    NOTREACHED();
    return common::RESOURCE_TYPE_SUB_RESOURCE;
  }
  return WebURLRequestContextToResourceType(request_context);
}

// void PopulateBogusURLResponse(
//     const blink::WebURL& url,
//     //const network::ResourceResponseInfo& info,
//     blink::WebURLResponse* response) {//,
//    //bool report_security_info) {
  
//   response->SetURL(url);
//   response->SetResponseTime(base::Time::Now());
//   //response->SetResponseTime(info.response_time);
//   response->SetMIMEType(blink::WebString::FromUTF8("text/html"));//info.mime_type));
//   response->SetTextEncodingName(blink::WebString::FromUTF8("UTF-8"));//info.charset));
//   response->SetExpectedContentLength(arraysize(kBodyContent));//info.content_length);
//   response->SetHasMajorCertificateErrors(false);
//    //   net::IsCertStatusError(info.cert_status) &&
//    //   !net::IsCertStatusMinorError(info.cert_status));
// //  response->SetCTPolicyCompliance(true);//info.ct_policy_compliance);
//   response->SetIsLegacySymantecCert(false);//info.is_legacy_symantec_cert);
//   response->SetAppCacheID(0);//info.appcache_id);
//   //response->SetAppCacheManifestURL();//(info.appcache_manifest_url);
//   response->SetWasCached(true);//!info.load_timing.request_start_time.is_null() &&
//                          //info.response_time <
//                          //    info.load_timing.request_start_time);
//   response->SetRemoteIPAddress(blink::WebString::FromUTF8("127.0.0.1"));
//   //    WebString::FromUTF8(info.socket_address.HostForURL()));
//   response->SetRemotePort(8080);//info.socket_address.port());
//   response->SetConnectionID(1001);//info.load_timing.socket_log_id);
//   response->SetConnectionReused(false);//info.load_timing.socket_reused);
//   response->SetDownloadFilePath(blink::WebString::FromUTF8(""));
//   //    blink::FilePathToWebString(info.download_file_path));
//   response->SetWasFetchedViaSPDY(false);//info.was_fetched_via_spdy);
//   response->SetWasFetchedViaServiceWorker(false);//info.was_fetched_via_service_worker);
//   response->SetWasFallbackRequiredByServiceWorker(
//       false);//info.was_fallback_required_by_service_worker);
//   //response->SetResponseTypeViaServiceWorker(
//   //    info.response_type_via_service_worker);
//   //response->SetURLListViaServiceWorker(info.url_list_via_service_worker);
//   response->SetCacheStorageCacheName(
//       //info.is_in_cache_storage
//       //    ? blink::WebString::FromUTF8(info.cache_storage_cache_name)
//           //: 
//   	blink::WebString());
//   //blink::WebVector<blink::WebString> cors_exposed_header_names(
//   //    info.cors_exposed_header_names.size());
//   //std::transform(
//   //    info.cors_exposed_header_names.begin(),
//   //    info.cors_exposed_header_names.end(), cors_exposed_header_names.begin(),
//   //    [](const std::string& h) { return blink::WebString::FromLatin1(h); });
//   //response->SetCorsExposedHeaderNames(cors_exposed_header_names);
//   response->SetDidServiceWorkerNavigationPreload(false);
//   //    info.did_service_worker_navigation_preload);
//   response->SetEncodedDataLength(blink::WebURLLoaderClient::kUnknownEncodedDataLength);//arraysize(kBodyContent));//info.encoded_data_length);
//   //response->SetAlpnNegotiatedProtocol(
//   //    WebString::FromUTF8(info.alpn_negotiated_protocol));
//   //response->SetConnectionInfo(info.connection_info);

//   //SetSecurityStyleAndDetails(url, info, response, report_security_info);

//   //WebURLResponseExtraDataImpl* extra_data = new WebURLResponseExtraDataImpl();
//   //response->SetExtraData(extra_data);
//   //extra_data->set_was_fetched_via_spdy(info.was_fetched_via_spdy);
//   //extra_data->set_was_alpn_negotiated(info.was_alpn_negotiated);
//   //extra_data->set_was_alternate_protocol_available(
//   //    info.was_alternate_protocol_available);
//   //extra_data->set_previews_state(
//   //    static_cast<PreviewsState>(info.previews_state));
//   //extra_data->set_effective_connection_type(info.effective_connection_type);

//   // If there's no received headers end time, don't set load timing.  This is
//   // the case for non-HTTP requests, requests that don't go over the wire, and
//   // certain error cases.
//   //if (!info.load_timing.receive_headers_end.is_null()) {
//   //  WebURLLoadTiming timing;
//   //  PopulateURLLoadTiming(info.load_timing, &timing);
//   //  timing.SetWorkerStart(info.service_worker_start_time);
//   //  timing.SetWorkerReady(info.service_worker_ready_time);
//   //  response->SetLoadTiming(timing);
//   //}

//   //if (info.raw_request_response_info.get()) {
//     blink::WebHTTPLoadInfo load_info;

//     load_info.SetHTTPStatusCode(200);
//         //info.raw_request_response_info->http_status_code);
//     load_info.SetHTTPStatusText(blink::WebString::FromUTF8("200 OK"));
//         //info.raw_request_response_info->http_status_text));

//     load_info.SetRequestHeadersText(blink::WebString::FromUTF8(""));
//     //    info.raw_request_response_info->request_headers_text));
//     load_info.SetResponseHeadersText(blink::WebString::FromUTF8(""));//
//     //    info.raw_request_response_info->response_headers_text));
//     //const HeadersVector& request_headers =
//     //    info.raw_request_response_info->request_headers;
//     //for (HeadersVector::const_iterator it = request_headers.begin();
//     //     it != request_headers.end(); ++it) {
//     //  load_info.AddRequestHeader(WebString::FromLatin1(it->first),
//     //                             WebString::FromLatin1(it->second));
//     //}
//     //const HeadersVector& response_headers =
//     //    info.raw_request_response_info->response_headers;
//     //for (HeadersVector::const_iterator it = response_headers.begin();
//     //     it != response_headers.end(); ++it) {
//     //  load_info.AddResponseHeader(WebString::FromLatin1(it->first),
//     //                              WebString::FromLatin1(it->second));
//     //}
//     //load_info.SetNPNNegotiatedProtocol(
//     //    WebString::FromLatin1(info.alpn_negotiated_protocol));
//     response->SetHTTPLoadInfo(load_info);
//   //}

//   //const net::HttpResponseHeaders* headers = info.headers.get();
//   //if (!headers)
//   //  return;

//   blink::WebURLResponse::HTTPVersion version = blink::WebURLResponse::kHTTPVersion_1_1;//WebURLResponse::kHTTPVersionUnknown;
//   //if (headers->GetHttpVersion() == net::HttpVersion(0, 9))
//   //  version = WebURLResponse::kHTTPVersion_0_9;
//   //else if (headers->GetHttpVersion() == net::HttpVersion(1, 0))
//   //  version = WebURLResponse::kHTTPVersion_1_0;
//   //else if (headers->GetHttpVersion() == net::HttpVersion(1, 1))
//   //  version = WebURLResponse::kHTTPVersion_1_1;
//   //else if (headers->GetHttpVersion() == net::HttpVersion(2, 0))
//   //  version = WebURLResponse::kHTTPVersion_2_0;
//   response->SetHTTPVersion(version);
//   response->SetHTTPStatusCode(200);//headers->response_code());
//   //response->SetHTTPStatusText(WebString::FromLatin1(headers->GetStatusText()));
//   response->SetHTTPStatusText(blink::WebString::FromUTF8("200 OK"));

//   // Build up the header map.
//   //size_t iter = 0;
//   //std::string name;
//   //std::string value;
//   //while (headers->EnumerateHeaderLines(&iter, &name, &value)) {
//   //  response->AddHTTPHeaderField(WebString::FromLatin1(name),
//   //                               WebString::FromLatin1(value));
//   //}
// }

net::RequestPriority ConvertWebKitPriorityToNetPriority(
    const blink::WebURLRequest::Priority& priority) {
  switch (priority) {
    case blink::WebURLRequest::Priority::kVeryHigh:
      return net::HIGHEST;

    case blink::WebURLRequest::Priority::kHigh:
      return net::MEDIUM;

    case blink::WebURLRequest::Priority::kMedium:
      return net::LOW;

    case blink::WebURLRequest::Priority::kLow:
      return net::LOWEST;

    case blink::WebURLRequest::Priority::kVeryLow:
      return net::IDLE;

    case blink::WebURLRequest::Priority::kUnresolved:
    default:
      NOTREACHED();
      return net::LOW;
  }
}

}

using Result = blink::WebDataConsumerHandle::Result;

class WebDataConsumerHandleImpl::Context
     : public base::RefCountedThreadSafe<Context> {
  public:
   explicit Context(Handle handle) : handle_(std::move(handle)) {}

   const Handle& handle() { return handle_; }

  private:
   friend class base::RefCountedThreadSafe<Context>;
   ~Context() {}
   Handle handle_;

   DISALLOW_COPY_AND_ASSIGN(Context);
};

WebDataConsumerHandleImpl::ReaderImpl::ReaderImpl(
    scoped_refptr<Context> context,
    Client* client,
    scoped_refptr<base::SingleThreadTaskRunner> task_runner)
    : context_(context),
      handle_watcher_(FROM_HERE,
                      mojo::SimpleWatcher::ArmingPolicy::MANUAL,
                      std::move(task_runner)),
      client_(client) {
  if (client_)
    StartWatching();
}

WebDataConsumerHandleImpl::ReaderImpl::~ReaderImpl() {
}

Result WebDataConsumerHandleImpl::ReaderImpl::Read(void* data,
                                                   size_t size,
                                                   Flags flags,
                                                   size_t* read_size) {
  //DLOG(INFO) << "WebDataConsumerHandleImpl::ReaderImpl::Read: size = " << size;
  // We need this variable definition to avoid a link error.
  const Flags kNone = kFlagNone;
  DCHECK_EQ(flags, kNone);
  DCHECK_LE(size, std::numeric_limits<uint32_t>::max());

  *read_size = 0;

  if (!size) {
    // Even if there is unread data available, ReadData() returns
    // FAILED_PRECONDITION when |size| is 0 and the producer handle was closed.
    // But in this case, WebDataConsumerHandle::Reader::read() must return Ok.
    // So we query the signals state directly.
    mojo::HandleSignalsState state = context_->handle()->QuerySignalsState();
    if (state.readable())
      return kOk;
    if (state.never_readable())
      return kDone;
    return kShouldWait;
  }

  uint32_t size_to_pass = size;
  MojoReadDataFlags flags_to_pass = MOJO_READ_DATA_FLAG_NONE;
  MojoResult rv = context_->handle()->ReadData(data, &size_to_pass, flags_to_pass);
  if (rv == MOJO_RESULT_OK)
    *read_size = size_to_pass;
  if (rv == MOJO_RESULT_SHOULD_WAIT)
    handle_watcher_.ArmOrNotify();

  return HandleReadResult(rv);
}

Result WebDataConsumerHandleImpl::ReaderImpl::BeginRead(const void** buffer,
                                                        Flags flags,
                                                        size_t* available) {
  //DLOG(INFO) << "WebDataConsumerHandleImpl::ReaderImpl::BeginRead";
  // We need this variable definition to avoid a link error.
  const Flags kNone = kFlagNone;
  DCHECK_EQ(flags, kNone);

  *buffer = nullptr;
  *available = 0;

  uint32_t size_to_pass = 0;
  MojoReadDataFlags flags_to_pass = MOJO_READ_DATA_FLAG_NONE;

  MojoResult rv =
      context_->handle()->BeginReadData(buffer, &size_to_pass, flags_to_pass);
  if (rv == MOJO_RESULT_OK)
    *available = size_to_pass;
  if (rv == MOJO_RESULT_SHOULD_WAIT)
    handle_watcher_.ArmOrNotify();
  return HandleReadResult(rv);
}

Result WebDataConsumerHandleImpl::ReaderImpl::EndRead(size_t read_size) {
  //DLOG(INFO) << "WebDataConsumerHandleImpl::ReaderImpl::EndRead: read_size = " << read_size;
  MojoResult rv = context_->handle()->EndReadData(read_size);
  return rv == MOJO_RESULT_OK ? kOk : kUnexpectedError;
}

Result WebDataConsumerHandleImpl::ReaderImpl::HandleReadResult(
    MojoResult mojo_result) {
  switch (mojo_result) {
    case MOJO_RESULT_OK:
      return kOk;
    case MOJO_RESULT_FAILED_PRECONDITION:
      return kDone;
    case MOJO_RESULT_BUSY:
      return kBusy;
    case MOJO_RESULT_SHOULD_WAIT:
      return kShouldWait;
    case MOJO_RESULT_RESOURCE_EXHAUSTED:
      return kResourceExhausted;
    default:
      return kUnexpectedError;
  }
}

void WebDataConsumerHandleImpl::ReaderImpl::StartWatching() {
  handle_watcher_.Watch(
      context_->handle().get(), MOJO_HANDLE_SIGNAL_READABLE,
      base::Bind(&ReaderImpl::OnHandleGotReadable, base::Unretained(this)));
  handle_watcher_.ArmOrNotify();
}

void WebDataConsumerHandleImpl::ReaderImpl::OnHandleGotReadable(MojoResult) {
  //DLOG(INFO) << "WebDataConsumerHandleImpl::ReaderImpl::OnHandleGotReadable";
  DCHECK(client_);
  client_->DidGetReadable();
}

WebDataConsumerHandleImpl::WebDataConsumerHandleImpl(Handle handle)
    : context_(new Context(std::move(handle))) {}

WebDataConsumerHandleImpl::~WebDataConsumerHandleImpl() {
}

std::unique_ptr<blink::WebDataConsumerHandle::Reader>
WebDataConsumerHandleImpl::ObtainReader(
    Client* client,
    scoped_refptr<base::SingleThreadTaskRunner> task_runner) {
 // //DLOG(INFO) << "WebDataConsumerHandleImpl::ObtainReader"; 
  return base::WrapUnique(
      new ReaderImpl(context_, client, std::move(task_runner)));
}

const char* WebDataConsumerHandleImpl::DebugName() const {
  return "WebDataConsumerHandleImpl";
}

// This inner class exists since the WebURLLoader may be deleted while inside a
// call to WebURLLoaderClient.  Refcounting is to keep the context from being
// deleted if it may have work to do after calling into the client.
class ApplicationURLLoader::Context : public base::RefCounted<Context> {
 public:
  using ReceivedData = RequestPeer::ReceivedData;

  Context(ApplicationURLLoader* loader,
          ResourceDispatcher* resource_dispatcher,
          scoped_refptr<base::SingleThreadTaskRunner> task_runner,
          scoped_refptr<network::SharedURLLoaderFactory> factory);//,
          //common::mojom::KeepAliveHandlePtr keep_alive_handle);

  ResourceDispatcher* resource_dispatcher() { return resource_dispatcher_; }
  int request_id() const { return request_id_; }
  blink::WebURLLoaderClient* client() const { return client_; }
  void set_client(blink::WebURLLoaderClient* client) { client_ = client; }
  scoped_refptr<base::SingleThreadTaskRunner> task_runner() {
    return task_runner_;
  }

  void AddHandler(std::unique_ptr<ResponseHandler> handler) {
    // compilers nowadays are clever, but just in case
    const std::string& handler_name = handler->name();
    handler_chain_.emplace(std::make_pair(handler_name, std::move(handler)));
  }

  void Cancel();
  void SetDefersLoading(bool value);
  void DidChangePriority(blink::WebURLRequest::Priority new_priority,
                         int intra_priority_value);
  void Start(const blink::WebURLRequest& request,
             SyncLoadResponse* sync_load_response);

  void OnUploadProgress(uint64_t position, uint64_t size);
  bool OnReceivedRedirect(const net::RedirectInfo& redirect_info,
                          const network::ResourceResponseInfo& info);
  void OnReceivedResponse(const network::ResourceResponseInfo& info);
  void OnStartLoadingResponseBody(mojo::ScopedDataPipeConsumerHandle body);
  void OnDownloadedData(int len, int encoded_data_length);
  void OnReceivedData(std::unique_ptr<ReceivedData> data);
  void OnTransferSizeUpdated(int transfer_size_diff);
  void OnReceivedCachedMetadata(const char* data, int len);
  void OnCompletedRequest(const network::URLLoaderCompletionStatus& status);

 private:
  friend class base::RefCounted<Context>;
  ~Context();

  // Called when the body data stream is detached from the reader side.
  void CancelBodyStreaming();
  // We can optimize the handling of data URLs in most cases.
  bool CanHandleDataURLRequestLocally(const blink::WebURLRequest& request) const;
  void HandleDataURL();

  static net::NetworkTrafficAnnotationTag GetTrafficAnnotationTag(
      const blink::WebURLRequest& request);

  ApplicationURLLoader* loader_;

  blink::WebURL url_;
  bool use_stream_on_response_;
  // Controls SetSecurityStyleAndDetails() in PopulateURLResponse(). Initially
  // set to WebURLRequest::ReportRawHeaders() in Start() and gets updated in
  // WillFollowRedirect() (by the InspectorNetworkAgent) while the new
  // ReportRawHeaders() value won't be propagated to the browser process.
  //
  // TODO(tyoshino): Investigate whether it's worth propagating the new value.
  bool report_raw_headers_;

  blink::WebURLLoaderClient* client_;
  ResourceDispatcher* resource_dispatcher_;
  scoped_refptr<base::SingleThreadTaskRunner> task_runner_;
  //std::unique_ptr<FtpDirectoryListingResponseDelegate> ftp_listing_delegate_;
  std::unique_ptr<SharedMemoryDataConsumerHandle::Writer> body_stream_writer_;
 // std::unique_ptr<KeepAliveHandleWithChildProcessReference> keep_alive_handle_;
  enum DeferState {NOT_DEFERRING, SHOULD_DEFER, DEFERRED_DATA};
  DeferState defers_loading_;
  int request_id_;

  scoped_refptr<network::SharedURLLoaderFactory> url_loader_factory_;

  std::unordered_map<std::string, std::unique_ptr<ResponseHandler>> handler_chain_;
  ResponseHandler* current_handler_;
};

// A thin wrapper class for Context to ensure its lifetime while it is
// handling IPC messages coming from ResourceDispatcher. Owns one ref to
// Context and held by ResourceDispatcher.
class ApplicationURLLoader::RequestPeerImpl : public RequestPeer {
 public:
  // If |discard_body| is false this doesn't propagate the received data
  // to the context.
  explicit RequestPeerImpl(Context* context, bool discard_body = false);

  // RequestPeer methods:
  void OnUploadProgress(uint64_t position, uint64_t size) override;
  bool OnReceivedRedirect(const net::RedirectInfo& redirect_info,
                          const network::ResourceResponseInfo& info) override;
  void OnReceivedResponse(const network::ResourceResponseInfo& info) override;
  void OnStartLoadingResponseBody(
      mojo::ScopedDataPipeConsumerHandle body) override;
  void OnDownloadedData(int len, int encoded_data_length) override;
  void OnReceivedData(std::unique_ptr<ReceivedData> data) override;
  void OnTransferSizeUpdated(int transfer_size_diff) override;
  void OnReceivedCachedMetadata(const char* data, int len) override;
  void OnCompletedRequest(
      const network::URLLoaderCompletionStatus& status) override;

 private:
  scoped_refptr<Context> context_;
  const bool discard_body_;
  DISALLOW_COPY_AND_ASSIGN(RequestPeerImpl);
};

// A sink peer that doesn't forward the data.
class ApplicationURLLoader::SinkPeer : public RequestPeer {
 public:
  explicit SinkPeer(Context* context) : context_(context) {}

  // RequestPeer implementation:
  void OnUploadProgress(uint64_t position, uint64_t size) override {}
  bool OnReceivedRedirect(const net::RedirectInfo& redirect_info,
                          const network::ResourceResponseInfo& info) override {
    return true;
  }
  void OnReceivedResponse(const network::ResourceResponseInfo& info) override {
    //DLOG(INFO) << "ApplicationURLLoader::SinkPeer::OnReceivedResponse";
  }
  void OnStartLoadingResponseBody(
      mojo::ScopedDataPipeConsumerHandle body) override {}
  void OnDownloadedData(int len, int encoded_data_length) override {}
  void OnReceivedData(std::unique_ptr<ReceivedData> data) override {
    //DLOG(INFO) << "ApplicationURLLoader::SinkPeer::OnReceivedData";
  }
  void OnTransferSizeUpdated(int transfer_size_diff) override {}
  void OnReceivedCachedMetadata(const char* data, int len) override {
    //DLOG(INFO) << "ApplicationURLLoader::SinkPeer::OnReceivedCachedMetaData";
  }
  void OnCompletedRequest(
      const network::URLLoaderCompletionStatus& status) override {
    //DLOG(INFO) << "ApplicationURLLoader::SinkPeer::OnCompletedRequest: calling resource_dispatcher()->Cancel()";
    context_->resource_dispatcher()->Cancel(context_->request_id(),
                                            context_->task_runner());
  }

 private:
  scoped_refptr<Context> context_;
  DISALLOW_COPY_AND_ASSIGN(SinkPeer);
};

// ApplicationURLLoader::RequestPeerImpl ------------------------------------------

ApplicationURLLoader::RequestPeerImpl::RequestPeerImpl(Context* context,
                                                   bool discard_body)
    : context_(context), discard_body_(discard_body) {}

void ApplicationURLLoader::RequestPeerImpl::OnUploadProgress(uint64_t position,
                                                         uint64_t size) {
  context_->OnUploadProgress(position, size);
}

bool ApplicationURLLoader::RequestPeerImpl::OnReceivedRedirect(
    const net::RedirectInfo& redirect_info,
    const network::ResourceResponseInfo& info) {
  return context_->OnReceivedRedirect(redirect_info, info);
}

void ApplicationURLLoader::RequestPeerImpl::OnReceivedResponse(
    const network::ResourceResponseInfo& info) {
 // //DLOG(INFO) << "ApplicationURLLoader::RequestPeerImpl::OnReceivedResponse";
  context_->OnReceivedResponse(info);
}

void ApplicationURLLoader::RequestPeerImpl::OnStartLoadingResponseBody(
    mojo::ScopedDataPipeConsumerHandle body) {
 // //DLOG(INFO) << "ApplicationURLLoader::RequestPeerImpl::OnStartLoadingResponseBody";
  context_->OnStartLoadingResponseBody(std::move(body));
}

void ApplicationURLLoader::RequestPeerImpl::OnDownloadedData(
    int len,
    int encoded_data_length) {
  context_->OnDownloadedData(len, encoded_data_length);
}

void ApplicationURLLoader::RequestPeerImpl::OnReceivedData(
    std::unique_ptr<ReceivedData> data) {
  //DLOG(INFO) << "ApplicationURLLoader::RequestPeerImpl::OnReceivedData";
  if (discard_body_)
    return;
  context_->OnReceivedData(std::move(data));
}

void ApplicationURLLoader::RequestPeerImpl::OnTransferSizeUpdated(
    int transfer_size_diff) {
 // //DLOG(INFO) << "ApplicationURLLoader::RequestPeerImpl::OnTransferSizeUpdated";
  context_->OnTransferSizeUpdated(transfer_size_diff);
}

void ApplicationURLLoader::RequestPeerImpl::OnReceivedCachedMetadata(
    const char* data,
    int len) {
  //DLOG(INFO) << "ApplicationURLLoader::RequestPeerImpl::OnReceivedCachedMetadata";
  
  if (discard_body_)
    return;
  context_->OnReceivedCachedMetadata(data, len);
}

void ApplicationURLLoader::RequestPeerImpl::OnCompletedRequest(
    const network::URLLoaderCompletionStatus& status) {
  //DLOG(INFO) << "ApplicationURLLoader::RequestPeerImpl::OnCompletedRequest";
  context_->OnCompletedRequest(status);
}


// ApplicationURLLoader::Context --------------------------------------------------

ApplicationURLLoader::Context::Context(
    ApplicationURLLoader* loader,
    ResourceDispatcher* resource_dispatcher,
    scoped_refptr<base::SingleThreadTaskRunner> task_runner,
    scoped_refptr<network::SharedURLLoaderFactory> url_loader_factory)//,
    //common::mojom::KeepAliveHandlePtr keep_alive_handle_ptr)
    : loader_(loader),
      use_stream_on_response_(false),
      report_raw_headers_(false),
      client_(nullptr),
      resource_dispatcher_(resource_dispatcher),
      task_runner_(std::move(task_runner)),
      //keep_alive_handle_(
      //    keep_alive_handle_ptr
      //        ? std::make_unique<KeepAliveHandleWithChildProcessReference>(
      //              std::move(keep_alive_handle_ptr))
      //        : nullptr),
      defers_loading_(NOT_DEFERRING),
      request_id_(-1),
      url_loader_factory_(url_loader_factory),
      current_handler_(nullptr) {
  //DCHECK(url_loader_factory_ || !resource_dispatcher);
}

void ApplicationURLLoader::Context::Cancel() {
  TRACE_EVENT_WITH_FLOW0("loading", "ApplicationURLLoader::Context::Cancel", this,
                         TRACE_EVENT_FLAG_FLOW_IN);
  if (resource_dispatcher_ && // NULL in unittest.
      request_id_ != -1) {
    resource_dispatcher_->Cancel(request_id_, task_runner_);
    request_id_ = -1;
  }

  if (body_stream_writer_)
    body_stream_writer_->Fail();

  // Ensure that we do not notify the delegate anymore as it has
  // its own pointer to the client.
  //if (ftp_listing_delegate_)
  //  ftp_listing_delegate_->Cancel();

  // Do not make any further calls to the client.
  client_ = nullptr;
  loader_ = nullptr;
}

void ApplicationURLLoader::Context::SetDefersLoading(bool value) {
  if (request_id_ != -1)
    resource_dispatcher_->SetDefersLoading(request_id_, value);
  if (value && defers_loading_ == NOT_DEFERRING) {
    defers_loading_ = SHOULD_DEFER;
  } else if (!value && defers_loading_ != NOT_DEFERRING) {
    if (defers_loading_ == DEFERRED_DATA) {
      task_runner_->PostTask(FROM_HERE,
                             base::BindOnce(&Context::HandleDataURL, this));
    }
    defers_loading_ = NOT_DEFERRING;
  }
}

void ApplicationURLLoader::Context::DidChangePriority(
    blink::WebURLRequest::Priority new_priority, int intra_priority_value) {
  if (request_id_ != -1) {
    resource_dispatcher_->DidChangePriority(
        request_id_,
        ConvertWebKitPriorityToNetPriority(new_priority),
        intra_priority_value);
  }
}

void ApplicationURLLoader::Context::Start(const blink::WebURLRequest& request,
                                          SyncLoadResponse* sync_load_response) {
  DCHECK(request_id_ == -1);

  url_ = request.Url();
  GURL gurl(url_.GetString().Utf8().data(), url_.GetParsed(), url_.IsValid());
  use_stream_on_response_ = request.UseStreamOnResponse();
  report_raw_headers_ = request.ReportRawHeaders();

  if (CanHandleDataURLRequestLocally(request)) {
    if (sync_load_response) {
      // This is a sync load. Do the work now.
      sync_load_response->url = gurl;
      sync_load_response->error_code =
          GetInfoFromDataURL(sync_load_response->url, &sync_load_response->info,
                             &sync_load_response->data);
    } else {
      task_runner_->PostTask(FROM_HERE,
                             base::BindOnce(&Context::HandleDataURL, this));
    }
    return;
  }

  std::unique_ptr<NavigationResponseOverrideParameters> response_override;
  //if (request.GetExtraData()) {
  //  RequestExtraData* extra_data =
  //      static_cast<RequestExtraData*>(request.GetExtraData());
  //  response_override = extra_data->TakeNavigationResponseOverrideOwnership();
  //}


  // PlzNavigate: outside of tests, the only navigation requests going through
  // the WebURLLoader are the ones created by CommitNavigation. Several browser
  // tests load HTML directly through a data url which will be handled by the
  // block above.
  //DCHECK(response_override ||
  //       request.GetFrameType() ==
  //           network::mojom::RequestContextFrameType::kNone);

  GURL referrer_url(
      request.HttpHeaderField(blink::WebString::FromASCII("Referer")).Latin1());
  const std::string& method = request.HttpMethod().Latin1();

  // TODO(brettw) this should take parameter encoding into account when
  // creating the GURLs.

  // TODO(horo): Check credentials flag is unset when credentials mode is omit.
  //             Check credentials flag is set when credentials mode is include.

  std::unique_ptr<network::ResourceRequest> resource_request(
      new network::ResourceRequest);

  resource_request->method = method;
  resource_request->url = gurl;
  resource_request->site_for_cookies = GURL(request.SiteForCookies().GetString().Utf8().data(), request.SiteForCookies().GetParsed(), request.SiteForCookies().IsValid());
  resource_request->request_initiator =
      request.RequestorOrigin().IsNull()
          ? base::Optional<url::Origin>()
          : base::Optional<url::Origin>(request.RequestorOrigin());
  resource_request->referrer = referrer_url;

  resource_request->referrer_policy =
      common::Referrer::ReferrerPolicyForUrlRequest(request.GetReferrerPolicy());
  resource_request->resource_type = WebURLRequestToResourceType(request);

  resource_request->headers = GetWebURLRequestHeaders(request);
  if (resource_request->resource_type == common::RESOURCE_TYPE_STYLESHEET) {
    resource_request->headers.SetHeader(network::kAcceptHeader,
                                        kStylesheetAcceptHeader);
  } else if (resource_request->resource_type == common::RESOURCE_TYPE_FAVICON ||
             resource_request->resource_type == common::RESOURCE_TYPE_IMAGE) {
    resource_request->headers.SetHeader(network::kAcceptHeader,
                                        kImageAcceptHeader);
  } else {
    // Calling SetHeaderIfMissing() instead of SetHeader() because JS can
    // manually set an accept header on an XHR.
    resource_request->headers.SetHeaderIfMissing(network::kAcceptHeader,
                                                 network::kDefaultAcceptHeader);
  }

  if (resource_request->resource_type == common::RESOURCE_TYPE_PREFETCH ||
      resource_request->resource_type == common::RESOURCE_TYPE_FAVICON) {
    resource_request->do_not_prompt_for_login = true;
  }

  resource_request->load_flags = GetLoadFlagsForWebURLRequest(request);

  // |plugin_child_id| only needs to be non-zero if the request originates
  // outside the render process, so we can use requestorProcessID even
  // for requests from in-process plugins.
  resource_request->plugin_child_id = request.GetPluginChildID();
  resource_request->priority =
      ConvertWebKitPriorityToNetPriority(request.GetPriority());
  resource_request->appcache_host_id = request.AppCacheHostID();
  resource_request->should_reset_appcache = request.ShouldResetAppCache();
  resource_request->is_external_request = request.IsExternalRequest();
  resource_request->cors_preflight_policy = request.GetCORSPreflightPolicy();
  resource_request->skip_service_worker = request.GetSkipServiceWorker();
  resource_request->fetch_request_mode = network::mojom::FetchRequestMode::kNoCORS;//request.GetFetchRequestMode();
  resource_request->fetch_credentials_mode = request.GetFetchCredentialsMode();
  resource_request->fetch_redirect_mode = request.GetFetchRedirectMode();
  resource_request->fetch_integrity =
      GetFetchIntegrityForWebURLRequest(request);
  resource_request->fetch_request_context_type =
      GetRequestContextTypeForWebURLRequest(request);

  resource_request->fetch_frame_type = request.GetFrameType();
  resource_request->request_body =
      GetRequestBodyForWebURLRequest(request).get();
  resource_request->download_to_file = request.DownloadToFile();
  resource_request->keepalive = request.GetKeepalive();
  resource_request->has_user_gesture = request.HasUserGesture();
  resource_request->enable_load_timing = true;
  resource_request->enable_upload_progress = request.ReportUploadProgress();
  
  if (request.GetRequestContext() ==
          blink::WebURLRequest::kRequestContextXMLHttpRequest &&
      (gurl.has_username() || gurl.has_password())) {
    resource_request->do_not_prompt_for_login = true;
  }
  resource_request->report_raw_headers = request.ReportRawHeaders();
  resource_request->previews_state =
      static_cast<int>(request.GetPreviewsState());

  // The network request has already been made by the browser. The renderer
  // should bind the URLLoaderClientEndpoints stored in |response_override| to
  // an implementation of a URLLoaderClient to get the response body.
  if (response_override) {
    DCHECK(!sync_load_response);
    DCHECK_NE(network::mojom::RequestContextFrameType::kNone,
              request.GetFrameType());
  }

  //RequestExtraData empty_extra_data;
  //RequestExtraData* extra_data;
 // if (request.GetExtraData())
 //   extra_data = static_cast<RequestExtraData*>(request.GetExtraData());
 // else
 //   extra_data = &empty_extra_data;
 // extra_data->CopyToResourceRequest(resource_request.get());

  std::unique_ptr<RequestPeer> peer;
  //if (extra_data->download_to_network_cache_only()) {
  //  peer = std::make_unique<SinkPeer>(this);
  //} else {
    const bool discard_body =
        (resource_request->resource_type == common::RESOURCE_TYPE_PREFETCH);
    peer =
        std::make_unique<ApplicationURLLoader::RequestPeerImpl>(this, discard_body);
  //}

  if (sync_load_response) {
    DCHECK(defers_loading_ == NOT_DEFERRING);

    blink::mojom::BlobRegistryPtrInfo download_to_blob_registry;
    if (request.PassResponsePipeToClient()) {
      blink::Platform::Current()->GetInterfaceProvider()->GetInterface(
          MakeRequest(&download_to_blob_registry));
    }
    resource_dispatcher_->StartSync(
        std::move(resource_request), request.RequestorID(),
        GetTrafficAnnotationTag(request), sync_load_response,
        url_loader_factory_, {}, //extra_data->TakeURLLoaderThrottles(),
        request.TimeoutInterval(), std::move(download_to_blob_registry),
        std::move(peer));
    return;
  }

  TRACE_EVENT_WITH_FLOW0("loading", "ApplicationURLLoader::Context::Start", this,
                         TRACE_EVENT_FLAG_FLOW_OUT);
  base::OnceClosure continue_navigation_function;
  request_id_ = resource_dispatcher_->StartAsync(
      std::move(resource_request), request.RequestorID(), task_runner_,
      GetTrafficAnnotationTag(request), false /* is_sync */,
      request.PassResponsePipeToClient(), std::move(peer), url_loader_factory_,
      {}, //extra_data->TakeURLLoaderThrottles(), 
      std::move(response_override),
      &continue_navigation_function);
  //extra_data->set_continue_navigation_function(
  //    std::move(continue_navigation_function));

  if (defers_loading_ != NOT_DEFERRING)
    resource_dispatcher_->SetDefersLoading(request_id_, true);
}

void ApplicationURLLoader::Context::OnUploadProgress(uint64_t position,
                                                     uint64_t size) {
  if (client_)
    client_->DidSendData(position, size);
}

bool ApplicationURLLoader::Context::OnReceivedRedirect(
    const net::RedirectInfo& redirect_info,
    const network::ResourceResponseInfo& info) {
  if (!client_)
    return false;

  TRACE_EVENT_WITH_FLOW0(
      "loading", "ApplicationURLLoader::Context::OnReceivedRedirect",
      this, TRACE_EVENT_FLAG_FLOW_IN | TRACE_EVENT_FLAG_FLOW_OUT);

  blink::WebURLResponse response;
  ApplicationURLLoader::PopulateURLResponse(url_, info, &response, report_raw_headers_);

  url_ = blink::WebURL(blink::KURL(String::FromUTF8(redirect_info.new_url.possibly_invalid_spec().data())));
  return client_->WillFollowRedirect(
      url_, 
      blink::KURL(String::FromUTF8(redirect_info.new_site_for_cookies.possibly_invalid_spec().data())),
      blink::WebString::FromUTF8(redirect_info.new_referrer),
      common::Referrer::NetReferrerPolicyToBlinkReferrerPolicy(
          redirect_info.new_referrer_policy),
      blink::WebString::FromUTF8(redirect_info.new_method), response,
      report_raw_headers_);
}

void ApplicationURLLoader::Context::OnReceivedResponse(
    const network::ResourceResponseInfo& info) {
  //DLOG(INFO) << "ApplicationURLLoader::Context::OnReceivedResponse";
  if (!client_)
    return;

  TRACE_EVENT_WITH_FLOW0(
      "loading", "ApplicationURLLoader::Context::OnReceivedResponse",
      this, TRACE_EVENT_FLAG_FLOW_IN | TRACE_EVENT_FLAG_FLOW_OUT);

  blink::WebURLResponse response;
  ApplicationURLLoader::PopulateURLResponse(url_, info, &response, report_raw_headers_);

  //bool show_raw_listing = false;
  //if (info.mime_type == "text/vnd.chromium.ftp-dir") {
  //  if (GURL(url_).query_piece() == "raw") {
  //    // Set the MIME type to plain text to prevent any active content.
  //    response.SetMIMEType("text/plain");
  //    show_raw_listing = true;
  //  } else {
  //    // We're going to produce a parsed listing in HTML.
  //    response.SetMIMEType("text/html");
  //  }
  //}
  if (info.headers.get() && info.mime_type == "multipart/x-mixed-replace") {
    std::string content_type;
    info.headers->EnumerateHeader(nullptr, "content-type", &content_type);

    std::string mime_type;
    std::string charset;
    bool had_charset = false;
    std::string boundary;
    net::HttpUtil::ParseContentType(content_type, &mime_type, &charset,
                                    &had_charset, &boundary);
    base::TrimString(boundary, " \"", &boundary);
    response.SetMultipartBoundary(boundary.data(), boundary.size());
  }

 // //DLOG(INFO) << "ApplicationURLLoader::Context::OnReceivedResponse: handlers = " << handler_chain_.size();
  for (auto it = handler_chain_.begin(); it != handler_chain_.end(); ++it) {
    ResponseHandler* handler = it->second.get();
   // //DLOG(INFO) << "ApplicationURLLoader::Context::OnReceivedResponse: calling WillHandleResponse() on handler =" << handler;
    if (handler->WillHandleResponse(&response)) {
     // //DLOG(INFO) << "ApplicationURLLoader::Context::OnReceivedResponse: WillHandleResponse() = true";
      current_handler_ = handler;
      break;
    }
  }

  if (use_stream_on_response_) {
//   //DLOG(INFO) << "ApplicationURLLoader::Context::OnReceivedResponse: use_stream_on_response_ = true";
  
    SharedMemoryDataConsumerHandle::BackpressureMode mode =
        SharedMemoryDataConsumerHandle::kDoNotApplyBackpressure;
    if (info.headers &&
        info.headers->HasHeaderValue("Cache-Control", "no-store")) {
      mode = SharedMemoryDataConsumerHandle::kApplyBackpressure;
    }

    auto read_handle = std::make_unique<SharedMemoryDataConsumerHandle>(
        mode, base::Bind(&Context::CancelBodyStreaming, this),
        &body_stream_writer_);

    // Here |body_stream_writer_| has an indirect reference to |this| and that
    // creates a reference cycle, but it is not a problem because the cycle
    // will break if one of the following happens:
    //  1) The body data transfer is done (with or without an error).
    //  2) |read_handle| (and its reader) is detached.
    //DLOG(INFO) << "ApplicationURLLoader::Context::OnReceivedResponse: use_stream_on_response_ = true => client_->DidReceiveResponse() with handle";
    client_->DidReceiveResponse(response, std::move(read_handle));
    // TODO(yhirano): Support ftp listening and multipart
    return;
  } //else {
    //DLOG(INFO) << "ApplicationURLLoader::Context::OnReceivedResponse: use_stream_on_response_ = false";
    
  //}

  client_->DidReceiveResponse(response);

  // DidReceiveResponse() may have triggered a cancel, causing the |client_| to
  // go away.
  if (!client_)
    return;

  //DCHECK(!ftp_listing_delegate_);
  //if (info.mime_type == "text/vnd.chromium.ftp-dir" && !show_raw_listing) {
  //  ftp_listing_delegate_ =
  //      std::make_unique<FtpDirectoryListingResponseDelegate>(client_, loader_,
  //                                                            response);
  //}
}

void ApplicationURLLoader::Context::OnStartLoadingResponseBody(
    mojo::ScopedDataPipeConsumerHandle body) {
  //DLOG(INFO) << "ApplicationURLLoader::Context::OnStartLoadingResponseBody";
  if (client_)
    client_->DidStartLoadingResponseBody(std::move(body));
}

void ApplicationURLLoader::Context::OnDownloadedData(int len,
                                                     int encoded_data_length) {
  if (client_)
    client_->DidDownloadData(len, encoded_data_length);
}

void ApplicationURLLoader::Context::OnReceivedData(
    std::unique_ptr<ReceivedData> data) {
//DLOG(INFO) << "\nApplicationURLLoader::Context::OnReceivedData: len = " << data->length();
  
  if (!client_)
    return;

  TRACE_EVENT_WITH_FLOW0(
      "loading", "ApplicationURLLoader::Context::OnReceivedData",
      this, TRACE_EVENT_FLAG_FLOW_IN | TRACE_EVENT_FLAG_FLOW_OUT);

  //if (ftp_listing_delegate_) {
    // The FTP listing delegate will make the appropriate calls to
    // client_->didReceiveData and client_->didReceiveResponse.
  //  ftp_listing_delegate_->OnReceivedData(payload, data_length);
  //  return;
  //}

  // we have some sort of trasform into the incoming data..
  if (current_handler_) { 
    std::unique_ptr<RequestPeer::ReceivedData> output_data;
    // If this is not streamed output and the this is a partial input payload
    // we expect to receive a IO_PENDING here, so we just call it again

    // int start_offset = 0;
    // int piece_size = 16384;

    // const uint8_t* offset_ptr = reinterpret_cast<const uint8_t*>(data->payload());
    // int pieces = (data->length() / piece_size);
    // int rest = data->length() - (pieces * piece_size);
    // bool haveRest = rest > 0;
    // if (haveRest) {
    //   pieces += 1;
    // }
    // for (int x = 0; x < pieces; ++x) {
    //   start_offset = x * piece_size;
    //   offset_ptr += start_offset;
    //   int size = x == (pieces - 1) && haveRest ? rest : piece_size;
    //   printf("\ndecoding reply %d of %d. offset: %d size: %d\n", x + 1, pieces, start_offset, size);

    //   for (int z = 0; z < size; z++) {
    //     printf("[%u]", *(offset_ptr + z));
    //     if (z % 40 == 0) {
    //       printf("\n");
    //     }
    //   }
    // }

    int r = current_handler_->OnDataAvailable(data->payload(), data->length());
    //bool is_streaming_output = current_handler_->CanStreamOutput();
    // here IO_PENDING + streaming_output -> deliver
    // OK -> deliver
    if (r == net::OK || (r == net::ERR_IO_PENDING)) { //&& is_streaming_output)) {
      output_data = current_handler_->GetResult();
    } else { // this is an actual error
      // how we should proceed here?
      LOG(ERROR) << "ResponseHandler::OnDataAvailable: returned error = " << r;
    }
    if (output_data) {
      client_->DidReceiveData(output_data->payload(), output_data->length());
      if (use_stream_on_response_) {
       // LOG(INFO) << "ResponseHandler::OnDataAvailable: use_stream_on_response_ = true => repassing transformed data of " << output_data->length() << " bytes";
        body_stream_writer_->AddData(std::move(output_data));
      }
    }
    // this is the end-of-line for output_data
  } else {
    client_->DidReceiveData(data->payload(), data->length());
    if (use_stream_on_response_) {
      //LOG(INFO) << "ResponseHandler::OnDataAvailable: use_stream_on_response_ = true => repassing data of " << data->length() << " bytes";
      body_stream_writer_->AddData(std::move(data));
    }
  }
}

void ApplicationURLLoader::Context::OnTransferSizeUpdated(int transfer_size_diff) {
  client_->DidReceiveTransferSizeUpdate(transfer_size_diff);
}

void ApplicationURLLoader::Context::OnReceivedCachedMetadata(
    const char* data, int len) {
  //DLOG(INFO) << "ApplicationURLLoader::Context::OnReceivedCachedMetadata";
  if (!client_)
    return;
  TRACE_EVENT_WITH_FLOW0(
      "loading", "ApplicationURLLoader::Context::OnReceivedCachedMetadata",
      this, TRACE_EVENT_FLAG_FLOW_IN | TRACE_EVENT_FLAG_FLOW_OUT);
  client_->DidReceiveCachedMetadata(data, len);
}

void ApplicationURLLoader::Context::OnCompletedRequest(
    const network::URLLoaderCompletionStatus& status) {
  int64_t total_transfer_size = status.encoded_data_length;
  int64_t encoded_body_size = status.encoded_body_length;
  //DLOG(INFO) << "ApplicationURLLoader::Context::OnCompletedRequest";
  //if (ftp_listing_delegate_) {
  //  ftp_listing_delegate_->OnCompletedRequest();
  //  ftp_listing_delegate_.reset(nullptr);
  //}

  if (body_stream_writer_ && status.error_code != net::OK)
    body_stream_writer_->Fail();
  body_stream_writer_.reset();

  if (current_handler_) {
    int r = current_handler_->OnFinishLoading(status.error_code, encoded_body_size);//total_transfer_size);
    if (r != net::OK && r != net::ERR_IO_PENDING) {
      //DLOG(ERROR) << "handler OnFinishLoading() error = " << r;
    }
  }

  if (client_) {
    TRACE_EVENT_WITH_FLOW0(
        "loading", "ApplicationURLLoader::Context::OnCompletedRequest",
        this, TRACE_EVENT_FLAG_FLOW_IN);

    if (status.error_code != net::OK) {
      const blink::WebURLError::HasCopyInCache has_copy_in_cache =
          status.exists_in_cache ? blink::WebURLError::HasCopyInCache::kTrue
                                 : blink::WebURLError::HasCopyInCache::kFalse;
      client_->DidFail(
          status.cors_error_status
              ? blink::WebURLError(*status.cors_error_status, has_copy_in_cache, url_)
              : blink::WebURLError(status.error_code, status.extended_error_code,
                            has_copy_in_cache,
                            blink::WebURLError::IsWebSecurityViolation::kFalse, url_),
          total_transfer_size, encoded_body_size, status.decoded_body_length);
    } else {
    //  //DLOG(INFO) << "ApplicationURLLoader::Context::OnCompletedRequest: client_->DidFinishLoading()";
      client_->DidFinishLoading(status.completion_time.ToInternalValue(), total_transfer_size,
                                encoded_body_size, status.decoded_body_length,
                                status.blocked_cross_site_document);
    }
  }
}

ApplicationURLLoader::Context::~Context() {
  //DLOG(INFO) << "ApplicationURLLoader::Context::~Context";
  // We must be already cancelled at this point.
  DCHECK_LT(request_id_, 0);
}

void ApplicationURLLoader::Context::CancelBodyStreaming() {
  //DLOG(INFO) << "ApplicationURLLoader::Context::CancelBodyStreaming()";
  scoped_refptr<Context> protect(this);

  // Notify renderer clients that the request is canceled.
  //if (ftp_listing_delegate_) {
  //  ftp_listing_delegate_->OnCompletedRequest();
  //  ftp_listing_delegate_.reset(nullptr);
  //}

  if (body_stream_writer_) {
    body_stream_writer_->Fail();
    body_stream_writer_.reset();
  }
  if (client_) {
    // TODO(yhirano): Set |stale_copy_in_cache| appropriately if possible.
    client_->DidFail(blink::WebURLError(net::ERR_ABORTED, url_),
                     blink::WebURLLoaderClient::kUnknownEncodedDataLength, 0, 0);
  }

  // Notify the browser process that the request is canceled.
  Cancel();
}

bool ApplicationURLLoader::Context::CanHandleDataURLRequestLocally(
    const blink::WebURLRequest& request) const {
  // //DLOG(INFO) << "ApplicationURLLoader::Context::CanHandleDataURLRequestLocally";   
  if (!request.Url().ProtocolIs(url::kDataScheme))
    return false;

  // The fast paths for data URL, Start() and HandleDataURL(), don't support
  // the downloadToFile option.
  if (request.DownloadToFile() || request.PassResponsePipeToClient())
    return false;

  // Data url requests from object tags may need to be intercepted as streams
  // and so need to be sent to the browser.
  if (request.GetRequestContext() == blink::WebURLRequest::kRequestContextObject)
    return false;

  // Optimize for the case where we can handle a data URL locally.  We must
  // skip this for data URLs targetted at frames since those could trigger a
  // download.
  //
  // NOTE: We special case MIME types we can render both for performance
  // reasons as well as to support unit tests.

#if defined(OS_ANDROID)
  // For compatibility reasons on Android we need to expose top-level data://
  // to the browser. In tests resource_dispatcher_ can be null, and test pages
  // need to be loaded locally.
  // For PlzNavigate, navigation requests were already checked in the browser.
  if (resource_dispatcher_ &&
      request.GetFrameType() ==
          network::mojom::RequestContextFrameType::kTopLevel) {
    if (!IsBrowserSideNavigationEnabled())
      return false;
  }
#endif

  if (request.GetFrameType() !=
          network::mojom::RequestContextFrameType::kTopLevel &&
      request.GetFrameType() !=
          network::mojom::RequestContextFrameType::kNested)
    return true;

  std::string mime_type, unused_charset;
  GURL gurl(request.Url().GetString().Utf8().data(), request.Url().GetParsed(), request.Url().IsValid());
  if (net::DataURL::Parse(gurl, &mime_type, &unused_charset,
                          nullptr) &&
      blink::IsSupportedMimeType(mime_type))
    return true;

  return false;
}

void ApplicationURLLoader::Context::HandleDataURL() {
  //DLOG(INFO) << "ApplicationURLLoader::Context::HandleDataURL";   
  DCHECK_NE(defers_loading_, DEFERRED_DATA);
  if (defers_loading_ == SHOULD_DEFER) {
      defers_loading_ = DEFERRED_DATA;
      return;
  }

  network::ResourceResponseInfo info;
  std::string data;
  GURL gurl(url_.GetString().Utf8().data(), url_.GetParsed(), url_.IsValid());
  int error_code = GetInfoFromDataURL(gurl, &info, &data);

  if (error_code == net::OK) {
    OnReceivedResponse(info);
    auto size = data.size();
    if (size != 0)
      OnReceivedData(std::make_unique<FixedReceivedData>(data.data(), size));
  }

  network::URLLoaderCompletionStatus status(error_code);
  status.encoded_body_length = data.size();
  status.decoded_body_length = data.size();
  OnCompletedRequest(status);
}

void ApplicationURLLoader::PopulateURLResponse(
    const blink::WebURL& url,
    const network::ResourceResponseInfo& info,
    blink::WebURLResponse* response,
    bool report_security_info) {
  
  GURL gurl(url.GetString().Utf8().data(), url.GetParsed(), url.IsValid());

  response->SetURL(url);
  response->SetResponseTime(info.response_time);
  response->SetMIMEType(blink::WebString::FromUTF8(info.mime_type));
  response->SetTextEncodingName(blink::WebString::FromUTF8(info.charset));
  response->SetExpectedContentLength(info.content_length);
  response->SetHasMajorCertificateErrors(
      net::IsCertStatusError(info.cert_status) &&
      !net::IsCertStatusMinorError(info.cert_status));
  response->SetCTPolicyCompliance(info.ct_policy_compliance);
  response->SetIsLegacySymantecCert(info.is_legacy_symantec_cert);
  response->SetAppCacheID(info.appcache_id);
  blink::KURL appcache_url(info.appcache_manifest_url.possibly_invalid_spec().data());
  response->SetAppCacheManifestURL(appcache_url);
  response->SetWasCached(!info.load_timing.request_start_time.is_null() &&
                         info.response_time <
                             info.load_timing.request_start_time);
  response->SetRemoteIPAddress(
      blink::WebString::FromUTF8(info.socket_address.HostForURL()));
  response->SetRemotePort(info.socket_address.port());
  response->SetConnectionID(info.load_timing.socket_log_id);
  response->SetConnectionReused(info.load_timing.socket_reused);
  response->SetDownloadFilePath(
      blink::FilePathToWebString(info.download_file_path));
  response->SetWasFetchedViaSPDY(info.was_fetched_via_spdy);
  response->SetWasFetchedViaServiceWorker(info.was_fetched_via_service_worker);
  response->SetWasFallbackRequiredByServiceWorker(
      info.was_fallback_required_by_service_worker);
  response->SetResponseTypeViaServiceWorker(
      info.response_type_via_service_worker);     
  response->SetURLListViaServiceWorker(ToKURLVector(info.url_list_via_service_worker));
  response->SetCacheStorageCacheName(
      info.is_in_cache_storage
          ? blink::WebString::FromUTF8(info.cache_storage_cache_name)
          : blink::WebString());
  blink::WebVector<blink::WebString> cors_exposed_header_names(
      info.cors_exposed_header_names.size());
  std::transform(
      info.cors_exposed_header_names.begin(),
      info.cors_exposed_header_names.end(), cors_exposed_header_names.begin(),
      [](const std::string& h) { return blink::WebString::FromLatin1(h); });
  response->SetCorsExposedHeaderNames(cors_exposed_header_names);
  response->SetDidServiceWorkerNavigationPreload(
      info.did_service_worker_navigation_preload);
  response->SetEncodedDataLength(info.encoded_data_length);
  response->SetAlpnNegotiatedProtocol(
      blink::WebString::FromUTF8(info.alpn_negotiated_protocol));
  response->SetConnectionInfo(info.connection_info);

  SetSecurityStyleAndDetails(gurl, info, response, report_security_info);

  blink::WebString header_name = blink::WebString::FromLatin1(
    blink::HTTPNames::Allow_CSP_From.Characters8(), blink::HTTPNames::Allow_CSP_From.length());
  response->SetHTTPHeaderField(header_name, blink::WebString("*"));
    
  //WebURLResponseExtraDataImpl* extra_data = new WebURLResponseExtraDataImpl();
  //response->SetExtraData(extra_data);
  //extra_data->set_was_fetched_via_spdy(info.was_fetched_via_spdy);
  //extra_data->set_was_alpn_negotiated(info.was_alpn_negotiated);
  //extra_data->set_was_alternate_protocol_available(
  //    info.was_alternate_protocol_available);
  //extra_data->set_previews_state(
  //    static_cast<PreviewsState>(info.previews_state));
  //extra_data->set_effective_connection_type(info.effective_connection_type);

  // If there's no received headers end time, don't set load timing.  This is
  // the case for non-HTTP requests, requests that don't go over the wire, and
  // certain error cases.
  if (!info.load_timing.receive_headers_end.is_null()) {
    blink::WebURLLoadTiming timing;
    PopulateURLLoadTiming(info.load_timing, &timing);
    timing.SetWorkerStart(info.service_worker_start_time.ToInternalValue());
    timing.SetWorkerReady(info.service_worker_ready_time.ToInternalValue());
    response->SetLoadTiming(timing);
  }

  if (info.raw_request_response_info.get()) {
    blink::WebHTTPLoadInfo load_info;

    load_info.SetHTTPStatusCode(
        info.raw_request_response_info->http_status_code);
    load_info.SetHTTPStatusText(blink::WebString::FromLatin1(
        info.raw_request_response_info->http_status_text));

    load_info.SetRequestHeadersText(blink::WebString::FromLatin1(
        info.raw_request_response_info->request_headers_text));
    load_info.SetResponseHeadersText(blink::WebString::FromLatin1(
        info.raw_request_response_info->response_headers_text));
    const HeadersVector& request_headers =
        info.raw_request_response_info->request_headers;
    for (HeadersVector::const_iterator it = request_headers.begin();
         it != request_headers.end(); ++it) {
      load_info.AddRequestHeader(blink::WebString::FromLatin1(it->first),
                                 blink::WebString::FromLatin1(it->second));
    }
    const HeadersVector& response_headers =
        info.raw_request_response_info->response_headers;
    for (HeadersVector::const_iterator it = response_headers.begin();
         it != response_headers.end(); ++it) {
      load_info.AddResponseHeader(blink::WebString::FromLatin1(it->first),
                                  blink::WebString::FromLatin1(it->second));
    }
    load_info.SetNPNNegotiatedProtocol(
        blink::WebString::FromLatin1(info.alpn_negotiated_protocol));
    response->SetHTTPLoadInfo(load_info);
  }

  const net::HttpResponseHeaders* headers = info.headers.get();
  if (!headers)
    return;

  blink::WebURLResponse::HTTPVersion version = blink::WebURLResponse::kHTTPVersionUnknown;
  if (headers->GetHttpVersion() == net::HttpVersion(0, 9))
    version = blink::WebURLResponse::kHTTPVersion_0_9;
  else if (headers->GetHttpVersion() == net::HttpVersion(1, 0))
    version = blink::WebURLResponse::kHTTPVersion_1_0;
  else if (headers->GetHttpVersion() == net::HttpVersion(1, 1))
    version = blink::WebURLResponse::kHTTPVersion_1_1;
  else if (headers->GetHttpVersion() == net::HttpVersion(2, 0))
    version = blink::WebURLResponse::kHTTPVersion_2_0;
  response->SetHTTPVersion(version);
  response->SetHTTPStatusCode(headers->response_code());
  response->SetHTTPStatusText(blink::WebString::FromLatin1(headers->GetStatusText()));

  // Build up the header map.
  size_t iter = 0;
  std::string name;
  std::string value;
  while (headers->EnumerateHeaderLines(&iter, &name, &value)) {
    response->AddHTTPHeaderField(blink::WebString::FromLatin1(name),
                                 blink::WebString::FromLatin1(value));
  }
}

ApplicationURLLoader::ApplicationURLLoader(
  ResourceDispatcher* resource_dispatcher,
  scoped_refptr<base::SingleThreadTaskRunner> task_runner,
  scoped_refptr<network::SharedURLLoaderFactory> url_loader_factory,
  CBlinkPlatformCallbacks callbacks,
  void* url_loader_state):
   context_(new Context(this,
                        resource_dispatcher,
                        std::move(task_runner),
                        std::move(url_loader_factory))),
   callbacks_(callbacks),
   url_loader_state_(url_loader_state) {
  
}

ApplicationURLLoader::ApplicationURLLoader(
  ResourceDispatcher* resource_dispatcher,
  scoped_refptr<base::SingleThreadTaskRunner> task_runner,
  scoped_refptr<network::SharedURLLoaderFactory> url_loader_factory):
   context_(new Context(this,
                        resource_dispatcher,
                        std::move(task_runner),
                        url_loader_factory)),
   //callbacks_(nullptr),
   url_loader_state_(nullptr) {
  memset(&callbacks_, 0, sizeof(CBlinkPlatformCallbacks));
  DCHECK(false);
}

ApplicationURLLoader::~ApplicationURLLoader() {
  //DLOG(INFO) << "~ApplicationURLLoader";
  Cancel();
  url_loader_state_ = nullptr;
}

void ApplicationURLLoader::AddHandler(std::unique_ptr<ResponseHandler> handler) {
 // //DLOG(INFO) << "ApplicationURLLoader::AddHandler";   
  context_->AddHandler(std::move(handler)); 
}

void ApplicationURLLoader::LoadSynchronously(
  const blink::WebURLRequest&,
  blink::WebURLResponse&,
  base::Optional<blink::WebURLError>&,
  blink::WebData&,
  int64_t& encoded_data_length,
  int64_t& encoded_body_length,
  base::Optional<int64_t>& downloaded_file_length,
  blink::WebBlobInfo& downloaded_blob) {
	//DLOG(INFO) << "ApplicationURLLoader::LoadSynchronously";
  // if (callbacks_.URLLoaderLoadSynchronously)
  //  callbacks_.URLLoaderLoadSynchronously(url_loader_state_);
}

void ApplicationURLLoader::LoadAsynchronously(
	const blink::WebURLRequest& request,
    blink::WebURLLoaderClient* client) {
 // //DLOG(INFO) << "ApplicationURLLoader::LoadAsynchronously: forcing a NoCORS policy";
	//blink::WebURLRequest local_request(request);
  //local_request.SetFetchRequestMode(network::mojom::FetchRequestMode::kNoCORS);
  //std::string ext;
  // FIXME:
  // GURL url(local_request.Url());
  // std::string filename = url.ExtractFileName();
  // if (!filename.empty()) {
  //   size_t offset = filename.find_first_of(".");
  //   if (offset != std::string::npos) {
  //     ext = filename.substr(offset + 1);
  //     if (ext == "css") {
  //       local_request.SetUseStreamOnResponse(true);
  //     }
  //   }
  // }

  //DLOG(INFO) << "ApplicationURLLoader::LoadAsynchronously: url: '" << local_request.Url() << " UseStreamOnResponse? " << local_request.UseStreamOnResponse();
	//blink::WebURLResponse response;
	
	//PopulateBogusURLResponse(request.Url(), &response);
	//client->DidReceiveResponse(response);
	
  //client->DidReceiveData(kBodyContent, arraysize(kBodyContent));
	//client->DidReceiveCachedMetadata(kBodyContent, arraysize(kBodyContent));
  //client->DidFinishLoading(0.1, 
	//					               blink::WebURLLoaderClient::kUnknownEncodedDataLength,//arraysize(kBodyContent), // we should have header size
  //                         0,//arraysize(kBodyContent), 
  //                         arraysize(kBodyContent),
  //                         false);
	//callbacks_.URLLoaderLoadAsynchronously(url_loader_state_);
  context_->set_client(client);
  context_->Start(request, nullptr);
}

void ApplicationURLLoader::Cancel() {
	//DLOG(INFO) << "ApplicationURLLoader::Cancel";
	// if (callbacks_.URLLoaderCancel) {
  //   callbacks_.URLLoaderCancel(url_loader_state_);
  // }
  context_->Cancel();
}

// Suspends/resumes an asynchronous load.
void ApplicationURLLoader::SetDefersLoading(bool defers) {
  // if (callbacks_.URLLoaderSetDefersLoading) {
	//   callbacks_.URLLoaderSetDefersLoading(url_loader_state_, defers);
  // }
  context_->SetDefersLoading(defers);
}

void ApplicationURLLoader::DidChangePriority(
	blink::WebURLRequest::Priority new_priority,
    int intra_priority_value) {
	//DLOG(INFO) << "ApplicationURLLoader::DidChangePriority. nothing here";
  // if (callbacks_.URLLoaderDidChangePriority) {
	//   callbacks_.URLLoaderDidChangePriority(url_loader_state_);
  // }
  context_->DidChangePriority(new_priority, intra_priority_value);
}

// ApplicationURLLoaderFactory::ApplicationURLLoaderFactory(
//     base::WeakPtr<ResourceDispatcher> resource_dispatcher,
//     scoped_refptr<network::SharedURLLoaderFactory> loader_factory,
//     CBlinkPlatformCallbacks callbacks,
//     void* url_loader_state)
//     : resource_dispatcher_(std::move(resource_dispatcher)),
//       loader_factory_(std::move(loader_factory)),
//       callbacks_(callbacks),
//       url_loader_state_(url_loader_state),
//       window_dispatcher_(nullptr) {}

// ApplicationURLLoaderFactory::ApplicationURLLoaderFactory(
//     base::WeakPtr<ResourceDispatcher> resource_dispatcher,
//     scoped_refptr<network::SharedURLLoaderFactory> loader_factory)
//     : resource_dispatcher_(std::move(resource_dispatcher)),
//       loader_factory_(std::move(loader_factory)),
//       //callbacks_(nullptr),
//       url_loader_state_(nullptr),
//       window_dispatcher_(nullptr) {

// }

ApplicationURLLoaderFactory::ApplicationURLLoaderFactory(
    base::WeakPtr<ResourceDispatcher> resource_dispatcher,
    scoped_refptr<network::SharedURLLoaderFactory> loader_factory,
    ApplicationWindowDispatcher* window_dispatcher):
     resource_dispatcher_(std::move(resource_dispatcher)),
     loader_factory_(std::move(loader_factory)),
     url_loader_state_(nullptr),
     window_dispatcher_(window_dispatcher),
     callbacks_set_(false) {

}

ApplicationURLLoaderFactory::ApplicationURLLoaderFactory(
    base::WeakPtr<ResourceDispatcher> resource_dispatcher,
    scoped_refptr<network::SharedURLLoaderFactory> loader_factory,
    CBlinkPlatformCallbacks callbacks,
    ApplicationWindowDispatcher* window_dispatcher):
     resource_dispatcher_(std::move(resource_dispatcher)),
     loader_factory_(std::move(loader_factory)),
     callbacks_(callbacks),
     url_loader_state_(nullptr),
     window_dispatcher_(window_dispatcher),
     callbacks_set_(true) {

}

ApplicationURLLoaderFactory::~ApplicationURLLoaderFactory() {

}

std::unique_ptr<blink::WebURLLoader> ApplicationURLLoaderFactory::CreateURLLoader(
	const blink::WebURLRequest& request,
	scoped_refptr<base::SingleThreadTaskRunner> task_runner) {	
  //DLOG(INFO) << "ApplicationURLLoaderFactory::CreateURLLoader";

  if (!window_dispatcher_) {
    DCHECK(false);
    return std::unique_ptr<blink::WebURLLoader>();
  }

  CBlinkPlatformCallbacks null_callbacks_;

  CBlinkPlatformCallbacks* cbs_ptr = callbacks_set_ ? &null_callbacks_ : &callbacks_;

  url_loader_state_ = window_dispatcher_->CreateURLLoader(
    const_cast<blink::WebURLRequest *>(&request),
    cbs_ptr);

  auto loader = std::make_unique<application::ApplicationURLLoader>(
    resource_dispatcher_.get(),
    task_runner,
    loader_factory_,
    *cbs_ptr, 
    url_loader_state_);

  int resp_handler_count = window_dispatcher_->CountResponseHandler();//callbacks_.CountResponseHandler(state_);
//DLOG(INFO) << "WebServiceWorkerNetworkProviderImpl: CountResponseHandler = " << resp_handler_count;
  for (int i = 0; i < resp_handler_count; i++) {
    CResponseHandler handler;
//    LOG(INFO) << "WebServiceWorkerNetworkProviderImpl: getting response handler" << i;
    void* handler_state = window_dispatcher_->GetResponseHandlerAt(//callbacks_.GetResponseHandlerAt(
    i,
    &handler);
    if (handler_state) {
//DLOG(INFO) << "WebServiceWorkerNetworkProviderImpl: adding response handler " << i << " to url loader";
      loader->AddHandler(std::make_unique<ApplicationResponseHandler>(
        handler_state,
        std::move(handler)));
    }
  }
  return loader;
}

// static
// We have this function at the bottom of this file because it confuses
// syntax highliting.
net::NetworkTrafficAnnotationTag
ApplicationURLLoader::Context::GetTrafficAnnotationTag(
    const blink::WebURLRequest& request) {
  switch (request.GetRequestContext()) {
    case blink::WebURLRequest::kRequestContextUnspecified:
    case blink::WebURLRequest::kRequestContextAudio:
    case blink::WebURLRequest::kRequestContextBeacon:
    case blink::WebURLRequest::kRequestContextCSPReport:
    case blink::WebURLRequest::kRequestContextDownload:
    case blink::WebURLRequest::kRequestContextEventSource:
    case blink::WebURLRequest::kRequestContextFetch:
    case blink::WebURLRequest::kRequestContextFont:
    case blink::WebURLRequest::kRequestContextForm:
    case blink::WebURLRequest::kRequestContextFrame:
    case blink::WebURLRequest::kRequestContextHyperlink:
    case blink::WebURLRequest::kRequestContextIframe:
    case blink::WebURLRequest::kRequestContextImage:
    case blink::WebURLRequest::kRequestContextImageSet:
    case blink::WebURLRequest::kRequestContextImport:
    case blink::WebURLRequest::kRequestContextInternal:
    case blink::WebURLRequest::kRequestContextLocation:
    case blink::WebURLRequest::kRequestContextManifest:
    case blink::WebURLRequest::kRequestContextPing:
    case blink::WebURLRequest::kRequestContextPrefetch:
    case blink::WebURLRequest::kRequestContextScript:
    case blink::WebURLRequest::kRequestContextServiceWorker:
    case blink::WebURLRequest::kRequestContextSharedWorker:
    case blink::WebURLRequest::kRequestContextSubresource:
    case blink::WebURLRequest::kRequestContextStyle:
    case blink::WebURLRequest::kRequestContextTrack:
    case blink::WebURLRequest::kRequestContextVideo:
    case blink::WebURLRequest::kRequestContextWorker:
    case blink::WebURLRequest::kRequestContextXMLHttpRequest:
    case blink::WebURLRequest::kRequestContextXSLT:
      return net::DefineNetworkTrafficAnnotation("blink_resource_loader", R"(
      semantics {
        sender: "Blink Resource Loader"
        description:
          "Blink-initiated request, which includes all resources for "
          "normal page loads, chrome URLs, and downloads."
        trigger:
          "The user navigates to a URL or downloads a file. Also when a "
          "webpage, ServiceWorker, or chrome:// uses any network communication."
        data: "Anything the initiator wants to send."
        destination: OTHER
      }
      policy {
        cookies_allowed: YES
        cookies_store: "user"
        setting: "These requests cannot be disabled in settings."
        policy_exception_justification:
          "Not implemented. Without these requests, Chrome will be unable "
          "to load any webpage."
      })");

    case blink::WebURLRequest::kRequestContextEmbed:
    case blink::WebURLRequest::kRequestContextObject:
    case blink::WebURLRequest::kRequestContextPlugin:
      return net::DefineNetworkTrafficAnnotation(
          "blink_extension_resource_loader", R"(
        semantics {
          sender: "Blink Resource Loader"
          description:
            "Blink-initiated request for resources required for NaCl instances "
            "tagged with <embed> or <object>, or installed extensions."
          trigger:
            "An extension or NaCl instance may initiate a request at any time, "
            "even in the background."
          data: "Anything the initiator wants to send."
          destination: OTHER
        }
        policy {
          cookies_allowed: YES
          cookies_store: "user"
          setting:
            "These requests cannot be disabled in settings, but they are "
            "sent only if user installs extensions."
          chrome_policy {
            ExtensionInstallBlacklist {
              ExtensionInstallBlacklist: {
                entries: '*'
              }
            }
          }
        })");

    case blink::WebURLRequest::kRequestContextFavicon:
      return net::DefineNetworkTrafficAnnotation("favicon_loader", R"(
        semantics {
          sender: "Blink Resource Loader"
          description:
            "Chrome sends a request to download favicon for a URL."
          trigger:
            "Navigating to a URL."
          data: "None."
          destination: WEBSITE
        }
        policy {
          cookies_allowed: YES
          cookies_store: "user"
          setting: "These requests cannot be disabled in settings."
          policy_exception_justification:
            "Not implemented."
        })");
  }

  return net::NetworkTrafficAnnotationTag::NotReached();
}

}