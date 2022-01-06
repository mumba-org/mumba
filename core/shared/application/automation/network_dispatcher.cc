// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/application/automation/network_dispatcher.h"

#define INSIDE_BLINK 1
#include "third_party/blink/renderer/bindings/core/v8/script_controller.h"
#include "third_party/blink/renderer/bindings/core/v8/script_regexp.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/document_timing.h"
#include "third_party/blink/renderer/core/dom/dom_implementation.h"
#include "third_party/blink/renderer/core/dom/user_gesture_indicator.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_client.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/frame/visual_viewport.h"
#include "third_party/blink/renderer/core/html/html_frame_owner_element.h"
#include "third_party/blink/renderer/core/html/imports/html_import_loader.h"
#include "third_party/blink/renderer/core/html/imports/html_imports_controller.h"
#include "third_party/blink/renderer/core/html/parser/text_resource_decoder.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/inspector/inspected_frames.h"
#include "third_party/blink/renderer/core/layout/adjust_for_absolute_zoom.h"
#include "third_party/blink/renderer/core/loader/document_loader.h"
#include "third_party/blink/renderer/core/loader/frame_loader.h"
#include "third_party/blink/renderer/core/loader/idleness_detector.h"
#include "third_party/blink/renderer/core/loader/resource/css_style_sheet_resource.h"
#include "third_party/blink/renderer/core/loader/resource/script_resource.h"
#include "third_party/blink/renderer/core/loader/scheduled_navigation.h"
#include "third_party/blink/renderer/core/loader/mixed_content_checker.h"
#include "third_party/blink/renderer/core/workers/worker_global_scope.h"
#include "third_party/blink/renderer/core/dom/scriptable_document_parser.h"
#include "third_party/blink/renderer/core/xmlhttprequest/xml_http_request.h"
#include "third_party/blink/renderer/platform/blob/blob_data.h"
#include "third_party/blink/public/platform/web_url_loader_client.h"
#include "third_party/blink/renderer/platform/loader/fetch/fetch_initiator_info.h"
#include "third_party/blink/renderer/platform/loader/fetch/fetch_initiator_type_names.h"
#include "third_party/blink/renderer/platform/loader/fetch/memory_cache.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_error.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_fetcher.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_load_timing.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_request.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_response.h"
#include "third_party/blink/renderer/platform/loader/fetch/unique_identifier.h"
#include "third_party/blink/renderer/platform/network/http_header_map.h"
#include "third_party/blink/renderer/platform/network/network_state_notifier.h"
#include "third_party/blink/renderer/platform/network/web_socket_handshake_request.h"
#include "third_party/blink/renderer/platform/network/web_socket_handshake_response.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/probe/core_probes.h"
#include "third_party/blink/renderer/core/style/computed_style.h"
#include "third_party/blink/renderer/core/inspector/identifiers_factory.h"
#include "third_party/blink/renderer/core/inspector/inspector_page_agent.h"
#include "third_party/blink/public/platform/web_private_ptr.h"
#include "third_party/blink/renderer/core/inspector/inspector_resource_content_loader.h"
#include "third_party/blink/renderer/platform/bindings/dom_wrapper_world.h"
#include "third_party/blink/renderer/platform/loader/fetch/memory_cache.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource.h"
#include "third_party/blink/renderer/core/fetch/response.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_fetcher.h"
#include "third_party/blink/renderer/platform/loader/fetch/text_resource_decoder_options.h"
#include "third_party/blink/renderer/platform/network/mime/mime_type_registry.h"
#include "third_party/blink/renderer/platform/weborigin/security_origin.h"
#include "third_party/blink/renderer/platform/wtf/text/base64.h"
#include "third_party/blink/renderer/platform/wtf/text/text_encoding.h"
#include "third_party/blink/renderer/platform/wtf/time.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"
#include "third_party/blink/renderer/platform/shared_buffer.h"
#include "third_party/blink/renderer/core/fileapi/file_reader_loader.h"
#include "third_party/blink/renderer/core/fileapi/file_reader_loader_client.h"
#include "third_party/blink/renderer/core/inspector/inspector_network_agent.h"
#include "third_party/blink/renderer/platform/weborigin/kurl.h"
#include "third_party/blink/renderer/core/inspector/network_resources_data.h"

#include "core/shared/application/application_window_dispatcher.h"
#include "core/shared/application/automation/page_instance.h"
#include "services/service_manager/public/cpp/binder_registry.h"
#include "services/service_manager/public/cpp/connector.h"
#include "services/service_manager/public/cpp/local_interface_provider.h"
#include "services/service_manager/public/cpp/service.h"
#include "services/service_manager/public/cpp/interface_provider.h"
#include "services/service_manager/public/mojom/connector.mojom.h"
#include "services/service_manager/public/mojom/interface_provider.mojom.h"
#include "ipc/ipc_sync_channel.h"

#pragma clang attribute push
#pragma clang diagnostic ignored "-Wignored-attributes"
#pragma clang diagnostic ignored "-Wunused-variable"
#pragma clang diagnostic ignored "-Wmacro-redefined"
#define V8_BASE_MACROS_H_
#define STATIC_ASSERT(test) static_assert(test, #test)
#include "v8/src/inspector/v8-regex.h"
#pragma clang attribute pop

namespace application {

namespace {

#if defined(OS_ANDROID)
// 10MB
static size_t g_maximum_total_buffer_size = 10 * 1000 * 1000;
// 5MB
static size_t g_maximum_resource_buffer_size = 5 * 1000 * 1000;
#else
// 100MB
static size_t g_maximum_total_buffer_size = 100 * 1000 * 1000;
// 10MB
static size_t g_maximum_resource_buffer_size = 10 * 1000 * 1000;
#endif

String BuildBlockedReason(blink::ResourceRequestBlockedReason reason) {
  switch (reason) {
    case blink::ResourceRequestBlockedReason::kCSP:
      return "csp";
    case blink::ResourceRequestBlockedReason::kMixedContent:
      return "mixed-content";
    case blink::ResourceRequestBlockedReason::kOrigin:
      return "origin";
    case blink::ResourceRequestBlockedReason::kInspector:
      return "inspector";
    case blink::ResourceRequestBlockedReason::kSubresourceFilter:
      return "subresource-filter";
    case blink::ResourceRequestBlockedReason::kOther:
      return "other";
    case blink::ResourceRequestBlockedReason::kNone:
    default:
      NOTREACHED();
      return "other";
  }
}

blink::WebConnectionType ToWebConnectionType(automation::ConnectionType connection_type) {
  if (connection_type == automation::ConnectionType::kCONNECTION_TYPE_NONE)
    return blink::kWebConnectionTypeNone;
  if (connection_type == automation::ConnectionType::kCONNECTION_TYPE_CELLULAR_2G)
    return blink::kWebConnectionTypeCellular2G;
  if (connection_type == automation::ConnectionType::kCONNECTION_TYPE_CELLULAR_3G)
    return blink::kWebConnectionTypeCellular3G;
  if (connection_type == automation::ConnectionType::kCONNECTION_TYPE_CELLULAR_4G)
    return blink::kWebConnectionTypeCellular4G;
  if (connection_type == automation::ConnectionType::kCONNECTION_TYPE_BLUETOOTH)
    return blink::kWebConnectionTypeBluetooth;
  if (connection_type == automation::ConnectionType::kCONNECTION_TYPE_ETHERNET)
    return blink::kWebConnectionTypeEthernet;
  if (connection_type == automation::ConnectionType::kCONNECTION_TYPE_WIFI)
    return blink::kWebConnectionTypeWifi;
  if (connection_type == automation::ConnectionType::kCONNECTION_TYPE_WIMAX)
    return blink::kWebConnectionTypeWimax;
  if (connection_type == automation::ConnectionType::kCONNECTION_TYPE_OTHER)
    return blink::kWebConnectionTypeOther;
  return blink::kWebConnectionTypeUnknown;
}

// static 
PageDispatcher::ResourceType ToResourceType(const blink::InspectorPageAgent::ResourceType resource_type) {
  switch (resource_type) {
    case blink::InspectorPageAgent::kDocumentResource:
      return PageDispatcher::kDocumentResource;
    case blink::InspectorPageAgent::kFontResource:
      return PageDispatcher::kFontResource;
    case blink::InspectorPageAgent::kImageResource:
      return PageDispatcher::kImageResource;
    case blink::InspectorPageAgent::kMediaResource:
      return PageDispatcher::kMediaResource;
    case blink::InspectorPageAgent::kScriptResource:
      return PageDispatcher::kScriptResource;
    case blink::InspectorPageAgent::kStylesheetResource:
      return PageDispatcher::kStylesheetResource;
    case blink::InspectorPageAgent::kTextTrackResource:
      return PageDispatcher::kTextTrackResource;
    case blink::InspectorPageAgent::kXHRResource:
      return PageDispatcher::kXHRResource;
    case blink::InspectorPageAgent::kFetchResource:
      return PageDispatcher::kFetchResource;
    case blink::InspectorPageAgent::kEventSourceResource:
      return PageDispatcher::kEventSourceResource;
    case blink::InspectorPageAgent::kWebSocketResource:
      return PageDispatcher::kWebSocketResource;
    case blink::InspectorPageAgent::kManifestResource:
      return PageDispatcher::kManifestResource;
    case blink::InspectorPageAgent::kOtherResource:
      return PageDispatcher::kOtherResource;
  }
  return PageDispatcher::kOtherResource;
}

// static 
blink::InspectorPageAgent::ResourceType ToResourceType(PageDispatcher::ResourceType resource_type) {
  switch (resource_type) {
    case PageDispatcher::kDocumentResource:
      return blink::InspectorPageAgent::kDocumentResource;
    case PageDispatcher::kFontResource:
      return blink::InspectorPageAgent::kFontResource;
    case PageDispatcher::kImageResource:
      return blink::InspectorPageAgent::kImageResource;
    case PageDispatcher::kMediaResource:
      return blink::InspectorPageAgent::kMediaResource;
    case PageDispatcher::kScriptResource:
      return blink::InspectorPageAgent::kScriptResource;
    case PageDispatcher::kStylesheetResource:
      return blink::InspectorPageAgent::kStylesheetResource;
    case PageDispatcher::kTextTrackResource:
      return blink::InspectorPageAgent::kTextTrackResource;
    case PageDispatcher::kXHRResource:
      return blink::InspectorPageAgent::kXHRResource;
    case PageDispatcher::kFetchResource:
      return blink::InspectorPageAgent::kFetchResource;
    case PageDispatcher::kEventSourceResource:
      return blink::InspectorPageAgent::kEventSourceResource;
    case PageDispatcher::kWebSocketResource:
      return blink::InspectorPageAgent::kWebSocketResource;
    case PageDispatcher::kManifestResource:
      return blink::InspectorPageAgent::kManifestResource;
    case PageDispatcher::kOtherResource:
      return blink::InspectorPageAgent::kOtherResource;
  }
  return blink::InspectorPageAgent::kOtherResource;
}

automation::MixedContentType MixedContentTypeForContextType(blink::WebMixedContentContextType context_type) {
  switch (context_type) {
    case blink::WebMixedContentContextType::kNotMixedContent:
      return automation::MixedContentType::kMIXED_CONTENT_TYPE_NONE;
    case blink::WebMixedContentContextType::kBlockable:
      return automation::MixedContentType::kMIXED_CONTENT_TYPE_BLOCKABLE;
    case blink::WebMixedContentContextType::kOptionallyBlockable:
    case blink::WebMixedContentContextType::kShouldBeBlockable:
      return automation::MixedContentType::kMIXED_CONTENT_TYPE_BLOCKABLE;
  }

  return automation::MixedContentType::kMIXED_CONTENT_TYPE_NONE;
}

bool LoadsFromCacheOnly(const blink::ResourceRequest& request) {
  switch (request.GetCacheMode()) {
    case blink::mojom::FetchCacheMode::kDefault:
    case blink::mojom::FetchCacheMode::kNoStore:
    case blink::mojom::FetchCacheMode::kValidateCache:
    case blink::mojom::FetchCacheMode::kBypassCache:
    case blink::mojom::FetchCacheMode::kForceCache:
      return false;
    case blink::mojom::FetchCacheMode::kOnlyIfCached:
    case blink::mojom::FetchCacheMode::kUnspecifiedOnlyIfCachedStrict:
    case blink::mojom::FetchCacheMode::kUnspecifiedForceCacheMiss:
      return true;
  }
  NOTREACHED();
  return false;
}

blink::KURL UrlWithoutFragment(const blink::KURL& url) {
  blink::KURL result = url;
  result.RemoveFragmentIdentifier();
  return result;
}

automation::BlockedReason ToBlockedReason(String reason) {
  if (reason == "csp") {
    return automation::BlockedReason::BLOCKED_REASON_CSP;
  }
  if (reason == "mixed-content") {
    return automation::BlockedReason::BLOCKED_REASON_MIXED_CONTENT;
  }
  if (reason == "origin") {
    return automation::BlockedReason::BLOCKED_REASON_ORIGIN;
  }
  if (reason == "inspector") {
    return automation::BlockedReason::BLOCKED_REASON_INSPECTOR;
  }
  if (reason == "subresource-filter") {
    return automation::BlockedReason::BLOCKED_REASON_SUBRESOURCE_FILTER;
  }
  if (reason == "other") {
    return automation::BlockedReason::BLOCKED_REASON_OTHER;
  }
  return automation::BlockedReason::BLOCKED_REASON_OTHER;
}

PageDispatcher::ResourceType FromInspectorPageAgentResourceType(blink::InspectorPageAgent::ResourceType type) {
  switch(type) {
    case blink::InspectorPageAgent::kDocumentResource:
      return PageDispatcher::kDocumentResource;
    case blink::InspectorPageAgent::kStylesheetResource:
      return PageDispatcher::kStylesheetResource;
    case blink::InspectorPageAgent::kImageResource:
      return PageDispatcher::kImageResource;
    case blink::InspectorPageAgent::kFontResource:
      return PageDispatcher::kFontResource;
    case blink::InspectorPageAgent::kMediaResource:
      return PageDispatcher::kMediaResource;
    case blink::InspectorPageAgent::kScriptResource:
      return PageDispatcher::kScriptResource;
    case blink::InspectorPageAgent::kTextTrackResource:
      return PageDispatcher::kTextTrackResource;
    case blink::InspectorPageAgent::kXHRResource:
      return PageDispatcher::kXHRResource;
    case blink::InspectorPageAgent::kFetchResource:
      return PageDispatcher::kFetchResource;
    case blink::InspectorPageAgent::kEventSourceResource:
      return PageDispatcher::kEventSourceResource;
    case blink::InspectorPageAgent::kWebSocketResource:
      return PageDispatcher::kWebSocketResource;
    case blink::InspectorPageAgent::kManifestResource:
      return PageDispatcher::kManifestResource;
    case blink::InspectorPageAgent::kOtherResource:
      return PageDispatcher::kOtherResource;
  }
  return PageDispatcher::kOtherResource;
}


blink::InspectorPageAgent::ResourceType ToInspectorPageAgentResourceType(PageDispatcher::ResourceType type) {
  switch(type) {
    case PageDispatcher::kDocumentResource:
      return blink::InspectorPageAgent::kDocumentResource;
    case PageDispatcher::kStylesheetResource:
      return blink::InspectorPageAgent::kStylesheetResource;
    case PageDispatcher::kImageResource:
      return blink::InspectorPageAgent::kImageResource;
    case PageDispatcher::kFontResource:
      return blink::InspectorPageAgent::kFontResource;
    case PageDispatcher::kMediaResource:
      return blink::InspectorPageAgent::kMediaResource;
    case PageDispatcher::kScriptResource:
      return blink::InspectorPageAgent::kScriptResource;
    case PageDispatcher::kTextTrackResource:
      return blink::InspectorPageAgent::kTextTrackResource;
    case PageDispatcher::kXHRResource:
      return blink::InspectorPageAgent::kXHRResource;
    case PageDispatcher::kFetchResource:
      return blink::InspectorPageAgent::kFetchResource;
    case PageDispatcher::kEventSourceResource:
      return blink::InspectorPageAgent::kEventSourceResource;
    case PageDispatcher::kWebSocketResource:
      return blink::InspectorPageAgent::kWebSocketResource;
    case PageDispatcher::kManifestResource:
      return blink::InspectorPageAgent::kManifestResource;
    case PageDispatcher::kOtherResource:
      return blink::InspectorPageAgent::kOtherResource;
  }
  return blink::InspectorPageAgent::kOtherResource;
}

v8_inspector::StringView ToV8InspectorStringView(const StringView& string) {
  if (string.IsNull())
    return v8_inspector::StringView();
  if (string.Is8Bit())
    return v8_inspector::StringView(
        reinterpret_cast<const uint8_t*>(string.Characters8()),
        string.length());
  return v8_inspector::StringView(
      reinterpret_cast<const uint16_t*>(string.Characters16()),
      string.length());
}

automation::ResourcePriority ResourcePriorityJSON(blink::ResourceLoadPriority priority) {
  switch (priority) {
    case blink::ResourceLoadPriority::kVeryLow:
      return automation::ResourcePriority::kRESOURCE_PRIORITY_VERYLOW;
    case blink::ResourceLoadPriority::kLow:
      return automation::ResourcePriority::kRESOURCE_PRIORITY_LOW;
    case blink::ResourceLoadPriority::kMedium:
      return automation::ResourcePriority::kRESOURCE_PRIORITY_MEDIUM;
    case blink::ResourceLoadPriority::kHigh:
      return automation::ResourcePriority::kRESOURCE_PRIORITY_HIGH;
    case blink::ResourceLoadPriority::kVeryHigh:
      return automation::ResourcePriority::kRESOURCE_PRIORITY_VERYHIGH;
    case blink::ResourceLoadPriority::kUnresolved:
      break;
  }
  NOTREACHED();
  return automation::ResourcePriority::kRESOURCE_PRIORITY_MEDIUM;
}

automation::ReferrerPolicy GetReferrerPolicy(blink::ReferrerPolicy policy) {
  switch (policy) {
    case blink::kReferrerPolicyAlways:
      return automation::ReferrerPolicy::kREFERRER_POLICY_UNSAFE_URL;
    case blink::kReferrerPolicyDefault:
      //if (RuntimeEnabledFeatures::ReducedReferrerGranularityEnabled()) {
        return automation::ReferrerPolicy::kREFERRER_POLICY_STRICT_ORIGIN_WHEN_CROSS_ORIGIN;
      //} else {
      //  return protocol::Network::Request::ReferrerPolicyEnum::
      //      NoReferrerWhenDowngrade;
     // }
    case blink::kReferrerPolicyNoReferrerWhenDowngrade:
      return automation::ReferrerPolicy::kREFERRER_POLICY_NO_REFERRER_WHEN_DOWNGRADE;
    case blink::kReferrerPolicyNever:
      return automation::ReferrerPolicy::kREFERRER_POLICY_NO_REFERRER;
    case blink::kReferrerPolicyOrigin:
      return automation::ReferrerPolicy::kREFERRER_POLICY_ORIGIN;
    case blink::kReferrerPolicyOriginWhenCrossOrigin:
      return automation::ReferrerPolicy::kREFERRER_POLICY_ORIGIN_WHEN_CROSS_ORIGIN;
    case blink::kReferrerPolicySameOrigin:
      return automation::ReferrerPolicy::kREFERRER_POLICY_SAME_ORIGIN;
    case blink::kReferrerPolicyStrictOrigin:
      return automation::ReferrerPolicy::kREFERRER_POLICY_STRICT_ORIGIN;
    case blink::kReferrerPolicyStrictOriginWhenCrossOrigin:
      return automation::ReferrerPolicy::kREFERRER_POLICY_STRICT_ORIGIN_WHEN_CROSS_ORIGIN;
  }

  return automation::ReferrerPolicy::kREFERRER_POLICY_NO_REFERRER_WHEN_DOWNGRADE;
}

}

static void ResponseBodyFileReaderLoaderDone(
    const String& mime_type,
    const String& text_encoding_name,
    NetworkDispatcher::GetResponseBodyCallback callback,
    scoped_refptr<blink::SharedBuffer> raw_data) {
  if (!raw_data) {
    //callback->sendFailure(Response::Error("Couldn't read BLOB"));
    //DLOG(ERROR) << "Couldn't read BLOB";
    std::move(callback).Run(std::string(), false);
    return;
  }
  String result;
  bool base64_encoded;
  if (PageDispatcher::SharedBufferContent(
          raw_data, mime_type, text_encoding_name, &result, &base64_encoded)) {
    //callback->sendSuccess(result, base64_encoded);
    std::move(callback).Run(std::string(result.Utf8().data(), result.Utf8().length()), base64_encoded);
  } else {
    //callback->sendFailure(Response::Error("Couldn't encode data"));
    //DLOG(ERROR) << "Couldn't encode data";
    std::move(callback).Run(std::string(), false);
  }
}

static bool FormDataToString(scoped_refptr<blink::EncodedFormData> body,
                             size_t max_body_size,
                             String* content) {
  *content = "";
  if (!body || body->IsEmpty())
    return false;

  // SizeInBytes below doesn't support all element types, so first check if all
  // the body elements are of the right type.
  for (const auto& element : body->Elements()) {
    if (element.type_ != blink::FormDataElement::kData)
      return true;
  }

  if (max_body_size != 0 && body->SizeInBytes() > max_body_size)
    return true;

  Vector<char> bytes;
  body->Flatten(bytes);
  *content = String::FromUTF8WithLatin1Fallback(bytes.data(), bytes.size());
  return true;
}

automation::CertificateTransparencyCompliance SerializeCTPolicyCompliance(
    blink::ResourceResponse::CTPolicyCompliance ct_compliance) {
  switch (ct_compliance) {
    case blink::ResourceResponse::kCTPolicyComplianceDetailsNotAvailable:
      return automation::CertificateTransparencyCompliance::kCERTIFICATE_TRANSPARENCY_COMPLIANCE_UNKNOWN;
    case blink::ResourceResponse::kCTPolicyComplies:
      return automation::CertificateTransparencyCompliance::kCERTIFICATE_TRANSPARENCY_COMPLIANCE_COMPLIANT;
    case blink::ResourceResponse::kCTPolicyDoesNotComply:
      return automation::CertificateTransparencyCompliance::kCERTIFICATE_TRANSPARENCY_COMPLIANCE_NOT_COMPLIANT;
  }
  NOTREACHED();
  return automation::CertificateTransparencyCompliance::kCERTIFICATE_TRANSPARENCY_COMPLIANCE_UNKNOWN;
}

static automation::ResourceTimingPtr BuildObjectForTiming(
    const blink::ResourceLoadTiming& timing) {
  automation::ResourceTimingPtr timing_obj = automation::ResourceTiming::New();
  timing_obj->request_time = TimeTicksInSeconds(timing.RequestTime());
  timing_obj->proxy_start = timing.CalculateMillisecondDelta(timing.ProxyStart());
  timing_obj->proxy_end = timing.CalculateMillisecondDelta(timing.ProxyEnd());
  timing_obj->dns_start = timing.CalculateMillisecondDelta(timing.DnsStart());
  timing_obj->dns_end = timing.CalculateMillisecondDelta(timing.DnsEnd());
  timing_obj->connect_start = timing.CalculateMillisecondDelta(timing.ConnectStart());
  timing_obj->connect_end = timing.CalculateMillisecondDelta(timing.ConnectEnd());
  timing_obj->ssl_start = timing.CalculateMillisecondDelta(timing.SslStart());
  timing_obj->ssl_end = timing.CalculateMillisecondDelta(timing.SslEnd());
  timing_obj->worker_start = timing.CalculateMillisecondDelta(timing.WorkerStart());
  timing_obj->worker_ready = timing.CalculateMillisecondDelta(timing.WorkerReady());
  timing_obj->send_start = timing.CalculateMillisecondDelta(timing.SendStart());
  timing_obj->send_end = timing.CalculateMillisecondDelta(timing.SendEnd());
  timing_obj->receive_headers_end = timing.CalculateMillisecondDelta(timing.ReceiveHeadersEnd());
  timing_obj->push_start = TimeTicksInSeconds(timing.PushStart());
  timing_obj->push_end = TimeTicksInSeconds(timing.PushEnd());
  return timing_obj;
}

static base::flat_map<std::string, std::string> BuildObjectForHeaders(
    const blink::HTTPHeaderMap& headers) {
  base::flat_map<std::string, std::string> headers_map;
  for (const auto& header : headers) {
    String key = header.key.GetString();
    String value = header.value;
    headers_map.emplace(std::string(key.Utf8().data(), key.length()), std::string(value.Utf8().data(), value.length()));
  }
  return headers_map;
}

static automation::RequestPtr BuildObjectForResourceRequest(
  const blink::ResourceRequest& request,
  size_t max_body_size) {
  String postData;
  bool hasPostData = FormDataToString(request.HttpBody(), max_body_size, &postData);
  automation::RequestPtr result = automation::Request::New();
  String url = UrlWithoutFragment(request.Url()).GetString();
  result->url = std::string(url.Utf8().data(), url.length());
  result->method = std::string(request.HttpMethod().Utf8().data());
  result->headers = BuildObjectForHeaders(request.HttpHeaderFields());
  result->initial_priority = ResourcePriorityJSON(request.Priority());
  result->referrer_policy = GetReferrerPolicy(request.GetReferrerPolicy());
  
  if (!postData.IsEmpty())
    result->post_data = std::string(postData.Utf8().data(), postData.length());
  if (hasPostData)
    result->has_post_data = true;
  return result;
}

static automation::ResponsePtr BuildObjectForResourceResponse(
  const blink::ResourceResponse& response,
  blink::Resource* cached_resource = nullptr,
  bool* is_empty = nullptr) {
  if (response.IsNull())
    return nullptr;

  int status;
  String status_text;
  if (response.GetResourceLoadInfo() &&
      response.GetResourceLoadInfo()->http_status_code) {
    status = response.GetResourceLoadInfo()->http_status_code;
    status_text = response.GetResourceLoadInfo()->http_status_text;
  } else {
    status = response.HttpStatusCode();
    status_text = response.HttpStatusText();
  }
  blink::HTTPHeaderMap headers_map;
  if (response.GetResourceLoadInfo() &&
      response.GetResourceLoadInfo()->response_headers.size())
    headers_map = response.GetResourceLoadInfo()->response_headers;
  else
    headers_map = response.HttpHeaderFields();

  int64_t encoded_data_length = response.EncodedDataLength();

  automation::SecurityState security_state = automation::SecurityState::SECURITY_STATE_UNKNOWN;
  switch (response.GetSecurityStyle()) {
    case blink::ResourceResponse::kSecurityStyleUnknown:
      security_state = automation::SecurityState::SECURITY_STATE_UNKNOWN;
      break;
    case blink::ResourceResponse::kSecurityStyleUnauthenticated:
      security_state = automation::SecurityState::SECURITY_STATE_NEUTRAL;
      break;
    case blink::ResourceResponse::kSecurityStyleAuthenticationBroken:
      security_state = automation::SecurityState::SECURITY_STATE_INSECURE;
      break;
    case blink::ResourceResponse::kSecurityStyleAuthenticated:
      security_state = automation::SecurityState::SECURITY_STATE_SECURE;
      break;
  }

  // Use mime type from cached resource in case the one in response is empty.
  String mime_type = response.MimeType();
  if (mime_type.IsEmpty() && cached_resource)
    mime_type = cached_resource->GetResponse().MimeType();

  if (is_empty)
    *is_empty = !status && mime_type.IsEmpty() && !headers_map.size();

  automation::ResponsePtr response_object = automation::Response::New();
  response_object->url = std::string(UrlWithoutFragment(response.Url()).GetString().Utf8().data());
  response_object->status = status;
  response_object->status_text = std::string(status_text.Utf8().data());
  response_object->headers = BuildObjectForHeaders(headers_map);
  response_object->mime_type = std::string(mime_type.Utf8().data());
  response_object->connection_reused = response.ConnectionReused();
  response_object->connection_id = response.ConnectionID();
  response_object->encoded_data_length = encoded_data_length;
  response_object->security_state = security_state;
  response_object->from_disk_cache = response.WasCached();
  response_object->from_service_worker = response.WasFetchedViaServiceWorker();
  
  if (response.GetResourceLoadTiming()) {
    response_object->timing = BuildObjectForTiming(*response.GetResourceLoadTiming());
  }

  if (response.GetResourceLoadInfo()) {
    if (!response.GetResourceLoadInfo()->response_headers_text.IsEmpty()) {
      response_object->headers_text = std::string(response.GetResourceLoadInfo()->response_headers_text.Utf8().data());
    }
    if (response.GetResourceLoadInfo()->request_headers.size()) {
      response_object->request_headers = BuildObjectForHeaders(response.GetResourceLoadInfo()->request_headers);
    }
    if (!response.GetResourceLoadInfo()->request_headers_text.IsEmpty()) {
      response_object->request_headers_text = std::string(response.GetResourceLoadInfo()->request_headers_text.Utf8().data());
    }
  }

  String remote_ip_address = response.RemoteIPAddress();
  if (!remote_ip_address.IsEmpty()) {
    response_object->remote_ip_address = std::string(remote_ip_address.Utf8().data());
    response_object->remote_port = response.RemotePort();
  }

  String protocol;
  if (response.GetResourceLoadInfo())
    protocol = response.GetResourceLoadInfo()->npn_negotiated_protocol;
  if (protocol.IsEmpty() || protocol == "unknown") {
    if (response.WasFetchedViaSPDY()) {
      protocol = "spdy";
    } else if (response.IsHTTP()) {
      protocol = "http";
      if (response.HttpVersion() ==
          blink::ResourceResponse::HTTPVersion::kHTTPVersion_0_9)
        protocol = "http/0.9";
      else if (response.HttpVersion() ==
               blink::ResourceResponse::HTTPVersion::kHTTPVersion_1_0)
        protocol = "http/1.0";
      else if (response.HttpVersion() ==
               blink::ResourceResponse::HTTPVersion::kHTTPVersion_1_1)
        protocol = "http/1.1";
    } else {
      protocol = response.Url().Protocol();
    }
  }
  response_object->protocol = std::string(protocol.Utf8().data(), protocol.length());

  if (response.GetSecurityStyle() != blink::ResourceResponse::kSecurityStyleUnknown &&
      response.GetSecurityStyle() !=
          blink::ResourceResponse::kSecurityStyleUnauthenticated) {
    const blink::ResourceResponse::SecurityDetails* response_security_details = response.GetSecurityDetails();

    std::vector<std::string> san_list;
    for (auto const& san : response_security_details->san_list)
      san_list.push_back(std::string(san.Utf8().data()));

    std::vector<automation::SignedCertificateTimestampPtr> signed_certificate_timestamp_list;
    for (auto const& sct : response_security_details->sct_list) {
      automation::SignedCertificateTimestampPtr signed_certificate_timestamp = automation::SignedCertificateTimestamp::New();
      signed_certificate_timestamp->status = std::string(sct.status_.Utf8().data());
      signed_certificate_timestamp->origin = std::string(sct.origin_.Utf8().data());
      signed_certificate_timestamp->log_description = std::string(sct.log_description_.Utf8().data());
      signed_certificate_timestamp->log_id = std::string(sct.log_id_.Utf8().data());
      signed_certificate_timestamp->timestamp = sct.timestamp_;
      signed_certificate_timestamp->hash_algorithm = std::string(sct.hash_algorithm_.Utf8().data());
      signed_certificate_timestamp->signature_algorithm = std::string(sct.signature_algorithm_.Utf8().data());
      signed_certificate_timestamp->signature_data = std::string(sct.signature_data_.Utf8().data());
      signed_certificate_timestamp_list.push_back(
          std::move(signed_certificate_timestamp));
    }

    automation::SecurityDetailsPtr security_details = automation::SecurityDetails::New();
    security_details->protocol = std::string(response_security_details->protocol.Utf8().data());
    security_details->key_exchange = std::string(response_security_details->key_exchange.Utf8().data());
    security_details->cipher = std::string(response_security_details->cipher.Utf8().data());
    security_details->subject_name = std::string(response_security_details->subject_name.Utf8().data());
    security_details->san_list = std::move(san_list);
    security_details->issuer = std::string(response_security_details->issuer.Utf8().data());
    security_details->valid_from = response_security_details->valid_from;
    security_details->valid_to = response_security_details->valid_to;
    security_details->certificate_id = 0;  // Keep this in protocol for compatability.
    security_details->signed_certificate_timestamp_list = std::move(signed_certificate_timestamp_list);
    security_details->certificate_transparency_compliance = SerializeCTPolicyCompliance(response.GetCTPolicyCompliance());
            
    if (response_security_details->key_exchange_group.length() > 0)
      security_details->key_exchange_group = std::string(response_security_details->key_exchange_group.Utf8().data());
    if (response_security_details->mac.length() > 0)
      security_details->mac = std::string(response_security_details->mac.Utf8().data());

    response_object->security_details = std::move(security_details);
  }

  return response_object;
}

class InspectorFileReaderLoaderClient final : public blink::FileReaderLoaderClient {
 public:
  InspectorFileReaderLoaderClient(
      scoped_refptr<blink::BlobDataHandle> blob,
      base::OnceCallback<void(scoped_refptr<blink::SharedBuffer>)> callback)
      : blob_(std::move(blob)), callback_(std::move(callback)) {
    loader_ = blink::FileReaderLoader::Create(blink::FileReaderLoader::kReadByClient, this);
  }

  ~InspectorFileReaderLoaderClient() override = default;

  void Start() {
    raw_data_ = blink::SharedBuffer::Create();
    loader_->Start(blob_);
  }

  void DidStartLoading() override {}

  void DidReceiveDataForClient(const char* data,
                               unsigned data_length) override {
    if (!data_length)
      return;
    raw_data_->Append(data, data_length);
  }

  void DidFinishLoading() override { Done(raw_data_); }

  void DidFail(blink::FileError::ErrorCode) override { Done(nullptr); }

 private:
  void Done(scoped_refptr<blink::SharedBuffer> output) {
    std::move(callback_).Run(output);
    delete this;
  }

  scoped_refptr<blink::BlobDataHandle> blob_;
  String mime_type_;
  String text_encoding_name_;
  base::OnceCallback<void(scoped_refptr<blink::SharedBuffer>)> callback_;
  std::unique_ptr<blink::FileReaderLoader> loader_;
  scoped_refptr<blink::SharedBuffer> raw_data_;
  DISALLOW_COPY_AND_ASSIGN(InspectorFileReaderLoaderClient);
};

class InspectorPostBodyParser
    : public WTF::RefCounted<InspectorPostBodyParser> {
 public:
  explicit InspectorPostBodyParser(
      NetworkDispatcher::GetRequestPostDataCallback callback)
      : callback_(std::move(callback)), error_(false) {}

  void Parse(blink::EncodedFormData* request_body) {
    if (!request_body || request_body->IsEmpty())
      return;

    parts_.Grow(request_body->Elements().size());
    for (size_t i = 0; i < request_body->Elements().size(); i++) {
      const blink::FormDataElement& data = request_body->Elements()[i];
      switch (data.type_) {
        case blink::FormDataElement::kData:
          parts_[i] = String::FromUTF8WithLatin1Fallback(data.data_.data(),
                                                         data.data_.size());
          break;
        case blink::FormDataElement::kEncodedBlob:
          ReadDataBlob(data.optional_blob_data_handle_, &parts_[i]);
          break;
        case blink::FormDataElement::kEncodedFile:
        case blink::FormDataElement::kDataPipe:
          // Do nothing, not supported
          break;
      }
    }
  }

 private:
  friend class WTF::RefCounted<InspectorPostBodyParser>;

  ~InspectorPostBodyParser() {
    if (error_)
      return;
    String result;
    for (const auto& part : parts_)
      result.append(part);
    //callback_->sendSuccess(result);
    std::move(callback_).Run(std::string(result.Utf8().data(), result.Utf8().length()));
  }

  void BlobReadCallback(String* destination,
                        scoped_refptr<blink::SharedBuffer> raw_data) {
    if (raw_data) {
      *destination = String::FromUTF8WithLatin1Fallback(raw_data->Data(),
                                                        raw_data->size());
    } else {
      error_ = true;
    }
  }

  void ReadDataBlob(scoped_refptr<blink::BlobDataHandle> blob_handle,
                    String* destination) {
    if (!blob_handle)
      return;
    auto* reader = new InspectorFileReaderLoaderClient(
        blob_handle,
        WTF::Bind(&InspectorPostBodyParser::BlobReadCallback,
                  WTF::RetainedRef(this), WTF::Unretained(destination)));
    reader->Start();
  }

  NetworkDispatcher::GetRequestPostDataCallback callback_;
  bool error_;
  Vector<String> parts_;
  DISALLOW_COPY_AND_ASSIGN(InspectorPostBodyParser);
};


class InspectorNetworkAgentImpl : public blink::InspectorNetworkAgent {
public:
  InspectorNetworkAgentImpl(NetworkDispatcher* dispatcher):
    // InspectorNetworkAgent(InspectedFrames*, WorkerGlobalScope*, v8_inspector::V8InspectorSession*);
    InspectorNetworkAgent(dispatcher->page_instance_->inspected_frames(), nullptr, nullptr),  
    dispatcher_(dispatcher) {

    }
 
 void DidBlockRequest(
    blink::ExecutionContext* execution_context,
    const blink::ResourceRequest& request,
    blink::DocumentLoader* loader,
    const blink::FetchInitiatorInfo& initiator_info,
    blink::ResourceRequestBlockedReason reason,
    blink::Resource::Type resource_type) override {
      dispatcher_->DidBlockRequest(execution_context, request, loader, initiator_info, reason, resource_type);
  }

  void DidChangeResourcePriority(
    blink::DocumentLoader* loader,
    unsigned long identifier,
    blink::ResourceLoadPriority load_priority) override {
     dispatcher_->DidChangeResourcePriority(loader, identifier, load_priority);
  }

  void WillSendRequest(
    blink::ExecutionContext* execution_context,
    unsigned long identifier,
    blink::DocumentLoader* loader,
    blink::ResourceRequest& request,
    const blink::ResourceResponse& redirect_response,
    const blink::FetchInitiatorInfo& initiator_info,
    blink::Resource::Type resource_type) override {

    dispatcher_->WillSendRequest(execution_context, identifier, loader, request, redirect_response, initiator_info, resource_type);
  }

  void MarkResourceAsCached(blink::DocumentLoader* loader,
                            unsigned long identifier) override {
    dispatcher_->MarkResourceAsCached(loader, identifier); 
  }

  void DidReceiveResourceResponse(
    unsigned long identifier,
    blink::DocumentLoader* loader,
    const blink::ResourceResponse& response,
    blink::Resource* cached_resource) override {
    dispatcher_->DidReceiveResourceResponse(identifier, loader, response, cached_resource); 
  }

  void DidReceiveData(unsigned long identifier,
                      blink::DocumentLoader* loader,
                      const char* data,
                      int data_length) override {
    dispatcher_->DidReceiveData(identifier, loader, data, data_length); 
  }

  void DidReceiveBlob(unsigned long identifier,
                      blink::DocumentLoader* loader,
                      scoped_refptr<blink::BlobDataHandle> blob) override {
    dispatcher_->DidReceiveBlob(identifier, loader, blob); 
  }

  void DidReceiveEncodedDataLength(
    blink::DocumentLoader* loader,
    unsigned long identifier,
    int encoded_data_length) override {
    dispatcher_->DidReceiveEncodedDataLength(loader, identifier, encoded_data_length); 
  }

  void DidFinishLoading(unsigned long identifier,
                        blink::DocumentLoader* loader,
                        double monotonic_finish_time,
                        int64_t encoded_data_length,
                        int64_t decoded_body_length,
                        bool blocked_cross_site_document) override {
    dispatcher_->DidFinishLoading(identifier, loader, monotonic_finish_time, encoded_data_length, decoded_body_length, blocked_cross_site_document);
  }

  void DidReceiveCORSRedirectResponse(
    unsigned long identifier,
    blink::DocumentLoader* loader,
    const blink::ResourceResponse& response,
    blink::Resource* resource) override {
     dispatcher_->DidReceiveCORSRedirectResponse(identifier, loader, response, resource);
  }

  void DidFailLoading(unsigned long identifier,
                      blink::DocumentLoader* loader,
                      const blink::ResourceError& error) override {
    dispatcher_->DidFailLoading(identifier, loader, error);
  }

  void ScriptImported(unsigned long identifier,
                      const String& source_string) override {
    dispatcher_->ScriptImported(identifier, source_string);
  }

  void DidReceiveScriptResponse(unsigned long identifier) override {
    dispatcher_->DidReceiveScriptResponse(identifier);
  }

  void DocumentThreadableLoaderStartedLoadingForClient(
    unsigned long identifier,
    blink::ThreadableLoaderClient* client) override {
    dispatcher_->DocumentThreadableLoaderStartedLoadingForClient(identifier, client);
  }

  void DocumentThreadableLoaderFailedToStartLoadingForClient(blink::ThreadableLoaderClient* client) override {
    dispatcher_->DocumentThreadableLoaderFailedToStartLoadingForClient(client); 
  }

  void WillLoadXHR(blink::XMLHttpRequest* xhr,
                   blink::ThreadableLoaderClient* client,
                   const AtomicString& method,
                   const blink::KURL& url,
                   bool async,
                   const blink::HTTPHeaderMap& headers,
                   bool include_credentials) override {
    dispatcher_->WillLoadXHR(xhr, client, method, url, async, headers, include_credentials);
  }

  void DidFailXHRLoading(blink::ExecutionContext* context,
                         blink::XMLHttpRequest* xhr,
                         blink::ThreadableLoaderClient* client,
                         const AtomicString& method,
                         const String& url) override {
    dispatcher_->DidFailXHRLoading(context, xhr, client, method, url);
  }

  void DidFinishXHRLoading(blink::ExecutionContext* context,
                           blink::XMLHttpRequest* xhr,
                           blink::ThreadableLoaderClient* client,
                           const AtomicString& method,
                           const String& url) override {
    dispatcher_->DidFinishXHRLoading(context, xhr, client, method, url);
  }

  void WillStartFetch(blink::ThreadableLoaderClient* client) override {
    dispatcher_->WillStartFetch(client);
  }
  
  void DidFailFetch(blink::ThreadableLoaderClient* client) override {
    dispatcher_->DidFailFetch(client);
  }

  void DidFinishFetch(blink::ExecutionContext* context,
                      blink::ThreadableLoaderClient* client,
                      const AtomicString& method,
                      const String& url) override {
    dispatcher_->DidFinishFetch(context, client, method, url);
  }

  void WillSendEventSourceRequest(blink::ThreadableLoaderClient* event_source) override {
    dispatcher_->WillSendEventSourceRequest(event_source);
  }

  void WillDispatchEventSourceEvent(
    blink::ThreadableLoaderClient* event_source,
    const AtomicString& event_name,
    const AtomicString& event_id,
    const String& data) override {

    dispatcher_->WillDispatchEventSourceEvent(event_source, event_name, event_id, data);
  }

  void DidFinishEventSourceRequest(blink::ThreadableLoaderClient* event_source) override {
    dispatcher_->DidFinishEventSourceRequest(event_source);
  }

  void DetachClientRequest(blink::ThreadableLoaderClient* client) override {
    dispatcher_->DetachClientRequest(client);
  }

  void ApplyUserAgentOverride(String* user_agent) override {
    dispatcher_->ApplyUserAgentOverride(user_agent);
  }

  void DidCreateWebSocket(
    blink::ExecutionContext* execution_context,
    unsigned long identifier,
    const blink::KURL& request_url,
    const String& protocol) override {
    dispatcher_->DidCreateWebSocket(execution_context, identifier, request_url, protocol);
  }

  void WillSendWebSocketHandshakeRequest(
    blink::ExecutionContext* execution_context,
    unsigned long identifier,
    const blink::WebSocketHandshakeRequest* request) override {
    dispatcher_->WillSendWebSocketHandshakeRequest(execution_context, identifier, request);
  }

  void DidReceiveWebSocketHandshakeResponse(
    blink::ExecutionContext* execution_context,
    unsigned long identifier,
    const blink::WebSocketHandshakeRequest* request,
    const blink::WebSocketHandshakeResponse* response) override {
    dispatcher_->DidReceiveWebSocketHandshakeResponse(execution_context, identifier, request, response);
  }

  void DidCloseWebSocket(blink::ExecutionContext* execution_context,
                         unsigned long identifier) override {
    dispatcher_->DidCloseWebSocket(execution_context, identifier); 
  }

  void DidReceiveWebSocketFrame(unsigned long identifier,
                                int op_code,
                                bool masked,
                                const char* payload,
                                size_t payload_length) override {
    dispatcher_->DidReceiveWebSocketFrame(identifier, op_code, masked, payload, payload_length); 
  }

  void DidSendWebSocketFrame(unsigned long identifier,
                             int op_code,
                             bool masked,
                             const char* payload,
                             size_t payload_length) override {
    dispatcher_->DidSendWebSocketFrame(identifier, op_code, masked, payload, payload_length); 
  }

  void DidReceiveWebSocketFrameError(unsigned long identifier, const String& error_message) override {
    dispatcher_->DidReceiveWebSocketFrameError(identifier, error_message); 
  }

private:
  NetworkDispatcher* dispatcher_;

  DISALLOW_COPY_AND_ASSIGN(InspectorNetworkAgentImpl);
};

// static
bool NetworkDispatcher::IsNavigation(blink::DocumentLoader* loader,
                                     unsigned long identifier) {
  return loader && loader->MainResourceIdentifier() == identifier;
}

// static 
void NetworkDispatcher::Create(automation::NetworkRequest request, PageInstance* page_instance) {
  new NetworkDispatcher(std::move(request), page_instance);
}

NetworkDispatcher::NetworkDispatcher(automation::NetworkRequest request, PageInstance* page_instance): 
    application_id_(-1),
    page_instance_(page_instance),
    binding_(this), 
    resources_data_(
          blink::NetworkResourcesData::Create(g_maximum_total_buffer_size,
                                              g_maximum_resource_buffer_size)),
    pending_request_type_(PageDispatcher::kOtherResource),
    total_buffer_size_(0),
    resource_buffer_size_(0),
    max_post_data_size_(0),
    enabled_(false),
    cache_disabled_(false),
    bypass_service_worker_(false) {
  
  
}

NetworkDispatcher::NetworkDispatcher(PageInstance* page_instance): 
    application_id_(-1),
    page_instance_(page_instance),
    binding_(this), 
    resources_data_(
          blink::NetworkResourcesData::Create(g_maximum_total_buffer_size,
                                              g_maximum_resource_buffer_size)),
    pending_request_type_(PageDispatcher::kOtherResource),
    total_buffer_size_(0),
    resource_buffer_size_(0),
    max_post_data_size_(0),
    enabled_(false),
    cache_disabled_(false),
    bypass_service_worker_(false) {
  
  
}

NetworkDispatcher::~NetworkDispatcher() {
  network_agent_impl_ = nullptr;
}

void NetworkDispatcher::Init(IPC::SyncChannel* channel) {
  channel->GetRemoteAssociatedInterface(&network_client_ptr_);
}

void NetworkDispatcher::Bind(automation::NetworkAssociatedRequest request) {
  //DLOG(INFO) << "NetworkDispatcher::Bind (application)";
  binding_.Bind(std::move(request));  
}

void NetworkDispatcher::Register(int32_t application_id) {
  application_id_ = application_id;
}

void NetworkDispatcher::RemoveFinishedReplayXHRFired(blink::TimerBase*) {
  replay_xhrs_to_be_deleted_.clear();
}

void NetworkDispatcher::Enable(int32_t total_buffer_size, int32_t resource_buffer_size, int32_t max_post_data_size) {
  //DLOG(INFO) << "NetworkDispatcher::Enable (application process)";
  if (enabled_) {
    return;
  }
  resources_data_->SetResourcesDataSizeLimits(total_buffer_size,
                                              resource_buffer_size);
  total_buffer_size_ = total_buffer_size;
  resource_buffer_size_ = resource_buffer_size;
  max_post_data_size_ = max_post_data_size;
  page_instance_->probe_sink()->addInspectorNetworkAgent(network_agent_impl_.Get());
  enabled_ = true;
}

void NetworkDispatcher::Disable() {
  enabled_ = false;
  user_agent_override_ = std::string();
  page_instance_->probe_sink()->removeInspectorNetworkAgent(network_agent_impl_.Get());
  resources_data_->Clear();
  known_request_id_map_.clear();
}

automation::NetworkClient* NetworkDispatcher::GetClient() const {
  return network_client_ptr_.get();
}

void NetworkDispatcher::CanClearBrowserCache(CanClearBrowserCacheCallback callback) {
  std::move(callback).Run(true);
}

void NetworkDispatcher::CanClearBrowserCookies(CanClearBrowserCookiesCallback callback) {
  std::move(callback).Run(true);
}

void NetworkDispatcher::CanEmulateNetworkConditions(CanEmulateNetworkConditionsCallback callback) {
  std::move(callback).Run(true);
}

void NetworkDispatcher::ClearBrowserCache() {}
void NetworkDispatcher::ClearBrowserCookies() {}
void NetworkDispatcher::ContinueInterceptedRequest(const std::string& interception_id, automation::ErrorReason error_reason, const base::Optional<std::string>& raw_response, const base::Optional<std::string>& url, const base::Optional<std::string>& method, const base::Optional<std::string>& post_data, const base::Optional<base::flat_map<std::string, std::string>>& headers, automation::AuthChallengeResponsePtr auth_challenge_response) {}
void NetworkDispatcher::DeleteCookies(const std::string& name, const base::Optional<std::string>& url, const base::Optional<std::string>& domain, const base::Optional<std::string>& path) {}
void NetworkDispatcher::GetCookies(const base::Optional<std::vector<std::string>>& urls, GetCookiesCallback callback) {}
void NetworkDispatcher::GetResponseBodyForInterception(const std::string& interception_id, GetResponseBodyForInterceptionCallback callback) {}
void NetworkDispatcher::TakeResponseBodyForInterceptionAsStream(const std::string& interception_id, TakeResponseBodyForInterceptionAsStreamCallback callback) {}

void NetworkDispatcher::EmulateNetworkConditions(bool offline, int64_t latency, int64_t download_throughput, int64_t upload_throughput, automation::ConnectionType connection_type) {
  blink::WebConnectionType type = blink::kWebConnectionTypeUnknown;
  type = ToWebConnectionType(connection_type);
  // TODO(dgozman): networkStateNotifier is per-process. It would be nice to
  // have per-frame override instead.
  if (offline || latency || download_throughput || upload_throughput) {
    blink::GetNetworkStateNotifier().SetNetworkConnectionInfoOverride(
        !offline, type, base::nullopt, latency,
        download_throughput / (1024 * 1024 / 8));
  } else {
    blink::GetNetworkStateNotifier().ClearOverride();
  }
}

void NetworkDispatcher::GetAllCookies(GetAllCookiesCallback callback) {

}

void NetworkDispatcher::GetCertificate(const std::string& origin, GetCertificateCallback callback) {
  std::vector<std::string> certificate;
  scoped_refptr<const blink::SecurityOrigin> security_origin =
      blink::SecurityOrigin::CreateFromString(String::FromUTF8(origin.data()));
  for (auto& resource : resources_data_->Resources()) {
    scoped_refptr<const blink::SecurityOrigin> resource_origin =
        blink::SecurityOrigin::Create(resource->RequestedURL());
    if (resource_origin->IsSameSchemeHostPort(security_origin.get()) &&
        resource->Certificate().size()) {
      for (auto& cert : resource->Certificate()) {
        String base64_encoded = Base64Encode(cert.Latin1());
        certificate.push_back(std::string(base64_encoded.Utf8().data(), base64_encoded.length()));
      }
      std::move(callback).Run(certificate);
      return;
    }
  }
  std::move(callback).Run(certificate);
}

bool NetworkDispatcher::CanGetResponseBodyBlob(const std::string& request_id) {
  blink::NetworkResourcesData::ResourceData const* resource_data =
      resources_data_->Data(String::FromUTF8(request_id.data()));
  blink::BlobDataHandle* blob =
      resource_data ? resource_data->DownloadedFileBlob() : nullptr;
  if (!blob)
    return false;
  if (page_instance_->worker_global_scope())
    return true;
  blink::LocalFrame* frame = blink::IdentifiersFactory::FrameById(page_instance_->inspected_frames(),
                                                                  resource_data->FrameId());
  return frame && frame->GetDocument();
}

void NetworkDispatcher::GetResponseBodyBlob(
    const std::string& request_id,
    GetResponseBodyCallback callback) {
  blink::NetworkResourcesData::ResourceData const* resource_data =
      resources_data_->Data(String::FromUTF8(request_id.data()));
  blink::BlobDataHandle* blob = resource_data->DownloadedFileBlob();
  InspectorFileReaderLoaderClient* client = new InspectorFileReaderLoaderClient(
      blob,
      WTF::Bind(ResponseBodyFileReaderLoaderDone, 
                resource_data->MimeType(),
                resource_data->TextEncodingName(),
                WTF::Passed(std::move(callback))));
  client->Start();
}

void NetworkDispatcher::GetResponseBody(const std::string& request_id, GetResponseBodyCallback callback) {
  if (CanGetResponseBodyBlob(request_id)) {
    GetResponseBodyBlob(request_id, std::move(callback));
    return;
  }
  blink::NetworkResourcesData::ResourceData const* resource_data = resources_data_->Data(String::FromUTF8(request_id.data()));
  String content;
  bool base64_encoded = false; 
  if (!resource_data) {
    //DLOG(ERROR) << "No resource with given identifier found";
    // TODO: reply anyway
    return;
  }

  if (resource_data->HasContent()) {
    std::move(callback).Run(
      std::string(resource_data->Content().Utf8().data(), resource_data->Content().Utf8().length()), 
      resource_data->Base64Encoded());
    return;
  }

  if (resource_data->IsContentEvicted()) {
    //DLOG(ERROR) << "Request content was evicted from inspector cache";
    return;
  }

  if (resource_data->Buffer() && !resource_data->TextEncodingName().IsNull()) {
    bool success = PageDispatcher::SharedBufferContent(
        resource_data->Buffer(), resource_data->MimeType(),
        resource_data->TextEncodingName(), &content, &base64_encoded);
    DCHECK(success);
    std::move(callback).Run(std::string(content.Utf8().data(), content.Utf8().length()), base64_encoded);
    return;
  }

  if (resource_data->CachedResource() &&
    PageDispatcher::CachedResourceContent(resource_data->CachedResource(),
                                          &content, &base64_encoded)) {
    std::move(callback).Run(std::string(content.Utf8().data(), content.Utf8().length()), base64_encoded);
    return;
  }

  //DLOG(ERROR) << "No data found for resource with given identifier";
}

void NetworkDispatcher::GetRequestPostData(const std::string& request_id, GetRequestPostDataCallback callback) {
  blink::NetworkResourcesData::ResourceData const* resource_data = resources_data_->Data(String::FromUTF8(request_id.data()));
  if (!resource_data) {
    //callback->sendFailure(
    //    Response::Error("No resource with given id was found"));
    //DLOG(ERROR) << "No resource with given id was found";
    return;
  }
  scoped_refptr<blink::EncodedFormData> post_data = resource_data->PostData();
  if (!post_data || post_data->IsEmpty()) {
    //callback->sendFailure(
    //    Response::Error("No post data available for the request"));
    //DLOG(ERROR) << "No post data available for the request";
    return;
  }

  scoped_refptr<InspectorPostBodyParser> parser =
      base::MakeRefCounted<InspectorPostBodyParser>(std::move(callback));
  // TODO(crbug.com/810554): Extend protocol to fetch body parts separately
  parser->Parse(post_data.get());
}

void NetworkDispatcher::ReplayXHR(const std::string& request_id) {
  String actual_request_id = String::FromUTF8(request_id.data());

  blink::XHRReplayData* xhr_replay_data = resources_data_->XhrReplayData(actual_request_id);
  auto* data = resources_data_->Data(actual_request_id);
  if (!xhr_replay_data || !data) {
    //DLOG(ERROR) << "Given id does not correspond to XHR";
    return;
  }

  blink::ExecutionContext* execution_context = data->GetExecutionContext();
  if (execution_context->IsContextDestroyed()) {
    resources_data_->SetXHRReplayData(actual_request_id, nullptr);
    //DLOG(ERROR) << "Document is already detached";
    return;
  }

  blink::XMLHttpRequest* xhr = blink::XMLHttpRequest::Create(execution_context);

  execution_context->RemoveURLFromMemoryCache(xhr_replay_data->Url());

  xhr->open(xhr_replay_data->Method(), xhr_replay_data->Url(),
            xhr_replay_data->Async(), IGNORE_EXCEPTION_FOR_TESTING);
  if (xhr_replay_data->IncludeCredentials())
    xhr->setWithCredentials(true, IGNORE_EXCEPTION_FOR_TESTING);
  for (const auto& header : xhr_replay_data->Headers()) {
    xhr->setRequestHeader(header.key, header.value,
                          IGNORE_EXCEPTION_FOR_TESTING);
  }
  xhr->SendForInspectorXHRReplay(data ? data->PostData() : nullptr,
                                 IGNORE_EXCEPTION_FOR_TESTING);

  replay_xhrs_.insert(xhr);
}

void NetworkDispatcher::SearchInResponseBody(const std::string& request_id, const std::string& query, bool case_sensitive, bool is_regex, SearchInResponseBodyCallback callback) {
  String content;
  bool base64_encoded;
  bool has_body = GetResponseBody(String::FromUTF8(request_id.data()), &content, &base64_encoded);
  if (!has_body) {
    //DLOG(ERROR) << "Network Search: response body with request id '" << request_id << "' not found"; 
    std::move(callback).Run(std::vector<automation::SearchMatchPtr>());
    return;
  }

  v8_inspector::StringView contents_view = ToV8InspectorStringView(content);
  v8_inspector::StringView query_view = ToV8InspectorStringView(String::FromUTF8(query.data()));

  auto matches = PageDispatcher::SearchInTextByLines(
      v8_inspector::String16(contents_view.characters16(), contents_view.length()), v8_inspector::String16(query_view.characters16(), query_view.length()),
      case_sensitive, is_regex);

  std::move(callback).Run(std::move(matches));
}

void NetworkDispatcher::SetBlockedURLs(const std::vector<std::string>& urls) {
  blocked_urls_ = urls;
}

void NetworkDispatcher::SetBypassServiceWorker(bool bypass) {
  bypass_service_worker_ = bypass;
}

void NetworkDispatcher::SetCacheDisabled(bool cache_disabled) {
  cache_disabled_ = cache_disabled;
  if (cache_disabled && IsMainThread())
    blink::GetMemoryCache()->EvictResources();
}

void NetworkDispatcher::SetCookie(const std::string& name, const std::string& value, const base::Optional<std::string>& url, const base::Optional<std::string>& domain, const base::Optional<std::string>& path, bool secure, bool http_only, automation::CookieSameSite same_site, int64_t expires, SetCookieCallback callback) {

}

void NetworkDispatcher::SetCookies(std::vector<automation::CookieParamPtr> cookies) {

}

void NetworkDispatcher::SetDataSizeLimitsForTest(int32_t max_total_size, int32_t max_resource_size) {

}

void NetworkDispatcher::SetExtraHTTPHeaders(const base::flat_map<std::string, std::string>& headers) {
  extra_http_headers_ = headers;
}

void NetworkDispatcher::SetRequestInterception(std::vector<automation::RequestPatternPtr> patterns) {

}

void NetworkDispatcher::SetUserAgentOverride(const std::string& user_agent) {
  user_agent_override_ = user_agent;
}

void NetworkDispatcher::DidBlockRequest(
  blink::ExecutionContext* execution_context,
  const blink::ResourceRequest& request,
  blink::DocumentLoader* loader,
  const blink::FetchInitiatorInfo& initiator_info,
  blink::ResourceRequestBlockedReason reason,
  blink::Resource::Type resource_type) {

  unsigned long identifier = blink::CreateUniqueIdentifier();
  PageDispatcher::ResourceType type = PageDispatcher::ToResourceType(resource_type);

  WillSendRequestInternal(execution_context, identifier, loader, request,
                          blink::ResourceResponse(), initiator_info, type);

  String request_id = blink::IdentifiersFactory::RequestId(loader, identifier);
  String protocol_reason = BuildBlockedReason(reason);
  GetClient()->OnLoadingFailed(
      std::string(request_id.Utf8().data(), request_id.length()), CurrentTimeTicksInSeconds(),
      PageDispatcher::ToAutomationResourceType(
          FromInspectorPageAgentResourceType(resources_data_->GetResourceType(request_id))),
      std::string(), false, ToBlockedReason(protocol_reason));
}

void NetworkDispatcher::DidChangeResourcePriority(
  blink::DocumentLoader* loader,
  unsigned long identifier,
  blink::ResourceLoadPriority load_priority) {
  String request_id = blink::IdentifiersFactory::RequestId(loader, identifier);
  GetClient()->OnResourceChangedPriority(std::string(request_id.Utf8().data(), request_id.length()),
                                         ResourcePriorityJSON(load_priority),
                                         CurrentTimeTicksInSeconds());
}

void NetworkDispatcher::WillSendRequestInternal(
  blink::ExecutionContext* execution_context,
  unsigned long identifier,
  blink::DocumentLoader* loader,
  const blink::ResourceRequest& request,
  const blink::ResourceResponse& redirect_response,
  const blink::FetchInitiatorInfo& initiator_info,
  PageDispatcher::ResourceType type) {
  String loader_id = blink::IdentifiersFactory::LoaderId(loader);
  // DocumentLoader doesn't have main resource set at the point, so RequestId()
  // won't properly detect main resource. Workaround this by checking the
  // frame type and manually setting request id to loader id.
  String request_id = blink::IdentifiersFactory::RequestId(loader, identifier);
  bool is_navigation =
      request.GetFrameType() != network::mojom::RequestContextFrameType::kNone;
  if (is_navigation)
    request_id = loader_id;
  blink::NetworkResourcesData::ResourceData const* data =
      resources_data_->Data(request_id);
  // Support for POST request redirect
  scoped_refptr<blink::EncodedFormData> post_data;
  if (data)
    post_data = data->PostData();
  else if (request.HttpBody())
    post_data = request.HttpBody()->DeepCopy();

  resources_data_->ResourceCreated(execution_context, request_id, loader_id,
                                   request.Url(), post_data);
  if (initiator_info.name == blink::FetchInitiatorTypeNames::xmlhttprequest)
    type = PageDispatcher::kXHRResource;

  resources_data_->SetResourceType(request_id, ToInspectorPageAgentResourceType(type));

  if (is_navigation)
    return;

  String frame_id = loader && loader->GetFrame()
                        ? blink::IdentifiersFactory::FrameId(loader->GetFrame())
                        : "";
  automation::InitiatorPtr initiator_object =
      BuildInitiatorObject(loader && loader->GetFrame()
                               ? loader->GetFrame()->GetDocument()
                               : nullptr,
                           initiator_info);

  automation::RequestPtr request_info(
      BuildObjectForResourceRequest(request, max_post_data_size_));

  // |loader| is null while inspecting worker.
  // TODO(horo): Refactor MixedContentChecker and set mixed content type even if
  // |loader| is null.
  if (loader) {
    request_info->mixed_content_type = MixedContentTypeForContextType(
        blink::MixedContentChecker::ContextTypeForInspector(loader->GetFrame(), request));
  }

  request_info->referrer_policy = GetReferrerPolicy(request.GetReferrerPolicy());
  if (initiator_info.is_link_preload)
    request_info->is_link_preload = true;

  automation::ResourceType resource_type = PageDispatcher::ToAutomationResourceType(type);
  String documentURL =
      loader ? UrlWithoutFragment(loader->Url()).GetString()
             : UrlWithoutFragment(execution_context->Url()).GetString();
  std::string maybe_frame_id;
  if (!frame_id.IsEmpty())
    maybe_frame_id = std::string(frame_id.Utf8().data());
  GetClient()->OnRequestWillBeSent(
      std::string(request_id.Utf8().data(), request_id.length()), 
      std::string(loader_id.Utf8().data()), 
      std::string(documentURL.Utf8().data()), 
      std::move(request_info),
      CurrentTimeTicksInSeconds(), CurrentTime(), std::move(initiator_object),
      BuildObjectForResourceResponse(redirect_response), 
      resource_type,
      std::move(maybe_frame_id), 
      request.HasUserGesture());
  if (pending_xhr_replay_data_ && !pending_xhr_replay_data_->Async())
    GetClient()->Flush();
}

void NetworkDispatcher::WillSendRequest(
  blink::ExecutionContext* execution_context,
  unsigned long identifier,
  blink::DocumentLoader* loader,
  blink::ResourceRequest& request,
  const blink::ResourceResponse& redirect_response,
  const blink::FetchInitiatorInfo& initiator_info,
  blink::Resource::Type resource_type) {
  // Ignore the request initiated internally.
  if (initiator_info.name == blink::FetchInitiatorTypeNames::internal)
    return;

  if (initiator_info.name == blink::FetchInitiatorTypeNames::document &&
      loader->GetSubstituteData().IsValid())
    return;

  //protocol::DictionaryValue* headers =
  //    state_->getObject(NetworkAgentState::kExtraRequestHeaders);
  const base::flat_map<std::string, std::string>& headers = extra_http_headers_;
  if (headers.size() > 0) {
    for (size_t i = 0; i < headers.size(); ++i) {
      auto header = headers.begin() + i;
      AtomicString header_name = AtomicString(header->first.data());
      String value = String::FromUTF8(header->second.data());
      // When overriding referer, also override referrer policy
      // for this request to assure the request will be allowed.
      if (header_name.LowerASCII() == blink::HTTPNames::Referer.LowerASCII())
        request.SetHTTPReferrer(blink::Referrer(value, blink::kReferrerPolicyAlways));
      else
        request.SetHTTPHeaderField(header_name, AtomicString(value));
    }
  }

  request.SetReportRawHeaders(true);

  if (cache_disabled_) {
    if (LoadsFromCacheOnly(request) &&
        request.GetRequestContext() != blink::WebURLRequest::kRequestContextInternal) {
      request.SetCacheMode(blink::mojom::FetchCacheMode::kUnspecifiedForceCacheMiss);
    } else {
      request.SetCacheMode(blink::mojom::FetchCacheMode::kBypassCache);
    }
    request.SetShouldResetAppCache(true);
  }
  if (bypass_service_worker_)
    request.SetSkipServiceWorker(true);

  PageDispatcher::ResourceType type =
      PageDispatcher::ToResourceType(resource_type);

  WillSendRequestInternal(execution_context, identifier, loader, request,
                          redirect_response, initiator_info, type);

  if (!conditions_token_.IsEmpty()) {
    request.AddHTTPHeaderField(
        blink::HTTPNames::X_DevTools_Emulate_Network_Conditions_Client_Id,
        AtomicString(conditions_token_));
  }
}

void NetworkDispatcher::MarkResourceAsCached(blink::DocumentLoader* loader,
                                             unsigned long identifier) {
  String request_id = blink::IdentifiersFactory::RequestId(loader, identifier);
  GetClient()->OnRequestServedFromCache(std::string(request_id.Utf8().data(), request_id.length()));
}

void NetworkDispatcher::DidReceiveResourceResponse(
  unsigned long identifier,
  blink::DocumentLoader* loader,
  const blink::ResourceResponse& response,
  blink::Resource* cached_resource) {
  String request_id = blink::IdentifiersFactory::RequestId(loader, identifier);
  bool is_not_modified = response.HttpStatusCode() == 304;

  bool resource_is_empty = true;
  automation::ResponsePtr resource_response =
      BuildObjectForResourceResponse(response, cached_resource,
                                     &resource_is_empty);

  PageDispatcher::ResourceType type =
      cached_resource
          ? PageDispatcher::ToResourceType(cached_resource->GetType())
          : PageDispatcher::kOtherResource;
  // Override with already discovered resource type.
  PageDispatcher::ResourceType saved_type = ToResourceType(resources_data_->GetResourceType(request_id));
  if (saved_type == PageDispatcher::kScriptResource ||
      saved_type == PageDispatcher::kXHRResource ||
      saved_type == PageDispatcher::kDocumentResource ||
      saved_type == PageDispatcher::kFetchResource ||
      saved_type == PageDispatcher::kEventSourceResource) {
    type = saved_type;
  }
  if (type == PageDispatcher::kDocumentResource && loader &&
      loader->GetSubstituteData().IsValid())
    return;

  // Resources are added to NetworkResourcesData as a WeakMember here and
  // removed in willDestroyResource() called in the prefinalizer of Resource.
  // Because NetworkResourceData retains weak references only, it
  // doesn't affect Resource lifetime.
  if (cached_resource)
    resources_data_->AddResource(request_id, cached_resource);
  String frame_id = loader && loader->GetFrame()
                        ? blink::IdentifiersFactory::FrameId(loader->GetFrame())
                        : "";
  String loader_id = blink::IdentifiersFactory::LoaderId(loader);
  resources_data_->ResponseReceived(request_id, frame_id, response);
  resources_data_->SetResourceType(request_id, ToResourceType(type));

  if (response.GetSecurityStyle() != blink::ResourceResponse::kSecurityStyleUnknown &&
      response.GetSecurityStyle() !=
          blink::ResourceResponse::kSecurityStyleUnauthenticated) {
    const blink::ResourceResponse::SecurityDetails* response_security_details =
        response.GetSecurityDetails();
    resources_data_->SetCertificate(request_id,
                                    response_security_details->certificate);
  }

  if (NetworkDispatcher::IsNavigation(loader, identifier))
    return;
  if (resource_response && !resource_is_empty) {
    std::string maybe_frame_id;
    if (!frame_id.IsEmpty())
      maybe_frame_id = std::string(frame_id.Utf8().data(), frame_id.length());
    GetClient()->OnResponseReceived(
        std::string(request_id.Utf8().data(), request_id.length()), std::string(loader_id.Utf8().data(), loader_id.length()), CurrentTimeTicksInSeconds(),
        PageDispatcher::ToAutomationResourceType(type),
        std::move(resource_response), std::move(maybe_frame_id));
  }
  // If we revalidated the resource and got Not modified, send content length
  // following didReceiveResponse as there will be no calls to didReceiveData
  // from the network stack.
  if (is_not_modified && cached_resource && cached_resource->EncodedSize())
    DidReceiveData(identifier, loader, nullptr, cached_resource->EncodedSize());
}

static bool IsErrorStatusCode(int status_code) {
  return status_code >= 400;
}

void NetworkDispatcher::DidReceiveData(unsigned long identifier,
                                       blink::DocumentLoader* loader,
                                       const char* data,
                                       int data_length) {
  String request_id = blink::IdentifiersFactory::RequestId(loader, identifier);

  if (data) {
    blink::NetworkResourcesData::ResourceData const* resource_data =
        resources_data_->Data(request_id);
    if (resource_data &&
        (!resource_data->CachedResource() ||
         resource_data->CachedResource()->GetDataBufferingPolicy() ==
             blink::kDoNotBufferData ||
         IsErrorStatusCode(resource_data->HttpStatusCode())))
      resources_data_->MaybeAddResourceData(request_id, data, data_length);
  }

  GetClient()->OnDataReceived(
      std::string(request_id.Utf8().data(), request_id.length()), 
      CurrentTimeTicksInSeconds(), data_length,
      resources_data_->GetAndClearPendingEncodedDataLength(request_id));
}

void NetworkDispatcher::DidReceiveBlob(unsigned long identifier,
                                       blink::DocumentLoader* loader,
                                       scoped_refptr<blink::BlobDataHandle> blob) {
  String request_id = blink::IdentifiersFactory::RequestId(loader, identifier);
  resources_data_->BlobReceived(request_id, std::move(blob));
}

void NetworkDispatcher::DidReceiveEncodedDataLength(
  blink::DocumentLoader* loader,
  unsigned long identifier,
  int encoded_data_length) {
  String request_id = blink::IdentifiersFactory::RequestId(loader, identifier);
  resources_data_->AddPendingEncodedDataLength(request_id, encoded_data_length);
}

void NetworkDispatcher::DidFinishLoading(unsigned long identifier,
                                         blink::DocumentLoader* loader,
                                         double monotonic_finish_time,
                                         int64_t encoded_data_length,
                                         int64_t decoded_body_length,
                                         bool blocked_cross_site_document) {
  String request_id = blink::IdentifiersFactory::RequestId(loader, identifier);
  std::string request_id_str(request_id.Utf8().data(), request_id.length());
  blink::NetworkResourcesData::ResourceData const* resource_data =
      resources_data_->Data(request_id);
  int pending_encoded_data_length =
      resources_data_->GetAndClearPendingEncodedDataLength(request_id);
  if (pending_encoded_data_length > 0) {
    GetClient()->OnDataReceived(request_id_str, CurrentTimeTicksInSeconds(), 0,
                                pending_encoded_data_length);
  }

  if (resource_data &&
      (!resource_data->CachedResource() ||
       resource_data->CachedResource()->GetDataBufferingPolicy() ==
           blink::kDoNotBufferData ||
       IsErrorStatusCode(resource_data->HttpStatusCode()))) {
    resources_data_->MaybeAddResourceData(request_id, "", 0);
  }

  resources_data_->MaybeDecodeDataToContent(request_id);
  if (!monotonic_finish_time)
    monotonic_finish_time = CurrentTimeTicksInSeconds();

  GetClient()->OnLoadingFinished(request_id_str, monotonic_finish_time,
                                 encoded_data_length,
                                 blocked_cross_site_document);
}

void NetworkDispatcher::DidReceiveCORSRedirectResponse(
  unsigned long identifier,
  blink::DocumentLoader* loader,
  const blink::ResourceResponse& response,
  blink::Resource* resource) {
  // Update the response and finish loading
  DidReceiveResourceResponse(identifier, loader, response, resource);
  DidFinishLoading(identifier, loader, 0,
                   blink::WebURLLoaderClient::kUnknownEncodedDataLength, 0, false);
}

void NetworkDispatcher::DidFailLoading(unsigned long identifier,
                                       blink::DocumentLoader* loader,
                                       const blink::ResourceError& error) {
  String request_id = blink::IdentifiersFactory::RequestId(loader, identifier);
  bool canceled = error.IsCancellation();
  GetClient()->OnLoadingFailed(
      std::string(request_id.Utf8().data(), request_id.length()), 
      CurrentTimeTicksInSeconds(),
      PageDispatcher::ToAutomationResourceType(ToResourceType(resources_data_->GetResourceType(request_id))),
      std::string(error.LocalizedDescription().Utf8().data(), error.LocalizedDescription().length()), 
      canceled,
      automation::BlockedReason::BLOCKED_REASON_OTHER);
}

void NetworkDispatcher::ScriptImported(unsigned long identifier,
                                       const String& source_string) {
  resources_data_->SetResourceContent(
      blink::IdentifiersFactory::SubresourceRequestId(identifier), source_string);
}

void NetworkDispatcher::DidReceiveScriptResponse(unsigned long identifier) {
  resources_data_->SetResourceType(
      blink::IdentifiersFactory::SubresourceRequestId(identifier),
      ToResourceType(PageDispatcher::kScriptResource));
}

void NetworkDispatcher::ClearPendingRequestData() {
  if (pending_request_type_ == PageDispatcher::kXHRResource)
    pending_xhr_replay_data_.Clear();
  pending_request_ = nullptr;
}

void NetworkDispatcher::DocumentThreadableLoaderStartedLoadingForClient(
  unsigned long identifier,
  blink::ThreadableLoaderClient* client) {
  if (!client)
    return;
  if (client != pending_request_) {
    DCHECK(!pending_request_);
    return;
  }

  known_request_id_map_.Set(client, identifier);
  String request_id = blink::IdentifiersFactory::SubresourceRequestId(identifier);
  resources_data_->SetResourceType(request_id, ToResourceType(pending_request_type_));
  if (pending_request_type_ == PageDispatcher::kXHRResource) {
    resources_data_->SetXHRReplayData(request_id,
                                      pending_xhr_replay_data_.Get());
  }

  ClearPendingRequestData();
}

void NetworkDispatcher::DocumentThreadableLoaderFailedToStartLoadingForClient(blink::ThreadableLoaderClient* client) {
  if (!client)
    return;
  if (client != pending_request_) {
    DCHECK(!pending_request_);
    return;
  }

  ClearPendingRequestData();
}

void NetworkDispatcher::WillLoadXHR(blink::XMLHttpRequest* xhr,
                                    blink::ThreadableLoaderClient* client,
                                    const AtomicString& method,
                                    const blink::KURL& url,
                                    bool async,
                                    const blink::HTTPHeaderMap& headers,
                                    bool include_credentials) {
  DCHECK(xhr);
  DCHECK(!pending_request_);
  pending_request_ = client;
  pending_request_type_ = PageDispatcher::kXHRResource;
  pending_xhr_replay_data_ = blink::XHRReplayData::Create(
      method, UrlWithoutFragment(url), async, include_credentials);
  for (const auto& header : headers)
    pending_xhr_replay_data_->AddHeader(header.key, header.value);
}

void NetworkDispatcher::DelayedRemoveReplayXHR(blink::XMLHttpRequest* xhr) {
  if (!replay_xhrs_.Contains(xhr))
    return;
  replay_xhrs_to_be_deleted_.insert(xhr);
  replay_xhrs_.erase(xhr);
  remove_finished_replay_xhr_timer_->StartOneShot(TimeDelta(), FROM_HERE);
}

void NetworkDispatcher::DidFailXHRLoading(blink::ExecutionContext* context,
                                          blink::XMLHttpRequest* xhr,
                                          blink::ThreadableLoaderClient* client,
                                          const AtomicString& method,
                                          const String& url) {
  DidFinishXHRInternal(context, xhr, client, method, url, false);
}

void NetworkDispatcher::DidFinishXHRLoading(blink::ExecutionContext* context,
                                            blink::XMLHttpRequest* xhr,
                                            blink::ThreadableLoaderClient* client,
                                            const AtomicString& method,
                                            const String& url) {
  DidFinishXHRInternal(context, xhr, client, method, url, true);
}

void NetworkDispatcher::DidFinishXHRInternal(blink::ExecutionContext* context,
                                             blink::XMLHttpRequest* xhr,
                                             blink::ThreadableLoaderClient* client,
                                             const AtomicString& method,
                                             const String& url,
                                             bool success) {
  ClearPendingRequestData();

  // This method will be called from the XHR.
  // We delay deleting the replay XHR, as deleting here may delete the caller.
  DelayedRemoveReplayXHR(xhr);

  ThreadableLoaderClientRequestIdMap::iterator it =
      known_request_id_map_.find(client);
  if (it == known_request_id_map_.end())
    return;
  known_request_id_map_.erase(client);
}

void NetworkDispatcher::WillStartFetch(blink::ThreadableLoaderClient* client) {
  DCHECK(!pending_request_);
  pending_request_ = client;
  pending_request_type_ = PageDispatcher::kFetchResource;
}

void NetworkDispatcher::DidFailFetch(blink::ThreadableLoaderClient* client) {
  known_request_id_map_.erase(client);
}

void NetworkDispatcher::DidFinishFetch(blink::ExecutionContext* context,
                                       blink::ThreadableLoaderClient* client,
                                       const AtomicString& method,
                                       const String& url) {
  ThreadableLoaderClientRequestIdMap::iterator it =
      known_request_id_map_.find(client);
  if (it == known_request_id_map_.end())
    return;
  known_request_id_map_.erase(client);
}

void NetworkDispatcher::WillSendEventSourceRequest(
  blink::ThreadableLoaderClient* event_source) {
  DCHECK(!pending_request_);
  pending_request_ = event_source;
  pending_request_type_ = PageDispatcher::kEventSourceResource;
}

void NetworkDispatcher::WillDispatchEventSourceEvent(
  blink::ThreadableLoaderClient* event_source,
  const AtomicString& event_name,
  const AtomicString& event_id,
  const String& data) {
  ThreadableLoaderClientRequestIdMap::iterator it =
      known_request_id_map_.find(event_source);
  if (it == known_request_id_map_.end())
    return;

  String request_id = blink::IdentifiersFactory::SubresourceRequestId(it->value);
  GetClient()->OnEventSourceMessageReceived(
      std::string(request_id.Utf8().data(), request_id.length()),
      CurrentTimeTicksInSeconds(), 
      std::string(reinterpret_cast<const char *>(event_name.Characters8()), event_name.length()), 
      std::string(reinterpret_cast<const char *>(event_id.Characters8()), event_id.length()),
      std::string(data.Utf8().data(), data.length()));
}

void NetworkDispatcher::DidFinishEventSourceRequest(
  blink::ThreadableLoaderClient* event_source) {
  known_request_id_map_.erase(event_source);
  ClearPendingRequestData();
}

void NetworkDispatcher::DetachClientRequest(
  blink::ThreadableLoaderClient* client) {
  // This method is called by loader clients when finalizing
  // (i.e., from their "prefinalizers".) The client reference must
  // no longer be held onto upon completion.
  if (pending_request_ == client) {
    pending_request_ = nullptr;
    if (pending_request_type_ == PageDispatcher::kXHRResource) {
      pending_xhr_replay_data_.Clear();
    }
  }
  known_request_id_map_.erase(client);
}

void NetworkDispatcher::ApplyUserAgentOverride(String* user_agent) {
  if (!user_agent_override_.empty())
    *user_agent = String::FromUTF8(user_agent_override_.data());
}

automation::InitiatorPtr NetworkDispatcher::BuildInitiatorObject(
  blink::Document* document,
  const blink::FetchInitiatorInfo& initiator_info) {

  if (!initiator_info.imported_module_referrer.IsEmpty()) {
    automation::InitiatorPtr initiator_object = automation::Initiator::New();
    initiator_object->url = std::string(initiator_info.imported_module_referrer.Utf8().data(), initiator_info.imported_module_referrer.length());
    initiator_object->line_number = initiator_info.position.line_.ZeroBasedInt();
    return initiator_object;
  }

  std::unique_ptr<v8_inspector::protocol::Runtime::API::StackTrace>
      current_stack_trace =
          blink::SourceLocation::Capture(document)->BuildInspectorObject();
  if (current_stack_trace) {
    automation::InitiatorPtr initiator_object = automation::Initiator::New();
    initiator_object->type = automation::InitiatorType::INITIATOR_TYPE_SCRIPT;
    //initiator_object->stack = std::move(current_stack_trace);
    return initiator_object;
  }

  while (document && !document->GetScriptableDocumentParser())
    document = document->LocalOwner() ? document->LocalOwner()->ownerDocument()
                                      : nullptr;
  if (document && document->GetScriptableDocumentParser()) {
    String doc_url = UrlWithoutFragment(document->Url()).GetString();
    automation::InitiatorPtr initiator_object = automation::Initiator::New();
    initiator_object->type = automation::InitiatorType::INITIATOR_TYPE_SCRIPT;
    initiator_object->url = std::string(doc_url.Utf8().data(), doc_url.length());
    if (TextPosition::BelowRangePosition() != initiator_info.position)
      initiator_object->line_number = initiator_info.position.line_.ZeroBasedInt();
    else
      initiator_object->line_number = document->GetScriptableDocumentParser()->LineNumber().ZeroBasedInt();
    return initiator_object;
  }

  automation::InitiatorPtr initiator_object = automation::Initiator::New();
  initiator_object->type = automation::InitiatorType::INITIATOR_TYPE_OTHER;
  return initiator_object;
}

void NetworkDispatcher::DidCreateWebSocket(
  blink::ExecutionContext* execution_context,
  unsigned long identifier,
  const blink::KURL& request_url,
  const String& protocol) {
  std::unique_ptr<v8_inspector::protocol::Runtime::API::StackTrace>
      current_stack_trace =
          blink::SourceLocation::Capture(execution_context)->BuildInspectorObject();
  std::string identifier_str(blink::IdentifiersFactory::SubresourceRequestId(identifier).Utf8().data(), blink::IdentifiersFactory::SubresourceRequestId(identifier).length());
  String request_url_str = UrlWithoutFragment(request_url).GetString();
  std::string request_str(request_url_str.Utf8().data(), request_url_str.length());
  if (!current_stack_trace) {
    GetClient()->OnWebSocketCreated(
        identifier_str,
        request_str,
        nullptr);
    return;
  }

  automation::InitiatorPtr initiator_object = automation::Initiator::New();
  initiator_object->type = automation::InitiatorType::INITIATOR_TYPE_SCRIPT;
  //initiator_object->stack = std::move(current_stack_trace);
  GetClient()->OnWebSocketCreated(
      identifier_str,
      request_str, 
      std::move(initiator_object));
}

void NetworkDispatcher::WillSendWebSocketHandshakeRequest(
  blink::ExecutionContext*,
  unsigned long identifier,
  const blink::WebSocketHandshakeRequest* request) {
  DCHECK(request);
  automation::WebSocketRequestPtr request_object = automation::WebSocketRequest::New();
  request_object->headers = BuildObjectForHeaders(request->HeaderFields());
  String identifier_str = blink::IdentifiersFactory::SubresourceRequestId(identifier);
  GetClient()->OnWebSocketWillSendHandshakeRequest(
      std::string(identifier_str.Utf8().data(), identifier_str.length()),
      CurrentTimeTicksInSeconds(), CurrentTime(), std::move(request_object));
}

void NetworkDispatcher::DidReceiveWebSocketHandshakeResponse(
  blink::ExecutionContext*,
  unsigned long identifier,
  const blink::WebSocketHandshakeRequest* request,
  const blink::WebSocketHandshakeResponse* response) {
  DCHECK(response);
  automation::WebSocketResponsePtr response_object = automation::WebSocketResponse::New();
  response_object->status = response->StatusCode();
  response_object->status_text = std::string(response->StatusText().Utf8().data(), response->StatusText().length());
  response_object->headers = BuildObjectForHeaders(response->HeaderFields());

  if (!response->HeadersText().IsEmpty())
    response_object->headers_text = std::string(response->HeadersText().Utf8().data(), response->HeadersText().length());
  if (request) {
    response_object->request_headers = BuildObjectForHeaders(request->HeaderFields());
    if (!request->HeadersText().IsEmpty())
      response_object->request_headers_text = std::string(request->HeadersText().Utf8().data(), request->HeadersText().length());
  }
  String identifier_str = blink::IdentifiersFactory::SubresourceRequestId(identifier);
  GetClient()->OnWebSocketHandshakeResponseReceived(
      std::string(identifier_str.Utf8().data(), identifier_str.length()),
      CurrentTimeTicksInSeconds(), std::move(response_object));
}

void NetworkDispatcher::DidCloseWebSocket(blink::ExecutionContext*,
                                          unsigned long identifier) {
  String identifier_str = blink::IdentifiersFactory::SubresourceRequestId(identifier);                                          
  GetClient()->OnWebSocketClosed(
      std::string(identifier_str.Utf8().data(), identifier_str.length()),
      CurrentTimeTicksInSeconds());
}

void NetworkDispatcher::DidReceiveWebSocketFrame(unsigned long identifier,
                                                 int op_code,
                                                 bool masked,
                                                 const char* payload,
                                                 size_t payload_length) {
  automation::WebSocketFramePtr frame_object = automation::WebSocketFrame::New();
  frame_object->opcode = op_code;
  frame_object->mask = masked;
  frame_object->payload_data = std::string(payload, payload_length);
  String identifier_str = blink::IdentifiersFactory::SubresourceRequestId(identifier);
  GetClient()->OnWebSocketFrameReceived(
      std::string(identifier_str.Utf8().data(), identifier_str.length()),
      CurrentTimeTicksInSeconds(), std::move(frame_object));
}

void NetworkDispatcher::DidSendWebSocketFrame(unsigned long identifier,
                                              int op_code,
                                              bool masked,
                                              const char* payload,
                                              size_t payload_length) {
  automation::WebSocketFramePtr frame_object = automation::WebSocketFrame::New();
  frame_object->opcode = op_code;
  frame_object->mask = masked;
  frame_object->payload_data = std::string(payload, payload_length);
  String identifier_str = blink::IdentifiersFactory::RequestId(nullptr, identifier);
  GetClient()->OnWebSocketFrameSent(
      std::string(identifier_str.Utf8().data(), identifier_str.length()),
      CurrentTimeTicksInSeconds(), std::move(frame_object));
}

void NetworkDispatcher::DidReceiveWebSocketFrameError(
  unsigned long identifier,
  const String& error_message) {
  String identifier_str = blink::IdentifiersFactory::RequestId(nullptr, identifier);
  GetClient()->OnWebSocketFrameError(
    std::string(identifier_str.Utf8().data(), identifier_str.length()),
    CurrentTimeTicksInSeconds(), 
    std::string(error_message.Utf8().data(), error_message.length()));
}

blink::LocalFrame* NetworkDispatcher::GetMainFrame() {
  return page_instance_->inspected_frames()->Root();
}

bool NetworkDispatcher::GetResponseBody(const String& request_id,
                                        String* content,
                                        bool* base64_encoded) {
  blink::NetworkResourcesData::ResourceData const* resource_data =
      resources_data_->Data(request_id);
  if (!resource_data) {
    //DLOG(ERROR) << "No resource with given identifier found";
    return false;
  }

  if (resource_data->HasContent()) {
    *content = resource_data->Content();
    *base64_encoded = resource_data->Base64Encoded();
    return true;
  }

  if (resource_data->IsContentEvicted()) {
    //DLOG(ERROR) << "Request content was evicted from inspector cache";
    return false;
  }

  if (resource_data->Buffer() && !resource_data->TextEncodingName().IsNull()) {
    bool success = PageDispatcher::SharedBufferContent(
        resource_data->Buffer(), resource_data->MimeType(),
        resource_data->TextEncodingName(), content, base64_encoded);
    DCHECK(success);
    return true;
  }

  if (resource_data->CachedResource() &&
    PageDispatcher::CachedResourceContent(resource_data->CachedResource(),
                                          content, base64_encoded)) {
    return true;
  }

  //DLOG(ERROR) << "No data found for resource with given identifier";
  return false;
}

bool NetworkDispatcher::FetchResourceContent(blink::Document* document,
                                             const blink::KURL& url,
                                             String* content,
                                             bool* base64_encoded) {
  DCHECK(document);
  DCHECK(IsMainThread());
  // First try to fetch content from the cached resource.
  blink::Resource* cached_resource = document->Fetcher()->CachedResource(url);
  if (!cached_resource) {
    cached_resource = blink::GetMemoryCache()->ResourceForURL(
        url, document->Fetcher()->GetCacheIdentifier());
  }
  if (cached_resource && PageDispatcher::CachedResourceContent(
                             cached_resource, content, base64_encoded))
    return true;

  // Then fall back to resource data.
  for (auto& resource : resources_data_->Resources()) {
    if (resource->RequestedURL() == url) {
      *content = resource->Content();
      *base64_encoded = resource->Base64Encoded();
      return true;
    }
  }
  return false;
}

void NetworkDispatcher::OnWebFrameCreated(blink::WebLocalFrame* web_frame) {
  network_agent_impl_ = new InspectorNetworkAgentImpl(this);
  
  network_agent_impl_->Init(
    page_instance_->probe_sink(), 
    page_instance_->inspector_backend_dispatcher(),
    page_instance_->state());
  
  conditions_token_ = blink::IdentifiersFactory::IdFromToken(
      page_instance_->worker_global_scope() ? page_instance_->worker_global_scope()->GetParentDevToolsToken()
                                            : page_instance_->inspected_frames()->Root()->GetDevToolsFrameToken());
  
  remove_finished_replay_xhr_timer_.reset(
    new blink::TaskRunnerTimer<NetworkDispatcher>(
          page_instance_->worker_global_scope()
              ? page_instance_->worker_global_scope()->GetTaskRunner(blink::TaskType::kInternalLoading)
              : page_instance_->inspected_frames()->Root()->GetTaskRunner(
                    blink::TaskType::kInternalLoading),
          this,
          &NetworkDispatcher::RemoveFinishedReplayXHRFired));
}

}
