// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_APPLICATION_NETWORK_DISPATCHER_H_
#define MUMBA_APPLICATION_NETWORK_DISPATCHER_H_

#include "core/shared/common/mojom/automation.mojom.h"

#include "mojo/public/cpp/bindings/binding.h"
#include "mojo/public/cpp/bindings/associated_binding.h"
#include "core/shared/application/automation/page_dispatcher.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource.h"

namespace blink {
class KURL;  
class NetworkResourcesData;
class ExecutionContext;
class ThreadableLoaderClient;
class XMLHttpRequest;
class WebSocketHandshakeRequest;
class WebSocketHandshakeResponse;
class DocumentLoader;
class XHRReplayData;
class TimerBase;
}

namespace service_manager {
class InterfaceProvider;
}

namespace IPC {
class SyncChannel;
}

namespace application {
class InspectorNetworkAgentImpl;
class PageInstance;

class NetworkDispatcher : public automation::Network {
public:

  static void Create(automation::NetworkRequest request, PageInstance* page_instance);
  
  NetworkDispatcher(automation::NetworkRequest request, PageInstance* page_instance);
  NetworkDispatcher(PageInstance* page_instance);
  ~NetworkDispatcher() override;

  static bool IsNavigation(blink::DocumentLoader*, unsigned long identifier);

  void Init(IPC::SyncChannel* channel);

  void Bind(automation::NetworkAssociatedRequest request);

  void Register(int32_t application_id) override;
  void CanClearBrowserCache(CanClearBrowserCacheCallback callback) override;
  void CanClearBrowserCookies(CanClearBrowserCookiesCallback callback) override;
  void CanEmulateNetworkConditions(CanEmulateNetworkConditionsCallback callback) override;
  void ClearBrowserCache() override;
  void ClearBrowserCookies() override;
  void ContinueInterceptedRequest(const std::string& interception_id, automation::ErrorReason error_reason, const base::Optional<std::string>& raw_response, const base::Optional<std::string>& url, const base::Optional<std::string>& method, const base::Optional<std::string>& post_data, const base::Optional<base::flat_map<std::string, std::string>>& headers, automation::AuthChallengeResponsePtr auth_challenge_response) override;
  void DeleteCookies(const std::string& name, const base::Optional<std::string>& url, const base::Optional<std::string>& domain, const base::Optional<std::string>& path) override;
  void Disable() override;
  void EmulateNetworkConditions(bool offline, int64_t latency, int64_t download_throughput, int64_t upload_throughput, automation::ConnectionType connection_type) override;
  void Enable(int32_t max_total_buffer_size, int32_t max_resource_buffer_size, int32_t max_post_data_size) override;
  void GetAllCookies(GetAllCookiesCallback callback) override;
  void GetCertificate(const std::string& origin, GetCertificateCallback callback) override;
  void GetCookies(const base::Optional<std::vector<std::string>>& urls, GetCookiesCallback callback) override;
  void GetResponseBody(const std::string& request_id, GetResponseBodyCallback callback) override;
  void GetRequestPostData(const std::string& request_id, GetRequestPostDataCallback callback) override;
  void GetResponseBodyForInterception(const std::string& interception_id, GetResponseBodyForInterceptionCallback callback) override;
  void TakeResponseBodyForInterceptionAsStream(const std::string& interception_id, TakeResponseBodyForInterceptionAsStreamCallback callback) override;
  void ReplayXHR(const std::string& request_id) override;
  void SearchInResponseBody(const std::string& request_id, const std::string& query, bool case_sensitive, bool is_regex, SearchInResponseBodyCallback callback) override;
  void SetBlockedURLs(const std::vector<std::string>& urls) override;
  void SetBypassServiceWorker(bool bypass) override;
  void SetCacheDisabled(bool cache_disabled) override;
  void SetCookie(const std::string& name, const std::string& value, const base::Optional<std::string>& url, const base::Optional<std::string>& domain, const base::Optional<std::string>& path, bool secure, bool http_only, automation::CookieSameSite same_site, int64_t expires, SetCookieCallback callback) override;
  void SetCookies(std::vector<automation::CookieParamPtr> cookies) override;
  void SetDataSizeLimitsForTest(int32_t max_total_size, int32_t max_resource_size) override;
  void SetExtraHTTPHeaders(const base::flat_map<std::string, std::string>& headers) override;
  void SetRequestInterception(std::vector<automation::RequestPatternPtr> patterns) override;
  void SetUserAgentOverride(const std::string& userAgent) override;

  bool FetchResourceContent(blink::Document*,
                            const blink::KURL&,
                            String* content,
                            bool* base64_encoded);

  automation::NetworkClient* GetClient() const;

  PageInstance* page_instance() const {
    return page_instance_;
  }

  void OnWebFrameCreated(blink::WebLocalFrame* web_frame);
  
private:
  friend class InspectorNetworkAgentImpl;

  blink::LocalFrame* GetMainFrame();

  void DidBlockRequest(
    blink::ExecutionContext* execution_context,
    const blink::ResourceRequest& request,
    blink::DocumentLoader* loader,
    const blink::FetchInitiatorInfo& initiator_info,
    blink::ResourceRequestBlockedReason reason,
    blink::Resource::Type resource_type);

  void DidChangeResourcePriority(
    blink::DocumentLoader* loader,
    unsigned long identifier,
    blink::ResourceLoadPriority load_priority);

  void WillSendRequestInternal(
    blink::ExecutionContext* execution_context,
    unsigned long identifier,
    blink::DocumentLoader* loader,
    const blink::ResourceRequest& request,
    const blink::ResourceResponse& redirect_response,
    const blink::FetchInitiatorInfo& initiator_info,
    PageDispatcher::ResourceType type);

  void WillSendRequest(
    blink::ExecutionContext* execution_context,
    unsigned long identifier,
    blink::DocumentLoader* loader,
    blink::ResourceRequest& request,
    const blink::ResourceResponse& redirect_response,
    const blink::FetchInitiatorInfo& initiator_info,
    blink::Resource::Type resource_type);

  void MarkResourceAsCached(blink::DocumentLoader* loader,
                            unsigned long identifier);

  void DidReceiveResourceResponse(
    unsigned long identifier,
    blink::DocumentLoader* loader,
    const blink::ResourceResponse& response,
    blink::Resource* cached_resource);

  void DidReceiveData(unsigned long identifier,
                      blink::DocumentLoader* loader,
                      const char* data,
                      int data_length);

  void DidReceiveBlob(unsigned long identifier,
                      blink::DocumentLoader* loader,
                      scoped_refptr<blink::BlobDataHandle> blob);

  void DidReceiveEncodedDataLength(
    blink::DocumentLoader* loader,
    unsigned long identifier,
    int encoded_data_length);

  void DidFinishLoading(unsigned long identifier,
                        blink::DocumentLoader* loader,
                        double monotonic_finish_time,
                        int64_t encoded_data_length,
                        int64_t decoded_body_length,
                        bool blocked_cross_site_document);

  void DidReceiveCORSRedirectResponse(
    unsigned long identifier,
    blink::DocumentLoader* loader,
    const blink::ResourceResponse& response,
    blink::Resource* resource);

  void DidFailLoading(unsigned long identifier,
                      blink::DocumentLoader* loader,
                      const blink::ResourceError& error);

  void ScriptImported(unsigned long identifier,
                      const String& source_string);

  void DidReceiveScriptResponse(unsigned long identifier);

  void ClearPendingRequestData();


  void DocumentThreadableLoaderStartedLoadingForClient(
    unsigned long identifier,
    blink::ThreadableLoaderClient* client);

  void DocumentThreadableLoaderFailedToStartLoadingForClient(blink::ThreadableLoaderClient* client);

  void WillLoadXHR(blink::XMLHttpRequest* xhr,
                   blink::ThreadableLoaderClient* client,
                   const AtomicString& method,
                   const blink::KURL& url,
                   bool async,
                   const blink::HTTPHeaderMap& headers,
                   bool include_credentials);

  void DelayedRemoveReplayXHR(blink::XMLHttpRequest* xhr);

  void DidFailXHRLoading(blink::ExecutionContext* context,
                         blink::XMLHttpRequest* xhr,
                         blink::ThreadableLoaderClient* client,
                         const AtomicString& method,
                         const String& url);

  void DidFinishXHRLoading(blink::ExecutionContext* context,
                           blink::XMLHttpRequest* xhr,
                           blink::ThreadableLoaderClient* client,
                           const AtomicString& method,
                           const String& url);

  void DidFinishXHRInternal(blink::ExecutionContext* context,
                            blink::XMLHttpRequest* xhr,
                            blink::ThreadableLoaderClient* client,
                            const AtomicString& method,
                            const String& url,
                            bool success);


  void WillStartFetch(blink::ThreadableLoaderClient* client);
  void DidFailFetch(blink::ThreadableLoaderClient* client);
  void DidFinishFetch(blink::ExecutionContext* context,
                      blink::ThreadableLoaderClient* client,
                      const AtomicString& method,
                      const String& url);
  void WillSendEventSourceRequest(blink::ThreadableLoaderClient* event_source);
  void WillDispatchEventSourceEvent(
    blink::ThreadableLoaderClient* event_source,
    const AtomicString& event_name,
    const AtomicString& event_id,
    const String& data);
  void DidFinishEventSourceRequest(blink::ThreadableLoaderClient* event_source);
  void DetachClientRequest(blink::ThreadableLoaderClient* client);

  void ApplyUserAgentOverride(String* user_agent);

  automation::InitiatorPtr BuildInitiatorObject(
    blink::Document* document,
    const blink::FetchInitiatorInfo& initiator_info);

  void DidCreateWebSocket(
    blink::ExecutionContext* execution_context,
    unsigned long identifier,
    const blink::KURL& request_url,
    const String&);

  void WillSendWebSocketHandshakeRequest(
    blink::ExecutionContext*,
    unsigned long identifier,
    const blink::WebSocketHandshakeRequest* request);

  void DidReceiveWebSocketHandshakeResponse(
    blink::ExecutionContext*,
    unsigned long identifier,
    const blink::WebSocketHandshakeRequest* request,
    const blink::WebSocketHandshakeResponse* response);

  void DidCloseWebSocket(blink::ExecutionContext*,
                         unsigned long identifier);

  void DidReceiveWebSocketFrame(unsigned long identifier,
                                int op_code,
                                bool masked,
                                const char* payload,
                                size_t payload_length);

  void DidSendWebSocketFrame(unsigned long identifier,
                             int op_code,
                             bool masked,
                             const char* payload,
                             size_t payload_length);

  void DidReceiveWebSocketFrameError(unsigned long identifier, const String& error_message);

  bool CanGetResponseBodyBlob(const std::string& request_id);
  void GetResponseBodyBlob(const std::string& request_id, GetResponseBodyCallback callback);

  bool GetResponseBody(const String& request_id,
                       String* content,
                       bool* base64_encoded);

  void RemoveFinishedReplayXHRFired(blink::TimerBase*);

  int32_t application_id_;
  PageInstance* page_instance_;
  mojo::AssociatedBinding<automation::Network> binding_;
  // FIXME: One PageInstance per dispatcher? the ideal is a shared one
  // but this is just til things run
  automation::NetworkClientAssociatedPtr network_client_ptr_;

  blink::Persistent<InspectorNetworkAgentImpl> network_agent_impl_;
  blink::HeapHashSet<blink::Member<blink::XMLHttpRequest>> replay_xhrs_;
  blink::HeapHashSet<blink::Member<blink::XMLHttpRequest>> replay_xhrs_to_be_deleted_;
  blink::Member<blink::NetworkResourcesData> resources_data_;

  typedef HashMap<blink::ThreadableLoaderClient*, unsigned long>
      ThreadableLoaderClientRequestIdMap;

  // Stores the pending ThreadableLoaderClient till an identifier for
  // the load is generated by the loader and passed to the inspector
  // via the documentThreadableLoaderStartedLoadingForClient() method.
  blink::ThreadableLoaderClient* pending_request_;
  PageDispatcher::ResourceType pending_request_type_;
  ThreadableLoaderClientRequestIdMap known_request_id_map_;

  std::vector<std::string> blocked_urls_;
  base::flat_map<std::string, std::string> extra_http_headers_;

  std::string user_agent_override_;
  String conditions_token_;

  blink::Member<blink::XHRReplayData> pending_xhr_replay_data_;
  std::unique_ptr<blink::TaskRunnerTimer<NetworkDispatcher>> remove_finished_replay_xhr_timer_;

  int32_t total_buffer_size_;
  int32_t resource_buffer_size_;
  int32_t max_post_data_size_;

  bool enabled_;
  bool cache_disabled_;
  bool bypass_service_worker_;

  DISALLOW_COPY_AND_ASSIGN(NetworkDispatcher); 
};

}

#endif