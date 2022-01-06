// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_RUNTIME_MUMBA_SHIMS_MODULE_SHIMS_H_
#define MUMBA_RUNTIME_MUMBA_SHIMS_MODULE_SHIMS_H_

#include "Globals.h"
#include "EngineCallbacks.h"

typedef void* EngineInstanceRef;
typedef void* EngineClientRef;
typedef void* ApplicationHostRef;
typedef void* StorageRef;
//typedef void* PlaceRegistryRef;

//
typedef void* HistogramPtrRef;
// automation::FramePtr
typedef void* FramePtrRef;
// automation::NavigationReason
typedef int NavigationReasonEnum;
//
typedef void* NavigationEntryPtrRef;
// automation::DialogType
typedef int DialogTypeEnum;
// automation::ScreencastFrameMetadataPtr
typedef void* ScreencastFrameMetadataPtrRef;
// ViewportPtrRef
typedef void* ViewportPtrRef;

typedef void* CookiePtrRef;
// automation::ServiceWorkerErrorMessagePtr 
typedef void* ServiceWorkerErrorMessagePtrRef;
// automation::ServiceWorkerRegistrationPtr
typedef void* ServiceWorkerRegistrationPtrRef;
// automation::ServiceWorkerVersionPtr
typedef void* ServiceWorkerVersionPtrRef;
// automation::TargetInfoPtr
typedef void* TargetInfoPtrRef;
// automation::StorageIdPtr
typedef void* StorageIdPtrRef;
// ResourceTypeEnum
typedef int ResourceTypeEnum;
// automation::RequestPtr
typedef void* RequestPtrRef;
// automation::ResourcePriority
typedef int ResourcePriorityEnum;
// automation::InitiatorPtr
typedef void* InitiatorPtrRef;
// automation::WebSocketFramePtr
typedef void* WebSocketFramePtrRef;
// automation::ResponsePtr
typedef void* ResponsePtrRef;
// automation::WebSocketRequestPtr
typedef void* WebSocketRequestPtrRef;

typedef void* WebSocketResponsePtrRef;
// automation::AuthChallengePtr
typedef void* AuthChallengePtrRef;
// automation::ErrorReason
typedef int ErrorReasonEnum;
// automation::LayerPtr
typedef void* LayerPtrRef;
// automation::DOMNodePtr
typedef void* DOMNodePtrRef;
// automation::DatabasePtr
typedef void* DatabasePtrRef;
// automation::BackendNodePtr
typedef void* BackendNodePtrRef;
// automation::FontFacePtr
typedef void* FontFacePtrRef;
// automation::CSSStyleSheetHeaderPtr
typedef void* CSSStyleSheetHeaderPtrRef;
// automation::AnimationPtr
typedef void* AnimationPtrRef;
// automation::BlockedReason
typedef int BlockedReasonEnum;
// automation::BoundsPtr
typedef void* BoundsPtrRef;
// automation::RGBAPtr
typedef void* RGBAPtrRef;
// automation::HighlightConfigPtr
typedef void* HighlightConfigPtrRef;
// automation::TransitionType
typedef int TransitionTypeEnum;
// automation::InspectMode
typedef int InspectModeEnum;
// automation::ScreenOrientationPtr
typedef void* ScreenOrientationPtrRef;
// automation::StorageType
typedef int StorageTypeEnum;
// automation::UsageForTypePtr
typedef void* UsageForTypePtrRef;
// automation::ConnectionType
typedef int ConnectionTypeEnum;
// automation::CookieSameSite
typedef int CookieSameSiteEnum;
// automation::RequestPatternPtr
typedef void* RequestPatternPtrRef;
// automation::PictureTilePtr
typedef void* PictureTilePtrRef;
// automation::CookieParamPtr
typedef void* CookieParamPtrRef;
// automation::KeyEventType
typedef int KeyEventTypeEnum;
// automation::MouseEventType
typedef int MouseEventTypeEnum;
// automation::TouchEventType
typedef int TouchEventTypeEnum;
// automation::MouseButton
typedef int MouseButtonEnum;
// automation::GestureSourceType
typedef int GestureSourceTypeEnum;
// automation::VirtualTimePolicy
typedef int VirtualTimePolicyEnum;
// automation::TouchEventForMouseConfiguration
typedef int TouchEventForMouseConfigurationEnum;
// automation::SourceRangePtr
typedef void* SourceRangePtrRef;
// automation::StyleDeclarationEditPtr
typedef void* StyleDeclarationEditPtrRef;

typedef void* GPUInfoPtrRef;

typedef int FrameFormatEnum;

typedef void* KeyRangePtrRef;

typedef void* ScreenshotParamsPtrRef;

typedef void* FrameTreePtrRef;

typedef void* FrameResourceTreePtrRef;

typedef void* FrameResourcePtrRef;

typedef void* SearchMatchPtrRef;

typedef void* LayoutViewportPtrRef;

typedef void* VisualViewportPtrRef;

typedef void* IndexedDBDataEntryPtrRef;

typedef void* DatabaseWithObjectStoresPtrRef;

typedef void* OwnedValueRef;

typedef void* ErrorPtrRef;

typedef void* LayoutTreeNodePtrRef;

typedef void* DOMSnapshotNodePtrRef;

typedef void* ComputedStylePtrRef;

typedef void* BoxModelPtrRef;

typedef void* RemoteObjectPtrRef;

typedef void* CSSRulePtrRef;

typedef void* CSSComputedStylePropertyPtrRef;

typedef void* CSSStylePtrRef;

typedef void* RuleMatchPtrRef;

typedef void* PseudoElementMatchesPtrRef;

typedef void* InheritedStyleEntryPtrRef;

typedef void* CSSKeyframesRulePtrRef;

typedef void* CSSKeyframeRulePtrRef;

typedef void* PlatformFontUsagePtrRef;

typedef void* CSSValuePtrRef;

typedef void* CSSMediaPtrRef;

typedef void* CSSMediaQueryPtrRef;

typedef void* CSSMediaQueryExpressionPtrRef;

typedef void* SelectorListPtrRef;

typedef void* CSSRuleUsagePtrRef;

typedef void* CachedResponsePtrRef;

typedef void* CachePtrRef;

typedef void* DataEntryPtrRef;

typedef void* AXNodePtrRef;

typedef void* FrameWithManifestPtrRef;

typedef void* AuthChallengeResponsePtrRef;

typedef void* TouchPointPtrRef;

typedef void* ApplicationCachePtrRef;

typedef void* AnimationEffectPtrRef;

typedef void* BlobBytesProviderRef;

typedef void* BlobDataRef;

// Callbacks/Events
// PageClient
typedef struct {
  void (*OnFrameAttached)(void* state, const char* frame_id, const char* parent_frame_id);
  void (*OnDomContentEventFired)(void* state, int64_t timestamp);
  void (*OnFrameClearedScheduledNavigation)(void* state, const char* frame_id);
  void (*OnFrameDetached)(void* state, const char* frame_id);
  void (*OnFrameNavigated)(void* state, FramePtrRef frame) ;
  void (*OnFrameResized)(void* state);
  void (*OnFrameScheduledNavigation)(void* state, const char* frame_id, int32_t delay, NavigationReasonEnum reason, const char* url);
  void (*OnFrameStartedLoading)(void* state, const char* frame_id);
  void (*OnFrameStoppedLoading)(void* state, const char* frame_id);
  void (*OnInterstitialHidden)(void* state);
  void (*OnInterstitialShown)(void* state);
  void (*OnJavascriptDialogClosed)(void* state, int /* bool */ result, const char* user_input);
  void (*OnJavascriptDialogOpening)(void* state, const char* url, const char* message, DialogTypeEnum type, int /* bool */ has_browser_handler, const char* /* optional */ default_prompt);
  void (*OnLifecycleEvent)(void* state, const char* frame_id, int32_t loader_id, const char* name, int64_t timestamp);
  void (*OnLoadEventFired)(void* state, int64_t timestamp);
  void (*OnNavigatedWithinDocument)(void* state, const char* frame_id, const char* url);
  void (*OnScreencastFrame)(void* state, const char* base64_data, ScreencastFrameMetadataPtrRef metadata, int32_t session_id);
  void (*OnScreencastVisibilityChanged)(void* state, int /* bool */ visible);
  void (*OnWindowOpen)(void* state, const char* url, const char* window_name, const char** window_features, int window_features_count, int /* bool */ user_gesture);
  void (*OnPageLayoutInvalidated)(void* state, int /* bool */ resized);
} CPageCallbacks;

typedef struct {
  void (*InspectNodeRequested)(void* state, int32_t backend_node_id);
  void (*NodeHighlightRequested)(void* state, int32_t node_id);
  void (*ScreenshotRequested)(void* state, ViewportPtrRef viewport);
} COverlayCallbacks;

typedef struct {
  void (*WorkerErrorReported)(void* state, ServiceWorkerErrorMessagePtrRef error_message);
  void (*WorkerRegistrationUpdated)(void* state, ServiceWorkerRegistrationPtrRef* registrations, int registrations_count);
  void (*WorkerVersionUpdated)(void* state, ServiceWorkerVersionPtrRef* versions, int versions_count);
  void (*OnAttachedToTarget)(void* state, const char* session_id, TargetInfoPtrRef target_info, int /* bool */ waiting_for_debugger);
  void (*OnDetachedFromTarget)(void* state, const char* session_id, const char* /* optional */ target_id);
  void (*OnReceivedMessageFromTarget)(void* state, const char* session_id, const char* message, const char* /* optional */ target_id);
} CWorkerCallbacks;

typedef struct {
  void (*OnCacheStorageContentUpdated)(void* state, const char* origin, const char* cache_name);
  void (*OnCacheStorageListUpdated)(void* state, const char* origin);
  void (*OnIndexedDBContentUpdated)(void* state, const char* origin, const char* database_name, const char* object_store_name);
  void (*OnIndexedDBListUpdated)(void* state, const char* origin);
} CStorageCallbacks;

typedef struct {
  void (*OnAccepted)(void* state, int32_t port, const char* connection_id);
} CTetheringCallbacks;

typedef struct {
  void (*OnDataReceived)(void* state, const char* request_id, int64_t timestamp, int64_t data_length, int64_t encoded_data_length);
  void (*OnEventSourceMessageReceived)(void* state, const char* request_id, int64_t timestamp, const char* event_name, const char* event_id, const char* data);
  void (*OnLoadingFailed)(void* state, const char* request_id, int64_t timestamp, ResourceTypeEnum type, const char* error_text, int /* bool */ canceled, BlockedReasonEnum blocked_reason);
  void (*OnLoadingFinished)(void* state, const char* request_id, int64_t timestamp, int64_t encoded_data_length, int /* bool */ blocked_cross_site_document);
  void (*OnRequestIntercepted)(void* state, 
    const char* interception_id, 
    RequestPtrRef request, 
    const char* frame_id, 
    ResourceTypeEnum resource_type, 
    int /* bool */ is_navigation_request, 
    int /* bool */ is_download, 
    const char* /* optional */ redirect_url, 
    AuthChallengePtrRef auth_challenge, 
    ErrorReasonEnum response_error_reason, 
    int32_t response_status_code, 
    const char** response_headers_keys, int response_headers_keys_count, 
    const char** response_headers_values, int response_headers_values_count);
  void (*OnRequestServedFromCache)(void* state, const char* request_id);
  void (*OnRequestWillBeSent)(void* state, const char* request_id, const char* loader_id, 
    const char* document_url, 
    RequestPtrRef request, 
    int64_t timestamp, 
    int64_t wall_time, 
    InitiatorPtrRef initiator, 
    ResponsePtrRef redirect_response, 
    ResourceTypeEnum type, 
    const char* /* optional */ frame_id, 
    int /* bool */ has_user_gesture);
  void (*OnResourceChangedPriority)(void* state, const char* request_id, ResourcePriorityEnum new_priority, int64_t timestamp);
  void (*OnResponseReceived)(void* state, const char* request_id, const char* loader_id, int64_t timestamp, ResourceTypeEnum type, ResponsePtrRef response, const char* /* optional */ frame_id);
  void (*OnWebSocketClosed)(void* state, const char* request_id, int64_t timestamp);
  void (*OnWebSocketCreated)(void* state, const char* request_id, const char* url, InitiatorPtrRef initiator);
  void (*OnWebSocketFrameError)(void* state, const char* request_id, int64_t timestamp, const char* error_message);
  void (*OnWebSocketFrameReceived)(void* state, const char* request_id, int64_t timestamp, WebSocketFramePtrRef response);
  void (*OnWebSocketFrameSent)(void* state, const char* request_id, int64_t timestamp, WebSocketFramePtrRef response);
  void (*OnWebSocketHandshakeResponseReceived)(void* state, const char* request_id, int64_t timestamp, WebSocketResponsePtrRef response);
  void (*OnWebSocketWillSendHandshakeRequest)(void* state, const char* request_id, int64_t timestamp, int64_t wall_time, WebSocketRequestPtrRef request);
  void (*Flush)(void* state);
} CNetworkCallbacks;

typedef struct {
  void (*OnLayerPainted)(void* state, const char* layer_id, int clip_x, int clip_y, int clip_w, int clip_h);
  void (*OnLayerTreeDidChange)(void* state, LayerPtrRef* /* optional */ layers, int layers_count);
} CLayerTreeCallbacks;

// Headless
typedef struct {
  void (*OnNeedsBeginFramesChanged)(void* state, int /* bool */ needs_begin_frames);
} CHeadlessCallbacks;

typedef struct {
  void (*OnDomStorageItemAdded)(void* state, StorageIdPtrRef storage_id, const char* key, const char* new_value);
  void (*OnDomStorageItemRemoved)(void* state, StorageIdPtrRef storage_id, const char* key);
  void (*OnDomStorageItemUpdated)(void* state, StorageIdPtrRef storage_id, const char* key, const char* old_value, const char* new_value);
  void (*OnDomStorageItemsCleared)(void* state, StorageIdPtrRef storage_id);
} CDOMStorageCallbacks;

typedef struct {
  void (*OnAddDatabase)(void* state, DatabasePtrRef database);
} CDatabaseCallbacks;

typedef struct {
  void (*OnVirtualTimeAdvanced)(void* state, int32_t virtual_time_elapsed);
  void (*OnVirtualTimeBudgetExpired)(void* state);
  void (*OnVirtualTimePaused)(void* state, int32_t virtual_time_elapsed);
} CEmulationCallbacks;

typedef struct {
  void (*SetChildNodes)(void* state, int32_t parent_id, DOMNodePtrRef* nodes, int nodes_count);
  void (*OnAttributeModified)(void* state, int32_t node_id, const char* name, const char* value);
  void (*OnAttributeRemoved)(void* state, int32_t node_id, const char* name);
  void (*OnCharacterDataModified)(void* state, int32_t node_id, const char* character_data);
  void (*OnChildNodeCountUpdated)(void* state, int32_t node_id, int32_t child_node_count);
  void (*OnChildNodeInserted)(void* state, int32_t parent_node_id, int32_t previous_node_id, DOMNodePtrRef node);
  void (*OnChildNodeRemoved)(void* state, int32_t parent_node_id, int32_t node_id);
  void (*OnDistributedNodesUpdated)(void* state, int32_t insertion_point_id, BackendNodePtrRef* distributed_nodes, int distributed_nodes_count);
  void (*OnDocumentUpdated)(void* state);
  void (*OnInlineStyleInvalidated)(void* state, int32_t* node_ids, int node_ids_count);
  void (*OnPseudoElementAdded)(void* state, int32_t parent_id, DOMNodePtrRef pseudo_element);
  void (*OnPseudoElementRemoved)(void* state, int32_t parent_id, int32_t pseudo_element_id);
  void (*OnShadowRootPopped)(void* state, int32_t host_id, int32_t root_id);
  void (*OnShadowRootPushed)(void* state, int32_t host_id, DOMNodePtrRef root);
} CDOMCallbacks;

typedef struct {
  void (*OnFontsUpdated)(void* state, FontFacePtrRef font);
  void (*OnMediaQueryResultChanged)(void* state);
  void (*OnStyleSheetAdded)(void* state, CSSStyleSheetHeaderPtrRef header);
  void (*OnStyleSheetChanged)(void* state, const char* style_sheet_id);
  void (*OnStyleSheetRemoved)(void* state, const char* style_sheet_id);
} CCSSCallbacks;

typedef struct {
  void (*OnApplicationCacheStatusUpdated)(void* state, const char* frame_id, const char* manifest_url, int32_t status);
  void (*OnNetworkStateUpdated)(void* state, int /* bool */ is_now_online);
} CApplicationCacheCallbacks;

typedef struct {
  void (*OnAnimationCanceled)(void* state, const char* id);
  void (*OnAnimationCreated)(void* state, const char* id);
  void (*OnAnimationStarted)(void* state, AnimationPtrRef animation);
} CAnimationCallbacks;

typedef void(*CGetInfoCallback)(void*, GPUInfoPtrRef, const char*, const char*, const char*);

typedef void(*CGetVersionCallback)(void*, const char*, const char*, const char*, const char*, const char*);
typedef void(*CGetHostCommandLineCallback)(void*, const char**, int);
typedef void(*CGetHistogramsCallback)(void*, HistogramPtrRef*, int);
typedef void(*CGetHistogramCallback)(void*, HistogramPtrRef);
typedef void(*CGetWindowBoundsCallback)(void*, BoundsPtrRef);
typedef void(*CGetWindowForTargetCallback)(void*, int32_t, BoundsPtrRef);

typedef void(*CAddScriptToEvaluateOnNewDocumentCallback)(void*, const char*);
typedef void(*CNavigateCallback)(void*, const char*, int32_t, const char*);
typedef void(*CGetNavigationHistoryCallback)(void*, int32_t, NavigationEntryPtrRef*, int /*count*/);
typedef void(*CGetCookiesCallback)(void*, CookiePtrRef*, int /*count*/);
typedef void(*CGetResourceTreeCallback)(void*, FrameResourceTreePtrRef);
typedef void(*CGetFrameTreeCallback)(void*, FrameTreePtrRef);
typedef void(*CGetResourceContentCallback)(void*, const char*, int /* bool */);
typedef void(*CSearchInResourceCallback)(void*, SearchMatchPtrRef*, int /*count*/);
typedef void(*CCaptureScreenshotCallback)(void*, const char*);
typedef void(*CPrintToPDFCallback)(void*, const char*);
typedef void(*CGetAppManifestCallback)(void*, const char*, const char**, int /*count*/, const char* /*optional*/);
typedef void(*CGetLayoutMetricsCallback)(void*, LayoutViewportPtrRef, VisualViewportPtrRef, int, int, int, int);
typedef void(*CCreateIsolatedWorldCallback)(void*, int32_t);

typedef void(*CCanClearBrowserCacheCallback)(void*, int /* bool */);
typedef void(*CCanClearBrowserCookiesCallback)(void*, int /* bool */);
typedef void(*CCanEmulateNetworkConditionsCallback)(void*, int /* bool */);
typedef void(*CGetAllCookiesCallback)(void*, CookiePtrRef*, int /* count */);
typedef void(*CGetCertificateCallback)(void*, const char**, int /* count */);
typedef void(*CGetCookiesCallback)(void*, CookiePtrRef*, int /* count */);
typedef void(*CGetResponseBodyCallback)(void*, const char*, int /* bool */);
typedef void(*CGetRequestPostDataCallback)(void*, const char*);
typedef void(*CGetResponseBodyForInterceptionCallback)(void*, const char*, int /* bool */);
typedef void(*CTakeResponseBodyForInterceptionAsStreamCallback)(void*, const char*);
typedef void(*CSearchInResponseBodyCallback)(void*, SearchMatchPtrRef*, int /* count */);
typedef void(*CSetCookieCallback)(void*, int /* bool */);

typedef void(*CCompositingReasonsCallback)(void*, const char**, int /* count */);
typedef void(*CLoadSnapshotCallback)(void*, const char*);
typedef void(*CMakeSnapshotCallback)(void*, const char*);
typedef void(*CProfileSnapshotCallback)(void*, double**, int /* count */, int /* count */);
typedef void(*CReplaySnapshotCallback)(void*, const char*);
typedef void(*CSnapshotCommandLogCallback)(void*, const char*);

typedef void(*CDispatchKeyEventCallback)(void*, int /* bool */);
typedef void(*CDispatchMouseEventCallback)(void*, int /* bool */);
typedef void(*CDispatchTouchEventCallback)(void*, int /* bool */);
typedef void(*CEmulateTouchFromMouseEventCallback)(void*, int /* bool */);
typedef void(*CSynthesizePinchGestureCallback)(void*, int /* bool */);
typedef void(*CSynthesizeScrollGestureCallback)(void*, int /* bool */);
typedef void(*CSynthesizeTapGestureCallback)(void*, int /* bool */);

typedef void(*CClearObjectStoreCallback)(void*, int /* bool */);
typedef void(*CDeleteDatabaseCallback)(void*, int /* bool */);
typedef void(*CDeleteObjectStoreEntriesCallback)(void*, int /* bool */);
typedef void(*CRequestDataCallback)(void*, IndexedDBDataEntryPtrRef*, int /* count */, int /* bool */);
typedef void(*CRequestDatabaseCallback)(void*, DatabaseWithObjectStoresPtrRef);
typedef void(*CRequestDatabaseNamesCallback)(void*, const char**, int /* count */);

typedef void(*CReadCallback)(void*, int /* bool */, const char*, int /* bool */);
typedef void(*CResolveBlobCallback)(void*, const char*);

typedef void(*CBeginFrameCallback)(void*, int /* bool */, const char* /*optional*/);
typedef void(*CGetDOMStorageItemsCallback)(void*, const char***, int/* count */, int/* count */);

typedef void(*CExecuteSQLCallback)(void*, const char**, int /* count */, OwnedValueRef*, int /* count */, ErrorPtrRef);
typedef void(*CGetDatabaseTableNamesCallback)(void*, const char**, int /* count */);

typedef void(*CCanEmulateCallback)(void*, int /* bool */);
typedef void(*CSetVirtualTimePolicyCallback)(void*, int64_t, int64_t);

typedef void(*CGetSnapshotCallback)(void*, DOMSnapshotNodePtrRef*, int /* count */, LayoutTreeNodePtrRef*, int /* count */, ComputedStylePtrRef*, int /* count */);
typedef void(*CCollectClassNamesFromSubtreeCallback)(void*, const char**, int /* count */);
typedef void(*CCopyToCallback)(void*, int32_t);
typedef void(*CDescribeNodeCallback)(void*, DOMNodePtrRef);
typedef void(*CGetAttributesCallback)(void*, const char**, int /* count */);
typedef void(*CGetBoxModelCallback)(void*, BoxModelPtrRef);
typedef void(*CGetDocumentCallback)(void*, DOMNodePtrRef);
typedef void(*CGetFlattenedDocumentCallback)(void*, DOMNodePtrRef*, int /* count */);
typedef void(*CGetNodeForLocationCallback)(void*, int32_t);
typedef void(*CGetOuterHTMLCallback)(void*, const char*);
typedef void(*CGetRelayoutBoundaryCallback)(void*, int32_t);
typedef void(*CGetSearchResultsCallback)(void*, const int32_t*, int/* count */);
typedef void(*CMoveToCallback)(void*, int32_t);
typedef void(*CPerformSearchCallback)(void*, const char*, int32_t);
typedef void(*CPushNodeByPathToFrontendCallback)(void*, int32_t);
typedef void(*CPushNodesByBackendIdsToFrontendCallback)(void*, const int32_t*, int /* count */);
typedef void(*CQuerySelectorCallback)(void*, int32_t);
typedef void(*CQuerySelectorAllCallback)(void*, const int32_t*, int /* count */);
typedef void(*CRequestNodeCallback)(void*, int32_t);
typedef void(*CResolveNodeCallback)(void*, RemoteObjectPtrRef);
typedef void(*CSetNodeNameCallback)(void*, int32_t);
typedef void(*CGetFrameOwnerCallback)(void*, int32_t);

typedef void(*CAddRuleCallback)(void*, CSSRulePtrRef);
typedef void(*CCollectClassNamesCallback)(void*, const char**, int);
typedef void(*CCreateStyleSheetCallback)(void*, const char*);
typedef void(*CGetBackgroundColorsCallback)(void*, const char** /* optional */, int /* count */, const char* /* optional */, const char* /* optional */, const char* /* optional */);
typedef void(*CGetComputedStyleForNodeCallback)(void*, CSSComputedStylePropertyPtrRef*, int);
typedef void(*CGetInlineStylesForNodeCallback)(void*, CSSStylePtrRef, CSSStylePtrRef);
typedef void(*CGetMatchedStylesForNodeCallback)(void*, CSSStylePtrRef, CSSStylePtrRef, RuleMatchPtrRef*, int, PseudoElementMatchesPtrRef*, int, InheritedStyleEntryPtrRef*, int, CSSKeyframesRulePtrRef*, int);
typedef void(*CGetMediaQueriesCallback)(void*, CSSMediaPtrRef*, int);
typedef void(*CGetPlatformFontsForNodeCallback)(void*, PlatformFontUsagePtrRef*, int);
typedef void(*CGetStyleSheetTextCallback)(void*, const char*);
typedef void(*CSetKeyframeKeyCallback)(void*, CSSValuePtrRef);
typedef void(*CSetMediaTextCallback)(void*, CSSMediaPtrRef);
typedef void(*CSetRuleSelectorCallback)(void*, SelectorListPtrRef);
typedef void(*CSetStyleSheetTextCallback)(void*, const char* /* optional */);
typedef void(*CSetStyleTextsCallback)(void*, CSSStylePtrRef*, int);
typedef void(*CStopRuleUsageTrackingCallback)(void*, CSSRuleUsagePtrRef*, int);
typedef void(*CTakeCoverageDeltaCallback)(void*, CSSRuleUsagePtrRef*, int);

typedef void(*CHasCacheCallback)(void*, int /* bool*/);
typedef void(*COpenCacheCallback)(void*, int);
typedef void(*CDeleteCacheCallback)(void*, int /* bool*/);
typedef void(*CDeleteEntryCallback)(void*, int /* bool*/);
typedef void(*CPutEntryCallback)(void*, int /* bool*/);
typedef void(*CRequestCacheNamesCallback)(void*, CachePtrRef*, int);
typedef void(*CRequestCachedResponseCallback)(void*, const char* data, int size);
typedef void(*CRequestEntriesCallback)(void*, DataEntryPtrRef*, int, int /* bool*/);
typedef void(*CGetApplicationCacheForFrameCallback)(void*, ApplicationCachePtrRef);
typedef void(*CGetFramesWithManifestsCallback)(void*, FrameWithManifestPtrRef*, int);
typedef void(*CGetManifestForFrameCallback)(void*, const char*);

typedef void(*CGetCurrentTimeCallback)(void*, int32_t);
typedef void(*CGetPlaybackRateCallback)(void*, int32_t);
typedef void(*CResolveAnimationCallback)(void*, AnimationPtrRef);
typedef void(*CGetPartialAXTreeCallback)(void*, AXNodePtrRef*, int);

EXPORT EngineInstanceRef _EngineCreate(
  void* state,
  CEngineCallbacks callbacks);
EXPORT void _EngineDestroy(EngineInstanceRef handle);
EXPORT EngineClientRef _EngineGetClient(EngineInstanceRef handle);
EXPORT void _EngineForeachApplication(EngineInstanceRef handle, void* state, void(*foreach)(void* state, void* app_state, const char* name, const char* uuid, const char* url));
EXPORT StorageRef _EngineStorageCreate(EngineInstanceRef handle, void* state, StorageShareCallbacks callbacks);
//EXPORT PlaceRegistryRef _EngineGetPlaceRegistry(EngineInstanceRef handle);

// ApplicationHost
EXPORT void _ApplicationHostDestroy(ApplicationHostRef handle);
EXPORT void _ApplicationHostBindCallbacks(ApplicationHostRef handle, void* state, CApplicationHostCallbacks callbacks);
EXPORT void _ApplicationHostInstanceLaunch(ApplicationHostRef handle, 
  int id, 
  const char* url, 
  int window_mode,
  int initial_bounds_x,
  int initial_bounds_y,
  int initial_bounds_w,
  int initial_bounds_h,
  int window_open_disposition,
  int fullscreen,
  int headless);
EXPORT void _ApplicationHostInstanceKill(ApplicationHostRef handle, int id);
EXPORT void _ApplicationHostInstanceClose(ApplicationHostRef handle, int id);
EXPORT void _ApplicationHostInstanceActivate(ApplicationHostRef handle, int id);
// Automation
EXPORT void _ApplicationHostSetPageCallbacks(ApplicationHostRef handle, CPageCallbacks cbs);
EXPORT void _ApplicationHostSetOverlayCallbacks(ApplicationHostRef handle, COverlayCallbacks cbs);
EXPORT void _ApplicationHostSetWorkerCallbacks(ApplicationHostRef handle, CWorkerCallbacks cbs);
EXPORT void _ApplicationHostSetStorageCallbacks(ApplicationHostRef handle, CStorageCallbacks cbs);
EXPORT void _ApplicationHostSetTetheringCallbacks(ApplicationHostRef handle, CTetheringCallbacks cbs);
EXPORT void _ApplicationHostSetNetworkCallbacks(ApplicationHostRef handle, CNetworkCallbacks cbs);
EXPORT void _ApplicationHostSetLayerTreeCallbacks(ApplicationHostRef handle, CLayerTreeCallbacks cbs);
EXPORT void _ApplicationHostSetHeadlessCallbacks(ApplicationHostRef handle, CHeadlessCallbacks cbs);
EXPORT void _ApplicationHostSetDOMStorageCallbacks(ApplicationHostRef handle, CDOMStorageCallbacks cbs);
EXPORT void _ApplicationHostSetDatabaseCallback(ApplicationHostRef handle, CDatabaseCallbacks cbs);
EXPORT void _ApplicationHostSetEmulationCallbacks(ApplicationHostRef handle, CEmulationCallbacks cbs);
EXPORT void _ApplicationHostSetDOMCallbacks(ApplicationHostRef handle, CDOMCallbacks cbs);
EXPORT void _ApplicationHostSetCSSCallbacks(ApplicationHostRef handle, CCSSCallbacks cbs);
EXPORT void _ApplicationHostSetApplicationCacheCallbacks(ApplicationHostRef handle, CApplicationCacheCallbacks cbs);
EXPORT void _ApplicationHostSetAnimationCallbacks(ApplicationHostRef handle, CAnimationCallbacks cbs);
EXPORT void _ApplicationHostSetDriverStateForInstance(ApplicationHostRef handle, int id, void* state);

// SystemInfo
EXPORT void _ApplicationHostSystemInfoGetInfo(ApplicationHostRef handle, int instance_id, CGetInfoCallback callback, void* state);
// Host
EXPORT void _ApplicationHostHostClose(ApplicationHostRef handle, int instance_id);
EXPORT void _ApplicationHostHostGetVersion(ApplicationHostRef handle, int instance_id, CGetVersionCallback callback, void* state);
EXPORT void _ApplicationHostHostGetHostCommandLine(ApplicationHostRef handle, int instance_id, CGetHostCommandLineCallback callback, void* state);
EXPORT void _ApplicationHostHostGetHistograms(ApplicationHostRef handle, int instance_id, const char* /* optional */ query, CGetHistogramsCallback callback, void* state);
EXPORT void _ApplicationHostHostGetHistogram(ApplicationHostRef handle, int instance_id, const char* name, CGetHistogramCallback callback, void* state);
EXPORT void _ApplicationHostHostGetWindowBounds(ApplicationHostRef handle, int instance_id, int32_t window_id, CGetWindowBoundsCallback callback, void* state);
EXPORT void _ApplicationHostHostGetWindowForTarget(ApplicationHostRef handle, int instance_id, const char* target_id, CGetWindowForTargetCallback callback, void* state);
EXPORT void _ApplicationHostHostSetWindowBounds(ApplicationHostRef handle, int instance_id, int32_t window_id, BoundsPtrRef bounds);
// Overlay
EXPORT void _ApplicationHostOverlayDisable(ApplicationHostRef handle, int instance_id);
EXPORT void _ApplicationHostOverlayEnable(ApplicationHostRef handle, int instance_id);
EXPORT void _ApplicationHostOverlayHideHighlight(ApplicationHostRef handle, int instance_id);
EXPORT void _ApplicationHostOverlayHighlightFrame(ApplicationHostRef handle, int instance_id, const char* frame_id, RGBAPtrRef content_color, RGBAPtrRef content_outline_color);
EXPORT void _ApplicationHostOverlayHighlightNode(ApplicationHostRef handle, int instance_id, HighlightConfigPtrRef highlight_config, int32_t node_id, int32_t backend_node_id, const char* /* optional */ object_id);
EXPORT void _ApplicationHostOverlayHighlightQuad(ApplicationHostRef handle, int instance_id, const double* quad, int quad_count, RGBAPtrRef color, RGBAPtrRef outline_color);
EXPORT void _ApplicationHostOverlayHighlightRect(
  ApplicationHostRef handle, 
  int instance_id, 
  int32_t x, 
  int32_t y, 
  int32_t width, 
  int32_t height, 
  int color_r,
  int color_g,
  int color_b,
  float color_a,
  int outline_r,
  int outline_g,
  int outline_b,
  float outline_a);
EXPORT void _ApplicationHostOverlaySetInspectMode(ApplicationHostRef handle, int instance_id, InspectModeEnum mode, HighlightConfigPtrRef highlight_config);
EXPORT void _ApplicationHostOverlaySetPausedInDebuggerMessage(ApplicationHostRef handle, int instance_id, const char* /* optional */ message);
EXPORT void _ApplicationHostOverlaySetShowDebugBorders(ApplicationHostRef handle, int instance_id, int /* bool */ show);
EXPORT void _ApplicationHostOverlaySetShowFPSCounter(ApplicationHostRef handle, int instance_id, int /* bool */ show);
EXPORT void _ApplicationHostOverlaySetShowPaintRects(ApplicationHostRef handle, int instance_id, int /* bool */ result);
EXPORT void _ApplicationHostOverlaySetShowScrollBottleneckRects(ApplicationHostRef handle, int instance_id, int /* bool */ show);
EXPORT void _ApplicationHostOverlaySetShowViewportSizeOnResize(ApplicationHostRef handle, int instance_id, int /* bool */ show);
EXPORT void _ApplicationHostOverlaySetSuspended(ApplicationHostRef handle, int instance_id, int /* bool */ suspended);
// Page
EXPORT void _ApplicationHostPageEnable(ApplicationHostRef handle, int instance_id);
EXPORT void _ApplicationHostPageDisable(ApplicationHostRef handle, int instance_id);
EXPORT void _ApplicationHostPageAddScriptToEvaluateOnNewDocument(ApplicationHostRef handle, int instance_id, const char* source, CAddScriptToEvaluateOnNewDocumentCallback callback, void* state);
EXPORT void _ApplicationHostPageRemoveScriptToEvaluateOnNewDocument(ApplicationHostRef handle, int instance_id, const char* identifier);
EXPORT void _ApplicationHostPageSetAutoAttachToCreatedPages(ApplicationHostRef handle, int instance_id, int /* bool */ auto_attach);
EXPORT void _ApplicationHostPageSetLifecycleEventsEnabled(ApplicationHostRef handle, int instance_id, int /* bool */ enabled);
EXPORT void _ApplicationHostPageReload(ApplicationHostRef handle, int instance_id, int /* bool */ ignore_cache, const char* script_to_evaluate_on_load);
EXPORT void _ApplicationHostPageSetAdBlockingEnabled(ApplicationHostRef handle, int instance_id, int /* bool */ enabled);
EXPORT void _ApplicationHostPageNavigate(ApplicationHostRef handle, int instance_id, const char* url, const char* referrer, TransitionTypeEnum transition_type, CNavigateCallback callback, void* state);
EXPORT void _ApplicationHostPageStopLoading(ApplicationHostRef handle, int instance_id);
EXPORT void _ApplicationHostPageGetNavigationHistory(ApplicationHostRef handle, int instance_id, CGetNavigationHistoryCallback callback, void* state);
EXPORT void _ApplicationHostPageNavigateToHistoryEntry(ApplicationHostRef handle, int instance_id, int32_t entry_id);
EXPORT void _ApplicationHostPageGetCookies(ApplicationHostRef handle, int instance_id, CGetCookiesCallback callback, void* state);
EXPORT void _ApplicationHostPageDeleteCookie(ApplicationHostRef handle, int instance_id, const char* cookie_name, const char* url);
EXPORT void _ApplicationHostPageGetResourceTree(ApplicationHostRef handle, int instance_id, CGetResourceTreeCallback callback, void* state);
EXPORT void _ApplicationHostPageGetFrameTree(ApplicationHostRef handle, int instance_id, CGetFrameTreeCallback callback, void* state);
EXPORT void _ApplicationHostPageGetResourceContent(ApplicationHostRef handle, int instance_id, const char* frame_id, const char* url, CGetResourceContentCallback callback, void* state);
EXPORT void _ApplicationHostPageSearchInResource(ApplicationHostRef handle, int instance_id, const char* frame_id, const char* url, const char* query, int /* bool */ case_sensitive, int /* bool */ is_regex, CSearchInResourceCallback callback, void* state);
EXPORT void _ApplicationHostPageSetDocumentContent(ApplicationHostRef handle, int instance_id, const char* frame_id, const char* html);
EXPORT void _ApplicationHostPageSetDeviceMetricsOverride(ApplicationHostRef handle, int instance_id, int32_t width, int32_t height, int32_t device_scale_factor, int /* bool */ mobile, int32_t scale, int32_t screen_width, int32_t screen_height, int32_t position_x, int32_t position_y, int /* bool */ dont_set_visible_size, ScreenOrientationPtrRef screen_orientation, ViewportPtrRef viewport);
EXPORT void _ApplicationHostPageClearDeviceMetricsOverride(ApplicationHostRef handle, int instance_id);
EXPORT void _ApplicationHostPageSetGeolocationOverride(ApplicationHostRef handle, int instance_id, int32_t latitude, int32_t longitude, int32_t accuracy);
EXPORT void _ApplicationHostPageClearGeolocationOverride(ApplicationHostRef handle, int instance_id);
EXPORT void _ApplicationHostPageSetDeviceOrientationOverride(ApplicationHostRef handle, int instance_id, int32_t alpha, int32_t beta, int32_t gamma);
EXPORT void _ApplicationHostPageClearDeviceOrientationOverride(ApplicationHostRef handle, int instance_id);
EXPORT void _ApplicationHostPageSetTouchEmulationEnabled(ApplicationHostRef handle, int instance_id, int /* bool */ enabled, const char* configuration);
EXPORT void _ApplicationHostPageCaptureScreenshot(ApplicationHostRef handle, int instance_id, FrameFormatEnum format, int32_t quality, ViewportPtrRef clip, int /* bool */ from_surface, CCaptureScreenshotCallback callback, void* state);
EXPORT void _ApplicationHostPagePrintToPDF(ApplicationHostRef handle, int instance_id, int /* bool */ landscape, int /* bool */ display_header_footer, int /* bool */ print_background, float scale, float paper_width, float paper_height, float margin_top, float margin_bottom, float margin_left, float margin_right, const char* /* optional */ page_ranges, int /* bool */ ignore_invalid_page_ranges, CPrintToPDFCallback callback, void* state);
EXPORT void _ApplicationHostPageStartScreencast(ApplicationHostRef handle, int instance_id, FrameFormatEnum format, int32_t quality, int32_t max_width, int32_t max_height, int32_t every_nth_frame);
EXPORT void _ApplicationHostPageStopScreencast(ApplicationHostRef handle, int instance_id);
EXPORT void _ApplicationHostPageSetBypassCSP(ApplicationHostRef handle, int instance_id, int /* bool */ enable);
EXPORT void _ApplicationHostPageScreencastFrameAck(ApplicationHostRef handle, int instance_id, int32_t session_id);
EXPORT void _ApplicationHostPageHandleJavaScriptDialog(ApplicationHostRef handle, int instance_id, int /* bool */ accept, const char* prompt_text);
EXPORT void _ApplicationHostPageGetAppManifest(ApplicationHostRef handle, int instance_id, CGetAppManifestCallback callback, void* state);
EXPORT void _ApplicationHostPageRequestAppBanner(ApplicationHostRef handle, int instance_id);
EXPORT void _ApplicationHostPageGetLayoutMetrics(ApplicationHostRef handle, int instance_id, CGetLayoutMetricsCallback callback, void* state);
EXPORT void _ApplicationHostPageCreateIsolatedWorld(ApplicationHostRef handle, int instance_id, const char* frame_id, const char* /* optional */ world_name, int /* bool */ grant_universal_access, CCreateIsolatedWorldCallback callback, void* state);
EXPORT void _ApplicationHostPageBringToFront(ApplicationHostRef handle, int instance_id);
EXPORT void _ApplicationHostPageSetDownloadBehavior(ApplicationHostRef handle, int instance_id, const char* behavior, const char* /* optional */ download_path);
EXPORT void _ApplicationHostPageClose(ApplicationHostRef handle, int instance_id);
// Worker
EXPORT void _ApplicationHostWorkerDeliverPushMessage(ApplicationHostRef handle, int instance_id, const char* origin, const char* registration_id, const char* data);
EXPORT void _ApplicationHostWorkerDisable(ApplicationHostRef handle, int instance_id);
EXPORT void _ApplicationHostWorkerDispatchSyncEvent(ApplicationHostRef handle, int instance_id, const char* origin, const char* registration_id, const char* tag, int /* bool */ last_chance);
EXPORT void _ApplicationHostWorkerEnable(ApplicationHostRef handle, int instance_id);
EXPORT void _ApplicationHostWorkerInspectWorker(ApplicationHostRef handle, int instance_id, const char* version_id);
EXPORT void _ApplicationHostWorkerSetForceUpdateOnPageLoad(ApplicationHostRef handle, int instance_id, int /* bool */ force_update_on_pageload);
EXPORT void _ApplicationHostWorkerSkipWaiting(ApplicationHostRef handle, int instance_id, const char* scope_url);
EXPORT void _ApplicationHostWorkerStartWorker(ApplicationHostRef handle, int instance_id, const char* scope_url);
EXPORT void _ApplicationHostWorkerStopAllWorkers(ApplicationHostRef handle, int instance_id);
EXPORT void _ApplicationHostWorkerStopWorker(ApplicationHostRef handle, int instance_id, const char* version_id);
EXPORT void _ApplicationHostWorkerUnregister(ApplicationHostRef handle, int instance_id, const char* scope_url);
EXPORT void _ApplicationHostWorkerUpdateRegistration(ApplicationHostRef handle, int instance_id, const char* scope_url);
EXPORT void _ApplicationHostWorkerSendMessageToTarget(ApplicationHostRef handle, int instance_id, const char* message, const char* /* optional */ session_id, const char* /* optional */ target_id);
// Storage
EXPORT void _ApplicationHostStorageClearDataForOrigin(ApplicationHostRef handle, int instance_id, const char* origin, StorageTypeEnum* storage_types, int storage_types_count);
EXPORT void _ApplicationHostStorageGetUsageAndQuota(ApplicationHostRef handle, int instance_id, const char* origin, int64_t usage, int64_t quota, UsageForTypePtrRef* usage_breakdown, int usage_breakdown_count);
EXPORT void _ApplicationHostStorageTrackCacheStorageForOrigin(ApplicationHostRef handle, int instance_id, const char* origin);
EXPORT void _ApplicationHostStorageTrackIndexedDBForOrigin(ApplicationHostRef handle, int instance_id, const char* origin);
EXPORT void _ApplicationHostStorageUntrackCacheStorageForOrigin(ApplicationHostRef handle, int instance_id, const char* origin);
EXPORT void _ApplicationHostStorageUntrackIndexedDBForOrigin(ApplicationHostRef handle, int instance_id, const char* origin);
// Tethering
EXPORT void _ApplicationHostTetheringBind(ApplicationHostRef handle, int instance_id, int32_t port);
EXPORT void _ApplicationHostTetheringUnbind(ApplicationHostRef handle, int instance_id, int32_t port);
// Network
EXPORT void _ApplicationHostNetworkCanClearBrowserCache(ApplicationHostRef handle, int instance_id, CCanClearBrowserCacheCallback callback, void* state);
EXPORT void _ApplicationHostNetworkCanClearBrowserCookies(ApplicationHostRef handle, int instance_id, CCanClearBrowserCookiesCallback callback, void* state);
EXPORT void _ApplicationHostNetworkCanEmulateNetworkConditions(ApplicationHostRef handle, int instance_id, CCanEmulateNetworkConditionsCallback callback, void* state);
EXPORT void _ApplicationHostNetworkClearBrowserCache(ApplicationHostRef handle, int instance_id);
EXPORT void _ApplicationHostNetworkClearBrowserCookies(ApplicationHostRef handle, int instance_id);
EXPORT void _ApplicationHostNetworkContinueInterceptedRequest(ApplicationHostRef handle, int instance_id, const char* interception_id, ErrorReasonEnum error_reason, const char* /* optional */ raw_response, const char* /* optional */ url, const char* /* optional */ method, const char* /* optional */ post_data, /* optional */ const char** header_keys, int header_keys_count, /* optional */ const char** header_values, int header_values_count, AuthChallengeResponsePtrRef auth_challenge_response);
EXPORT void _ApplicationHostNetworkDeleteCookies(ApplicationHostRef handle, int instance_id, const char* name, const char* /* optional */ url, const char* /* optional */ domain, const char* /* optional */ path);
EXPORT void _ApplicationHostNetworkDisable(ApplicationHostRef handle, int instance_id);
EXPORT void _ApplicationHostNetworkEmulateNetworkConditions(ApplicationHostRef handle, int instance_id, int /* bool */ offline, int64_t latency, int64_t download_throughput, int64_t upload_throughput, ConnectionTypeEnum connection_type);
EXPORT void _ApplicationHostNetworkEnable(ApplicationHostRef handle, int instance_id, int32_t max_total_buffer_size, int32_t max_resource_buffer_size, int32_t max_post_data_size);
EXPORT void _ApplicationHostNetworkGetAllCookies(ApplicationHostRef handle, int instance_id, CGetAllCookiesCallback callback, void* state);
EXPORT void _ApplicationHostNetworkGetCertificate(ApplicationHostRef handle, int instance_id, const char* origin, CGetCertificateCallback callback, void* state);
EXPORT void _ApplicationHostNetworkGetCookies(ApplicationHostRef handle, int instance_id, /* optional */ const char** urls, int urls_count, CGetCookiesCallback callback, void* state);
EXPORT void _ApplicationHostNetworkGetResponseBody(ApplicationHostRef handle, int instance_id, const char* request_id, CGetResponseBodyCallback callback, void* state);
EXPORT void _ApplicationHostNetworkGetRequestPostData(ApplicationHostRef handle, int instance_id, const char* request_id, CGetRequestPostDataCallback callback, void* state);
EXPORT void _ApplicationHostNetworkGetResponseBodyForInterception(ApplicationHostRef handle, int instance_id, const char* interception_id, CGetResponseBodyForInterceptionCallback callback, void* state);
EXPORT void _ApplicationHostNetworkTakeResponseBodyForInterceptionAsStream(ApplicationHostRef handle, int instance_id, const char* interception_id, CTakeResponseBodyForInterceptionAsStreamCallback callback, void* state);
EXPORT void _ApplicationHostNetworkReplayXHR(ApplicationHostRef handle, int instance_id, const char* request_id);
EXPORT void _ApplicationHostNetworkSearchInResponseBody(ApplicationHostRef handle, int instance_id, const char* request_id, const char* query, int /* bool */ case_sensitive, int /* bool */ is_regex, CSearchInResponseBodyCallback callback, void* state);
EXPORT void _ApplicationHostNetworkSetBlockedURLs(ApplicationHostRef handle, int instance_id, const char** urls, int urls_count);
EXPORT void _ApplicationHostNetworkSetBypassServiceWorker(ApplicationHostRef handle, int instance_id, int /* bool */ bypass);
EXPORT void _ApplicationHostNetworkSetCacheDisabled(ApplicationHostRef handle, int instance_id, int /* bool */ cache_disabled);
EXPORT void _ApplicationHostNetworkSetCookie(ApplicationHostRef handle, int instance_id, const char* name, const char* value, const char* /* optional */ url, const char* /* optional */ domain, const char* /* optional */ path, int /* bool */ secure, int /* bool */ http_only, CookieSameSiteEnum same_site, int64_t expires, CSetCookieCallback callback, void* state);
EXPORT void _ApplicationHostNetworkSetCookies(ApplicationHostRef handle, int instance_id, CookieParamPtrRef* cookies, int cookies_count);
EXPORT void _ApplicationHostNetworkSetDataSizeLimits(ApplicationHostRef handle, int instance_id, int32_t max_total_size, int32_t max_resource_size);
EXPORT void _ApplicationHostNetworkSetExtraHTTPHeaders(ApplicationHostRef handle, int instance_id, const char** headers_keys, int header_keys_count, const char** headers_values, int header_values_count);
EXPORT void _ApplicationHostNetworkSetRequestInterception(ApplicationHostRef handle, int instance_id, RequestPatternPtrRef* patterns, int patterns_count);
EXPORT void _ApplicationHostNetworkSetUserAgentOverride(ApplicationHostRef handle, int instance_id, const char* user_agent);
// LayerTree
EXPORT void _ApplicationHostLayerTreeCompositingReasons(ApplicationHostRef handle, int instance_id, const char* layer_id, CCompositingReasonsCallback callback, void* state);
EXPORT void _ApplicationHostLayerTreeDisable(ApplicationHostRef handle, int instance_id);
EXPORT void _ApplicationHostLayerTreeEnable(ApplicationHostRef handle, int instance_id);
EXPORT void _ApplicationHostLayerTreeLoadSnapshot(ApplicationHostRef handle, int instance_id, PictureTilePtrRef* tiles, int tyles_count, CLoadSnapshotCallback callback, void* state);
EXPORT void _ApplicationHostLayerTreeMakeSnapshot(ApplicationHostRef handle, int instance_id, const char* layer_id, CMakeSnapshotCallback callback, void* state);
EXPORT void _ApplicationHostLayerTreeProfileSnapshot(ApplicationHostRef handle, int instance_id, const char* snapshot_id, int32_t min_repeat_count, int32_t min_duration, int clip_rect_x, int clip_rect_y, int clip_rect_w, int clip_rect_h, CProfileSnapshotCallback callback, void* state);
EXPORT void _ApplicationHostLayerTreeReleaseSnapshot(ApplicationHostRef handle, int instance_id, const char* snapshot_id);
EXPORT void _ApplicationHostLayerTreeReplaySnapshot(ApplicationHostRef handle, int instance_id, const char* snapshot_id, int32_t from_step, int32_t to_step, int32_t scale, CReplaySnapshotCallback callback, void* state);
EXPORT void _ApplicationHostLayerTreeSnapshotCommandLog(ApplicationHostRef handle, int instance_id, const char* snapshot_id, CSnapshotCommandLogCallback callback, void* state);
// Input
EXPORT void _ApplicationHostInputDispatchKeyEvent(ApplicationHostRef handle, int instance_id, KeyEventTypeEnum type, int32_t modifiers, int64_t timestamp, const char* /* optional */ text, const char* /* optional */ unmodified_text, const char* /* optional */ key_identifier, const char* /* optional */ code, const char* /* optional */ key, int32_t windows_virtual_key_code, int32_t native_virtual_key_code, int /* bool */ auto_repeat, int /* bool */ is_keypad, int /* bool */ is_system_key, int32_t location, CDispatchKeyEventCallback callback, void* state);
EXPORT void _ApplicationHostInputDispatchMouseEvent(ApplicationHostRef handle, int instance_id, MouseEventTypeEnum type, int32_t x, int32_t y, int32_t modifiers, int64_t timestamp, MouseButtonEnum button, int32_t click_count, int32_t delta_x, int32_t delta_y, CDispatchMouseEventCallback callback, void* state);
EXPORT void _ApplicationHostInputDispatchTouchEvent(ApplicationHostRef handle, int instance_id, TouchEventTypeEnum type, TouchPointPtrRef* touch_points, int touch_points_count, int32_t modifiers, int64_t timestamp, CDispatchTouchEventCallback callback, void* state);
EXPORT void _ApplicationHostInputEmulateTouchFromMouseEvent(ApplicationHostRef handle, int instance_id, MouseEventTypeEnum type, int32_t x, int32_t y, MouseButtonEnum button, int64_t timestamp, int32_t delta_x, int32_t delta_y, int32_t modifiers, int32_t click_count, CEmulateTouchFromMouseEventCallback callback, void* state);
EXPORT void _ApplicationHostInputSetIgnoreInputEvents(ApplicationHostRef handle, int instance_id, int /* bool */ ignore);
EXPORT void _ApplicationHostInputSynthesizePinchGesture(ApplicationHostRef handle, int instance_id, int32_t x, int32_t y, int32_t scale_factor, int32_t relative_speed, GestureSourceTypeEnum gesture_source_type, CSynthesizePinchGestureCallback callback, void* state);
EXPORT void _ApplicationHostInputSynthesizeScrollGesture(ApplicationHostRef handle, int instance_id, int32_t x, int32_t y, int32_t x_distance, int32_t y_distance, int32_t x_overscroll, int32_t y_overscroll, int /* bool */ prevent_fling, int32_t speed, GestureSourceTypeEnum gesture_source_type, int32_t repeat_count, int32_t repeat_delay_ms, const char* /* optional */ interaction_marker_name, CSynthesizeScrollGestureCallback callback, void* state);
EXPORT void _ApplicationHostInputSynthesizeTapGesture(ApplicationHostRef handle, int instance_id, int32_t x, int32_t y, int32_t duration, int32_t tap_count, GestureSourceTypeEnum gesture_source_type, CSynthesizeTapGestureCallback callback, void* state);
// IndexedDB
EXPORT void _ApplicationHostIndexedDBDisable(ApplicationHostRef handle, int instance_id);
EXPORT void _ApplicationHostIndexedDBEnable(ApplicationHostRef handle, int instance_id);
EXPORT void _ApplicationHostIndexedDBClearObjectStore(ApplicationHostRef handle, int instance_id, const char* security_origin, const char* database_name, const char* object_store_name, CClearObjectStoreCallback callback, void* state);
EXPORT void _ApplicationHostIndexedDBDeleteDatabase(ApplicationHostRef handle, int instance_id, const char* security_origin, const char* database_name, CDeleteDatabaseCallback callback, void* state);
EXPORT void _ApplicationHostIndexedDBDeleteObjectStoreEntries(ApplicationHostRef handle, int instance_id, const char* security_origin, const char* database_name, const char* object_store_name, KeyRangePtrRef keyRange, CDeleteObjectStoreEntriesCallback callback, void* state);
EXPORT void _ApplicationHostIndexedDBRequestData(ApplicationHostRef handle, int instance_id, const char* security_origin, const char* database_name, const char* object_store_name, const char* index_name, int32_t skip_count, int32_t page_size, KeyRangePtrRef key_range, CRequestDataCallback callback, void* state);
EXPORT void _ApplicationHostIndexedDBRequestDatabase(ApplicationHostRef handl, int instance_ide, const char* security_origin, const char* database_name, CRequestDatabaseCallback callback, void* state);
EXPORT void _ApplicationHostIndexedDBRequestDatabaseNames(ApplicationHostRef handle, int instance_id, const char* security_origin, CRequestDatabaseNamesCallback callback, void* state);
// IO
EXPORT void _ApplicationHostIOClose(ApplicationHostRef handle, int instance_id, const char* handl);
EXPORT void _ApplicationHostIORead(ApplicationHostRef handle, int instance_id, const char* handl, int32_t offset, int32_t size, CReadCallback callback, void* state);
EXPORT void _ApplicationHostIOResolveBlob(ApplicationHostRef handle, int instance_id, const char* object_id, CResolveBlobCallback callback, void* state);
// Headless
EXPORT void _ApplicationHostHeadlessBeginFrame(ApplicationHostRef handle, int instance_id, int64_t frame_time, int32_t frame_time_ticks, int64_t deadline, int32_t deadline_ticks, int32_t interval, int /* bool */ no_display_updates, ScreenshotParamsPtrRef screenshot, CBeginFrameCallback callback, void* state);
EXPORT void _ApplicationHostHeadlessEnterDeterministicMode(ApplicationHostRef handle, int instance_id, int32_t initial_date);
EXPORT void _ApplicationHostHeadlessDisable(ApplicationHostRef handle, int instance_id);
EXPORT void _ApplicationHostHeadlessEnable(ApplicationHostRef handle, int instance_id);
// DOMStorage
EXPORT void _ApplicationHostDOMStorageClear(ApplicationHostRef handle, int instance_id, StorageIdPtrRef storage_id);
EXPORT void _ApplicationHostDOMStorageDisable(ApplicationHostRef handle, int instance_id);
EXPORT void _ApplicationHostDOMStorageEnable(ApplicationHostRef handle, int instance_id);
EXPORT void _ApplicationHostDOMStorageGetDOMStorageItems(ApplicationHostRef handle, int instance_id, StorageIdPtrRef storageId, CGetDOMStorageItemsCallback callback, void* state);
EXPORT void _ApplicationHostDOMStorageRemoveDOMStorageItem(ApplicationHostRef handle, int instance_id, StorageIdPtrRef storage_id, const char* key);
EXPORT void _ApplicationHostDOMStorageSetDOMStorageItem(ApplicationHostRef handle, int instance_id, StorageIdPtrRef storageId, const char* key, const char* value);
// Database
EXPORT void _ApplicationHostDatabaseDisable(ApplicationHostRef handle, int instance_id);
EXPORT void _ApplicationHostDatabaseEnable(ApplicationHostRef handle, int instance_id);
EXPORT void _ApplicationHostDatabaseExecuteSQL(ApplicationHostRef handle, int instance_id, const char* database_id, const char* query, CExecuteSQLCallback callback, void* state);
EXPORT void _ApplicationHostDatabaseGetDatabaseTableNames(ApplicationHostRef handle, int instance_id, const char* database_id, CGetDatabaseTableNamesCallback callback, void* state);
// DeviceOrientation
EXPORT void _ApplicationHostDeviceOrientationClearDeviceOrientationOverride(ApplicationHostRef handle, int instance_id);
EXPORT void _ApplicationHostDeviceOrientationSetDeviceOrientationOverride(ApplicationHostRef handle, int instance_id, int32_t alpha, int32_t beta, int32_t gamma);
// Emulation
EXPORT void _ApplicationHostEmulationCanEmulate(ApplicationHostRef handle, int instance_id, CCanEmulateCallback callback, void* state);
EXPORT void _ApplicationHostEmulationClearDeviceMetricsOverride(ApplicationHostRef handle, int instance_id);
EXPORT void _ApplicationHostEmulationClearGeolocationOverride(ApplicationHostRef handle, int instance_id);
EXPORT void _ApplicationHostEmulationResetPageScaleFactor(ApplicationHostRef handle, int instance_id);
EXPORT void _ApplicationHostEmulationSetCPUThrottlingRate(ApplicationHostRef handle, int instance_id, int32_t rate);
EXPORT void _ApplicationHostEmulationSetDefaultBackgroundColorOverride(ApplicationHostRef handle, int instance_id, RGBAPtrRef color);
EXPORT void _ApplicationHostEmulationSetDeviceMetricsOverride(ApplicationHostRef handle, int instance_id, int32_t width, int32_t height, float device_scale_factor, int /* bool */ mobile, float scale, int32_t screen_width, int32_t screen_height, int32_t position_x, int32_t position_y, int /* bool */ dont_set_visible_size, ScreenOrientationPtrRef screen_orientation, ViewportPtrRef viewport);
EXPORT void _ApplicationHostEmulationSetEmitTouchEventsForMouse(ApplicationHostRef handle, int instance_id, int /* bool */ enabled, TouchEventForMouseConfigurationEnum configuration);
EXPORT void _ApplicationHostEmulationSetEmulatedMedia(ApplicationHostRef handle, int instance_id, const char* media);
EXPORT void _ApplicationHostEmulationSetGeolocationOverride(ApplicationHostRef handle, int instance_id, int64_t latitude, int64_t longitude, int64_t accuracy);
EXPORT void _ApplicationHostEmulationSetNavigatorOverrides(ApplicationHostRef handle, int instance_id, const char* platform);
EXPORT void _ApplicationHostEmulationSetPageScaleFactor(ApplicationHostRef handle, int instance_id, float page_scale_factor);
EXPORT void _ApplicationHostEmulationSetScriptExecutionDisabled(ApplicationHostRef handle, int instance_id, int /* bool */ value);
EXPORT void _ApplicationHostEmulationSetTouchEmulationEnabled(ApplicationHostRef handle, int instance_id, int /* bool */ enabled, int32_t max_touch_points);
EXPORT void _ApplicationHostEmulationSetVirtualTimePolicy(ApplicationHostRef handle, int instance_id, VirtualTimePolicyEnum policy, int32_t budget, int32_t max_virtual_time_task_starvation_count, int /* bool */ wait_for_navigation, CSetVirtualTimePolicyCallback callback, void* state);
EXPORT void _ApplicationHostEmulationSetVisibleSize(ApplicationHostRef handle, int instance_id, int32_t width, int32_t height);
// DOMSnapshot
EXPORT void _ApplicationHostDOMSnapshotGetSnapshot(
    ApplicationHostRef handle,
    int instance_id,
    const char** computed_style_whitelist,
    int computed_style_whitelist_count, 
    int /* bool */ include_event_listeners, 
    int /* bool */ include_paint_order, 
    int /* bool */ include_user_agent_shadow_tree, 
    CGetSnapshotCallback callback, void* state);
// DOM
EXPORT void _ApplicationHostDOMCollectClassNamesFromSubtree(ApplicationHostRef handle, int instance_id, int32_t node_id, CCollectClassNamesFromSubtreeCallback callback, void* state);
EXPORT void _ApplicationHostDOMCopyTo(ApplicationHostRef handle, int instance_id, int32_t node_id, int32_t target_node_id, int32_t anchor_node_id, CCopyToCallback callback, void* state);
EXPORT void _ApplicationHostDOMDescribeNode(ApplicationHostRef handle, int instance_id, int32_t node_id, int32_t backend_node_id, const char* /* optional */ object_id, int32_t depth, int /* bool */ pierce, CDescribeNodeCallback callback, void* state);
EXPORT void _ApplicationHostDOMDisable(ApplicationHostRef handle, int instance_id);
EXPORT void _ApplicationHostDOMDiscardSearchResults(ApplicationHostRef handle, int instance_id, const char* search_id);
EXPORT void _ApplicationHostDOMEnable(ApplicationHostRef handle, int instance_id);
EXPORT void _ApplicationHostDOMFocus(ApplicationHostRef handle, int instance_id, int32_t node_id, int32_t backend_node_id, const char* /* optional */ object_id);
EXPORT void _ApplicationHostDOMGetAttributes(ApplicationHostRef handle, int instance_id, int32_t node_id, CGetAttributesCallback callback, void* state);
EXPORT void _ApplicationHostDOMGetBoxModel(ApplicationHostRef handle, int instance_id, int32_t node_id, int32_t backend_node_id, const char* /* optional */ object_id, CGetBoxModelCallback callback, void* state);
EXPORT void _ApplicationHostDOMGetDocument(ApplicationHostRef handle, int instance_id, int32_t depth, int /* bool */ pierce, CGetDocumentCallback callback, void* state);
EXPORT void _ApplicationHostDOMGetFlattenedDocument(ApplicationHostRef handle, int instance_id, int32_t depth, int /* bool */ pierce, CGetFlattenedDocumentCallback callback, void* state);
EXPORT void _ApplicationHostDOMGetNodeForLocation(ApplicationHostRef handle, int instance_id, int32_t x, int32_t y, int /* bool */ include_user_agent_shadow_dom, CGetNodeForLocationCallback callback, void* state);
EXPORT void _ApplicationHostDOMGetOuterHTML(ApplicationHostRef handle, int instance_id, int32_t node_id, int32_t backend_node_id, const char* /* optional */ object_id, CGetOuterHTMLCallback callback, void* state);
EXPORT void _ApplicationHostDOMGetRelayoutBoundary(ApplicationHostRef handle, int instance_id, int32_t node_id, CGetRelayoutBoundaryCallback callback, void* state);
EXPORT void _ApplicationHostDOMGetSearchResults(ApplicationHostRef handle, int instance_id, const char* search_id, int32_t from_index, int32_t to_index, CGetSearchResultsCallback callback, void* state);
EXPORT void _ApplicationHostDOMHideHighlight(ApplicationHostRef handle, int instance_id);
EXPORT void _ApplicationHostDOMHighlightNode(ApplicationHostRef handle, int instance_id, HighlightConfigPtrRef highlight_config, int32_t node_id, int32_t backend_node_id, int32_t object_id);
EXPORT void _ApplicationHostDOMHighlightRect(ApplicationHostRef handle, int instance_id, int32_t x, int32_t y, int32_t width, int32_t height, RGBAPtrRef color, RGBAPtrRef outline_color);
EXPORT void _ApplicationHostDOMMarkUndoableState(ApplicationHostRef handle, int instance_id);
EXPORT void _ApplicationHostDOMMoveTo(ApplicationHostRef handle, int instance_id, int32_t node_id, int32_t target_node_id, int32_t insert_before_node_id, CMoveToCallback callback, void* state);
EXPORT void _ApplicationHostDOMPerformSearch(ApplicationHostRef handle, int instance_id, const char* query, int /* bool */ include_user_agent_shadow_dom, CPerformSearchCallback callback, void* state);
EXPORT void _ApplicationHostDOMPushNodeByPathToFrontend(ApplicationHostRef handle, int instance_id, const char* path, CPushNodeByPathToFrontendCallback callback, void* state);
EXPORT void _ApplicationHostDOMPushNodesByBackendIdsToFrontend(ApplicationHostRef handle, int instance_id, int32_t* backend_node_ids, int backend_node_ids_count, CPushNodesByBackendIdsToFrontendCallback callback, void* state);
EXPORT void _ApplicationHostDOMQuerySelector(ApplicationHostRef handle, int instance_id, int32_t node_id, const char* selector, CQuerySelectorCallback callback, void* state);
EXPORT void _ApplicationHostDOMQuerySelectorAll(ApplicationHostRef handle, int instance_id, int32_t node_id, const char* selector, CQuerySelectorAllCallback callback, void* state);
EXPORT void _ApplicationHostDOMRedo(ApplicationHostRef handle, int instance_id);
EXPORT void _ApplicationHostDOMRemoveAttribute(ApplicationHostRef handle, int instance_id, int32_t node_id, const char* name);
EXPORT void _ApplicationHostDOMRemoveNode(ApplicationHostRef handle, int instance_id, int32_t node_id);
EXPORT void _ApplicationHostDOMRequestChildNodes(ApplicationHostRef handle, int instance_id, int32_t node_id, int32_t depth, int /* bool */ pierce);
EXPORT void _ApplicationHostDOMRequestNode(ApplicationHostRef handle, int instance_id, const char* object_id, CRequestNodeCallback callback, void* state);
EXPORT void _ApplicationHostDOMResolveNode(ApplicationHostRef handle, int instance_id, int32_t node_id, const char* /* optional */ object_group, CResolveNodeCallback callback, void* state);
EXPORT void _ApplicationHostDOMSetAttributeValue(ApplicationHostRef handle, int instance_id, int32_t node_id, const char* name, const char* value);
EXPORT void _ApplicationHostDOMSetAttributesAsText(ApplicationHostRef handle, int instance_id, int32_t node_id, const char* text, const char* /* optional */ name);
EXPORT void _ApplicationHostDOMSetFileInputFiles(ApplicationHostRef handle, int instance_id, const char** files, int files_count, int32_t node_id, int32_t backend_node_id, const char* /* optional */ object_id);
EXPORT void _ApplicationHostDOMSetInspectedNode(ApplicationHostRef handle, int instance_id, int32_t node_id);
EXPORT void _ApplicationHostDOMSetNodeName(ApplicationHostRef handle, int instance_id, int32_t node_id, const char* name, CSetNodeNameCallback callback, void* state);
EXPORT void _ApplicationHostDOMSetNodeValue(ApplicationHostRef handle, int instance_id, int32_t node_id, const char* value);
EXPORT void _ApplicationHostDOMSetOuterHTML(ApplicationHostRef handle, int instance_id, int32_t node_id, const char* outer_html);
EXPORT void _ApplicationHostDOMUndo(ApplicationHostRef handle, int instance_id);
EXPORT void _ApplicationHostDOMGetFrameOwner(ApplicationHostRef handle, int instance_id, const char* frame_id, CGetFrameOwnerCallback callback, void* state);
// CSS
EXPORT void _ApplicationHostCSSAddRule(ApplicationHostRef handle, int instance_id, const char* style_sheet_id, const char* rule_text, SourceRangePtrRef location, CAddRuleCallback callback, void* state);
EXPORT void _ApplicationHostCSSCollectClassNames(ApplicationHostRef handle, int instance_id, const char* style_sheet_id, CCollectClassNamesCallback callback, void* state);
EXPORT void _ApplicationHostCSSCreateStyleSheet(ApplicationHostRef handle, int instance_id, const char* frame_id, CCreateStyleSheetCallback callback, void* state);
EXPORT void _ApplicationHostCSSDisable(ApplicationHostRef handle, int instance_id);
EXPORT void _ApplicationHostCSSEnable(ApplicationHostRef handle, int instance_id);
EXPORT void _ApplicationHostCSSForcePseudoState(ApplicationHostRef handle, int instance_id, int32_t node_id, const char** forced_pseudo_classes, int forced_pseudo_classes_count);
EXPORT void _ApplicationHostCSSGetBackgroundColors(ApplicationHostRef handle, int instance_id, int32_t node_id, CGetBackgroundColorsCallback callback, void* state);
EXPORT void _ApplicationHostCSSGetComputedStyleForNode(ApplicationHostRef handle, int instance_id, int32_t node_id, CGetComputedStyleForNodeCallback callback, void* state);
EXPORT void _ApplicationHostCSSGetInlineStylesForNode(ApplicationHostRef handle, int instance_id, int32_t node_id, CGetInlineStylesForNodeCallback callback, void* state);
EXPORT void _ApplicationHostCSSGetMatchedStylesForNode(ApplicationHostRef handle, int instance_id, int32_t node_id, CGetMatchedStylesForNodeCallback callback, void* state);
EXPORT void _ApplicationHostCSSGetMediaQueries(ApplicationHostRef handle, int instance_id, CGetMediaQueriesCallback callback, void* state);
EXPORT void _ApplicationHostCSSGetPlatformFontsForNode(ApplicationHostRef handle, int instance_id, int32_t node_id, CGetPlatformFontsForNodeCallback callback, void* state);
EXPORT void _ApplicationHostCSSGetStyleSheetText(ApplicationHostRef handle, int instance_id, const char* style_sheet_id, CGetStyleSheetTextCallback callback, void* state);
EXPORT void _ApplicationHostCSSSetEffectivePropertyValueForNode(ApplicationHostRef handle, int instance_id, int32_t node_id, const char* property_name, const char* value);
EXPORT void _ApplicationHostCSSSetKeyframeKey(ApplicationHostRef handle, int instance_id, const char* style_sheet_id, SourceRangePtrRef range, const char* key_text, CSetKeyframeKeyCallback callback, void* state);
EXPORT void _ApplicationHostCSSSetMediaText(ApplicationHostRef handle, int instance_id, const char* style_sheet_id, SourceRangePtrRef range, const char* text, CSetMediaTextCallback callback, void* state);
EXPORT void _ApplicationHostCSSSetRuleSelector(ApplicationHostRef handle, int instance_id, const char* style_sheet_id, SourceRangePtrRef range, const char* selector, CSetRuleSelectorCallback callback, void* state);
EXPORT void _ApplicationHostCSSSetStyleSheetText(ApplicationHostRef handle, int instance_id, const char* style_sheet_id, const char* text, CSetStyleSheetTextCallback callback, void* state);
EXPORT void _ApplicationHostCSSSetStyleTexts(ApplicationHostRef handle, int instance_id, StyleDeclarationEditPtrRef* edits, int edits_count, CSetStyleTextsCallback callback, void* state);
EXPORT void _ApplicationHostCSSStartRuleUsageTracking(ApplicationHostRef handle, int instance_id);
EXPORT void _ApplicationHostCSSStopRuleUsageTracking(ApplicationHostRef handle, int instance_id, CStopRuleUsageTrackingCallback callback, void* state);
EXPORT void _ApplicationHostCSSTakeCoverageDelta(ApplicationHostRef handle, int instance_id, CTakeCoverageDeltaCallback callback, void* state);
// CacheStorage
EXPORT void _ApplicationHostCacheStorageHasCache(ApplicationHostRef handle, int instance_id, const char* cache_id, CHasCacheCallback callback, void* state);
EXPORT void _ApplicationHostCacheStorageOpenCache(ApplicationHostRef handle, int instance_id, const char* cache_id, COpenCacheCallback callback, void* state);
EXPORT void _ApplicationHostCacheStorageDeleteCache(ApplicationHostRef handle, int instance_id, const char* cache_id, CDeleteCacheCallback callback, void* state);
EXPORT void _ApplicationHostCacheStoragePutEntryData(ApplicationHostRef handle, int instance_id, const char* cache_id, const char* request, const void* data, int size, CPutEntryCallback callback, void* state);
EXPORT void _ApplicationHostCacheStoragePutEntryBlob(ApplicationHostRef handle, int instance_id, const char* cache_id, const char* request, BlobDataRef blob, CPutEntryCallback callback, void* state);
EXPORT void _ApplicationHostCacheStoragePutEntryFile(ApplicationHostRef handle, int instance_id, const char* cache_id, const char* request, const char* path, uint64_t offset, uint64_t len, CPutEntryCallback callback, void* state);
EXPORT void _ApplicationHostCacheStorageDeleteEntry(ApplicationHostRef handle, int instance_id, const char* cache_id, const char* request, CDeleteEntryCallback callback, void* state);
EXPORT void _ApplicationHostCacheStorageRequestCacheNames(ApplicationHostRef handle, int instance_id, const char* securityOrigin, CRequestCacheNamesCallback callback, void* state);
EXPORT void _ApplicationHostCacheStorageRequestCachedResponse(ApplicationHostRef handle, int instance_id, const char* cache_id, const char* request_url, int base64_encoded, CRequestCachedResponseCallback callback, void* state);
EXPORT void _ApplicationHostCacheStorageRequestEntries(ApplicationHostRef handle, int instance_id, const char* cache_id, int32_t skipCount, int32_t pageSize, CRequestEntriesCallback callback, void* state);
// ApplicationCache
EXPORT void _ApplicationHostApplicationCacheEnable(ApplicationHostRef handle, int instance_id);
EXPORT void _ApplicationHostApplicationCacheGetApplicationCacheForFrame(ApplicationHostRef handle, int instance_id, const char* frameId, CGetApplicationCacheForFrameCallback callback, void* state);
EXPORT void _ApplicationHostApplicationCacheGetFramesWithManifests(ApplicationHostRef handle, int instance_id, CGetFramesWithManifestsCallback callback, void* state);
EXPORT void _ApplicationHostApplicationCacheGetManifestForFrame(ApplicationHostRef handle, int instance_id, const char* frame_id, CGetManifestForFrameCallback callback, void* state);
// Animation
EXPORT void _ApplicationHostAnimationDisable(ApplicationHostRef handle, int instance_id);
EXPORT void _ApplicationHostAnimationEnable(ApplicationHostRef handle, int instance_id);
EXPORT void _ApplicationHostAnimationGetCurrentTime(ApplicationHostRef handle, int instance_id, const char* id, CGetCurrentTimeCallback callback, void* state);
EXPORT void _ApplicationHostAnimationGetPlaybackRate(ApplicationHostRef handle, int instance_id, CGetPlaybackRateCallback callback, void* state);
EXPORT void _ApplicationHostAnimationReleaseAnimations(ApplicationHostRef handle, int instance_id, const char** animations, int animations_count);
EXPORT void _ApplicationHostAnimationResolveAnimation(ApplicationHostRef handle, int instance_id, const char* animation_id, CResolveAnimationCallback callback, void* state);
EXPORT void _ApplicationHostAnimationSeekAnimations(ApplicationHostRef handle, int instance_id, const char** animations, int animations_count, int32_t current_time);
EXPORT void _ApplicationHostAnimationSetPaused(ApplicationHostRef handle, int instance_id, const char** animations, int animations_count, int /* bool */ paused);
EXPORT void _ApplicationHostAnimationSetPlaybackRate(ApplicationHostRef handle, int instance_id, int32_t playback_rate);
EXPORT void _ApplicationHostAnimationSetTiming(ApplicationHostRef handle, int instance_id, const char* animation_id, int32_t duration, int32_t delay);
// Accessibility
EXPORT void _ApplicationHostAccessibilityGetPartialAXTree(
    ApplicationHostRef handle, 
    int instance_id,
    const char* /* optional */ node_id, 
    int32_t backend_node_id, 
    const char* /* optional */ object_id, 
    int /* bool */ fetch_relatives, 
    CGetPartialAXTreeCallback callback, void* state);


EXPORT void _GpuInfoRead(GPUInfoPtrRef reference, 
  int* vendor, 
  int* device, 
  const char** vendor_str, 
  const char** device_str, 
  int* device_count,
  const char** aux_str_keys,
  int* aux_str_keys_count,
  const char** aux_str_vals,
  int* aux_str_vals_count,
  const char** feat_str_keys,
  int* feat_str_keys_count,
  const char** feat_str_vals,
  int* feat_str_vals_count,
  const char** workarounds,
  int* workarounds_count);

EXPORT void _GpuInfoClean(
  GPUInfoPtrRef reference, 
  int* vendor, 
  int* device);

EXPORT void _HistogramRead(
      HistogramPtrRef ref,
      const char** cname,
      int* sum,
      int* count,
      int** lows,
      int** highs,
      int** counts,
      int* bucket_count);

EXPORT void _HistogramClean(
  HistogramPtrRef ref,
  int* lows,
  int* highs,
  int* counts);

EXPORT void _BoundsRead(
  BoundsPtrRef ref,
  int* left,
  int* top,
  int* width,
  int* height,
  int* state);

EXPORT void _SearchMatchRead(
  SearchMatchPtrRef ref,
  int* line_number,
  const char** line_content);

EXPORT void _VisualViewportRead(
  VisualViewportPtrRef ptr,
  int* offset_x,
  int* offset_y,
  int* page_x,
  int* page_y,
  int* client_width,
  int* client_height,
  float* scale);

EXPORT void _LayoutViewportRead(
  LayoutViewportPtrRef ptr,
  int* page_x,
  int* page_y,
  int* client_width,
  int* client_height);

EXPORT void _CookieRead(
  CookiePtrRef ptr,
  const char** name,
  const char** value,
  const char** domain,
  const char** path,
  int64_t* expires,
  int* size,
  int* http_only,
  int* secure,
  int* session,
  int* same_site);

EXPORT void _IndexedDBDataEntryRead(
  IndexedDBDataEntryPtrRef ref,
  const char** key,
  const char** primary_key,
  const char** value);

EXPORT void _DatabaseWithObjectStoresRead(
  DatabaseWithObjectStoresPtrRef reference,
  const char** name,
  int* version,
  const char*** object_names,
  int** object_auto_increments,
  int** object_keypath_types,
  const char*** object_keypath_strs,
  int* object_count,
  const char**** index_names,
  int*** index_uniques,
  int*** index_multientries,
  int*** index_keypath_types,
  const char**** index_keypath_strs,
  int** index_count);

EXPORT void _DatabaseWithObjectStoresClean(
  DatabaseWithObjectStoresPtrRef reference,
  const char** object_names,
  int* object_auto_increments,
  int* object_keypath_types,
  const char** object_keypath_strs,
  const char*** index_names,
  int** index_uniques,
  int** index_multientries,
  int** index_keypath_types,
  const char*** index_keypath_strs);

EXPORT void _DOMSnapshotNodeRead(
  DOMSnapshotNodePtrRef reference, 
  int* nodeType,
  const char** nodeName,
  const char** nodeValue,
  const char** textValue,
  const char** inputValue,
  int* inputChecked,
  int* optionSelected,
  int* backendNodeId,
  int** childNodeIndexes,
  int* childNodeIndexesCount,
  const char*** attributesName,
  const char*** attributesValue,
  int* attributesCount,
  int** pseudoElementIndexes,
  int* pseudoElementIndexesCount,
  int* layoutNodeIndex,
  const char** documentUrl,
  const char** baseUrl,
  const char** contentLanguage,
  const char** documentEncoding,
  const char** publicId,
  const char** systemId,
  const char** frameId,
  int* contentDocumentIndex,
  int* importedDocumentIndex,
  int* templateContentIndex,
  int* pseudoType,
  int* shadowRootType,
  int* isClickable,
  const char** currentSourceUrl);

  
EXPORT void _DOMSnapshotNodeCleanup(
  DOMSnapshotNodePtrRef reference, 
  int* childNodeIndexes,
  const char** attributesName,
  const char** attributesValue,
  int* pseudoElementIndexes);


EXPORT void _ComputedStyleRead(
  ComputedStylePtrRef ptr,
  const char*** name_strs,
  const char*** values_strs,
  int* count);

EXPORT void _ComputedStyleCleanup(
  ComputedStylePtrRef ptr,
  const char** name_strs,
  const char** values_strs);

EXPORT void _LayoutTreeNodeRead(
  LayoutTreeNodePtrRef ptr,
  int* domNodeIndex,
  int* bbx,
  int* bby,
  int* bbw,
  int* bbh,
  const char** layoutText,
  int** itbbx,
  int** itbby,
  int** itbbw,
  int** itbbh,
  int** itsci,
  int** itnc,
  int* itCount,
  int* styleIndex,
  int* paintOrder);
    
EXPORT void _LayoutTreeNodeCleanup(
  LayoutTreeNodePtrRef ptr,
  int* itbbx,
  int* itbby,
  int* itbbw,
  int* itbbh,
  int* itsci,
  int* itnc);


EXPORT void _DOMNodeRead(
  DOMNodePtrRef ptr,
  int* nodeId,
  int* parentId,
  int* backendNodeId,
  int* nodeType,
  const char** nodeName,
  const char** localName,
  const char** nodeValue,
  int* childNodeCount,
  const char*** attributes,
  int* attributes_count,
  const char** documentUrl,
  const char** baseUrl,
  const char** publicId,
  const char** systemId,
  const char** internalSubset,
  const char** xmlVersion,
  const char** name,
  const char** value,
  int* pseudoType,
  int* shadowRootType,
  const char** frameId,
  int* isSvg,
  int** dnNodeTypes,
  const char*** dnNodeNames,
  int** dnNodeIds,
  int* dnNodesCount);

EXPORT void _ScreencastFrameMetadataRead(
  ScreencastFrameMetadataPtrRef ptr,
  int* offsetTop,
  float* pageScaleFactor,
  int* deviceWidth,
  int* deviceHeight,
  int* scrollOffsetX,
  int* scrollOffsetY,
  int* timestamp);

EXPORT void _ViewportRead(ViewportPtrRef ptr, int* x, int* y, int* width, int* height, float* scale);

EXPORT void _ServiceWorkerRegistrationRead(
  ServiceWorkerRegistrationPtrRef ptr, 
  const char** id,
  const char** url,
  int* is_deleted);

EXPORT void _ServiceWorkerVersionRead(
  ServiceWorkerVersionPtrRef ptr, 
  const char** vid,
  const char** rid,
  const char** url,
  int* runningStatus,
  int* status,
  int* scriptLastModified,
  int64_t* scriptResponseTime,
  int** controlledClients,
  int* controlledClientsCount,
  int* targetId);

EXPORT void _ServiceWorkerVersionCleanup(
  ServiceWorkerVersionPtrRef ptr,
  int* controlledClients);

EXPORT void _ServiceWorkerErrorMessageRead(
  ServiceWorkerErrorMessagePtrRef ptr, 
  const char** msg,
  const char** rid,
  const char** surl,
  int* line,
  int* column);

EXPORT void _TargetInfoRead(
  TargetInfoPtrRef ref, 
  const char** targetId, 
  const char** type, 
  const char** title, 
  const char** url, 
  int* attached, 
  const char** openerId, 
  const char** browserContextId);

EXPORT void _AuthChallengeRead(
  AuthChallengePtrRef ptr, 
  int* source, 
  const char** origin, 
  const char** scheme, 
  const char** realm);

EXPORT void _InitiatorRead(
  InitiatorPtrRef ptr, 
  int* type,
  const char** url,
  int* linenumber);

EXPORT void _WebSocketFrameRead(
  WebSocketFramePtrRef ptr, 
  int* opcode,
  int* mask,
  const char** payloadData);
    
EXPORT void _WebSocketResponseRead(
  WebSocketResponsePtrRef ptr, 
  int* status,
  const char** statusText,
  const char*** headersKeys,
  const char*** headersValues,
  int* headersCount,
  const char** headersText,
  const char*** requestHeadersKeys,
  const char*** requestHeadersValues,
  int* requestHeadersCount,
  const char** requestHeadersText);

EXPORT void _WebSocketResponseCleanup(
  WebSocketResponsePtrRef ptr,
  const char** headersKeys,
  const char** headersValues,
  const char** requestHeadersKeys,
  const char** requestHeadersValues);

EXPORT void _WebSocketRequestRead(
  WebSocketRequestPtrRef ptr, 
  const char*** headersKeys,
  const char*** headersValues,
  int* headersCount);
    
EXPORT void _WebSocketRequestCleanup(
  WebSocketRequestPtrRef ptr, 
  const char** headersKeys,
  const char** headersValues);

EXPORT void _SQLErrorRead(
  ErrorPtrRef ptr, 
  const char** message, 
  int* code);

EXPORT void _BoxModelRead(
  BoxModelPtrRef ptr,
  double** content,
  int* contentCount,
  double** padding,
  int* paddingCount,
  double** border,
  int* borderCount,
  double** margin,
  int* marginCount,
  int* width,
  int* height,
  double** shapeBounds,
  int* shapeBoundsCount);
    
EXPORT void _BoxModelCleanup(
  BoxModelPtrRef ptr,
  double* content,
  int contentCount,
  double* padding,
  int paddingCount,
  double* border,
  int borderCount,
  double* margin,
  int marginCount,
  double* shapeBounds,
  int shapeCount);

EXPORT void _CSSRuleRead(
  CSSRulePtrRef ptr,
  const char** cstylesheetId,
  const char** cselectorListText,
  int* cselectorListValuesCount,
  const char*** cselectorListValuesTexts,
  int** cselectorListValuesStartLine,
  int** cselectorListValuesStartColumn,
  int** cselectorListValuesEndLine,
  int** cselectorListValuesEndColumn,
  int* corigin,
  int* cssPropertiesCount,
  const char*** cssPropertiesNames,
  const char*** cssPropertiesValues,
  int** cssPropertiesImportants,
  int** cssPropertiesImplicits,
  const char*** cssPropertiesTexts,
  int** cssPropertiesParsedOk,
  int** cssPropertiesDisabled,
  int** cssPropertiesStartLine,
  int** cssPropertiesStartColumn,
  int** cssPropertiesEndLine,
  int** cssPropertiesEndColumn,
  int* shorthandEntriesCount,
  const char*** shorthandEntriesNames,
  const char*** shorthandEntriesValues,
  int** shorthandEntriesImportants,
  const char** styleSheetId,
  const char** styleCssText,
  int* styleStartLine,
  int* styleStartColumn,
  int* styleEndLine,
  int* styleEndColumn,
  CSSMediaPtrRef** cssMedias,
  int* cssMediasCount);

EXPORT void _CSSRuleCleanup(
  CSSRulePtrRef ptr,
  int cselectorListValuesCount,
  const char** cselectorListValuesTexts,
  int* cselectorListValuesStartLine,
  int* cselectorListValuesStartColumn,
  int* cselectorListValuesEndLine,
  int* cselectorListValuesEndColumn,
  int cssPropertiesCount,
  const char** cssPropertiesNames,
  const char** cssPropertiesValues,
  int* cssPropertiesImportants,
  int* cssPropertiesImplicits,
  const char** cssPropertiesTexts,
  int* cssPropertiesParsedOk,
  int* cssPropertiesDisabled,
  int* cssPropertiesStartLine,
  int* cssPropertiesStartColumn,
  int* cssPropertiesEndLine,
  int* cssPropertiesEndColumn,
  int shorthandEntriesCount,
  const char** shorthandEntriesNames,
  const char** shorthandEntriesValues,
  int* shorthandEntriesImportants,
  CSSMediaPtrRef* cssMedias,
  int cssMediasCount);

EXPORT void _FrameRead(
  FramePtrRef ptr,
  const char** cid,
  const char** pid,
  const char** lid,
  const char** cname,
  const char** curl,
  const char** csecurityOrigin,
  const char** cmimeType,
  const char** cunreachableUrl);

EXPORT void _LayerRead(
  LayerPtrRef ptr,
  const char** clayerId,
  const char** playerId,
  int* cbackendNode,
  int* coffsetx,
  int* coffsety,
  int* cwidth,
  int* cheight,
  double** ctransform,
  int* ctransformCount,
  int* canchorX,
  int* canchorY,
  int* canchorZ,
  int* cpaintCount,
  int* cdrawsContent,
  int* cinvisible,
  int** csx,
  int** csy,
  int** csw,
  int** csh,
  int** cstype,
  int* scrollRectCount,
  int* cspx,
  int* cspy,
  int* cspw,
  int* csph,
  int* cspcx,
  int* cspcy,
  int* cspcw,
  int* cspch,
  const char** cspStickyBox,
  const char** cspContainingBlock);

EXPORT void _LayerCleanup(
  LayerPtrRef ptr,
  double* ctransform,
  int ctransformCount,
  int* csx,
  int* csy,
  int* csw,
  int* csh,
  int* cstype,
  int scrollRectCount);

EXPORT void _StorageIdRead(
  StorageIdPtrRef ptr,
  const char** securityOrigin,
  int* localStorage);

EXPORT void _CSSStyleRead(
  CSSStylePtrRef ptr,
  const char** styleSheetId,
  const char** styleCssText,
  int* styleStartLine,
  int* styleStartColumn,
  int* styleEndLine,
  int* styleEndColumn,
  int* cssPropertiesCount,
  const char*** cssPropertiesNames,
  const char*** cssPropertiesValues,
  int** cssPropertiesImportants,
  int** cssPropertiesImplicits,
  const char*** cssPropertiesTexts,
  int** cssPropertiesParsedOk,
  int** cssPropertiesDisabled,
  int** cssPropertiesStartLine,
  int** cssPropertiesStartColumn,
  int** cssPropertiesEndLine,
  int** cssPropertiesEndColumn,
  int* shorthandEntriesCount,
  const char*** shorthandEntriesNames,
  const char*** shorthandEntriesValues,
  int** shorthandEntriesImportants);

EXPORT void _BackendNodeRead(
  BackendNodePtrRef ptr, 
  int* nodeType,
  const char** nodeName,
  int* backendNodeId);

EXPORT void _CSSValueRead(
  CSSValuePtrRef ptr,
  const char** text,
  int* startLine,
  int* startColumn,
  int* endLine,
  int* endColumn);

EXPORT void _RuleMatchRead(
  RuleMatchPtrRef ptr, 
  CSSRulePtrRef* rule,
  int** sels,
  int* selsCount);

EXPORT void _RuleMatchCleanup(
  RuleMatchPtrRef ptr,
  int* sels,
  int selsCount);

EXPORT void _DatabaseRead(
  DatabasePtrRef ptr, 
  const char** id,
  const char** dom,
  const char** name,
  const char** version);

EXPORT void _FontFaceRead(
  FontFacePtrRef ptr,
  const char** fontFamily,
  const char** fontStyle,
  const char** fontVariant,
  const char** fontWeight,
  const char** fontStretch,
  const char** unicodeRange,
  const char** src,
  const char** platformFontFamily);

EXPORT void _CSSStyleSheetHeaderRead(
  CSSStyleSheetHeaderPtrRef ptr,
  const char** styleStyleSheetId,
  const char** frameId,
  const char** sourceUrl,
  const char** sourceMapUrl,
  int* origin,
  const char** title,
  int* ownerNode,
  int* disabled,
  int* hasSourceUrl,
  int* isInline,
  int* startLine,
  int* startColumn,
  int* length);

EXPORT void _AnimationRead(
  AnimationPtrRef ptr, 
  const char** id,
  const char** name,
  int* pausedState,
  const char** playState,
  int* playbackRate,
  int64_t* startTime,
  int64_t* currentTime,
  int* type,
  AnimationEffectPtrRef* source,
  const char** cssId);

EXPORT void _AnimationEffectRead(
  AnimationEffectPtrRef ptr,
  int* delay,
  int* endDelay,
  int* iterationStart,
  int* iterations,
  int* duration,
  const char** direction,
  const char** fill,
  int* backendNodeId,
  CSSKeyframesRulePtrRef* keyframesRule,
  const char** easing);

EXPORT void _KeyframesRuleRead(
  CSSKeyframesRulePtrRef ptr,
  const char** name,
  const char*** offsets,
  const char*** easing,
  int* stylesCount);

EXPORT void _KeyframesRuleCleanup(
  CSSKeyframesRulePtrRef ptr,
  const char** offsets,
  const char** easing,
  int stylesCount);

EXPORT void _NavigationEntryRead(
  NavigationEntryPtrRef ptr,
  int* id,
  const char** url,
  const char** userTypedUrl,
  const char** title,
  int* transitionType);

EXPORT void _CSSComputedStylePropertyRead(
  CSSComputedStylePropertyPtrRef ptr,
  const char** name,
  const char** value);

EXPORT void _PseudoElementMatchesRead(
  PseudoElementMatchesPtrRef ptr,
  int* pseudoType,
  RuleMatchPtrRef** matches,
  int* matchesCount);

EXPORT void _PseudoElementMatchesCleanup(
  PseudoElementMatchesPtrRef ptr, 
  RuleMatchPtrRef* matches,
  int matchesCount);

EXPORT void _InheritedStyleEntryRead(
  InheritedStyleEntryPtrRef ptr,
  CSSStylePtrRef* inlineStyle,
  RuleMatchPtrRef** matches,
  int* matchesCount);

EXPORT void _InheritedStyleEntryCleanup(
  InheritedStyleEntryPtrRef ptr, 
  RuleMatchPtrRef* matches,
  int matchesCount);

EXPORT void _CSSKeyframeRuleRead(
  CSSKeyframeRulePtrRef ptr, 
  const char** styleSheetId, 
  int* origin, 
  CSSValuePtrRef* keyText, 
  CSSValuePtrRef* style);

EXPORT void _CSSKeyframesRuleRead(
  CSSKeyframesRulePtrRef ptr, 
  CSSValuePtrRef* animationName, 
  CSSKeyframeRulePtrRef** keyframes, 
  int* keyframesCount);

EXPORT void _CSSKeyframesRuleCleanup(
  CSSKeyframesRulePtrRef ptr, 
  CSSKeyframeRulePtrRef* keyframes, 
  int keyframesCount);

EXPORT void _CSSMediaQueryExpressionRead(
  CSSMediaQueryExpressionPtrRef ptr,
  int* value,
  const char** unit,
  const char** feature,
  int* startLine,
  int* startColumn,
  int* endLine,
  int* endColumn,
  int* computedLength);

EXPORT void _CSSMediaQueryRead(
  CSSMediaQueryPtrRef ptr,
  CSSMediaQueryExpressionPtrRef** expr,
  int* exprCount,
  int* active);

EXPORT void _CSSMediaQueryCleanup(
  CSSMediaQueryPtrRef ptr, 
  CSSMediaQueryExpressionPtrRef* expr,
  int exprCount);

EXPORT void _CSSMediaRead(
  CSSMediaPtrRef ptr,
  int* source,
  const char** text,
  const char** sourceUrl,
  int* startLine,
  int* startColumn,
  int* endLine,
  int* endColumn,
  const char** styleSheetId,
  CSSMediaQueryPtrRef** mediaList,
  int* mediaListCount);

EXPORT void _CSSMediaCleanup(
  CSSMediaPtrRef ptr,
  CSSMediaQueryPtrRef* mediaList,
  int mediaListCount);

EXPORT void _CSSRuleUsageRead(
  CSSRuleUsagePtrRef ptr,
  const char** styleSheetId,
  int* startOffset,
  int* endOffset,
  int* used);

EXPORT void _CacheRead(
  CachePtrRef ptr,
  const char** cacheId,
  const char** securityOrigin,
  const char** cacheName);

EXPORT void _FrameWithManifestRead(
  FrameWithManifestPtrRef ptr,
  const char** frameId,
  const char** manifestUrl,
  int* status);

EXPORT void _SelectorListRead(
  SelectorListPtrRef ptr, 
  CSSValuePtrRef** sel,
  int* selCount,
  const char** text);

EXPORT void _SelectorListCleanup(
  SelectorListPtrRef ptr, 
  CSSValuePtrRef* sel,
  int selCount);

EXPORT void _ApplicationCacheRead(
  ApplicationCachePtrRef ptr, 
  const char** manifestUrl,
  int64_t* size,
  int64_t* creationTime,
  int64_t* updateTime,
  const char*** resourceUrls,
  int** resourceSizes,
  const char*** resourceTypes,
  int* resourceCount);

EXPORT void _ApplicationCacheCleanup(
  ApplicationCachePtrRef ptr, 
  const char** resourceUrls,
  int* resourceSizes,
  const char** resourceTypes,
  int resourceCount);

EXPORT void _PlatformFontUsage(
  PlatformFontUsagePtrRef ptr,
  const char** familyName,
  int* isCustomFont,
  int* glyphCount);
    
EXPORT void _DataEntryRead(
  DataEntryPtrRef ptr,
  const char** requestUrl,
  const char** requestMethod,
  const char*** requestHeadersNames,
  const char*** requestHeadersValues,
  int* requestHeadersCount,
  int64_t* responseTime,
  int* responseStatus,
  const char** responseStatusText, 
  const char*** responseHeadersNames,
  const char*** responseHeadersValues,
  int* responseHeadersCount);

EXPORT void _DataEntryCleanup(
  DataEntryPtrRef ptr,
  const char** requestHeadersNames,
  const char** requestHeadersValues,
  int requestHeadersCount,
  const char** responseHeadersNames,
  const char** responseHeadersValues,
  int responseHeadersCount);

EXPORT void _FrameResourceRead(
  FrameResourcePtrRef ptr,
  const char** url,
  int* type,
  const char** mimetype,
  int* lastModified,
  int* contentSize,
  int* failed,
  int* canceled);
    
EXPORT void _FrameTreeRead(
  FrameTreePtrRef ptr,
  FramePtrRef* frame,
  FrameTreePtrRef** childFrames,
  int* childFramesCount);

EXPORT void _FrameTreeCleanup(
  FrameTreePtrRef ptr,
  FrameTreePtrRef* childFrames,
  int childFramesCount);

EXPORT void _FrameResourceTreeRead(
  FrameResourceTreePtrRef ptr,
  FramePtrRef* frame,
  FrameTreePtrRef** childFrames,
  int* childFramesCount,
  FrameResourcePtrRef** resources,
  int* resourcesCount);
    
EXPORT void _FrameResourceTreeCleanup(
  FrameResourceTreePtrRef ptr,
  FrameTreePtrRef* childFrames,
  int childFramesCount,
  FrameResourcePtrRef* resources,
  int resourcesCount);

// BlobBytesProvider

EXPORT void BlobBytesProviderAppendData(BlobBytesProviderRef handle, const void* data, int size);

EXPORT BlobDataRef BlobDataCreate();
EXPORT BlobDataRef BlobDataCreateForFile(const char* path);
EXPORT BlobDataRef BlobDataCreateForFilesystemUrl(const char* url);
EXPORT void BlobDataDestroy(BlobDataRef reference);
EXPORT char* BlobDataGetContentType(BlobDataRef reference, int* len);
EXPORT void BlobDataSetContentType(BlobDataRef reference, const char* content_type);
EXPORT uint64_t BlobDataGetLength(BlobDataRef reference);
EXPORT void BlobDataAppendBytes(BlobDataRef reference, const void*, size_t length);
EXPORT void BlobDataAppendFile(BlobDataRef reference, 
                               const char* path,
                               long long offset,
                               long long length,
                               double expected_modification_time);
EXPORT void BlobDataAppendFileSystemURL(BlobDataRef reference, 
                                        const char* url,
                                        long long offset,
                                        long long length,
                                        double expected_modification_time);
EXPORT void BlobDataAppendText(BlobDataRef reference, const char* text, int normalize_line_endings_to_native);

#endif