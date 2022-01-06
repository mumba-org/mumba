// Copyright 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_DOMAIN_APPLICATION_APPLICATION_DRIVER_H_
#define MUMBA_DOMAIN_APPLICATION_APPLICATION_DRIVER_H_

#include "base/macros.h"
#include "base/uuid.h"
#include "core/shared/common/content_export.h"
#include "core/shared/common/mojom/automation.mojom.h"
#include "mojo/public/cpp/bindings/associated_binding.h"
#include "mojo/public/cpp/bindings/associated_binding_set.h"
#include "mojo/public/cpp/bindings/interface_ptr.h"
#include "third_party/blink/public/mojom/blob/blob_registry.mojom-blink.h"

namespace domain {
class Application;

class ApplicationDriver;

class CONTENT_EXPORT SystemInfoInterface {
public:
  SystemInfoInterface(ApplicationDriver* driver);
  ~SystemInfoInterface();

  ApplicationDriver* driver() const {
    return driver_;
  }

  void GetInfo(automation::SystemInfo::GetInfoCallback callback);

private:  
  ApplicationDriver* driver_;
  
  DISALLOW_COPY_AND_ASSIGN(SystemInfoInterface);
};

class CONTENT_EXPORT HostInterface {
public:
  HostInterface(ApplicationDriver* driver);
  ~HostInterface();

  ApplicationDriver* driver() const {
    return driver_;
  }

  void Close();
  void GetVersion(automation::Host::GetVersionCallback callback);
  void GetHostCommandLine(automation::Host::GetHostCommandLineCallback callback);
  void GetHistograms(const base::Optional<std::string>& query, automation::Host::GetHistogramsCallback callback);
  void GetHistogram(const std::string& name, automation::Host::GetHistogramCallback callback);
  void GetWindowBounds(int32_t window_id, automation::Host::GetWindowBoundsCallback callback);
  void GetWindowForTarget(const std::string& target_id, automation::Host::GetWindowForTargetCallback callback);
  void SetWindowBounds(int32_t window_id, automation::BoundsPtr bounds);

private:
  
  ApplicationDriver* driver_;

  DISALLOW_COPY_AND_ASSIGN(HostInterface);
};

class CONTENT_EXPORT OverlayInterface {
public:
  OverlayInterface(ApplicationDriver* driver);
  ~OverlayInterface();

  ApplicationDriver* driver() const {
    return driver_;
  }

  void Disable();
  void Enable();
  void HideHighlight();
  void HighlightFrame(const std::string& frame_id, automation::RGBAPtr content_color, automation::RGBAPtr content_outline_color);
  void HighlightNode(automation::HighlightConfigPtr highlight_config, int32_t node_id, int32_t backend_node_id, const base::Optional<std::string>& object_id);
  void HighlightQuad(const std::vector<double>& quad, automation::RGBAPtr color, automation::RGBAPtr outline_color);
  void HighlightRect(int32_t x, int32_t y, int32_t width, int32_t height, automation::RGBAPtr color, automation::RGBAPtr outline_color);
  void SetInspectMode(automation::InspectMode mode, automation::HighlightConfigPtr highlight_config);
  void SetPausedInDebuggerMessage(const base::Optional<std::string>& message);
  void SetShowDebugBorders(bool show);
  void SetShowFPSCounter(bool show);
  void SetShowPaintRects(bool result);
  void SetShowScrollBottleneckRects(bool show);
  void SetShowViewportSizeOnResize(bool show);
  void SetSuspended(bool suspended);

private:
  ApplicationDriver* driver_;

  DISALLOW_COPY_AND_ASSIGN(OverlayInterface);
};

class CONTENT_EXPORT PageInterface {
public:
  PageInterface(ApplicationDriver* driver);
  ~PageInterface();

  ApplicationDriver* driver() const {
    return driver_;
  }

  void Enable();
  void Disable();
  void AddScriptToEvaluateOnNewDocument(const std::string& source, automation::Page::AddScriptToEvaluateOnNewDocumentCallback callback);
  void RemoveScriptToEvaluateOnNewDocument(const std::string& identifier);
  void SetAutoAttachToCreatedPages(bool auto_attach);
  void SetLifecycleEventsEnabled(bool enabled);
  void Reload(bool ignore_cache, const std::string& script_to_evaluate_on_load);
  void SetAdBlockingEnabled(bool enabled);
  void Navigate(const std::string& url, const std::string& referrer, automation::TransitionType transition_type, automation::Page::NavigateCallback callback);
  void StopLoading();
  void GetNavigationHistory(automation::Page::GetNavigationHistoryCallback callback);
  void NavigateToHistoryEntry(int32_t entry_id);
  void GetCookies(automation::Page::GetCookiesCallback callback);
  void DeleteCookie(const std::string& cookie_name, const std::string& url);
  void GetResourceTree(automation::Page::GetResourceTreeCallback callback);
  void GetFrameTree(automation::Page::GetFrameTreeCallback callback);
  void GetResourceContent(const std::string& frame_id, const std::string& url, automation::Page::GetResourceContentCallback callback);
  void SearchInResource(const std::string& frame_id, const std::string& url, const std::string& query, bool case_sensitive, bool is_regex, automation::Page::SearchInResourceCallback callback);
  void SetDocumentContent(const std::string& frame_id, const std::string& html);
  void SetDeviceMetricsOverride(int32_t width, int32_t height, int32_t device_scale_factor, bool mobile, int32_t scale, int32_t screen_width, int32_t screen_height, int32_t position_x, int32_t position_y, bool dont_set_visible_size, automation::ScreenOrientationPtr screen_orientation, automation::ViewportPtr viewport);
  void ClearDeviceMetricsOverride();
  void SetGeolocationOverride(int32_t latitude, int32_t longitude, int32_t accuracy);
  void ClearGeolocationOverride();
  void SetDeviceOrientationOverride(int32_t alpha, int32_t beta, int32_t gamma);
  void ClearDeviceOrientationOverride();
  void SetTouchEmulationEnabled(bool enabled, const std::string& configuration);
  void CaptureScreenshot(automation::FrameFormat format, int32_t quality, automation::ViewportPtr clip, bool from_surface, automation::Page::CaptureScreenshotCallback callback);
  void PrintToPDF(bool landscape, bool display_header_footer, bool print_background, float scale, float paper_width, float paper_height, float margin_top, float margin_bottom, float margin_left, float margin_right, const base::Optional<std::string>& page_ranges, bool ignore_invalid_page_ranges, automation::Page::PrintToPDFCallback callback);
  void StartScreencast(automation::FrameFormat format, int32_t quality, int32_t max_width, int32_t max_height, int32_t every_nth_frame);
  void StopScreencast();
  void SetBypassCSP(bool enable);
  void ScreencastFrameAck(int32_t session_id);
  void HandleJavaScriptDialog(bool accept, const std::string& prompt_text);
  void GetAppManifest(automation::Page::GetAppManifestCallback callback);
  void RequestAppBanner();
  void GetLayoutMetrics(automation::Page::GetLayoutMetricsCallback callback);
  void CreateIsolatedWorld(const std::string& frame_id, const base::Optional<std::string>& world_name, bool grant_universal_access, automation::Page::CreateIsolatedWorldCallback callback);
  void BringToFront();
  void SetDownloadBehavior(const std::string& behavior, const base::Optional<std::string>& download_path);
  void Close();

private:
  ApplicationDriver* driver_;

  DISALLOW_COPY_AND_ASSIGN(PageInterface);
};

class CONTENT_EXPORT WorkerInterface {
public:
  WorkerInterface(ApplicationDriver* driver);
  ~WorkerInterface();

  ApplicationDriver* driver() const {
    return driver_;
  }

  void DeliverPushMessage(const std::string& origin, const std::string& registration_id, const std::string& data);
  void Disable();
  void DispatchSyncEvent(const std::string& origin, const std::string& registration_id, const std::string& tag, bool last_chance);
  void Enable();
  void InspectWorker(const std::string& version_id);
  void SetForceUpdateOnPageLoad(bool force_update_on_pageload);
  void SkipWaiting(const std::string& scope_url);
  void StartWorker(const std::string& scope_url);
  void StopAllWorkers();
  void StopWorker(const std::string& version_id);
  void Unregister(const std::string& scope_url);
  void UpdateRegistration(const std::string& scope_url);
  void SendMessageToTarget(const std::string& message, const base::Optional<std::string>& session_id, const base::Optional<std::string>& target_id);

private:
  
  ApplicationDriver* driver_;

  DISALLOW_COPY_AND_ASSIGN(WorkerInterface);
};

class CONTENT_EXPORT StorageInterface {
public:
  StorageInterface(ApplicationDriver* driver);
  ~StorageInterface();

  ApplicationDriver* driver() const {
    return driver_;
  }

  void ClearDataForOrigin(const std::string& origin, const std::vector<automation::StorageType>& storage_types);
  void GetUsageAndQuota(const std::string& origin, int64_t usage, int64_t quota, std::vector<automation::UsageForTypePtr> usage_breakdown);
  void TrackCacheStorageForOrigin(const std::string& origin);
  void TrackIndexedDBForOrigin(const std::string& origin);
  void UntrackCacheStorageForOrigin(const std::string& origin);
  void UntrackIndexedDBForOrigin(const std::string& origin);

private:
  ApplicationDriver* driver_;
  DISALLOW_COPY_AND_ASSIGN(StorageInterface);
};

class CONTENT_EXPORT TetheringInterface {
public:
  TetheringInterface(ApplicationDriver* driver);
  ~TetheringInterface();

  ApplicationDriver* driver() const {
    return driver_;
  }

  void Bind(int32_t port);
  void Unbind(int32_t port);

private:
  ApplicationDriver* driver_;
  DISALLOW_COPY_AND_ASSIGN(TetheringInterface);
};

class CONTENT_EXPORT NetworkInterface {
public:
  NetworkInterface(ApplicationDriver* driver);
  ~NetworkInterface();

  ApplicationDriver* driver() const {
    return driver_;
  }

  void CanClearBrowserCache(automation::Network::CanClearBrowserCacheCallback callback);
  void CanClearBrowserCookies(automation::Network::CanClearBrowserCookiesCallback callback);
  void CanEmulateNetworkConditions(automation::Network::CanEmulateNetworkConditionsCallback callback);
  void ClearBrowserCache();
  void ClearBrowserCookies();
  void ContinueInterceptedRequest(const std::string& interception_id, automation::ErrorReason error_reason, const base::Optional<std::string>& raw_response, const base::Optional<std::string>& url, const base::Optional<std::string>& method, const base::Optional<std::string>& post_data, const base::Optional<base::flat_map<std::string, std::string>>& headers, automation::AuthChallengeResponsePtr auth_challenge_response);
  void DeleteCookies(const std::string& name, const base::Optional<std::string>& url, const base::Optional<std::string>& domain, const base::Optional<std::string>& path);
  void Disable();
  void EmulateNetworkConditions(bool offline, int64_t latency, int64_t download_throughput, int64_t upload_throughput, automation::ConnectionType connection_type);
  void Enable(int32_t max_total_buffer_size, int32_t max_resource_buffer_size, int32_t max_post_data_size);
  void GetAllCookies(automation::Network::GetAllCookiesCallback callback);
  void GetCertificate(const std::string& origin, automation::Network::GetCertificateCallback callback);
  void GetCookies(const base::Optional<std::vector<std::string>>& urls, automation::Network::GetCookiesCallback callback);
  void GetResponseBody(const std::string& request_id, automation::Network::GetResponseBodyCallback callback);
  void GetRequestPostData(const std::string& request_id, automation::Network::GetRequestPostDataCallback callback);
  void GetResponseBodyForInterception(const std::string& interception_id, automation::Network::GetResponseBodyForInterceptionCallback callback);
  void TakeResponseBodyForInterceptionAsStream(const std::string& interception_id, automation::Network::TakeResponseBodyForInterceptionAsStreamCallback callback);
  void ReplayXHR(const std::string& request_id);
  void SearchInResponseBody(const std::string& request_id, const std::string& query, bool case_sensitive, bool is_regex, automation::Network::SearchInResponseBodyCallback callback);
  void SetBlockedURLs(const std::vector<std::string>& urls);
  void SetBypassServiceWorker(bool bypass);
  void SetCacheDisabled(bool cache_disabled);
  void SetCookie(const std::string& name, const std::string& value, const base::Optional<std::string>& url, const base::Optional<std::string>& domain, const base::Optional<std::string>& path, bool secure, bool http_only, automation::CookieSameSite same_site, int64_t expires, automation::Network::SetCookieCallback callback);
  void SetCookies(std::vector<automation::CookieParamPtr> cookies);
  void SetDataSizeLimits(int32_t max_total_size, int32_t max_resource_size);
  void SetExtraHTTPHeaders(const base::flat_map<std::string, std::string>& headers);
  void SetRequestInterception(std::vector<automation::RequestPatternPtr> patterns);
  void SetUserAgentOverride(const std::string& user_agent);
private:
  ApplicationDriver* driver_;

  DISALLOW_COPY_AND_ASSIGN(NetworkInterface);
};

class CONTENT_EXPORT LayerTreeInterface {
public:
  LayerTreeInterface(ApplicationDriver* driver);
  ~LayerTreeInterface();

  ApplicationDriver* driver() const {
    return driver_;
  }

  void CompositingReasons(const std::string& layer_id, automation::LayerTree::CompositingReasonsCallback callback);
  void Disable();
  void Enable();
  void LoadSnapshot(std::vector<automation::PictureTilePtr> tiles, automation::LayerTree::LoadSnapshotCallback callback);
  void MakeSnapshot(const std::string& layer_id, automation::LayerTree::MakeSnapshotCallback callback);
  void ProfileSnapshot(const std::string& snapshot_id, int32_t min_repeat_count, int32_t min_duration, const base::Optional<gfx::Rect>& clip_rect, automation::LayerTree::ProfileSnapshotCallback callback);
  void ReleaseSnapshot(const std::string& snapshot_id);
  void ReplaySnapshot(const std::string& snapshot_id, int32_t from_step, int32_t to_step, int32_t scale, automation::LayerTree::ReplaySnapshotCallback callback);
  void SnapshotCommandLog(const std::string& snapshot_id, automation::LayerTree::SnapshotCommandLogCallback callback);

private:
  ApplicationDriver* driver_;
  DISALLOW_COPY_AND_ASSIGN(LayerTreeInterface); 
};

class CONTENT_EXPORT InputInterface {
public:
  InputInterface(ApplicationDriver* driver);
  ~InputInterface();

  ApplicationDriver* driver() const {
    return driver_;
  }

  void DispatchKeyEvent(automation::KeyEventType type, int32_t modifiers, int64_t timestamp, const base::Optional<std::string>& text, const base::Optional<std::string>& unmodified_text, const base::Optional<std::string>& key_identifier, const base::Optional<std::string>& code, const base::Optional<std::string>& key, int32_t windows_virtual_key_code, int32_t native_virtual_key_code, bool auto_repeat, bool is_keypad, bool is_system_key, int32_t location, automation::Input::DispatchKeyEventCallback callback);
  void DispatchMouseEvent(automation::MouseEventType type, int32_t x, int32_t y, int32_t modifiers, int64_t timestamp, automation::MouseButton button, int32_t click_count, int32_t delta_x, int32_t delta_y, automation::Input::DispatchMouseEventCallback callback);
  void DispatchTouchEvent(automation::TouchEventType type, std::vector<automation::TouchPointPtr> touch_points, int32_t modifiers, int64_t timestamp, automation::Input::DispatchTouchEventCallback callback);
  void EmulateTouchFromMouseEvent(automation::MouseEventType type, int32_t x, int32_t y, automation::MouseButton button, int64_t timestamp, int32_t delta_x, int32_t delta_y, int32_t modifiers, int32_t click_count, automation::Input::EmulateTouchFromMouseEventCallback callback);
  void SetIgnoreInputEvents(bool ignore);
  void SynthesizePinchGesture(int32_t x, int32_t y, int32_t scale_factor, int32_t relative_speed, automation::GestureSourceType gesture_source_type, automation::Input::SynthesizePinchGestureCallback callback);
  void SynthesizeScrollGesture(int32_t x, int32_t y, int32_t x_distance, int32_t y_distance, int32_t x_overscroll, int32_t y_overscroll, bool prevent_fling, int32_t speed, automation::GestureSourceType gesture_source_type, int32_t repeat_count, int32_t repeat_delay_ms, const base::Optional<std::string>& interaction_marker_name, automation::Input::SynthesizeScrollGestureCallback callback);
  void SynthesizeTapGesture(int32_t x, int32_t y, int32_t duration, int32_t tap_count, automation::GestureSourceType gesture_source_type, automation::Input::SynthesizeTapGestureCallback callback);
private:
  ApplicationDriver* driver_;
  DISALLOW_COPY_AND_ASSIGN(InputInterface); 
};

class CONTENT_EXPORT IndexedDBInterface {
public:
  IndexedDBInterface(ApplicationDriver* driver);
  ~IndexedDBInterface();

  ApplicationDriver* driver() const {
    return driver_;
  }

  void Disable();
  void Enable();
  void ClearObjectStore(const std::string& security_origin, const std::string& database_name, const std::string& object_store_name, automation::IndexedDB::ClearObjectStoreCallback callback);
  void DeleteDatabase(const std::string& security_origin, const std::string& database_name, automation::IndexedDB::DeleteDatabaseCallback callback);
  void DeleteObjectStoreEntries(const std::string& security_origin, const std::string& database_name, const std::string& object_store_name, automation::KeyRangePtr keyRange, automation::IndexedDB::DeleteObjectStoreEntriesCallback callback);
  void RequestData(const std::string& security_origin, const std::string& database_name, const std::string& object_store_name, const std::string& index_name, int32_t skip_count, int32_t page_size, automation::KeyRangePtr key_range, automation::IndexedDB::RequestDataCallback callback);
  void RequestDatabase(const std::string& security_origin, const std::string& database_name, automation::IndexedDB::RequestDatabaseCallback callback);
  void RequestDatabaseNames(const std::string& security_origin, automation::IndexedDB::RequestDatabaseNamesCallback callback);

private:
  ApplicationDriver* driver_;
  
  DISALLOW_COPY_AND_ASSIGN(IndexedDBInterface);
};

class CONTENT_EXPORT IOInterface {
public:
  IOInterface(ApplicationDriver* driver);
  ~IOInterface();

  ApplicationDriver* driver() const {
    return driver_;
  }

  void Close(const std::string& handl);
  void Read(const std::string& handl, int32_t offset, int32_t size, automation::IO::ReadCallback callback);
  void ResolveBlob(const std::string& object_id, automation::IO::ResolveBlobCallback callback);

private:
  ApplicationDriver* driver_;

  DISALLOW_COPY_AND_ASSIGN(IOInterface);
};

class CONTENT_EXPORT HeadlessInterface {
public:
  HeadlessInterface(ApplicationDriver* driver);
  ~HeadlessInterface();

  ApplicationDriver* driver() const {
    return driver_;
  }

  void BeginFrame(int64_t frame_time, int32_t frame_time_ticks, int64_t deadline, int32_t deadline_ticks, int32_t interval, bool no_display_updates, automation::ScreenshotParamsPtr screenshot, automation::Headless::BeginFrameCallback callback);
  void EnterDeterministicMode(int32_t initial_date);
  void Disable();
  void Enable();

private:
  ApplicationDriver* driver_;

  DISALLOW_COPY_AND_ASSIGN(HeadlessInterface);
};

class CONTENT_EXPORT DOMStorageInterface {
public:
  DOMStorageInterface(ApplicationDriver* driver);
  ~DOMStorageInterface();

  ApplicationDriver* driver() const {
    return driver_;
  }

  void Clear(automation::StorageIdPtr storage_id);
  void Disable();
  void Enable();
  void GetDOMStorageItems(automation::StorageIdPtr storageId, automation::DOMStorage::GetDOMStorageItemsCallback callback);
  void RemoveDOMStorageItem(automation::StorageIdPtr storage_id, const std::string& key);
  void SetDOMStorageItem(automation::StorageIdPtr storageId, const std::string& key, const std::string& value);
private:
  ApplicationDriver* driver_;

  DISALLOW_COPY_AND_ASSIGN(DOMStorageInterface);
};

class CONTENT_EXPORT DatabaseInterface {
public:
  DatabaseInterface(ApplicationDriver* driver);
  ~DatabaseInterface();

  ApplicationDriver* driver() const {
    return driver_;
  }

  void Disable();
  void Enable();
  void ExecuteSQL(const std::string& database_id, const std::string& query, automation::DatabaseInterface::ExecuteSQLCallback callback);
  void GetDatabaseTableNames(const std::string& database_id, automation::DatabaseInterface::GetDatabaseTableNamesCallback callback);

private:
  
  ApplicationDriver* driver_;
  
  DISALLOW_COPY_AND_ASSIGN(DatabaseInterface);
};

class CONTENT_EXPORT DeviceOrientationInterface {
public:
 DeviceOrientationInterface(ApplicationDriver* driver);
 ~DeviceOrientationInterface();
 
 ApplicationDriver* driver() const {
    return driver_;
 }
 
 void ClearDeviceOrientationOverride();
 void SetDeviceOrientationOverride(int32_t alpha, int32_t beta, int32_t gamma);

private:
  ApplicationDriver* driver_;
  DISALLOW_COPY_AND_ASSIGN(DeviceOrientationInterface);
};

class CONTENT_EXPORT EmulationInterface {
public:
  EmulationInterface(ApplicationDriver* driver);
  ~EmulationInterface();

  ApplicationDriver* driver() const {
    return driver_;
  }

  void CanEmulate(automation::Emulation::CanEmulateCallback callback);
  void ClearDeviceMetricsOverride();
  void ClearGeolocationOverride();
  void ResetPageScaleFactor();
  void SetCPUThrottlingRate(int32_t rate);
  void SetDefaultBackgroundColorOverride(automation::RGBAPtr color);
  void SetDeviceMetricsOverride(int32_t width, int32_t height, float device_scale_factor, bool mobile, float scale, int32_t screen_width, int32_t screen_height, int32_t position_x, int32_t position_y, bool dont_set_visible_size, automation::ScreenOrientationPtr screen_orientation, automation::ViewportPtr viewport);
  void SetEmitTouchEventsForMouse(bool enabled, automation::TouchEventForMouseConfiguration configuration);
  void SetEmulatedMedia(const std::string& media);
  void SetGeolocationOverride(int64_t latitude, int64_t longitude, int64_t accuracy);
  void SetNavigatorOverrides(const std::string& platform);
  void SetPageScaleFactor(float page_scale_factor);
  void SetScriptExecutionDisabled(bool value);
  void SetTouchEmulationEnabled(bool enabled, int32_t max_touch_points);
  void SetVirtualTimePolicy(automation::VirtualTimePolicy policy, int32_t budget, int32_t max_virtual_time_task_starvation_count, bool wait_for_navigation, automation::Emulation::SetVirtualTimePolicyCallback callback);
  void SetVisibleSize(int32_t width, int32_t height);

private:

  ApplicationDriver* driver_;

  DISALLOW_COPY_AND_ASSIGN(EmulationInterface);
};

class CONTENT_EXPORT DOMSnapshotInterface {
public:
  DOMSnapshotInterface(ApplicationDriver* driver);
  ~DOMSnapshotInterface();

  ApplicationDriver* driver() const {
    return driver_;
  }

  void GetSnapshot(
    const std::vector<std::string>& computed_style_whitelist, 
    bool include_event_listeners, 
    bool include_paint_order, 
    bool include_user_agent_shadow_tree, 
    automation::DOMSnapshot::GetSnapshotCallback callback);

private:

  ApplicationDriver* driver_;

  DISALLOW_COPY_AND_ASSIGN(DOMSnapshotInterface);
};

class CONTENT_EXPORT DOMInterface {
public:
  DOMInterface(ApplicationDriver* driver);
  ~DOMInterface();

  ApplicationDriver* driver() const {
    return driver_;
  }

  void CollectClassNamesFromSubtree(int32_t node_id, automation::DOM::CollectClassNamesFromSubtreeCallback callback);
  void CopyTo(int32_t node_id, int32_t target_node_id, int32_t anchor_node_id, automation::DOM::CopyToCallback callback);
  void DescribeNode(int32_t node_id, int32_t backend_node_id, const base::Optional<std::string>& object_id, int32_t depth, bool pierce, automation::DOM::DescribeNodeCallback callback);
  void Disable();
  void DiscardSearchResults(const std::string& search_id);
  void Enable();
  void Focus(int32_t node_id, int32_t backend_node_id, const base::Optional<std::string>& object_id);
  void GetAttributes(int32_t node_id, automation::DOM::GetAttributesCallback callback);
  void GetBoxModel(int32_t node_id, int32_t backend_node_id, const base::Optional<std::string>& object_id, automation::DOM::GetBoxModelCallback callback);
  void GetDocument(int32_t depth, bool pierce, automation::DOM::GetDocumentCallback callback);
  void GetFlattenedDocument(int32_t depth, bool pierce, automation::DOM::GetFlattenedDocumentCallback callback);
  void GetNodeForLocation(int32_t x, int32_t y, bool include_user_agent_shadow_dom, automation::DOM::GetNodeForLocationCallback callback);
  void GetOuterHTML(int32_t node_id, int32_t backend_node_id, const base::Optional<std::string>& object_id, automation::DOM::GetOuterHTMLCallback callback);
  void GetRelayoutBoundary(int32_t node_id, automation::DOM::GetRelayoutBoundaryCallback callback);
  void GetSearchResults(const std::string& search_id, int32_t from_index, int32_t to_index, automation::DOM::GetSearchResultsCallback callback);
  void HideHighlight();
  void HighlightNode(automation::HighlightConfigPtr highlight_config, int32_t node_id, int32_t backend_node_id, int32_t object_id);
  void HighlightRect(int32_t x, int32_t y, int32_t width, int32_t height, automation::RGBAPtr color, automation::RGBAPtr outline_color);
  void MarkUndoableState();
  void MoveTo(int32_t node_id, int32_t target_node_id, int32_t insert_before_node_id, automation::DOM::MoveToCallback callback);
  void PerformSearch(const std::string& query, bool include_user_agent_shadow_dom, automation::DOM::PerformSearchCallback callback);
  void PushNodeByPathToFrontend(const std::string& path, automation::DOM::PushNodeByPathToFrontendCallback callback);
  void PushNodesByBackendIdsToFrontend(const std::vector<int32_t>& backend_node_ids, automation::DOM::PushNodesByBackendIdsToFrontendCallback callback);
  void QuerySelector(int32_t node_id, const std::string& selector, automation::DOM::QuerySelectorCallback callback);
  void QuerySelectorAll(int32_t node_id, const std::string& selector, automation::DOM::QuerySelectorAllCallback callback);
  void Redo();
  void RemoveAttribute(int32_t node_id, const std::string& name);
  void RemoveNode(int32_t node_id);
  void RequestChildNodes(int32_t node_id, int32_t depth, bool pierce);
  void RequestNode(const std::string& object_id, automation::DOM::RequestNodeCallback callback);
  void ResolveNode(int32_t node_id, const base::Optional<std::string>& object_group, automation::DOM::ResolveNodeCallback callback);
  void SetAttributeValue(int32_t node_id, const std::string& name, const std::string& value);
  void SetAttributesAsText(int32_t node_id, const std::string& text, const base::Optional<std::string>& name);
  void SetFileInputFiles(const std::vector<std::string>& files, int32_t node_id, int32_t backend_node_id, const base::Optional<std::string>& object_id);
  void SetInspectedNode(int32_t node_id);
  void SetNodeName(int32_t node_id, const std::string& name, automation::DOM::SetNodeNameCallback callback);
  void SetNodeValue(int32_t node_id, const std::string& value);
  void SetOuterHTML(int32_t node_id, const std::string& outer_html);
  void Undo();
  void GetFrameOwner(const std::string& frame_id, automation::DOM::GetFrameOwnerCallback callback);

private:

  ApplicationDriver* driver_;

  DISALLOW_COPY_AND_ASSIGN(DOMInterface);
};

class CONTENT_EXPORT CSSInterface {
public:
  CSSInterface(ApplicationDriver* driver);
  ~CSSInterface();

  ApplicationDriver* driver() const {
    return driver_;
  }

  void AddRule(const std::string& style_sheet_id, const std::string& rule_text, automation::SourceRangePtr location, automation::CSS::AddRuleCallback callback);
  void CollectClassNames(const std::string& style_sheet_id, automation::CSS::CollectClassNamesCallback callback);
  void CreateStyleSheet(const std::string& frame_id, automation::CSS::CreateStyleSheetCallback callback);
  void Disable();
  void Enable();
  void ForcePseudoState(int32_t node_id, const std::vector<std::string>& forced_pseudo_classes);
  void GetBackgroundColors(int32_t node_id, automation::CSS::GetBackgroundColorsCallback callback);
  void GetComputedStyleForNode(int32_t node_id, automation::CSS::GetComputedStyleForNodeCallback callback);
  void GetInlineStylesForNode(int32_t node_id, automation::CSS::GetInlineStylesForNodeCallback callback);
  void GetMatchedStylesForNode(int32_t node_id, automation::CSS::GetMatchedStylesForNodeCallback callback);
  void GetMediaQueries(automation::CSS::GetMediaQueriesCallback callback);
  void GetPlatformFontsForNode(int32_t node_id, automation::CSS::GetPlatformFontsForNodeCallback callback);
  void GetStyleSheetText(const std::string& style_sheet_id, automation::CSS::GetStyleSheetTextCallback callback);
  void SetEffectivePropertyValueForNode(int32_t node_id, const std::string& property_name, const std::string& value);
  void SetKeyframeKey(const std::string& style_sheet_id, automation::SourceRangePtr range, const std::string& key_text, automation::CSS::SetKeyframeKeyCallback callback);
  void SetMediaText(const std::string& style_sheet_id, automation::SourceRangePtr range, const std::string& text, automation::CSS::SetMediaTextCallback callback);
  void SetRuleSelector(const std::string& style_sheet_id, automation::SourceRangePtr range, const std::string& selector, automation::CSS::SetRuleSelectorCallback callback);
  void SetStyleSheetText(const std::string& style_sheet_id, const std::string& text, automation::CSS::SetStyleSheetTextCallback callback);
  void SetStyleTexts(std::vector<automation::StyleDeclarationEditPtr> edits, automation::CSS::SetStyleTextsCallback callback);
  void StartRuleUsageTracking();
  void StopRuleUsageTracking(automation::CSS::StopRuleUsageTrackingCallback callback);
  void TakeCoverageDelta(automation::CSS::TakeCoverageDeltaCallback callback);

private:
  
  ApplicationDriver* driver_;

  DISALLOW_COPY_AND_ASSIGN(CSSInterface);
};

class CONTENT_EXPORT CacheStorageInterface {
public:
  CacheStorageInterface(ApplicationDriver* driver);
  ~CacheStorageInterface();

  ApplicationDriver* driver() const {
    return driver_;
  }
  
  void HasCache(const std::string& cache_id, automation::CacheStorage::HasCacheCallback callback);
  void OpenCache(const std::string& cache_id, automation::CacheStorage::OpenCacheCallback callback);
  void DeleteCache(const std::string& cache_id, automation::CacheStorage::DeleteCacheCallback callback);
  void DeleteEntry(const std::string& cache_id, const std::string& request, automation::CacheStorage::DeleteEntryCallback callback);
  void PutEntry(const std::string& cache_id, const std::string& request, blink::mojom::DataElementPtr data, automation::CacheStorage::PutEntryCallback callback);
  void PutEntryBlob(const std::string& cache_id, const std::string& request, blink::mojom::SerializedBlobPtr blob, automation::CacheStorage::PutEntryBlobCallback callback);
  void RequestCacheNames(const std::string& securityOrigin, automation::CacheStorage::RequestCacheNamesCallback callback);
  void RequestCachedResponse(const std::string& cache_id, const std::string& request_url, bool base64_encoded, automation::CacheStorage::RequestCachedResponseCallback callback);
  void RequestEntries(const std::string& cache_id, int32_t skipCount, int32_t pageSize, automation::CacheStorage::RequestEntriesCallback callback);

private:

  ApplicationDriver* driver_;

  DISALLOW_COPY_AND_ASSIGN(CacheStorageInterface);
};

class CONTENT_EXPORT ApplicationCacheInterface {
public:
  ApplicationCacheInterface(ApplicationDriver* driver);
  ~ApplicationCacheInterface();

  ApplicationDriver* driver() const {
    return driver_;
  }

  void Enable();
  void GetApplicationCacheForFrame(const std::string& frameId, automation::ApplicationCacheInterface::GetApplicationCacheForFrameCallback callback);
  void GetFramesWithManifests(automation::ApplicationCacheInterface::GetFramesWithManifestsCallback callback);
  void GetManifestForFrame(const std::string& frame_id, automation::ApplicationCacheInterface::GetManifestForFrameCallback callback);

private:
  
  ApplicationDriver* driver_;

  DISALLOW_COPY_AND_ASSIGN(ApplicationCacheInterface);
};

class CONTENT_EXPORT AnimationInterface {
public:
  AnimationInterface(ApplicationDriver* driver);
  ~AnimationInterface();

  ApplicationDriver* driver() const {
    return driver_;
  }

  void Disable();
  void Enable();
  void GetCurrentTime(const std::string& id, automation::AnimationInterface::GetCurrentTimeCallback callback);
  void GetPlaybackRate(automation::AnimationInterface::GetPlaybackRateCallback callback);
  void ReleaseAnimations(const std::vector<std::string>& animations);
  void ResolveAnimation(const std::string& animation_id, automation::AnimationInterface::ResolveAnimationCallback callback);
  void SeekAnimations(const std::vector<std::string>& animations, int32_t current_time);
  void SetPaused(const std::vector<std::string>& animations, bool paused);
  void SetPlaybackRate(int32_t playback_rate);
  void SetTiming(const std::string& animation_id, int32_t duration, int32_t delay);

private:
  ApplicationDriver* driver_;
  DISALLOW_COPY_AND_ASSIGN(AnimationInterface);
};

class CONTENT_EXPORT AccessibilityInterface {
public:
  AccessibilityInterface(ApplicationDriver* driver);
  ~AccessibilityInterface();

  ApplicationDriver* driver() const {
    return driver_;
  }
  
  void GetPartialAXTree(
    const base::Optional<std::string>& node_id, 
    int32_t backend_node_id, 
    const base::Optional<std::string>& object_id, 
    bool fetch_relatives, 
    automation::Accessibility::GetPartialAXTreeCallback callback);

private:
  ApplicationDriver* driver_;
  DISALLOW_COPY_AND_ASSIGN(AccessibilityInterface);
};

class CONTENT_EXPORT ApplicationDriver : public automation::PageClient,
                                         public automation::OverlayClient,
                                         public automation::ServiceWorkerClient,
                                         public automation::StorageClient,
                                         public automation::TetheringClient,
                                         public automation::NetworkClient,
                                         public automation::LayerTreeClient,
                                         public automation::HeadlessClient,
                                         public automation::DOMStorageClient,
                                         public automation::DatabaseClient,
                                         public automation::EmulationClient,
                                         public automation::DOMClient,
                                         public automation::CSSClient,
                                         public automation::ApplicationCacheClient,
                                         public automation::AnimationClient {
public:
  ApplicationDriver(void* state, Application* application, int instance_id);
  ~ApplicationDriver() override;

  int instance_id() const {
    return instance_id_;
  }

  Application* application() const {
    return application_;
  }

  SystemInfoInterface* system_info() {
    return &system_info_;
  }

  HostInterface* host() {
    return &host_;
  }

  PageInterface* pages() {
    return &pages_;
  }

  OverlayInterface* overlay() {
    return &overlay_;
  }

  WorkerInterface* worker() {
    return &worker_;
  }

  StorageInterface* storage() {
    return &storage_;
  }

  TetheringInterface* tethering() {
    return &tethering_;
  }

  NetworkInterface* network() {
    return &network_;
  }

  LayerTreeInterface* layer_tree() {
    return &layer_tree_;
  }

  InputInterface* input() {
    return &input_;
  }

  IndexedDBInterface* indexed_db() {
    return &indexed_db_;
  }

  IOInterface* io() {
    return &io_;
  }

  HeadlessInterface* headless() {
    return &headless_;
  }

  DOMStorageInterface* dom_storage() {
    return &dom_storage_;
  }

  DatabaseInterface* database() {
    return &database_;
  }

  DeviceOrientationInterface* device_orientation() {
    return &device_orientation_;
  }

  EmulationInterface* emulation() {
    return &emulation_;
  }

  DOMSnapshotInterface* dom_snapshot() {
    return &dom_snapshot_;
  }

  DOMInterface* dom() {
    return &dom_;
  }

  CSSInterface* css() {
    return &css_;
  }

  CacheStorageInterface* cache_storage() {
    return &cache_storage_;
  }

  AnimationInterface* animation() {
    return &animation_;
  }

  AccessibilityInterface* accessibility() {
    return &accessibility_;
  }

  ApplicationCacheInterface* application_cache() {
    return &application_cache_;
  }

  scoped_refptr<base::SingleThreadTaskRunner> io_task_runner() const {
    return io_task_runner_;
  }

  void set_state(void* state);

  void RegisterInterfaces();
  
  void BindAnimationClient(automation::AnimationClientAssociatedRequest request);
  void BindPageClient(automation::PageClientAssociatedRequest request);
  void BindOverlayClient(automation::OverlayClientAssociatedRequest request);
  void BindWorkerClient(automation::ServiceWorkerClientAssociatedRequest request);
  void BindStorageClient(automation::StorageClientAssociatedRequest request);
  void BindNetworkClient(automation::NetworkClientAssociatedRequest request);
  void BindLayerTreeClient(automation::LayerTreeClientAssociatedRequest request);
  void BindHeadlessClient(automation::HeadlessClientAssociatedRequest request);
  void BindDOMStorageClient(automation::DOMStorageClientAssociatedRequest request);
  void BindDatabaseClient(automation::DatabaseClientAssociatedRequest request);
  void BindEmulationClient(automation::EmulationClientAssociatedRequest request);
  void BindDOMClient(automation::DOMClientAssociatedRequest request);
  void BindCSSClient(automation::CSSClientAssociatedRequest request);
  void BindApplicationCacheClient(automation::ApplicationCacheClientAssociatedRequest request);

private:
  friend class SystemInfoInterface;
  friend class HostInterface;
  friend class PageInterface;
  friend class OverlayInterface;
  friend class WorkerInterface;
  friend class StorageInterface;
  friend class TetheringInterface;
  friend class NetworkInterface;
  friend class LayerTreeInterface;
  friend class InputInterface;
  friend class IndexedDBInterface;
  friend class IOInterface;
  friend class HeadlessInterface;
  friend class DOMStorageInterface;
  friend class DatabaseInterface;
  friend class DeviceOrientationInterface;
  friend class EmulationInterface;
  friend class DOMSnapshotInterface;
  friend class DOMInterface;
  friend class CSSInterface;
  friend class CacheStorageInterface;
  friend class ApplicationCacheInterface;
  friend class AnimationInterface;
  friend class AccessibilityInterface;
  
  // PageClient
  void OnFrameAttached(const std::string& frame_id, const std::string& parent_frame_id) override;
  void OnDomContentEventFired(int64_t timestamp) override;
  void OnFrameClearedScheduledNavigation(const std::string& frame_id) override;
  void OnFrameDetached(const std::string& frame_id) override;
  void OnFrameNavigated(automation::FramePtr frame) override;
  void OnFrameResized() override;
  void OnFrameScheduledNavigation(const std::string& frame_id, int32_t delay, automation::NavigationReason reason, const std::string& url) override;;
  void OnFrameStartedLoading(const std::string& frame_id) override;
  void OnFrameStoppedLoading(const std::string& frame_id) override;
  void OnInterstitialHidden() override;
  void OnInterstitialShown() override;
  void OnJavascriptDialogClosed(bool result, const std::string& user_input) override;
  void OnJavascriptDialogOpening(const std::string& url, const std::string& message, automation::DialogType type, bool has_browser_handler, const base::Optional<std::string>& default_prompt) override;
  void OnLifecycleEvent(const std::string& frame_id, int32_t loader_id, const std::string& name, int64_t timestamp) override;
  void OnLoadEventFired(int64_t timestamp) override;
  void OnNavigatedWithinDocument(const std::string& frame_id, const std::string& url) override;
  void OnScreencastFrame(const std::string& base64_data, automation::ScreencastFrameMetadataPtr metadata, int32_t session_id) override;
  void OnScreencastVisibilityChanged(bool visible) override;
  void OnWindowOpen(const std::string& url, const std::string& window_name, const std::vector<std::string>& window_features, bool user_gesture) override;
  void OnPageLayoutInvalidated(bool resized) override;

  // OverlayClient
  void InspectNodeRequested(int32_t backend_node_id) override;
  void NodeHighlightRequested(int32_t node_id) override;
  void ScreenshotRequested(automation::ViewportPtr viewport) override;

  // ServiceWorkerClient
  void WorkerErrorReported(automation::ServiceWorkerErrorMessagePtr error_message) override;
  void WorkerRegistrationUpdated(std::vector<automation::ServiceWorkerRegistrationPtr> registrations) override;
  void WorkerVersionUpdated(std::vector<automation::ServiceWorkerVersionPtr> versions) override;
  void OnAttachedToTarget(const std::string& session_id, automation::TargetInfoPtr target_info, bool waiting_for_debugger) override;
  void OnDetachedFromTarget(const std::string& session_id, const base::Optional<std::string>& target_id) override;
  void OnReceivedMessageFromTarget(const std::string& session_id, const std::string& message, const base::Optional<std::string>& target_id) override;

  // StorageClient
  void OnCacheStorageContentUpdated(const std::string& origin, const std::string& cache_name) override;
  void OnCacheStorageListUpdated(const std::string& origin) override;
  void OnIndexedDBContentUpdated(const std::string& origin, const std::string& database_name, const std::string& object_store_name) override;
  void OnIndexedDBListUpdated(const std::string& origin) override;

  // TetheringClient
  void OnAccepted(int32_t port, const std::string& connection_id) override;
  
  // NetworkClient
  void OnDataReceived(const std::string& request_id, int64_t timestamp, int64_t data_length, int64_t encoded_data_length) override;
  void OnEventSourceMessageReceived(const std::string& request_id, int64_t timestamp, const std::string& event_name, const std::string& event_id, const std::string& data) override;
  void OnLoadingFailed(const std::string& request_id, int64_t timestamp, automation::ResourceType type, const std::string& error_text, bool canceled, automation::BlockedReason blocked_reason) override;
  void OnLoadingFinished(const std::string& request_id, int64_t timestamp, int64_t encoded_data_length, bool blocked_cross_site_document) override;
  void OnRequestIntercepted(const std::string& interceptionId, automation::RequestPtr request, const std::string& frame_id, automation::ResourceType resource_type, bool is_navigation_request, bool is_download, const base::Optional<std::string>& redirect_url, automation::AuthChallengePtr auth_challenge, automation::ErrorReason response_error_reason, int32_t response_status_code, const base::Optional<base::flat_map<std::string, std::string>>& response_headers) override;
  void OnRequestServedFromCache(const std::string& request_id) override;
  void OnRequestWillBeSent(const std::string& request_id, const std::string& loader_id, const std::string& document_url, automation::RequestPtr request, int64_t timestamp, int64_t wall_time, automation::InitiatorPtr initiator, automation::ResponsePtr redirect_response, automation::ResourceType type, const base::Optional<std::string>& frame_id, bool has_user_gesture) override;
  void OnResourceChangedPriority(const std::string& request_id, automation::ResourcePriority new_priority, int64_t timestamp) override;
  void OnResponseReceived(const std::string& request_id, const std::string& loader_id, int64_t timestamp, automation::ResourceType type, automation::ResponsePtr response, const base::Optional<std::string>& frame_id) override;
  void OnWebSocketClosed(const std::string& request_id, int64_t timestamp) override;
  void OnWebSocketCreated(const std::string& request_id, const std::string& url, automation::InitiatorPtr initiator) override;
  void OnWebSocketFrameError(const std::string& request_id, int64_t timestamp, const std::string& error_message) override;
  void OnWebSocketFrameReceived(const std::string& request_id, int64_t timestamp, automation::WebSocketFramePtr response) override;
  void OnWebSocketFrameSent(const std::string& request_id, int64_t timestamp, automation::WebSocketFramePtr response) override;
  void OnWebSocketHandshakeResponseReceived(const std::string& request_id, int64_t timestamp, automation::WebSocketResponsePtr response) override;
  void OnWebSocketWillSendHandshakeRequest(const std::string& request_id, int64_t timestamp, int64_t wall_time, automation::WebSocketRequestPtr request) override;
  void Flush() override;
  
  // LayerTreeClient
  void OnLayerPainted(const std::string& layer_id, const gfx::Rect& clip) override;
  void OnLayerTreeDidChange(base::Optional<std::vector<automation::LayerPtr>> layers) override;

  // HeadlessClient
  void OnNeedsBeginFramesChanged(bool needs_begin_frames) override;

  // DOMStorageClient
  void OnDomStorageItemAdded(automation::StorageIdPtr storage_id, const std::string& key, const std::string& new_value) override;
  void OnDomStorageItemRemoved(automation::StorageIdPtr storage_id, const std::string& key) override;
  void OnDomStorageItemUpdated(automation::StorageIdPtr storage_id, const std::string& key, const std::string& old_value, const std::string& new_value) override;
  void OnDomStorageItemsCleared(automation::StorageIdPtr storage_id) override;

  // DatabaseClient
  void OnAddDatabase(automation::DatabasePtr database) override;

  // EmulationClient
  void OnVirtualTimeAdvanced(int32_t virtual_time_elapsed) override;
  void OnVirtualTimeBudgetExpired() override;
  void OnVirtualTimePaused(int32_t virtual_time_elapsed) override;

  // DOMClient
  void SetChildNodes(int32_t parent_id, std::vector<automation::DOMNodePtr> nodes) override;
  void OnAttributeModified(int32_t node_id, const std::string& name, const std::string& value) override;
  void OnAttributeRemoved(int32_t node_id, const std::string& name) override;
  void OnCharacterDataModified(int32_t node_id, const std::string& character_data) override;
  void OnChildNodeCountUpdated(int32_t node_id, int32_t child_node_count) override;
  void OnChildNodeInserted(int32_t parent_node_id, int32_t previous_node_id, automation::DOMNodePtr node) override;
  void OnChildNodeRemoved(int32_t parent_node_id, int32_t node_id) override;
  void OnDistributedNodesUpdated(int32_t insertion_point_id, std::vector<automation::BackendNodePtr> distributed_nodes) override;
  void OnDocumentUpdated() override;
  void OnInlineStyleInvalidated(const std::vector<int32_t>& node_ids) override;
  void OnPseudoElementAdded(int32_t parent_id, automation::DOMNodePtr pseudo_element) override;
  void OnPseudoElementRemoved(int32_t parent_id, int32_t pseudo_element_id) override;
  void OnShadowRootPopped(int32_t host_id, int32_t root_id) override;
  void OnShadowRootPushed(int32_t host_id, automation::DOMNodePtr root) override;

  // CSSClient
  void OnFontsUpdated(automation::FontFacePtr font) override;
  void OnMediaQueryResultChanged() override;
  void OnStyleSheetAdded(automation::CSSStyleSheetHeaderPtr header) override;
  void OnStyleSheetChanged(const std::string& style_sheet_id) override;
  void OnStyleSheetRemoved(const std::string& style_sheet_id) override;

  // ApplicationCacheClient
  void OnApplicationCacheStatusUpdated(const std::string& frame_id, const std::string& manifest_url, int32_t status) override;
  void OnNetworkStateUpdated(bool is_now_online) override;

  // AnimationClient
  void OnAnimationCanceled(const std::string& id) override;
  void OnAnimationCreated(const std::string& id) override;
  void OnAnimationStarted(automation::AnimationPtr animation) override;

  void BindInterfaces();

  void* state_;
  Application* application_;
  int instance_id_;
  SystemInfoInterface system_info_;
  HostInterface host_;
  PageInterface pages_;
  OverlayInterface overlay_;
  WorkerInterface worker_;
  StorageInterface storage_;
  TetheringInterface tethering_;
  NetworkInterface network_;
  LayerTreeInterface layer_tree_;
  InputInterface input_;
  IndexedDBInterface indexed_db_;
  IOInterface io_;
  HeadlessInterface headless_;
  DOMStorageInterface dom_storage_;
  DatabaseInterface database_;
  DeviceOrientationInterface device_orientation_;
  EmulationInterface emulation_;
  DOMSnapshotInterface dom_snapshot_;
  DOMInterface dom_;
  CSSInterface css_;
  CacheStorageInterface cache_storage_;
  ApplicationCacheInterface application_cache_;
  AnimationInterface animation_;
  AccessibilityInterface accessibility_;

  automation::PageAssociatedPtr page_interface_;
  automation::SystemInfoAssociatedPtr system_info_interface_;
  automation::HostAssociatedPtr host_interface_;
  automation::OverlayAssociatedPtr overlay_interface_;
  automation::ServiceWorkerAssociatedPtr worker_interface_;
  automation::StorageAssociatedPtr storage_interface_;
  automation::TetheringAssociatedPtr tethering_interface_;
  automation::NetworkAssociatedPtr network_interface_;
  automation::LayerTreeAssociatedPtr layer_tree_interface_;
  automation::InputAssociatedPtr input_interface_;
  automation::IndexedDBAssociatedPtr indexed_db_interface_;
  automation::IOAssociatedPtr io_interface_;
  automation::HeadlessAssociatedPtr headless_interface_;
  automation::DOMStorageAssociatedPtr dom_storage_interface_;
  automation::DatabaseInterfaceAssociatedPtr database_interface_;
  automation::DeviceOrientationAssociatedPtr device_orientation_interface_;
  automation::EmulationAssociatedPtr emulation_interface_;
  automation::DOMSnapshotAssociatedPtr dom_snapshot_interface_;
  automation::DOMAssociatedPtr dom_interface_;
  automation::CSSAssociatedPtr css_interface_;
  automation::CacheStorageAssociatedPtr cache_storage_interface_;
  automation::ApplicationCacheInterfaceAssociatedPtr application_cache_interface_;
  automation::AnimationInterfaceAssociatedPtr animation_interface_;
  automation::AccessibilityAssociatedPtr accessibility_interface_;
  
  mojo::AssociatedBinding<automation::PageClient> page_client_binding_;
  mojo::AssociatedBinding<automation::OverlayClient> overlay_client_binding_;
  mojo::AssociatedBinding<automation::ServiceWorkerClient> worker_client_binding_;
  mojo::AssociatedBinding<automation::StorageClient> storage_client_binding_;
  mojo::AssociatedBinding<automation::NetworkClient> network_client_binding_;
  mojo::AssociatedBinding<automation::LayerTreeClient> layer_tree_client_binding_;
  mojo::AssociatedBinding<automation::HeadlessClient> headless_client_binding_;
  mojo::AssociatedBinding<automation::DOMStorageClient> dom_storage_client_binding_;
  mojo::AssociatedBinding<automation::DatabaseClient> database_client_binding_;
  mojo::AssociatedBinding<automation::EmulationClient> emulation_client_binding_;
  mojo::AssociatedBinding<automation::DOMClient> dom_client_binding_;
  mojo::AssociatedBinding<automation::CSSClient> css_client_binding_;
  mojo::AssociatedBinding<automation::ApplicationCacheClient> application_cache_client_binding_;
  mojo::AssociatedBinding<automation::AnimationClient> animation_client_binding_;

  scoped_refptr<base::SingleThreadTaskRunner> io_task_runner_;

  DISALLOW_COPY_AND_ASSIGN(ApplicationDriver);
};

}

#endif