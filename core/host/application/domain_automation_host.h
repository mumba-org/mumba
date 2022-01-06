// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_APPLICATION_DOMAIN_AUTOMATION_HOST_H_
#define MUMBA_HOST_APPLICATION_DOMAIN_AUTOMATION_HOST_H_

#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "base/single_thread_task_runner.h"
#include "core/shared/common/content_export.h"
#include "mojo/public/cpp/bindings/binding_set.h"
#include "core/host/application/automation/application_driver.h"
#include "core/shared/common/mojom/automation.mojom.h"
#include "services/service_manager/public/cpp/binder_registry.h"
#include "mojo/public/cpp/bindings/associated_binding_set.h"
#include "third_party/blink/public/mojom/blob/blob_registry.mojom-blink.h"

namespace IPC {
class ChannelProxy;  
}

namespace host {
class Domain;
class Application;
class ApplicationDriver;
class DomainAutomationHost;

// this guy do the routing from domain <-> (DomainAutomationHost) - host - (ApplicationDriver) <-> application
// Here ApplicationDriver will receive the messages from application and ping back the observers
// we then send this back to domain

// From the point of view of domain process, for each application
// this is the interface it's calling directly
// that will route back to driver on the application
// and call the proper impl on the application process 

class DomainPageImpl : public automation::Page {
public:
  DomainPageImpl(DomainAutomationHost* host);
  ~DomainPageImpl() override;

  void Register(int application_id) override;
  void Enable() override;
  void Disable() override;
  void AddScriptToEvaluateOnNewDocument(const std::string& source, automation::Page::AddScriptToEvaluateOnNewDocumentCallback callback) override;
  void RemoveScriptToEvaluateOnNewDocument(const std::string& identifier) override;
  void SetAutoAttachToCreatedPages(bool auto_attach) override;
  void SetLifecycleEventsEnabled(bool enabled) override;
  void Reload(bool ignore_cache, const std::string& script_to_evaluate_on_load) override;
  void SetAdBlockingEnabled(bool enabled) override;
  void Navigate(const std::string& url, const std::string& referrer, automation::TransitionType transition_type, automation::Page::NavigateCallback callback) override;
  void StopLoading() override;
  void GetNavigationHistory(automation::Page::GetNavigationHistoryCallback callback) override;
  void NavigateToHistoryEntry(int32_t entry_id) override;
  void GetCookies(automation::Page::GetCookiesCallback callback) override;
  void DeleteCookie(const std::string& cookie_name, const std::string& url) override;
  void GetResourceTree(automation::Page::GetResourceTreeCallback callback) override;
  void GetFrameTree(automation::Page::GetFrameTreeCallback callback) override;
  void GetResourceContent(const std::string& frame_id, const std::string& url, automation::Page::GetResourceContentCallback callback) override;
  void SearchInResource(const std::string& frame_id, const std::string& url, const std::string& query, bool case_sensitive, bool is_regex, automation::Page::SearchInResourceCallback callback) override;
  void SetDocumentContent(const std::string& frame_id, const std::string& html) override;
  void SetDeviceMetricsOverride(int32_t width, int32_t height, int32_t device_scale_factor, bool mobile, int32_t scale, int32_t screen_width, int32_t screen_height, int32_t position_x, int32_t position_y, bool dont_set_visible_size, automation::ScreenOrientationPtr screen_orientation, automation::ViewportPtr viewport) override;
  void ClearDeviceMetricsOverride() override;
  void SetGeolocationOverride(int32_t latitude, int32_t longitude, int32_t accuracy) override;
  void ClearGeolocationOverride() override;
  void SetDeviceOrientationOverride(int32_t alpha, int32_t beta, int32_t gamma) override;
  void ClearDeviceOrientationOverride() override;
  void SetTouchEmulationEnabled(bool enabled, const std::string& configuration) override;
  void CaptureScreenshot(automation::FrameFormat format, int32_t quality, automation::ViewportPtr clip, bool from_surface, automation::Page::CaptureScreenshotCallback callback) override;
  void PrintToPDF(bool landscape, bool display_header_footer, bool print_background, float scale, float paper_width, float paper_height, float margin_top, float margin_bottom, float margin_left, float margin_right, const base::Optional<std::string>& page_ranges, bool ignore_invalid_page_ranges, automation::Page::PrintToPDFCallback callback) override;
  void StartScreencast(automation::FrameFormat format, int32_t quality, int32_t max_width, int32_t max_height, int32_t every_nth_frame) override;
  void StopScreencast() override;
  void SetBypassCSP(bool enable) override;
  void ScreencastFrameAck(int32_t session_id) override;
  void HandleJavaScriptDialog(bool accept, const std::string& prompt_text) override;
  void GetAppManifest(automation::Page::GetAppManifestCallback callback) override;
  void RequestAppBanner() override;
  void GetLayoutMetrics(automation::Page::GetLayoutMetricsCallback callback) override;
  void CreateIsolatedWorld(const std::string& frame_id, const base::Optional<std::string>& world_name, bool grant_universal_access, automation::Page::CreateIsolatedWorldCallback callback) override;
  void BringToFront() override;
  void SetDownloadBehavior(const std::string& behavior, const base::Optional<std::string>& download_path) override;
  void Close() override;

private:
 DomainAutomationHost* host_;
 scoped_refptr<ApplicationDriver> driver_;
 int application_id_;
 bool registered_;
 
 DISALLOW_COPY_AND_ASSIGN(DomainPageImpl);
};

class DomainAccessibilityImpl : public automation::Accessibility {
public:
  DomainAccessibilityImpl(DomainAutomationHost* host);
  ~DomainAccessibilityImpl() override;
  
  void Register(int32_t application_id) override;
  void GetPartialAXTree(const base::Optional<std::string>& node_id, int32_t backend_node_id, const base::Optional<std::string>& object_id, bool fetch_relatives, GetPartialAXTreeCallback callback) override;

private:
  DomainAutomationHost* host_;
  scoped_refptr<ApplicationDriver> driver_;
  int application_id_;
  bool registered_;
  
  DISALLOW_COPY_AND_ASSIGN(DomainAccessibilityImpl); 
};

class DomainAnimationImpl : public automation::AnimationInterface {
public:
  DomainAnimationImpl(DomainAutomationHost* host);
  ~DomainAnimationImpl() override;

  void Register(int32_t application_id) override;
  void Disable() override;
  void Enable() override;
  void GetCurrentTime(const std::string& id, GetCurrentTimeCallback callback) override;
  void GetPlaybackRate(GetPlaybackRateCallback callback) override;
  void ReleaseAnimations(const std::vector<std::string>& animations) override;
  void ResolveAnimation(const std::string& animation_id, ResolveAnimationCallback callback) override;
  void SeekAnimations(const std::vector<std::string>& animations, int32_t current_time) override;
  void SetPaused(const std::vector<std::string>& animations, bool paused) override;
  void SetPlaybackRate(int32_t playback_rate) override;
  void SetTiming(const std::string& animation_id, int32_t duration, int32_t delay) override;
  
private:

  DomainAutomationHost* host_;
  scoped_refptr<ApplicationDriver> driver_;
  int application_id_;
  bool registered_;

  DISALLOW_COPY_AND_ASSIGN(DomainAnimationImpl); 
};

class DomainApplicationCacheImpl : public automation::ApplicationCacheInterface {
public:
  DomainApplicationCacheImpl(DomainAutomationHost* host);
  ~DomainApplicationCacheImpl() override;

  void Register(int32_t application_id) override;
  void Enable() override;
  void GetApplicationCacheForFrame(const std::string& frameId, GetApplicationCacheForFrameCallback callback) override;
  void GetFramesWithManifests(GetFramesWithManifestsCallback callback) override;
  void GetManifestForFrame(const std::string& frame_id, GetManifestForFrameCallback callback) override;  
  
private:
  DomainAutomationHost* host_;
  scoped_refptr<ApplicationDriver> driver_;
  int application_id_;
  bool registered_;

  DISALLOW_COPY_AND_ASSIGN(DomainApplicationCacheImpl); 
};

class DomainCacheStorageImpl : public automation::CacheStorage {
public:
  DomainCacheStorageImpl(DomainAutomationHost* host);
  ~DomainCacheStorageImpl() override;

  void Register(int32_t application_id) override;
  void HasCache(const std::string& cache_id, HasCacheCallback callback) override;
  void OpenCache(const std::string& cache_id, OpenCacheCallback callback) override;
  void DeleteCache(const std::string& cache_id, DeleteCacheCallback callback) override;
  void DeleteEntry(const std::string& cache_id, const std::string& request, DeleteEntryCallback callback) override;
  void PutEntry(const std::string& cache_id, const std::string& request, blink::mojom::DataElementPtr data, PutEntryCallback callback) override;
  void PutEntryBlob(const std::string& cache_id, const std::string& request, blink::mojom::SerializedBlobPtr blob, PutEntryBlobCallback callback) override;
  void RequestCacheNames(const std::string& securityOrigin, RequestCacheNamesCallback callback) override;
  void RequestCachedResponse(const std::string& cache_id, const std::string& request_url, bool base64_encoded, RequestCachedResponseCallback callback) override;
  void RequestEntries(const std::string& cache_id, int32_t skipCount, int32_t pageSize, RequestEntriesCallback callback) override;
  
private:
  DomainAutomationHost* host_;
  scoped_refptr<ApplicationDriver> driver_;
  int application_id_;
  bool registered_;

  DISALLOW_COPY_AND_ASSIGN(DomainCacheStorageImpl); 
};

class DomainCSSImpl : public automation::CSS {
public:
  DomainCSSImpl(DomainAutomationHost* host);
  ~DomainCSSImpl() override;

  void Register(int32_t application_id) override;
  void AddRule(const std::string& style_sheet_id, const std::string& rule_text, automation::SourceRangePtr location, AddRuleCallback callback) override;
  void CollectClassNames(const std::string& style_sheet_id, CollectClassNamesCallback callback) override;
  void CreateStyleSheet(const std::string& frame_id, CreateStyleSheetCallback callback) override;
  void Disable() override;
  void Enable() override;
  void ForcePseudoState(int32_t node_id, const std::vector<std::string>& forced_pseudo_classes) override;
  void GetBackgroundColors(int32_t node_id, GetBackgroundColorsCallback callback) override;
  void GetComputedStyleForNode(int32_t node_id, GetComputedStyleForNodeCallback callback) override;
  void GetInlineStylesForNode(int32_t node_id, GetInlineStylesForNodeCallback callback) override;
  void GetMatchedStylesForNode(int32_t node_id, GetMatchedStylesForNodeCallback callback) override;
  void GetMediaQueries(GetMediaQueriesCallback callback) override;
  void GetPlatformFontsForNode(int32_t node_id, GetPlatformFontsForNodeCallback callback) override;
  void GetStyleSheetText(const std::string& style_sheet_id, GetStyleSheetTextCallback callback) override;
  void SetEffectivePropertyValueForNode(int32_t node_id, const std::string& property_name, const std::string& value) override;
  void SetKeyframeKey(const std::string& style_sheet_id, automation::SourceRangePtr range, const std::string& key_text, SetKeyframeKeyCallback callback) override;
  void SetMediaText(const std::string& style_sheet_id, automation::SourceRangePtr range, const std::string& text, SetMediaTextCallback callback) override;
  void SetRuleSelector(const std::string& style_sheet_id, automation::SourceRangePtr range, const std::string& selector, SetRuleSelectorCallback callback) override;
  void SetStyleSheetText(const std::string& style_sheet_id, const std::string& text, SetStyleSheetTextCallback callback) override;
  void SetStyleTexts(std::vector<automation::StyleDeclarationEditPtr> edits, SetStyleTextsCallback callback) override;
  void StartRuleUsageTracking() override;
  void StopRuleUsageTracking(StopRuleUsageTrackingCallback callback) override;
  void TakeCoverageDelta(TakeCoverageDeltaCallback callback) override;

private:
  DomainAutomationHost* host_;
  scoped_refptr<ApplicationDriver> driver_;
  int application_id_;
  bool registered_;

  DISALLOW_COPY_AND_ASSIGN(DomainCSSImpl); 
};

class DomainDatabaseImpl : public automation::DatabaseInterface {
public:
  DomainDatabaseImpl(DomainAutomationHost* host);
  ~DomainDatabaseImpl() override;

  void Register(int32_t application_id) override;
  void Disable() override;
  void Enable() override;
  void ExecuteSQL(const std::string& database_id, const std::string& query, ExecuteSQLCallback callback) override;
  void GetDatabaseTableNames(const std::string& database_id, GetDatabaseTableNamesCallback callback) override;

private:
  
  DomainAutomationHost* host_;
  scoped_refptr<ApplicationDriver> driver_;
  int application_id_;
  bool registered_;

  DISALLOW_COPY_AND_ASSIGN(DomainDatabaseImpl); 
};

class DomainDeviceOrientationImpl : public automation::DeviceOrientation {
public:
  DomainDeviceOrientationImpl(DomainAutomationHost* host);
  ~DomainDeviceOrientationImpl() override;

  void Register(int32_t application_id) override;
  void ClearDeviceOrientationOverride() override;
  void SetDeviceOrientationOverride(int32_t alpha, int32_t beta, int32_t gamma) override;

private:
  DomainAutomationHost* host_;
  scoped_refptr<ApplicationDriver> driver_;
  int application_id_;
  bool registered_;
  
  DISALLOW_COPY_AND_ASSIGN(DomainDeviceOrientationImpl); 
};

class DomainDOMImpl : public automation::DOM {
public:
  DomainDOMImpl(DomainAutomationHost* host);
  ~DomainDOMImpl() override;

  void Register(int32_t application_id) override;
  void CollectClassNamesFromSubtree(int32_t node_id, CollectClassNamesFromSubtreeCallback callback) override;
  void CopyTo(int32_t node_id, int32_t target_node_id, int32_t anchor_node_id, CopyToCallback callback) override;
  void DescribeNode(int32_t node_id, int32_t backend_node_id, const base::Optional<std::string>& object_id, int32_t depth, bool pierce, DescribeNodeCallback callback) override;
  void Disable() override;
  void DiscardSearchResults(const std::string& search_id) override;
  void Enable() override;
  void Focus(int32_t node_id, int32_t backend_node_id, const base::Optional<std::string>& object_id) override;
  void GetAttributes(int32_t node_id, GetAttributesCallback callback) override;
  void GetBoxModel(int32_t node_id, int32_t backend_node_id, const base::Optional<std::string>& object_id, GetBoxModelCallback callback) override;
  void GetDocument(int32_t depth, bool pierce, GetDocumentCallback callback) override;
  void GetFlattenedDocument(int32_t depth, bool pierce, GetFlattenedDocumentCallback callback) override;
  void GetNodeForLocation(int32_t x, int32_t y, bool include_user_agent_shadow_dom, GetNodeForLocationCallback callback) override;
  void GetOuterHTML(int32_t node_id, int32_t backend_node_id, const base::Optional<std::string>& object_id, GetOuterHTMLCallback callback) override;
  void GetRelayoutBoundary(int32_t node_id, GetRelayoutBoundaryCallback callback) override;
  void GetSearchResults(const std::string& search_id, int32_t from_index, int32_t to_index, GetSearchResultsCallback callback) override;
  void HideHighlight() override;
  void HighlightNode(automation::HighlightConfigPtr highlight_config, int32_t node_id, int32_t backend_node_id, int32_t object_id) override;
  void HighlightRect(int32_t x, int32_t y, int32_t width, int32_t height, automation::RGBAPtr color, automation::RGBAPtr outline_color) override;
  void MarkUndoableState() override;
  void MoveTo(int32_t node_id, int32_t target_node_id, int32_t insert_before_node_id, MoveToCallback callback) override;
  void PerformSearch(const std::string& query, bool include_user_agent_shadow_dom, PerformSearchCallback callback) override;
  void PushNodeByPathToFrontend(const std::string& path, PushNodeByPathToFrontendCallback callback) override;
  void PushNodesByBackendIdsToFrontend(const std::vector<int32_t>& backend_node_ids, PushNodesByBackendIdsToFrontendCallback callback) override;
  void QuerySelector(int32_t node_id, const std::string& selector, QuerySelectorCallback callback) override;
  void QuerySelectorAll(int32_t node_id, const std::string& selector, QuerySelectorAllCallback callback) override;
  void Redo() override;
  void RemoveAttribute(int32_t node_id, const std::string& name) override;
  void RemoveNode(int32_t node_id) override;
  void RequestChildNodes(int32_t node_id, int32_t depth, bool pierce) override;
  void RequestNode(const std::string& object_id, RequestNodeCallback callback) override;
  void ResolveNode(int32_t node_id, const base::Optional<std::string>& object_group, ResolveNodeCallback callback) override;
  void SetAttributeValue(int32_t node_id, const std::string& name, const std::string& value) override;
  void SetAttributesAsText(int32_t node_id, const std::string& text, const base::Optional<std::string>& name) override;
  void SetFileInputFiles(const std::vector<std::string>& files, int32_t node_id, int32_t backend_node_id, const base::Optional<std::string>& object_id) override;
  void SetInspectedNode(int32_t node_id) override;
  void SetNodeName(int32_t node_id, const std::string& name, SetNodeNameCallback callback) override;
  void SetNodeValue(int32_t node_id, const std::string& value) override;
  void SetOuterHTML(int32_t node_id, const std::string& outer_html) override;
  void Undo() override;
  void GetFrameOwner(const std::string& frame_id, GetFrameOwnerCallback callback) override;

private:
  DomainAutomationHost* host_;
  scoped_refptr<ApplicationDriver> driver_;
  int application_id_;
  bool registered_;
  
  DISALLOW_COPY_AND_ASSIGN(DomainDOMImpl); 
};

class DomainDOMSnapshotImpl : public automation::DOMSnapshot {
public:
  DomainDOMSnapshotImpl(DomainAutomationHost* host);
  ~DomainDOMSnapshotImpl() override;

  void Register(int32_t application_id) override;
  void GetSnapshot(const std::vector<std::string>& computed_style_whitelist, bool include_event_listeners, bool include_paint_order, bool include_user_agent_shadow_tree, GetSnapshotCallback callback) override;

private:
  
  DomainAutomationHost* host_;
  scoped_refptr<ApplicationDriver> driver_;
  int application_id_;
  bool registered_;
  
  DISALLOW_COPY_AND_ASSIGN(DomainDOMSnapshotImpl); 
};


class DomainDOMStorageImpl : public automation::DOMStorage {
public:
  DomainDOMStorageImpl(DomainAutomationHost* host);
  ~DomainDOMStorageImpl() override;

  void Register(int32_t application_id) override;
  void Clear(automation::StorageIdPtr storage_id) override;
  void Disable() override;
  void Enable() override;
  void GetDOMStorageItems(automation::StorageIdPtr storageId, GetDOMStorageItemsCallback callback) override;
  void RemoveDOMStorageItem(automation::StorageIdPtr storage_id, const std::string& key) override;
  void SetDOMStorageItem(automation::StorageIdPtr storageId, const std::string& key, const std::string& value) override;
  
private:
  DomainAutomationHost* host_;
  scoped_refptr<ApplicationDriver> driver_;
  int application_id_;
  bool registered_;

  DISALLOW_COPY_AND_ASSIGN(DomainDOMStorageImpl); 
};

class DomainEmulationImpl : public automation::Emulation {
public:
  DomainEmulationImpl(DomainAutomationHost* host);
  ~DomainEmulationImpl() override;

  void Register(int32_t application_id) override;
  void CanEmulate(CanEmulateCallback callback) override;
  void ClearDeviceMetricsOverride() override;
  void ClearGeolocationOverride() override;
  void ResetPageScaleFactor() override;
  void SetCPUThrottlingRate(int32_t rate) override;
  void SetDefaultBackgroundColorOverride(automation::RGBAPtr color) override;
  void SetDeviceMetricsOverride(int32_t width, int32_t height, float device_scale_factor, bool mobile, float scale, int32_t screen_width, int32_t screen_height, int32_t position_x, int32_t position_y, bool dont_set_visible_size, automation::ScreenOrientationPtr screen_orientation, automation::ViewportPtr viewport) override;
  void SetEmitTouchEventsForMouse(bool enabled, automation::TouchEventForMouseConfiguration configuration) override;
  void SetEmulatedMedia(const std::string& media) override;
  void SetGeolocationOverride(int64_t latitude, int64_t longitude, int64_t accuracy) override;
  void SetNavigatorOverrides(const std::string& platform) override;
  void SetPageScaleFactor(float page_scale_factor) override;
  void SetScriptExecutionDisabled(bool value) override;
  void SetTouchEmulationEnabled(bool enabled, int32_t max_touch_points) override;
  void SetVirtualTimePolicy(automation::VirtualTimePolicy policy, int32_t budget, int32_t max_virtual_time_task_starvation_count, bool wait_for_navigation, SetVirtualTimePolicyCallback callback) override;
  void SetVisibleSize(int32_t width, int32_t height) override;
  
private:
  
  DomainAutomationHost* host_;
  scoped_refptr<ApplicationDriver> driver_;
  int application_id_;
  bool registered_;

  DISALLOW_COPY_AND_ASSIGN(DomainEmulationImpl); 
};

class DomainHeadlessImpl : public automation::Headless {
public:
  DomainHeadlessImpl(DomainAutomationHost* host);
  ~DomainHeadlessImpl() override;

  void Register(int32_t application_id) override;
  void BeginFrame(int64_t frame_time, int32_t frame_time_ticks, int64_t deadline, int32_t deadline_ticks, int32_t interval, bool no_display_updates, automation::ScreenshotParamsPtr screenshot, BeginFrameCallback callback) override;
  void EnterDeterministicMode(int32_t initial_date) override;
  void Disable() override;
  void Enable() override;
  
private:
  DomainAutomationHost* host_;
  scoped_refptr<ApplicationDriver> driver_;
  int application_id_;
  bool registered_;
  
  DISALLOW_COPY_AND_ASSIGN(DomainHeadlessImpl); 
};

class DomainHostImpl : public automation::Host {
public:
  DomainHostImpl(DomainAutomationHost* host);
  ~DomainHostImpl() override;

  void Register(int32_t application_id) override;
  void Close() override;
  void GetVersion(GetVersionCallback callback) override;
  void GetHostCommandLine(GetHostCommandLineCallback callback) override;
  void GetHistograms(const base::Optional<std::string>& query, GetHistogramsCallback callback) override;
  void GetHistogram(const std::string& name, GetHistogramCallback callback) override;
  void GetWindowBounds(int32_t window_id, GetWindowBoundsCallback callback) override;
  void GetWindowForTarget(const std::string& target_id, GetWindowForTargetCallback callback) override;
  void SetWindowBounds(int32_t window_id, automation::BoundsPtr bounds) override;
  
private:
  DomainAutomationHost* host_;
  scoped_refptr<ApplicationDriver> driver_;
  int application_id_;
  bool registered_;

  DISALLOW_COPY_AND_ASSIGN(DomainHostImpl); 
};

class DomainIndexedDBImpl : public automation::IndexedDB {
public:
  DomainIndexedDBImpl(DomainAutomationHost* host);
  ~DomainIndexedDBImpl() override;

  void Register(int32_t application_id) override;
  void ClearObjectStore(const std::string& security_origin, const std::string& database_name, const std::string& object_store_name, ClearObjectStoreCallback callback) override;
  void DeleteDatabase(const std::string& security_origin, const std::string& database_name, DeleteDatabaseCallback callback) override;
  void DeleteObjectStoreEntries(const std::string& security_origin, const std::string& database_name, const std::string& object_store_name, automation::KeyRangePtr keyRange, DeleteObjectStoreEntriesCallback callback) override;
  void Disable() override;
  void Enable() override;
  void RequestData(const std::string& security_origin, const std::string& database_name, const std::string& object_store_name, const std::string& index_name, int32_t skip_count, int32_t page_size, automation::KeyRangePtr key_range, RequestDataCallback callback) override;
  void RequestDatabase(const std::string& security_origin, const std::string& database_name, RequestDatabaseCallback callback) override;
  void RequestDatabaseNames(const std::string& security_origin, RequestDatabaseNamesCallback callback) override;

private:
  DomainAutomationHost* host_;
  scoped_refptr<ApplicationDriver> driver_;
  int application_id_;
  bool registered_;

  DISALLOW_COPY_AND_ASSIGN(DomainIndexedDBImpl); 
};

class DomainInputImpl : public automation::Input {
public:
  DomainInputImpl(DomainAutomationHost* host);
  ~DomainInputImpl() override;

  void Register(int32_t application_id) override;
  void DispatchKeyEvent(automation::KeyEventType type, int32_t modifiers, int64_t timestamp, const base::Optional<std::string>& text, const base::Optional<std::string>& unmodified_text, const base::Optional<std::string>& key_identifier, const base::Optional<std::string>& code, const base::Optional<std::string>& key, int32_t windows_virtual_key_code, int32_t native_virtual_key_code, bool auto_repeat, bool is_keypad, bool is_system_key, int32_t location, DispatchKeyEventCallback callback) override;
  void DispatchMouseEvent(automation::MouseEventType type, int32_t x, int32_t y, int32_t modifiers, int64_t timestamp, automation::MouseButton button, int32_t click_count, int32_t delta_x, int32_t delta_y, DispatchMouseEventCallback callback) override;
  void DispatchTouchEvent(automation::TouchEventType type, std::vector<automation::TouchPointPtr> touch_points, int32_t modifiers, int64_t timestamp, DispatchTouchEventCallback callback) override;
  void EmulateTouchFromMouseEvent(automation::MouseEventType type, int32_t x, int32_t y, automation::MouseButton button, int64_t timestamp, int32_t delta_x, int32_t delta_y, int32_t modifiers, int32_t click_count, EmulateTouchFromMouseEventCallback callback) override;
  void SetIgnoreInputEvents(bool ignore) override;
  void SynthesizePinchGesture(int32_t x, int32_t y, int32_t scale_factor, int32_t relative_speed, automation::GestureSourceType gesture_source_type, SynthesizePinchGestureCallback callback) override;
  void SynthesizeScrollGesture(int32_t x, int32_t y, int32_t x_distance, int32_t y_distance, int32_t x_overscroll, int32_t y_overscroll, bool prevent_fling, int32_t speed, automation::GestureSourceType gesture_source_type, int32_t repeat_count, int32_t repeat_delay_ms, const base::Optional<std::string>& interaction_marker_name, SynthesizeScrollGestureCallback callback) override;
  void SynthesizeTapGesture(int32_t x, int32_t y, int32_t duration, int32_t tap_count, automation::GestureSourceType gesture_source_type, SynthesizeTapGestureCallback callback) override;

private:

  DomainAutomationHost* host_;
  scoped_refptr<ApplicationDriver> driver_;
  int application_id_;
  bool registered_;

  DISALLOW_COPY_AND_ASSIGN(DomainInputImpl); 
};

class DomainIOImpl : public automation::IO {
public:
  DomainIOImpl(DomainAutomationHost* host);
  ~DomainIOImpl() override;

  void Register(int32_t application_id) override;
  void Close(const std::string& handl) override;
  void Read(const std::string& handl, int32_t offset, int32_t size, ReadCallback callback) override;
  void ResolveBlob(const std::string& object_id, ResolveBlobCallback callback) override;
  
private:
  DomainAutomationHost* host_;
  scoped_refptr<ApplicationDriver> driver_;
  int application_id_;
  bool registered_;

  DISALLOW_COPY_AND_ASSIGN(DomainIOImpl); 
};

class DomainLayerTreeImpl : public automation::LayerTree {
public:
  DomainLayerTreeImpl(DomainAutomationHost* host);
  ~DomainLayerTreeImpl() override;

  void Register(int32_t application_id) override;
  void CompositingReasons(const std::string& layer_id, CompositingReasonsCallback callback) override;
  void Disable() override;
  void Enable() override;
  void LoadSnapshot(std::vector<automation::PictureTilePtr> tiles, LoadSnapshotCallback callback) override;
  void MakeSnapshot(const std::string& layer_id, MakeSnapshotCallback callback) override;
  void ProfileSnapshot(const std::string& snapshot_id, int32_t min_repeat_count, int32_t min_duration, const base::Optional<gfx::Rect>& clip_rect, ProfileSnapshotCallback callback) override;
  void ReleaseSnapshot(const std::string& snapshot_id) override;
  void ReplaySnapshot(const std::string& snapshot_id, int32_t from_step, int32_t to_step, int32_t scale, ReplaySnapshotCallback callback) override;
  void SnapshotCommandLog(const std::string& snapshot_id, SnapshotCommandLogCallback callback) override;

private:
  DomainAutomationHost* host_;
  scoped_refptr<ApplicationDriver> driver_;
  int application_id_;
  bool registered_;

  DISALLOW_COPY_AND_ASSIGN(DomainLayerTreeImpl);
};

class DomainNetworkImpl : public automation::Network {
public:
  DomainNetworkImpl(DomainAutomationHost* host);
  ~DomainNetworkImpl() override;

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
  
private:
  DomainAutomationHost* host_;
  scoped_refptr<ApplicationDriver> driver_;
  int application_id_;
  bool registered_;

  DISALLOW_COPY_AND_ASSIGN(DomainNetworkImpl); 
};

class DomainOverlayImpl : public automation::Overlay {
public:
  DomainOverlayImpl(DomainAutomationHost* host);
  ~DomainOverlayImpl() override;

  void Register(int32_t application_id) override;
  void Disable() override;
  void Enable() override;
  void HideHighlight() override;
  void HighlightFrame(const std::string& frame_id, automation::RGBAPtr content_color, automation::RGBAPtr content_outline_color) override;
  void HighlightNode(automation::HighlightConfigPtr highlight_config, int32_t node_id, int32_t backend_node_id, const base::Optional<std::string>& object_id) override;
  void HighlightQuad(const std::vector<double>& quad, automation::RGBAPtr color, automation::RGBAPtr outline_color) override;
  void HighlightRect(int32_t x, int32_t y, int32_t width, int32_t height, automation::RGBAPtr color, automation::RGBAPtr outline_color) override;
  void SetInspectMode(automation::InspectMode mode, automation::HighlightConfigPtr highlight_config) override;
  void SetPausedInDebuggerMessage(const base::Optional<std::string>& message) override;
  void SetShowDebugBorders(bool show) override;
  void SetShowFPSCounter(bool show) override;
  void SetShowPaintRects(bool result) override;
  void SetShowScrollBottleneckRects(bool show) override;
  void SetShowViewportSizeOnResize(bool show) override;
  void SetSuspended(bool suspended) override;
  
private:
  DomainAutomationHost* host_;
  scoped_refptr<ApplicationDriver> driver_;
  int application_id_;
  bool registered_;

  DISALLOW_COPY_AND_ASSIGN(DomainOverlayImpl); 
};

class DomainWorkerImpl : public automation::ServiceWorker {
public:
  DomainWorkerImpl(DomainAutomationHost* host);
  ~DomainWorkerImpl() override;

  void Register(int32_t application_id) override;
  void DeliverPushMessage(const std::string& origin, const std::string& registration_id, const std::string& data) override;
  void Disable() override;
  void DispatchSyncEvent(const std::string& origin, const std::string& registration_id, const std::string& tag, bool last_chance) override;
  void Enable() override;
  void InspectWorker(const std::string& version_id) override;
  void SetForceUpdateOnPageLoad(bool force_update_on_pageload) override;
  void SkipWaiting(const std::string& scope_url) override;
  void StartWorker(const std::string& scope_url) override;
  void StopAllWorkers() override;
  void StopWorker(const std::string& version_id) override;
  void Unregister(const std::string& scope_url) override;
  void UpdateRegistration(const std::string& scope_url) override;
  void SendMessageToTarget(const std::string& message,
                           const base::Optional<std::string>& session_id,
                           const base::Optional<std::string>& target_id) override;
private:

  DomainAutomationHost* host_;
  scoped_refptr<ApplicationDriver> driver_;
  int application_id_;
  bool registered_;

  DISALLOW_COPY_AND_ASSIGN(DomainWorkerImpl); 
};

class DomainStorageImpl : public automation::Storage {
public:
  DomainStorageImpl(DomainAutomationHost* host);
  ~DomainStorageImpl() override;

  void Register(int32_t application_id) override;
  void ClearDataForOrigin(const std::string& origin, const std::vector<automation::StorageType>& storage_types) override;
  void GetUsageAndQuota(const std::string& origin, int64_t usage, int64_t quota, std::vector<automation::UsageForTypePtr> usage_breakdown) override;
  void TrackCacheStorageForOrigin(const std::string& origin) override;
  void TrackIndexedDBForOrigin(const std::string& origin) override;
  void UntrackCacheStorageForOrigin(const std::string& origin) override;
  void UntrackIndexedDBForOrigin(const std::string& origin) override;

public:
  DomainAutomationHost* host_;
  scoped_refptr<ApplicationDriver> driver_;
  int application_id_;
  bool registered_;

  DISALLOW_COPY_AND_ASSIGN(DomainStorageImpl); 
};

class DomainSystemInfoImpl : public automation::SystemInfo {
public:
  DomainSystemInfoImpl(DomainAutomationHost* host);
  ~DomainSystemInfoImpl() override;

  // SystemInfo
  void Register(int32_t application_id) override;
  void GetInfo(GetInfoCallback callback) override;

private:
  DomainAutomationHost* host_;
  scoped_refptr<ApplicationDriver> driver_;
  int application_id_;
  bool registered_;

  DISALLOW_COPY_AND_ASSIGN(DomainSystemInfoImpl); 
};

class DomainTetheringImpl : public automation::Tethering {
public:
  DomainTetheringImpl(DomainAutomationHost* host);
  ~DomainTetheringImpl() override;

  void Register(int32_t application_id) override;
  void Bind(int32_t port) override;
  void Unbind(int32_t port) override;

private:
  DomainAutomationHost* host_;
  scoped_refptr<ApplicationDriver> driver_;
  int application_id_;
  bool registered_;

  DISALLOW_COPY_AND_ASSIGN(DomainTetheringImpl); 
};

class DomainAutomationHost : public ApplicationDriver::Observer {
public:
  DomainAutomationHost(Domain* domain);
  ~DomainAutomationHost() override;

  Domain* domain() const {
    return domain_;
  }

  void OnFrameAttached(const std::string& frame_id, const std::string& parent_frame_id) override;
  void OnDomContentEventFired(int64_t timestamp) override;
  void OnFrameClearedScheduledNavigation(const std::string& frame_id) override;
  void OnFrameDetached(const std::string& frame_id) override;
  void OnFrameNavigated(automation::FramePtr frame) override;
  void OnFrameResized() override;
  void OnFrameScheduledNavigation(const std::string& frame_id, int32_t delay, automation::NavigationReason reason, const std::string& url) override;
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
  void InspectNodeRequested(int32_t backend_node_id) override;
  void NodeHighlightRequested(int32_t node_id) override;
  void ScreenshotRequested(automation::ViewportPtr viewport) override;
  void WorkerErrorReported(automation::ServiceWorkerErrorMessagePtr error_message) override;
  void WorkerRegistrationUpdated(std::vector<automation::ServiceWorkerRegistrationPtr> registrations) override;
  void WorkerVersionUpdated(std::vector<automation::ServiceWorkerVersionPtr> versions) override;
  void OnAttachedToTarget(const std::string& session_id, automation::TargetInfoPtr target_info, bool waiting_for_debugger) override;
  void OnDetachedFromTarget(const std::string& session_id, const base::Optional<std::string>& target_id) override;
  void OnReceivedMessageFromTarget(const std::string& session_id, const std::string& message, const base::Optional<std::string>& target_id) override;
  void OnCacheStorageContentUpdated(const std::string& origin, const std::string& cache_name) override;
  void OnCacheStorageListUpdated(const std::string& origin) override;
  void OnIndexedDBContentUpdated(const std::string& origin, const std::string& database_name, const std::string& object_store_name) override;
  void OnIndexedDBListUpdated(const std::string& origin) override;
  void OnAccepted(int32_t port, const std::string& connection_id) override;
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
  void OnLayerPainted(const std::string& layer_id, const gfx::Rect& clip) override;
  void OnLayerTreeDidChange(base::Optional<std::vector<automation::LayerPtr>> layers) override;
  void OnNeedsBeginFramesChanged(bool needs_begin_frames) override;
  void OnDomStorageItemAdded(automation::StorageIdPtr storage_id, const std::string& key, const std::string& new_value) override;
  void OnDomStorageItemRemoved(automation::StorageIdPtr storage_id, const std::string& key) override;
  void OnDomStorageItemUpdated(automation::StorageIdPtr storage_id, const std::string& key, const std::string& old_value, const std::string& new_value) override;
  void OnDomStorageItemsCleared(automation::StorageIdPtr storage_id) override; 
  void OnAddDatabase(automation::DatabasePtr database) override;
  void OnVirtualTimeAdvanced(int32_t virtual_time_elapsed) override;
  void OnVirtualTimeBudgetExpired() override;
  void OnVirtualTimePaused(int32_t virtual_time_elapsed) override;
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
  void OnFontsUpdated(automation::FontFacePtr font) override;
  void OnMediaQueryResultChanged() override;
  void OnStyleSheetAdded(automation::CSSStyleSheetHeaderPtr header) override;
  void OnStyleSheetChanged(const std::string& style_sheet_id) override;
  void OnStyleSheetRemoved(const std::string& style_sheet_id) override;
  void OnApplicationCacheStatusUpdated(const std::string& frame_id, const std::string& manifest_url, int32_t status) override;
  void OnNetworkStateUpdated(bool is_now_online) override;
  void OnAnimationCanceled(const std::string& id) override;
  void OnAnimationCreated(const std::string& id) override;
  void OnAnimationStarted(automation::AnimationPtr animation) override;

  void AddPageBinding(automation::PageAssociatedRequest request);
  void AddAccessibilityBinding(automation::AccessibilityAssociatedRequest request);
  void AddAnimationBinding(automation::AnimationInterfaceAssociatedRequest request);
  void AddApplicationCacheBinding(automation::ApplicationCacheInterfaceAssociatedRequest request);
  void AddCacheStorageBinding(automation::CacheStorageAssociatedRequest request);
  void AddCSSBinding(automation::CSSAssociatedRequest request);
  void AddDatabaseBinding(automation::DatabaseInterfaceAssociatedRequest request);
  void AddDeviceOrientationBinding(automation::DeviceOrientationAssociatedRequest request);
  void AddDOMBinding(automation::DOMAssociatedRequest request);
  void AddDOMSnapshotBinding(automation::DOMSnapshotAssociatedRequest request);
  void AddDOMStorageBinding(automation::DOMStorageAssociatedRequest request);
  void AddEmulationBinding(automation::EmulationAssociatedRequest request);
  void AddHeadlessBinding(automation::HeadlessAssociatedRequest request);
  void AddHostBinding(automation::HostAssociatedRequest request);
  void AddIndexedDBBinding(automation::IndexedDBAssociatedRequest request);
  void AddInputBinding(automation::InputAssociatedRequest request);
  void AddIOBinding(automation::IOAssociatedRequest request);
  void AddLayerTreeBinding(automation::LayerTreeAssociatedRequest request);
  void AddNetworkBinding(automation::NetworkAssociatedRequest request);
  void AddOverlayBinding(automation::OverlayAssociatedRequest request);
  void AddServiceWorkerBinding(automation::ServiceWorkerAssociatedRequest request);
  void AddStorageBinding(automation::StorageAssociatedRequest request);
  void AddSystemInfoBinding(automation::SystemInfoAssociatedRequest request);
  void AddTetheringBinding(automation::TetheringAssociatedRequest request);

  void MaybeObserve(scoped_refptr<ApplicationDriver> driver);

  void BindClientInterfaces(int id, IPC::ChannelProxy* channel);

private: 

  void OnFrameAttachedImpl(const std::string& frame_id, const std::string& parent_frame_id);
  void OnDomContentEventFiredImpl(int64_t timestamp);
  void OnFrameClearedScheduledNavigationImpl(const std::string& frame_id);
  void OnFrameDetachedImpl(const std::string& frame_id);
  void OnFrameNavigatedImpl(automation::FramePtr frame);
  void OnFrameResizedImpl();
  void OnFrameScheduledNavigationImpl(const std::string& frame_id, int32_t delay, automation::NavigationReason reason, const std::string& url);
  void OnFrameStartedLoadingImpl(const std::string& frame_id);
  void OnFrameStoppedLoadingImpl(const std::string& frame_id);
  void OnInterstitialHiddenImpl();
  void OnInterstitialShownImpl();
  void OnJavascriptDialogClosedImpl(bool result, const std::string& user_input);
  void OnJavascriptDialogOpeningImpl(const std::string& url, const std::string& message, automation::DialogType type, bool has_browser_handler, const base::Optional<std::string>& default_prompt);
  void OnLifecycleEventImpl(const std::string& frame_id, int32_t loader_id, const std::string& name, int64_t timestamp);
  void OnLoadEventFiredImpl(int64_t timestamp);
  void OnNavigatedWithinDocumentImpl(const std::string& frame_id, const std::string& url);
  void OnScreencastFrameImpl(const std::string& base64_data, automation::ScreencastFrameMetadataPtr metadata, int32_t session_id);
  void OnScreencastVisibilityChangedImpl(bool visible);
  void OnWindowOpenImpl(const std::string& url, const std::string& window_name, const std::vector<std::string>& window_features, bool user_gesture);
  void OnPageLayoutInvalidatedImpl(bool resized);
  void InspectNodeRequestedImpl(int32_t backend_node_id);
  void NodeHighlightRequestedImpl(int32_t node_id);
  void ScreenshotRequestedImpl(automation::ViewportPtr viewport);
  void WorkerErrorReportedImpl(automation::ServiceWorkerErrorMessagePtr error_message);
  void WorkerRegistrationUpdatedImpl(std::vector<automation::ServiceWorkerRegistrationPtr> registrations);
  void WorkerVersionUpdatedImpl(std::vector<automation::ServiceWorkerVersionPtr> versions);
  void OnAttachedToTargetImpl(const std::string& session_id, automation::TargetInfoPtr target_info, bool waiting_for_debugger);
  void OnDetachedFromTargetImpl(const std::string& session_id, const base::Optional<std::string>& target_id);
  void OnReceivedMessageFromTargetImpl(const std::string& session_id, const std::string& message, const base::Optional<std::string>& target_id);
  void OnCacheStorageContentUpdatedImpl(const std::string& origin, const std::string& cache_name);
  void OnCacheStorageListUpdatedImpl(const std::string& origin);
  void OnIndexedDBContentUpdatedImpl(const std::string& origin, const std::string& database_name, const std::string& object_store_name);
  void OnIndexedDBListUpdatedImpl(const std::string& origin);
  void OnAcceptedImpl(int32_t port, const std::string& connection_id);
  void OnDataReceivedImpl(const std::string& request_id, int64_t timestamp, int64_t data_length, int64_t encoded_data_length);
  void OnEventSourceMessageReceivedImpl(const std::string& request_id, int64_t timestamp, const std::string& event_name, const std::string& event_id, const std::string& data);
  void OnLoadingFailedImpl(const std::string& request_id, int64_t timestamp, automation::ResourceType type, const std::string& error_text, bool canceled, automation::BlockedReason blocked_reason);
  void OnLoadingFinishedImpl(const std::string& request_id, int64_t timestamp, int64_t encoded_data_length, bool blocked_cross_site_document);
  void OnRequestInterceptedImpl(const std::string& interceptionId, automation::RequestPtr request, const std::string& frame_id, automation::ResourceType resource_type, bool is_navigation_request, bool is_download, const base::Optional<std::string>& redirect_url, automation::AuthChallengePtr auth_challenge, automation::ErrorReason response_error_reason, int32_t response_status_code, const base::Optional<base::flat_map<std::string, std::string>>& response_headers);
  void OnRequestServedFromCacheImpl(const std::string& request_id);
  void OnRequestWillBeSentImpl(const std::string& request_id, const std::string& loader_id, const std::string& document_url, automation::RequestPtr request, int64_t timestamp, int64_t wall_time, automation::InitiatorPtr initiator, automation::ResponsePtr redirect_response, automation::ResourceType type, const base::Optional<std::string>& frame_id, bool has_user_gesture);
  void OnResourceChangedPriorityImpl(const std::string& request_id, automation::ResourcePriority new_priority, int64_t timestamp);
  void OnResponseReceivedImpl(const std::string& request_id, const std::string& loader_id, int64_t timestamp, automation::ResourceType type, automation::ResponsePtr response, const base::Optional<std::string>& frame_id);
  void OnWebSocketClosedImpl(const std::string& request_id, int64_t timestamp);
  void OnWebSocketCreatedImpl(const std::string& request_id, const std::string& url, automation::InitiatorPtr initiator);
  void OnWebSocketFrameErrorImpl(const std::string& request_id, int64_t timestamp, const std::string& error_message);
  void OnWebSocketFrameReceivedImpl(const std::string& request_id, int64_t timestamp, automation::WebSocketFramePtr response);
  void OnWebSocketFrameSentImpl(const std::string& request_id, int64_t timestamp, automation::WebSocketFramePtr response);
  void OnWebSocketHandshakeResponseReceivedImpl(const std::string& request_id, int64_t timestamp, automation::WebSocketResponsePtr response);
  void OnWebSocketWillSendHandshakeRequestImpl(const std::string& request_id, int64_t timestamp, int64_t wall_time, automation::WebSocketRequestPtr request);
  void FlushImpl();
  void OnLayerPaintedImpl(const std::string& layer_id, const gfx::Rect& clip);
  void OnLayerTreeDidChangeImpl(base::Optional<std::vector<automation::LayerPtr>> layers);
  void OnNeedsBeginFramesChangedImpl(bool needs_begin_frames);
  void OnDomStorageItemAddedImpl(automation::StorageIdPtr storage_id, const std::string& key, const std::string& new_value);
  void OnDomStorageItemRemovedImpl(automation::StorageIdPtr storage_id, const std::string& key);
  void OnDomStorageItemUpdatedImpl(automation::StorageIdPtr storage_id, const std::string& key, const std::string& old_value, const std::string& new_value);
  void OnDomStorageItemsClearedImpl(automation::StorageIdPtr storage_id); 
  void OnAddDatabaseImpl(automation::DatabasePtr database);
  void OnVirtualTimeAdvancedImpl(int32_t virtual_time_elapsed);
  void OnVirtualTimeBudgetExpiredImpl();
  void OnVirtualTimePausedImpl(int32_t virtual_time_elapsed);
  void SetChildNodesImpl(int32_t parent_id, std::vector<automation::DOMNodePtr> nodes);
  void OnAttributeModifiedImpl(int32_t node_id, const std::string& name, const std::string& value);
  void OnAttributeRemovedImpl(int32_t node_id, const std::string& name);
  void OnCharacterDataModifiedImpl(int32_t node_id, const std::string& character_data);
  void OnChildNodeCountUpdatedImpl(int32_t node_id, int32_t child_node_count);
  void OnChildNodeInsertedImpl(int32_t parent_node_id, int32_t previous_node_id, automation::DOMNodePtr node);
  void OnChildNodeRemovedImpl(int32_t parent_node_id, int32_t node_id);
  void OnDistributedNodesUpdatedImpl(int32_t insertion_point_id, std::vector<automation::BackendNodePtr> distributed_nodes);
  void OnDocumentUpdatedImpl();
  void OnInlineStyleInvalidatedImpl(const std::vector<int32_t>& node_ids);
  void OnPseudoElementAddedImpl(int32_t parent_id, automation::DOMNodePtr pseudo_element);
  void OnPseudoElementRemovedImpl(int32_t parent_id, int32_t pseudo_element_id);
  void OnShadowRootPoppedImpl(int32_t host_id, int32_t root_id);
  void OnShadowRootPushedImpl(int32_t host_id, automation::DOMNodePtr root);
  void OnFontsUpdatedImpl(automation::FontFacePtr font);
  void OnMediaQueryResultChangedImpl();
  void OnStyleSheetAddedImpl(automation::CSSStyleSheetHeaderPtr header);
  void OnStyleSheetChangedImpl(const std::string& style_sheet_id);
  void OnStyleSheetRemovedImpl(const std::string& style_sheet_id);
  void OnApplicationCacheStatusUpdatedImpl(const std::string& frame_id, const std::string& manifest_url, int32_t status);
  void OnNetworkStateUpdatedImpl(bool is_now_online);
  void OnAnimationCanceledImpl(const std::string& id);
  void OnAnimationCreatedImpl(const std::string& id);
  void OnAnimationStartedImpl(automation::AnimationPtr animation);

  Domain* domain_;

  std::vector<std::unique_ptr<DomainPageImpl>> pages_;
  std::vector<std::unique_ptr<DomainAccessibilityImpl>> accessibilities_;
  std::vector<std::unique_ptr<DomainAnimationImpl>> animations_;
  std::vector<std::unique_ptr<DomainApplicationCacheImpl>> app_caches_;
  std::vector<std::unique_ptr<DomainCacheStorageImpl>> cache_storages_;
  std::vector<std::unique_ptr<DomainCSSImpl>> css_;
  std::vector<std::unique_ptr<DomainDatabaseImpl>> databases_;
  std::vector<std::unique_ptr<DomainDeviceOrientationImpl>> device_orientations_;
  std::vector<std::unique_ptr<DomainDOMImpl>> doms_;
  std::vector<std::unique_ptr<DomainDOMSnapshotImpl>> dom_snapshots_;
  std::vector<std::unique_ptr<DomainDOMStorageImpl>> dom_storages_;
  std::vector<std::unique_ptr<DomainEmulationImpl>> emulations_;
  std::vector<std::unique_ptr<DomainHeadlessImpl>> headless_;
  std::vector<std::unique_ptr<DomainHostImpl>> hosts_;
  std::vector<std::unique_ptr<DomainIndexedDBImpl>> indexed_dbs_;
  std::vector<std::unique_ptr<DomainInputImpl>> inputs_;
  std::vector<std::unique_ptr<DomainIOImpl>> ios_;
  std::vector<std::unique_ptr<DomainLayerTreeImpl>> layer_trees_;
  std::vector<std::unique_ptr<DomainNetworkImpl>> networks_;
  std::vector<std::unique_ptr<DomainOverlayImpl>> overlays_;
  std::vector<std::unique_ptr<DomainWorkerImpl>> workers_;
  std::vector<std::unique_ptr<DomainStorageImpl>> storages_;
  std::vector<std::unique_ptr<DomainSystemInfoImpl>> systems_;
  std::vector<std::unique_ptr<DomainTetheringImpl>> tetherings_;

  // keep a list of already observed ApplicationDriver 's
  std::vector<scoped_refptr<ApplicationDriver>> observed_;

  mojo::AssociatedBindingSet<automation::Page> page_bindings_;
  mojo::AssociatedBindingSet<automation::SystemInfo> system_info_bindings_;
  mojo::AssociatedBindingSet<automation::Host> host_bindings_;
  mojo::AssociatedBindingSet<automation::Overlay> overlay_bindings_;
  mojo::AssociatedBindingSet<automation::ServiceWorker> service_worker_bindings_;
  mojo::AssociatedBindingSet<automation::Storage> storage_bindings_;
  mojo::AssociatedBindingSet<automation::Tethering> tethering_bindings_;
  mojo::AssociatedBindingSet<automation::Network> network_bindings_;
  mojo::AssociatedBindingSet<automation::LayerTree> layer_tree_bindings_;
  mojo::AssociatedBindingSet<automation::Input> input_bindings_;
  mojo::AssociatedBindingSet<automation::IndexedDB> indexed_db_bindings_;
  mojo::AssociatedBindingSet<automation::IO> io_bindings_;
  mojo::AssociatedBindingSet<automation::Headless> headless_bindings_;
  mojo::AssociatedBindingSet<automation::DOMStorage> dom_storage_bindings_;
  mojo::AssociatedBindingSet<automation::DatabaseInterface> database_bindings_;
  mojo::AssociatedBindingSet<automation::DeviceOrientation> device_orientation_bindings_;
  mojo::AssociatedBindingSet<automation::Emulation> emulation_bindings_;
  mojo::AssociatedBindingSet<automation::DOMSnapshot> dom_snapshot_bindings_;
  mojo::AssociatedBindingSet<automation::DOM> dom_bindings_;
  mojo::AssociatedBindingSet<automation::CSS> css_bindings_;
  mojo::AssociatedBindingSet<automation::CacheStorage> cache_storage_bindings_;
  mojo::AssociatedBindingSet<automation::ApplicationCacheInterface> application_cache_bindings_;
  mojo::AssociatedBindingSet<automation::AnimationInterface> animation_bindings_;
  mojo::AssociatedBindingSet<automation::Accessibility> accessibility_bindings_;

  automation::PageClientAssociatedPtr page_client_;
  automation::OverlayClientAssociatedPtr overlay_client_;
  automation::ServiceWorkerClientAssociatedPtr service_worker_client_;
  automation::StorageClientAssociatedPtr storage_client_;
  automation::TetheringClientAssociatedPtr tethering_client_;
  automation::NetworkClientAssociatedPtr network_client_;
  automation::LayerTreeClientAssociatedPtr layer_tree_;
  automation::HeadlessClientAssociatedPtr headless_client_;
  automation::DOMStorageClientAssociatedPtr dom_storage_client_;
  automation::DatabaseClientAssociatedPtr database_client_;
  automation::EmulationClientAssociatedPtr emulation_client_;
  automation::DOMClientAssociatedPtr dom_client_;
  automation::CSSClientAssociatedPtr css_client_;
  automation::ApplicationCacheClientAssociatedPtr application_cache_client_; 
  automation::AnimationClientAssociatedPtr animation_client_;
  

  DISALLOW_COPY_AND_ASSIGN(DomainAutomationHost);
};

}

#endif
