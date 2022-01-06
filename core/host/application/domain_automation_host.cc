// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/application/domain_automation_host.h"

#include "core/host/application/domain.h"
#include "core/host/application/application.h"
#include "core/host/application/automation/application_driver.h"
#include "core/host/host_thread.h"
#include "ipc/ipc_channel.h"

namespace host {

DomainPageImpl::DomainPageImpl(DomainAutomationHost* host): 
  host_(host),
  driver_(nullptr),
  application_id_(-1),
  registered_(false) {

}

DomainPageImpl::~DomainPageImpl() {

}

void DomainPageImpl::Register(int application_id) {
  application_id_ = application_id;
  Application* application = host_->domain()->GetApplication(application_id);
  DCHECK(application->application_driver());
  driver_ = application->application_driver();
  //DLOG(INFO) << "DomainPageImpl::Register: " << application_id << " application = " << application << " driver = " << driver_;
  host_->MaybeObserve(driver_);
  driver_->pages()->Register(application_id);
  registered_ = true;
}

void DomainPageImpl::Enable() {
  //DLOG(INFO) << "DomainPageImpl::Enable";
  driver_->pages()->Enable();
}

void DomainPageImpl::Disable() {
  driver_->pages()->Disable();
}

void DomainPageImpl::AddScriptToEvaluateOnNewDocument(const std::string& source, automation::Page::AddScriptToEvaluateOnNewDocumentCallback callback) {
  driver_->pages()->AddScriptToEvaluateOnNewDocument(source, std::move(callback));
}

void DomainPageImpl::RemoveScriptToEvaluateOnNewDocument(const std::string& identifier) {
  driver_->pages()->RemoveScriptToEvaluateOnNewDocument(identifier);
}

void DomainPageImpl::SetAutoAttachToCreatedPages(bool auto_attach) {
  driver_->pages()->SetAutoAttachToCreatedPages(auto_attach);
}

void DomainPageImpl::SetLifecycleEventsEnabled(bool enabled) {
  driver_->pages()->SetLifecycleEventsEnabled(enabled);
}

void DomainPageImpl::Reload(bool ignore_cache, const std::string& script_to_evaluate_on_load) {
  driver_->pages()->Reload(ignore_cache, script_to_evaluate_on_load);
}

void DomainPageImpl::SetAdBlockingEnabled(bool enabled) {
  driver_->pages()->SetAdBlockingEnabled(enabled);
}

void DomainPageImpl::Navigate(const std::string& url, const std::string& referrer, automation::TransitionType transition_type, automation::Page::NavigateCallback callback) {
  driver_->pages()->Navigate(url, referrer, transition_type, std::move(callback));
}

void DomainPageImpl::StopLoading() {
  driver_->pages()->StopLoading();
}

void DomainPageImpl::GetNavigationHistory(automation::Page::GetNavigationHistoryCallback callback) {
  driver_->pages()->GetNavigationHistory(std::move(callback));
}

void DomainPageImpl::NavigateToHistoryEntry(int32_t entry_id) {
  driver_->pages()->NavigateToHistoryEntry(entry_id);
}

void DomainPageImpl::GetCookies(automation::Page::GetCookiesCallback callback) {
  driver_->pages()->GetCookies(std::move(callback));
}

void DomainPageImpl::DeleteCookie(const std::string& cookie_name, const std::string& url) {
  driver_->pages()->DeleteCookie(cookie_name, url);
}

void DomainPageImpl::GetResourceTree(automation::Page::GetResourceTreeCallback callback) {
  //DLOG(INFO) << "DomainPageImpl::GetResourceTree: driver_ = " << driver_.get();
  driver_->pages()->GetResourceTree(std::move(callback));
}

void DomainPageImpl::GetFrameTree(automation::Page::GetFrameTreeCallback callback) {
  //DLOG(INFO) << "DomainPageImpl::GetFrameTree: this = " << this << " driver_ = " << driver_.get();
  driver_->pages()->GetFrameTree(std::move(callback));
}

void DomainPageImpl::GetResourceContent(const std::string& frame_id, const std::string& url, automation::Page::GetResourceContentCallback callback) {
  driver_->pages()->GetResourceContent(frame_id, url, std::move(callback));
}

void DomainPageImpl::SearchInResource(const std::string& frame_id, const std::string& url, const std::string& query, bool case_sensitive, bool is_regex, automation::Page::SearchInResourceCallback callback) {
  driver_->pages()->SearchInResource(frame_id, url, query, case_sensitive, is_regex, std::move(callback));
}

void DomainPageImpl::SetDocumentContent(const std::string& frame_id, const std::string& html) {
  driver_->pages()->SetDocumentContent(frame_id, html);
}

void DomainPageImpl::SetDeviceMetricsOverride(int32_t width, int32_t height, int32_t device_scale_factor, bool mobile, int32_t scale, int32_t screen_width, int32_t screen_height, int32_t position_x, int32_t position_y, bool dont_set_visible_size, automation::ScreenOrientationPtr screen_orientation, automation::ViewportPtr viewport) {
  driver_->pages()->SetDeviceMetricsOverride(width, height, device_scale_factor, mobile, scale, screen_width, screen_height, position_x, position_y, dont_set_visible_size, std::move(screen_orientation), std::move(viewport));
}

void DomainPageImpl::ClearDeviceMetricsOverride() {
  driver_->pages()->ClearDeviceMetricsOverride();
}

void DomainPageImpl::SetGeolocationOverride(int32_t latitude, int32_t longitude, int32_t accuracy) {
  driver_->pages()->SetGeolocationOverride(latitude, longitude, accuracy);
}

void DomainPageImpl::ClearGeolocationOverride() {
  driver_->pages()->ClearGeolocationOverride();
}

void DomainPageImpl::SetDeviceOrientationOverride(int32_t alpha, int32_t beta, int32_t gamma) {
  driver_->pages()->SetDeviceOrientationOverride(alpha, beta, gamma);
}

void DomainPageImpl::ClearDeviceOrientationOverride() {
  driver_->pages()->ClearDeviceOrientationOverride();
}

void DomainPageImpl::SetTouchEmulationEnabled(bool enabled, const std::string& configuration) {
  driver_->pages()->SetTouchEmulationEnabled(enabled, configuration);
}

void DomainPageImpl::CaptureScreenshot(automation::FrameFormat format, int32_t quality, automation::ViewportPtr clip, bool from_surface, automation::Page::CaptureScreenshotCallback callback) {
  driver_->pages()->CaptureScreenshot(format, quality, std::move(clip), from_surface, std::move(callback));
}

void DomainPageImpl::PrintToPDF(bool landscape, bool display_header_footer, bool print_background, float scale, float paper_width, float paper_height, float margin_top, float margin_bottom, float margin_left, float margin_right, const base::Optional<std::string>& page_ranges, bool ignore_invalid_page_ranges, automation::Page::PrintToPDFCallback callback) {
  driver_->pages()->PrintToPDF(landscape, display_header_footer, print_background, scale, paper_width, paper_height, margin_top, margin_bottom, margin_left, margin_right, page_ranges, ignore_invalid_page_ranges, std::move(callback));
}

void DomainPageImpl::StartScreencast(automation::FrameFormat format, int32_t quality, int32_t max_width, int32_t max_height, int32_t every_nth_frame) {
  driver_->pages()->StartScreencast(format, quality, max_width, max_height, every_nth_frame);
}

void DomainPageImpl::StopScreencast() {
  driver_->pages()->StopScreencast();
}

void DomainPageImpl::SetBypassCSP(bool enable) {
  driver_->pages()->SetBypassCSP(enable);
}

void DomainPageImpl::ScreencastFrameAck(int32_t session_id) {
  driver_->pages()->ScreencastFrameAck(session_id);
}

void DomainPageImpl::HandleJavaScriptDialog(bool accept, const std::string& prompt_text) {
  driver_->pages()->HandleJavaScriptDialog(accept, prompt_text);
}

void DomainPageImpl::GetAppManifest(automation::Page::GetAppManifestCallback callback) {
  driver_->pages()->GetAppManifest(std::move(callback));
}

void DomainPageImpl::RequestAppBanner() {
  driver_->pages()->RequestAppBanner();
}

void DomainPageImpl::GetLayoutMetrics(automation::Page::GetLayoutMetricsCallback callback) {
  driver_->pages()->GetLayoutMetrics(std::move(callback));
}

void DomainPageImpl::CreateIsolatedWorld(const std::string& frame_id, const base::Optional<std::string>& world_name, bool grant_universal_access, automation::Page::CreateIsolatedWorldCallback callback) {
  driver_->pages()->CreateIsolatedWorld(frame_id, world_name, grant_universal_access, std::move(callback));
}

void DomainPageImpl::BringToFront() {
  driver_->pages()->BringToFront();
}

void DomainPageImpl::SetDownloadBehavior(const std::string& behavior, const base::Optional<std::string>& download_path) {
  driver_->pages()->SetDownloadBehavior(behavior, download_path);
}

void DomainPageImpl::Close() {
  driver_->pages()->Close();
}

DomainAccessibilityImpl::DomainAccessibilityImpl(DomainAutomationHost* host): host_(host) {
  
}

DomainAccessibilityImpl::~DomainAccessibilityImpl() {

}
  
void DomainAccessibilityImpl::Register(int32_t application_id) {
  //DLOG(INFO) << "DomainAccessibilityImpl::Register: " << application_id;
  application_id_ = application_id;
  Application* application = host_->domain()->GetApplication(application_id);
  DCHECK(application);
  driver_ = application->application_driver();
  host_->MaybeObserve(driver_);
  driver_->accessibility()->Register(application_id);
  registered_ = true;
}

void DomainAccessibilityImpl::GetPartialAXTree(const base::Optional<std::string>& node_id, int32_t backend_node_id, const base::Optional<std::string>& object_id, bool fetch_relatives, GetPartialAXTreeCallback callback) {
  driver_->accessibility()->GetPartialAXTree(node_id, backend_node_id, object_id, fetch_relatives, std::move(callback));
}

DomainAnimationImpl::DomainAnimationImpl(DomainAutomationHost* host): host_(host) {

}

DomainAnimationImpl::~DomainAnimationImpl() {

}

void DomainAnimationImpl::Register(int32_t application_id) {
  //DLOG(INFO) << "DomainAnimationImpl::Register: " << application_id;
  application_id_ = application_id;
  Application* application = host_->domain()->GetApplication(application_id);
  DCHECK(application);
  driver_ = application->application_driver();
  host_->MaybeObserve(driver_);
  driver_->animation()->Register(application_id);
  registered_ = true;
}

void DomainAnimationImpl::Disable() {
  driver_->animation()->Disable();
}

void DomainAnimationImpl::Enable() {
  //DLOG(INFO) << "DomainAnimationImpl::Enable (host process)";
  driver_->animation()->Enable();
}

void DomainAnimationImpl::GetCurrentTime(const std::string& id, GetCurrentTimeCallback callback) {
  driver_->animation()->GetCurrentTime(id, std::move(callback));
}

void DomainAnimationImpl::GetPlaybackRate(GetPlaybackRateCallback callback) {
  driver_->animation()->GetPlaybackRate(std::move(callback));
}

void DomainAnimationImpl::ReleaseAnimations(const std::vector<std::string>& animations) {
  driver_->animation()->ReleaseAnimations(animations);
}

void DomainAnimationImpl::ResolveAnimation(const std::string& animation_id, ResolveAnimationCallback callback) {
  driver_->animation()->ResolveAnimation(animation_id, std::move(callback));
}

void DomainAnimationImpl::SeekAnimations(const std::vector<std::string>& animations, int32_t current_time) {
  driver_->animation()->SeekAnimations(animations, current_time);
}

void DomainAnimationImpl::SetPaused(const std::vector<std::string>& animations, bool paused) {
  driver_->animation()->SetPaused(animations, paused);
}

void DomainAnimationImpl::SetPlaybackRate(int32_t playback_rate) {
  driver_->animation()->SetPlaybackRate(playback_rate);
}

void DomainAnimationImpl::SetTiming(const std::string& animation_id, int32_t duration, int32_t delay) {
  driver_->animation()->SetTiming(animation_id, duration, delay);
}

DomainApplicationCacheImpl::DomainApplicationCacheImpl(DomainAutomationHost* host): host_(host) {

}

DomainApplicationCacheImpl::~DomainApplicationCacheImpl() {

}

void DomainApplicationCacheImpl::Register(int32_t application_id) {
  //DLOG(INFO) << "DomainApplicationCacheImpl::Register: " << application_id;
  application_id_ = application_id;
  Application* application = host_->domain()->GetApplication(application_id);
  DCHECK(application);
  driver_ = application->application_driver();
  host_->MaybeObserve(driver_);
  driver_->application_cache()->Register(application_id);
  registered_ = true;
}

void DomainApplicationCacheImpl::Enable() {
  //DLOG(INFO) << "DomainApplicationCacheImpl::Enable (host process)";
  driver_->application_cache()->Enable();
}  

void DomainApplicationCacheImpl::GetApplicationCacheForFrame(const std::string& frame_id, GetApplicationCacheForFrameCallback callback) {
  driver_->application_cache()->GetApplicationCacheForFrame(frame_id, std::move(callback));
}

void DomainApplicationCacheImpl::GetFramesWithManifests(GetFramesWithManifestsCallback callback) {
  driver_->application_cache()->GetFramesWithManifests(std::move(callback));
}

void DomainApplicationCacheImpl::GetManifestForFrame(const std::string& frame_id, GetManifestForFrameCallback callback) {
  driver_->application_cache()->GetManifestForFrame(frame_id, std::move(callback));
}

DomainCacheStorageImpl::DomainCacheStorageImpl(DomainAutomationHost* host): host_(host) {

}

DomainCacheStorageImpl::~DomainCacheStorageImpl() {

}

void DomainCacheStorageImpl::Register(int32_t application_id) {
  DLOG(INFO) << "DomainCacheStorageImpl::Register: this = " << this << " app_id = " << application_id;
  application_id_ = application_id;
  Application* application = host_->domain()->GetApplication(application_id);
  DCHECK(application);
  driver_ = application->application_driver();
  host_->MaybeObserve(driver_);
  driver_->cache_storage()->Register(application_id);
  registered_ = true;
}

void DomainCacheStorageImpl::HasCache(const std::string& cache_id, HasCacheCallback callback) {
  driver_->cache_storage()->HasCache(cache_id, std::move(callback));
}

void DomainCacheStorageImpl::OpenCache(const std::string& cache_id, OpenCacheCallback callback) {
  DLOG(INFO) << "DomainCacheStorageImpl::OpenCache: this = " << this;
  driver_->cache_storage()->OpenCache(cache_id, std::move(callback));
}

void DomainCacheStorageImpl::DeleteCache(const std::string& cache_id, DeleteCacheCallback callback) {
  driver_->cache_storage()->DeleteCache(cache_id, std::move(callback));
}

void DomainCacheStorageImpl::DeleteEntry(const std::string& cache_id, const std::string& request, DeleteEntryCallback callback) {
  driver_->cache_storage()->DeleteEntry(cache_id, request, std::move(callback));
}

void DomainCacheStorageImpl::PutEntry(const std::string& cache_id, const std::string& request, blink::mojom::DataElementPtr data, PutEntryCallback callback) {
  ////DLOG(INFO) << "DomainCacheStorageImpl::PutEntryData: [" << data.size() << "] '" << std::string(data.begin()[0], data.size()) << "'";
  driver_->cache_storage()->PutEntry(cache_id, request, std::move(data), std::move(callback));
}

void DomainCacheStorageImpl::PutEntryBlob(const std::string& cache_id, const std::string& request, blink::mojom::SerializedBlobPtr blob, PutEntryBlobCallback callback) {
  driver_->cache_storage()->PutEntryBlob(cache_id, request, std::move(blob), std::move(callback));
}

void DomainCacheStorageImpl::RequestCacheNames(const std::string& security_origin, RequestCacheNamesCallback callback) {
  driver_->cache_storage()->RequestCacheNames(security_origin, std::move(callback));
}

void DomainCacheStorageImpl::RequestCachedResponse(const std::string& cache_id, const std::string& request_url, bool base64_encoded, RequestCachedResponseCallback callback) {
  driver_->cache_storage()->RequestCachedResponse(cache_id, request_url, base64_encoded, std::move(callback));
}

void DomainCacheStorageImpl::RequestEntries(const std::string& cache_id, int32_t skip_count, int32_t page_size, RequestEntriesCallback callback) {
  driver_->cache_storage()->RequestEntries(cache_id, skip_count, page_size, std::move(callback));
}

DomainCSSImpl::DomainCSSImpl(DomainAutomationHost* host): host_(host) {

}

DomainCSSImpl::~DomainCSSImpl() {

}

void DomainCSSImpl::Register(int32_t application_id) {
  //DLOG(INFO) << "DomainCSSImpl::Register: " << application_id;
  application_id_ = application_id;
  Application* application = host_->domain()->GetApplication(application_id);
  DCHECK(application);
  driver_ = application->application_driver();
  host_->MaybeObserve(driver_);
  driver_->css()->Register(application_id);
  registered_ = true;
}

void DomainCSSImpl::AddRule(const std::string& style_sheet_id, const std::string& rule_text, automation::SourceRangePtr location, AddRuleCallback callback) {
  driver_->css()->AddRule(style_sheet_id, rule_text, std::move(location), std::move(callback));
}

void DomainCSSImpl::CollectClassNames(const std::string& style_sheet_id, CollectClassNamesCallback callback) {
  driver_->css()->CollectClassNames(style_sheet_id, std::move(callback));
}

void DomainCSSImpl::CreateStyleSheet(const std::string& frame_id, CreateStyleSheetCallback callback) {
  driver_->css()->CreateStyleSheet(frame_id, std::move(callback));
}

void DomainCSSImpl::Disable() {
  driver_->css()->Disable();
}

void DomainCSSImpl::Enable() {
  //DLOG(INFO) << "DomainCSSImpl::Enable (host process)";
  driver_->css()->Enable();
}

void DomainCSSImpl::ForcePseudoState(int32_t node_id, const std::vector<std::string>& forced_pseudo_classes) {
  driver_->css()->ForcePseudoState(node_id, forced_pseudo_classes);
}

void DomainCSSImpl::GetBackgroundColors(int32_t node_id, GetBackgroundColorsCallback callback) {
  driver_->css()->GetBackgroundColors(node_id, std::move(callback));
}

void DomainCSSImpl::GetComputedStyleForNode(int32_t node_id, GetComputedStyleForNodeCallback callback) {
  driver_->css()->GetComputedStyleForNode(node_id, std::move(callback));
}

void DomainCSSImpl::GetInlineStylesForNode(int32_t node_id, GetInlineStylesForNodeCallback callback) {
  driver_->css()->GetInlineStylesForNode(node_id, std::move(callback));
}

void DomainCSSImpl::GetMatchedStylesForNode(int32_t node_id, GetMatchedStylesForNodeCallback callback) {
  driver_->css()->GetMatchedStylesForNode(node_id, std::move(callback));
}

void DomainCSSImpl::GetMediaQueries(GetMediaQueriesCallback callback) {
  driver_->css()->GetMediaQueries(std::move(callback));
}

void DomainCSSImpl::GetPlatformFontsForNode(int32_t node_id, GetPlatformFontsForNodeCallback callback) {
  driver_->css()->GetPlatformFontsForNode(node_id, std::move(callback));
}

void DomainCSSImpl::GetStyleSheetText(const std::string& style_sheet_id, GetStyleSheetTextCallback callback) {
  driver_->css()->GetStyleSheetText(style_sheet_id, std::move(callback));
}

void DomainCSSImpl::SetEffectivePropertyValueForNode(int32_t node_id, const std::string& property_name, const std::string& value) {
  driver_->css()->SetEffectivePropertyValueForNode(node_id, property_name, value);
}

void DomainCSSImpl::SetKeyframeKey(const std::string& style_sheet_id, automation::SourceRangePtr range, const std::string& key_text, SetKeyframeKeyCallback callback) {
  driver_->css()->SetKeyframeKey(style_sheet_id, std::move(range), key_text, std::move(callback));
}

void DomainCSSImpl::SetMediaText(const std::string& style_sheet_id, automation::SourceRangePtr range, const std::string& text, SetMediaTextCallback callback) {
  driver_->css()->SetMediaText(style_sheet_id, std::move(range), text, std::move(callback));
}

void DomainCSSImpl::SetRuleSelector(const std::string& style_sheet_id, automation::SourceRangePtr range, const std::string& selector, SetRuleSelectorCallback callback) {
  driver_->css()->SetRuleSelector(style_sheet_id, std::move(range), selector, std::move(callback));
}

void DomainCSSImpl::SetStyleSheetText(const std::string& style_sheet_id, const std::string& text, SetStyleSheetTextCallback callback) {
  driver_->css()->SetStyleSheetText(style_sheet_id, text, std::move(callback));
}

void DomainCSSImpl::SetStyleTexts(std::vector<automation::StyleDeclarationEditPtr> edits, SetStyleTextsCallback callback) {
  driver_->css()->SetStyleTexts(std::move(edits), std::move(callback));
}

void DomainCSSImpl::StartRuleUsageTracking() {
  driver_->css()->StartRuleUsageTracking();
}

void DomainCSSImpl::StopRuleUsageTracking(StopRuleUsageTrackingCallback callback) {
  driver_->css()->StopRuleUsageTracking(std::move(callback));
}

void DomainCSSImpl::TakeCoverageDelta(TakeCoverageDeltaCallback callback) {
  driver_->css()->TakeCoverageDelta(std::move(callback));
}

DomainDatabaseImpl::DomainDatabaseImpl(DomainAutomationHost* host): host_(host) {

}

DomainDatabaseImpl::~DomainDatabaseImpl() {

}

void DomainDatabaseImpl::Register(int32_t application_id) {
  //DLOG(INFO) << "DomainDatabaseImpl::Register: " << application_id;
  application_id_ = application_id;
  Application* application = host_->domain()->GetApplication(application_id);
  DCHECK(application);
  driver_ = application->application_driver();
  host_->MaybeObserve(driver_);
  driver_->database()->Register(application_id);
  registered_ = true;
}

void DomainDatabaseImpl::Disable() {
  driver_->database()->Disable();
}

void DomainDatabaseImpl::Enable() {
  driver_->database()->Enable();
}

void DomainDatabaseImpl::ExecuteSQL(const std::string& database_id, const std::string& query, ExecuteSQLCallback callback) {
  driver_->database()->ExecuteSQL(database_id, query, std::move(callback));
}

void DomainDatabaseImpl::GetDatabaseTableNames(const std::string& database_id, GetDatabaseTableNamesCallback callback) {
  driver_->database()->GetDatabaseTableNames(database_id, std::move(callback));
}

DomainDeviceOrientationImpl::DomainDeviceOrientationImpl(DomainAutomationHost* host): host_(host) {

}

DomainDeviceOrientationImpl::~DomainDeviceOrientationImpl() {

}

void DomainDeviceOrientationImpl::Register(int32_t application_id) {
  //DLOG(INFO) << "DomainDeviceOrientationImpl::Register: " << application_id;
  application_id_ = application_id;
  Application* application = host_->domain()->GetApplication(application_id);
  DCHECK(application);
  driver_ = application->application_driver();
  host_->MaybeObserve(driver_);
  driver_->device_orientation()->Register(application_id);
  registered_ = true;
}

void DomainDeviceOrientationImpl::ClearDeviceOrientationOverride() {
  driver_->device_orientation()->ClearDeviceOrientationOverride();
}

void DomainDeviceOrientationImpl::SetDeviceOrientationOverride(int32_t alpha, int32_t beta, int32_t gamma) {
  driver_->device_orientation()->SetDeviceOrientationOverride(alpha, beta, gamma);
}

DomainDOMImpl::DomainDOMImpl(DomainAutomationHost* host): host_(host) {

}

DomainDOMImpl::~DomainDOMImpl() {

}

void DomainDOMImpl::Register(int32_t application_id) {
  //DLOG(INFO) << "DomainDOMImpl::Register: " << application_id;
  application_id_ = application_id;
  Application* application = host_->domain()->GetApplication(application_id);
  DCHECK(application);
  driver_ = application->application_driver();
  host_->MaybeObserve(driver_);
  driver_->dom()->Register(application_id);
  registered_ = true;
}

void DomainDOMImpl::CollectClassNamesFromSubtree(int32_t node_id, CollectClassNamesFromSubtreeCallback callback) {
  driver_->dom()->CollectClassNamesFromSubtree(node_id, std::move(callback));
}

void DomainDOMImpl::CopyTo(int32_t node_id, int32_t target_node_id, int32_t anchor_node_id, CopyToCallback callback) {
  driver_->dom()->CopyTo(node_id, target_node_id, anchor_node_id, std::move(callback));
}

void DomainDOMImpl::DescribeNode(int32_t node_id, int32_t backend_node_id, const base::Optional<std::string>& object_id, int32_t depth, bool pierce, DescribeNodeCallback callback) {
  driver_->dom()->DescribeNode(node_id, backend_node_id, object_id, depth, pierce, std::move(callback));
}

void DomainDOMImpl::Disable() {
  driver_->dom()->Disable();
}

void DomainDOMImpl::DiscardSearchResults(const std::string& search_id) {
  driver_->dom()->DiscardSearchResults(search_id);
}

void DomainDOMImpl::Enable() {
  driver_->dom()->Enable();
}

void DomainDOMImpl::Focus(int32_t node_id, int32_t backend_node_id, const base::Optional<std::string>& object_id) {
  driver_->dom()->Focus(node_id, backend_node_id, object_id);
}

void DomainDOMImpl::GetAttributes(int32_t node_id, GetAttributesCallback callback) {
  driver_->dom()->GetAttributes(node_id, std::move(callback));
}

void DomainDOMImpl::GetBoxModel(int32_t node_id, int32_t backend_node_id, const base::Optional<std::string>& object_id, GetBoxModelCallback callback) {
  driver_->dom()->GetBoxModel(node_id, backend_node_id, object_id, std::move(callback));
}

void DomainDOMImpl::GetDocument(int32_t depth, bool pierce, GetDocumentCallback callback) {
  driver_->dom()->GetDocument(depth, pierce, std::move(callback));
}

void DomainDOMImpl::GetFlattenedDocument(int32_t depth, bool pierce, GetFlattenedDocumentCallback callback) {
  driver_->dom()->GetFlattenedDocument(depth, pierce, std::move(callback));
}

void DomainDOMImpl::GetNodeForLocation(int32_t x, int32_t y, bool include_user_agent_shadow_dom, GetNodeForLocationCallback callback) {
  driver_->dom()->GetNodeForLocation(x, y, include_user_agent_shadow_dom, std::move(callback));
}

void DomainDOMImpl::GetOuterHTML(int32_t node_id, int32_t backend_node_id, const base::Optional<std::string>& object_id, GetOuterHTMLCallback callback) {
  driver_->dom()->GetOuterHTML(node_id, backend_node_id, object_id, std::move(callback));
}

void DomainDOMImpl::GetRelayoutBoundary(int32_t node_id, GetRelayoutBoundaryCallback callback) {
  driver_->dom()->GetRelayoutBoundary(node_id, std::move(callback));
}

void DomainDOMImpl::GetSearchResults(const std::string& search_id, int32_t from_index, int32_t to_index, GetSearchResultsCallback callback) {
  driver_->dom()->GetSearchResults(search_id, from_index, to_index, std::move(callback));
}

void DomainDOMImpl::HideHighlight() {
  driver_->dom()->HideHighlight();
}

void DomainDOMImpl::HighlightNode(automation::HighlightConfigPtr highlight_config, int32_t node_id, int32_t backend_node_id, int32_t object_id) {
  driver_->dom()->HighlightNode(std::move(highlight_config), node_id, backend_node_id, object_id);
}

void DomainDOMImpl::HighlightRect(int32_t x, int32_t y, int32_t width, int32_t height, automation::RGBAPtr color, automation::RGBAPtr outline_color) {
  driver_->dom()->HighlightRect(x, y, width, height, std::move(color), std::move(outline_color));
}

void DomainDOMImpl::MarkUndoableState() { 
  driver_->dom()->MarkUndoableState();
}

void DomainDOMImpl::MoveTo(int32_t node_id, int32_t target_node_id, int32_t insert_before_node_id, MoveToCallback callback) {
  driver_->dom()->MoveTo(node_id, target_node_id, insert_before_node_id, std::move(callback));
}

void DomainDOMImpl::PerformSearch(const std::string& query, bool include_user_agent_shadow_dom, PerformSearchCallback callback) {
  driver_->dom()->PerformSearch(query, include_user_agent_shadow_dom, std::move(callback));
}

void DomainDOMImpl::PushNodeByPathToFrontend(const std::string& path, PushNodeByPathToFrontendCallback callback) {
  driver_->dom()->PushNodeByPathToFrontend(path, std::move(callback));
}

void DomainDOMImpl::PushNodesByBackendIdsToFrontend(const std::vector<int32_t>& backend_node_ids, PushNodesByBackendIdsToFrontendCallback callback) {
  driver_->dom()->PushNodesByBackendIdsToFrontend(backend_node_ids, std::move(callback));
}

void DomainDOMImpl::QuerySelector(int32_t node_id, const std::string& selector, QuerySelectorCallback callback) {
  driver_->dom()->QuerySelector(node_id, selector, std::move(callback));
}

void DomainDOMImpl::QuerySelectorAll(int32_t node_id, const std::string& selector, QuerySelectorAllCallback callback) {
  driver_->dom()->QuerySelectorAll(node_id, selector, std::move(callback));
}

void DomainDOMImpl::Redo() {
  driver_->dom()->Redo();
}

void DomainDOMImpl::RemoveAttribute(int32_t node_id, const std::string& name) {
  driver_->dom()->RemoveAttribute(node_id, name);
}

void DomainDOMImpl::RemoveNode(int32_t node_id) {
  driver_->dom()->RemoveNode(node_id);
}

void DomainDOMImpl::RequestChildNodes(int32_t node_id, int32_t depth, bool pierce) {
  driver_->dom()->RequestChildNodes(node_id, depth, pierce);
}

void DomainDOMImpl::RequestNode(const std::string& object_id, RequestNodeCallback callback) {
  driver_->dom()->RequestNode(object_id, std::move(callback));
}

void DomainDOMImpl::ResolveNode(int32_t node_id, const base::Optional<std::string>& object_group, ResolveNodeCallback callback) {
  driver_->dom()->ResolveNode(node_id, object_group, std::move(callback));
}

void DomainDOMImpl::SetAttributeValue(int32_t node_id, const std::string& name, const std::string& value) {
  driver_->dom()->SetAttributeValue(node_id, name, value);
}

void DomainDOMImpl::SetAttributesAsText(int32_t node_id, const std::string& text, const base::Optional<std::string>& name) {
  driver_->dom()->SetAttributesAsText(node_id, text, name);
}

void DomainDOMImpl::SetFileInputFiles(const std::vector<std::string>& files, int32_t node_id, int32_t backend_node_id, const base::Optional<std::string>& object_id) {
  driver_->dom()->SetFileInputFiles(files, node_id, backend_node_id, object_id);
}

void DomainDOMImpl::SetInspectedNode(int32_t node_id) {
  driver_->dom()->SetInspectedNode(node_id);
}

void DomainDOMImpl::SetNodeName(int32_t node_id, const std::string& name, SetNodeNameCallback callback) {
  driver_->dom()->SetNodeName(node_id, name, std::move(callback));
}

void DomainDOMImpl::SetNodeValue(int32_t node_id, const std::string& value) {
  driver_->dom()->SetNodeValue(node_id, value);
}

void DomainDOMImpl::SetOuterHTML(int32_t node_id, const std::string& outer_html) {
  driver_->dom()->SetOuterHTML(node_id, outer_html);
}

void DomainDOMImpl::Undo() {
  driver_->dom()->Undo();
}

void DomainDOMImpl::GetFrameOwner(const std::string& frame_id, GetFrameOwnerCallback callback) {
  driver_->dom()->GetFrameOwner(frame_id, std::move(callback));
}

DomainDOMSnapshotImpl::DomainDOMSnapshotImpl(DomainAutomationHost* host): host_(host) {

}

DomainDOMSnapshotImpl::~DomainDOMSnapshotImpl() {

}

void DomainDOMSnapshotImpl::Register(int32_t application_id) {
  //DLOG(INFO) << "DomainDOMSnapshotImpl::Register: " << application_id;
  application_id_ = application_id;
  Application* application = host_->domain()->GetApplication(application_id);
  DCHECK(application);
  driver_ = application->application_driver();
  host_->MaybeObserve(driver_);
  driver_->dom_snapshot()->Register(application_id);
  registered_ = true;
}

void DomainDOMSnapshotImpl::GetSnapshot(
  const std::vector<std::string>& computed_style_whitelist, 
  bool include_event_listeners, 
  bool include_paint_order, 
  bool include_user_agent_shadow_tree, 
  GetSnapshotCallback callback) {
    driver_->dom_snapshot()->GetSnapshot(
      computed_style_whitelist, 
      include_event_listeners, 
      include_paint_order, 
      include_user_agent_shadow_tree, 
      std::move(callback));
}

DomainDOMStorageImpl::DomainDOMStorageImpl(DomainAutomationHost* host): host_(host) {

}

DomainDOMStorageImpl::~DomainDOMStorageImpl() {

}

void DomainDOMStorageImpl::Register(int32_t application_id) {
  //DLOG(INFO) << "DomainDOMStorageImpl::Register: " << application_id;
  application_id_ = application_id;
  Application* application = host_->domain()->GetApplication(application_id);
  DCHECK(application);
  driver_ = application->application_driver();
  host_->MaybeObserve(driver_);
  driver_->dom_storage()->Register(application_id);
  registered_ = true;
}

void DomainDOMStorageImpl::Clear(automation::StorageIdPtr storage_id) {
  driver_->dom_storage()->Clear(std::move(storage_id));
}

void DomainDOMStorageImpl::Disable() { 
  driver_->dom_storage()->Disable();
}

void DomainDOMStorageImpl::Enable() {
  driver_->dom_storage()->Enable();
}

void DomainDOMStorageImpl::GetDOMStorageItems(automation::StorageIdPtr storage_id, GetDOMStorageItemsCallback callback) {
  driver_->dom_storage()->GetDOMStorageItems(std::move(storage_id), std::move(callback));
}

void DomainDOMStorageImpl::RemoveDOMStorageItem(automation::StorageIdPtr storage_id, const std::string& key) {
  driver_->dom_storage()->RemoveDOMStorageItem(std::move(storage_id), key);
}

void DomainDOMStorageImpl::SetDOMStorageItem(automation::StorageIdPtr storage_id, const std::string& key, const std::string& value) {
  driver_->dom_storage()->SetDOMStorageItem(std::move(storage_id), key, value);
}

DomainEmulationImpl::DomainEmulationImpl(DomainAutomationHost* host): host_(host) {

}

DomainEmulationImpl::~DomainEmulationImpl() {

}

void DomainEmulationImpl::Register(int32_t application_id) {
  //DLOG(INFO) << "DomainEmulationImpl::Register: " << application_id;
  application_id_ = application_id;
  Application* application = host_->domain()->GetApplication(application_id);
  DCHECK(application);
  driver_ = application->application_driver();
  host_->MaybeObserve(driver_);
  driver_->emulation()->Register(application_id);
  registered_ = true;
}

void DomainEmulationImpl::CanEmulate(CanEmulateCallback callback) {
  driver_->emulation()->CanEmulate(std::move(callback));
}

void DomainEmulationImpl::ClearDeviceMetricsOverride() {
  driver_->emulation()->ClearDeviceMetricsOverride();
}

void DomainEmulationImpl::ClearGeolocationOverride() {
  driver_->emulation()->ClearGeolocationOverride();
}

void DomainEmulationImpl::ResetPageScaleFactor() {
  driver_->emulation()->ResetPageScaleFactor(); 
}

void DomainEmulationImpl::SetCPUThrottlingRate(int32_t rate) {
  driver_->emulation()->SetCPUThrottlingRate(rate); 
}

void DomainEmulationImpl::SetDefaultBackgroundColorOverride(automation::RGBAPtr color) {
  driver_->emulation()->SetDefaultBackgroundColorOverride(std::move(color));
}

void DomainEmulationImpl::SetDeviceMetricsOverride(int32_t width, int32_t height, float device_scale_factor, bool mobile, float scale, int32_t screen_width, int32_t screen_height, int32_t position_x, int32_t position_y, bool dont_set_visible_size, automation::ScreenOrientationPtr screen_orientation, automation::ViewportPtr viewport) {
  driver_->emulation()->SetDeviceMetricsOverride(width, height, device_scale_factor, mobile, scale, screen_width, screen_height, position_x, position_y, dont_set_visible_size, std::move(screen_orientation), std::move(viewport));
}

void DomainEmulationImpl::SetEmitTouchEventsForMouse(bool enabled, automation::TouchEventForMouseConfiguration configuration) {
  driver_->emulation()->SetEmitTouchEventsForMouse(enabled, std::move(configuration));
}

void DomainEmulationImpl::SetEmulatedMedia(const std::string& media) {
  driver_->emulation()->SetEmulatedMedia(media);
}

void DomainEmulationImpl::SetGeolocationOverride(int64_t latitude, int64_t longitude, int64_t accuracy) {
  driver_->emulation()->SetGeolocationOverride(latitude, longitude, accuracy);
}

void DomainEmulationImpl::SetNavigatorOverrides(const std::string& platform) {
  driver_->emulation()->SetNavigatorOverrides(platform);
}

void DomainEmulationImpl::SetPageScaleFactor(float page_scale_factor) {
  driver_->emulation()->SetPageScaleFactor(page_scale_factor);
}

void DomainEmulationImpl::SetScriptExecutionDisabled(bool value) {
  driver_->emulation()->SetScriptExecutionDisabled(value);
}

void DomainEmulationImpl::SetTouchEmulationEnabled(bool enabled, int32_t max_touch_points) {
  driver_->emulation()->SetTouchEmulationEnabled(enabled, max_touch_points);
}

void DomainEmulationImpl::SetVirtualTimePolicy(automation::VirtualTimePolicy policy, int32_t budget, int32_t max_virtual_time_task_starvation_count, bool wait_for_navigation, SetVirtualTimePolicyCallback callback) {
  driver_->emulation()->SetVirtualTimePolicy(std::move(policy), budget, max_virtual_time_task_starvation_count, wait_for_navigation, std::move(callback));
}

void DomainEmulationImpl::SetVisibleSize(int32_t width, int32_t height) {
  driver_->emulation()->SetVisibleSize(width, height);
}

DomainHeadlessImpl::DomainHeadlessImpl(DomainAutomationHost* host): host_(host) {

}

DomainHeadlessImpl::~DomainHeadlessImpl() {

}

void DomainHeadlessImpl::Register(int32_t application_id) {
  //DLOG(INFO) << "DomainHeadlessImpl::Register: " << application_id;
  application_id_ = application_id;
  Application* application = host_->domain()->GetApplication(application_id);
  DCHECK(application);
  driver_ = application->application_driver();
  host_->MaybeObserve(driver_);
  driver_->headless()->Register(application_id);
  registered_ = true;
}

void DomainHeadlessImpl::BeginFrame(int64_t frame_time, int32_t frame_time_ticks, int64_t deadline, int32_t deadline_ticks, int32_t interval, bool no_display_updates, automation::ScreenshotParamsPtr screenshot, BeginFrameCallback callback) {
  driver_->headless()->BeginFrame(frame_time, frame_time_ticks, deadline, deadline_ticks, interval, no_display_updates, std::move(screenshot), std::move(callback));
}

void DomainHeadlessImpl::EnterDeterministicMode(int32_t initial_date) {
  driver_->headless()->EnterDeterministicMode(initial_date);
}

void DomainHeadlessImpl::Disable() {
  driver_->headless()->Disable();
}

void DomainHeadlessImpl::Enable() {
  driver_->headless()->Enable();
}

DomainHostImpl::DomainHostImpl(DomainAutomationHost* host): host_(host) {

}

DomainHostImpl::~DomainHostImpl() {

}

void DomainHostImpl::Register(int32_t application_id) {
  //DLOG(INFO) << "DomainHostImpl::Register: " << application_id;
  application_id_ = application_id;
  Application* application = host_->domain()->GetApplication(application_id);
  DCHECK(application);
  driver_ = application->application_driver();
  host_->MaybeObserve(driver_);
  driver_->host()->Register(application_id);
  registered_ = true;
}

void DomainHostImpl::Close() {
  driver_->host()->Close();
}

void DomainHostImpl::GetVersion(GetVersionCallback callback) {
  driver_->host()->GetVersion(std::move(callback));
}

void DomainHostImpl::GetHostCommandLine(GetHostCommandLineCallback callback) {
  driver_->host()->GetHostCommandLine(std::move(callback));
}

void DomainHostImpl::GetHistograms(const base::Optional<std::string>& query, GetHistogramsCallback callback) {
  driver_->host()->GetHistograms(query, std::move(callback));
}

void DomainHostImpl::GetHistogram(const std::string& name, GetHistogramCallback callback) {
  driver_->host()->GetHistogram(name, std::move(callback));
}

void DomainHostImpl::GetWindowBounds(int32_t window_id, GetWindowBoundsCallback callback) {
  driver_->host()->GetWindowBounds(window_id, std::move(callback));
}

void DomainHostImpl::GetWindowForTarget(const std::string& target_id, GetWindowForTargetCallback callback) {
  driver_->host()->GetWindowForTarget(target_id, std::move(callback));
}

void DomainHostImpl::SetWindowBounds(int32_t window_id, automation::BoundsPtr bounds) {
  driver_->host()->SetWindowBounds(window_id, std::move(bounds));
}

DomainIndexedDBImpl::DomainIndexedDBImpl(DomainAutomationHost* host): host_(host) {

}

DomainIndexedDBImpl::~DomainIndexedDBImpl() {

}

void DomainIndexedDBImpl::Register(int32_t application_id) {
  //DLOG(INFO) << "DomainIndexedDBImpl::Register: " << application_id;
  application_id_ = application_id;
  Application* application = host_->domain()->GetApplication(application_id);
  DCHECK(application);
  driver_ = application->application_driver();
  host_->MaybeObserve(driver_);
  driver_->indexed_db()->Register(application_id);
  registered_ = true;
}

void DomainIndexedDBImpl::ClearObjectStore(const std::string& security_origin, const std::string& database_name, const std::string& object_store_name, ClearObjectStoreCallback callback) {
  driver_->indexed_db()->ClearObjectStore(security_origin, database_name, object_store_name, std::move(callback));
}

void DomainIndexedDBImpl::DeleteDatabase(const std::string& security_origin, const std::string& database_name, DeleteDatabaseCallback callback) {
  driver_->indexed_db()->DeleteDatabase(security_origin, database_name, std::move(callback));
}

void DomainIndexedDBImpl::DeleteObjectStoreEntries(const std::string& security_origin, const std::string& database_name, const std::string& object_store_name, automation::KeyRangePtr key_range, DeleteObjectStoreEntriesCallback callback)  {
  driver_->indexed_db()->DeleteObjectStoreEntries(security_origin, database_name, object_store_name, std::move(key_range), std::move(callback));
}

void DomainIndexedDBImpl::Disable() {
  driver_->indexed_db()->Disable();
}

void DomainIndexedDBImpl::Enable() {
  driver_->indexed_db()->Enable();
}

void DomainIndexedDBImpl::RequestData(const std::string& security_origin, const std::string& database_name, const std::string& object_store_name, const std::string& index_name, int32_t skip_count, int32_t page_size, automation::KeyRangePtr key_range, RequestDataCallback callback) {
  driver_->indexed_db()->RequestData(security_origin, database_name, object_store_name, index_name, skip_count, page_size, std::move(key_range), std::move(callback));
}

void DomainIndexedDBImpl::RequestDatabase(const std::string& security_origin, const std::string& database_name, RequestDatabaseCallback callback) {
  driver_->indexed_db()->RequestDatabase(security_origin, database_name, std::move(callback));
}

void DomainIndexedDBImpl::RequestDatabaseNames(const std::string& security_origin, RequestDatabaseNamesCallback callback) {
  driver_->indexed_db()->RequestDatabaseNames(security_origin, std::move(callback));
}

DomainInputImpl::DomainInputImpl(DomainAutomationHost* host): host_(host) {

}

DomainInputImpl::~DomainInputImpl() {

}

void DomainInputImpl::Register(int32_t application_id) {
  //DLOG(INFO) << "DomainInputImpl::Register: " << application_id;
  application_id_ = application_id;
  Application* application = host_->domain()->GetApplication(application_id);
  DCHECK(application);
  driver_ = application->application_driver();
  host_->MaybeObserve(driver_);
  driver_->input()->Register(application_id);
  registered_ = true;
}

void DomainInputImpl::DispatchKeyEvent(automation::KeyEventType type, int32_t modifiers, int64_t timestamp, const base::Optional<std::string>& text, const base::Optional<std::string>& unmodified_text, const base::Optional<std::string>& key_identifier, const base::Optional<std::string>& code, const base::Optional<std::string>& key, int32_t windows_virtual_key_code, int32_t native_virtual_key_code, bool auto_repeat, bool is_keypad, bool is_system_key, int32_t location, DispatchKeyEventCallback callback) {
  driver_->input()->DispatchKeyEvent(type, modifiers, timestamp, text, unmodified_text, key_identifier, code, key, windows_virtual_key_code, native_virtual_key_code, auto_repeat, is_keypad, is_system_key, location, std::move(callback));
}

void DomainInputImpl::DispatchMouseEvent(automation::MouseEventType type, int32_t x, int32_t y, int32_t modifiers, int64_t timestamp, automation::MouseButton button, int32_t click_count, int32_t delta_x, int32_t delta_y, DispatchMouseEventCallback callback) {
  driver_->input()->DispatchMouseEvent(type, x, y, modifiers, timestamp, button, click_count, delta_x, delta_y, std::move(callback));
}

void DomainInputImpl::DispatchTouchEvent(automation::TouchEventType type, std::vector<automation::TouchPointPtr> touch_points, int32_t modifiers, int64_t timestamp, DispatchTouchEventCallback callback) {
  driver_->input()->DispatchTouchEvent(type, std::move(touch_points), modifiers, timestamp, std::move(callback));
}

void DomainInputImpl::EmulateTouchFromMouseEvent(automation::MouseEventType type, int32_t x, int32_t y, automation::MouseButton button, int64_t timestamp, int32_t delta_x, int32_t delta_y, int32_t modifiers, int32_t click_count, EmulateTouchFromMouseEventCallback callback) {
  driver_->input()->EmulateTouchFromMouseEvent(type, x, y, button, timestamp, delta_x, delta_y, modifiers, click_count, std::move(callback));
}

void DomainInputImpl::SetIgnoreInputEvents(bool ignore) {
  driver_->input()->SetIgnoreInputEvents(ignore);
}

void DomainInputImpl::SynthesizePinchGesture(int32_t x, int32_t y, int32_t scale_factor, int32_t relative_speed, automation::GestureSourceType gesture_source_type, SynthesizePinchGestureCallback callback) {
  driver_->input()->SynthesizePinchGesture(x, y, scale_factor, relative_speed, gesture_source_type, std::move(callback));
}

void DomainInputImpl::SynthesizeScrollGesture(int32_t x, int32_t y, int32_t x_distance, int32_t y_distance, int32_t x_overscroll, int32_t y_overscroll, bool prevent_fling, int32_t speed, automation::GestureSourceType gesture_source_type, int32_t repeat_count, int32_t repeat_delay_ms, const base::Optional<std::string>& interaction_marker_name, SynthesizeScrollGestureCallback callback) {
  driver_->input()->SynthesizeScrollGesture(x, y, x_distance, y_distance, x_overscroll, y_overscroll, prevent_fling, speed, gesture_source_type, repeat_count, repeat_delay_ms, interaction_marker_name, std::move(callback));
}

void DomainInputImpl::SynthesizeTapGesture(int32_t x, int32_t y, int32_t duration, int32_t tap_count, automation::GestureSourceType gesture_source_type, SynthesizeTapGestureCallback callback) {
  driver_->input()->SynthesizeTapGesture(x, y, duration, tap_count, gesture_source_type, std::move(callback));
}

DomainIOImpl::DomainIOImpl(DomainAutomationHost* host): host_(host) {

}

DomainIOImpl::~DomainIOImpl() {

}

void DomainIOImpl::Register(int32_t application_id) {
  //DLOG(INFO) << "DomainIOImpl::Register: " << application_id;
  application_id_ = application_id;
  Application* application = host_->domain()->GetApplication(application_id);
  DCHECK(application);
  driver_ = application->application_driver();
  host_->MaybeObserve(driver_);
  driver_->io()->Register(application_id);
  registered_ = true;
}

void DomainIOImpl::Close(const std::string& handl) {
  driver_->io()->Close(handl);
}

void DomainIOImpl::Read(const std::string& handl, int32_t offset, int32_t size, ReadCallback callback) {
  driver_->io()->Read(handl, offset, size, std::move(callback));
}

void DomainIOImpl::ResolveBlob(const std::string& object_id, ResolveBlobCallback callback) {
  driver_->io()->ResolveBlob(object_id, std::move(callback));
}

DomainLayerTreeImpl::DomainLayerTreeImpl(DomainAutomationHost* host): host_(host) {

}

DomainLayerTreeImpl::~DomainLayerTreeImpl() {

}

void DomainLayerTreeImpl::Register(int32_t application_id) {
  //DLOG(INFO) << "DomainLayerTreeImpl::Register: " << application_id;
  application_id_ = application_id;
  Application* application = host_->domain()->GetApplication(application_id);
  DCHECK(application);
  driver_ = application->application_driver();
  host_->MaybeObserve(driver_);
  driver_->layer_tree()->Register(application_id);
  registered_ = true;
}

void DomainLayerTreeImpl::CompositingReasons(const std::string& layer_id, CompositingReasonsCallback callback) {
  driver_->layer_tree()->CompositingReasons(layer_id, std::move(callback));
}

void DomainLayerTreeImpl::Disable() {
  driver_->layer_tree()->Disable();
}

void DomainLayerTreeImpl::Enable() {
  driver_->layer_tree()->Enable();
}

void DomainLayerTreeImpl::LoadSnapshot(std::vector<automation::PictureTilePtr> tiles, LoadSnapshotCallback callback) {
  driver_->layer_tree()->LoadSnapshot(std::move(tiles), std::move(callback));
}

void DomainLayerTreeImpl::MakeSnapshot(const std::string& layer_id, MakeSnapshotCallback callback) {
  driver_->layer_tree()->MakeSnapshot(layer_id, std::move(callback));
}

void DomainLayerTreeImpl::ProfileSnapshot(const std::string& snapshot_id, int32_t min_repeat_count, int32_t min_duration, const base::Optional<gfx::Rect>& clip_rect, ProfileSnapshotCallback callback) {
  driver_->layer_tree()->ProfileSnapshot(snapshot_id, min_repeat_count, min_duration, clip_rect, std::move(callback));
}

void DomainLayerTreeImpl::ReleaseSnapshot(const std::string& snapshot_id) {
  driver_->layer_tree()->ReleaseSnapshot(snapshot_id);
}

void DomainLayerTreeImpl::ReplaySnapshot(const std::string& snapshot_id, int32_t from_step, int32_t to_step, int32_t scale, ReplaySnapshotCallback callback) {
  driver_->layer_tree()->ReplaySnapshot(snapshot_id, from_step, to_step, scale, std::move(callback));
}

void DomainLayerTreeImpl::SnapshotCommandLog(const std::string& snapshot_id, SnapshotCommandLogCallback callback) {
  driver_->layer_tree()->SnapshotCommandLog(snapshot_id, std::move(callback));
}

DomainNetworkImpl::DomainNetworkImpl(DomainAutomationHost* host): host_(host) {
  
}

DomainNetworkImpl::~DomainNetworkImpl() {
  
}

void DomainNetworkImpl::Register(int32_t application_id) {
  //DLOG(INFO) << "DomainNetworkImpl::Register: " << application_id;
  application_id_ = application_id;
  Application* application = host_->domain()->GetApplication(application_id);
  DCHECK(application);
  driver_ = application->application_driver();
  host_->MaybeObserve(driver_);
  driver_->network()->Register(application_id);
  registered_ = true;
}

void DomainNetworkImpl::CanClearBrowserCache(CanClearBrowserCacheCallback callback) {
  driver_->network()->CanClearBrowserCache(std::move(callback));
}

void DomainNetworkImpl::CanClearBrowserCookies(CanClearBrowserCookiesCallback callback) {
  driver_->network()->CanClearBrowserCookies(std::move(callback));
}

void DomainNetworkImpl::CanEmulateNetworkConditions(CanEmulateNetworkConditionsCallback callback) {
  driver_->network()->CanEmulateNetworkConditions(std::move(callback));
}

void DomainNetworkImpl::ClearBrowserCache() {
  driver_->network()->ClearBrowserCache();
}

void DomainNetworkImpl::ClearBrowserCookies() {
  driver_->network()->ClearBrowserCookies();
}

void DomainNetworkImpl::ContinueInterceptedRequest(const std::string& interception_id, automation::ErrorReason error_reason, const base::Optional<std::string>& raw_response, const base::Optional<std::string>& url, const base::Optional<std::string>& method, const base::Optional<std::string>& post_data, const base::Optional<base::flat_map<std::string, std::string>>& headers, automation::AuthChallengeResponsePtr auth_challenge_response) {
  driver_->network()->ContinueInterceptedRequest(interception_id, error_reason, raw_response, url, method, post_data, headers, std::move(auth_challenge_response));
}

void DomainNetworkImpl::DeleteCookies(const std::string& name, const base::Optional<std::string>& url, const base::Optional<std::string>& domain, const base::Optional<std::string>& path) {
  driver_->network()->DeleteCookies(name, url, domain, path);
}

void DomainNetworkImpl::Disable() {
  driver_->network()->Disable();
}

void DomainNetworkImpl::EmulateNetworkConditions(bool offline, int64_t latency, int64_t download_throughput, int64_t upload_throughput, automation::ConnectionType connection_type) {
  driver_->network()->EmulateNetworkConditions(offline, latency, download_throughput, upload_throughput, connection_type);
}

void DomainNetworkImpl::Enable(int32_t max_total_buffer_size, int32_t max_resource_buffer_size, int32_t max_post_data_size) {
  driver_->network()->Enable(max_total_buffer_size, max_resource_buffer_size, max_post_data_size);
}

void DomainNetworkImpl::GetAllCookies(GetAllCookiesCallback callback) {
  driver_->network()->GetAllCookies(std::move(callback));
}

void DomainNetworkImpl::GetCertificate(const std::string& origin, GetCertificateCallback callback) {
  driver_->network()->GetCertificate(origin, std::move(callback));
}

void DomainNetworkImpl::GetCookies(const base::Optional<std::vector<std::string>>& urls, GetCookiesCallback callback) {
  driver_->network()->GetCookies(urls, std::move(callback));
}

void DomainNetworkImpl::GetResponseBody(const std::string& request_id, GetResponseBodyCallback callback) {
  driver_->network()->GetResponseBody(request_id, std::move(callback));
}

void DomainNetworkImpl::GetRequestPostData(const std::string& request_id, GetRequestPostDataCallback callback) {
  driver_->network()->GetRequestPostData(request_id, std::move(callback));
}

void DomainNetworkImpl::GetResponseBodyForInterception(const std::string& interception_id, GetResponseBodyForInterceptionCallback callback) {
  driver_->network()->GetResponseBodyForInterception(interception_id, std::move(callback));
}

void DomainNetworkImpl::TakeResponseBodyForInterceptionAsStream(const std::string& interception_id, TakeResponseBodyForInterceptionAsStreamCallback callback) {
  driver_->network()->TakeResponseBodyForInterceptionAsStream(interception_id, std::move(callback));
}

void DomainNetworkImpl::ReplayXHR(const std::string& request_id) {
  driver_->network()->ReplayXHR(request_id);
}

void DomainNetworkImpl::SearchInResponseBody(const std::string& request_id, const std::string& query, bool case_sensitive, bool is_regex, SearchInResponseBodyCallback callback) {
  driver_->network()->SearchInResponseBody(request_id, query, case_sensitive, is_regex, std::move(callback));
}

void DomainNetworkImpl::SetBlockedURLs(const std::vector<std::string>& urls) {
  driver_->network()->SetBlockedURLs(urls);
}

void DomainNetworkImpl::SetBypassServiceWorker(bool bypass) {
  driver_->network()->SetBypassServiceWorker(bypass);
}

void DomainNetworkImpl::SetCacheDisabled(bool cache_disabled) {
  driver_->network()->SetCacheDisabled(cache_disabled);
}

void DomainNetworkImpl::SetCookie(const std::string& name, const std::string& value, const base::Optional<std::string>& url, const base::Optional<std::string>& domain, const base::Optional<std::string>& path, bool secure, bool http_only, automation::CookieSameSite same_site, int64_t expires, SetCookieCallback callback) {
  driver_->network()->SetCookie(name, value, url, domain, path, secure, http_only, same_site, expires, std::move(callback));
}

void DomainNetworkImpl::SetCookies(std::vector<automation::CookieParamPtr> cookies) {
  driver_->network()->SetCookies(std::move(cookies));
}

void DomainNetworkImpl::SetDataSizeLimitsForTest(int32_t max_total_size, int32_t max_resource_size) {
  driver_->network()->SetDataSizeLimits(max_total_size, max_resource_size);
}

void DomainNetworkImpl::SetExtraHTTPHeaders(const base::flat_map<std::string, std::string>& headers) {
  driver_->network()->SetExtraHTTPHeaders(headers);
}

void DomainNetworkImpl::SetRequestInterception(std::vector<automation::RequestPatternPtr> patterns) {
  driver_->network()->SetRequestInterception(std::move(patterns));
}

void DomainNetworkImpl::SetUserAgentOverride(const std::string& user_agent) {
  driver_->network()->SetUserAgentOverride(user_agent);
}

DomainOverlayImpl::DomainOverlayImpl(DomainAutomationHost* host): host_(host) {

}

DomainOverlayImpl::~DomainOverlayImpl() {

}

void DomainOverlayImpl::Register(int32_t application_id) {
  //DLOG(INFO) << "DomainOverlayImpl::Register: " << application_id;
  application_id_ = application_id;
  Application* application = host_->domain()->GetApplication(application_id);
  DCHECK(application);
  driver_ = application->application_driver();
  host_->MaybeObserve(driver_);
  driver_->overlay()->Register(application_id);
  registered_ = true;
}

void DomainOverlayImpl::Disable() {
  driver_->overlay()->Disable();
}

void DomainOverlayImpl::Enable() {
  driver_->overlay()->Enable();
}

void DomainOverlayImpl::HideHighlight()  {
  driver_->overlay()->HideHighlight();
}

void DomainOverlayImpl::HighlightFrame(const std::string& frame_id, automation::RGBAPtr content_color, automation::RGBAPtr content_outline_color) {
  driver_->overlay()->HighlightFrame(frame_id, std::move(content_color), std::move(content_outline_color));
}

void DomainOverlayImpl::HighlightNode(automation::HighlightConfigPtr highlight_config, int32_t node_id, int32_t backend_node_id, const base::Optional<std::string>& object_id) {
  driver_->overlay()->HighlightNode(
    std::move(highlight_config),
    node_id, 
    backend_node_id, 
    object_id);
}

void DomainOverlayImpl::HighlightQuad(const std::vector<double>& quad, automation::RGBAPtr color, automation::RGBAPtr outline_color) {
  driver_->overlay()->HighlightQuad(quad, std::move(color), std::move(outline_color));
}

void DomainOverlayImpl::HighlightRect(int32_t x, int32_t y, int32_t width, int32_t height, automation::RGBAPtr color, automation::RGBAPtr outline_color) {
  driver_->overlay()->HighlightRect(x, y, width, height, std::move(color), std::move(outline_color));
}

void DomainOverlayImpl::SetInspectMode(automation::InspectMode mode, automation::HighlightConfigPtr highlight_config) {
  driver_->overlay()->SetInspectMode(mode, std::move(highlight_config));
}

void DomainOverlayImpl::SetPausedInDebuggerMessage(const base::Optional<std::string>& message) {
  driver_->overlay()->SetPausedInDebuggerMessage(message);
}

void DomainOverlayImpl::SetShowDebugBorders(bool show) {
  driver_->overlay()->SetShowDebugBorders(show);
}

void DomainOverlayImpl::SetShowFPSCounter(bool show) {
  driver_->overlay()->SetShowFPSCounter(show);
}

void DomainOverlayImpl::SetShowPaintRects(bool result) {
  driver_->overlay()->SetShowPaintRects(result);
}

void DomainOverlayImpl::SetShowScrollBottleneckRects(bool show) {
  driver_->overlay()->SetShowScrollBottleneckRects(show);
}

void DomainOverlayImpl::SetShowViewportSizeOnResize(bool show) {
  driver_->overlay()->SetShowViewportSizeOnResize(show);
}

void DomainOverlayImpl::SetSuspended(bool suspended) {
  driver_->overlay()->SetSuspended(suspended);
}

DomainWorkerImpl::DomainWorkerImpl(DomainAutomationHost* host): 
  host_(host) {

}

DomainWorkerImpl::~DomainWorkerImpl() {

}

void DomainWorkerImpl::Register(int32_t application_id) {
  //DLOG(INFO) << "DomainWorkerImpl::Register: " << application_id;
  application_id_ = application_id;
  Application* application = host_->domain()->GetApplication(application_id);
  DCHECK(application);
  driver_ = application->application_driver();
  host_->MaybeObserve(driver_);
  driver_->worker()->Register(application_id);
  registered_ = true;
}

void DomainWorkerImpl::DeliverPushMessage(const std::string& origin, const std::string& registration_id, const std::string& data) {
  driver_->worker()->DeliverPushMessage(origin, registration_id, data);
}

void DomainWorkerImpl::Disable() {
  driver_->worker()->Disable();
}

void DomainWorkerImpl::DispatchSyncEvent(const std::string& origin, const std::string& registration_id, const std::string& tag, bool last_chance) {
  driver_->worker()->DispatchSyncEvent(origin, registration_id, tag, last_chance);
}

void DomainWorkerImpl::Enable() {
  driver_->worker()->Enable();
}

void DomainWorkerImpl::InspectWorker(const std::string& version_id) {
  driver_->worker()->InspectWorker(version_id);
}

void DomainWorkerImpl::SetForceUpdateOnPageLoad(bool force_update_on_pageload) {
  driver_->worker()->SetForceUpdateOnPageLoad(force_update_on_pageload);
}

void DomainWorkerImpl::SkipWaiting(const std::string& scope_url) {
  driver_->worker()->SkipWaiting(scope_url);
}

void DomainWorkerImpl::StartWorker(const std::string& scope_url) {
  driver_->worker()->StartWorker(scope_url);
}

void DomainWorkerImpl::StopAllWorkers() {
  driver_->worker()->StopAllWorkers();
}

void DomainWorkerImpl::StopWorker(const std::string& version_id) {
  driver_->worker()->StopWorker(version_id);
}

void DomainWorkerImpl::Unregister(const std::string& scope_url) {
  driver_->worker()->Unregister(scope_url);
}

void DomainWorkerImpl::UpdateRegistration(const std::string& scope_url) {
  driver_->worker()->UpdateRegistration(scope_url);
}

void DomainWorkerImpl::SendMessageToTarget(const std::string& message,
                                            const base::Optional<std::string>& session_id,
                                            const base::Optional<std::string>& target_id) {
  driver_->worker()->SendMessageToTarget(message, session_id, target_id);
}

DomainStorageImpl::DomainStorageImpl(DomainAutomationHost* host): host_(host) {
  
}

DomainStorageImpl::~DomainStorageImpl() {
  
}

void DomainStorageImpl::Register(int32_t application_id) {
  //DLOG(INFO) << "DomainStorageImpl::Register: " << application_id;
  application_id_ = application_id;
  Application* application = host_->domain()->GetApplication(application_id);
  DCHECK(application);
  driver_ = application->application_driver();
  host_->MaybeObserve(driver_);
  driver_->storage()->Register(application_id);
  registered_ = true;
}

void DomainStorageImpl::ClearDataForOrigin(const std::string& origin, const std::vector<automation::StorageType>& storage_types) {
  driver_->storage()->ClearDataForOrigin(origin, storage_types);
}

void DomainStorageImpl::GetUsageAndQuota(const std::string& origin, int64_t usage, int64_t quota, std::vector<automation::UsageForTypePtr> usage_breakdown) {
  driver_->storage()->GetUsageAndQuota(origin, usage, quota, std::move(usage_breakdown));
}

void DomainStorageImpl::TrackCacheStorageForOrigin(const std::string& origin) {
  driver_->storage()->TrackCacheStorageForOrigin(origin);
}

void DomainStorageImpl::TrackIndexedDBForOrigin(const std::string& origin) {
  driver_->storage()->TrackIndexedDBForOrigin(origin);
}

void DomainStorageImpl::UntrackCacheStorageForOrigin(const std::string& origin) {
  driver_->storage()->UntrackCacheStorageForOrigin(origin);
}

void DomainStorageImpl::UntrackIndexedDBForOrigin(const std::string& origin) {
  driver_->storage()->UntrackIndexedDBForOrigin(origin);
}

DomainSystemInfoImpl::DomainSystemInfoImpl(DomainAutomationHost* host): host_(host) {

}

DomainSystemInfoImpl::~DomainSystemInfoImpl() {

}

void DomainSystemInfoImpl::Register(int32_t application_id) {
  //DLOG(INFO) << "DomainSystemInfoImpl::Register: " << application_id;
  application_id_ = application_id;
  Application* application = host_->domain()->GetApplication(application_id);
  DCHECK(application);
  driver_ = application->application_driver();
  host_->MaybeObserve(driver_);
  driver_->system_info()->Register(application_id);
  registered_ = true;
}

void DomainSystemInfoImpl::GetInfo(GetInfoCallback callback) {
  driver_->system_info()->GetInfo(std::move(callback));
}

DomainTetheringImpl::DomainTetheringImpl(DomainAutomationHost* host): host_(host) {

}

DomainTetheringImpl::~DomainTetheringImpl() {

}

void DomainTetheringImpl::Register(int32_t application_id) {
  //DLOG(INFO) << "DomainTetheringImpl::Register: " << application_id;
  application_id_ = application_id;
  Application* application = host_->domain()->GetApplication(application_id);
  DCHECK(application);
  driver_ = application->application_driver();
  host_->MaybeObserve(driver_);
  driver_->tethering()->Register(application_id);
  registered_ = true;
}

void DomainTetheringImpl::Bind(int32_t port) {
  driver_->tethering()->Bind(port);
}

void DomainTetheringImpl::Unbind(int32_t port) {
  driver_->tethering()->Unbind(port);
}

DomainAutomationHost::DomainAutomationHost(Domain* domain):
 domain_(domain) {

}

DomainAutomationHost::~DomainAutomationHost() {

}

void DomainAutomationHost::BindClientInterfaces(int id, IPC::ChannelProxy* channel) {
  //DLOG(INFO) << "DomainAutomationHost::BindClientInterfaces: binding to " << "'automation.PageClient_" + base::NumberToString(id) << "'";

  auto page_request = mojo::MakeRequest(&page_client_);
  channel->GetGenericRemoteAssociatedInterface("automation.PageClient_" + base::NumberToString(id), page_request.PassHandle());
  
  auto overlay_request = mojo::MakeRequest(&overlay_client_);
  channel->GetGenericRemoteAssociatedInterface("automation.OverlayClient_" + base::NumberToString(id), overlay_request.PassHandle());

  auto worker_request = mojo::MakeRequest(&service_worker_client_);
  channel->GetGenericRemoteAssociatedInterface("automation.ServiceWorkerClient_" + base::NumberToString(id), worker_request.PassHandle());

  auto storage_request = mojo::MakeRequest(&storage_client_);
  channel->GetGenericRemoteAssociatedInterface("automation.StorageClient_" + base::NumberToString(id), storage_request.PassHandle());

  auto tethering_request = mojo::MakeRequest(&tethering_client_);
  channel->GetGenericRemoteAssociatedInterface("automation.TheteringClient_" + base::NumberToString(id), tethering_request.PassHandle());
  
  auto network_request = mojo::MakeRequest(&network_client_);
  channel->GetGenericRemoteAssociatedInterface("automation.NetworkClient_" + base::NumberToString(id), network_request.PassHandle());
  
  auto layer_tree_request = mojo::MakeRequest(&layer_tree_);
  channel->GetGenericRemoteAssociatedInterface("automation.LayerTreeClient_" + base::NumberToString(id), layer_tree_request.PassHandle());

  auto headless_request = mojo::MakeRequest(&headless_client_);
  channel->GetGenericRemoteAssociatedInterface("automation.HeadlessClient_" + base::NumberToString(id), headless_request.PassHandle());

  auto dom_storage_request = mojo::MakeRequest(&dom_storage_client_);
  channel->GetGenericRemoteAssociatedInterface("automation.DOMStorageClient_" + base::NumberToString(id), dom_storage_request.PassHandle());

  auto database_request = mojo::MakeRequest(&database_client_);
  channel->GetGenericRemoteAssociatedInterface("automation.DatabaseClient_" + base::NumberToString(id), database_request.PassHandle());

  auto emulation_request = mojo::MakeRequest(&emulation_client_);
  channel->GetGenericRemoteAssociatedInterface("automation.EmulationClient_" + base::NumberToString(id), emulation_request.PassHandle());

  auto dom_request = mojo::MakeRequest(&dom_client_);
  channel->GetGenericRemoteAssociatedInterface("automation.DOMClient_" + base::NumberToString(id), dom_request.PassHandle());

  auto css_request = mojo::MakeRequest(&css_client_);
  channel->GetGenericRemoteAssociatedInterface("automation.CSSClient_" + base::NumberToString(id), css_request.PassHandle());
  
  auto application_cache_request = mojo::MakeRequest(&application_cache_client_);
  channel->GetGenericRemoteAssociatedInterface("automation.ApplicationCacheClient_" + base::NumberToString(id), application_cache_request.PassHandle());

  auto animation_request = mojo::MakeRequest(&animation_client_);
  channel->GetGenericRemoteAssociatedInterface("automation.AnimationClient_" + base::NumberToString(id), animation_request.PassHandle());
}

void DomainAutomationHost::AddPageBinding(automation::PageAssociatedRequest request) {
  //DLOG(INFO) << "DomainAutomationHost::AddPageAssociatedBinding(associated)";
  auto page = std::make_unique<DomainPageImpl>(this);
  DomainPageImpl* page_ptr = page.get();
  pages_.push_back(std::move(page));
  page_bindings_.AddBinding(page_ptr, std::move(request));
}

void DomainAutomationHost::AddAccessibilityBinding(automation::AccessibilityAssociatedRequest request) {
  //DLOG(INFO) << "DomainAutomationHost::AddAccessibilityBinding";
  auto accessibility = std::make_unique<DomainAccessibilityImpl>(this);
  DomainAccessibilityImpl* accessibility_ptr = accessibility.get();
  accessibilities_.push_back(std::move(accessibility));
  accessibility_bindings_.AddBinding(accessibility_ptr, std::move(request));
}

void DomainAutomationHost::AddAnimationBinding(automation::AnimationInterfaceAssociatedRequest request) {
  //DLOG(INFO) << "DomainAutomationHost::AddAnimationBinding";
  auto animation = std::make_unique<DomainAnimationImpl>(this);
  DomainAnimationImpl* animation_ptr = animation.get();
  animations_.push_back(std::move(animation));
  animation_bindings_.AddBinding(animation_ptr, std::move(request));
}

void DomainAutomationHost::AddApplicationCacheBinding(automation::ApplicationCacheInterfaceAssociatedRequest request) {
  //DLOG(INFO) << "DomainAutomationHost::AddApplicationCacheBinding";
  auto app = std::make_unique<DomainApplicationCacheImpl>(this);
  DomainApplicationCacheImpl* app_ptr = app.get();
  app_caches_.push_back(std::move(app));
  application_cache_bindings_.AddBinding(app_ptr, std::move(request));
}

void DomainAutomationHost::AddCacheStorageBinding(automation::CacheStorageAssociatedRequest request) {
  auto cache = std::make_unique<DomainCacheStorageImpl>(this);
  DomainCacheStorageImpl* cache_ptr = cache.get();
  DLOG(INFO) << "DomainAutomationHost::AddStorageBinding: DomainCacheStorageImpl = " << cache_ptr;
  cache_storages_.push_back(std::move(cache));
  cache_storage_bindings_.AddBinding(cache_ptr, std::move(request));
}

void DomainAutomationHost::AddCSSBinding(automation::CSSAssociatedRequest request) {
  //DLOG(INFO) << "DomainAutomationHost::AddCSSBinding";
  auto css = std::make_unique<DomainCSSImpl>(this);
  DomainCSSImpl* css_ptr = css.get();
  css_.push_back(std::move(css));
  css_bindings_.AddBinding(css_ptr, std::move(request));
}

void DomainAutomationHost::AddDatabaseBinding(automation::DatabaseInterfaceAssociatedRequest request) {
  //DLOG(INFO) << "DomainAutomationHost::AddDatabaseBinding";
  auto db = std::make_unique<DomainDatabaseImpl>(this);
  DomainDatabaseImpl* db_ptr = db.get();
  databases_.push_back(std::move(db));
  database_bindings_.AddBinding(db_ptr, std::move(request));
}

void DomainAutomationHost::AddDeviceOrientationBinding(automation::DeviceOrientationAssociatedRequest request) {
  //DLOG(INFO) << "DomainAutomationHost::AddDeviceOrientationBinding";
  auto dev = std::make_unique<DomainDeviceOrientationImpl>(this);
  DomainDeviceOrientationImpl* dev_ptr = dev.get();
  device_orientations_.push_back(std::move(dev));
  device_orientation_bindings_.AddBinding(dev_ptr, std::move(request));
}

void DomainAutomationHost::AddDOMBinding(automation::DOMAssociatedRequest request) {
  //DLOG(INFO) << "DomainAutomationHost::AddDOMBinding";
  auto dom = std::make_unique<DomainDOMImpl>(this);
  DomainDOMImpl* dom_ptr = dom.get();
  doms_.push_back(std::move(dom));
  dom_bindings_.AddBinding(dom_ptr, std::move(request));
}

void DomainAutomationHost::AddDOMSnapshotBinding(automation::DOMSnapshotAssociatedRequest request) {
  //DLOG(INFO) << "DomainAutomationHost::AddDOMSnapshotBinding";
  auto dom = std::make_unique<DomainDOMSnapshotImpl>(this);
  DomainDOMSnapshotImpl* dom_ptr = dom.get();
  dom_snapshots_.push_back(std::move(dom));
  dom_snapshot_bindings_.AddBinding(dom_ptr, std::move(request));
}

void DomainAutomationHost::AddDOMStorageBinding(automation::DOMStorageAssociatedRequest request) {
  //DLOG(INFO) << "DomainAutomationHost::AddDOMStorageBinding";
  auto dom = std::make_unique<DomainDOMStorageImpl>(this);
  DomainDOMStorageImpl* dom_ptr = dom.get();
  dom_storages_.push_back(std::move(dom));
  dom_storage_bindings_.AddBinding(dom_ptr, std::move(request));
}

void DomainAutomationHost::AddEmulationBinding(automation::EmulationAssociatedRequest request) {
  //DLOG(INFO) << "DomainAutomationHost::AddEmulationBinding";
  auto emu = std::make_unique<DomainEmulationImpl>(this);
  DomainEmulationImpl* emu_ptr = emu.get();
  emulations_.push_back(std::move(emu));
  emulation_bindings_.AddBinding(emu_ptr, std::move(request));
}

void DomainAutomationHost::AddHeadlessBinding(automation::HeadlessAssociatedRequest request) {
  //DLOG(INFO) << "DomainAutomationHost::AddHeadlessBinding";
  auto head = std::make_unique<DomainHeadlessImpl>(this);
  DomainHeadlessImpl* head_ptr = head.get();
  headless_.push_back(std::move(head));
  headless_bindings_.AddBinding(head_ptr, std::move(request));
}

void DomainAutomationHost::AddHostBinding(automation::HostAssociatedRequest request) {
  //DLOG(INFO) << "DomainAutomationHost::AddHostBinding";
  auto host = std::make_unique<DomainHostImpl>(this);
  DomainHostImpl* host_ptr = host.get();
  hosts_.push_back(std::move(host));
  host_bindings_.AddBinding(host_ptr, std::move(request));
}

void DomainAutomationHost::AddIndexedDBBinding(automation::IndexedDBAssociatedRequest request) {
  //DLOG(INFO) << "DomainAutomationHost::AddIndexedDBBinding";
  auto indexed_db = std::make_unique<DomainIndexedDBImpl>(this);
  DomainIndexedDBImpl* indexed_db_ptr = indexed_db.get();
  indexed_dbs_.push_back(std::move(indexed_db));
  indexed_db_bindings_.AddBinding(indexed_db_ptr, std::move(request));
}

void DomainAutomationHost::AddInputBinding(automation::InputAssociatedRequest request) {
  //DLOG(INFO) << "DomainAutomationHost::AddInputBinding";
  auto input = std::make_unique<DomainInputImpl>(this);
  DomainInputImpl* input_ptr = input.get();
  inputs_.push_back(std::move(input));
  input_bindings_.AddBinding(input_ptr, std::move(request));
}

void DomainAutomationHost::AddIOBinding(automation::IOAssociatedRequest request) {
  //DLOG(INFO) << "DomainAutomationHost::AddIOBinding";
  auto io = std::make_unique<DomainIOImpl>(this);
  DomainIOImpl* io_ptr = io.get();
  ios_.push_back(std::move(io));
  io_bindings_.AddBinding(io_ptr, std::move(request));
}

void DomainAutomationHost::AddLayerTreeBinding(automation::LayerTreeAssociatedRequest request) {
  //DLOG(INFO) << "DomainAutomationHost::AddLayerTreeBinding";
  auto layer_tree = std::make_unique<DomainLayerTreeImpl>(this);
  DomainLayerTreeImpl* layer_tree_ptr = layer_tree.get();
  layer_trees_.push_back(std::move(layer_tree));
  layer_tree_bindings_.AddBinding(layer_tree_ptr, std::move(request));
}

void DomainAutomationHost::AddNetworkBinding(automation::NetworkAssociatedRequest request) {
  //DLOG(INFO) << "DomainAutomationHost::AddNetworkBinding";
  auto network = std::make_unique<DomainNetworkImpl>(this);
  DomainNetworkImpl* network_ptr = network.get();
  networks_.push_back(std::move(network));
  network_bindings_.AddBinding(network_ptr, std::move(request));
}

void DomainAutomationHost::AddOverlayBinding(automation::OverlayAssociatedRequest request) {
  //DLOG(INFO) << "DomainAutomationHost::AddOverlayBinding";
  auto overlay = std::make_unique<DomainOverlayImpl>(this);
  DomainOverlayImpl* overlay_ptr = overlay.get();
  overlays_.push_back(std::move(overlay));
  overlay_bindings_.AddBinding(overlay_ptr, std::move(request));
}

void DomainAutomationHost::AddServiceWorkerBinding(automation::ServiceWorkerAssociatedRequest request) {
  //DLOG(INFO) << "DomainAutomationHost::AddServiceWorkerBinding";
  auto worker = std::make_unique<DomainWorkerImpl>(this);
  DomainWorkerImpl* worker_ptr = worker.get();
  workers_.push_back(std::move(worker));
  service_worker_bindings_.AddBinding(worker_ptr, std::move(request));
}

void DomainAutomationHost::AddStorageBinding(automation::StorageAssociatedRequest request) {
  //DLOG(INFO) << "DomainAutomationHost::AddStorageBinding";
  auto storage = std::make_unique<DomainStorageImpl>(this);
  DomainStorageImpl* storage_ptr = storage.get();
  storages_.push_back(std::move(storage));
  storage_bindings_.AddBinding(storage_ptr, std::move(request));
}

void DomainAutomationHost::AddSystemInfoBinding(automation::SystemInfoAssociatedRequest request) {
  //DLOG(INFO) << "DomainAutomationHost::AddSystemInfoBinding";
  auto system = std::make_unique<DomainSystemInfoImpl>(this);
  DomainSystemInfoImpl* system_ptr = system.get();
  systems_.push_back(std::move(system));
  system_info_bindings_.AddBinding(system_ptr, std::move(request));
}

void DomainAutomationHost::AddTetheringBinding(automation::TetheringAssociatedRequest request) {
  //DLOG(INFO) << "DomainAutomationHost::AddTetheringBinding";
  auto tether = std::make_unique<DomainTetheringImpl>(this);
  DomainTetheringImpl* tether_ptr = tether.get();
  tetherings_.push_back(std::move(tether));
  tethering_bindings_.AddBinding(tether_ptr, std::move(request));
}

void DomainAutomationHost::MaybeObserve(scoped_refptr<ApplicationDriver> driver) {
  bool found = false;
  for (auto it = observed_.begin(); it != observed_.end(); it++) {
    if (*it == driver.get()) {
      found = true;
      break;
    }
  }
  if (!found) {
    driver->AddObserver(this);
    observed_.push_back(std::move(driver));
  }
}

void DomainAutomationHost::OnFrameAttached(const std::string& frame_id, const std::string& parent_frame_id) {
  HostThread::PostTask(HostThread::IO, 
                       FROM_HERE,
                       base::BindOnce(&DomainAutomationHost::OnFrameAttachedImpl, 
                                      base::Unretained(this),
                                      frame_id,
                                      parent_frame_id));
}

void DomainAutomationHost::OnDomContentEventFired(int64_t timestamp) {
  HostThread::PostTask(HostThread::IO, 
                       FROM_HERE,
                       base::BindOnce(&DomainAutomationHost::OnDomContentEventFiredImpl, 
                                      base::Unretained(this),
                                      timestamp));
}

void DomainAutomationHost::OnFrameClearedScheduledNavigation(const std::string& frame_id) {
  HostThread::PostTask(HostThread::IO, 
                       FROM_HERE,
                       base::BindOnce(&DomainAutomationHost::OnFrameClearedScheduledNavigationImpl, 
                                      base::Unretained(this),
                                      frame_id));
}

void DomainAutomationHost::OnFrameDetached(const std::string& frame_id) {
  HostThread::PostTask(HostThread::IO, 
                       FROM_HERE,
                       base::BindOnce(&DomainAutomationHost::OnFrameDetachedImpl, 
                                      base::Unretained(this),
                                      frame_id));
}

void DomainAutomationHost::OnFrameNavigated(automation::FramePtr frame) {
  HostThread::PostTask(HostThread::IO, 
                       FROM_HERE,
                       base::BindOnce(&DomainAutomationHost::OnFrameNavigatedImpl, 
                                      base::Unretained(this),
                                      base::Passed(std::move(frame))));
}

void DomainAutomationHost::OnFrameResized() {
  HostThread::PostTask(HostThread::IO, 
                       FROM_HERE,
                       base::BindOnce(&DomainAutomationHost::OnFrameResizedImpl, 
                                      base::Unretained(this)));
}

void DomainAutomationHost::OnFrameScheduledNavigation(const std::string& frame_id, int32_t delay, automation::NavigationReason reason, const std::string& url) {
  HostThread::PostTask(HostThread::IO, 
                       FROM_HERE,
                       base::BindOnce(&DomainAutomationHost::OnFrameScheduledNavigationImpl, 
                                      base::Unretained(this),
                                      frame_id,
                                      delay,
                                      reason,
                                      url));
}

void DomainAutomationHost::OnFrameStartedLoading(const std::string& frame_id) {
  HostThread::PostTask(HostThread::IO, 
                       FROM_HERE,
                       base::BindOnce(&DomainAutomationHost::OnFrameStartedLoadingImpl, 
                                      base::Unretained(this),
                                      frame_id));
}

void DomainAutomationHost::OnFrameStoppedLoading(const std::string& frame_id) {
  HostThread::PostTask(HostThread::IO, 
                       FROM_HERE,
                       base::BindOnce(&DomainAutomationHost::OnFrameStoppedLoadingImpl, 
                                      base::Unretained(this),
                                      frame_id));
}

void DomainAutomationHost::OnInterstitialHidden() {
  HostThread::PostTask(HostThread::IO, 
                       FROM_HERE,
                       base::BindOnce(&DomainAutomationHost::OnInterstitialHiddenImpl, 
                                      base::Unretained(this)));
}

void DomainAutomationHost::OnInterstitialShown() {
  HostThread::PostTask(HostThread::IO, 
                       FROM_HERE,
                       base::BindOnce(&DomainAutomationHost::OnInterstitialShownImpl, 
                                      base::Unretained(this)));
}

void DomainAutomationHost::OnJavascriptDialogClosed(bool result, const std::string& user_input) {
  HostThread::PostTask(HostThread::IO, 
                       FROM_HERE,
                       base::BindOnce(&DomainAutomationHost::OnJavascriptDialogClosedImpl, 
                                      base::Unretained(this),
                                      result,
                                      user_input));
}

void DomainAutomationHost::OnJavascriptDialogOpening(const std::string& url, const std::string& message, automation::DialogType type, bool has_browser_handler, const base::Optional<std::string>& default_prompt) {
  HostThread::PostTask(HostThread::IO, 
                       FROM_HERE,
                       base::BindOnce(&DomainAutomationHost::OnJavascriptDialogOpeningImpl, 
                                      base::Unretained(this),
                                      url, 
                                      message, 
                                      type, 
                                      has_browser_handler, 
                                      default_prompt));
}

void DomainAutomationHost::OnLifecycleEvent(const std::string& frame_id, int32_t loader_id, const std::string& name, int64_t timestamp) {
  HostThread::PostTask(HostThread::IO, 
                       FROM_HERE,
                       base::BindOnce(&DomainAutomationHost::OnLifecycleEventImpl, 
                                      base::Unretained(this),
                                      frame_id, 
                                      loader_id, 
                                      name, 
                                      timestamp));
}

void DomainAutomationHost::OnLoadEventFired(int64_t timestamp) {
  HostThread::PostTask(HostThread::IO, 
                       FROM_HERE,
                       base::BindOnce(&DomainAutomationHost::OnLoadEventFiredImpl, 
                                      base::Unretained(this),
                                      timestamp));
}

void DomainAutomationHost::OnNavigatedWithinDocument(const std::string& frame_id, const std::string& url) {
  HostThread::PostTask(HostThread::IO, 
                       FROM_HERE,
                       base::BindOnce(&DomainAutomationHost::OnNavigatedWithinDocumentImpl, 
                                      base::Unretained(this),
                                      frame_id,
                                      url));
}

void DomainAutomationHost::OnScreencastFrame(const std::string& base64_data, automation::ScreencastFrameMetadataPtr metadata, int32_t session_id) {
  HostThread::PostTask(HostThread::IO, 
                       FROM_HERE,
                       base::BindOnce(&DomainAutomationHost::OnScreencastFrameImpl, 
                                      base::Unretained(this),
                                      base64_data, 
                                      std::move(metadata), 
                                      session_id));
}

void DomainAutomationHost::OnScreencastVisibilityChanged(bool visible) {
  HostThread::PostTask(HostThread::IO, 
                       FROM_HERE,
                       base::BindOnce(&DomainAutomationHost::OnScreencastVisibilityChangedImpl, 
                                      base::Unretained(this),
                                      visible));
}

void DomainAutomationHost::OnWindowOpen(const std::string& url, const std::string& window_name, const std::vector<std::string>& window_features, bool user_gesture) {
  HostThread::PostTask(HostThread::IO, 
                       FROM_HERE,
                       base::BindOnce(&DomainAutomationHost::OnWindowOpenImpl, 
                                      base::Unretained(this),
                                      url, 
                                      window_name, 
                                      window_features, 
                                      user_gesture));
}

void DomainAutomationHost::OnPageLayoutInvalidated(bool resized) {
  HostThread::PostTask(HostThread::IO, 
                       FROM_HERE,
                       base::BindOnce(&DomainAutomationHost::OnPageLayoutInvalidatedImpl, 
                                      base::Unretained(this),
                                      resized));
}

void DomainAutomationHost::InspectNodeRequested(int32_t backend_node_id) {
  HostThread::PostTask(HostThread::IO, 
                       FROM_HERE,
                       base::BindOnce(&DomainAutomationHost::InspectNodeRequestedImpl, 
                                      base::Unretained(this),
                                      backend_node_id));
}

void DomainAutomationHost::NodeHighlightRequested(int32_t node_id) {
  HostThread::PostTask(HostThread::IO, 
                       FROM_HERE,
                       base::BindOnce(&DomainAutomationHost::NodeHighlightRequestedImpl, 
                                      base::Unretained(this),
                                      node_id));
}

void DomainAutomationHost::ScreenshotRequested(automation::ViewportPtr viewport) {
  HostThread::PostTask(HostThread::IO, 
                       FROM_HERE,
                       base::BindOnce(&DomainAutomationHost::ScreenshotRequestedImpl, 
                                      base::Unretained(this),
                                      base::Passed(std::move(viewport))));
}

void DomainAutomationHost::WorkerErrorReported(automation::ServiceWorkerErrorMessagePtr error_message) {
  HostThread::PostTask(HostThread::IO, 
                       FROM_HERE,
                       base::BindOnce(&DomainAutomationHost::WorkerErrorReportedImpl, 
                                      base::Unretained(this),
                                      base::Passed(std::move(error_message))));
}

void DomainAutomationHost::WorkerRegistrationUpdated(std::vector<automation::ServiceWorkerRegistrationPtr> registrations) {
  HostThread::PostTask(HostThread::IO, 
                       FROM_HERE,
                       base::BindOnce(&DomainAutomationHost::WorkerRegistrationUpdatedImpl, 
                                      base::Unretained(this),
                                      base::Passed(std::move(registrations))));
}

void DomainAutomationHost::WorkerVersionUpdated(std::vector<automation::ServiceWorkerVersionPtr> versions) {
  HostThread::PostTask(HostThread::IO, 
                       FROM_HERE,
                       base::BindOnce(&DomainAutomationHost::WorkerVersionUpdatedImpl, 
                                      base::Unretained(this),
                                      base::Passed(std::move(versions))));
}

void DomainAutomationHost::OnAttachedToTarget(const std::string& session_id, automation::TargetInfoPtr target_info, bool waiting_for_debugger) {
  HostThread::PostTask(HostThread::IO, 
                       FROM_HERE,
                       base::BindOnce(&DomainAutomationHost::OnAttachedToTargetImpl, 
                                      base::Unretained(this),
                                      session_id, 
                                      base::Passed(std::move(target_info)), 
                                      waiting_for_debugger));
}

void DomainAutomationHost::OnDetachedFromTarget(const std::string& session_id, const base::Optional<std::string>& target_id) {
  HostThread::PostTask(HostThread::IO, 
                       FROM_HERE,
                       base::BindOnce(&DomainAutomationHost::OnDetachedFromTargetImpl, 
                                      base::Unretained(this),
                                      session_id, 
                                      target_id));
}

void DomainAutomationHost::OnReceivedMessageFromTarget(const std::string& session_id, const std::string& message, const base::Optional<std::string>& target_id) {
  HostThread::PostTask(HostThread::IO, 
                       FROM_HERE,
                       base::BindOnce(&DomainAutomationHost::OnReceivedMessageFromTargetImpl, 
                                      base::Unretained(this),
                                      session_id, 
                                      message, 
                                      target_id));
}

void DomainAutomationHost::OnCacheStorageContentUpdated(const std::string& origin, const std::string& cache_name) {
  HostThread::PostTask(HostThread::IO, 
                       FROM_HERE,
                       base::BindOnce(&DomainAutomationHost::OnCacheStorageContentUpdatedImpl, 
                                      base::Unretained(this),
                                      origin,
                                      cache_name));
}

void DomainAutomationHost::OnCacheStorageListUpdated(const std::string& origin) {
  HostThread::PostTask(HostThread::IO, 
                       FROM_HERE,
                       base::BindOnce(&DomainAutomationHost::OnCacheStorageListUpdatedImpl, 
                                      base::Unretained(this),
                                      origin));
}

void DomainAutomationHost::OnIndexedDBContentUpdated(const std::string& origin, const std::string& database_name, const std::string& object_store_name) {
  HostThread::PostTask(HostThread::IO, 
                       FROM_HERE,
                       base::BindOnce(&DomainAutomationHost::OnIndexedDBContentUpdatedImpl, 
                                      base::Unretained(this),
                                      origin, 
                                      database_name, 
                                      object_store_name));
}

void DomainAutomationHost::OnIndexedDBListUpdated(const std::string& origin) {
  HostThread::PostTask(HostThread::IO, 
                       FROM_HERE,
                       base::BindOnce(&DomainAutomationHost::OnIndexedDBListUpdatedImpl, 
                                      base::Unretained(this),
                                      origin));
}

void DomainAutomationHost::OnAccepted(int32_t port, const std::string& connection_id) {
  HostThread::PostTask(HostThread::IO, 
                       FROM_HERE,
                       base::BindOnce(&DomainAutomationHost::OnAcceptedImpl, 
                                      base::Unretained(this),
                                      port, 
                                      connection_id));
}

void DomainAutomationHost::OnDataReceived(const std::string& request_id, int64_t timestamp, int64_t data_length, int64_t encoded_data_length) {
  HostThread::PostTask(HostThread::IO, 
                       FROM_HERE,
                       base::BindOnce(&DomainAutomationHost::OnDataReceivedImpl, 
                                      base::Unretained(this),
                                      request_id, 
                                      timestamp, 
                                      data_length, 
                                      encoded_data_length));
}

void DomainAutomationHost::OnEventSourceMessageReceived(const std::string& request_id, int64_t timestamp, const std::string& event_name, const std::string& event_id, const std::string& data) {
  HostThread::PostTask(HostThread::IO, 
                       FROM_HERE,
                       base::BindOnce(&DomainAutomationHost::OnEventSourceMessageReceivedImpl, 
                                      base::Unretained(this),
                                      request_id, 
                                      timestamp, 
                                      event_name, 
                                      event_id, 
                                      data));
}

void DomainAutomationHost::OnLoadingFailed(const std::string& request_id, int64_t timestamp, automation::ResourceType type, const std::string& error_text, bool canceled, automation::BlockedReason blocked_reason) {
  HostThread::PostTask(HostThread::IO, 
                       FROM_HERE,
                       base::BindOnce(&DomainAutomationHost::OnLoadingFailedImpl, 
                                      base::Unretained(this),
                                      request_id, 
                                      timestamp, 
                                      type, 
                                      error_text, 
                                      canceled, 
                                      blocked_reason));
}

void DomainAutomationHost::OnLoadingFinished(const std::string& request_id, int64_t timestamp, int64_t encoded_data_length, bool blocked_cross_site_document) {
  HostThread::PostTask(HostThread::IO, 
                       FROM_HERE,
                       base::BindOnce(&DomainAutomationHost::OnLoadingFinishedImpl, 
                                      base::Unretained(this),
                                      request_id, 
                                      timestamp, 
                                      encoded_data_length, 
                                      blocked_cross_site_document));
}

void DomainAutomationHost::OnRequestIntercepted(const std::string& interceptionId, automation::RequestPtr request, const std::string& frame_id, automation::ResourceType resource_type, bool is_navigation_request, bool is_download, const base::Optional<std::string>& redirect_url, automation::AuthChallengePtr auth_challenge, automation::ErrorReason response_error_reason, int32_t response_status_code, const base::Optional<base::flat_map<std::string, std::string>>& response_headers) {
  HostThread::PostTask(HostThread::IO, 
                       FROM_HERE,
                       base::BindOnce(&DomainAutomationHost::OnRequestInterceptedImpl, 
                                      base::Unretained(this),
                                      interceptionId, 
                                      base::Passed(std::move(request)), 
                                      frame_id, 
                                      resource_type, 
                                      is_navigation_request, 
                                      is_download, 
                                      redirect_url, 
                                      base::Passed(std::move(auth_challenge)), 
                                      response_error_reason, 
                                      response_status_code, 
                                      response_headers));
}

void DomainAutomationHost::OnRequestServedFromCache(const std::string& request_id) {
  HostThread::PostTask(HostThread::IO, 
                       FROM_HERE,
                       base::BindOnce(&DomainAutomationHost::OnRequestServedFromCacheImpl, 
                                      base::Unretained(this),
                                      request_id));
}

void DomainAutomationHost::OnRequestWillBeSent(const std::string& request_id, const std::string& loader_id, const std::string& document_url, automation::RequestPtr request, int64_t timestamp, int64_t wall_time, automation::InitiatorPtr initiator, automation::ResponsePtr redirect_response, automation::ResourceType type, const base::Optional<std::string>& frame_id, bool has_user_gesture) {
  HostThread::PostTask(HostThread::IO, 
                       FROM_HERE,
                       base::BindOnce(&DomainAutomationHost::OnRequestWillBeSentImpl, 
                                      base::Unretained(this),
                                      request_id, 
                                      loader_id, 
                                      document_url, 
                                      base::Passed(std::move(request)), 
                                      timestamp, 
                                      wall_time, 
                                      base::Passed(std::move(initiator)), 
                                      base::Passed(std::move(redirect_response)), 
                                      type, 
                                      frame_id, 
                                      has_user_gesture));
}

void DomainAutomationHost::OnResourceChangedPriority(const std::string& request_id, automation::ResourcePriority new_priority, int64_t timestamp) {
  HostThread::PostTask(HostThread::IO, 
                       FROM_HERE,
                       base::BindOnce(&DomainAutomationHost::OnResourceChangedPriorityImpl, 
                                      base::Unretained(this),
                                      request_id, 
                                      new_priority, 
                                      timestamp));
}

void DomainAutomationHost::OnResponseReceived(const std::string& request_id, const std::string& loader_id, int64_t timestamp, automation::ResourceType type, automation::ResponsePtr response, const base::Optional<std::string>& frame_id) {
  HostThread::PostTask(HostThread::IO, 
                       FROM_HERE,
                       base::BindOnce(&DomainAutomationHost::OnResponseReceivedImpl, 
                                      base::Unretained(this),
                                      request_id, 
                                      loader_id, 
                                      timestamp, 
                                      type, 
                                      base::Passed(std::move(response)), 
                                      frame_id));
}

void DomainAutomationHost::OnWebSocketClosed(const std::string& request_id, int64_t timestamp) {
  HostThread::PostTask(HostThread::IO, 
                       FROM_HERE,
                       base::BindOnce(&DomainAutomationHost::OnWebSocketClosedImpl, 
                                      base::Unretained(this),
                                      request_id,
                                      timestamp));
}

void DomainAutomationHost::OnWebSocketCreated(const std::string& request_id, const std::string& url, automation::InitiatorPtr initiator) {
  HostThread::PostTask(HostThread::IO, 
                       FROM_HERE,
                       base::BindOnce(&DomainAutomationHost::OnWebSocketCreatedImpl, 
                                      base::Unretained(this),
                                      request_id, 
                                      url, 
                                      base::Passed(std::move(initiator))));
}

void DomainAutomationHost::OnWebSocketFrameError(const std::string& request_id, int64_t timestamp, const std::string& error_message) {
  HostThread::PostTask(HostThread::IO, 
                       FROM_HERE,
                       base::BindOnce(&DomainAutomationHost::OnWebSocketFrameErrorImpl, 
                                      base::Unretained(this),
                                      request_id,
                                      timestamp,
                                      error_message));
}

void DomainAutomationHost::OnWebSocketFrameReceived(const std::string& request_id, int64_t timestamp, automation::WebSocketFramePtr response) {
  HostThread::PostTask(HostThread::IO, 
                       FROM_HERE,
                       base::BindOnce(&DomainAutomationHost::OnWebSocketFrameReceivedImpl, 
                                      base::Unretained(this),
                                      request_id, 
                                      timestamp, 
                                      base::Passed(std::move(response))));
}

void DomainAutomationHost::OnWebSocketFrameSent(const std::string& request_id, int64_t timestamp, automation::WebSocketFramePtr response) {
  HostThread::PostTask(HostThread::IO, 
                       FROM_HERE,
                       base::BindOnce(&DomainAutomationHost::OnWebSocketFrameSentImpl, 
                                      base::Unretained(this),
                                      request_id, 
                                      timestamp, 
                                      base::Passed(std::move(response))));
}

void DomainAutomationHost::OnWebSocketHandshakeResponseReceived(const std::string& request_id, int64_t timestamp, automation::WebSocketResponsePtr response) {
  HostThread::PostTask(HostThread::IO, 
                       FROM_HERE,
                       base::BindOnce(&DomainAutomationHost::OnWebSocketHandshakeResponseReceivedImpl, 
                                      base::Unretained(this),
                                      request_id, 
                                      timestamp, 
                                      base::Passed(std::move(response))));
}

void DomainAutomationHost::OnWebSocketWillSendHandshakeRequest(const std::string& request_id, int64_t timestamp, int64_t wall_time, automation::WebSocketRequestPtr request) {
  HostThread::PostTask(HostThread::IO, 
                       FROM_HERE,
                       base::BindOnce(&DomainAutomationHost::OnWebSocketWillSendHandshakeRequestImpl, 
                                      base::Unretained(this),
                                      request_id, 
                                      timestamp, 
                                      wall_time, 
                                      base::Passed(std::move(request))));
}

void DomainAutomationHost::Flush() {
  HostThread::PostTask(HostThread::IO, 
                       FROM_HERE,
                       base::BindOnce(&DomainAutomationHost::FlushImpl, 
                                      base::Unretained(this)));
}

void DomainAutomationHost::OnLayerPainted(const std::string& layer_id, const gfx::Rect& clip) {
  HostThread::PostTask(HostThread::IO, 
                       FROM_HERE,
                       base::BindOnce(&DomainAutomationHost::OnLayerPaintedImpl, 
                                      base::Unretained(this),
                                      layer_id,
                                      clip));
}

void DomainAutomationHost::OnLayerTreeDidChange(base::Optional<std::vector<automation::LayerPtr>> layers) {
  HostThread::PostTask(HostThread::IO, 
                       FROM_HERE,
                       base::BindOnce(&DomainAutomationHost::OnLayerTreeDidChangeImpl, 
                                      base::Unretained(this),
                                      base::Passed(std::move(layers))));
}

void DomainAutomationHost::OnNeedsBeginFramesChanged(bool needs_begin_frames) {
  HostThread::PostTask(HostThread::IO, 
                       FROM_HERE,
                       base::BindOnce(&DomainAutomationHost::OnNeedsBeginFramesChangedImpl, 
                                      base::Unretained(this),
                                      needs_begin_frames));
}

void DomainAutomationHost::OnDomStorageItemAdded(automation::StorageIdPtr storage_id, const std::string& key, const std::string& new_value) {
  HostThread::PostTask(HostThread::IO, 
                       FROM_HERE,
                       base::BindOnce(&DomainAutomationHost::OnDomStorageItemAddedImpl, 
                                      base::Unretained(this),
                                      base::Passed(std::move(storage_id)),
                                      key, 
                                      new_value));
}

void DomainAutomationHost::OnDomStorageItemRemoved(automation::StorageIdPtr storage_id, const std::string& key) {
  HostThread::PostTask(HostThread::IO, 
                       FROM_HERE,
                       base::BindOnce(&DomainAutomationHost::OnDomStorageItemRemovedImpl, 
                                      base::Unretained(this),
                                      base::Passed(std::move(storage_id)),
                                      key));
}

void DomainAutomationHost::OnDomStorageItemUpdated(automation::StorageIdPtr storage_id, const std::string& key, const std::string& old_value, const std::string& new_value) {
  HostThread::PostTask(HostThread::IO, 
                       FROM_HERE,
                       base::BindOnce(&DomainAutomationHost::OnDomStorageItemUpdatedImpl, 
                                      base::Unretained(this),
                                      base::Passed(std::move(storage_id)),
                                      key, 
                                      old_value, 
                                      new_value));
}

void DomainAutomationHost::OnDomStorageItemsCleared(automation::StorageIdPtr storage_id) {
  HostThread::PostTask(HostThread::IO, 
                       FROM_HERE,
                       base::BindOnce(&DomainAutomationHost::OnDomStorageItemsClearedImpl, 
                                      base::Unretained(this),
                                      base::Passed(std::move(storage_id))));
}

void DomainAutomationHost::OnAddDatabase(automation::DatabasePtr database) {
  HostThread::PostTask(HostThread::IO, 
                       FROM_HERE,
                       base::BindOnce(&DomainAutomationHost::OnAddDatabaseImpl, 
                                      base::Unretained(this),
                                      base::Passed(std::move(database))));
}

void DomainAutomationHost::OnVirtualTimeAdvanced(int32_t virtual_time_elapsed) {
  HostThread::PostTask(HostThread::IO, 
                       FROM_HERE,
                       base::BindOnce(&DomainAutomationHost::OnVirtualTimeAdvancedImpl, 
                                      base::Unretained(this),
                                      virtual_time_elapsed));
}

void DomainAutomationHost::OnVirtualTimeBudgetExpired() {
  HostThread::PostTask(HostThread::IO, 
                       FROM_HERE,
                       base::BindOnce(&DomainAutomationHost::OnVirtualTimeBudgetExpiredImpl, 
                                      base::Unretained(this)));
}

void DomainAutomationHost::OnVirtualTimePaused(int32_t virtual_time_elapsed) {
  HostThread::PostTask(HostThread::IO, 
                       FROM_HERE,
                       base::BindOnce(&DomainAutomationHost::OnVirtualTimePausedImpl, 
                                      base::Unretained(this),
                                      virtual_time_elapsed));
}

void DomainAutomationHost::SetChildNodes(int32_t parent_id, std::vector<automation::DOMNodePtr> nodes) {
  HostThread::PostTask(HostThread::IO, 
                       FROM_HERE,
                       base::BindOnce(&DomainAutomationHost::SetChildNodesImpl, 
                                      base::Unretained(this),
                                      parent_id, 
                                      base::Passed(std::move(nodes))));
}

void DomainAutomationHost::OnAttributeModified(int32_t node_id, const std::string& name, const std::string& value) {
  HostThread::PostTask(HostThread::IO, 
                       FROM_HERE,
                       base::BindOnce(&DomainAutomationHost::OnAttributeModifiedImpl, 
                                      base::Unretained(this),
                                      node_id, 
                                      name, 
                                      value));
}

void DomainAutomationHost::OnAttributeRemoved(int32_t node_id, const std::string& name) {
  HostThread::PostTask(HostThread::IO, 
                       FROM_HERE,
                       base::BindOnce(&DomainAutomationHost::OnAttributeRemovedImpl, 
                                      base::Unretained(this),
                                      node_id, 
                                      name));
}

void DomainAutomationHost::OnCharacterDataModified(int32_t node_id, const std::string& character_data) {
  HostThread::PostTask(HostThread::IO, 
                       FROM_HERE,
                       base::BindOnce(&DomainAutomationHost::OnCharacterDataModifiedImpl, 
                                      base::Unretained(this),
                                      node_id, 
                                      character_data));
}

void DomainAutomationHost::OnChildNodeCountUpdated(int32_t node_id, int32_t child_node_count) {
  HostThread::PostTask(HostThread::IO, 
                       FROM_HERE,
                       base::BindOnce(&DomainAutomationHost::OnChildNodeCountUpdatedImpl, 
                                      base::Unretained(this),
                                      node_id, 
                                      child_node_count));
}

void DomainAutomationHost::OnChildNodeInserted(int32_t parent_node_id, int32_t previous_node_id, automation::DOMNodePtr node) {
  HostThread::PostTask(HostThread::IO, 
                       FROM_HERE,
                       base::BindOnce(&DomainAutomationHost::OnChildNodeInsertedImpl, 
                                      base::Unretained(this),
                                      parent_node_id, 
                                      previous_node_id, 
                                      std::move(node)));
}

void DomainAutomationHost::OnChildNodeRemoved(int32_t parent_node_id, int32_t node_id) {
  HostThread::PostTask(HostThread::IO, 
                       FROM_HERE,
                       base::BindOnce(&DomainAutomationHost::OnChildNodeRemovedImpl, 
                                      base::Unretained(this),
                                      parent_node_id, 
                                      node_id));
}

void DomainAutomationHost::OnDistributedNodesUpdated(int32_t insertion_point_id, std::vector<automation::BackendNodePtr> distributed_nodes) {
  HostThread::PostTask(HostThread::IO, 
                       FROM_HERE,
                       base::BindOnce(&DomainAutomationHost::OnDistributedNodesUpdatedImpl, 
                                      base::Unretained(this),
                                      insertion_point_id, 
                                      base::Passed(std::move(distributed_nodes))));
}

void DomainAutomationHost::OnDocumentUpdated() {
  HostThread::PostTask(HostThread::IO, 
                       FROM_HERE,
                       base::BindOnce(&DomainAutomationHost::OnDocumentUpdatedImpl, 
                                      base::Unretained(this)));
}

void DomainAutomationHost::OnInlineStyleInvalidated(const std::vector<int32_t>& node_ids) {
  HostThread::PostTask(HostThread::IO, 
                       FROM_HERE,
                       base::BindOnce(&DomainAutomationHost::OnInlineStyleInvalidatedImpl, 
                                      base::Unretained(this),
                                      node_ids));
}

void DomainAutomationHost::OnPseudoElementAdded(int32_t parent_id, automation::DOMNodePtr pseudo_element) {
  HostThread::PostTask(HostThread::IO, 
                       FROM_HERE,
                       base::BindOnce(&DomainAutomationHost::OnPseudoElementAddedImpl, 
                                      base::Unretained(this),
                                      parent_id,
                                      base::Passed(std::move(pseudo_element))));
}

void DomainAutomationHost::OnPseudoElementRemoved(int32_t parent_id, int32_t pseudo_element_id) {
  HostThread::PostTask(HostThread::IO, 
                       FROM_HERE,
                       base::BindOnce(&DomainAutomationHost::OnPseudoElementRemovedImpl, 
                                      base::Unretained(this),
                                      parent_id, 
                                      pseudo_element_id));
}

void DomainAutomationHost::OnShadowRootPopped(int32_t host_id, int32_t root_id) {
  HostThread::PostTask(HostThread::IO, 
                       FROM_HERE,
                       base::BindOnce(&DomainAutomationHost::OnShadowRootPoppedImpl, 
                                      base::Unretained(this),
                                      host_id,
                                      root_id));
}

void DomainAutomationHost::OnShadowRootPushed(int32_t host_id, automation::DOMNodePtr root) {
  HostThread::PostTask(HostThread::IO, 
                       FROM_HERE,
                       base::BindOnce(&DomainAutomationHost::OnShadowRootPushedImpl, 
                                      base::Unretained(this),
                                      host_id, 
                                      base::Passed(std::move(root))));
}

void DomainAutomationHost::OnFontsUpdated(automation::FontFacePtr font) {
  HostThread::PostTask(HostThread::IO, 
                       FROM_HERE,
                       base::BindOnce(&DomainAutomationHost::OnFontsUpdatedImpl, 
                                      base::Unretained(this),
                                      base::Passed(std::move(font))));
}

void DomainAutomationHost::OnMediaQueryResultChanged() {
  HostThread::PostTask(HostThread::IO, 
                       FROM_HERE,
                       base::BindOnce(&DomainAutomationHost::OnMediaQueryResultChangedImpl, 
                                      base::Unretained(this)));
}

void DomainAutomationHost::OnStyleSheetAdded(automation::CSSStyleSheetHeaderPtr header) {
  HostThread::PostTask(HostThread::IO, 
                       FROM_HERE,
                       base::BindOnce(&DomainAutomationHost::OnStyleSheetAddedImpl, 
                                      base::Unretained(this),
                                      base::Passed(std::move(header))));
}

void DomainAutomationHost::OnStyleSheetChanged(const std::string& style_sheet_id) {
  HostThread::PostTask(HostThread::IO, 
                       FROM_HERE,
                       base::BindOnce(&DomainAutomationHost::OnStyleSheetChangedImpl, 
                                      base::Unretained(this),
                                      style_sheet_id));
}

void DomainAutomationHost::OnStyleSheetRemoved(const std::string& style_sheet_id) {
  HostThread::PostTask(HostThread::IO, 
                       FROM_HERE,
                       base::BindOnce(&DomainAutomationHost::OnStyleSheetRemovedImpl, 
                                      base::Unretained(this),
                                      style_sheet_id));
}

void DomainAutomationHost::OnApplicationCacheStatusUpdated(const std::string& frame_id, const std::string& manifest_url, int32_t status) {
  HostThread::PostTask(HostThread::IO, 
                       FROM_HERE,
                       base::BindOnce(&DomainAutomationHost::OnApplicationCacheStatusUpdatedImpl, 
                                      base::Unretained(this),
                                      frame_id, 
                                      manifest_url, 
                                      status));
}

void DomainAutomationHost::OnNetworkStateUpdated(bool is_now_online) {
  HostThread::PostTask(HostThread::IO, 
                       FROM_HERE,
                       base::BindOnce(&DomainAutomationHost::OnNetworkStateUpdatedImpl, 
                                      base::Unretained(this),
                                      is_now_online));
}

void DomainAutomationHost::OnAnimationCanceled(const std::string& id) {
  HostThread::PostTask(HostThread::IO, 
                       FROM_HERE,
                       base::BindOnce(&DomainAutomationHost::OnAnimationCanceledImpl, 
                                      base::Unretained(this),
                                      id));
}

void DomainAutomationHost::OnAnimationCreated(const std::string& id) {
  HostThread::PostTask(HostThread::IO, 
                       FROM_HERE,
                       base::BindOnce(&DomainAutomationHost::OnAnimationCreatedImpl, 
                                      base::Unretained(this),
                                      id));
}

void DomainAutomationHost::OnAnimationStarted(automation::AnimationPtr animation) {
  HostThread::PostTask(HostThread::IO, 
                       FROM_HERE,
                       base::BindOnce(&DomainAutomationHost::OnAnimationStartedImpl, 
                                      base::Unretained(this),
                                      base::Passed(std::move(animation))));
}

/*
 *
 * Impl's
 * 
 */

void DomainAutomationHost::OnFrameAttachedImpl(const std::string& frame_id, const std::string& parent_frame_id) {
  page_client_->OnFrameAttached(frame_id, parent_frame_id);
}

void DomainAutomationHost::OnDomContentEventFiredImpl(int64_t timestamp) {
  page_client_->OnDomContentEventFired(timestamp);
}

void DomainAutomationHost::OnFrameClearedScheduledNavigationImpl(const std::string& frame_id) {
  page_client_->OnFrameClearedScheduledNavigation(frame_id);
}

void DomainAutomationHost::OnFrameDetachedImpl(const std::string& frame_id) {
  page_client_->OnFrameDetached(frame_id);
}

void DomainAutomationHost::OnFrameNavigatedImpl(automation::FramePtr frame) {
  page_client_->OnFrameNavigated(std::move(frame));
}

void DomainAutomationHost::OnFrameResizedImpl() {
  page_client_->OnFrameResized();
}

void DomainAutomationHost::OnFrameScheduledNavigationImpl(const std::string& frame_id, int32_t delay, automation::NavigationReason reason, const std::string& url) {
  page_client_->OnFrameScheduledNavigation(frame_id, delay, reason, url);
}

void DomainAutomationHost::OnFrameStartedLoadingImpl(const std::string& frame_id) {
  page_client_->OnFrameStartedLoading(frame_id);
}

void DomainAutomationHost::OnFrameStoppedLoadingImpl(const std::string& frame_id) {
  page_client_->OnFrameStoppedLoading(frame_id);
}

void DomainAutomationHost::OnInterstitialHiddenImpl() {
  page_client_->OnInterstitialHidden();
}

void DomainAutomationHost::OnInterstitialShownImpl() {
  page_client_->OnInterstitialShown();
}

void DomainAutomationHost::OnJavascriptDialogClosedImpl(bool result, const std::string& user_input) {
  page_client_->OnJavascriptDialogClosed(result, user_input);
}

void DomainAutomationHost::OnJavascriptDialogOpeningImpl(const std::string& url, const std::string& message, automation::DialogType type, bool has_browser_handler, const base::Optional<std::string>& default_prompt) {
  page_client_->OnJavascriptDialogOpening(url, message, type, has_browser_handler, default_prompt);
}

void DomainAutomationHost::OnLifecycleEventImpl(const std::string& frame_id, int32_t loader_id, const std::string& name, int64_t timestamp) {
  page_client_->OnLifecycleEvent(frame_id, loader_id, name, timestamp);
}

void DomainAutomationHost::OnLoadEventFiredImpl(int64_t timestamp) {
  page_client_->OnLoadEventFired(timestamp);
}

void DomainAutomationHost::OnNavigatedWithinDocumentImpl(const std::string& frame_id, const std::string& url) {
  page_client_->OnNavigatedWithinDocument(frame_id, url);
}

void DomainAutomationHost::OnScreencastFrameImpl(const std::string& base64_data, automation::ScreencastFrameMetadataPtr metadata, int32_t session_id) {
  page_client_->OnScreencastFrame(base64_data, std::move(metadata), session_id);
}

void DomainAutomationHost::OnScreencastVisibilityChangedImpl(bool visible) {
  page_client_->OnScreencastVisibilityChanged(visible);
}

void DomainAutomationHost::OnWindowOpenImpl(const std::string& url, const std::string& window_name, const std::vector<std::string>& window_features, bool user_gesture) {
  page_client_->OnWindowOpen(url, window_name, window_features, user_gesture);
}

void DomainAutomationHost::OnPageLayoutInvalidatedImpl(bool resized) {
  page_client_->OnPageLayoutInvalidated(resized);
}

void DomainAutomationHost::InspectNodeRequestedImpl(int32_t backend_node_id) {
  overlay_client_->InspectNodeRequested(backend_node_id);
}

void DomainAutomationHost::NodeHighlightRequestedImpl(int32_t node_id) {
  overlay_client_->NodeHighlightRequested(node_id);
}

void DomainAutomationHost::ScreenshotRequestedImpl(automation::ViewportPtr viewport) {
  overlay_client_->ScreenshotRequested(std::move(viewport));
}

void DomainAutomationHost::WorkerErrorReportedImpl(automation::ServiceWorkerErrorMessagePtr error_message) {
  service_worker_client_->WorkerErrorReported(std::move(error_message));
}

void DomainAutomationHost::WorkerRegistrationUpdatedImpl(std::vector<automation::ServiceWorkerRegistrationPtr> registrations) {
  service_worker_client_->WorkerRegistrationUpdated(std::move(registrations));
}

void DomainAutomationHost::WorkerVersionUpdatedImpl(std::vector<automation::ServiceWorkerVersionPtr> versions) {
  service_worker_client_->WorkerVersionUpdated(std::move(versions));
}

void DomainAutomationHost::OnAttachedToTargetImpl(const std::string& session_id, automation::TargetInfoPtr target_info, bool waiting_for_debugger) {
  service_worker_client_->OnAttachedToTarget(session_id, std::move(target_info), waiting_for_debugger);
}

void DomainAutomationHost::OnDetachedFromTargetImpl(const std::string& session_id, const base::Optional<std::string>& target_id) {
  service_worker_client_->OnDetachedFromTarget(session_id, target_id);
}

void DomainAutomationHost::OnReceivedMessageFromTargetImpl(const std::string& session_id, const std::string& message, const base::Optional<std::string>& target_id) {
  service_worker_client_->OnReceivedMessageFromTarget(session_id, message, target_id);
}

void DomainAutomationHost::OnCacheStorageContentUpdatedImpl(const std::string& origin, const std::string& cache_name) {
  storage_client_->OnCacheStorageContentUpdated(origin, cache_name);
}

void DomainAutomationHost::OnCacheStorageListUpdatedImpl(const std::string& origin) {
  storage_client_->OnCacheStorageListUpdated(origin);
}

void DomainAutomationHost::OnIndexedDBContentUpdatedImpl(const std::string& origin, const std::string& database_name, const std::string& object_store_name) {
  storage_client_->OnIndexedDBContentUpdated(origin, database_name, object_store_name);
}

void DomainAutomationHost::OnIndexedDBListUpdatedImpl(const std::string& origin) {
  storage_client_->OnIndexedDBListUpdated(origin);
}

void DomainAutomationHost::OnAcceptedImpl(int32_t port, const std::string& connection_id) {
  tethering_client_->OnAccepted(port, connection_id);
}

void DomainAutomationHost::OnDataReceivedImpl(const std::string& request_id, int64_t timestamp, int64_t data_length, int64_t encoded_data_length) {
  network_client_->OnDataReceived(request_id, timestamp, data_length, encoded_data_length);
}

void DomainAutomationHost::OnEventSourceMessageReceivedImpl(const std::string& request_id, int64_t timestamp, const std::string& event_name, const std::string& event_id, const std::string& data) {
  network_client_->OnEventSourceMessageReceived(request_id, timestamp, event_name, event_id, data);
}

void DomainAutomationHost::OnLoadingFailedImpl(const std::string& request_id, int64_t timestamp, automation::ResourceType type, const std::string& error_text, bool canceled, automation::BlockedReason blocked_reason) {
  network_client_->OnLoadingFailed(request_id, timestamp, type, error_text, canceled, blocked_reason);
}

void DomainAutomationHost::OnLoadingFinishedImpl(const std::string& request_id, int64_t timestamp, int64_t encoded_data_length, bool blocked_cross_site_document) {
  network_client_->OnLoadingFinished(request_id, timestamp, encoded_data_length, blocked_cross_site_document);
}

void DomainAutomationHost::OnRequestInterceptedImpl(const std::string& interception_id, automation::RequestPtr request, const std::string& frame_id, automation::ResourceType resource_type, bool is_navigation_request, bool is_download, const base::Optional<std::string>& redirect_url, automation::AuthChallengePtr auth_challenge, automation::ErrorReason response_error_reason, int32_t response_status_code, const base::Optional<base::flat_map<std::string, std::string>>& response_headers) {
  network_client_->OnRequestIntercepted(interception_id, std::move(request), frame_id, resource_type, is_navigation_request, is_download, redirect_url, std::move(auth_challenge), response_error_reason, response_status_code, response_headers);
}

void DomainAutomationHost::OnRequestServedFromCacheImpl(const std::string& request_id) {
  network_client_->OnRequestServedFromCache(request_id);
}

void DomainAutomationHost::OnRequestWillBeSentImpl(const std::string& request_id, const std::string& loader_id, const std::string& document_url, automation::RequestPtr request, int64_t timestamp, int64_t wall_time, automation::InitiatorPtr initiator, automation::ResponsePtr redirect_response, automation::ResourceType type, const base::Optional<std::string>& frame_id, bool has_user_gesture) {
  network_client_->OnRequestWillBeSent(request_id, loader_id, document_url, std::move(request), timestamp, wall_time, std::move(initiator), std::move(redirect_response), type, frame_id, has_user_gesture);
}

void DomainAutomationHost::OnResourceChangedPriorityImpl(const std::string& request_id, automation::ResourcePriority new_priority, int64_t timestamp) {
  network_client_->OnResourceChangedPriority(request_id, new_priority, timestamp);
}

void DomainAutomationHost::OnResponseReceivedImpl(const std::string& request_id, const std::string& loader_id, int64_t timestamp, automation::ResourceType type, automation::ResponsePtr response, const base::Optional<std::string>& frame_id) {
  network_client_->OnResponseReceived(request_id, loader_id, timestamp, type, std::move(response), frame_id);
}

void DomainAutomationHost::OnWebSocketClosedImpl(const std::string& request_id, int64_t timestamp) {
  network_client_->OnWebSocketClosed(request_id, timestamp);
}

void DomainAutomationHost::OnWebSocketCreatedImpl(const std::string& request_id, const std::string& url, automation::InitiatorPtr initiator) {
  network_client_->OnWebSocketCreated(request_id, url, std::move(initiator));
}

void DomainAutomationHost::OnWebSocketFrameErrorImpl(const std::string& request_id, int64_t timestamp, const std::string& error_message) {
  network_client_->OnWebSocketFrameError(request_id, timestamp, error_message);
}

void DomainAutomationHost::OnWebSocketFrameReceivedImpl(const std::string& request_id, int64_t timestamp, automation::WebSocketFramePtr response) {
  network_client_->OnWebSocketFrameReceived(request_id, timestamp, std::move(response));
}

void DomainAutomationHost::OnWebSocketFrameSentImpl(const std::string& request_id, int64_t timestamp, automation::WebSocketFramePtr response) {
  network_client_->OnWebSocketFrameSent(request_id, timestamp, std::move(response));
}

void DomainAutomationHost::OnWebSocketHandshakeResponseReceivedImpl(const std::string& request_id, int64_t timestamp, automation::WebSocketResponsePtr response) {
  network_client_->OnWebSocketHandshakeResponseReceived(request_id, timestamp, std::move(response));
}

void DomainAutomationHost::OnWebSocketWillSendHandshakeRequestImpl(const std::string& request_id, int64_t timestamp, int64_t wall_time, automation::WebSocketRequestPtr request) {
  network_client_->OnWebSocketWillSendHandshakeRequest(request_id, timestamp, wall_time, std::move(request));
}

void DomainAutomationHost::FlushImpl() {
  network_client_->Flush();
}

void DomainAutomationHost::OnLayerPaintedImpl(const std::string& layer_id, const gfx::Rect& clip) {
  layer_tree_->OnLayerPainted(layer_id, clip);
}

void DomainAutomationHost::OnLayerTreeDidChangeImpl(base::Optional<std::vector<automation::LayerPtr>> layers) {
  layer_tree_->OnLayerTreeDidChange(std::move(layers));
}

void DomainAutomationHost::OnNeedsBeginFramesChangedImpl(bool needs_begin_frames) {
  headless_client_->OnNeedsBeginFramesChanged(needs_begin_frames);
}

void DomainAutomationHost::OnDomStorageItemAddedImpl(automation::StorageIdPtr storage_id, const std::string& key, const std::string& new_value) {
  dom_storage_client_->OnDomStorageItemAdded(std::move(storage_id), key, new_value);
}

void DomainAutomationHost::OnDomStorageItemRemovedImpl(automation::StorageIdPtr storage_id, const std::string& key) {
  dom_storage_client_->OnDomStorageItemRemoved(std::move(storage_id), key);
}

void DomainAutomationHost::OnDomStorageItemUpdatedImpl(automation::StorageIdPtr storage_id, const std::string& key, const std::string& old_value, const std::string& new_value) {
  dom_storage_client_->OnDomStorageItemUpdated(std::move(storage_id), key, old_value, new_value);
}

void DomainAutomationHost::OnDomStorageItemsClearedImpl(automation::StorageIdPtr storage_id) {
  dom_storage_client_->OnDomStorageItemsCleared(std::move(storage_id));
}

void DomainAutomationHost::OnAddDatabaseImpl(automation::DatabasePtr database) {
  database_client_->OnAddDatabase(std::move(database));
}

void DomainAutomationHost::OnVirtualTimeAdvancedImpl(int32_t virtual_time_elapsed) {
  emulation_client_->OnVirtualTimeAdvanced(virtual_time_elapsed);
}

void DomainAutomationHost::OnVirtualTimeBudgetExpiredImpl() {
  emulation_client_->OnVirtualTimeBudgetExpired();
}

void DomainAutomationHost::OnVirtualTimePausedImpl(int32_t virtual_time_elapsed) {
  emulation_client_->OnVirtualTimePaused(virtual_time_elapsed);
}

void DomainAutomationHost::SetChildNodesImpl(int32_t parent_id, std::vector<automation::DOMNodePtr> nodes) {
  dom_client_->SetChildNodes(parent_id, std::move(nodes));
}

void DomainAutomationHost::OnAttributeModifiedImpl(int32_t node_id, const std::string& name, const std::string& value) {
  dom_client_->OnAttributeModified(node_id, name, value);
}

void DomainAutomationHost::OnAttributeRemovedImpl(int32_t node_id, const std::string& name) {
  dom_client_->OnAttributeRemoved(node_id, name);
}

void DomainAutomationHost::OnCharacterDataModifiedImpl(int32_t node_id, const std::string& character_data) {
  dom_client_->OnCharacterDataModified(node_id, character_data);
}

void DomainAutomationHost::OnChildNodeCountUpdatedImpl(int32_t node_id, int32_t child_node_count) {
  dom_client_->OnChildNodeCountUpdated(node_id, child_node_count);
}

void DomainAutomationHost::OnChildNodeInsertedImpl(int32_t parent_node_id, int32_t previous_node_id, automation::DOMNodePtr node) {
  dom_client_->OnChildNodeInserted(parent_node_id, previous_node_id, std::move(node));
}

void DomainAutomationHost::OnChildNodeRemovedImpl(int32_t parent_node_id, int32_t node_id) {
  dom_client_->OnChildNodeRemoved(parent_node_id, node_id);
}

void DomainAutomationHost::OnDistributedNodesUpdatedImpl(int32_t insertion_point_id, std::vector<automation::BackendNodePtr> distributed_nodes) {
  dom_client_->OnDistributedNodesUpdated(insertion_point_id, std::move(distributed_nodes));
}

void DomainAutomationHost::OnDocumentUpdatedImpl()  {
  dom_client_->OnDocumentUpdated();
}

void DomainAutomationHost::OnInlineStyleInvalidatedImpl(const std::vector<int32_t>& node_ids) {
  dom_client_->OnInlineStyleInvalidated(node_ids);
}

void DomainAutomationHost::OnPseudoElementAddedImpl(int32_t parent_id, automation::DOMNodePtr pseudo_element) {
  dom_client_->OnPseudoElementAdded(parent_id, std::move(pseudo_element));
}

void DomainAutomationHost::OnPseudoElementRemovedImpl(int32_t parent_id, int32_t pseudo_element_id) {
  dom_client_->OnPseudoElementRemoved(parent_id, pseudo_element_id);
}

void DomainAutomationHost::OnShadowRootPoppedImpl(int32_t host_id, int32_t root_id) {
  dom_client_->OnShadowRootPopped(host_id, root_id);
}

void DomainAutomationHost::OnShadowRootPushedImpl(int32_t host_id, automation::DOMNodePtr root) {
  dom_client_->OnShadowRootPushed(host_id, std::move(root));
}

void DomainAutomationHost::OnFontsUpdatedImpl(automation::FontFacePtr font) {
  css_client_->OnFontsUpdated(std::move(font));
}

void DomainAutomationHost::OnMediaQueryResultChangedImpl() {
  css_client_->OnMediaQueryResultChanged();
}

void DomainAutomationHost::OnStyleSheetAddedImpl(automation::CSSStyleSheetHeaderPtr header) {
  css_client_->OnStyleSheetAdded(std::move(header));
}

void DomainAutomationHost::OnStyleSheetChangedImpl(const std::string& style_sheet_id) {
  css_client_->OnStyleSheetChanged(style_sheet_id);
}

void DomainAutomationHost::OnStyleSheetRemovedImpl(const std::string& style_sheet_id) {
  css_client_->OnStyleSheetRemoved(style_sheet_id);
}

void DomainAutomationHost::OnApplicationCacheStatusUpdatedImpl(const std::string& frame_id, const std::string& manifest_url, int32_t status) {
  application_cache_client_->OnApplicationCacheStatusUpdated(frame_id, manifest_url, status);
}

void DomainAutomationHost::OnNetworkStateUpdatedImpl(bool is_now_online) {
  application_cache_client_->OnNetworkStateUpdated(is_now_online);
}

void DomainAutomationHost::OnAnimationCanceledImpl(const std::string& id) {
  animation_client_->OnAnimationCanceled(id);
}

void DomainAutomationHost::OnAnimationCreatedImpl(const std::string& id) {
  animation_client_->OnAnimationCreated(id);
}

void DomainAutomationHost::OnAnimationStartedImpl(automation::AnimationPtr animation) {
  animation_client_->OnAnimationStarted(std::move(animation));
}

}