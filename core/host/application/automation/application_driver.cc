// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/application/automation/application_driver.h"

#include "base/bind.h"
#include "base/callback.h"
#include "core/host/host_thread.h"
#include "services/service_manager/public/cpp/connector.h"
#include "core/shared/common/service_manager/child_connection.h"
#include "core/shared/common/service_manager/service_manager_connection_impl.h"
#include "core/host/application/application.h"
#include "core/host/application/domain.h"

namespace host {

SystemInfoInterface::SystemInfoInterface() {

}

SystemInfoInterface::~SystemInfoInterface() {

}

void SystemInfoInterface::Register(int32_t application_id) {
  system_info_interface_->Register(application_id);
}

void SystemInfoInterface::GetInfo(automation::SystemInfo::GetInfoCallback callback) {
  system_info_interface_->GetInfo(std::move(callback));
}

HostInterface::HostInterface() {

}

HostInterface::~HostInterface() {

}

void HostInterface::Register(int32_t application_id) {
  DCHECK(host_interface_);
  host_interface_->Register(application_id);
}

void HostInterface::Close() {
  host_interface_->Close();  
}

void HostInterface::GetVersion(automation::Host::GetVersionCallback callback) {
  host_interface_->GetVersion(std::move(callback));  
}

void HostInterface::GetHostCommandLine(automation::Host::GetHostCommandLineCallback callback) {
  host_interface_->GetHostCommandLine(std::move(callback));  
}

void HostInterface::GetHistograms(const base::Optional<std::string>& query, automation::Host::GetHistogramsCallback callback) {
  host_interface_->GetHistograms(query, std::move(callback));
}

void HostInterface::GetHistogram(const std::string& name, automation::Host::GetHistogramCallback callback) {
  host_interface_->GetHistogram(name, std::move(callback));
}

void HostInterface::GetWindowBounds(int32_t window_id, automation::Host::GetWindowBoundsCallback callback) {
  host_interface_->GetWindowBounds(window_id, std::move(callback));
}

void HostInterface::GetWindowForTarget(const std::string& target_id, automation::Host::GetWindowForTargetCallback callback) {
  host_interface_->GetWindowForTarget(target_id, std::move(callback));
}

void HostInterface::SetWindowBounds(int32_t window_id, automation::BoundsPtr bounds) {
  host_interface_->SetWindowBounds(window_id, std::move(bounds));
}

PageInterface::PageInterface() {

}

PageInterface::~PageInterface() {

}

void PageInterface::Register(int32_t application_id) {
  DCHECK(page_interface_);
  page_interface_->Register(application_id);
}

void PageInterface::Enable() {
  page_interface_->Enable();
}

void PageInterface::Disable() {
  page_interface_->Disable();
}

void PageInterface::AddScriptToEvaluateOnNewDocument(const std::string& source, automation::Page::AddScriptToEvaluateOnNewDocumentCallback callback) {
  page_interface_->AddScriptToEvaluateOnNewDocument(source, std::move(callback));
}

void PageInterface::RemoveScriptToEvaluateOnNewDocument(const std::string& identifier) {
  page_interface_->RemoveScriptToEvaluateOnNewDocument(identifier);
}

void PageInterface::SetAutoAttachToCreatedPages(bool auto_attach) {
  page_interface_->SetAutoAttachToCreatedPages(auto_attach);
}

void PageInterface::SetLifecycleEventsEnabled(bool enabled) {
  page_interface_->SetLifecycleEventsEnabled(enabled);
}

void PageInterface::Reload(bool ignore_cache, const std::string& script_to_evaluate_on_load) {
  page_interface_->Reload(ignore_cache, script_to_evaluate_on_load);
}

void PageInterface::SetAdBlockingEnabled(bool enabled) {
  page_interface_->SetAdBlockingEnabled(enabled);
}

void PageInterface::Navigate(const std::string& url, const std::string& referrer, automation::TransitionType transition_type, automation::Page::NavigateCallback callback) {
  page_interface_->Navigate(url, referrer, transition_type, std::move(callback));
}

void PageInterface::StopLoading() {
  page_interface_->StopLoading();
}

void PageInterface::GetNavigationHistory(automation::Page::GetNavigationHistoryCallback callback) {
  page_interface_->GetNavigationHistory(std::move(callback));
}

void PageInterface::NavigateToHistoryEntry(int32_t entry_id) {
  page_interface_->NavigateToHistoryEntry(entry_id);
}

void PageInterface::GetCookies(automation::Page::GetCookiesCallback callback) {
  page_interface_->GetCookies(std::move(callback));
}

void PageInterface::DeleteCookie(const std::string& cookie_name, const std::string& url) {
  page_interface_->DeleteCookie(cookie_name, url);
}

void PageInterface::GetResourceTree(automation::Page::GetResourceTreeCallback callback) {
  page_interface_->GetResourceTree(std::move(callback));
}

void PageInterface::GetFrameTree(automation::Page::GetFrameTreeCallback callback) {
  page_interface_->GetFrameTree(std::move(callback));
}

void PageInterface::GetResourceContent(const std::string& frame_id, const std::string& url, automation::Page::GetResourceContentCallback callback) {
  page_interface_->GetResourceContent(frame_id, url, std::move(callback));
}

void PageInterface::SearchInResource(const std::string& frame_id, const std::string& url, const std::string& query, bool case_sensitive, bool is_regex, automation::Page::SearchInResourceCallback callback) {
  page_interface_->SearchInResource(frame_id, url, query, case_sensitive, is_regex, std::move(callback));
}

void PageInterface::SetDocumentContent(const std::string& frame_id, const std::string& html) {
  page_interface_->SetDocumentContent(frame_id, html);
}

void PageInterface::SetDeviceMetricsOverride(int32_t width, int32_t height, int32_t device_scale_factor, bool mobile, int32_t scale, int32_t screen_width, int32_t screen_height, int32_t position_x, int32_t position_y, bool dont_set_visible_size, automation::ScreenOrientationPtr screen_orientation, automation::ViewportPtr viewport) {
  page_interface_->SetDeviceMetricsOverride(width, height, device_scale_factor, mobile, scale, screen_width, screen_height, position_x, position_y, dont_set_visible_size, std::move(screen_orientation), std::move(viewport));
}

void PageInterface::ClearDeviceMetricsOverride() {
  page_interface_->ClearDeviceMetricsOverride();
}

void PageInterface::SetGeolocationOverride(int32_t latitude, int32_t longitude, int32_t accuracy) {
  page_interface_->SetGeolocationOverride(latitude, longitude, accuracy);
}

void PageInterface::ClearGeolocationOverride() {
  page_interface_->ClearGeolocationOverride();
}

void PageInterface::SetDeviceOrientationOverride(int32_t alpha, int32_t beta, int32_t gamma) {
  page_interface_->SetDeviceOrientationOverride(alpha, beta, gamma);
}

void PageInterface::ClearDeviceOrientationOverride() {
  page_interface_->ClearDeviceOrientationOverride();
}

void PageInterface::SetTouchEmulationEnabled(bool enabled, const std::string& configuration) {
  page_interface_->SetTouchEmulationEnabled(enabled, configuration);
}

void PageInterface::CaptureScreenshot(automation::FrameFormat format, int32_t quality, automation::ViewportPtr clip, bool from_surface, automation::Page::CaptureScreenshotCallback callback) {
  page_interface_->CaptureScreenshot(format, quality, std::move(clip), from_surface, std::move(callback));
}

void PageInterface::PrintToPDF(bool landscape, bool display_header_footer, bool print_background, float scale, float paper_width, float paper_height, float margin_top, float margin_bottom, float margin_left, float margin_right, const base::Optional<std::string>& page_ranges, bool ignore_invalid_page_ranges, automation::Page::PrintToPDFCallback callback) {
  page_interface_->PrintToPDF(landscape, display_header_footer, print_background, scale, paper_width, paper_height, margin_top, margin_bottom, margin_left, margin_right, page_ranges, ignore_invalid_page_ranges, std::move(callback));
}

void PageInterface::StartScreencast(automation::FrameFormat format, int32_t quality, int32_t max_width, int32_t max_height, int32_t every_nth_frame) {
  page_interface_->StartScreencast(format, quality, max_width, max_height, every_nth_frame);
}

void PageInterface::StopScreencast() {
  page_interface_->StopScreencast();
}

void PageInterface::SetBypassCSP(bool enable) {
  page_interface_->SetBypassCSP(enable);
}

void PageInterface::ScreencastFrameAck(int32_t session_id) {
  page_interface_->ScreencastFrameAck(session_id);
}

void PageInterface::HandleJavaScriptDialog(bool accept, const std::string& prompt_text) {
  page_interface_->HandleJavaScriptDialog(accept, prompt_text);
}

void PageInterface::GetAppManifest(automation::Page::GetAppManifestCallback callback) {
  page_interface_->GetAppManifest(std::move(callback));
}

void PageInterface::RequestAppBanner() {
  page_interface_->RequestAppBanner();
}

void PageInterface::GetLayoutMetrics(automation::Page::GetLayoutMetricsCallback callback) {
  page_interface_->GetLayoutMetrics(std::move(callback));
}

void PageInterface::CreateIsolatedWorld(const std::string& frame_id, const base::Optional<std::string>& world_name, bool grant_universal_access, automation::Page::CreateIsolatedWorldCallback callback) {
  page_interface_->CreateIsolatedWorld(frame_id, world_name, grant_universal_access, std::move(callback));
}

void PageInterface::BringToFront() {
  page_interface_->BringToFront();
}

void PageInterface::SetDownloadBehavior(const std::string& behavior, const base::Optional<std::string>& download_path) {
  page_interface_->SetDownloadBehavior(behavior, download_path);
}

void PageInterface::Close() {
  page_interface_->Close();
}

OverlayInterface::OverlayInterface() {

}

OverlayInterface::~OverlayInterface(){

}

void OverlayInterface::Register(int32_t application_id) {
  DCHECK(overlay_interface_);
  overlay_interface_->Register(application_id);
}

void OverlayInterface::Disable() {
  overlay_interface_->Disable();
}

void OverlayInterface::Enable() {
  overlay_interface_->Enable();
}

void OverlayInterface::HideHighlight() {
  overlay_interface_->HideHighlight();
}

void OverlayInterface::HighlightFrame(const std::string& frame_id, automation::RGBAPtr content_color, automation::RGBAPtr content_outline_color) {
  overlay_interface_->HighlightFrame(frame_id, std::move(content_color), std::move(content_outline_color));
}

void OverlayInterface::HighlightNode(automation::HighlightConfigPtr highlight_config, int32_t node_id, int32_t backend_node_id, const base::Optional<std::string>& object_id) {
  overlay_interface_->HighlightNode(std::move(highlight_config), node_id, backend_node_id, object_id);
}

void OverlayInterface::HighlightQuad(const std::vector<double>& quad, automation::RGBAPtr color, automation::RGBAPtr outline_color) {
  overlay_interface_->HighlightQuad(quad, std::move(color), std::move(outline_color));
}

void OverlayInterface::HighlightRect(int32_t x, int32_t y, int32_t width, int32_t height, automation::RGBAPtr color, automation::RGBAPtr outline_color) {
  overlay_interface_->HighlightRect(x, y, width, height, std::move(color), std::move(outline_color));
}

void OverlayInterface::SetInspectMode(automation::InspectMode mode, automation::HighlightConfigPtr highlight_config) {
  overlay_interface_->SetInspectMode(mode, std::move(highlight_config));
}

void OverlayInterface::SetPausedInDebuggerMessage(const base::Optional<std::string>& message) {
  overlay_interface_->SetPausedInDebuggerMessage(message);
}

void OverlayInterface::SetShowDebugBorders(bool show) {
  overlay_interface_->SetShowDebugBorders(show);
}

void OverlayInterface::SetShowFPSCounter(bool show) {
  overlay_interface_->SetShowFPSCounter(show);
}

void OverlayInterface::SetShowPaintRects(bool result) {
  overlay_interface_->SetShowPaintRects(result);
}

void OverlayInterface::SetShowScrollBottleneckRects(bool show) {
  overlay_interface_->SetShowScrollBottleneckRects(show);
}

void OverlayInterface::SetShowViewportSizeOnResize(bool show) {
  overlay_interface_->SetShowViewportSizeOnResize(show);
}

void OverlayInterface::SetSuspended(bool suspended) {
  overlay_interface_->SetShowViewportSizeOnResize(suspended);
}

WorkerInterface::WorkerInterface() {

}

WorkerInterface::~WorkerInterface() {

}

void WorkerInterface::Register(int32_t application_id) {
  DCHECK(worker_interface_);
  worker_interface_->Register(application_id);
}

void WorkerInterface::DeliverPushMessage(const std::string& origin, const std::string& registration_id, const std::string& data) {
  worker_interface_->DeliverPushMessage(origin, registration_id, data); 
}

void WorkerInterface::Disable() {
  worker_interface_->Disable(); 
}

void WorkerInterface::DispatchSyncEvent(const std::string& origin, const std::string& registration_id, const std::string& tag, bool last_chance) {
  worker_interface_->DispatchSyncEvent(origin, registration_id, tag, last_chance); 
}

void WorkerInterface::Enable() {
  worker_interface_->Enable(); 
}

void WorkerInterface::InspectWorker(const std::string& version_id) {
  worker_interface_->InspectWorker(version_id); 
}

void WorkerInterface::SetForceUpdateOnPageLoad(bool force_update_on_pageload) {
  worker_interface_->SetForceUpdateOnPageLoad(force_update_on_pageload); 
}

void WorkerInterface::SkipWaiting(const std::string& scope_url) {
  worker_interface_->SkipWaiting(scope_url); 
}

void WorkerInterface::StartWorker(const std::string& scope_url) {
  worker_interface_->StartWorker(scope_url); 
}

void WorkerInterface::StopAllWorkers() {
  worker_interface_->StopAllWorkers(); 
}

void WorkerInterface::StopWorker(const std::string& version_id) {
  worker_interface_->StopWorker(version_id); 
}

void WorkerInterface::Unregister(const std::string& scope_url) {
  worker_interface_->Unregister(scope_url); 
}

void WorkerInterface::UpdateRegistration(const std::string& scope_url) {
  worker_interface_->UpdateRegistration(scope_url); 
}

void WorkerInterface::SendMessageToTarget(const std::string& message, const base::Optional<std::string>& session_id, const base::Optional<std::string>& target_id) {
  worker_interface_->SendMessageToTarget(message, session_id, target_id); 
}

StorageInterface::StorageInterface() {

}

StorageInterface::~StorageInterface() {

}

void StorageInterface::Register(int32_t application_id) {
  DCHECK(storage_interface_);
  storage_interface_->Register(application_id);
}

void StorageInterface::ClearDataForOrigin(const std::string& origin, const std::vector<automation::StorageType>& storage_types) {
  storage_interface_->ClearDataForOrigin(origin, storage_types);
}

void StorageInterface::GetUsageAndQuota(const std::string& origin, int64_t usage, int64_t quota, std::vector<automation::UsageForTypePtr> usage_breakdown) {
  storage_interface_->GetUsageAndQuota(origin, usage, quota, std::move(usage_breakdown));
}

void StorageInterface::TrackCacheStorageForOrigin(const std::string& origin) {
  storage_interface_->TrackCacheStorageForOrigin(origin);
}

void StorageInterface::TrackIndexedDBForOrigin(const std::string& origin) {
  storage_interface_->TrackIndexedDBForOrigin(origin);
}

void StorageInterface::UntrackCacheStorageForOrigin(const std::string& origin) {
  storage_interface_->UntrackCacheStorageForOrigin(origin);
}

void StorageInterface::UntrackIndexedDBForOrigin(const std::string& origin) {
  storage_interface_->UntrackIndexedDBForOrigin(origin);
}

TetheringInterface::TetheringInterface() {

}

TetheringInterface::~TetheringInterface() {

}

void TetheringInterface::Register(int32_t application_id) {
  DCHECK(tethering_interface_);
  tethering_interface_->Register(application_id);
}

void TetheringInterface::Bind(int32_t port) {
  tethering_interface_->Bind(port);
}

void TetheringInterface::Unbind(int32_t port) {
  tethering_interface_->Unbind(port);
}

NetworkInterface::NetworkInterface() {

}

NetworkInterface::~NetworkInterface() {

}


void NetworkInterface::Register(int32_t application_id) {
  network_interface_->Register(application_id);
}

void NetworkInterface::CanClearBrowserCache(automation::Network::CanClearBrowserCacheCallback callback) {
  network_interface_->CanClearBrowserCache(std::move(callback));
}

void NetworkInterface::CanClearBrowserCookies(automation::Network::CanClearBrowserCookiesCallback callback) {
  network_interface_->CanClearBrowserCookies(std::move(callback));
}

void NetworkInterface::CanEmulateNetworkConditions(automation::Network::CanEmulateNetworkConditionsCallback callback) {
  network_interface_->CanEmulateNetworkConditions(std::move(callback));
}

void NetworkInterface::ClearBrowserCache() {
  network_interface_->ClearBrowserCache();
}

void NetworkInterface::ClearBrowserCookies() {
  network_interface_->ClearBrowserCookies();
}

void NetworkInterface::ContinueInterceptedRequest(const std::string& interception_id, automation::ErrorReason error_reason, const base::Optional<std::string>& raw_response, const base::Optional<std::string>& url, const base::Optional<std::string>& method, const base::Optional<std::string>& post_data, const base::Optional<base::flat_map<std::string, std::string>>& headers, automation::AuthChallengeResponsePtr auth_challenge_response) {
  network_interface_->ContinueInterceptedRequest(interception_id, error_reason, raw_response, url, method, post_data, headers, std::move(auth_challenge_response));
}

void NetworkInterface::DeleteCookies(const std::string& name, const base::Optional<std::string>& url, const base::Optional<std::string>& domain, const base::Optional<std::string>& path) {
  network_interface_->DeleteCookies(name, url, domain, path);
}

void NetworkInterface::Disable() {
  network_interface_->Disable();
}

void NetworkInterface::EmulateNetworkConditions(bool offline, int64_t latency, int64_t download_throughput, int64_t upload_throughput, automation::ConnectionType connection_type) {
  network_interface_->EmulateNetworkConditions(offline, latency, download_throughput, upload_throughput, connection_type);
}

void NetworkInterface::Enable(int32_t max_total_buffer_size, int32_t max_resource_buffer_size, int32_t max_post_data_size) {
  network_interface_->Enable(max_total_buffer_size, max_resource_buffer_size, max_post_data_size);
}

void NetworkInterface::GetAllCookies(automation::Network::GetAllCookiesCallback callback) {
  network_interface_->GetAllCookies(std::move(callback));
}

void NetworkInterface::GetCertificate(const std::string& origin, automation::Network::GetCertificateCallback callback) {
  network_interface_->GetCertificate(origin, std::move(callback));
}

void NetworkInterface::GetCookies(const base::Optional<std::vector<std::string>>& urls, automation::Network::GetCookiesCallback callback) {
  network_interface_->GetCookies(urls, std::move(callback));
}

void NetworkInterface::GetResponseBody(const std::string& request_id, automation::Network::GetResponseBodyCallback callback) {
  network_interface_->GetResponseBody(request_id, std::move(callback));
}

void NetworkInterface::GetRequestPostData(const std::string& request_id, automation::Network::GetRequestPostDataCallback callback) {
  network_interface_->GetRequestPostData(request_id, std::move(callback));
}

void NetworkInterface::GetResponseBodyForInterception(const std::string& interception_id, automation::Network::GetResponseBodyForInterceptionCallback callback) {
  network_interface_->GetResponseBodyForInterception(interception_id, std::move(callback));
}

void NetworkInterface::TakeResponseBodyForInterceptionAsStream(const std::string& interception_id, automation::Network::TakeResponseBodyForInterceptionAsStreamCallback callback) {
  network_interface_->TakeResponseBodyForInterceptionAsStream(interception_id, std::move(callback));
} 

void NetworkInterface::ReplayXHR(const std::string& request_id) {
  network_interface_->ReplayXHR(request_id);
}

void NetworkInterface::SearchInResponseBody(const std::string& request_id, const std::string& query, bool case_sensitive, bool is_regex, automation::Network::SearchInResponseBodyCallback callback) {
  network_interface_->SearchInResponseBody(request_id, query, case_sensitive, is_regex, std::move(callback));
}

void NetworkInterface::SetBlockedURLs(const std::vector<std::string>& urls) {
  network_interface_->SetBlockedURLs(urls);
}

void NetworkInterface::SetBypassServiceWorker(bool bypass) {
  network_interface_->SetBypassServiceWorker(bypass);
}

void NetworkInterface::SetCacheDisabled(bool cache_disabled) {
  network_interface_->SetCacheDisabled(cache_disabled);
}

void NetworkInterface::SetCookie(const std::string& name, const std::string& value, const base::Optional<std::string>& url, const base::Optional<std::string>& domain, const base::Optional<std::string>& path, bool secure, bool http_only, automation::CookieSameSite same_site, int64_t expires, automation::Network::SetCookieCallback callback) {
  network_interface_->SetCookie(name, value, url, domain, path, secure, http_only, same_site, expires, std::move(callback));
}

void NetworkInterface::SetCookies(std::vector<automation::CookieParamPtr> cookies) {
  network_interface_->SetCookies(std::move(cookies));
}

void NetworkInterface::SetDataSizeLimits(int32_t max_total_size, int32_t max_resource_size) {
  network_interface_->SetDataSizeLimitsForTest(max_total_size, max_resource_size);
}

void NetworkInterface::SetExtraHTTPHeaders(const base::flat_map<std::string, std::string>& headers) {
  network_interface_->SetExtraHTTPHeaders(headers);
}

void NetworkInterface::SetRequestInterception(std::vector<automation::RequestPatternPtr> patterns) {
  network_interface_->SetRequestInterception(std::move(patterns));
}

void NetworkInterface::SetUserAgentOverride(const std::string& user_agent) {
  network_interface_->SetUserAgentOverride(user_agent);
}


LayerTreeInterface::LayerTreeInterface() {

}

LayerTreeInterface::~LayerTreeInterface() {

}

void LayerTreeInterface::Register(int32_t application_id) {
  DCHECK(layer_tree_interface_);
  layer_tree_interface_->Register(application_id);
}

void LayerTreeInterface::CompositingReasons(const std::string& layer_id, automation::LayerTree::CompositingReasonsCallback callback) {
  layer_tree_interface_->CompositingReasons(layer_id, std::move(callback));
}

void LayerTreeInterface::Disable() {
  layer_tree_interface_->Disable();
}

void LayerTreeInterface::Enable() {
  layer_tree_interface_->Enable();
}

void LayerTreeInterface::LoadSnapshot(std::vector<automation::PictureTilePtr> tiles, automation::LayerTree::LoadSnapshotCallback callback) {
  layer_tree_interface_->LoadSnapshot(std::move(tiles), std::move(callback));
}

void LayerTreeInterface::MakeSnapshot(const std::string& layer_id, automation::LayerTree::MakeSnapshotCallback callback) {
  layer_tree_interface_->MakeSnapshot(layer_id, std::move(callback));
}

void LayerTreeInterface::ProfileSnapshot(const std::string& snapshot_id, int32_t min_repeat_count, int32_t min_duration, const base::Optional<gfx::Rect>& clip_rect, automation::LayerTree::ProfileSnapshotCallback callback) {
  layer_tree_interface_->ProfileSnapshot(snapshot_id, min_repeat_count, min_duration, clip_rect, std::move(callback));
}

void LayerTreeInterface::ReleaseSnapshot(const std::string& snapshot_id) {
  layer_tree_interface_->ReleaseSnapshot(snapshot_id);
}

void LayerTreeInterface::ReplaySnapshot(const std::string& snapshot_id, int32_t from_step, int32_t to_step, int32_t scale, automation::LayerTree::ReplaySnapshotCallback callback) {
  layer_tree_interface_->ReplaySnapshot(snapshot_id, from_step, to_step, scale, std::move(callback));
}

void LayerTreeInterface::SnapshotCommandLog(const std::string& snapshot_id, automation::LayerTree::SnapshotCommandLogCallback callback) {
  layer_tree_interface_->SnapshotCommandLog(snapshot_id, std::move(callback));
}

InputInterface::InputInterface() {

}

InputInterface::~InputInterface() {

}

void InputInterface::Register(int32_t application_id) {
  DCHECK(input_interface_);
  input_interface_->Register(application_id);
}

void InputInterface::DispatchKeyEvent(automation::KeyEventType type, int32_t modifiers, int64_t timestamp, const base::Optional<std::string>& text, const base::Optional<std::string>& unmodified_text, const base::Optional<std::string>& key_identifier, const base::Optional<std::string>& code, const base::Optional<std::string>& key, int32_t windows_virtual_key_code, int32_t native_virtual_key_code, bool auto_repeat, bool is_keypad, bool is_system_key, int32_t location, automation::Input::DispatchKeyEventCallback callback) {
  input_interface_->DispatchKeyEvent(
    type, 
    modifiers, 
    timestamp, 
    text,
    unmodified_text, 
    key_identifier, 
    code, 
    key, 
    windows_virtual_key_code, 
    native_virtual_key_code, 
    auto_repeat, 
    is_keypad, 
    is_system_key, 
    location, 
    std::move(callback));
}

void InputInterface::DispatchMouseEvent(automation::MouseEventType type, int32_t x, int32_t y, int32_t modifiers, int64_t timestamp, automation::MouseButton button, int32_t click_count, int32_t delta_x, int32_t delta_y, automation::Input::DispatchMouseEventCallback callback) {
  input_interface_->DispatchMouseEvent(
    type, 
    x,
    y,
    modifiers,
    timestamp,
    button,
    click_count,
    delta_x,
    delta_y,
    std::move(callback));
}

void InputInterface::DispatchTouchEvent(automation::TouchEventType type, std::vector<automation::TouchPointPtr> touch_points, int32_t modifiers, int64_t timestamp, automation::Input::DispatchTouchEventCallback callback) {
  input_interface_->DispatchTouchEvent(type, std::move(touch_points), modifiers, timestamp, std::move(callback));
}

void InputInterface::EmulateTouchFromMouseEvent(automation::MouseEventType type, int32_t x, int32_t y, automation::MouseButton button, int64_t timestamp, int32_t delta_x, int32_t delta_y, int32_t modifiers, int32_t click_count, automation::Input::EmulateTouchFromMouseEventCallback callback) {
  input_interface_->EmulateTouchFromMouseEvent(type, x, y, button, timestamp, delta_x, delta_y, modifiers, click_count, std::move(callback));
}

void InputInterface::SetIgnoreInputEvents(bool ignore) {
  input_interface_->SetIgnoreInputEvents(ignore);
}

void InputInterface::SynthesizePinchGesture(int32_t x, int32_t y, int32_t scale_factor, int32_t relative_speed, automation::GestureSourceType gesture_source_type, automation::Input::SynthesizePinchGestureCallback callback) {
  input_interface_->SynthesizePinchGesture(x, y, scale_factor, relative_speed, gesture_source_type, std::move(callback));
}

void InputInterface::SynthesizeScrollGesture(int32_t x, int32_t y, int32_t x_distance, int32_t y_distance, int32_t x_overscroll, int32_t y_overscroll, bool prevent_fling, int32_t speed, automation::GestureSourceType gesture_source_type, int32_t repeat_count, int32_t repeat_delay_ms, const base::Optional<std::string>& interaction_marker_name, automation::Input::SynthesizeScrollGestureCallback callback) {
  input_interface_->SynthesizeScrollGesture(
    x, 
    y, 
    x_distance, 
    y_distance, 
    x_overscroll, 
    y_overscroll, 
    prevent_fling, 
    speed, 
    gesture_source_type, 
    repeat_count, 
    repeat_delay_ms, 
    interaction_marker_name, 
    std::move(callback));
}

void InputInterface::SynthesizeTapGesture(int32_t x, int32_t y, int32_t duration, int32_t tap_count, automation::GestureSourceType gesture_source_type, automation::Input::SynthesizeTapGestureCallback callback) {
  input_interface_->SynthesizeTapGesture(x, y, duration, tap_count, gesture_source_type, std::move(callback));
}

IndexedDBInterface::IndexedDBInterface() {

}

IndexedDBInterface::~IndexedDBInterface() {

}

void IndexedDBInterface::Register(int32_t application_id) {
  DCHECK(indexed_db_interface_);
  indexed_db_interface_->Register(application_id);
}

void IndexedDBInterface::Disable() {
  indexed_db_interface_->Disable();
}

void IndexedDBInterface::Enable() {
  indexed_db_interface_->Enable();
}

void IndexedDBInterface::ClearObjectStore(const std::string& security_origin, const std::string& database_name, const std::string& object_store_name, automation::IndexedDB::ClearObjectStoreCallback callback) {
  indexed_db_interface_->ClearObjectStore(security_origin, database_name, object_store_name, std::move(callback));
}

void IndexedDBInterface::DeleteDatabase(const std::string& security_origin, const std::string& database_name, automation::IndexedDB::DeleteDatabaseCallback callback) {
  indexed_db_interface_->DeleteDatabase(security_origin, database_name, std::move(callback));
}

void IndexedDBInterface::DeleteObjectStoreEntries(const std::string& security_origin, const std::string& database_name, const std::string& object_store_name, automation::KeyRangePtr key_range, automation::IndexedDB::DeleteObjectStoreEntriesCallback callback) {
  indexed_db_interface_->DeleteObjectStoreEntries(security_origin, database_name, object_store_name, std::move(key_range), std::move(callback));
}

void IndexedDBInterface::RequestData(const std::string& security_origin, const std::string& database_name, const std::string& object_store_name, const std::string& index_name, int32_t skip_count, int32_t page_size, automation::KeyRangePtr key_range, automation::IndexedDB::RequestDataCallback callback) {
  indexed_db_interface_->RequestData(
    security_origin, 
    database_name, 
    object_store_name, 
    index_name, 
    skip_count, 
    page_size, 
    std::move(key_range), 
    std::move(callback));
}

void IndexedDBInterface::RequestDatabase(const std::string& security_origin, const std::string& database_name, automation::IndexedDB::RequestDatabaseCallback callback) {
  indexed_db_interface_->RequestDatabase(security_origin, database_name, std::move(callback));
}

void IndexedDBInterface::RequestDatabaseNames(const std::string& security_origin, automation::IndexedDB::RequestDatabaseNamesCallback callback) {
  indexed_db_interface_->RequestDatabaseNames(security_origin, std::move(callback));
}

IOInterface::IOInterface() {
  
}

IOInterface::~IOInterface() {

}

void IOInterface::Register(int32_t application_id) {
  DCHECK(io_interface_);
  io_interface_->Register(application_id);
}

void IOInterface::Close(const std::string& handl) {
  io_interface_->Close(handl);
}

void IOInterface::Read(const std::string& handl, int32_t offset, int32_t size, automation::IO::ReadCallback callback) {
  io_interface_->Read(handl, offset, size, std::move(callback));
}

void IOInterface::ResolveBlob(const std::string& object_id, automation::IO::ResolveBlobCallback callback) {
  io_interface_->ResolveBlob(object_id, std::move(callback));
}

HeadlessInterface::HeadlessInterface() {
  
}

HeadlessInterface::~HeadlessInterface() {

}

void HeadlessInterface::Register(int32_t application_id) {
  DCHECK(headless_interface_);
  headless_interface_->Register(application_id);
}

void HeadlessInterface::BeginFrame(int64_t frame_time, int32_t frame_time_ticks, int64_t deadline, int32_t deadline_ticks, int32_t interval, bool no_display_updates, automation::ScreenshotParamsPtr screenshot, automation::Headless::BeginFrameCallback callback) {
  headless_interface_->BeginFrame(frame_time, frame_time_ticks, deadline, deadline_ticks, interval, no_display_updates, std::move(screenshot), std::move(callback));
}

void HeadlessInterface::EnterDeterministicMode(int32_t initial_date) {
  headless_interface_->EnterDeterministicMode(initial_date);
}

void HeadlessInterface::Disable() {
  headless_interface_->Disable();
}

void HeadlessInterface::Enable() {
  headless_interface_->Enable();
}

DOMStorageInterface::DOMStorageInterface() {

}

DOMStorageInterface::~DOMStorageInterface() {

}

void DOMStorageInterface::Register(int32_t application_id) {
  DCHECK(dom_storage_interface_);
  dom_storage_interface_->Register(application_id);
}

void DOMStorageInterface::Clear(automation::StorageIdPtr storage_id) {
  dom_storage_interface_->Clear(std::move(storage_id));
}

void DOMStorageInterface::Disable() {
  dom_storage_interface_->Disable();
}

void DOMStorageInterface::Enable() {
  dom_storage_interface_->Enable();
}

void DOMStorageInterface::GetDOMStorageItems(automation::StorageIdPtr storage_id, automation::DOMStorage::GetDOMStorageItemsCallback callback) {
  dom_storage_interface_->GetDOMStorageItems(std::move(storage_id), std::move(callback));
}

void DOMStorageInterface::RemoveDOMStorageItem(automation::StorageIdPtr storage_id, const std::string& key) {
  dom_storage_interface_->RemoveDOMStorageItem(std::move(storage_id), key);
}

void DOMStorageInterface::SetDOMStorageItem(automation::StorageIdPtr storage_id, const std::string& key, const std::string& value) {
  dom_storage_interface_->SetDOMStorageItem(std::move(storage_id), key, value);
}

DatabaseInterface::DatabaseInterface() {

}

DatabaseInterface::~DatabaseInterface() {

}

void DatabaseInterface::Register(int32_t application_id) {
  DCHECK(database_interface_);
  database_interface_->Register(application_id);
}

void DatabaseInterface::Disable() {
  database_interface_->Disable();
}

void DatabaseInterface::Enable() {
  database_interface_->Enable();
}

void DatabaseInterface::ExecuteSQL(const std::string& database_id, const std::string& query, automation::DatabaseInterface::ExecuteSQLCallback callback) {
  database_interface_->ExecuteSQL(database_id, query, std::move(callback));
}

void DatabaseInterface::GetDatabaseTableNames(const std::string& database_id, automation::DatabaseInterface::GetDatabaseTableNamesCallback callback) {
  database_interface_->GetDatabaseTableNames(database_id, std::move(callback));
}

DeviceOrientationInterface::DeviceOrientationInterface() {

}

DeviceOrientationInterface::~DeviceOrientationInterface() {

}

void DeviceOrientationInterface::Register(int32_t application_id) {
  DCHECK(device_orientation_interface_);
  device_orientation_interface_->Register(application_id);
}

void DeviceOrientationInterface::ClearDeviceOrientationOverride() {
  device_orientation_interface_->ClearDeviceOrientationOverride();
}

void DeviceOrientationInterface::SetDeviceOrientationOverride(int32_t alpha, int32_t beta, int32_t gamma) {
  device_orientation_interface_->SetDeviceOrientationOverride(alpha, beta, gamma);
}

EmulationInterface::EmulationInterface() {
  
}

EmulationInterface::~EmulationInterface() {
  
}

void EmulationInterface::Register(int32_t application_id) {
  DCHECK(emulation_interface_);
  emulation_interface_->Register(application_id);
}

void EmulationInterface::CanEmulate(automation::Emulation::CanEmulateCallback callback) {
  emulation_interface_->CanEmulate(std::move(callback));
}

void EmulationInterface::ClearDeviceMetricsOverride() {
  emulation_interface_->ClearDeviceMetricsOverride();
}

void EmulationInterface::ClearGeolocationOverride() {
  emulation_interface_->ClearGeolocationOverride();
}

void EmulationInterface::ResetPageScaleFactor() {
  emulation_interface_->ResetPageScaleFactor();
}

void EmulationInterface::SetCPUThrottlingRate(int32_t rate) {
  emulation_interface_->SetCPUThrottlingRate(rate);
}

void EmulationInterface::SetDefaultBackgroundColorOverride(automation::RGBAPtr color) {
  emulation_interface_->SetDefaultBackgroundColorOverride(std::move(color));
}

void EmulationInterface::SetDeviceMetricsOverride(int32_t width, int32_t height, float device_scale_factor, bool mobile, float scale, int32_t screen_width, int32_t screen_height, int32_t position_x, int32_t position_y, bool dont_set_visible_size, automation::ScreenOrientationPtr screen_orientation, automation::ViewportPtr viewport) {
  emulation_interface_->SetDeviceMetricsOverride(width, height, device_scale_factor, mobile, scale, screen_width, screen_height, position_x, position_y, dont_set_visible_size, std::move(screen_orientation), std::move(viewport));
}

void EmulationInterface::SetEmitTouchEventsForMouse(bool enabled, automation::TouchEventForMouseConfiguration configuration) {
  emulation_interface_->SetEmitTouchEventsForMouse(enabled, std::move(configuration));  
}

void EmulationInterface::SetEmulatedMedia(const std::string& media) {
  emulation_interface_->SetEmulatedMedia(media);
}

void EmulationInterface::SetGeolocationOverride(int64_t latitude, int64_t longitude, int64_t accuracy) {
  emulation_interface_->SetGeolocationOverride(latitude, longitude, accuracy);
}

void EmulationInterface::SetNavigatorOverrides(const std::string& platform) {
  emulation_interface_->SetNavigatorOverrides(platform);
}

void EmulationInterface::SetPageScaleFactor(float page_scale_factor) {
  emulation_interface_->SetPageScaleFactor(page_scale_factor);
}

void EmulationInterface::SetScriptExecutionDisabled(bool value) {
  emulation_interface_->SetScriptExecutionDisabled(value);
}

void EmulationInterface::SetTouchEmulationEnabled(bool enabled, int32_t max_touch_points) {
  emulation_interface_->SetTouchEmulationEnabled(enabled, max_touch_points);
}

void EmulationInterface::SetVirtualTimePolicy(automation::VirtualTimePolicy policy, int32_t budget, int32_t max_virtual_time_task_starvation_count, bool wait_for_navigation, automation::Emulation::SetVirtualTimePolicyCallback callback) {
  emulation_interface_->SetVirtualTimePolicy(policy, budget, max_virtual_time_task_starvation_count, wait_for_navigation, std::move(callback));
}

void EmulationInterface::SetVisibleSize(int32_t width, int32_t height) {
  emulation_interface_->SetVisibleSize(width, height);
}

DOMSnapshotInterface::DOMSnapshotInterface() {

}

DOMSnapshotInterface::~DOMSnapshotInterface() {

}

void DOMSnapshotInterface::Register(int32_t application_id) {
  DCHECK(dom_snapshot_interface_);
  dom_snapshot_interface_->Register(application_id);
}

void DOMSnapshotInterface::GetSnapshot(
    const std::vector<std::string>& computed_style_whitelist, 
    bool include_event_listeners, 
    bool include_paint_order, 
    bool include_user_agent_shadow_tree, 
    automation::DOMSnapshot::GetSnapshotCallback callback) {
  dom_snapshot_interface_->GetSnapshot(computed_style_whitelist, include_event_listeners, include_paint_order, include_user_agent_shadow_tree, std::move(callback));
}

DOMInterface::DOMInterface() {

}

DOMInterface::~DOMInterface() {

}

void DOMInterface::Register(int32_t application_id) {
  DCHECK(dom_interface_);
  dom_interface_->Register(application_id);
}

void DOMInterface::CollectClassNamesFromSubtree(int32_t node_id, automation::DOM::CollectClassNamesFromSubtreeCallback callback) {
  dom_interface_->CollectClassNamesFromSubtree(node_id, std::move(callback));
}

void DOMInterface::CopyTo(int32_t node_id, int32_t target_node_id, int32_t anchor_node_id, automation::DOM::CopyToCallback callback) {
  dom_interface_->CopyTo(node_id, target_node_id, anchor_node_id, std::move(callback));
}

void DOMInterface::DescribeNode(int32_t node_id, int32_t backend_node_id, const base::Optional<std::string>& object_id, int32_t depth, bool pierce, automation::DOM::DescribeNodeCallback callback) {
  dom_interface_->DescribeNode(node_id, backend_node_id, object_id, depth, pierce, std::move(callback));
}

void DOMInterface::Disable() {
  dom_interface_->Disable();
}

void DOMInterface::DiscardSearchResults(const std::string& search_id) {
  dom_interface_->DiscardSearchResults(search_id);
}

void DOMInterface::Enable() {
  dom_interface_->Enable();
}

void DOMInterface::Focus(int32_t node_id, int32_t backend_node_id, const base::Optional<std::string>& object_id) {
  dom_interface_->Focus(node_id, backend_node_id, object_id);
}

void DOMInterface::GetAttributes(int32_t node_id, automation::DOM::GetAttributesCallback callback) {
  dom_interface_->GetAttributes(node_id, std::move(callback));
}

void DOMInterface::GetBoxModel(int32_t node_id, int32_t backend_node_id, const base::Optional<std::string>& object_id, automation::DOM::GetBoxModelCallback callback) {
  dom_interface_->GetBoxModel(node_id, backend_node_id, object_id, std::move(callback));
}

void DOMInterface::GetDocument(int32_t depth, bool pierce, automation::DOM::GetDocumentCallback callback) {
  dom_interface_->GetDocument(depth, pierce, std::move(callback));
}

void DOMInterface::GetFlattenedDocument(int32_t depth, bool pierce, automation::DOM::GetFlattenedDocumentCallback callback) {
  dom_interface_->GetFlattenedDocument(depth, pierce, std::move(callback));
}

void DOMInterface::GetNodeForLocation(int32_t x, int32_t y, bool include_user_agent_shadow_dom, automation::DOM::GetNodeForLocationCallback callback) {
  dom_interface_->GetNodeForLocation(x, y, include_user_agent_shadow_dom, std::move(callback));
}

void DOMInterface::GetOuterHTML(int32_t node_id, int32_t backend_node_id, const base::Optional<std::string>& object_id, automation::DOM::GetOuterHTMLCallback callback) {
  dom_interface_->GetOuterHTML(node_id, backend_node_id, object_id, std::move(callback));
}

void DOMInterface::GetRelayoutBoundary(int32_t node_id, automation::DOM::GetRelayoutBoundaryCallback callback) {
  dom_interface_->GetRelayoutBoundary(node_id, std::move(callback));
}

void DOMInterface::GetSearchResults(const std::string& search_id, int32_t from_index, int32_t to_index, automation::DOM::GetSearchResultsCallback callback) {
  dom_interface_->GetSearchResults(search_id, from_index, to_index, std::move(callback));
}

void DOMInterface::HideHighlight() {
  dom_interface_->HideHighlight();
}

void DOMInterface::HighlightNode(automation::HighlightConfigPtr highlight_config, int32_t node_id, int32_t backend_node_id, int32_t object_id) {
  dom_interface_->HighlightNode(std::move(highlight_config), node_id, backend_node_id, object_id);
}

void DOMInterface::HighlightRect(int32_t x, int32_t y, int32_t width, int32_t height, automation::RGBAPtr color, automation::RGBAPtr outline_color) {
  dom_interface_->HighlightRect(x, y, width, height, std::move(color), std::move(outline_color));
}

void DOMInterface::MarkUndoableState() {
  dom_interface_->MarkUndoableState();
}

void DOMInterface::MoveTo(int32_t node_id, int32_t target_node_id, int32_t insert_before_node_id, automation::DOM::MoveToCallback callback) {
  dom_interface_->MoveTo(node_id, target_node_id, insert_before_node_id, std::move(callback));
}

void DOMInterface::PerformSearch(const std::string& query, bool include_user_agent_shadow_dom, automation::DOM::PerformSearchCallback callback) {
  dom_interface_->PerformSearch(query, include_user_agent_shadow_dom, std::move(callback));
}

void DOMInterface::PushNodeByPathToFrontend(const std::string& path, automation::DOM::PushNodeByPathToFrontendCallback callback) {
  dom_interface_->PushNodeByPathToFrontend(path, std::move(callback));
}

void DOMInterface::PushNodesByBackendIdsToFrontend(const std::vector<int32_t>& backend_node_ids, automation::DOM::PushNodesByBackendIdsToFrontendCallback callback) {
  dom_interface_->PushNodesByBackendIdsToFrontend(backend_node_ids, std::move(callback));
}

void DOMInterface::QuerySelector(int32_t node_id, const std::string& selector, automation::DOM::QuerySelectorCallback callback) {
  dom_interface_->QuerySelector(node_id, selector, std::move(callback));
}

void DOMInterface::QuerySelectorAll(int32_t node_id, const std::string& selector, automation::DOM::QuerySelectorAllCallback callback) {
  dom_interface_->QuerySelectorAll(node_id, selector, std::move(callback));
}

void DOMInterface::Redo() {
  dom_interface_->Redo();
}

void DOMInterface::RemoveAttribute(int32_t node_id, const std::string& name) {
  dom_interface_->RemoveAttribute(node_id, name);
}

void DOMInterface::RemoveNode(int32_t node_id) {
  dom_interface_->RemoveNode(node_id);
}

void DOMInterface::RequestChildNodes(int32_t node_id, int32_t depth, bool pierce) {
  dom_interface_->RequestChildNodes(node_id, depth, pierce);
}

void DOMInterface::RequestNode(const std::string& object_id, automation::DOM::RequestNodeCallback callback) {
  dom_interface_->RequestNode(object_id, std::move(callback));
}

void DOMInterface::ResolveNode(int32_t node_id, const base::Optional<std::string>& object_group, automation::DOM::ResolveNodeCallback callback) {
  dom_interface_->ResolveNode(node_id, object_group, std::move(callback));
}

void DOMInterface::SetAttributeValue(int32_t node_id, const std::string& name, const std::string& value) {
  dom_interface_->SetAttributeValue(node_id, name, value);
}

void DOMInterface::SetAttributesAsText(int32_t node_id, const std::string& text, const base::Optional<std::string>& name) {
  dom_interface_->SetAttributesAsText(node_id, text, name);
}

void DOMInterface::SetFileInputFiles(const std::vector<std::string>& files, int32_t node_id, int32_t backend_node_id, const base::Optional<std::string>& object_id) {
  dom_interface_->SetFileInputFiles(files, node_id, backend_node_id, object_id);
}

void DOMInterface::SetInspectedNode(int32_t node_id) {
  dom_interface_->SetInspectedNode(node_id);
}

void DOMInterface::SetNodeName(int32_t node_id, const std::string& name, automation::DOM::SetNodeNameCallback callback) {
  dom_interface_->SetNodeName(node_id, name, std::move(callback));
}

void DOMInterface::SetNodeValue(int32_t node_id, const std::string& value) {
  dom_interface_->SetNodeValue(node_id, value);
}

void DOMInterface::SetOuterHTML(int32_t node_id, const std::string& outer_html) {
  dom_interface_->SetOuterHTML(node_id, outer_html);
}

void DOMInterface::Undo() {
  dom_interface_->Undo();
}

void DOMInterface::GetFrameOwner(const std::string& frame_id, automation::DOM::GetFrameOwnerCallback callback) {
  dom_interface_->GetFrameOwner(frame_id, std::move(callback));
}

CSSInterface::CSSInterface() {
  
}

CSSInterface::~CSSInterface() {
  
}

void CSSInterface::Register(int32_t application_id) {
  DCHECK(css_interface_);
  css_interface_->Register(application_id);
}

void CSSInterface::AddRule(const std::string& style_sheet_id, const std::string& rule_text, automation::SourceRangePtr location, automation::CSS::AddRuleCallback callback) {
  css_interface_->AddRule(style_sheet_id, rule_text, std::move(location), std::move(callback));
}

void CSSInterface::CollectClassNames(const std::string& style_sheet_id, automation::CSS::CollectClassNamesCallback callback) {
  css_interface_->CollectClassNames(style_sheet_id, std::move(callback));
}

void CSSInterface::CreateStyleSheet(const std::string& frame_id, automation::CSS::CreateStyleSheetCallback callback) {
  css_interface_->CreateStyleSheet(frame_id, std::move(callback));
}

void CSSInterface::Disable() {
  css_interface_->Disable();
}

void CSSInterface::Enable() {
  css_interface_->Enable();
}

void CSSInterface::ForcePseudoState(int32_t node_id, const std::vector<std::string>& forced_pseudo_classes) {
  css_interface_->ForcePseudoState(node_id, forced_pseudo_classes);
}

void CSSInterface::GetBackgroundColors(int32_t node_id, automation::CSS::GetBackgroundColorsCallback callback) {
  css_interface_->GetBackgroundColors(node_id, std::move(callback));
}

void CSSInterface::GetComputedStyleForNode(int32_t node_id, automation::CSS::GetComputedStyleForNodeCallback callback) {
  css_interface_->GetComputedStyleForNode(node_id, std::move(callback));
}

void CSSInterface::GetInlineStylesForNode(int32_t node_id, automation::CSS::GetInlineStylesForNodeCallback callback) {
  css_interface_->GetInlineStylesForNode(node_id, std::move(callback));
}

void CSSInterface::GetMatchedStylesForNode(int32_t node_id, automation::CSS::GetMatchedStylesForNodeCallback callback) {
  css_interface_->GetMatchedStylesForNode(node_id, std::move(callback));
}

void CSSInterface::GetMediaQueries(automation::CSS::GetMediaQueriesCallback callback) {
  css_interface_->GetMediaQueries(std::move(callback));
}

void CSSInterface::GetPlatformFontsForNode(int32_t node_id, automation::CSS::GetPlatformFontsForNodeCallback callback) {
  css_interface_->GetPlatformFontsForNode(node_id, std::move(callback));
}

void CSSInterface::GetStyleSheetText(const std::string& style_sheet_id, automation::CSS::GetStyleSheetTextCallback callback) {
  css_interface_->GetStyleSheetText(style_sheet_id, std::move(callback));
}

void CSSInterface::SetEffectivePropertyValueForNode(int32_t node_id, const std::string& property_name, const std::string& value) {
  css_interface_->SetEffectivePropertyValueForNode(node_id, property_name, value);
}

void CSSInterface::SetKeyframeKey(const std::string& style_sheet_id, automation::SourceRangePtr range, const std::string& key_text, automation::CSS::SetKeyframeKeyCallback callback) {
  css_interface_->SetKeyframeKey(style_sheet_id, std::move(range), key_text, std::move(callback));
}

void CSSInterface::SetMediaText(const std::string& style_sheet_id, automation::SourceRangePtr range, const std::string& text, automation::CSS::SetMediaTextCallback callback) {
  css_interface_->SetMediaText(style_sheet_id, std::move(range), text, std::move(callback));
}

void CSSInterface::SetRuleSelector(const std::string& style_sheet_id, automation::SourceRangePtr range, const std::string& selector, automation::CSS::SetRuleSelectorCallback callback) {
  css_interface_->SetRuleSelector(style_sheet_id, std::move(range), selector, std::move(callback));
}

void CSSInterface::SetStyleSheetText(const std::string& style_sheet_id, const std::string& text, automation::CSS::SetStyleSheetTextCallback callback) {
  css_interface_->SetStyleSheetText(style_sheet_id, text, std::move(callback));
}

void CSSInterface::SetStyleTexts(std::vector<automation::StyleDeclarationEditPtr> edits, automation::CSS::SetStyleTextsCallback callback) {
  css_interface_->SetStyleTexts(std::move(edits), std::move(callback));
}

void CSSInterface::StartRuleUsageTracking() {
  css_interface_->StartRuleUsageTracking();
}

void CSSInterface::StopRuleUsageTracking(automation::CSS::StopRuleUsageTrackingCallback callback) {
  css_interface_->StopRuleUsageTracking(std::move(callback));
}

void CSSInterface::TakeCoverageDelta(automation::CSS::TakeCoverageDeltaCallback callback) {
  css_interface_->TakeCoverageDelta(std::move(callback));
}

CacheStorageInterface::CacheStorageInterface() {
  
}

CacheStorageInterface::~CacheStorageInterface() {

}

void CacheStorageInterface::Register(int32_t application_id) {
  DCHECK(cache_storage_interface_);
  DLOG(INFO) << "CacheStorageInterface::Register: this = " << this << " cache_storage_interface_ = " << cache_storage_interface_.get();
  cache_storage_interface_->Register(application_id);
}

void CacheStorageInterface::HasCache(const std::string& cache_id, automation::CacheStorage::HasCacheCallback callback) {
  cache_storage_interface_->HasCache(cache_id, std::move(callback));
}

void CacheStorageInterface::OpenCache(const std::string& cache_id, automation::CacheStorage::OpenCacheCallback callback) {
  DLOG(INFO) << "CacheStorageInterface::OpenCache: this = " << this << " cache_storage_interface_ = " << cache_storage_interface_.get();
  cache_storage_interface_->OpenCache(cache_id, std::move(callback));
}

void CacheStorageInterface::PutEntry(const std::string& cache_id, const std::string& request, blink::mojom::DataElementPtr data, automation::CacheStorage::PutEntryCallback callback) {
  //DLOG(INFO) << "CacheStorageInterface::PutEntryData: [" << data.size() << "] '" << std::string(data.begin()[0], data.size()) << "'";
  cache_storage_interface_->PutEntry(cache_id, request, std::move(data), std::move(callback));
}

void CacheStorageInterface::PutEntryBlob(const std::string& cache_id, const std::string& request, blink::mojom::SerializedBlobPtr blob, automation::CacheStorage::PutEntryBlobCallback callback) {
  cache_storage_interface_->PutEntryBlob(cache_id, request, std::move(blob), std::move(callback));
}
  
void CacheStorageInterface::DeleteCache(const std::string& cache_id, automation::CacheStorage::DeleteCacheCallback callback) {
  cache_storage_interface_->DeleteCache(cache_id, std::move(callback));
}

void CacheStorageInterface::DeleteEntry(const std::string& cache_id, const std::string& request, automation::CacheStorage::DeleteEntryCallback callback) {
  cache_storage_interface_->DeleteEntry(cache_id, request, std::move(callback));
}

void CacheStorageInterface::RequestCacheNames(const std::string& security_origin, automation::CacheStorage::RequestCacheNamesCallback callback) {
  cache_storage_interface_->RequestCacheNames(security_origin, std::move(callback));
}

void CacheStorageInterface::RequestCachedResponse(const std::string& cache_id, const std::string& request_url, bool base64_encoded, automation::CacheStorage::RequestCachedResponseCallback callback) {
  cache_storage_interface_->RequestCachedResponse(cache_id, request_url, base64_encoded, std::move(callback));
}

void CacheStorageInterface::RequestEntries(const std::string& cache_id, int32_t skip_count, int32_t page_size, automation::CacheStorage::RequestEntriesCallback callback) {
  cache_storage_interface_->RequestEntries(cache_id, skip_count, page_size, std::move(callback));
}

ApplicationCacheInterface::ApplicationCacheInterface() {

}

ApplicationCacheInterface::~ApplicationCacheInterface() {

}

void ApplicationCacheInterface::Register(int32_t application_id) {
  DCHECK(application_cache_interface_);
  application_cache_interface_->Register(application_id);
}

void ApplicationCacheInterface::Enable() {
  application_cache_interface_->Enable();
}

void ApplicationCacheInterface::GetApplicationCacheForFrame(const std::string& frame_id, automation::ApplicationCacheInterface::GetApplicationCacheForFrameCallback callback) {
  application_cache_interface_->GetApplicationCacheForFrame(frame_id, std::move(callback));
}

void ApplicationCacheInterface::GetFramesWithManifests(automation::ApplicationCacheInterface::GetFramesWithManifestsCallback callback) {
  application_cache_interface_->GetFramesWithManifests(std::move(callback));
}

void ApplicationCacheInterface::GetManifestForFrame(const std::string& frame_id, automation::ApplicationCacheInterface::GetManifestForFrameCallback callback) {
  application_cache_interface_->GetManifestForFrame(frame_id, std::move(callback));
}

AnimationInterface::AnimationInterface() {
  
}

AnimationInterface::~AnimationInterface() {
  
}

void AnimationInterface::Register(int32_t application_id) {
  DCHECK(animation_interface_);
  animation_interface_->Register(application_id);
}

void AnimationInterface::Disable() {
  animation_interface_->Disable();
}

void AnimationInterface::Enable() {
  animation_interface_->Enable();
}

void AnimationInterface::GetCurrentTime(const std::string& id, automation::AnimationInterface::GetCurrentTimeCallback callback) {
  animation_interface_->GetCurrentTime(id, std::move(callback));
}

void AnimationInterface::GetPlaybackRate(automation::AnimationInterface::GetPlaybackRateCallback callback) {
  animation_interface_->GetPlaybackRate(std::move(callback));
}

void AnimationInterface::ReleaseAnimations(const std::vector<std::string>& animations) {
  animation_interface_->ReleaseAnimations(animations);
}

void AnimationInterface::ResolveAnimation(const std::string& animation_id, automation::AnimationInterface::ResolveAnimationCallback callback) {
  animation_interface_->ResolveAnimation(animation_id, std::move(callback));
}

void AnimationInterface::SeekAnimations(const std::vector<std::string>& animations, int32_t current_time) {
  animation_interface_->SeekAnimations(animations, current_time);
}

void AnimationInterface::SetPaused(const std::vector<std::string>& animations, bool paused) {
  animation_interface_->SetPaused(animations, paused);
}

void AnimationInterface::SetPlaybackRate(int32_t playback_rate) {
  animation_interface_->SetPlaybackRate(playback_rate);
}

void AnimationInterface::SetTiming(const std::string& animation_id, int32_t duration, int32_t delay) {
  animation_interface_->SetTiming(animation_id, duration, delay);
}

AccessibilityInterface::AccessibilityInterface() {

}

AccessibilityInterface::~AccessibilityInterface() {

}

void AccessibilityInterface::Register(int32_t application_id) {
  DCHECK(accessibility_interface_);
  accessibility_interface_->Register(application_id);
}
  
void AccessibilityInterface::GetPartialAXTree(
    const base::Optional<std::string>& node_id, 
    int32_t backend_node_id, 
    const base::Optional<std::string>& object_id, 
    bool fetch_relatives, 
    automation::Accessibility::GetPartialAXTreeCallback callback) {
  accessibility_interface_->GetPartialAXTree(node_id, backend_node_id, object_id, fetch_relatives, std::move(callback));
}

ApplicationDriver::ApplicationDriver(Application* application):
  application_(application),
  page_client_binding_(this),
  overlay_client_binding_(this),
  worker_client_binding_(this),
  storage_client_binding_(this),
  network_client_binding_(this),
  layer_tree_client_binding_(this),
  headless_client_binding_(this),
  dom_storage_client_binding_(this),
  database_client_binding_(this),
  emulation_client_binding_(this),
  dom_client_binding_(this),
  css_client_binding_(this),
  application_cache_client_binding_(this),
  animation_client_binding_(this) {

}

ApplicationDriver::~ApplicationDriver() {

}

void ApplicationDriver::AddObserver(Observer* observer) {
  observers_.AddObserver(observer);
}

void ApplicationDriver::RemoveObserver(Observer* observer) {
  observers_.RemoveObserver(observer);
}

void ApplicationDriver::BindInterfaces() {
  // service_manager::Connector* connector = application_->domain()->GetConnector(); 
  // connector->BindInterface(
  //   "automation.Page",
  //   mojo::MakeRequest(&page_interface_));

  // connector->BindInterface(
  //   "automation.Host",
  //   mojo::MakeRequest(&host_interface_));
  
  // connector->BindInterface(
  //   "automation.Overlay",
  //   mojo::MakeRequest(&overlay_interface_));

  // connector->BindInterface(
  //   "automation.ServiceWorkerInterface",
  //   mojo::MakeRequest(&worker_interface_));

  // connector->BindInterface(
  //   "automation.Storage",
  //    mojo::MakeRequest(&storage_interface_));

  // connector->BindInterface(
  //   "automation.Tethering",
  //    mojo::MakeRequest(&tethering_interface_));

  // connector->BindInterface(
  //   "automation.Network",
  //    mojo::MakeRequest(&network_interface_));

  // connector->BindInterface(
  //   "automation.LayerTree",
  //    mojo::MakeRequest(&layer_tree_interface_));

  // connector->BindInterface(
  //   "automation.Input",
  //    mojo::MakeRequest(&input_interface_));

  // connector->BindInterface(
  //   "automation.IndexedDB",
  //    mojo::MakeRequest(&indexed_db_interface_));
  
  // connector->BindInterface(
  //   "automation.IO",
  //    mojo::MakeRequest(&io_interface_));

  // connector->BindInterface(
  //   "automation.Headless",
  //    mojo::MakeRequest(&headless_interface_));

  // connector->BindInterface(
  //   "automation.DOM",
  //    mojo::MakeRequest(&dom_storage_interface_));
  
  // connector->BindInterface(
  //   "automation.DatabaseInterface",
  //    mojo::MakeRequest(&database_interface_));
  
  // connector->BindInterface(
  //   "automation.DeviceOrientation",
  //    mojo::MakeRequest(&device_orientation_interface_));
  
  // connector->BindInterface(
  //   "automation.Emulation",
  //    mojo::MakeRequest(&emulation_interface_));
  
  // connector->BindInterface(
  //   "automation.DOMSnapshot",
  //    mojo::MakeRequest(&dom_snapshot_interface_));
  
  // connector->BindInterface(
  //   "automation.DOM",
  //    mojo::MakeRequest(&dom_interface_));
  
  // connector->BindInterface(
  //   "automation.CSS",
  //    mojo::MakeRequest(&css_interface_));

  // connector->BindInterface(
  //   "automation.CacheStorage",
  //    mojo::MakeRequest(&cache_storage_interface_));
  
  // connector->BindInterface(
  //   "automation.ApplicationCacheInterface",
  //    mojo::MakeRequest(&application_cache_interface_));
  
  // connector->BindInterface(
  //   "automation.Accessibility",
  //    mojo::MakeRequest(&accessibility_interface_));
  
  // connector->BindInterface(
  //   "automation.AnimationInterface",
  //    mojo::MakeRequest(&animation_interface_));

  IPC::ChannelProxy* channel = application_->process()->GetChannelProxy();
  channel->GetRemoteAssociatedInterface(&animation_.animation_interface_);
  channel->GetRemoteAssociatedInterface(&pages_.page_interface_); 
  channel->GetRemoteAssociatedInterface(&system_info_.system_info_interface_);
  channel->GetRemoteAssociatedInterface(&host_.host_interface_);
  channel->GetRemoteAssociatedInterface(&accessibility_.accessibility_interface_);
  channel->GetRemoteAssociatedInterface(&application_cache_.application_cache_interface_);
  channel->GetRemoteAssociatedInterface(&cache_storage_.cache_storage_interface_);
  channel->GetRemoteAssociatedInterface(&css_.css_interface_);
  channel->GetRemoteAssociatedInterface(&dom_.dom_interface_);
  channel->GetRemoteAssociatedInterface(&dom_snapshot_.dom_snapshot_interface_);
  channel->GetRemoteAssociatedInterface(&device_orientation_.device_orientation_interface_);
  channel->GetRemoteAssociatedInterface(&emulation_.emulation_interface_);
  channel->GetRemoteAssociatedInterface(&database_.database_interface_);
  channel->GetRemoteAssociatedInterface(&overlay_.overlay_interface_);
  channel->GetRemoteAssociatedInterface(&worker_.worker_interface_);
  channel->GetRemoteAssociatedInterface(&dom_storage_.dom_storage_interface_);
  channel->GetRemoteAssociatedInterface(&headless_.headless_interface_);
  channel->GetRemoteAssociatedInterface(&io_.io_interface_);
  channel->GetRemoteAssociatedInterface(&indexed_db_.indexed_db_interface_);
  channel->GetRemoteAssociatedInterface(&storage_.storage_interface_);
  channel->GetRemoteAssociatedInterface(&input_.input_interface_);
  channel->GetRemoteAssociatedInterface(&tethering_.tethering_interface_);
  channel->GetRemoteAssociatedInterface(&network_.network_interface_);
  channel->GetRemoteAssociatedInterface(&layer_tree_.layer_tree_interface_);
  
  // automation::AnimationInterfaceAssociatedPtrInfo anim_ptr;
  // auto r0 = mojo::MakeRequest(&anim_ptr);
  // BindAnimation(std::move(anim_ptr));

  // automation::PageAssociatedPtrInfo page_ptr;
  // auto r1 = mojo::MakeRequest(&page_ptr);
  // BindPage(std::move(page_ptr));

  // automation::OverlayAssociatedPtrInfo overlay_ptr;
  // auto r2 = mojo::MakeRequest(&overlay_ptr);
  // BindOverlay(std::move(overlay_ptr));

  // automation::SystemInfoAssociatedPtrInfo system_info_ptr;
  // auto r3 = mojo::MakeRequest(&system_info_ptr);
  // BindSystemInfo(std::move(system_info_ptr));

  // automation::HostAssociatedPtrInfo host_ptr;
  // auto r4 = mojo::MakeRequest(&host_ptr);
  // BindHost(std::move(host_ptr));

  // automation::AccessibilityAssociatedPtrInfo accessibility_ptr;
  // auto r5 = mojo::MakeRequest(&accessibility_ptr);
  // BindAccessibility(std::move(accessibility_ptr));

  // automation::DOMSnapshotAssociatedPtrInfo dom_snapshot_ptr;
  // auto r6 = mojo::MakeRequest(&dom_snapshot_ptr);
  // BindDOMSnapshot(std::move(dom_snapshot_ptr));

  // automation::ServiceWorkerAssociatedPtrInfo service_worker_ptr;
  // auto r7 = mojo::MakeRequest(&service_worker_ptr);
  // BindWorker(std::move(service_worker_ptr));

  // automation::StorageAssociatedPtrInfo storage_ptr;
  // auto r8 = mojo::MakeRequest(&storage_ptr);
  // BindStorage(std::move(storage_ptr));

  // automation::NetworkAssociatedPtrInfo network_ptr;
  // auto r9 = mojo::MakeRequest(&network_ptr);
  // BindNetwork(std::move(network_ptr));

  // automation::LayerTreeAssociatedPtrInfo layer_tree_ptr;
  // auto r10 = mojo::MakeRequest(&layer_tree_ptr);
  // BindLayerTree(std::move(layer_tree_ptr));

  // automation::HeadlessAssociatedPtrInfo headless_ptr;
  // auto r11 = mojo::MakeRequest(&headless_ptr);
  // BindHeadless(std::move(headless_ptr));

  // automation::DOMStorageAssociatedPtrInfo dom_storage_ptr;
  // auto r12 = mojo::MakeRequest(&dom_storage_ptr);
  // BindDOMStorage(std::move(dom_storage_ptr));

  // automation::DatabaseInterfaceAssociatedPtrInfo database_ptr;
  // auto r13 = mojo::MakeRequest(&database_ptr);
  // BindDatabase(std::move(database_ptr));

  // automation::DOMAssociatedPtrInfo dom_ptr;
  // auto r14 = mojo::MakeRequest(&dom_ptr);
  // BindDOM(std::move(dom_ptr));

  // automation::EmulationAssociatedPtrInfo emu_ptr;
  // auto r15 = mojo::MakeRequest(&emu_ptr);
  // BindEmulation(std::move(emu_ptr));

  // automation::CSSAssociatedPtrInfo css_ptr;
  // auto r16 = mojo::MakeRequest(&css_ptr);
  // BindCSS(std::move(css_ptr));

  // automation::ApplicationCacheInterfaceAssociatedPtrInfo appcache_ptr;
  // auto r17 = mojo::MakeRequest(&appcache_ptr);
  // BindApplicationCache(std::move(appcache_ptr));

  // automation::CacheStorageAssociatedPtrInfo cache_ptr;
  // auto r18 = mojo::MakeRequest(&cache_ptr);
  // BindCacheStorage(std::move(cache_ptr));

  // automation::DeviceOrientationAssociatedPtrInfo dev_ptr;
  // auto r19 = mojo::MakeRequest(&dev_ptr);
  // BindDeviceOrientation(std::move(dev_ptr));

  // automation::IndexedDBAssociatedPtrInfo indexed_db_ptr;
  // auto r20 = mojo::MakeRequest(&indexed_db_ptr);
  // BindIndexedDB(std::move(indexed_db_ptr));

  // automation::IOAssociatedPtrInfo io_ptr;
  // auto r21 = mojo::MakeRequest(&io_ptr);
  // BindIO(std::move(io_ptr));

  // automation::TetheringAssociatedPtrInfo tethering_ptr;
  // auto r22 = mojo::MakeRequest(&tethering_ptr);
  // BindTethering(std::move(tethering_ptr));
}

// void ApplicationDriver::BindAnimation(automation::AnimationInterfaceAssociatedPtrInfo request) {
//   animation_interface_.Bind(std::move(request));
// }

// void ApplicationDriver::BindPage(automation::PageAssociatedPtrInfo request) {
//   page_interface_.Bind(std::move(request));
// } 
  
// void ApplicationDriver::BindOverlay(automation::OverlayAssociatedPtrInfo request) {
//   overlay_interface_.Bind(std::move(request));
// }

// void ApplicationDriver::BindSystemInfo(automation::SystemInfoAssociatedPtrInfo request) {
//   system_info_interface_.Bind(std::move(request));
// }

// void ApplicationDriver::BindHost(automation::HostAssociatedPtrInfo request) {
//   host_interface_.Bind(std::move(request));;
// }

// void ApplicationDriver::BindAccessibility(automation::AccessibilityAssociatedPtrInfo request) {
//   accessibility_interface_.Bind(std::move(request));
// }

// void ApplicationDriver::BindDOMSnapshot(automation::DOMSnapshotAssociatedPtrInfo request) {
//   dom_snapshot_interface_.Bind(std::move(request));
// }
  
// void ApplicationDriver::BindWorker(automation::ServiceWorkerAssociatedPtrInfo request) {
//   worker_interface_.Bind(std::move(request));
// }

// void ApplicationDriver::BindStorage(automation::StorageAssociatedPtrInfo request) {
//   storage_interface_.Bind(std::move(request));
// }

// void ApplicationDriver::BindNetwork(automation::NetworkAssociatedPtrInfo request) {
//   network_interface_.Bind(std::move(request));
// }

// void ApplicationDriver::BindLayerTree(automation::LayerTreeAssociatedPtrInfo request) {
//   layer_tree_interface_.Bind(std::move(request));
// }

// void ApplicationDriver::BindHeadless(automation::HeadlessAssociatedPtrInfo request) {
//   headless_interface_.Bind(std::move(request));
// }

// void ApplicationDriver::BindDOMStorage(automation::DOMStorageAssociatedPtrInfo request) {
//   dom_storage_interface_.Bind(std::move(request));
// }

// void ApplicationDriver::BindDatabase(automation::DatabaseInterfaceAssociatedPtrInfo request) {
//   database_interface_.Bind(std::move(request));
// }

// void ApplicationDriver::BindEmulation(automation::EmulationAssociatedPtrInfo request) {
//   emulation_interface_.Bind(std::move(request));
// }

// void ApplicationDriver::BindDOM(automation::DOMAssociatedPtrInfo request) {
//   dom_interface_.Bind(std::move(request));
// }

// void ApplicationDriver::BindCSS(automation::CSSAssociatedPtrInfo request) {
//   css_interface_.Bind(std::move(request));
// }

// void ApplicationDriver::BindApplicationCache(automation::ApplicationCacheInterfaceAssociatedPtrInfo request) {
//   application_cache_interface_.Bind(std::move(request));
// }

// void ApplicationDriver::BindCacheStorage(automation::CacheStorageAssociatedPtrInfo request) {
//   cache_storage_interface_.Bind(std::move(request));
// }

// void ApplicationDriver::BindDeviceOrientation(automation::DeviceOrientationAssociatedPtrInfo request) {
//   device_orientation_interface_.Bind(std::move(request));
// }

// void ApplicationDriver::BindIO(automation::IOAssociatedPtrInfo request) {
//   io_interface_.Bind(std::move(request));
// }

// void ApplicationDriver::BindIndexedDB(automation::IndexedDBAssociatedPtrInfo request) {
//   indexed_db_interface_.Bind(std::move(request));
// }

// void ApplicationDriver::BindInput(automation::InputAssociatedPtrInfo request) {
//   input_interface_.Bind(std::move(request));
// }

// void ApplicationDriver::BindTethering(automation::TetheringAssociatedPtrInfo request) {
//   tethering_interface_.Bind(std::move(request));
// }

// Clients

void ApplicationDriver::BindAnimationClient(automation::AnimationClientAssociatedRequest request) {
  animation_client_binding_.Bind(std::move(request));
}

void ApplicationDriver::BindPageClient(automation::PageClientAssociatedRequest request) {
  page_client_binding_.Bind(std::move(request));
}

void ApplicationDriver::BindOverlayClient(automation::OverlayClientAssociatedRequest request) {
  overlay_client_binding_.Bind(std::move(request));
}

void ApplicationDriver::BindWorkerClient(automation::ServiceWorkerClientAssociatedRequest request) {
  worker_client_binding_.Bind(std::move(request));
}

void ApplicationDriver::BindStorageClient(automation::StorageClientAssociatedRequest request) {
  storage_client_binding_.Bind(std::move(request));
}

void ApplicationDriver::BindNetworkClient(automation::NetworkClientAssociatedRequest request) {
  network_client_binding_.Bind(std::move(request));
}

void ApplicationDriver::BindLayerTreeClient(automation::LayerTreeClientAssociatedRequest request) {
  layer_tree_client_binding_.Bind(std::move(request));
}

void ApplicationDriver::BindHeadlessClient(automation::HeadlessClientAssociatedRequest request) {
  headless_client_binding_.Bind(std::move(request));
}

void ApplicationDriver::BindDOMStorageClient(automation::DOMStorageClientAssociatedRequest request) {
  dom_storage_client_binding_.Bind(std::move(request));
}

void ApplicationDriver::BindDatabaseClient(automation::DatabaseClientAssociatedRequest request) {
  database_client_binding_.Bind(std::move(request));
}

void ApplicationDriver::BindEmulationClient(automation::EmulationClientAssociatedRequest request) {  
  emulation_client_binding_.Bind(std::move(request));
}

void ApplicationDriver::BindDOMClient(automation::DOMClientAssociatedRequest request) {
  dom_client_binding_.Bind(std::move(request));
}
  
void ApplicationDriver::BindCSSClient(automation::CSSClientAssociatedRequest request) {
  css_client_binding_.Bind(std::move(request));
}

void ApplicationDriver::BindApplicationCacheClient(automation::ApplicationCacheClientAssociatedRequest request) {  
  application_cache_client_binding_.Bind(std::move(request));
}

void ApplicationDriver::OnFrameAttached(const std::string& frame_id, const std::string& parent_frame_id) {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&ApplicationDriver::OnFrameAttachedImpl, 
      base::Unretained(this), 
      frame_id, 
      parent_frame_id));
}

void ApplicationDriver::OnDomContentEventFired(int64_t timestamp) {
   HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&ApplicationDriver::OnDomContentEventFiredImpl, 
      base::Unretained(this), 
      timestamp)); 
}

void ApplicationDriver::OnFrameClearedScheduledNavigation(const std::string& frame_id) {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&ApplicationDriver::OnFrameClearedScheduledNavigationImpl, 
      base::Unretained(this), 
      frame_id));
}

void ApplicationDriver::OnFrameDetached(const std::string& frame_id) {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&ApplicationDriver::OnFrameDetachedImpl, 
      base::Unretained(this), 
      frame_id));
}

void ApplicationDriver::OnFrameNavigated(automation::FramePtr frame) {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&ApplicationDriver::OnFrameNavigatedImpl, 
      base::Unretained(this), 
      base::Passed(std::move(frame))));
}

void ApplicationDriver::OnFrameResized() {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&ApplicationDriver::OnFrameResizedImpl, 
      base::Unretained(this)));
}

void ApplicationDriver::OnFrameScheduledNavigation(const std::string& frame_id, int32_t delay, automation::NavigationReason reason, const std::string& url) {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&ApplicationDriver::OnFrameScheduledNavigationImpl, 
      base::Unretained(this),
      frame_id,
      delay,
      reason,
      url));
}

void ApplicationDriver::OnFrameStartedLoading(const std::string& frame_id) {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&ApplicationDriver::OnFrameStartedLoadingImpl, 
      base::Unretained(this),
      frame_id));
}

void ApplicationDriver::OnFrameStoppedLoading(const std::string& frame_id) {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&ApplicationDriver::OnFrameStoppedLoadingImpl, 
      base::Unretained(this),
      frame_id));
}

void ApplicationDriver::OnInterstitialHidden() {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&ApplicationDriver::OnInterstitialHiddenImpl, 
      base::Unretained(this)));
}

void ApplicationDriver::OnInterstitialShown() {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&ApplicationDriver::OnInterstitialShownImpl, 
      base::Unretained(this)));
}

void ApplicationDriver::OnJavascriptDialogClosed(bool result, const std::string& user_input) {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&ApplicationDriver::OnJavascriptDialogClosedImpl, 
      base::Unretained(this),
      result,
      user_input));
}

void ApplicationDriver::OnJavascriptDialogOpening(const std::string& url, const std::string& message, automation::DialogType type, bool has_browser_handler, const base::Optional<std::string>& default_prompt) {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&ApplicationDriver::OnJavascriptDialogOpeningImpl, 
      base::Unretained(this),
      url,
      message,
      type,
      has_browser_handler,
      default_prompt));
}

void ApplicationDriver::OnLifecycleEvent(const std::string& frame_id, int32_t loader_id, const std::string& name, int64_t timestamp) {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&ApplicationDriver::OnLifecycleEventImpl, 
      base::Unretained(this),
      frame_id,
      loader_id,
      name,
      timestamp));
}

void ApplicationDriver::OnLoadEventFired(int64_t timestamp) {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&ApplicationDriver::OnLoadEventFiredImpl, 
      base::Unretained(this),
      timestamp));
}

void ApplicationDriver::OnNavigatedWithinDocument(const std::string& frame_id, const std::string& url) {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&ApplicationDriver::OnNavigatedWithinDocumentImpl, 
      base::Unretained(this),
      frame_id,
      url));
}

void ApplicationDriver::OnScreencastFrame(const std::string& base64_data, automation::ScreencastFrameMetadataPtr metadata, int32_t session_id) {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&ApplicationDriver::OnScreencastFrameImpl, 
      base::Unretained(this),
      base64_data,
      std::move(metadata),
      session_id));
}

void ApplicationDriver::OnScreencastVisibilityChanged(bool visible) {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&ApplicationDriver::OnScreencastVisibilityChangedImpl, 
      base::Unretained(this),
      visible));
}

void ApplicationDriver::OnWindowOpen(const std::string& url, const std::string& window_name, const std::vector<std::string>& window_features, bool user_gesture) {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&ApplicationDriver::OnWindowOpenImpl, 
      base::Unretained(this),
      url,
      window_name,
      window_features,
      user_gesture));
}

void ApplicationDriver::OnPageLayoutInvalidated(bool resized) {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&ApplicationDriver::OnPageLayoutInvalidatedImpl, 
      base::Unretained(this),
      resized));
}

void ApplicationDriver::InspectNodeRequested(int32_t backend_node_id) {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&ApplicationDriver::InspectNodeRequestedImpl, 
      base::Unretained(this),
      backend_node_id));
}

void ApplicationDriver::NodeHighlightRequested(int32_t node_id) {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&ApplicationDriver::NodeHighlightRequestedImpl, 
      base::Unretained(this),
      node_id));
}

void ApplicationDriver::ScreenshotRequested(automation::ViewportPtr viewport) {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&ApplicationDriver::ScreenshotRequestedImpl, 
      base::Unretained(this),
      base::Passed(std::move(viewport))));
}

void ApplicationDriver::WorkerErrorReported(automation::ServiceWorkerErrorMessagePtr error_message) {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&ApplicationDriver::WorkerErrorReportedImpl, 
      base::Unretained(this),
      base::Passed(std::move(error_message))));
}

void ApplicationDriver::WorkerRegistrationUpdated(std::vector<automation::ServiceWorkerRegistrationPtr> registrations) {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&ApplicationDriver::WorkerRegistrationUpdatedImpl, 
      base::Unretained(this),
      base::Passed(std::move(registrations))));
}

void ApplicationDriver::WorkerVersionUpdated(std::vector<automation::ServiceWorkerVersionPtr> versions) {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&ApplicationDriver::WorkerVersionUpdatedImpl, 
      base::Unretained(this),
      base::Passed(std::move(versions))));
}

void ApplicationDriver::OnAttachedToTarget(const std::string& session_id, automation::TargetInfoPtr target_info, bool waiting_for_debugger) {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&ApplicationDriver::OnAttachedToTargetImpl, 
      base::Unretained(this),
      session_id, 
      base::Passed(std::move(target_info)),
      waiting_for_debugger));
}

void ApplicationDriver::OnDetachedFromTarget(const std::string& session_id, const base::Optional<std::string>& target_id) {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&ApplicationDriver::OnDetachedFromTargetImpl, 
      base::Unretained(this),
      session_id, 
      target_id));
}

void ApplicationDriver::OnReceivedMessageFromTarget(const std::string& session_id, const std::string& message, const base::Optional<std::string>& target_id) {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&ApplicationDriver::OnReceivedMessageFromTargetImpl, 
      base::Unretained(this),
      session_id, 
      message,
      target_id));
}

void ApplicationDriver::OnCacheStorageContentUpdated(const std::string& origin, const std::string& cache_name) {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&ApplicationDriver::OnCacheStorageContentUpdatedImpl, 
      base::Unretained(this),
      origin, 
      cache_name));
}

void ApplicationDriver::OnCacheStorageListUpdated(const std::string& origin) {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&ApplicationDriver::OnCacheStorageListUpdatedImpl, 
      base::Unretained(this),
      origin));
}

void ApplicationDriver::OnIndexedDBContentUpdated(const std::string& origin, const std::string& database_name, const std::string& object_store_name) {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&ApplicationDriver::OnIndexedDBContentUpdatedImpl, 
      base::Unretained(this),
      origin,
      database_name,
      object_store_name));
}

void ApplicationDriver::OnIndexedDBListUpdated(const std::string& origin) {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&ApplicationDriver::OnIndexedDBListUpdatedImpl, 
      base::Unretained(this),
      origin));
}

void ApplicationDriver::OnAccepted(int32_t port, const std::string& connection_id) {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&ApplicationDriver::OnAcceptedImpl, 
      base::Unretained(this),
      port,
      connection_id));
}

void ApplicationDriver::OnDataReceived(const std::string& request_id, int64_t timestamp, int64_t data_length, int64_t encoded_data_length) {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&ApplicationDriver::OnDataReceivedImpl, 
      base::Unretained(this),
      request_id,
      timestamp,
      data_length,
      encoded_data_length));
}

void ApplicationDriver::OnEventSourceMessageReceived(const std::string& request_id, int64_t timestamp, const std::string& event_name, const std::string& event_id, const std::string& data) {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&ApplicationDriver::OnEventSourceMessageReceivedImpl, 
      base::Unretained(this),
      request_id,
      timestamp,
      event_name,
      event_id,
      data));
}

void ApplicationDriver::OnLoadingFailed(const std::string& request_id, int64_t timestamp, automation::ResourceType type, const std::string& error_text, bool canceled, automation::BlockedReason blocked_reason) {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&ApplicationDriver::OnLoadingFailedImpl, 
      base::Unretained(this),
      request_id,
      timestamp,
      type,
      error_text, 
      canceled, 
      blocked_reason));
}

void ApplicationDriver::OnLoadingFinished(const std::string& request_id, int64_t timestamp, int64_t encoded_data_length, bool blocked_cross_site_document) {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&ApplicationDriver::OnLoadingFinishedImpl, 
      base::Unretained(this),
      request_id,
      timestamp,
      encoded_data_length,
      blocked_cross_site_document));
}

void ApplicationDriver::OnRequestIntercepted(const std::string& interception_id, automation::RequestPtr request, const std::string& frame_id, automation::ResourceType resource_type, bool is_navigation_request, bool is_download, const base::Optional<std::string>& redirect_url, automation::AuthChallengePtr auth_challenge, automation::ErrorReason response_error_reason, int32_t response_status_code, const base::Optional<base::flat_map<std::string, std::string>>& response_headers) {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&ApplicationDriver::OnRequestInterceptedImpl, 
      base::Unretained(this),
      interception_id,
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

void ApplicationDriver::OnRequestServedFromCache(const std::string& request_id) {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&ApplicationDriver::OnRequestServedFromCacheImpl, 
      base::Unretained(this),
      request_id));
}

void ApplicationDriver::OnRequestWillBeSent(const std::string& request_id, const std::string& loader_id, const std::string& document_url, automation::RequestPtr request, int64_t timestamp, int64_t wall_time, automation::InitiatorPtr initiator, automation::ResponsePtr redirect_response, automation::ResourceType type, const base::Optional<std::string>& frame_id, bool has_user_gesture) {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&ApplicationDriver::OnRequestWillBeSentImpl, 
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

void ApplicationDriver::OnResourceChangedPriority(const std::string& request_id, automation::ResourcePriority new_priority, int64_t timestamp) {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&ApplicationDriver::OnResourceChangedPriorityImpl, 
      base::Unretained(this),
      request_id,
      new_priority,
      timestamp));
}

void ApplicationDriver::OnResponseReceived(const std::string& request_id, const std::string& loader_id, int64_t timestamp, automation::ResourceType type, automation::ResponsePtr response, const base::Optional<std::string>& frame_id) {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&ApplicationDriver::OnResponseReceivedImpl, 
      base::Unretained(this),
      request_id,
      loader_id,
      timestamp,
      type,
      base::Passed(std::move(response)), 
      frame_id));
}

void ApplicationDriver::OnWebSocketClosed(const std::string& request_id, int64_t timestamp) {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&ApplicationDriver::OnWebSocketClosedImpl, 
      base::Unretained(this),
      request_id,
      timestamp));
}

void ApplicationDriver::OnWebSocketCreated(const std::string& request_id, const std::string& url, automation::InitiatorPtr initiator) {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&ApplicationDriver::OnWebSocketCreatedImpl, 
      base::Unretained(this),
      request_id,
      url,
      base::Passed(std::move(initiator))));
}

void ApplicationDriver::OnWebSocketFrameError(const std::string& request_id, int64_t timestamp, const std::string& error_message) {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&ApplicationDriver::OnWebSocketFrameErrorImpl, 
      base::Unretained(this),
      request_id,
      timestamp,
      error_message));
}

void ApplicationDriver::OnWebSocketFrameReceived(const std::string& request_id, int64_t timestamp, automation::WebSocketFramePtr response) {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&ApplicationDriver::OnWebSocketFrameReceivedImpl, 
      base::Unretained(this),
      request_id,
      timestamp,
      base::Passed(std::move(response))));
}

void ApplicationDriver::OnWebSocketFrameSent(const std::string& request_id, int64_t timestamp, automation::WebSocketFramePtr response) {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&ApplicationDriver::OnWebSocketFrameSentImpl, 
      base::Unretained(this),
      request_id,
      timestamp,
      base::Passed(std::move(response))));
}

void ApplicationDriver::OnWebSocketHandshakeResponseReceived(const std::string& request_id, int64_t timestamp, automation::WebSocketResponsePtr response) {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&ApplicationDriver::OnWebSocketHandshakeResponseReceivedImpl, 
      base::Unretained(this),
      request_id,
      timestamp,
      base::Passed(std::move(response))));
}

void ApplicationDriver::OnWebSocketWillSendHandshakeRequest(const std::string& request_id, int64_t timestamp, int64_t wall_time, automation::WebSocketRequestPtr request) {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&ApplicationDriver::OnWebSocketWillSendHandshakeRequestImpl, 
      base::Unretained(this),
      request_id,
      timestamp,
      wall_time,
      base::Passed(std::move(request))));
}

void ApplicationDriver::Flush() {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&ApplicationDriver::FlushImpl, 
      base::Unretained(this)));
}

void ApplicationDriver::OnLayerPainted(const std::string& layer_id, const gfx::Rect& clip) {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&ApplicationDriver::OnLayerPaintedImpl, 
      base::Unretained(this),
      layer_id,
      clip));
}

void ApplicationDriver::OnLayerTreeDidChange(base::Optional<std::vector<automation::LayerPtr>> layers) {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&ApplicationDriver::OnLayerTreeDidChangeImpl, 
      base::Unretained(this),
      base::Passed(std::move(layers))));
}

void ApplicationDriver::OnNeedsBeginFramesChanged(bool needs_begin_frames) {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&ApplicationDriver::OnNeedsBeginFramesChangedImpl, 
      base::Unretained(this),
      needs_begin_frames));
}

void ApplicationDriver::OnDomStorageItemAdded(automation::StorageIdPtr storage_id, const std::string& key, const std::string& new_value) {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&ApplicationDriver::OnDomStorageItemAddedImpl, 
      base::Unretained(this),
      base::Passed(std::move(storage_id)),
      key, 
      new_value));
}

void ApplicationDriver::OnDomStorageItemRemoved(automation::StorageIdPtr storage_id, const std::string& key) {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&ApplicationDriver::OnDomStorageItemRemovedImpl, 
      base::Unretained(this),
      base::Passed(std::move(storage_id)),
      key));
}

void ApplicationDriver::OnDomStorageItemUpdated(automation::StorageIdPtr storage_id, const std::string& key, const std::string& old_value, const std::string& new_value) {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&ApplicationDriver::OnDomStorageItemUpdatedImpl, 
      base::Unretained(this),
      base::Passed(std::move(storage_id)),
      key, 
      old_value,
      new_value));
}

void ApplicationDriver::OnDomStorageItemsCleared(automation::StorageIdPtr storage_id) {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&ApplicationDriver::OnDomStorageItemsClearedImpl, 
      base::Unretained(this),
      base::Passed(std::move(storage_id))));
}

void ApplicationDriver::OnAddDatabase(automation::DatabasePtr database) {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&ApplicationDriver::OnAddDatabaseImpl, 
      base::Unretained(this),
      base::Passed(std::move(database))));
}

void ApplicationDriver::OnVirtualTimeAdvanced(int32_t virtual_time_elapsed) {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&ApplicationDriver::OnVirtualTimeAdvancedImpl, 
      base::Unretained(this),
      virtual_time_elapsed));
}

void ApplicationDriver::OnVirtualTimeBudgetExpired() {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&ApplicationDriver::OnVirtualTimeBudgetExpiredImpl, 
      base::Unretained(this)));
}

void ApplicationDriver::OnVirtualTimePaused(int32_t virtual_time_elapsed) {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&ApplicationDriver::OnVirtualTimePausedImpl, 
      base::Unretained(this),
      virtual_time_elapsed));
}

void ApplicationDriver::SetChildNodes(int32_t parent_id, std::vector<automation::DOMNodePtr> nodes) {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&ApplicationDriver::SetChildNodesImpl, 
      base::Unretained(this),
      parent_id,
      base::Passed(std::move(nodes))));
}

void ApplicationDriver::OnAttributeModified(int32_t node_id, const std::string& name, const std::string& value) {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&ApplicationDriver::OnAttributeModifiedImpl, 
      base::Unretained(this),
      node_id,
      name,
      value));
}

void ApplicationDriver::OnAttributeRemoved(int32_t node_id, const std::string& name) {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&ApplicationDriver::OnAttributeRemovedImpl, 
      base::Unretained(this),
      node_id,
      name));
}

void ApplicationDriver::OnCharacterDataModified(int32_t node_id, const std::string& character_data) {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&ApplicationDriver::OnCharacterDataModifiedImpl, 
      base::Unretained(this),
      node_id,
      character_data));
}

void ApplicationDriver::OnChildNodeCountUpdated(int32_t node_id, int32_t child_node_count) {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&ApplicationDriver::OnChildNodeCountUpdatedImpl, 
      base::Unretained(this),
      node_id,
      child_node_count));
}

void ApplicationDriver::OnChildNodeInserted(int32_t parent_node_id, int32_t previous_node_id, automation::DOMNodePtr node) {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&ApplicationDriver::OnChildNodeInsertedImpl, 
      base::Unretained(this),
      parent_node_id,
      previous_node_id,
      base::Passed(std::move(node))));
}

void ApplicationDriver::OnChildNodeRemoved(int32_t parent_node_id, int32_t node_id) {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&ApplicationDriver::OnChildNodeRemovedImpl, 
      base::Unretained(this),
      parent_node_id,
      node_id));
}

void ApplicationDriver::OnDistributedNodesUpdated(int32_t insertion_point_id, std::vector<automation::BackendNodePtr> distributed_nodes) {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&ApplicationDriver::OnDistributedNodesUpdatedImpl, 
      base::Unretained(this),
      insertion_point_id,
      base::Passed(std::move(distributed_nodes))));
}

void ApplicationDriver::OnDocumentUpdated() {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&ApplicationDriver::OnDocumentUpdatedImpl, 
      base::Unretained(this)));
}

void ApplicationDriver::OnInlineStyleInvalidated(const std::vector<int32_t>& node_ids) {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&ApplicationDriver::OnInlineStyleInvalidatedImpl, 
      base::Unretained(this),
      node_ids));
}

void ApplicationDriver::OnPseudoElementAdded(int32_t parent_id, automation::DOMNodePtr pseudo_element) {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&ApplicationDriver::OnPseudoElementAddedImpl, 
      base::Unretained(this),
      parent_id,
      base::Passed(std::move(pseudo_element))));
}

void ApplicationDriver::OnPseudoElementRemoved(int32_t parent_id, int32_t pseudo_element_id) {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&ApplicationDriver::OnPseudoElementRemovedImpl, 
      base::Unretained(this),
      parent_id,
      pseudo_element_id));
}

void ApplicationDriver::OnShadowRootPopped(int32_t host_id, int32_t root_id) {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&ApplicationDriver::OnShadowRootPoppedImpl, 
      base::Unretained(this),
      host_id,
      root_id));
}

void ApplicationDriver::OnShadowRootPushed(int32_t host_id, automation::DOMNodePtr root) {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&ApplicationDriver::OnShadowRootPushedImpl, 
      base::Unretained(this),
      host_id,
      base::Passed(std::move(root))));
}

void ApplicationDriver::OnFontsUpdated(automation::FontFacePtr font) {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&ApplicationDriver::OnFontsUpdatedImpl, 
      base::Unretained(this),
      base::Passed(std::move(font))));
}

void ApplicationDriver::OnMediaQueryResultChanged() {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&ApplicationDriver::OnMediaQueryResultChangedImpl, 
      base::Unretained(this)));
}

void ApplicationDriver::OnStyleSheetAdded(automation::CSSStyleSheetHeaderPtr header) {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&ApplicationDriver::OnStyleSheetAddedImpl, 
      base::Unretained(this),
      base::Passed(std::move(header))));
}

void ApplicationDriver::OnStyleSheetChanged(const std::string& style_sheet_id) {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&ApplicationDriver::OnStyleSheetChangedImpl, 
      base::Unretained(this),
      style_sheet_id));
}

void ApplicationDriver::OnStyleSheetRemoved(const std::string& style_sheet_id) {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&ApplicationDriver::OnStyleSheetRemovedImpl, 
      base::Unretained(this),
      style_sheet_id));
}

void ApplicationDriver::OnApplicationCacheStatusUpdated(const std::string& frame_id, const std::string& manifest_url, int32_t status) {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&ApplicationDriver::OnApplicationCacheStatusUpdatedImpl, 
      base::Unretained(this),
      frame_id, manifest_url, status));
}

void ApplicationDriver::OnNetworkStateUpdated(bool is_now_online) {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&ApplicationDriver::OnNetworkStateUpdatedImpl, 
      base::Unretained(this),
      is_now_online));
}

void ApplicationDriver::OnAnimationCanceled(const std::string& id) {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&ApplicationDriver::OnAnimationCanceledImpl, 
      base::Unretained(this),
      id));
}

void ApplicationDriver::OnAnimationCreated(const std::string& id) {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&ApplicationDriver::OnAnimationCreatedImpl, 
      base::Unretained(this),
      id));
}

void ApplicationDriver::OnAnimationStarted(automation::AnimationPtr animation) {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&ApplicationDriver::OnAnimationStartedImpl, 
      base::Unretained(this),
      base::Passed(std::move(animation))));
}

/*
 * Impls
 */

void ApplicationDriver::OnFrameAttachedImpl(const std::string& frame_id, const std::string& parent_frame_id) {
  for (auto& observer : observers_) {
    observer.OnFrameAttached(frame_id, parent_frame_id);
  }
}

void ApplicationDriver::OnDomContentEventFiredImpl(int64_t timestamp) {
  for (auto& observer : observers_) {
    observer.OnDomContentEventFired(timestamp);
  }
}

void ApplicationDriver::OnFrameClearedScheduledNavigationImpl(const std::string& frame_id) {
  for (auto& observer : observers_) {
    observer.OnFrameClearedScheduledNavigation(frame_id);
  }
}

void ApplicationDriver::OnFrameDetachedImpl(const std::string& frame_id) {
  for (auto& observer : observers_) {
    observer.OnFrameDetached(frame_id);
  }
}

void ApplicationDriver::OnFrameNavigatedImpl(automation::FramePtr frame) {
  for (auto& observer : observers_) {
    observer.OnFrameNavigated(std::move(frame));
  }
}

void ApplicationDriver::OnFrameResizedImpl() {
  for (auto& observer : observers_) {
    observer.OnFrameResized();
  }
}

void ApplicationDriver::OnFrameScheduledNavigationImpl(const std::string& frame_id, int32_t delay, automation::NavigationReason reason, const std::string& url) {
  for (auto& observer : observers_) {
    observer.OnFrameScheduledNavigation(frame_id, delay, reason, url);
  }
}

void ApplicationDriver::OnFrameStartedLoadingImpl(const std::string& frame_id) {
  for (auto& observer : observers_) {
    observer.OnFrameStartedLoading(frame_id);
  }
}

void ApplicationDriver::OnFrameStoppedLoadingImpl(const std::string& frame_id) {
  for (auto& observer : observers_) {
    observer.OnFrameStoppedLoading(frame_id);
  }
}

void ApplicationDriver::OnInterstitialHiddenImpl() {
  for (auto& observer : observers_) {
    observer.OnInterstitialHidden();
  }
}

void ApplicationDriver::OnInterstitialShownImpl() {
  for (auto& observer : observers_) {
    observer.OnInterstitialShown();
  }
}

void ApplicationDriver::OnJavascriptDialogClosedImpl(bool result, const std::string& user_input) {
  for (auto& observer : observers_) {
    observer.OnJavascriptDialogClosed(result, user_input);
  }
}

void ApplicationDriver::OnJavascriptDialogOpeningImpl(const std::string& url, const std::string& message, automation::DialogType type, bool has_browser_handler, const base::Optional<std::string>& default_prompt) { 
  for (auto& observer : observers_) {
    observer.OnJavascriptDialogOpening(url, message, type, has_browser_handler, default_prompt);
  }
}

void ApplicationDriver::OnLifecycleEventImpl(const std::string& frame_id, int32_t loader_id, const std::string& name, int64_t timestamp) {
  for (auto& observer : observers_) {
    observer.OnLifecycleEvent(frame_id, loader_id, name, timestamp);
  }
}

void ApplicationDriver::OnLoadEventFiredImpl(int64_t timestamp) {
  for (auto& observer : observers_) {
    observer.OnLoadEventFired(timestamp);
  }
}

void ApplicationDriver::OnNavigatedWithinDocumentImpl(const std::string& frame_id, const std::string& url) {
  for (auto& observer : observers_) {
    observer.OnNavigatedWithinDocument(frame_id, url);
  }
}

void ApplicationDriver::OnScreencastFrameImpl(const std::string& base64_data, automation::ScreencastFrameMetadataPtr metadata, int32_t session_id) {
  for (auto& observer : observers_) {
    observer.OnScreencastFrame(base64_data, std::move(metadata), session_id);
  }
}

void ApplicationDriver::OnScreencastVisibilityChangedImpl(bool visible) {
  for (auto& observer : observers_) {
    observer.OnScreencastVisibilityChanged(visible);
  }
}

void ApplicationDriver::OnWindowOpenImpl(const std::string& url, const std::string& window_name, const std::vector<std::string>& window_features, bool user_gesture) {
  for (auto& observer : observers_) {
    observer.OnWindowOpen(url, window_name, window_features, user_gesture);
  }
}

void ApplicationDriver::OnPageLayoutInvalidatedImpl(bool resized) {
  for (auto& observer : observers_) {
    observer.OnPageLayoutInvalidated(resized);
  }
}

void ApplicationDriver::InspectNodeRequestedImpl(int32_t backend_node_id) {
  for (auto& observer : observers_) {
    observer.InspectNodeRequested(backend_node_id);
  }
}

void ApplicationDriver::NodeHighlightRequestedImpl(int32_t node_id) {
  for (auto& observer : observers_) {
    observer.NodeHighlightRequested(node_id);
  }
}

void ApplicationDriver::ScreenshotRequestedImpl(automation::ViewportPtr viewport) {
  for (auto& observer : observers_) {
    observer.ScreenshotRequested(std::move(viewport));
  }
}

void ApplicationDriver::WorkerErrorReportedImpl(automation::ServiceWorkerErrorMessagePtr error_message) {
  for (auto& observer : observers_) {
    observer.WorkerErrorReported(std::move(error_message));
  }
}

void ApplicationDriver::WorkerRegistrationUpdatedImpl(std::vector<automation::ServiceWorkerRegistrationPtr> registrations) {
  for (auto& observer : observers_) {
    observer.WorkerRegistrationUpdated(std::move(registrations));
  }
}

void ApplicationDriver::WorkerVersionUpdatedImpl(std::vector<automation::ServiceWorkerVersionPtr> versions) {
  for (auto& observer : observers_) {
    observer.WorkerVersionUpdated(std::move(versions));
  }
}

void ApplicationDriver::OnAttachedToTargetImpl(const std::string& session_id, automation::TargetInfoPtr target_info, bool waiting_for_debugger) {
  for (auto& observer : observers_) {
    observer.OnAttachedToTarget(session_id, std::move(target_info), waiting_for_debugger);
  }
}

void ApplicationDriver::OnDetachedFromTargetImpl(const std::string& session_id, const base::Optional<std::string>& target_id) {
  for (auto& observer : observers_) {
    observer.OnDetachedFromTarget(session_id, target_id);
  }
}

void ApplicationDriver::OnReceivedMessageFromTargetImpl(const std::string& session_id, const std::string& message, const base::Optional<std::string>& target_id) {
  for (auto& observer : observers_) {
    observer.OnReceivedMessageFromTarget(session_id, message, target_id);
  }
}

void ApplicationDriver::OnCacheStorageContentUpdatedImpl(const std::string& origin, const std::string& cache_name) {
  for (auto& observer : observers_) {
    observer.OnCacheStorageContentUpdated(origin, cache_name);
  }
}

void ApplicationDriver::OnCacheStorageListUpdatedImpl(const std::string& origin) {
  for (auto& observer : observers_) {
    observer.OnCacheStorageListUpdated(origin);
  }
}

void ApplicationDriver::OnIndexedDBContentUpdatedImpl(const std::string& origin, const std::string& database_name, const std::string& object_store_name) {
  for (auto& observer : observers_) {
    observer.OnIndexedDBContentUpdated(origin, database_name, object_store_name);
  }
}

void ApplicationDriver::OnIndexedDBListUpdatedImpl(const std::string& origin) {
  for (auto& observer : observers_) {
    observer.OnIndexedDBListUpdated(origin);
  }
}

void ApplicationDriver::OnAcceptedImpl(int32_t port, const std::string& connection_id) {
  for (auto& observer : observers_) {
    observer.OnAccepted(port, connection_id);
  }
}

void ApplicationDriver::OnDataReceivedImpl(const std::string& request_id, int64_t timestamp, int64_t data_length, int64_t encoded_data_length) {
  for (auto& observer : observers_) {
    observer.OnDataReceived(request_id, timestamp, data_length, encoded_data_length);
  }
}

void ApplicationDriver::OnEventSourceMessageReceivedImpl(const std::string& request_id, int64_t timestamp, const std::string& event_name, const std::string& event_id, const std::string& data) {
  for (auto& observer : observers_) {
    observer.OnEventSourceMessageReceived(request_id, timestamp, event_name, event_id, data);
  }
}

void ApplicationDriver::OnLoadingFailedImpl(const std::string& request_id, int64_t timestamp, automation::ResourceType type, const std::string& error_text, bool canceled, automation::BlockedReason blocked_reason) {
  for (auto& observer : observers_) {
    observer.OnLoadingFailed(request_id, timestamp, type, error_text, canceled, blocked_reason);
  }
}

void ApplicationDriver::OnLoadingFinishedImpl(const std::string& request_id, int64_t timestamp, int64_t encoded_data_length, bool blocked_cross_site_document) {
  for (auto& observer : observers_) {
    observer.OnLoadingFinished(request_id, timestamp, encoded_data_length, blocked_cross_site_document);
  }
}

void ApplicationDriver::OnRequestInterceptedImpl(const std::string& interception_id, automation::RequestPtr request, const std::string& frame_id, automation::ResourceType resource_type, bool is_navigation_request, bool is_download, const base::Optional<std::string>& redirect_url, automation::AuthChallengePtr auth_challenge, automation::ErrorReason response_error_reason, int32_t response_status_code, const base::Optional<base::flat_map<std::string, std::string>>& response_headers) {
  for (auto& observer : observers_) {
    observer.OnRequestIntercepted(interception_id, std::move(request), frame_id, resource_type, is_navigation_request, is_download, redirect_url, std::move(auth_challenge), response_error_reason, response_status_code, response_headers);
  }
}

void ApplicationDriver::OnRequestServedFromCacheImpl(const std::string& request_id) {
  for (auto& observer : observers_) {
    observer.OnRequestServedFromCache(request_id);
  }
}

void ApplicationDriver::OnRequestWillBeSentImpl(const std::string& request_id, const std::string& loader_id, const std::string& document_url, automation::RequestPtr request, int64_t timestamp, int64_t wall_time, automation::InitiatorPtr initiator, automation::ResponsePtr redirect_response, automation::ResourceType type, const base::Optional<std::string>& frame_id, bool has_user_gesture) {
  for (auto& observer : observers_) {
    observer.OnRequestWillBeSent(request_id, loader_id, document_url, std::move(request), timestamp, wall_time, std::move(initiator), std::move(redirect_response), type, frame_id, has_user_gesture);
  }
}

void ApplicationDriver::OnResourceChangedPriorityImpl(const std::string& request_id, automation::ResourcePriority new_priority, int64_t timestamp) {
  for (auto& observer : observers_) {
    observer.OnResourceChangedPriority(request_id, new_priority, timestamp);
  }
}

void ApplicationDriver::OnResponseReceivedImpl(const std::string& request_id, const std::string& loader_id, int64_t timestamp, automation::ResourceType type, automation::ResponsePtr response, const base::Optional<std::string>& frame_id) {
  for (auto& observer : observers_) {
    observer.OnResponseReceived(request_id, loader_id, timestamp, type, std::move(response), frame_id);
  }
}

void ApplicationDriver::OnWebSocketClosedImpl(const std::string& request_id, int64_t timestamp) {
  for (auto& observer : observers_) {
    observer.OnWebSocketClosed(request_id, timestamp);
  }
}

void ApplicationDriver::OnWebSocketCreatedImpl(const std::string& request_id, const std::string& url, automation::InitiatorPtr initiator) {
  for (auto& observer : observers_) {
    observer.OnWebSocketCreated(request_id, url, std::move(initiator));
  }
}

void ApplicationDriver::OnWebSocketFrameErrorImpl(const std::string& request_id, int64_t timestamp, const std::string& error_message) {
  for (auto& observer : observers_) {
    observer.OnWebSocketFrameError(request_id, timestamp, error_message);
  }
}

void ApplicationDriver::OnWebSocketFrameReceivedImpl(const std::string& request_id, int64_t timestamp, automation::WebSocketFramePtr response) {
  for (auto& observer : observers_) {
    observer.OnWebSocketFrameReceived(request_id, timestamp, std::move(response));
  }
}

void ApplicationDriver::OnWebSocketFrameSentImpl(const std::string& request_id, int64_t timestamp, automation::WebSocketFramePtr response) {
  for (auto& observer : observers_) {
    observer.OnWebSocketFrameSent(request_id, timestamp, std::move(response));
  }
}

void ApplicationDriver::OnWebSocketHandshakeResponseReceivedImpl(const std::string& request_id, int64_t timestamp, automation::WebSocketResponsePtr response) {
  for (auto& observer : observers_) {
    observer.OnWebSocketHandshakeResponseReceived(request_id, timestamp, std::move(response));
  }
}

void ApplicationDriver::OnWebSocketWillSendHandshakeRequestImpl(const std::string& request_id, int64_t timestamp, int64_t wall_time, automation::WebSocketRequestPtr request) {
  for (auto& observer : observers_) {
    observer.OnWebSocketWillSendHandshakeRequest(request_id, timestamp, wall_time, std::move(request));
  }
}

void ApplicationDriver::FlushImpl() {
  for (auto& observer : observers_) {
    observer.Flush();
  }
}

void ApplicationDriver::OnLayerPaintedImpl(const std::string& layer_id, const gfx::Rect& clip) {
  for (auto& observer : observers_) {
    observer.OnLayerPainted(layer_id, clip);
  }
}

void ApplicationDriver::OnLayerTreeDidChangeImpl(base::Optional<std::vector<automation::LayerPtr>> layers) {
  for (auto& observer : observers_) {
    observer.OnLayerTreeDidChange(std::move(layers));
  }
}

void ApplicationDriver::OnNeedsBeginFramesChangedImpl(bool needs_begin_frames) {
  for (auto& observer : observers_) {
    observer.OnNeedsBeginFramesChanged(needs_begin_frames);
  }
}

void ApplicationDriver::OnDomStorageItemAddedImpl(automation::StorageIdPtr storage_id, const std::string& key, const std::string& new_value) {
  for (auto& observer : observers_) {
    observer.OnDomStorageItemAdded(std::move(storage_id), key, new_value);
  }
}

void ApplicationDriver::OnDomStorageItemRemovedImpl(automation::StorageIdPtr storage_id, const std::string& key) {
  for (auto& observer : observers_) {
    observer.OnDomStorageItemRemoved(std::move(storage_id), key);
  }
}

void ApplicationDriver::OnDomStorageItemUpdatedImpl(automation::StorageIdPtr storage_id, const std::string& key, const std::string& old_value, const std::string& new_value) {
  for (auto& observer : observers_) {
    observer.OnDomStorageItemUpdated(std::move(storage_id), key, old_value, new_value);
  }
}

void ApplicationDriver::OnDomStorageItemsClearedImpl(automation::StorageIdPtr storage_id) {
  for (auto& observer : observers_) {
    observer.OnDomStorageItemsCleared(std::move(storage_id));
  }
}

void ApplicationDriver::OnAddDatabaseImpl(automation::DatabasePtr database) {
  for (auto& observer : observers_) {
    observer.OnAddDatabase(std::move(database));
  }
}

void ApplicationDriver::OnVirtualTimeAdvancedImpl(int32_t virtual_time_elapsed) {
  for (auto& observer : observers_) {
    observer.OnVirtualTimeAdvanced(virtual_time_elapsed);
  }
}

void ApplicationDriver::OnVirtualTimeBudgetExpiredImpl() {
  for (auto& observer : observers_) {
    observer.OnVirtualTimeBudgetExpired();
  }
}

void ApplicationDriver::OnVirtualTimePausedImpl(int32_t virtual_time_elapsed) {
  for (auto& observer : observers_) {
    observer.OnVirtualTimePaused(virtual_time_elapsed);
  }
}

void ApplicationDriver::SetChildNodesImpl(int32_t parent_id, std::vector<automation::DOMNodePtr> nodes) {
  for (auto& observer : observers_) {
    observer.SetChildNodes(parent_id, std::move(nodes));
  }
}

void ApplicationDriver::OnAttributeModifiedImpl(int32_t node_id, const std::string& name, const std::string& value) {
  for (auto& observer : observers_) {
    observer.OnAttributeModified(node_id, name, value);
  }
}

void ApplicationDriver::OnAttributeRemovedImpl(int32_t node_id, const std::string& name) {
  for (auto& observer : observers_) {
    observer.OnAttributeRemoved(node_id, name);
  }
}

void ApplicationDriver::OnCharacterDataModifiedImpl(int32_t node_id, const std::string& character_data) {
  for (auto& observer : observers_) {
    observer.OnCharacterDataModified(node_id, character_data);
  }
}

void ApplicationDriver::OnChildNodeCountUpdatedImpl(int32_t node_id, int32_t child_node_count) {
  for (auto& observer : observers_) {
    observer.OnChildNodeCountUpdated(node_id, child_node_count);
  }
}

void ApplicationDriver::OnChildNodeInsertedImpl(int32_t parent_node_id, int32_t previous_node_id, automation::DOMNodePtr node) {
  for (auto& observer : observers_) {
    observer.OnChildNodeInserted(parent_node_id, previous_node_id, std::move(node));
  }
}

void ApplicationDriver::OnChildNodeRemovedImpl(int32_t parent_node_id, int32_t node_id) {
  for (auto& observer : observers_) {
    observer.OnChildNodeRemoved(parent_node_id, node_id);
  }
}

void ApplicationDriver::OnDistributedNodesUpdatedImpl(int32_t insertion_point_id, std::vector<automation::BackendNodePtr> distributed_nodes) {
  for (auto& observer : observers_) {
    observer.OnDistributedNodesUpdated(insertion_point_id, std::move(distributed_nodes));
  }
}

void ApplicationDriver::OnDocumentUpdatedImpl() {
  for (auto& observer : observers_) {
    observer.OnDocumentUpdated();
  }
}

void ApplicationDriver::OnInlineStyleInvalidatedImpl(const std::vector<int32_t>& node_ids) {
  for (auto& observer : observers_) {
    observer.OnInlineStyleInvalidated(node_ids);
  }
}

void ApplicationDriver::OnPseudoElementAddedImpl(int32_t parent_id, automation::DOMNodePtr pseudo_element) {
  for (auto& observer : observers_) {
    observer.OnPseudoElementAdded(parent_id, std::move(pseudo_element));
  }
}

void ApplicationDriver::OnPseudoElementRemovedImpl(int32_t parent_id, int32_t pseudo_element_id) {
  for (auto& observer : observers_) {
    observer.OnPseudoElementRemoved(parent_id, pseudo_element_id);
  }
}

void ApplicationDriver::OnShadowRootPoppedImpl(int32_t host_id, int32_t root_id) {
  for (auto& observer : observers_) {
    observer.OnShadowRootPopped(host_id, root_id);
  }
}

void ApplicationDriver::OnShadowRootPushedImpl(int32_t host_id, automation::DOMNodePtr root) {
  for (auto& observer : observers_) {
    observer.OnShadowRootPushed(host_id, std::move(root));
  }
}

void ApplicationDriver::OnFontsUpdatedImpl(automation::FontFacePtr font) {
  for (auto& observer : observers_) {
    observer.OnFontsUpdated(std::move(font));
  }
}

void ApplicationDriver::OnMediaQueryResultChangedImpl() {
  for (auto& observer : observers_) {
    observer.OnMediaQueryResultChanged();
  }
}

void ApplicationDriver::OnStyleSheetAddedImpl(automation::CSSStyleSheetHeaderPtr header) {
  for (auto& observer : observers_) {
    observer.OnStyleSheetAdded(std::move(header));
  }
}

void ApplicationDriver::OnStyleSheetChangedImpl(const std::string& style_sheet_id) {
  for (auto& observer : observers_) {
    observer.OnStyleSheetChanged(style_sheet_id);
  }
}

void ApplicationDriver::OnStyleSheetRemovedImpl(const std::string& style_sheet_id) {
  for (auto& observer : observers_) {
    observer.OnStyleSheetRemoved(style_sheet_id);
  }
}

void ApplicationDriver::OnApplicationCacheStatusUpdatedImpl(const std::string& frame_id, const std::string& manifest_url, int32_t status) {
  for (auto& observer : observers_) {
    observer.OnApplicationCacheStatusUpdated(frame_id, manifest_url, status);
  }
}

void ApplicationDriver::OnNetworkStateUpdatedImpl(bool is_now_online) {
  for (auto& observer : observers_) {
    observer.OnNetworkStateUpdated(is_now_online);
  }
}

void ApplicationDriver::OnAnimationCanceledImpl(const std::string& id) {
  for (auto& observer : observers_) {
    observer.OnAnimationCanceled(id);
  }
}

void ApplicationDriver::OnAnimationCreatedImpl(const std::string& id) {
  for (auto& observer : observers_) {
    observer.OnAnimationCreated(id);
  }
}

void ApplicationDriver::OnAnimationStartedImpl(automation::AnimationPtr animation) {
  for (auto& observer : observers_) {
    observer.OnAnimationStarted(std::move(animation));
  }
}

}
