// Copyright 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/domain/application/application_driver.h"

#include "core/shared/domain/application/application.h"
#include "ipc/ipc_sync_channel.h"

namespace domain {

SystemInfoInterface::SystemInfoInterface(ApplicationDriver* driver): driver_(driver) {

}

SystemInfoInterface::~SystemInfoInterface() {

}

void SystemInfoInterface::GetInfo(automation::SystemInfo::GetInfoCallback callback) {
  //driver_->system_info_interface_->GetInfo(std::move(callback));
}

HostInterface::HostInterface(ApplicationDriver* driver): driver_(driver) {

}

HostInterface::~HostInterface() {

}

void HostInterface::Close() {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Host::Close,
                   base::Unretained(driver_->host_interface_.get())));
}

void HostInterface::GetVersion(automation::Host::GetVersionCallback callback) {
  driver_->host_interface_->GetVersion(std::move(callback));  
}

void HostInterface::GetHostCommandLine(automation::Host::GetHostCommandLineCallback callback) {
  driver_->host_interface_->GetHostCommandLine(std::move(callback));  
}

void HostInterface::GetHistograms(const base::Optional<std::string>& query, automation::Host::GetHistogramsCallback callback) {
  driver_->host_interface_->GetHistograms(query, std::move(callback));
}

void HostInterface::GetHistogram(const std::string& name, automation::Host::GetHistogramCallback callback) {
  driver_->host_interface_->GetHistogram(name, std::move(callback));
}

void HostInterface::GetWindowBounds(int32_t window_id, automation::Host::GetWindowBoundsCallback callback) {
  driver_->host_interface_->GetWindowBounds(window_id, std::move(callback));
}

void HostInterface::GetWindowForTarget(const std::string& target_id, automation::Host::GetWindowForTargetCallback callback) {
  driver_->host_interface_->GetWindowForTarget(target_id, std::move(callback));
}

void HostInterface::SetWindowBounds(int32_t window_id, automation::BoundsPtr bounds) {
  driver_->host_interface_->SetWindowBounds(window_id, std::move(bounds));
}

PageInterface::PageInterface(ApplicationDriver* driver): driver_(driver) {

}

PageInterface::~PageInterface() {

}

void PageInterface::Enable() {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Page::Enable,
                   base::Unretained(driver_->page_interface_.get())));
}

void PageInterface::Disable() {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Page::Disable,
                   base::Unretained(driver_->page_interface_.get())));
}

void PageInterface::AddScriptToEvaluateOnNewDocument(const std::string& source, automation::Page::AddScriptToEvaluateOnNewDocumentCallback callback) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Page::AddScriptToEvaluateOnNewDocument,
                   base::Unretained(driver_->page_interface_.get()),
                   source, 
                   base::Passed(std::move(callback))));
}

void PageInterface::RemoveScriptToEvaluateOnNewDocument(const std::string& identifier) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Page::RemoveScriptToEvaluateOnNewDocument,
                   base::Unretained(driver_->page_interface_.get()),
                   identifier));
}

void PageInterface::SetAutoAttachToCreatedPages(bool auto_attach) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Page::SetAutoAttachToCreatedPages,
                   base::Unretained(driver_->page_interface_.get()),
                   auto_attach));
}

void PageInterface::SetLifecycleEventsEnabled(bool enabled) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Page::SetLifecycleEventsEnabled,
                   base::Unretained(driver_->page_interface_.get()),
                   enabled));
}

void PageInterface::Reload(bool ignore_cache, const std::string& script_to_evaluate_on_load) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Page::Reload,
                   base::Unretained(driver_->page_interface_.get()),
                   ignore_cache, 
                   script_to_evaluate_on_load));
}

void PageInterface::SetAdBlockingEnabled(bool enabled) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Page::SetAdBlockingEnabled,
                   base::Unretained(driver_->page_interface_.get()),
                   enabled));
}

void PageInterface::Navigate(const std::string& url, const std::string& referrer, automation::TransitionType transition_type, automation::Page::NavigateCallback callback) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Page::Navigate,
                   base::Unretained(driver_->page_interface_.get()),
                   url, 
                   referrer, 
                   transition_type, 
                   base::Passed(std::move(callback))));
}

void PageInterface::StopLoading() {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Page::StopLoading,
                   base::Unretained(driver_->page_interface_.get())));
}

void PageInterface::GetNavigationHistory(automation::Page::GetNavigationHistoryCallback callback) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Page::GetNavigationHistory,
                   base::Unretained(driver_->page_interface_.get()),
                   base::Passed(std::move(callback))));
}

void PageInterface::NavigateToHistoryEntry(int32_t entry_id) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Page::NavigateToHistoryEntry,
                   base::Unretained(driver_->page_interface_.get()),
                   entry_id));
}

void PageInterface::GetCookies(automation::Page::GetCookiesCallback callback) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Page::GetCookies,
                   base::Unretained(driver_->page_interface_.get()),
                   base::Passed(std::move(callback))));
}

void PageInterface::DeleteCookie(const std::string& cookie_name, const std::string& url) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Page::DeleteCookie,
                   base::Unretained(driver_->page_interface_.get()),
                   cookie_name,
                   url));
}

void PageInterface::GetResourceTree(automation::Page::GetResourceTreeCallback callback) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Page::GetResourceTree,
                   base::Unretained(driver_->page_interface_.get()),
                   base::Passed(std::move(callback))));
}

void PageInterface::GetFrameTree(automation::Page::GetFrameTreeCallback callback) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Page::GetFrameTree,
                   base::Unretained(driver_->page_interface_.get()),
                   base::Passed(std::move(callback))));
}

void PageInterface::GetResourceContent(const std::string& frame_id, const std::string& url, automation::Page::GetResourceContentCallback callback) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Page::GetResourceContent,
                   base::Unretained(driver_->page_interface_.get()),
                   frame_id, 
                   url, 
                   base::Passed(std::move(callback))));
}

void PageInterface::SearchInResource(const std::string& frame_id, const std::string& url, const std::string& query, bool case_sensitive, bool is_regex, automation::Page::SearchInResourceCallback callback) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Page::SearchInResource,
                   base::Unretained(driver_->page_interface_.get()),
                   frame_id, 
                   url, 
                   query, 
                   case_sensitive, 
                   is_regex,
                   base::Passed(std::move(callback))));
}

void PageInterface::SetDocumentContent(const std::string& frame_id, const std::string& html) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Page::SetDocumentContent,
                   base::Unretained(driver_->page_interface_.get()),
                   frame_id, 
                   html));
}

void PageInterface::SetDeviceMetricsOverride(int32_t width, int32_t height, int32_t device_scale_factor, bool mobile, int32_t scale, int32_t screen_width, int32_t screen_height, int32_t position_x, int32_t position_y, bool dont_set_visible_size, automation::ScreenOrientationPtr screen_orientation, automation::ViewportPtr viewport) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Page::SetDeviceMetricsOverride,
                   base::Unretained(driver_->page_interface_.get()),
                   width, 
                   height, 
                   device_scale_factor, 
                   mobile, 
                   scale, 
                   screen_width, 
                   screen_height, 
                   position_x, 
                   position_y, 
                   dont_set_visible_size, 
                   base::Passed(std::move(screen_orientation)), 
                   base::Passed(std::move(viewport))));
}

void PageInterface::ClearDeviceMetricsOverride() {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Page::ClearDeviceMetricsOverride,
                   base::Unretained(driver_->page_interface_.get())));
}

void PageInterface::SetGeolocationOverride(int32_t latitude, int32_t longitude, int32_t accuracy) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Page::SetGeolocationOverride,
                   base::Unretained(driver_->page_interface_.get()),
                   latitude, longitude, accuracy));
}

void PageInterface::ClearGeolocationOverride() {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Page::ClearGeolocationOverride,
                   base::Unretained(driver_->page_interface_.get())));
}

void PageInterface::SetDeviceOrientationOverride(int32_t alpha, int32_t beta, int32_t gamma) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Page::SetDeviceOrientationOverride,
                   base::Unretained(driver_->page_interface_.get()),
                   alpha, beta, gamma));
}

void PageInterface::ClearDeviceOrientationOverride() {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Page::ClearDeviceOrientationOverride,
                   base::Unretained(driver_->page_interface_.get())));
}

void PageInterface::SetTouchEmulationEnabled(bool enabled, const std::string& configuration) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Page::SetTouchEmulationEnabled,
                   base::Unretained(driver_->page_interface_.get()),
                   enabled, configuration));
}

void PageInterface::CaptureScreenshot(automation::FrameFormat format, int32_t quality, automation::ViewportPtr clip, bool from_surface, automation::Page::CaptureScreenshotCallback callback) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Page::CaptureScreenshot,
                   base::Unretained(driver_->page_interface_.get()),
                   format, quality, std::move(clip), from_surface, base::Passed(std::move(callback))));
}

void PageInterface::PrintToPDF(bool landscape, bool display_header_footer, bool print_background, float scale, float paper_width, float paper_height, float margin_top, float margin_bottom, float margin_left, float margin_right, const base::Optional<std::string>& page_ranges, bool ignore_invalid_page_ranges, automation::Page::PrintToPDFCallback callback) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Page::PrintToPDF,
                   base::Unretained(driver_->page_interface_.get()),
                   landscape, 
                   display_header_footer, 
                   print_background, 
                   scale, 
                   paper_width, 
                   paper_height, 
                   margin_top, 
                   margin_bottom, 
                   margin_left, 
                   margin_right, 
                   page_ranges, 
                   ignore_invalid_page_ranges, 
                   base::Passed(std::move(callback))));
}

void PageInterface::StartScreencast(automation::FrameFormat format, int32_t quality, int32_t max_width, int32_t max_height, int32_t every_nth_frame) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Page::StartScreencast,
                   base::Unretained(driver_->page_interface_.get()),
                   format, quality, max_width, max_height, every_nth_frame));
}

void PageInterface::StopScreencast() {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Page::StopScreencast,
                   base::Unretained(driver_->page_interface_.get())));
}

void PageInterface::SetBypassCSP(bool enable) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Page::SetBypassCSP,
                   base::Unretained(driver_->page_interface_.get()),
                   enable));
}

void PageInterface::ScreencastFrameAck(int32_t session_id) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Page::ScreencastFrameAck,
                   base::Unretained(driver_->page_interface_.get()),
                   session_id));
}

void PageInterface::HandleJavaScriptDialog(bool accept, const std::string& prompt_text) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Page::HandleJavaScriptDialog,
                   base::Unretained(driver_->page_interface_.get()),
                   accept, prompt_text));
}

void PageInterface::GetAppManifest(automation::Page::GetAppManifestCallback callback) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Page::GetAppManifest,
                   base::Unretained(driver_->page_interface_.get()),
                   base::Passed(std::move(callback))));
}

void PageInterface::RequestAppBanner() {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Page::RequestAppBanner,
                   base::Unretained(driver_->page_interface_.get())));
}

void PageInterface::GetLayoutMetrics(automation::Page::GetLayoutMetricsCallback callback) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Page::GetLayoutMetrics,
                   base::Unretained(driver_->page_interface_.get()),
                   base::Passed(std::move(callback))));
}

void PageInterface::CreateIsolatedWorld(const std::string& frame_id, const base::Optional<std::string>& world_name, bool grant_universal_access, automation::Page::CreateIsolatedWorldCallback callback) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Page::CreateIsolatedWorld,
                   base::Unretained(driver_->page_interface_.get()),
                   frame_id, 
                   world_name, 
                   grant_universal_access, 
                   base::Passed(std::move(callback))));
}

void PageInterface::BringToFront() {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Page::BringToFront,
                   base::Unretained(driver_->page_interface_.get())));
}

void PageInterface::SetDownloadBehavior(const std::string& behavior, const base::Optional<std::string>& download_path) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Page::SetDownloadBehavior,
                   base::Unretained(driver_->page_interface_.get()),
                   behavior, download_path));
}

void PageInterface::Close() {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Page::Close,
                   base::Unretained(driver_->page_interface_.get())));
}

OverlayInterface::OverlayInterface(ApplicationDriver* driver): 
  driver_(driver) {

}

OverlayInterface::~OverlayInterface(){

}

void OverlayInterface::Disable() {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Overlay::Disable,
                   base::Unretained(driver_->overlay_interface_.get())));
}

void OverlayInterface::Enable() {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Overlay::Enable,
                   base::Unretained(driver_->overlay_interface_.get())));
}

void OverlayInterface::HideHighlight() {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Overlay::HideHighlight,
                   base::Unretained(driver_->overlay_interface_.get())));
}

void OverlayInterface::HighlightFrame(const std::string& frame_id, automation::RGBAPtr content_color, automation::RGBAPtr content_outline_color) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Overlay::HighlightFrame,
                   base::Unretained(driver_->overlay_interface_.get()),
                   frame_id, 
                   std::move(content_color), 
                   std::move(content_outline_color)));
}

void OverlayInterface::HighlightNode(automation::HighlightConfigPtr highlight_config, int32_t node_id, int32_t backend_node_id, const base::Optional<std::string>& object_id) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Overlay::HighlightNode,
                   base::Unretained(driver_->overlay_interface_.get()),
                   base::Passed(std::move(highlight_config)),
                   node_id, 
                   backend_node_id,
                   object_id));
}

void OverlayInterface::HighlightQuad(const std::vector<double>& quad, automation::RGBAPtr color, automation::RGBAPtr outline_color) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Overlay::HighlightQuad,
                   base::Unretained(driver_->overlay_interface_.get()),
                   quad, 
                   base::Passed(std::move(color)), 
                   base::Passed(std::move(outline_color))));
}

void OverlayInterface::HighlightRect(int32_t x, int32_t y, int32_t width, int32_t height, automation::RGBAPtr color, automation::RGBAPtr outline_color) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Overlay::HighlightRect,
                   base::Unretained(driver_->overlay_interface_.get()),
                   x, y, width, height, 
                   base::Passed(std::move(color)), 
                   base::Passed(std::move(outline_color))));
}

void OverlayInterface::SetInspectMode(automation::InspectMode mode, automation::HighlightConfigPtr highlight_config) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Overlay::SetInspectMode,
                   base::Unretained(driver_->overlay_interface_.get()),
                   mode, std::move(highlight_config)));
}

void OverlayInterface::SetPausedInDebuggerMessage(const base::Optional<std::string>& message) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Overlay::SetPausedInDebuggerMessage,
                   base::Unretained(driver_->overlay_interface_.get()),
                   message));
}

void OverlayInterface::SetShowDebugBorders(bool show) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Overlay::SetShowDebugBorders,
                   base::Unretained(driver_->overlay_interface_.get()),
                   show));
}

void OverlayInterface::SetShowFPSCounter(bool show) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Overlay::SetShowFPSCounter,
      base::Unretained(driver_->overlay_interface_.get()),
      show));
}

void OverlayInterface::SetShowPaintRects(bool result) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Overlay::SetShowPaintRects,
                   base::Unretained(driver_->overlay_interface_.get()),
                   result));
}

void OverlayInterface::SetShowScrollBottleneckRects(bool show) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Overlay::SetShowScrollBottleneckRects,
                   base::Unretained(driver_->overlay_interface_.get()),
                   show));
}

void OverlayInterface::SetShowViewportSizeOnResize(bool show) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Overlay::SetShowViewportSizeOnResize,
                   base::Unretained(driver_->overlay_interface_.get()),
                   show));
}

void OverlayInterface::SetSuspended(bool suspended) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Overlay::SetSuspended,
    base::Unretained(driver_->overlay_interface_.get()),
    suspended));
}

WorkerInterface::WorkerInterface(ApplicationDriver* driver): driver_(driver) {

}

WorkerInterface::~WorkerInterface() {

}

void WorkerInterface::DeliverPushMessage(const std::string& origin, const std::string& registration_id, const std::string& data) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::ServiceWorker::DeliverPushMessage,
                   base::Unretained(driver_->worker_interface_.get()),
                   origin, registration_id, data));
}

void WorkerInterface::Disable() {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::ServiceWorker::Disable,
                   base::Unretained(driver_->worker_interface_.get())));
}

void WorkerInterface::DispatchSyncEvent(const std::string& origin, const std::string& registration_id, const std::string& tag, bool last_chance) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::ServiceWorker::DispatchSyncEvent,
                   base::Unretained(driver_->worker_interface_.get()),
                   origin, 
                   registration_id, 
                   tag, 
                   last_chance));
}

void WorkerInterface::Enable() {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::ServiceWorker::Enable,
                   base::Unretained(driver_->worker_interface_.get())));
}

void WorkerInterface::InspectWorker(const std::string& version_id) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::ServiceWorker::InspectWorker,
                   base::Unretained(driver_->worker_interface_.get()),
                   version_id));
}

void WorkerInterface::SetForceUpdateOnPageLoad(bool force_update_on_pageload) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::ServiceWorker::SetForceUpdateOnPageLoad,
                   base::Unretained(driver_->worker_interface_.get()),
                   force_update_on_pageload));
}

void WorkerInterface::SkipWaiting(const std::string& scope_url) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::ServiceWorker::SkipWaiting,
                   base::Unretained(driver_->worker_interface_.get()),
                   scope_url));
}

void WorkerInterface::StartWorker(const std::string& scope_url) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::ServiceWorker::StartWorker,
                   base::Unretained(driver_->worker_interface_.get()),
                   scope_url));
}

void WorkerInterface::StopAllWorkers() {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::ServiceWorker::StopAllWorkers,
                   base::Unretained(driver_->worker_interface_.get())));
}

void WorkerInterface::StopWorker(const std::string& version_id) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::ServiceWorker::StopWorker,
                   base::Unretained(driver_->worker_interface_.get()),
                   version_id));
}

void WorkerInterface::Unregister(const std::string& scope_url) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::ServiceWorker::Unregister,
                   base::Unretained(driver_->worker_interface_.get()),
                   scope_url));
}

void WorkerInterface::UpdateRegistration(const std::string& scope_url) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::ServiceWorker::UpdateRegistration,
                   base::Unretained(driver_->worker_interface_.get()),
                   scope_url));
}

void WorkerInterface::SendMessageToTarget(const std::string& message, const base::Optional<std::string>& session_id, const base::Optional<std::string>& target_id) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::ServiceWorker::SendMessageToTarget,
                   base::Unretained(driver_->worker_interface_.get()),
                   message, 
                   session_id, 
                   target_id));
}

StorageInterface::StorageInterface(ApplicationDriver* driver): driver_(driver) {

}

StorageInterface::~StorageInterface() {

}

void StorageInterface::ClearDataForOrigin(const std::string& origin, const std::vector<automation::StorageType>& storage_types) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Storage::ClearDataForOrigin,
                   base::Unretained(driver_->storage_interface_.get()), 
                   origin, 
                   storage_types));
}

void StorageInterface::GetUsageAndQuota(const std::string& origin, int64_t usage, int64_t quota, std::vector<automation::UsageForTypePtr> usage_breakdown) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Storage::GetUsageAndQuota,
                   base::Unretained(driver_->storage_interface_.get()), 
                   origin, 
                   usage, 
                   quota, 
                   base::Passed(std::move(usage_breakdown))));
}

void StorageInterface::TrackCacheStorageForOrigin(const std::string& origin) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Storage::TrackCacheStorageForOrigin,
                   base::Unretained(driver_->storage_interface_.get()),
                   origin));
}

void StorageInterface::TrackIndexedDBForOrigin(const std::string& origin) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Storage::TrackIndexedDBForOrigin,
                   base::Unretained(driver_->storage_interface_.get()),
                   origin)); 
}

void StorageInterface::UntrackCacheStorageForOrigin(const std::string& origin) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Storage::UntrackCacheStorageForOrigin,
                   base::Unretained(driver_->storage_interface_.get()),
                   origin));
}

void StorageInterface::UntrackIndexedDBForOrigin(const std::string& origin) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Storage::UntrackIndexedDBForOrigin,
                   base::Unretained(driver_->storage_interface_.get()),
                   origin));
}

TetheringInterface::TetheringInterface(ApplicationDriver* driver): driver_(driver) {

}

TetheringInterface::~TetheringInterface() {

}

void TetheringInterface::Bind(int32_t port) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Tethering::Bind,
                   base::Unretained(driver_->tethering_interface_.get()),
                   port));
}

void TetheringInterface::Unbind(int32_t port) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Tethering::Unbind,
                   base::Unretained(driver_->tethering_interface_.get()),
                   port));
}

NetworkInterface::NetworkInterface(ApplicationDriver* driver): driver_(driver) {

}

NetworkInterface::~NetworkInterface() {

}

void NetworkInterface::CanClearBrowserCache(automation::Network::CanClearBrowserCacheCallback callback) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Network::CanClearBrowserCache,
                   base::Unretained(driver_->network_interface_.get()),
                   base::Passed(std::move(callback))));
}

void NetworkInterface::CanClearBrowserCookies(automation::Network::CanClearBrowserCookiesCallback callback) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Network::CanClearBrowserCookies,
      base::Unretained(driver_->network_interface_.get()),
      base::Passed(std::move(callback))));
}

void NetworkInterface::CanEmulateNetworkConditions(automation::Network::CanEmulateNetworkConditionsCallback callback) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Network::CanEmulateNetworkConditions,
      base::Unretained(driver_->network_interface_.get()),
      base::Passed(std::move(callback))));
}

void NetworkInterface::ClearBrowserCache() {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Network::ClearBrowserCache,
      base::Unretained(driver_->network_interface_.get())));
}

void NetworkInterface::ClearBrowserCookies() {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Network::ClearBrowserCookies,
      base::Unretained(driver_->network_interface_.get())));
}

void NetworkInterface::ContinueInterceptedRequest(const std::string& interception_id, automation::ErrorReason error_reason, const base::Optional<std::string>& raw_response, const base::Optional<std::string>& url, const base::Optional<std::string>& method, const base::Optional<std::string>& post_data, const base::Optional<base::flat_map<std::string, std::string>>& headers, automation::AuthChallengeResponsePtr auth_challenge_response) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Network::ContinueInterceptedRequest,
      base::Unretained(driver_->network_interface_.get()),
      interception_id, 
      error_reason, 
      raw_response, 
      url, 
      method, 
      post_data, 
      headers, 
      base::Passed(std::move(auth_challenge_response))));
}

void NetworkInterface::DeleteCookies(const std::string& name, const base::Optional<std::string>& url, const base::Optional<std::string>& domain, const base::Optional<std::string>& path) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Network::DeleteCookies,
      base::Unretained(driver_->network_interface_.get()),
      name, 
      url, 
      domain, 
      path));
}

void NetworkInterface::Disable() {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Network::Disable,
      base::Unretained(driver_->network_interface_.get())));
}

void NetworkInterface::EmulateNetworkConditions(bool offline, int64_t latency, int64_t download_throughput, int64_t upload_throughput, automation::ConnectionType connection_type) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Network::EmulateNetworkConditions,
      base::Unretained(driver_->network_interface_.get()),
      offline, 
      latency, 
      download_throughput, 
      upload_throughput, 
      connection_type));
}

void NetworkInterface::Enable(int32_t max_total_buffer_size, int32_t max_resource_buffer_size, int32_t max_post_data_size) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Network::Enable,
      base::Unretained(driver_->network_interface_.get()),
      max_total_buffer_size, max_resource_buffer_size, max_post_data_size));
}

void NetworkInterface::GetAllCookies(automation::Network::GetAllCookiesCallback callback) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Network::GetAllCookies,
      base::Unretained(driver_->network_interface_.get()),
      base::Passed(std::move(callback))));
}

void NetworkInterface::GetCertificate(const std::string& origin, automation::Network::GetCertificateCallback callback) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Network::GetCertificate,
      base::Unretained(driver_->network_interface_.get()),
      origin, 
      base::Passed(std::move(callback))));
}

void NetworkInterface::GetCookies(const base::Optional<std::vector<std::string>>& urls, automation::Network::GetCookiesCallback callback) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Network::GetCookies,
    base::Unretained(driver_->network_interface_.get()),
    urls, 
    base::Passed(std::move(callback))));
}

void NetworkInterface::GetResponseBody(const std::string& request_id, automation::Network::GetResponseBodyCallback callback) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Network::GetResponseBody,
    base::Unretained(driver_->network_interface_.get()),
    request_id, 
    base::Passed(std::move(callback))));
}

void NetworkInterface::GetRequestPostData(const std::string& request_id, automation::Network::GetRequestPostDataCallback callback) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Network::GetRequestPostData,
    base::Unretained(driver_->network_interface_.get()),
    request_id, 
    base::Passed(std::move(callback))));
}

void NetworkInterface::GetResponseBodyForInterception(const std::string& interception_id, automation::Network::GetResponseBodyForInterceptionCallback callback) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Network::GetResponseBodyForInterception,
    base::Unretained(driver_->network_interface_.get()),
    interception_id, 
    base::Passed(std::move(callback))));
}

void NetworkInterface::TakeResponseBodyForInterceptionAsStream(const std::string& interception_id, automation::Network::TakeResponseBodyForInterceptionAsStreamCallback callback) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Network::TakeResponseBodyForInterceptionAsStream,
    base::Unretained(driver_->network_interface_.get()),
    interception_id, 
    base::Passed(std::move(callback))));
} 

void NetworkInterface::ReplayXHR(const std::string& request_id) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Network::ReplayXHR,
    base::Unretained(driver_->network_interface_.get()),
    request_id));
}

void NetworkInterface::SearchInResponseBody(const std::string& request_id, const std::string& query, bool case_sensitive, bool is_regex, automation::Network::SearchInResponseBodyCallback callback) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Network::SearchInResponseBody,
    base::Unretained(driver_->network_interface_.get()),
    request_id, 
    query, 
    case_sensitive, 
    is_regex, 
    base::Passed(std::move(callback))));
}

void NetworkInterface::SetBlockedURLs(const std::vector<std::string>& urls) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Network::SetBlockedURLs,
    base::Unretained(driver_->network_interface_.get()),
    urls));
}

void NetworkInterface::SetBypassServiceWorker(bool bypass) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Network::SetBypassServiceWorker,
    base::Unretained(driver_->network_interface_.get()),
    bypass));
}

void NetworkInterface::SetCacheDisabled(bool cache_disabled) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Network::SetCacheDisabled,
    base::Unretained(driver_->network_interface_.get()),
    cache_disabled));
}

void NetworkInterface::SetCookie(const std::string& name, const std::string& value, const base::Optional<std::string>& url, const base::Optional<std::string>& domain, const base::Optional<std::string>& path, bool secure, bool http_only, automation::CookieSameSite same_site, int64_t expires, automation::Network::SetCookieCallback callback) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Network::SetCookie,
    base::Unretained(driver_->network_interface_.get()),
    name, 
    value, 
    url, 
    domain, 
    path, 
    secure, 
    http_only, 
    same_site, 
    expires, 
    base::Passed(std::move(callback))));
}

void NetworkInterface::SetCookies(std::vector<automation::CookieParamPtr> cookies) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Network::SetCookies,
    base::Unretained(driver_->network_interface_.get()),
    base::Passed(std::move(cookies))));
}

void NetworkInterface::SetDataSizeLimits(int32_t max_total_size, int32_t max_resource_size) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Network::SetDataSizeLimitsForTest,
    base::Unretained(driver_->network_interface_.get()),
    max_total_size, 
    max_resource_size));
}

void NetworkInterface::SetExtraHTTPHeaders(const base::flat_map<std::string, std::string>& headers) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Network::SetExtraHTTPHeaders,
    base::Unretained(driver_->network_interface_.get()),
    headers));
}

void NetworkInterface::SetRequestInterception(std::vector<automation::RequestPatternPtr> patterns) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Network::SetRequestInterception,
    base::Unretained(driver_->network_interface_.get()),
    base::Passed(std::move(patterns))));
}

void NetworkInterface::SetUserAgentOverride(const std::string& user_agent) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Network::SetUserAgentOverride,
    base::Unretained(driver_->network_interface_.get()),
    user_agent));
}


LayerTreeInterface::LayerTreeInterface(ApplicationDriver* driver): driver_(driver) {

}

LayerTreeInterface::~LayerTreeInterface() {

}

void LayerTreeInterface::CompositingReasons(const std::string& layer_id, automation::LayerTree::CompositingReasonsCallback callback) {

}

void LayerTreeInterface::Disable() {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::LayerTree::Disable,
    base::Unretained(driver_->layer_tree_interface_.get())));
}

void LayerTreeInterface::Enable() {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::LayerTree::Enable,
    base::Unretained(driver_->layer_tree_interface_.get())));
}

void LayerTreeInterface::LoadSnapshot(std::vector<automation::PictureTilePtr> tiles, automation::LayerTree::LoadSnapshotCallback callback) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::LayerTree::LoadSnapshot,
    base::Unretained(driver_->layer_tree_interface_.get()),
    std::move(tiles), 
    std::move(callback)));
}

void LayerTreeInterface::MakeSnapshot(const std::string& layer_id, automation::LayerTree::MakeSnapshotCallback callback) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::LayerTree::MakeSnapshot,
    base::Unretained(driver_->layer_tree_interface_.get()),
    layer_id, std::move(callback)));
}

void LayerTreeInterface::ProfileSnapshot(const std::string& snapshot_id, int32_t min_repeat_count, int32_t min_duration, const base::Optional<gfx::Rect>& clip_rect, automation::LayerTree::ProfileSnapshotCallback callback) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::LayerTree::ProfileSnapshot,
    base::Unretained(driver_->layer_tree_interface_.get()),
    snapshot_id, 
    min_repeat_count, 
    min_duration, 
    clip_rect, 
    base::Passed(std::move(callback))));
}

void LayerTreeInterface::ReleaseSnapshot(const std::string& snapshot_id) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::LayerTree::ReleaseSnapshot,
    base::Unretained(driver_->layer_tree_interface_.get()),
    snapshot_id));
}

void LayerTreeInterface::ReplaySnapshot(const std::string& snapshot_id, int32_t from_step, int32_t to_step, int32_t scale, automation::LayerTree::ReplaySnapshotCallback callback) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::LayerTree::ReplaySnapshot,
    base::Unretained(driver_->layer_tree_interface_.get()),
    snapshot_id, 
    from_step, 
    to_step, 
    scale, 
    base::Passed(std::move(callback))));
}

void LayerTreeInterface::SnapshotCommandLog(const std::string& snapshot_id, automation::LayerTree::SnapshotCommandLogCallback callback) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::LayerTree::SnapshotCommandLog,
    base::Unretained(driver_->layer_tree_interface_.get()),
    snapshot_id, 
    base::Passed(std::move(callback))));
}

InputInterface::InputInterface(ApplicationDriver* driver): driver_(driver) {

}

InputInterface::~InputInterface() {

}

void InputInterface::DispatchKeyEvent(automation::KeyEventType type, int32_t modifiers, int64_t timestamp, const base::Optional<std::string>& text, const base::Optional<std::string>& unmodified_text, const base::Optional<std::string>& key_identifier, const base::Optional<std::string>& code, const base::Optional<std::string>& key, int32_t windows_virtual_key_code, int32_t native_virtual_key_code, bool auto_repeat, bool is_keypad, bool is_system_key, int32_t location, automation::Input::DispatchKeyEventCallback callback) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Input::DispatchKeyEvent,
    base::Unretained(driver_->input_interface_.get()),
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
    base::Passed(std::move(callback))));
  }

void InputInterface::DispatchMouseEvent(automation::MouseEventType type, int32_t x, int32_t y, int32_t modifiers, int64_t timestamp, automation::MouseButton button, int32_t click_count, int32_t delta_x, int32_t delta_y, automation::Input::DispatchMouseEventCallback callback) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Input::DispatchMouseEvent,
    base::Unretained(driver_->input_interface_.get()),
    type, 
    x,
    y,
    modifiers,
    timestamp,
    button,
    click_count,
    delta_x,
    delta_y,
    base::Passed(std::move(callback))));
}

void InputInterface::DispatchTouchEvent(automation::TouchEventType type, std::vector<automation::TouchPointPtr> touch_points, int32_t modifiers, int64_t timestamp, automation::Input::DispatchTouchEventCallback callback) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Input::DispatchTouchEvent,
    base::Unretained(driver_->input_interface_.get()),
    type,
    base::Passed(std::move(touch_points)), 
    modifiers, 
    timestamp, 
    base::Passed(std::move(callback))));
}

void InputInterface::EmulateTouchFromMouseEvent(automation::MouseEventType type, int32_t x, int32_t y, automation::MouseButton button, int64_t timestamp, int32_t delta_x, int32_t delta_y, int32_t modifiers, int32_t click_count, automation::Input::EmulateTouchFromMouseEventCallback callback) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Input::EmulateTouchFromMouseEvent,
    base::Unretained(driver_->input_interface_.get()),
    type, x, y, button, timestamp, delta_x, delta_y, modifiers, click_count,
    base::Passed(std::move(callback))));
}

void InputInterface::SetIgnoreInputEvents(bool ignore) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Input::SetIgnoreInputEvents,
    base::Unretained(driver_->input_interface_.get()),
    ignore));
}

void InputInterface::SynthesizePinchGesture(int32_t x, int32_t y, int32_t scale_factor, int32_t relative_speed, automation::GestureSourceType gesture_source_type, automation::Input::SynthesizePinchGestureCallback callback) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Input::SynthesizePinchGesture,
    base::Unretained(driver_->input_interface_.get()),
    x, y, scale_factor, relative_speed, gesture_source_type,
    base::Passed(std::move(callback))));
}

void InputInterface::SynthesizeScrollGesture(int32_t x, int32_t y, int32_t x_distance, int32_t y_distance, int32_t x_overscroll, int32_t y_overscroll, bool prevent_fling, int32_t speed, automation::GestureSourceType gesture_source_type, int32_t repeat_count, int32_t repeat_delay_ms, const base::Optional<std::string>& interaction_marker_name, automation::Input::SynthesizeScrollGestureCallback callback) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Input::SynthesizeScrollGesture,
    base::Unretained(driver_->input_interface_.get()),
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
    base::Passed(std::move(callback))));
}

void InputInterface::SynthesizeTapGesture(int32_t x, int32_t y, int32_t duration, int32_t tap_count, automation::GestureSourceType gesture_source_type, automation::Input::SynthesizeTapGestureCallback callback) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Input::SynthesizeTapGesture,
    base::Unretained(driver_->input_interface_.get()),
    x, y, duration, tap_count, gesture_source_type,
    base::Passed(std::move(callback))));
}

IndexedDBInterface::IndexedDBInterface(ApplicationDriver* driver): driver_(driver) {

}

IndexedDBInterface::~IndexedDBInterface() {

}

void IndexedDBInterface::Disable() {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::IndexedDB::Disable,
      base::Unretained(driver_->indexed_db_interface_.get())));
}

void IndexedDBInterface::Enable() {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::IndexedDB::Enable,
      base::Unretained(driver_->indexed_db_interface_.get())));
}

void IndexedDBInterface::ClearObjectStore(const std::string& security_origin, const std::string& database_name, const std::string& object_store_name, automation::IndexedDB::ClearObjectStoreCallback callback) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::IndexedDB::ClearObjectStore,
      base::Unretained(driver_->indexed_db_interface_.get()),
      security_origin, 
      database_name, 
      object_store_name, 
      base::Passed(std::move(callback))));
}

void IndexedDBInterface::DeleteDatabase(const std::string& security_origin, const std::string& database_name, automation::IndexedDB::DeleteDatabaseCallback callback) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::IndexedDB::DeleteDatabase,
      base::Unretained(driver_->indexed_db_interface_.get()),
      security_origin, 
      database_name,
      base::Passed(std::move(callback))));
}

void IndexedDBInterface::DeleteObjectStoreEntries(const std::string& security_origin, const std::string& database_name, const std::string& object_store_name, automation::KeyRangePtr key_range, automation::IndexedDB::DeleteObjectStoreEntriesCallback callback) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::IndexedDB::DeleteObjectStoreEntries,
      base::Unretained(driver_->indexed_db_interface_.get()),
      security_origin, 
      database_name, 
      object_store_name, 
      base::Passed(std::move(key_range)), 
      base::Passed(std::move(callback))));
}

void IndexedDBInterface::RequestData(const std::string& security_origin, const std::string& database_name, const std::string& object_store_name, const std::string& index_name, int32_t skip_count, int32_t page_size, automation::KeyRangePtr key_range, automation::IndexedDB::RequestDataCallback callback) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::IndexedDB::RequestData,
      base::Unretained(driver_->indexed_db_interface_.get()),
      security_origin, 
      database_name, 
      object_store_name, 
      index_name, 
      skip_count, 
      page_size, 
      base::Passed(std::move(key_range)), 
      base::Passed(std::move(callback))));
}

void IndexedDBInterface::RequestDatabase(const std::string& security_origin, const std::string& database_name, automation::IndexedDB::RequestDatabaseCallback callback) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::IndexedDB::RequestDatabase,
      base::Unretained(driver_->indexed_db_interface_.get()),
      security_origin, 
      database_name, 
      base::Passed(std::move(callback))));
}

void IndexedDBInterface::RequestDatabaseNames(const std::string& security_origin, automation::IndexedDB::RequestDatabaseNamesCallback callback) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::IndexedDB::RequestDatabaseNames,
      base::Unretained(driver_->indexed_db_interface_.get()),
      security_origin, 
      base::Passed(std::move(callback))));
}

IOInterface::IOInterface(ApplicationDriver* driver): driver_(driver) {
  
}

IOInterface::~IOInterface() {

}

void IOInterface::Close(const std::string& handl) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::IO::Close,
      base::Unretained(driver_->io_interface_.get()),
      handl));
}

void IOInterface::Read(const std::string& handl, int32_t offset, int32_t size, automation::IO::ReadCallback callback) {
   driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::IO::Read,
      base::Unretained(driver_->io_interface_.get()),
      handl, 
      offset, 
      size, 
      base::Passed(std::move(callback))));
}

void IOInterface::ResolveBlob(const std::string& object_id, automation::IO::ResolveBlobCallback callback) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::IO::ResolveBlob,
      base::Unretained(driver_->io_interface_.get()),
      object_id, 
      base::Passed(std::move(callback))));
}

HeadlessInterface::HeadlessInterface(ApplicationDriver* driver): driver_(driver) {
  
}

HeadlessInterface::~HeadlessInterface() {

}

void HeadlessInterface::BeginFrame(int64_t frame_time, int32_t frame_time_ticks, int64_t deadline, int32_t deadline_ticks, int32_t interval, bool no_display_updates, automation::ScreenshotParamsPtr screenshot, automation::Headless::BeginFrameCallback callback) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Headless::BeginFrame,
      base::Unretained(driver_->headless_interface_.get()),
      frame_time, 
      frame_time_ticks, 
      deadline, 
      deadline_ticks, 
      interval, 
      no_display_updates, 
      base::Passed(std::move(screenshot)), 
      base::Passed(std::move(callback))));
}

void HeadlessInterface::EnterDeterministicMode(int32_t initial_date) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Headless::EnterDeterministicMode,
      base::Unretained(driver_->headless_interface_.get()),
      initial_date));
}

void HeadlessInterface::Disable() {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Headless::Disable,
      base::Unretained(driver_->headless_interface_.get())));
}

void HeadlessInterface::Enable() {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Headless::Enable,
                   base::Unretained(driver_->headless_interface_.get())));
}

DOMStorageInterface::DOMStorageInterface(ApplicationDriver* driver): driver_(driver) {

}

DOMStorageInterface::~DOMStorageInterface() {

}

void DOMStorageInterface::Clear(automation::StorageIdPtr storage_id) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::DOMStorage::Clear,
                   base::Unretained(driver_->dom_storage_interface_.get()),
                   base::Passed(std::move(storage_id))));
}

void DOMStorageInterface::Disable() {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::DOMStorage::Disable,
                   base::Unretained(driver_->dom_storage_interface_.get())));
}

void DOMStorageInterface::Enable() {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::DOMStorage::Enable,
                   base::Unretained(driver_->dom_storage_interface_.get())));
}

void DOMStorageInterface::GetDOMStorageItems(automation::StorageIdPtr storage_id, automation::DOMStorage::GetDOMStorageItemsCallback callback) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::DOMStorage::GetDOMStorageItems,
                   base::Unretained(driver_->dom_storage_interface_.get()),
                   base::Passed(std::move(storage_id)), 
                   base::Passed(std::move(callback))));
}

void DOMStorageInterface::RemoveDOMStorageItem(automation::StorageIdPtr storage_id, const std::string& key) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::DOMStorage::RemoveDOMStorageItem,
                   base::Unretained(driver_->dom_storage_interface_.get()),
                   base::Passed(std::move(storage_id)), 
                   key));
}

void DOMStorageInterface::SetDOMStorageItem(automation::StorageIdPtr storage_id, const std::string& key, const std::string& value) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::DOMStorage::SetDOMStorageItem,
                   base::Unretained(driver_->dom_storage_interface_.get()),
                   base::Passed(std::move(storage_id)), 
                   key, 
                   value));
}

DatabaseInterface::DatabaseInterface(ApplicationDriver* driver): driver_(driver) {

}

DatabaseInterface::~DatabaseInterface() {

}

void DatabaseInterface::Disable() {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::DatabaseInterface::Disable,
                   base::Unretained(driver_->database_interface_.get())));
}

void DatabaseInterface::Enable() {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::DatabaseInterface::Enable,
                   base::Unretained(driver_->database_interface_.get())));
}

void DatabaseInterface::ExecuteSQL(const std::string& database_id, const std::string& query, automation::DatabaseInterface::ExecuteSQLCallback callback) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::DatabaseInterface::ExecuteSQL,
                   base::Unretained(driver_->database_interface_.get()),
                   database_id, 
                   query, 
                   base::Passed(std::move(callback))));
}

void DatabaseInterface::GetDatabaseTableNames(const std::string& database_id, automation::DatabaseInterface::GetDatabaseTableNamesCallback callback) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::DatabaseInterface::GetDatabaseTableNames,
                   base::Unretained(driver_->database_interface_.get()),
                   database_id, 
                   base::Passed(std::move(callback))));
}

DeviceOrientationInterface::DeviceOrientationInterface(ApplicationDriver* driver): driver_(driver) {

}

DeviceOrientationInterface::~DeviceOrientationInterface() {

}

void DeviceOrientationInterface::ClearDeviceOrientationOverride() {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::DeviceOrientation::ClearDeviceOrientationOverride,
                   base::Unretained(driver_->device_orientation_interface_.get())));
}

void DeviceOrientationInterface::SetDeviceOrientationOverride(int32_t alpha, int32_t beta, int32_t gamma) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::DeviceOrientation::SetDeviceOrientationOverride,
                   base::Unretained(driver_->device_orientation_interface_.get()),
                   alpha, 
                   beta, 
                   gamma));
}

EmulationInterface::EmulationInterface(ApplicationDriver* driver): driver_(driver) {
  
}

EmulationInterface::~EmulationInterface() {
  
}

void EmulationInterface::CanEmulate(automation::Emulation::CanEmulateCallback callback) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Emulation::CanEmulate,
                   base::Unretained(driver_->emulation_interface_.get()),
                   base::Passed(std::move(callback))));
}

void EmulationInterface::ClearDeviceMetricsOverride() {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Emulation::ClearDeviceMetricsOverride,
                   base::Unretained(driver_->emulation_interface_.get())));
}

void EmulationInterface::ClearGeolocationOverride() {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Emulation::ClearGeolocationOverride,
                   base::Unretained(driver_->emulation_interface_.get())));
}

void EmulationInterface::ResetPageScaleFactor() {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Emulation::ResetPageScaleFactor,
                   base::Unretained(driver_->emulation_interface_.get())));
}

void EmulationInterface::SetCPUThrottlingRate(int32_t rate) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Emulation::SetCPUThrottlingRate,
                   base::Unretained(driver_->emulation_interface_.get()),
                   rate));
}

void EmulationInterface::SetDefaultBackgroundColorOverride(automation::RGBAPtr color) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Emulation::SetDefaultBackgroundColorOverride,
                   base::Unretained(driver_->emulation_interface_.get()),
                   base::Passed(std::move(color))));
}

void EmulationInterface::SetDeviceMetricsOverride(int32_t width, int32_t height, float device_scale_factor, bool mobile, float scale, int32_t screen_width, int32_t screen_height, int32_t position_x, int32_t position_y, bool dont_set_visible_size, automation::ScreenOrientationPtr screen_orientation, automation::ViewportPtr viewport) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Emulation::SetDeviceMetricsOverride,
                   base::Unretained(driver_->emulation_interface_.get()),
                   width, 
                   height, 
                   device_scale_factor, 
                   mobile, 
                   scale, 
                   screen_width, 
                   screen_height, 
                   position_x, 
                   position_y, 
                   dont_set_visible_size, 
                   base::Passed(std::move(screen_orientation)), 
                   base::Passed(std::move(viewport))));
}

void EmulationInterface::SetEmitTouchEventsForMouse(bool enabled, automation::TouchEventForMouseConfiguration configuration) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Emulation::SetEmitTouchEventsForMouse,
                   base::Unretained(driver_->emulation_interface_.get()),
                   enabled, 
                   base::Passed(std::move(configuration))));
}

void EmulationInterface::SetEmulatedMedia(const std::string& media) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Emulation::SetEmulatedMedia,
                   base::Unretained(driver_->emulation_interface_.get()),
                   media));
}

void EmulationInterface::SetGeolocationOverride(int64_t latitude, int64_t longitude, int64_t accuracy) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Emulation::SetGeolocationOverride,
                   base::Unretained(driver_->emulation_interface_.get()),
                   latitude, 
                   longitude, 
                   accuracy));
}

void EmulationInterface::SetNavigatorOverrides(const std::string& platform) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Emulation::SetNavigatorOverrides,
                   base::Unretained(driver_->emulation_interface_.get()),
                   platform));
}

void EmulationInterface::SetPageScaleFactor(float page_scale_factor) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Emulation::SetPageScaleFactor,
                   base::Unretained(driver_->emulation_interface_.get()),
                   page_scale_factor));
}

void EmulationInterface::SetScriptExecutionDisabled(bool value) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Emulation::SetScriptExecutionDisabled,
                   base::Unretained(driver_->emulation_interface_.get()),
                   value));
}

void EmulationInterface::SetTouchEmulationEnabled(bool enabled, int32_t max_touch_points) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Emulation::SetTouchEmulationEnabled,
                   base::Unretained(driver_->emulation_interface_.get()),
                   enabled,
                   max_touch_points));
}

void EmulationInterface::SetVirtualTimePolicy(automation::VirtualTimePolicy policy, int32_t budget, int32_t max_virtual_time_task_starvation_count, bool wait_for_navigation, automation::Emulation::SetVirtualTimePolicyCallback callback) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Emulation::SetVirtualTimePolicy,
                   base::Unretained(driver_->emulation_interface_.get()),
                   policy, 
                   budget, 
                   max_virtual_time_task_starvation_count, 
                   wait_for_navigation, 
                   base::Passed(std::move(callback))));
}

void EmulationInterface::SetVisibleSize(int32_t width, int32_t height) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Emulation::SetVisibleSize,
                   base::Unretained(driver_->emulation_interface_.get()),
                   width, 
                   height));
}

DOMSnapshotInterface::DOMSnapshotInterface(ApplicationDriver* driver): driver_(driver) {

}

DOMSnapshotInterface::~DOMSnapshotInterface() {

}

void DOMSnapshotInterface::GetSnapshot(
    const std::vector<std::string>& computed_style_whitelist, 
    bool include_event_listeners, 
    bool include_paint_order, 
    bool include_user_agent_shadow_tree, 
    automation::DOMSnapshot::GetSnapshotCallback callback) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::DOMSnapshot::GetSnapshot,
                   base::Unretained(driver_->dom_snapshot_interface_.get()),
                   computed_style_whitelist, 
                   include_event_listeners, 
                   include_paint_order, 
                   include_user_agent_shadow_tree, 
                   base::Passed(std::move(callback))));
}

DOMInterface::DOMInterface(ApplicationDriver* driver): driver_(driver) {

}

DOMInterface::~DOMInterface() {

}

void DOMInterface::CollectClassNamesFromSubtree(int32_t node_id, automation::DOM::CollectClassNamesFromSubtreeCallback callback) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::DOM::CollectClassNamesFromSubtree,
                   base::Unretained(driver_->dom_interface_.get()),
                   node_id, 
                   base::Passed(std::move(callback))));
}

void DOMInterface::CopyTo(int32_t node_id, int32_t target_node_id, int32_t anchor_node_id, automation::DOM::CopyToCallback callback) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::DOM::CopyTo,
                   base::Unretained(driver_->dom_interface_.get()),
                   node_id, 
                   target_node_id, 
                   anchor_node_id, 
                   base::Passed(std::move(callback))));
}

void DOMInterface::DescribeNode(int32_t node_id, int32_t backend_node_id, const base::Optional<std::string>& object_id, int32_t depth, bool pierce, automation::DOM::DescribeNodeCallback callback) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::DOM::DescribeNode,
                   base::Unretained(driver_->dom_interface_.get()),
                   node_id, 
                   backend_node_id, 
                   object_id, 
                   depth, 
                   pierce, 
                   base::Passed(std::move(callback))));
}

void DOMInterface::Disable() {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::DOM::Disable,
                   base::Unretained(driver_->dom_interface_.get())));
}

void DOMInterface::DiscardSearchResults(const std::string& search_id) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::DOM::DiscardSearchResults,
                   base::Unretained(driver_->dom_interface_.get()),
                   search_id));
}

void DOMInterface::Enable() {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::DOM::Enable,
                   base::Unretained(driver_->dom_interface_.get())));
}

void DOMInterface::Focus(int32_t node_id, int32_t backend_node_id, const base::Optional<std::string>& object_id) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::DOM::Focus,
                   base::Unretained(driver_->dom_interface_.get()),
                   node_id, 
                   backend_node_id, 
                   object_id));
}

void DOMInterface::GetAttributes(int32_t node_id, automation::DOM::GetAttributesCallback callback) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::DOM::GetAttributes,
                   base::Unretained(driver_->dom_interface_.get()),
                   node_id, 
                   base::Passed(std::move(callback))));
}

void DOMInterface::GetBoxModel(int32_t node_id, int32_t backend_node_id, const base::Optional<std::string>& object_id, automation::DOM::GetBoxModelCallback callback) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::DOM::GetBoxModel,
                   base::Unretained(driver_->dom_interface_.get()),
                   node_id, 
                   backend_node_id, 
                   object_id, 
                   base::Passed(std::move(callback))));
}

void DOMInterface::GetDocument(int32_t depth, bool pierce, automation::DOM::GetDocumentCallback callback) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::DOM::GetDocument,
                   base::Unretained(driver_->dom_interface_.get()),
                   depth, 
                   pierce, 
                   base::Passed(std::move(callback))));
}

void DOMInterface::GetFlattenedDocument(int32_t depth, bool pierce, automation::DOM::GetFlattenedDocumentCallback callback) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::DOM::GetFlattenedDocument,
                   base::Unretained(driver_->dom_interface_.get()),
                   depth, 
                   pierce, 
                   base::Passed(std::move(callback))));
}

void DOMInterface::GetNodeForLocation(int32_t x, int32_t y, bool include_user_agent_shadow_dom, automation::DOM::GetNodeForLocationCallback callback) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::DOM::GetNodeForLocation,
                   base::Unretained(driver_->dom_interface_.get()),
                   x, 
                   y, 
                   include_user_agent_shadow_dom,
                   base::Passed(std::move(callback))));
}

void DOMInterface::GetOuterHTML(int32_t node_id, int32_t backend_node_id, const base::Optional<std::string>& object_id, automation::DOM::GetOuterHTMLCallback callback) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::DOM::GetOuterHTML,
                   base::Unretained(driver_->dom_interface_.get()),
                   node_id, backend_node_id, object_id,
                   base::Passed(std::move(callback))));
}

void DOMInterface::GetRelayoutBoundary(int32_t node_id, automation::DOM::GetRelayoutBoundaryCallback callback) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::DOM::GetRelayoutBoundary,
                   base::Unretained(driver_->dom_interface_.get()),
                   node_id,
                   base::Passed(std::move(callback))));
}

void DOMInterface::GetSearchResults(const std::string& search_id, int32_t from_index, int32_t to_index, automation::DOM::GetSearchResultsCallback callback) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::DOM::GetSearchResults,
                   base::Unretained(driver_->dom_interface_.get()),
                   search_id, from_index, to_index,
                   base::Passed(std::move(callback))));
}

void DOMInterface::HideHighlight() {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::DOM::HideHighlight,
                   base::Unretained(driver_->dom_interface_.get())));
}

void DOMInterface::HighlightNode(automation::HighlightConfigPtr highlight_config, int32_t node_id, int32_t backend_node_id, int32_t object_id) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::DOM::HighlightNode,
                   base::Unretained(driver_->dom_interface_.get()),
                   base::Passed(std::move(highlight_config)), 
                   node_id, 
                   backend_node_id, 
                   object_id));
}

void DOMInterface::HighlightRect(int32_t x, int32_t y, int32_t width, int32_t height, automation::RGBAPtr color, automation::RGBAPtr outline_color) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::DOM::HighlightRect,
                   base::Unretained(driver_->dom_interface_.get()),
                   x, 
                   y, 
                   width, 
                   height, 
                   base::Passed(std::move(color)), 
                   base::Passed(std::move(outline_color))));
}

void DOMInterface::MarkUndoableState() {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::DOM::MarkUndoableState,
                   base::Unretained(driver_->dom_interface_.get())));
}

void DOMInterface::MoveTo(int32_t node_id, int32_t target_node_id, int32_t insert_before_node_id, automation::DOM::MoveToCallback callback) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::DOM::MoveTo,
                   base::Unretained(driver_->dom_interface_.get()),
                   node_id, 
                   target_node_id, 
                   insert_before_node_id, 
                   base::Passed(std::move(callback))));
}

void DOMInterface::PerformSearch(const std::string& query, bool include_user_agent_shadow_dom, automation::DOM::PerformSearchCallback callback) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::DOM::PerformSearch,
                   base::Unretained(driver_->dom_interface_.get()),
                   query, 
                   include_user_agent_shadow_dom, 
                   base::Passed(std::move(callback))));
}

void DOMInterface::PushNodeByPathToFrontend(const std::string& path, automation::DOM::PushNodeByPathToFrontendCallback callback) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::DOM::PushNodeByPathToFrontend,
                   base::Unretained(driver_->dom_interface_.get()),
                   path, 
                   base::Passed(std::move(callback))));
}

void DOMInterface::PushNodesByBackendIdsToFrontend(const std::vector<int32_t>& backend_node_ids, automation::DOM::PushNodesByBackendIdsToFrontendCallback callback) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::DOM::PushNodesByBackendIdsToFrontend,
                   base::Unretained(driver_->dom_interface_.get()),
                   backend_node_ids, 
                   base::Passed(std::move(callback))));
}

void DOMInterface::QuerySelector(int32_t node_id, const std::string& selector, automation::DOM::QuerySelectorCallback callback) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::DOM::QuerySelector,
                   base::Unretained(driver_->dom_interface_.get()),
                   node_id, 
                   selector, 
                   base::Passed(std::move(callback))));
}

void DOMInterface::QuerySelectorAll(int32_t node_id, const std::string& selector, automation::DOM::QuerySelectorAllCallback callback) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::DOM::QuerySelectorAll,
                   base::Unretained(driver_->dom_interface_.get()),
                   node_id, 
                   selector, 
                   base::Passed(std::move(callback))));
}

void DOMInterface::Redo() {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::DOM::Redo,
                   base::Unretained(driver_->dom_interface_.get())));
}

void DOMInterface::RemoveAttribute(int32_t node_id, const std::string& name) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::DOM::RemoveAttribute,
                   base::Unretained(driver_->dom_interface_.get()),
                   node_id,
                   name));
}

void DOMInterface::RemoveNode(int32_t node_id) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::DOM::RemoveNode,
                   base::Unretained(driver_->dom_interface_.get()),
                   node_id));
}

void DOMInterface::RequestChildNodes(int32_t node_id, int32_t depth, bool pierce) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::DOM::RequestChildNodes,
                   base::Unretained(driver_->dom_interface_.get()),
                   node_id, depth, pierce));
}

void DOMInterface::RequestNode(const std::string& object_id, automation::DOM::RequestNodeCallback callback) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::DOM::RequestNode,
                   base::Unretained(driver_->dom_interface_.get()),
                   object_id, 
                   std::move(callback)));
}

void DOMInterface::ResolveNode(int32_t node_id, const base::Optional<std::string>& object_group, automation::DOM::ResolveNodeCallback callback) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::DOM::ResolveNode,
                   base::Unretained(driver_->dom_interface_.get()),
                   node_id, 
                   object_group, 
                   base::Passed(std::move(callback))));
}

void DOMInterface::SetAttributeValue(int32_t node_id, const std::string& name, const std::string& value) {
   driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::DOM::SetAttributeValue,
                   base::Unretained(driver_->dom_interface_.get()),
                   node_id, 
                   name, 
                   value));
}

void DOMInterface::SetAttributesAsText(int32_t node_id, const std::string& text, const base::Optional<std::string>& name) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::DOM::SetAttributesAsText,
                   base::Unretained(driver_->dom_interface_.get()),
                   node_id, 
                   text, 
                   name));
}

void DOMInterface::SetFileInputFiles(const std::vector<std::string>& files, int32_t node_id, int32_t backend_node_id, const base::Optional<std::string>& object_id) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::DOM::SetFileInputFiles,
                   base::Unretained(driver_->dom_interface_.get()),
                   files, 
                   node_id, 
                   backend_node_id, 
                   object_id));
}

void DOMInterface::SetInspectedNode(int32_t node_id) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::DOM::SetInspectedNode,
                   base::Unretained(driver_->dom_interface_.get()),
                   node_id));
}

void DOMInterface::SetNodeName(int32_t node_id, const std::string& name, automation::DOM::SetNodeNameCallback callback) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::DOM::SetNodeName,
                   base::Unretained(driver_->dom_interface_.get()),
                   node_id, 
                   name, 
                   base::Passed(std::move(callback))));
}

void DOMInterface::SetNodeValue(int32_t node_id, const std::string& value) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::DOM::SetNodeValue,
                   base::Unretained(driver_->dom_interface_.get()),
                   node_id, 
                   value));
}

void DOMInterface::SetOuterHTML(int32_t node_id, const std::string& outer_html) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::DOM::SetOuterHTML,
                   base::Unretained(driver_->dom_interface_.get()),
                   node_id, 
                   outer_html));
}

void DOMInterface::Undo() {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::DOM::Undo,
                   base::Unretained(driver_->dom_interface_.get())));
}

void DOMInterface::GetFrameOwner(const std::string& frame_id, automation::DOM::GetFrameOwnerCallback callback) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::DOM::GetFrameOwner,
                   base::Unretained(driver_->dom_interface_.get()),
                   frame_id, 
                   base::Passed(std::move(callback))));
}

CSSInterface::CSSInterface(ApplicationDriver* driver): driver_(driver) {
  
}

CSSInterface::~CSSInterface() {
  
}

void CSSInterface::AddRule(const std::string& style_sheet_id, const std::string& rule_text, automation::SourceRangePtr location, automation::CSS::AddRuleCallback callback) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::CSS::AddRule,
                   base::Unretained(driver_->css_interface_.get()),
                   style_sheet_id, 
                   rule_text,
                   base::Passed(std::move(location)), 
                   base::Passed(std::move(callback))));
}

void CSSInterface::CollectClassNames(const std::string& style_sheet_id, automation::CSS::CollectClassNamesCallback callback) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::CSS::CollectClassNames,
                   base::Unretained(driver_->css_interface_.get()),
                   style_sheet_id, 
                   base::Passed(std::move(callback))));
}

void CSSInterface::CreateStyleSheet(const std::string& frame_id, automation::CSS::CreateStyleSheetCallback callback) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::CSS::CreateStyleSheet,
                   base::Unretained(driver_->css_interface_.get()),
                   frame_id, 
                   base::Passed(std::move(callback))));
}

void CSSInterface::Disable() {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::CSS::Disable,
                   base::Unretained(driver_->css_interface_.get())));
}

void CSSInterface::Enable() {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::CSS::Enable,
                   base::Unretained(driver_->css_interface_.get())));
}

void CSSInterface::ForcePseudoState(int32_t node_id, const std::vector<std::string>& forced_pseudo_classes) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::CSS::ForcePseudoState,
                   base::Unretained(driver_->css_interface_.get()),
                   node_id, 
                   forced_pseudo_classes));
}

void CSSInterface::GetBackgroundColors(int32_t node_id, automation::CSS::GetBackgroundColorsCallback callback) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::CSS::GetBackgroundColors,
                   base::Unretained(driver_->css_interface_.get()),
                   node_id, 
                   base::Passed(std::move(callback))));
}

void CSSInterface::GetComputedStyleForNode(int32_t node_id, automation::CSS::GetComputedStyleForNodeCallback callback) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::CSS::GetComputedStyleForNode,
                   base::Unretained(driver_->css_interface_.get()),
                   node_id, 
                   base::Passed(std::move(callback))));
}

void CSSInterface::GetInlineStylesForNode(int32_t node_id, automation::CSS::GetInlineStylesForNodeCallback callback) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::CSS::GetInlineStylesForNode,
                   base::Unretained(driver_->css_interface_.get()),
                   node_id, 
                   base::Passed(std::move(callback))));
}

void CSSInterface::GetMatchedStylesForNode(int32_t node_id, automation::CSS::GetMatchedStylesForNodeCallback callback) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::CSS::GetMatchedStylesForNode,
                   base::Unretained(driver_->css_interface_.get()),
                   node_id, 
                   base::Passed(std::move(callback))));
}

void CSSInterface::GetMediaQueries(automation::CSS::GetMediaQueriesCallback callback) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::CSS::GetMediaQueries,
                   base::Unretained(driver_->css_interface_.get()),
                   base::Passed(std::move(callback))));
}

void CSSInterface::GetPlatformFontsForNode(int32_t node_id, automation::CSS::GetPlatformFontsForNodeCallback callback) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::CSS::GetPlatformFontsForNode,
                   base::Unretained(driver_->css_interface_.get()),
                   node_id, 
                   base::Passed(std::move(callback))));
}

void CSSInterface::GetStyleSheetText(const std::string& style_sheet_id, automation::CSS::GetStyleSheetTextCallback callback) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::CSS::GetStyleSheetText,
                   base::Unretained(driver_->css_interface_.get()),
                   style_sheet_id, 
                   base::Passed(std::move(callback))));
}

void CSSInterface::SetEffectivePropertyValueForNode(int32_t node_id, const std::string& property_name, const std::string& value) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::CSS::SetEffectivePropertyValueForNode,
                   base::Unretained(driver_->css_interface_.get()),
                   node_id, 
                   property_name, 
                   value));
}

void CSSInterface::SetKeyframeKey(const std::string& style_sheet_id, automation::SourceRangePtr range, const std::string& key_text, automation::CSS::SetKeyframeKeyCallback callback) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::CSS::SetKeyframeKey,
                   base::Unretained(driver_->css_interface_.get()),
                   style_sheet_id, 
                   base::Passed(std::move(range)), 
                   key_text, 
                   base::Passed(std::move(callback))));
}

void CSSInterface::SetMediaText(const std::string& style_sheet_id, automation::SourceRangePtr range, const std::string& text, automation::CSS::SetMediaTextCallback callback) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::CSS::SetMediaText,
                   base::Unretained(driver_->css_interface_.get()),
                   style_sheet_id, 
                   std::move(range), 
                   text, 
                   base::Passed(std::move(callback))));
}

void CSSInterface::SetRuleSelector(const std::string& style_sheet_id, automation::SourceRangePtr range, const std::string& selector, automation::CSS::SetRuleSelectorCallback callback) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::CSS::SetRuleSelector,
                   base::Unretained(driver_->css_interface_.get()),
                   style_sheet_id, 
                   base::Passed(std::move(range)), 
                   selector, 
                   base::Passed(std::move(callback))));
}

void CSSInterface::SetStyleSheetText(const std::string& style_sheet_id, const std::string& text, automation::CSS::SetStyleSheetTextCallback callback) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::CSS::SetStyleSheetText,
                   base::Unretained(driver_->css_interface_.get()),
                   style_sheet_id, 
                   text, 
                   base::Passed(std::move(callback))));
}

void CSSInterface::SetStyleTexts(std::vector<automation::StyleDeclarationEditPtr> edits, automation::CSS::SetStyleTextsCallback callback) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::CSS::SetStyleTexts,
                   base::Unretained(driver_->css_interface_.get()),
                   base::Passed(std::move(edits)), 
                   base::Passed(std::move(callback))));
}

void CSSInterface::StartRuleUsageTracking() {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::CSS::StartRuleUsageTracking,
                   base::Unretained(driver_->css_interface_.get())));
}

void CSSInterface::StopRuleUsageTracking(automation::CSS::StopRuleUsageTrackingCallback callback) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::CSS::StopRuleUsageTracking,
                   base::Unretained(driver_->css_interface_.get()),
                   base::Passed(std::move(callback))));
}

void CSSInterface::TakeCoverageDelta(automation::CSS::TakeCoverageDeltaCallback callback) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::CSS::TakeCoverageDelta,
                   base::Unretained(driver_->css_interface_.get()),
                   base::Passed(std::move(callback))));
}

CacheStorageInterface::CacheStorageInterface(ApplicationDriver* driver): driver_(driver) {
  
}

CacheStorageInterface::~CacheStorageInterface() {

}

void CacheStorageInterface::HasCache(const std::string& cache_id, automation::CacheStorage::HasCacheCallback callback) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::CacheStorage::HasCache,
                   base::Unretained(driver_->cache_storage_interface_.get()),
                   cache_id, 
                   base::Passed(std::move(callback)))); 
}

void CacheStorageInterface::OpenCache(const std::string& cache_id, automation::CacheStorage::OpenCacheCallback callback) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::CacheStorage::OpenCache,
                   base::Unretained(driver_->cache_storage_interface_.get()),
                   cache_id, 
                   base::Passed(std::move(callback))));
}

void CacheStorageInterface::DeleteCache(const std::string& cache_id, automation::CacheStorage::DeleteCacheCallback callback) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::CacheStorage::DeleteCache,
                   base::Unretained(driver_->cache_storage_interface_.get()),
                   cache_id, 
                   base::Passed(std::move(callback))));
}

void CacheStorageInterface::DeleteEntry(const std::string& cache_id, const std::string& request, automation::CacheStorage::DeleteEntryCallback callback) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::CacheStorage::DeleteEntry,
                   base::Unretained(driver_->cache_storage_interface_.get()),
                   cache_id, 
                   request, 
                   base::Passed(std::move(callback))));
}

void CacheStorageInterface::PutEntry(const std::string& cache_id, const std::string& request, blink::mojom::DataElementPtr data, automation::CacheStorage::PutEntryCallback callback) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::CacheStorage::PutEntry,
                   base::Unretained(driver_->cache_storage_interface_.get()),
                   cache_id, 
                   request,
                   base::Passed(std::move(data)),
                   base::Passed(std::move(callback))));
}

void CacheStorageInterface::PutEntryBlob(const std::string& cache_id, const std::string& request, blink::mojom::SerializedBlobPtr blob, automation::CacheStorage::PutEntryBlobCallback callback) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::CacheStorage::PutEntryBlob,
                   base::Unretained(driver_->cache_storage_interface_.get()),
                   cache_id, 
                   request,
                   base::Passed(std::move(blob)),
                   base::Passed(std::move(callback))));
}

void CacheStorageInterface::RequestCacheNames(const std::string& security_origin, automation::CacheStorage::RequestCacheNamesCallback callback) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::CacheStorage::RequestCacheNames,
                   base::Unretained(driver_->cache_storage_interface_.get()),
                   security_origin,
                   base::Passed(std::move(callback))));
}

void CacheStorageInterface::RequestCachedResponse(const std::string& cache_id, const std::string& request_url, bool base64_encoded, automation::CacheStorage::RequestCachedResponseCallback callback) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::CacheStorage::RequestCachedResponse,
                   base::Unretained(driver_->cache_storage_interface_.get()),
                   cache_id, 
                   request_url,
                   base64_encoded,
                   base::Passed(std::move(callback))));
}

void CacheStorageInterface::RequestEntries(const std::string& cache_id, int32_t skip_count, int32_t page_size, automation::CacheStorage::RequestEntriesCallback callback) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::CacheStorage::RequestEntries,
                   base::Unretained(driver_->cache_storage_interface_.get()),
                   cache_id, 
                   skip_count, 
                   page_size, 
                   base::Passed(std::move(callback))));
}

ApplicationCacheInterface::ApplicationCacheInterface(ApplicationDriver* driver): driver_(driver) {
  
}

ApplicationCacheInterface::~ApplicationCacheInterface() {

}

void ApplicationCacheInterface::Enable() {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::ApplicationCacheInterface::Enable,
                   base::Unretained(driver_->application_cache_interface_.get())));
}

void ApplicationCacheInterface::GetApplicationCacheForFrame(const std::string& frame_id, automation::ApplicationCacheInterface::GetApplicationCacheForFrameCallback callback) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::ApplicationCacheInterface::GetApplicationCacheForFrame,
                   base::Unretained(driver_->application_cache_interface_.get()),
                   frame_id, 
                   base::Passed(std::move(callback))));
}

void ApplicationCacheInterface::GetFramesWithManifests(automation::ApplicationCacheInterface::GetFramesWithManifestsCallback callback) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::ApplicationCacheInterface::GetFramesWithManifests,
                   base::Unretained(driver_->application_cache_interface_.get()),
                   base::Passed(std::move(callback))));
}

void ApplicationCacheInterface::GetManifestForFrame(const std::string& frame_id, automation::ApplicationCacheInterface::GetManifestForFrameCallback callback) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::ApplicationCacheInterface::GetManifestForFrame,
                   base::Unretained(driver_->application_cache_interface_.get()),
                   frame_id, 
                   base::Passed(std::move(callback))));
}

AnimationInterface::AnimationInterface(ApplicationDriver* driver): driver_(driver) {
  
}

AnimationInterface::~AnimationInterface() {
  
}

void AnimationInterface::Disable() {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::AnimationInterface::Disable,
                   base::Unretained(driver_->animation_interface_.get())));
}

void AnimationInterface::Enable() {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::AnimationInterface::Enable,
                   base::Unretained(driver_->animation_interface_.get())));
}

void AnimationInterface::GetCurrentTime(const std::string& id, automation::AnimationInterface::GetCurrentTimeCallback callback) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::AnimationInterface::GetCurrentTime,
                   base::Unretained(driver_->animation_interface_.get()),
                   id, 
                   base::Passed(std::move(callback))));
}

void AnimationInterface::GetPlaybackRate(automation::AnimationInterface::GetPlaybackRateCallback callback) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::AnimationInterface::GetPlaybackRate,
                   base::Unretained(driver_->animation_interface_.get()),
                   base::Passed(std::move(callback))));
}

void AnimationInterface::ReleaseAnimations(const std::vector<std::string>& animations) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::AnimationInterface::ReleaseAnimations,
                   base::Unretained(driver_->animation_interface_.get()),
                   animations));
}

void AnimationInterface::ResolveAnimation(const std::string& animation_id, automation::AnimationInterface::ResolveAnimationCallback callback) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::AnimationInterface::ResolveAnimation,
                   base::Unretained(driver_->animation_interface_.get()),
                   animation_id, 
                   base::Passed(std::move(callback))));
}

void AnimationInterface::SeekAnimations(const std::vector<std::string>& animations, int32_t current_time) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::AnimationInterface::SeekAnimations,
                   base::Unretained(driver_->animation_interface_.get()),
                   animations, 
                   current_time));
}

void AnimationInterface::SetPaused(const std::vector<std::string>& animations, bool paused) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::AnimationInterface::SetPaused,
                   base::Unretained(driver_->animation_interface_.get()),
                   animations, 
                   paused));
}

void AnimationInterface::SetPlaybackRate(int32_t playback_rate) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::AnimationInterface::SetPlaybackRate,
                   base::Unretained(driver_->animation_interface_.get()),
                   playback_rate));
}

void AnimationInterface::SetTiming(const std::string& animation_id, int32_t duration, int32_t delay) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::AnimationInterface::SetTiming,
                   base::Unretained(driver_->animation_interface_.get()),
                   animation_id, 
                   duration, 
                   delay));
}

AccessibilityInterface::AccessibilityInterface(ApplicationDriver* driver): driver_(driver) {

}

AccessibilityInterface::~AccessibilityInterface() {

}
  
void AccessibilityInterface::GetPartialAXTree(
    const base::Optional<std::string>& node_id, 
    int32_t backend_node_id, 
    const base::Optional<std::string>& object_id, 
    bool fetch_relatives, 
    automation::Accessibility::GetPartialAXTreeCallback callback) {
  driver_->io_task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&automation::Accessibility::GetPartialAXTree,
                   base::Unretained(driver_->accessibility_interface_.get()),
                   node_id, 
                   backend_node_id, 
                   object_id, 
                   fetch_relatives, 
                   base::Passed(std::move(callback))));
}

ApplicationDriver::ApplicationDriver(
  void* state,
  Application* application, 
  int instance_id): 
    state_(state),
    application_(application),
    instance_id_(instance_id),
    system_info_(this),
    host_(this),
    pages_(this),
    overlay_(this),
    worker_(this),
    storage_(this),
    tethering_(this),
    network_(this),
    layer_tree_(this),
    input_(this),
    indexed_db_(this),
    io_(this),
    headless_(this),
    dom_storage_(this),
    database_(this),
    device_orientation_(this),
    emulation_(this),
    dom_snapshot_(this),
    dom_(this),
    css_(this),
    cache_storage_(this),
    application_cache_(this),
    animation_(this),
    accessibility_(this),
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

  io_task_runner_ = application_->GetIOTaskRunner();
  io_task_runner_->PostTask(
    FROM_HERE,
    base::BindOnce(&ApplicationDriver::BindInterfaces, base::Unretained(this)));
}

ApplicationDriver::~ApplicationDriver() {}

void ApplicationDriver::set_state(void* state) {
  state_ = state;
}

void ApplicationDriver::BindInterfaces() {
  //DLOG(INFO) << "ApplicationDriver (Domain process): making requests for automation interfaces";
  // mojo::MakeRequest(&page_interface_, io_task_runner_);
  // mojo::MakeRequest(&system_info_interface_, io_task_runner_);
  // mojo::MakeRequest(&host_interface_, io_task_runner_);
  // mojo::MakeRequest(&overlay_interface_, io_task_runner_);
  // mojo::MakeRequest(&worker_interface_, io_task_runner_);
  // mojo::MakeRequest(&storage_interface_, io_task_runner_);
  // mojo::MakeRequest(&tethering_interface_, io_task_runner_);
  // mojo::MakeRequest(&network_interface_, io_task_runner_);
  // mojo::MakeRequest(&layer_tree_interface_, io_task_runner_);
  // mojo::MakeRequest(&input_interface_, io_task_runner_);
  // mojo::MakeRequest(&indexed_db_interface_, io_task_runner_);
  // mojo::MakeRequest(&io_interface_, io_task_runner_);
  // mojo::MakeRequest(&headless_interface_, io_task_runner_);
  // mojo::MakeRequest(&dom_storage_interface_, io_task_runner_);
  // mojo::MakeRequest(&database_interface_, io_task_runner_);
  // mojo::MakeRequest(&device_orientation_interface_, io_task_runner_);
  // mojo::MakeRequest(&emulation_interface_, io_task_runner_);
  // mojo::MakeRequest(&dom_snapshot_interface_, io_task_runner_);
  // mojo::MakeRequest(&dom_interface_, io_task_runner_);
  // mojo::MakeRequest(&css_interface_, io_task_runner_);
  // mojo::MakeRequest(&cache_storage_interface_, io_task_runner_);
  // mojo::MakeRequest(&application_cache_interface_, io_task_runner_);
  // mojo::MakeRequest(&animation_interface_, io_task_runner_);
  // mojo::MakeRequest(&accessibility_interface_, io_task_runner_);

  // page_interface_->Register(instance_id_);
  // system_info_interface_->Register(instance_id_);
  // host_interface_->Register(instance_id_);
  // overlay_interface_->Register(instance_id_);
  // worker_interface_->Register(instance_id_);
  // storage_interface_->Register(instance_id_);
  // tethering_interface_->Register(instance_id_);
  // network_interface_->Register(instance_id_);
  // layer_tree_interface_->Register(instance_id_);
  // input_interface_->Register(instance_id_);
  // indexed_db_interface_->Register(instance_id_);
  // io_interface_->Register(instance_id_);
  // headless_interface_->Register(instance_id_);
  // dom_storage_interface_->Register(instance_id_);
  // database_interface_->Register(instance_id_);
  // device_orientation_interface_->Register(instance_id_);
  // emulation_interface_->Register(instance_id_);
  // dom_snapshot_interface_->Register(instance_id_);
  // dom_interface_->Register(instance_id_);
  // css_interface_->Register(instance_id_);
  // cache_storage_interface_->Register(instance_id_);
  // application_cache_interface_->Register(instance_id_);
  // animation_interface_->Register(instance_id_);
  // accessibility_interface_->Register(instance_id_);

  application_->GetChannel()->GetRemoteAssociatedInterface(&page_interface_);
  application_->GetChannel()->GetRemoteAssociatedInterface(&system_info_interface_);
  application_->GetChannel()->GetRemoteAssociatedInterface(&host_interface_);
  application_->GetChannel()->GetRemoteAssociatedInterface(&overlay_interface_);
  application_->GetChannel()->GetRemoteAssociatedInterface(&worker_interface_);
  application_->GetChannel()->GetRemoteAssociatedInterface(&storage_interface_);
  application_->GetChannel()->GetRemoteAssociatedInterface(&tethering_interface_);
  application_->GetChannel()->GetRemoteAssociatedInterface(&network_interface_);
  application_->GetChannel()->GetRemoteAssociatedInterface(&layer_tree_interface_);
  application_->GetChannel()->GetRemoteAssociatedInterface(&input_interface_);
  application_->GetChannel()->GetRemoteAssociatedInterface(&indexed_db_interface_);
  application_->GetChannel()->GetRemoteAssociatedInterface(&io_interface_);
  application_->GetChannel()->GetRemoteAssociatedInterface(&headless_interface_);
  application_->GetChannel()->GetRemoteAssociatedInterface(&dom_storage_interface_);
  application_->GetChannel()->GetRemoteAssociatedInterface(&database_interface_);
  application_->GetChannel()->GetRemoteAssociatedInterface(&device_orientation_interface_);
  application_->GetChannel()->GetRemoteAssociatedInterface(&emulation_interface_);
  application_->GetChannel()->GetRemoteAssociatedInterface(&dom_snapshot_interface_);
  application_->GetChannel()->GetRemoteAssociatedInterface(&dom_interface_);
  application_->GetChannel()->GetRemoteAssociatedInterface(&css_interface_);
  application_->GetChannel()->GetRemoteAssociatedInterface(&cache_storage_interface_);
  application_->GetChannel()->GetRemoteAssociatedInterface(&application_cache_interface_);
  application_->GetChannel()->GetRemoteAssociatedInterface(&animation_interface_);
  application_->GetChannel()->GetRemoteAssociatedInterface(&accessibility_interface_);
}

void ApplicationDriver::RegisterInterfaces() {
  page_interface_->Register(instance_id_);
  system_info_interface_->Register(instance_id_);
  host_interface_->Register(instance_id_);
  overlay_interface_->Register(instance_id_);
  worker_interface_->Register(instance_id_);
  storage_interface_->Register(instance_id_);
  tethering_interface_->Register(instance_id_);
  network_interface_->Register(instance_id_);
  layer_tree_interface_->Register(instance_id_);
  input_interface_->Register(instance_id_);
  indexed_db_interface_->Register(instance_id_);
  io_interface_->Register(instance_id_);
  headless_interface_->Register(instance_id_);
  dom_storage_interface_->Register(instance_id_);
  database_interface_->Register(instance_id_);
  device_orientation_interface_->Register(instance_id_);
  emulation_interface_->Register(instance_id_);
  dom_snapshot_interface_->Register(instance_id_);
  dom_interface_->Register(instance_id_);
  css_interface_->Register(instance_id_);
  cache_storage_interface_->Register(instance_id_);
  application_cache_interface_->Register(instance_id_);
  animation_interface_->Register(instance_id_);
  accessibility_interface_->Register(instance_id_);
}

void ApplicationDriver::BindAnimationClient(automation::AnimationClientAssociatedRequest request) {
  //DLOG(INFO) << "\nApplicationDriver::BindAnimationClient (domain)\n";
  animation_client_binding_.Bind(std::move(request));
}

void ApplicationDriver::BindPageClient(automation::PageClientAssociatedRequest request) {
  //DLOG(INFO) << "\nApplicationDriver::BindPageClient (domain)\n";
  page_client_binding_.Bind(std::move(request));
}

void ApplicationDriver::BindOverlayClient(automation::OverlayClientAssociatedRequest request) {
  //DLOG(INFO) << "\nApplicationDriver::BindOverlayClient (domain)\n";
  overlay_client_binding_.Bind(std::move(request));
}

void ApplicationDriver::BindWorkerClient(automation::ServiceWorkerClientAssociatedRequest request) {
  //DLOG(INFO) << "\nApplicationDriver::BindWorkerClient (domain)\n";
  worker_client_binding_.Bind(std::move(request));
}

void ApplicationDriver::BindStorageClient(automation::StorageClientAssociatedRequest request) {
  //DLOG(INFO) << "\nApplicationDriver::BindStorageClient (domain)\n";
  storage_client_binding_.Bind(std::move(request));
}

void ApplicationDriver::BindNetworkClient(automation::NetworkClientAssociatedRequest request) {
  //DLOG(INFO) << "\nApplicationDriver::BindNetworkClient (domain)\n";
  network_client_binding_.Bind(std::move(request));
}

void ApplicationDriver::BindLayerTreeClient(automation::LayerTreeClientAssociatedRequest request) {
  //DLOG(INFO) << "\nApplicationDriver::BindLayerTreeClient (domain)\n";
  layer_tree_client_binding_.Bind(std::move(request));
}

void ApplicationDriver::BindHeadlessClient(automation::HeadlessClientAssociatedRequest request) {
  //DLOG(INFO) << "\nApplicationDriver::BindHeadlessClient (domain)\n";
  headless_client_binding_.Bind(std::move(request));
}

void ApplicationDriver::BindDOMStorageClient(automation::DOMStorageClientAssociatedRequest request) {
  //DLOG(INFO) << "\nApplicationDriver::BindDOMStorageClient (domain)\n";
  dom_storage_client_binding_.Bind(std::move(request));
}

void ApplicationDriver::BindDatabaseClient(automation::DatabaseClientAssociatedRequest request) {
  //DLOG(INFO) << "\nApplicationDriver::BindDatabaseClient (domain)\n";
  database_client_binding_.Bind(std::move(request));
}

void ApplicationDriver::BindEmulationClient(automation::EmulationClientAssociatedRequest request) {  
  //DLOG(INFO) << "\nApplicationDriver::BindEmulationClient (domain)\n";
  emulation_client_binding_.Bind(std::move(request));
}

void ApplicationDriver::BindDOMClient(automation::DOMClientAssociatedRequest request) {
  //DLOG(INFO) << "\nApplicationDriver::BindDOMClient (domain)\n";
  dom_client_binding_.Bind(std::move(request));
}
  
void ApplicationDriver::BindCSSClient(automation::CSSClientAssociatedRequest request) {
  //DLOG(INFO) << "\nApplicationDriver::BindCSSClient (domain)\n";
  css_client_binding_.Bind(std::move(request));
}

void ApplicationDriver::BindApplicationCacheClient(automation::ApplicationCacheClientAssociatedRequest request) {  
  //DLOG(INFO) << "\nApplicationDriver::BindCacheClient (domain)\n";
  application_cache_client_binding_.Bind(std::move(request));
}

void ApplicationDriver::OnFrameAttached(const std::string& frame_id, const std::string& parent_frame_id) {
  application_->page_callbacks().OnFrameAttached(state_, frame_id.data(), parent_frame_id.data());
}

void ApplicationDriver::OnDomContentEventFired(int64_t timestamp) {
  application_->page_callbacks().OnDomContentEventFired(state_, timestamp);
}

void ApplicationDriver::OnFrameClearedScheduledNavigation(const std::string& frame_id) {
  application_->page_callbacks().OnFrameClearedScheduledNavigation(state_, frame_id.data());
}

void ApplicationDriver::OnFrameDetached(const std::string& frame_id) {
  application_->page_callbacks().OnFrameDetached(state_, frame_id.data());
}

void ApplicationDriver::OnFrameNavigated(automation::FramePtr frame) {
  application_->page_callbacks().OnFrameNavigated(state_, frame.get());
}

void ApplicationDriver::OnFrameResized() {
  application_->page_callbacks().OnFrameResized(state_);
}

void ApplicationDriver::OnFrameScheduledNavigation(const std::string& frame_id, int32_t delay, automation::NavigationReason reason, const std::string& url) {
  application_->page_callbacks().OnFrameScheduledNavigation(state_, frame_id.data(), delay, static_cast<int>(reason), url.data());
}

void ApplicationDriver::OnFrameStartedLoading(const std::string& frame_id) {
  application_->page_callbacks().OnFrameStartedLoading(state_, frame_id.data());
}

void ApplicationDriver::OnFrameStoppedLoading(const std::string& frame_id) {
  application_->page_callbacks().OnFrameStoppedLoading(state_, frame_id.data());
}

void ApplicationDriver::OnInterstitialHidden() {
  application_->page_callbacks().OnInterstitialHidden(state_);
}

void ApplicationDriver::OnInterstitialShown() {
  application_->page_callbacks().OnInterstitialShown(state_);
}

void ApplicationDriver::OnJavascriptDialogClosed(bool result, const std::string& user_input) {
  application_->page_callbacks().OnJavascriptDialogClosed(state_, result, user_input.data());
}

void ApplicationDriver::OnJavascriptDialogOpening(const std::string& url, const std::string& message, automation::DialogType type, bool has_browser_handler, const base::Optional<std::string>& default_prompt) {
  application_->page_callbacks().OnJavascriptDialogOpening(
    state_, 
    url.data(), 
    message.data(), 
    static_cast<int>(type), 
    has_browser_handler ? 1 : 0, 
    default_prompt.has_value() ? default_prompt.value().data() : nullptr);
}

void ApplicationDriver::OnLifecycleEvent(const std::string& frame_id, int32_t loader_id, const std::string& name, int64_t timestamp) {
  application_->page_callbacks().OnLifecycleEvent(state_, frame_id.data(), loader_id, name.data(), timestamp);
}

void ApplicationDriver::OnLoadEventFired(int64_t timestamp) {
  application_->page_callbacks().OnLoadEventFired(state_, timestamp);
}

void ApplicationDriver::OnNavigatedWithinDocument(const std::string& frame_id, const std::string& url) {
  application_->page_callbacks().OnNavigatedWithinDocument(state_, frame_id.data(), url.data());
}

void ApplicationDriver::OnScreencastFrame(const std::string& base64_data, automation::ScreencastFrameMetadataPtr metadata, int32_t session_id) {
  application_->page_callbacks().OnScreencastFrame(state_, base64_data.data(), metadata.get(), session_id);
}

void ApplicationDriver::OnScreencastVisibilityChanged(bool visible) {
  application_->page_callbacks().OnScreencastVisibilityChanged(state_, visible);
}

void ApplicationDriver::OnWindowOpen(const std::string& url, const std::string& window_name, const std::vector<std::string>& window_features, bool user_gesture) {
  const char* arr[window_features.size()];
  size_t idx = 0;
  for (const auto& feature : window_features) {
    arr[idx] = feature.data();
    idx++;
  }
  application_->page_callbacks().OnWindowOpen(
    state_, 
    url.data(), 
    window_name.data(), 
    arr,
    window_features.size(),
    user_gesture ? 1 : 0);
}

void ApplicationDriver::OnPageLayoutInvalidated(bool resized) {
  application_->page_callbacks().OnPageLayoutInvalidated(state_, resized);
}

void ApplicationDriver::InspectNodeRequested(int32_t backend_node_id) {
  application_->overlay_callbacks().InspectNodeRequested(state_, backend_node_id);
}

void ApplicationDriver::NodeHighlightRequested(int32_t node_id) {
  application_->overlay_callbacks().NodeHighlightRequested(state_, node_id);
}

void ApplicationDriver::ScreenshotRequested(automation::ViewportPtr viewport) {
  application_->overlay_callbacks().ScreenshotRequested(state_, viewport.get());
}

void ApplicationDriver::WorkerErrorReported(automation::ServiceWorkerErrorMessagePtr error_message) {
  application_->worker_callbacks().WorkerErrorReported(state_, error_message.get());
}

void ApplicationDriver::WorkerRegistrationUpdated(std::vector<automation::ServiceWorkerRegistrationPtr> registrations) {
  void* arr[registrations.size()];
  size_t idx = 0;
  for (const auto& registration : registrations) {
    arr[idx] = registration.get();
    idx++;
  }
  application_->worker_callbacks().WorkerRegistrationUpdated(
    state_,
    arr,
    registrations.size());
}

void ApplicationDriver::WorkerVersionUpdated(std::vector<automation::ServiceWorkerVersionPtr> versions) {
  void* arr[versions.size()];
  size_t idx = 0;
  for (const auto& version : versions) {
    arr[idx] = version.get();
    idx++;
  }
  application_->worker_callbacks().WorkerVersionUpdated(state_, arr, versions.size());
}

void ApplicationDriver::OnAttachedToTarget(const std::string& session_id, automation::TargetInfoPtr target_info, bool waiting_for_debugger) {
  application_->worker_callbacks().OnAttachedToTarget(state_, session_id.data(), target_info.get(), waiting_for_debugger ? 1 : 0);
}

void ApplicationDriver::OnDetachedFromTarget(const std::string& session_id, const base::Optional<std::string>& target_id) {
  application_->worker_callbacks().OnDetachedFromTarget(state_, session_id.data(), target_id.has_value() ? target_id.value().data() : nullptr);
}

void ApplicationDriver::OnReceivedMessageFromTarget(const std::string& session_id, const std::string& message, const base::Optional<std::string>& target_id) {
  application_->worker_callbacks().OnReceivedMessageFromTarget(state_, session_id.data(), message.data(), target_id.has_value() ? target_id.value().data() : nullptr);
}

void ApplicationDriver::OnCacheStorageContentUpdated(const std::string& origin, const std::string& cache_name) {
  application_->storage_callbacks().OnCacheStorageContentUpdated(state_, origin.data(), cache_name.data());
}

void ApplicationDriver::OnCacheStorageListUpdated(const std::string& origin) {
  application_->storage_callbacks().OnCacheStorageListUpdated(state_, origin.data());
}

void ApplicationDriver::OnIndexedDBContentUpdated(const std::string& origin, const std::string& database_name, const std::string& object_store_name) {
  application_->storage_callbacks().OnIndexedDBContentUpdated(state_, origin.data(), database_name.data(), object_store_name.data());
}

void ApplicationDriver::OnIndexedDBListUpdated(const std::string& origin) {
  application_->storage_callbacks().OnIndexedDBListUpdated(state_, origin.data());
}

void ApplicationDriver::OnAccepted(int32_t port, const std::string& connection_id) {
  application_->tethering_callbacks().OnAccepted(state_, port, connection_id.data());
}

void ApplicationDriver::OnDataReceived(const std::string& request_id, int64_t timestamp, int64_t data_length, int64_t encoded_data_length) {
  application_->network_callbacks().OnDataReceived(state_, request_id.data(), timestamp, data_length, encoded_data_length);
}

void ApplicationDriver::OnEventSourceMessageReceived(const std::string& request_id, int64_t timestamp, const std::string& event_name, const std::string& event_id, const std::string& data) {
  application_->network_callbacks().OnEventSourceMessageReceived(state_, request_id.data(), timestamp, event_name.data(), event_id.data(), data.data());
}

void ApplicationDriver::OnLoadingFailed(const std::string& request_id, int64_t timestamp, automation::ResourceType type, const std::string& error_text, bool canceled, automation::BlockedReason blocked_reason) {
  application_->network_callbacks().OnLoadingFailed(
    state_,
    request_id.data(), 
    timestamp, 
    static_cast<int>(type),
    error_text.data(), 
    canceled ? 1 : 0, 
    static_cast<int>(blocked_reason));
}

void ApplicationDriver::OnLoadingFinished(const std::string& request_id, int64_t timestamp, int64_t encoded_data_length, bool blocked_cross_site_document) {
  application_->network_callbacks().OnLoadingFinished(
    state_,
    request_id.data(),
    timestamp, 
    encoded_data_length, 
    blocked_cross_site_document ? 1 : 0);
}

void ApplicationDriver::OnRequestIntercepted(const std::string& interception_id, automation::RequestPtr request, const std::string& frame_id, automation::ResourceType resource_type, bool is_navigation_request, bool is_download, const base::Optional<std::string>& redirect_url, automation::AuthChallengePtr auth_challenge, automation::ErrorReason response_error_reason, int32_t response_status_code, const base::Optional<base::flat_map<std::string, std::string>>& response_headers) {
  size_t len = response_headers.has_value() ? response_headers.value().size() : 0;
  const char* keys[len];
  const char* vals[len];
  
  for (size_t i = 0; i < len; i++) {
    keys[i] = (response_headers.value().begin() + i)->first.data();
  }
  for (size_t i = 0; i < len; i++) {
    vals[i] = (response_headers.value().begin() + i)->second.data();
  }
  application_->network_callbacks().OnRequestIntercepted(
    state_,
    interception_id.data(),
    request.get(),
    frame_id.data(), 
    static_cast<int>(resource_type), 
    is_navigation_request ? 1 : 0, 
    is_download ? 1 : 0,
    redirect_url.has_value() ? redirect_url.value().data() : nullptr,
    auth_challenge.get(), 
    static_cast<int>(response_error_reason), 
    response_status_code,
    keys, 
    len,
    vals,
    len);
}

void ApplicationDriver::OnRequestServedFromCache(const std::string& request_id) {
  application_->network_callbacks().OnRequestServedFromCache(state_, request_id.data());
}

void ApplicationDriver::OnRequestWillBeSent(const std::string& request_id, const std::string& loader_id, const std::string& document_url, automation::RequestPtr request, int64_t timestamp, int64_t wall_time, automation::InitiatorPtr initiator, automation::ResponsePtr redirect_response, automation::ResourceType type, const base::Optional<std::string>& frame_id, bool has_user_gesture) {
  application_->network_callbacks().OnRequestWillBeSent(
    state_, 
    request_id.data(),
    loader_id.data(),
    document_url.data(),
    request.get(), 
    timestamp, 
    wall_time, 
    initiator.get(), 
    redirect_response.get(), 
    static_cast<int>(type), 
    frame_id.has_value() ? frame_id.value().data() : nullptr,
    has_user_gesture ? 1 : 0);
}

void ApplicationDriver::OnResourceChangedPriority(const std::string& request_id, automation::ResourcePriority new_priority, int64_t timestamp) {
  application_->network_callbacks().OnResourceChangedPriority(
    state_,
    request_id.data(),
    static_cast<int>(new_priority),
    timestamp);
}

void ApplicationDriver::OnResponseReceived(const std::string& request_id, const std::string& loader_id, int64_t timestamp, automation::ResourceType type, automation::ResponsePtr response, const base::Optional<std::string>& frame_id) {
  application_->network_callbacks().OnResponseReceived(
    state_,
    request_id.data(),
    loader_id.data(),
    timestamp,
    static_cast<int>(type), 
    response.get(), 
    frame_id.has_value() ? frame_id.value().data() : nullptr);
}

void ApplicationDriver::OnWebSocketClosed(const std::string& request_id, int64_t timestamp) {
  application_->network_callbacks().OnWebSocketClosed(
    state_,
    request_id.data(),
    timestamp);
}

void ApplicationDriver::OnWebSocketCreated(const std::string& request_id, const std::string& url, automation::InitiatorPtr initiator) {
  application_->network_callbacks().OnWebSocketCreated(
    state_,
    request_id.data(),
    url.data(),
    initiator.get());
}

void ApplicationDriver::OnWebSocketFrameError(const std::string& request_id, int64_t timestamp, const std::string& error_message) {
  application_->network_callbacks().OnWebSocketFrameError(
    state_,
    request_id.data(),
    timestamp,
    error_message.data());
}

void ApplicationDriver::OnWebSocketFrameReceived(const std::string& request_id, int64_t timestamp, automation::WebSocketFramePtr response) {
  application_->network_callbacks().OnWebSocketFrameReceived(
    state_,
    request_id.data(),
    timestamp,
    response.get());
}

void ApplicationDriver::OnWebSocketFrameSent(const std::string& request_id, int64_t timestamp, automation::WebSocketFramePtr response) {
  application_->network_callbacks().OnWebSocketFrameReceived(
    state_,
    request_id.data(),
    timestamp,
    response.get());
}

void ApplicationDriver::OnWebSocketHandshakeResponseReceived(const std::string& request_id, int64_t timestamp, automation::WebSocketResponsePtr response) {
  application_->network_callbacks().OnWebSocketHandshakeResponseReceived(
    state_,
    request_id.data(),
    timestamp,
    response.get());
}

void ApplicationDriver::OnWebSocketWillSendHandshakeRequest(const std::string& request_id, int64_t timestamp, int64_t wall_time, automation::WebSocketRequestPtr request) {
  application_->network_callbacks().OnWebSocketWillSendHandshakeRequest(
    state_,
    request_id.data(),
    timestamp,
    wall_time,
    request.get());
}

void ApplicationDriver::Flush() {
  application_->network_callbacks().Flush(state_);
}

void ApplicationDriver::OnLayerPainted(const std::string& layer_id, const gfx::Rect& clip) {
  application_->layer_tree_callbacks().OnLayerPainted(state_, layer_id.data(), clip.x(), clip.y(), clip.width(), clip.height());
}

void ApplicationDriver::OnLayerTreeDidChange(base::Optional<std::vector<automation::LayerPtr>> layers) {
  size_t len = layers.has_value() ? layers.value().size() : 0;
  void* ptrs[len];
  for (size_t i = 0; i < len; i++) {
    ptrs[i] = (layers.value().begin() + i)->get();
  }
  application_->layer_tree_callbacks().OnLayerTreeDidChange(state_, ptrs, len);
}

void ApplicationDriver::OnNeedsBeginFramesChanged(bool needs_begin_frames) {
  application_->headless_callbacks().OnNeedsBeginFramesChanged(
    state_,
    needs_begin_frames);
}

void ApplicationDriver::OnDomStorageItemAdded(automation::StorageIdPtr storage_id, const std::string& key, const std::string& new_value) {
  application_->dom_storage_callbacks().OnDomStorageItemAdded(
    state_,
    storage_id.get(), 
    key.data(), 
    new_value.data());
}

void ApplicationDriver::OnDomStorageItemRemoved(automation::StorageIdPtr storage_id, const std::string& key) {
  application_->dom_storage_callbacks().OnDomStorageItemRemoved(
    state_,
    storage_id.get(), 
    key.data());
}

void ApplicationDriver::OnDomStorageItemUpdated(automation::StorageIdPtr storage_id, const std::string& key, const std::string& old_value, const std::string& new_value) {
  application_->dom_storage_callbacks().OnDomStorageItemUpdated(
    state_,
    storage_id.get(), 
    key.data(),
    old_value.data(), 
    new_value.data());
}

void ApplicationDriver::OnDomStorageItemsCleared(automation::StorageIdPtr storage_id) {
  application_->dom_storage_callbacks().OnDomStorageItemsCleared(
    state_,
    storage_id.get());
}

void ApplicationDriver::OnAddDatabase(automation::DatabasePtr database) {
  application_->database_callbacks().OnAddDatabase(state_, database.get());
}

void ApplicationDriver::OnVirtualTimeAdvanced(int32_t virtual_time_elapsed) {
  application_->emulation_callbacks().OnVirtualTimeAdvanced(state_, virtual_time_elapsed);
}

void ApplicationDriver::OnVirtualTimeBudgetExpired() {
  application_->emulation_callbacks().OnVirtualTimeBudgetExpired(state_);
}

void ApplicationDriver::OnVirtualTimePaused(int32_t virtual_time_elapsed) {
  application_->emulation_callbacks().OnVirtualTimePaused(state_, virtual_time_elapsed);
}

void ApplicationDriver::SetChildNodes(int32_t parent_id, std::vector<automation::DOMNodePtr> nodes) {
  void* ptrs[nodes.size()];
  for (size_t i = 0; i < nodes.size(); i++) {
    ptrs[i] = nodes[i].get();
  }
  application_->dom_callbacks().SetChildNodes(
    state_, 
    parent_id,
    ptrs,
    nodes.size());
}

void ApplicationDriver::OnAttributeModified(int32_t node_id, const std::string& name, const std::string& value) {
  application_->dom_callbacks().OnAttributeModified(state_, node_id, name.data(), value.data());
}

void ApplicationDriver::OnAttributeRemoved(int32_t node_id, const std::string& name) {
  application_->dom_callbacks().OnAttributeRemoved(state_, node_id, name.data());
}

void ApplicationDriver::OnCharacterDataModified(int32_t node_id, const std::string& character_data) {
  application_->dom_callbacks().OnCharacterDataModified(state_, node_id, character_data.data());
}

void ApplicationDriver::OnChildNodeCountUpdated(int32_t node_id, int32_t child_node_count) {
  application_->dom_callbacks().OnChildNodeCountUpdated(state_, node_id, child_node_count);
}

void ApplicationDriver::OnChildNodeInserted(int32_t parent_node_id, int32_t previous_node_id, automation::DOMNodePtr node) {
  application_->dom_callbacks().OnChildNodeInserted(state_, parent_node_id, previous_node_id, node.get());
}

void ApplicationDriver::OnChildNodeRemoved(int32_t parent_node_id, int32_t node_id) {
  application_->dom_callbacks().OnChildNodeRemoved(state_, parent_node_id, node_id);
}

void ApplicationDriver::OnDistributedNodesUpdated(int32_t insertion_point_id, std::vector<automation::BackendNodePtr> distributed_nodes) {
  void* ptrs[distributed_nodes.size()];
  for (size_t i = 0; i < distributed_nodes.size(); i++) {
    ptrs[i] = distributed_nodes[i].get();
  }
  application_->dom_callbacks().OnDistributedNodesUpdated(state_, insertion_point_id, ptrs, distributed_nodes.size());
}

void ApplicationDriver::OnDocumentUpdated() {
  //DLOG(INFO) << "ApplicationDriver::OnDocumentUpdated (domain)";
  application_->dom_callbacks().OnDocumentUpdated(state_);
}

void ApplicationDriver::OnInlineStyleInvalidated(const std::vector<int32_t>& node_ids) {
  int32_t ids[node_ids.size()];
  for (size_t i = 0; i < node_ids.size(); i++) {
    ids[i] = node_ids[i];
  }
  application_->dom_callbacks().OnInlineStyleInvalidated(state_, ids, node_ids.size());
}

void ApplicationDriver::OnPseudoElementAdded(int32_t parent_id, automation::DOMNodePtr pseudo_element) {
  application_->dom_callbacks().OnPseudoElementAdded(state_, parent_id, pseudo_element.get());
}

void ApplicationDriver::OnPseudoElementRemoved(int32_t parent_id, int32_t pseudo_element_id) {
  application_->dom_callbacks().OnPseudoElementRemoved(state_, parent_id, pseudo_element_id);
}

void ApplicationDriver::OnShadowRootPopped(int32_t host_id, int32_t root_id) {
  application_->dom_callbacks().OnShadowRootPopped(state_, host_id, root_id);
}

void ApplicationDriver::OnShadowRootPushed(int32_t host_id, automation::DOMNodePtr root) {
  application_->dom_callbacks().OnShadowRootPushed(state_, host_id, root.get());
}

void ApplicationDriver::OnFontsUpdated(automation::FontFacePtr font) {
  application_->css_callbacks().OnFontsUpdated(state_, font.get());
}

void ApplicationDriver::OnMediaQueryResultChanged() {
  application_->css_callbacks().OnMediaQueryResultChanged(state_);
}

void ApplicationDriver::OnStyleSheetAdded(automation::CSSStyleSheetHeaderPtr header) {
  application_->css_callbacks().OnStyleSheetAdded(state_, header.get());
}

void ApplicationDriver::OnStyleSheetChanged(const std::string& style_sheet_id) {
  application_->css_callbacks().OnStyleSheetChanged(state_, style_sheet_id.data());
}

void ApplicationDriver::OnStyleSheetRemoved(const std::string& style_sheet_id) {
  application_->css_callbacks().OnStyleSheetRemoved(state_, style_sheet_id.data());
}

void ApplicationDriver::OnApplicationCacheStatusUpdated(const std::string& frame_id, const std::string& manifest_url, int32_t status) {
  application_->application_cache_callback().OnApplicationCacheStatusUpdated(state_, frame_id.data(), manifest_url.data(), status);
}

void ApplicationDriver::OnNetworkStateUpdated(bool is_now_online) {
  application_->application_cache_callback().OnNetworkStateUpdated(state_, is_now_online);
}

void ApplicationDriver::OnAnimationCanceled(const std::string& id) {
  application_->animation_callbacks().OnAnimationCanceled(state_, id.data());
}

void ApplicationDriver::OnAnimationCreated(const std::string& id) {
  application_->animation_callbacks().OnAnimationCreated(state_, id.data());
}

void ApplicationDriver::OnAnimationStarted(automation::AnimationPtr animation) {
  application_->animation_callbacks().OnAnimationStarted(state_, animation.get());
}

}