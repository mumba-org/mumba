// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/application/application_window_host_delegate.h"

#include "build/build_config.h"
//#include "components/rappor/public/sample.h"
#include "core/host/application/application_window_host_delegate_view.h"
#include "core/host/application/keyboard_event_processing_result.h"
#include "ui/gfx/geometry/rect.h"

namespace host {

KeyboardEventProcessingResult ApplicationWindowHostDelegate::PreHandleKeyboardEvent(
    const NativeWebKeyboardEvent& event) {
  DLOG(INFO) << "ApplicationWindowHostDelegate::PreHandleKeyboardEvent";
  return KeyboardEventProcessingResult::NOT_HANDLED;
}

bool ApplicationWindowHostDelegate::HandleWheelEvent(
    const blink::WebMouseWheelEvent& event) {
  DLOG(INFO) << "ApplicationWindowHostDelegate::HandleWheelEvent";
  return false;
}

bool ApplicationWindowHostDelegate::PreHandleGestureEvent(
    const blink::WebGestureEvent& event) {
  return false;
}

BrowserAccessibilityManager*
    ApplicationWindowHostDelegate::GetRootAccessibilityManager() {
  return nullptr;
}

BrowserAccessibilityManager*
    ApplicationWindowHostDelegate::GetOrCreateRootAccessibilityManager() {
  return nullptr;
}

// If a delegate does not override this, the ApplicationWindowHostView will
// assume it is the sole platform event consumer.
ApplicationWindowHostInputEventRouter*
ApplicationWindowHostDelegate::GetInputEventRouter() {
  return nullptr;
}

// If a delegate does not override this, the ApplicationWindowHostView will
// assume its own ApplicationWindowHost should consume keyboard events.
ApplicationWindowHost* ApplicationWindowHostDelegate::GetFocusedApplicationWindowHost(
    ApplicationWindowHost* receiving_widget) {
  return receiving_widget;
}

ApplicationWindowHost*
ApplicationWindowHostDelegate::GetApplicationWindowHostWithPageFocus() {
  return nullptr;
}

bool ApplicationWindowHostDelegate::IsFullscreen() const {
  return false;
}

blink::WebDisplayMode ApplicationWindowHostDelegate::GetDisplayMode(
    ApplicationWindowHost* application_window_host) const {
  return blink::kWebDisplayModeBrowser;
}

bool ApplicationWindowHostDelegate::HasMouseLock(
    ApplicationWindowHost* application_window_host) {
  return false;
}

ApplicationWindowHost* ApplicationWindowHostDelegate::GetMouseLockWidget() {
  return nullptr;
}

bool ApplicationWindowHostDelegate::RequestKeyboardLock(ApplicationWindowHost* host,
                                                        bool esc_key_locked) {
  return false;
}

ApplicationWindowHost* ApplicationWindowHostDelegate::GetKeyboardLockWidget() {
  return nullptr;
}

TextInputManager* ApplicationWindowHostDelegate::GetTextInputManager() {
  return nullptr;
}

RouteController* ApplicationWindowHostDelegate::GetRouteController() {
  return nullptr; 
}

NavigationController* ApplicationWindowHostDelegate::GetNavigationController() {
  return nullptr; 
}

bool ApplicationWindowHostDelegate::IsHidden() {
  return false;
}

ApplicationWindowHostDelegateView* ApplicationWindowHostDelegate::GetDelegateView() {
  return nullptr;
}

ApplicationWindowHost* ApplicationWindowHostDelegate::GetFullscreenApplicationWindowHost()
    const {
  return nullptr;
}

bool ApplicationWindowHostDelegate::OnUpdateDragCursor() {
  return false;
}

//bool ApplicationWindowHostDelegate::IsWindowForMainFrame(ApplicationWindowHost*) {
//  return false;
//}

//bool ApplicationWindowHostDelegate::AddDomainInfoToRapporSample(
//    rappor::Sample* sample) {
  //sample->SetStringField("Domain", "Unknown");
//  return false;
//}

// void ApplicationWindowHostDelegate::UpdateUrlForUkmSource(
//     ukm::UkmRecorder* service,
//     ukm::SourceId ukm_source_id) {}

gfx::Size ApplicationWindowHostDelegate::GetAutoResizeSize() {
  return gfx::Size();
}

ApplicationContents* ApplicationWindowHostDelegate::GetAsApplicationContents() {
  return nullptr;
}

bool ApplicationWindowHostDelegate::IsShowingContextMenuOnPage() const {
  return false;
}

std::string ApplicationWindowHostDelegate::GetDefaultMediaDeviceID(common::MediaStreamType media_stream_type) {
  return std::string();
}

double ApplicationWindowHostDelegate::GetPendingPageZoomLevel() {
  return 0.0;
}

bool ApplicationWindowHostDelegate::IsNeverVisible() {
  return false;
}

bool ApplicationWindowHostDelegate::ShouldIgnoreUnresponsiveApplication() {
  return false;
}

bool ApplicationWindowHostDelegate::HasPersistentVideo() const {
  return false;
}

bool ApplicationWindowHostDelegate::OnMessageReceived(
  ApplicationWindowHost* application_window_host,
  const IPC::Message& message) {
  return false;
}

bool ApplicationWindowHostDelegate::CanOverscrollContent() const {
  return false;
}

void ApplicationWindowHostDelegate::UpdateTitle(
  ApplicationWindowHost* application_window_host,
  const base::string16& title, 
  base::i18n::TextDirection title_direction) {
  
}

void ApplicationWindowHostDelegate::CancelModalDialogs() {

}

void ApplicationWindowHostDelegate::DidChangeLoadProgress() {
  
}

void ApplicationWindowHostDelegate::DidFailLoadWithError(const GURL& url, int32_t error_code, const base::string16& error_description) {

}

void ApplicationWindowHostDelegate::DidStartLoading(bool is_main_frame, bool to_different_document) {

}

void ApplicationWindowHostDelegate::DidStopLoading() {
  
}

void ApplicationWindowHostDelegate::DidCancelLoading() {
  
}

void ApplicationWindowHostDelegate::DidCallFocus() {

}

void ApplicationWindowHostDelegate::UpdateStateForFrame(ApplicationFrame* application_frame, const common::mojom::PageState& page_state) {

}

void ApplicationWindowHostDelegate::UpdateApplicationWindowSize(bool is_main_frame) {
  
}

void ApplicationWindowHostDelegate::DidAccessInitialDocument() {

}

void ApplicationWindowHostDelegate::DocumentOnLoadCompleted(ApplicationFrame* application_frame) {
  
}

void ApplicationWindowHostDelegate::DidNavigateMainFramePreCommit(bool navigation_is_within_page) {

}

void ApplicationWindowHostDelegate::DidNavigateMainFramePostCommit(ApplicationFrame* application_window_host, const common::mojom::DidCommitProvisionalLoadParams& params) {

}

void ApplicationWindowHostDelegate::DidNavigateAnyFramePostCommit(ApplicationFrame* application_window_host, const common::mojom::DidCommitProvisionalLoadParams& params) {

}

void ApplicationWindowHostDelegate::NotifySwapped(
  ApplicationFrame* old_host,
  ApplicationFrame* new_host,
  bool is_main_frame) {

}

void ApplicationWindowHostDelegate::NotifyMainFrameSwapped(
  ApplicationFrame* old_host,
  ApplicationFrame* new_host) {

}

void ApplicationWindowHostDelegate::NotifyFrameSwapped(ApplicationFrame* old_frame,
                                                       ApplicationFrame* new_frame) {

}

ApplicationContents* ApplicationWindowHostDelegate::OpenURL(const GURL& url) {
  return nullptr;
}

Visibility ApplicationWindowHostDelegate::GetVisibility() const {
  return Visibility::HIDDEN;
}

void ApplicationWindowHostDelegate::OnCloseAckReceived(ApplicationWindowHost* application_window_host) {
  
}

}  // namespace host
