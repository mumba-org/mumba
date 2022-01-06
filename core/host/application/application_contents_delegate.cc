// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/application/application_contents_delegate.h"

#include <memory>

#include "base/compiler_specific.h"
#include "base/logging.h"
#include "base/memory/singleton.h"
#include "build/build_config.h"
#include "components/viz/common/surfaces/surface_id.h"
#include "core/host/application/keyboard_event_processing_result.h"
#include "core/host/application/application_window_host.h"
#include "core/host/application/application_contents.h"
//#include "core/common/bindings_policy.h"
//#include "core/common/url_constants.h"
#include "ui/gfx/geometry/rect.h"

namespace host {

ApplicationContentsDelegate::ApplicationContentsDelegate() {
  
}

ApplicationContents* ApplicationContentsDelegate::OpenURL(
  ApplicationContents* source,
  const OpenURLParams& params) {
  return nullptr;
}

bool ApplicationContentsDelegate::ShouldTransferNavigation(
    bool is_main_frame_navigation) {
  return true;
}

bool ApplicationContentsDelegate::IsPopupOrPanel(const ApplicationContents* source) const {
  return false;
}

bool ApplicationContentsDelegate::CanOverscrollContent() const { return false; }

bool ApplicationContentsDelegate::ShouldSuppressDialogs(ApplicationContents* source) {
  return false;
}

bool ApplicationContentsDelegate::ShouldPreserveAbortedURLs(ApplicationContents* source) {
  return false;
}

bool ApplicationContentsDelegate::DidAddMessageToConsole(
    ApplicationContents* source,
    int32_t level,
    const base::string16& message,
    int32_t line_no,
    const base::string16& source_id) {
  return false;
}

void ApplicationContentsDelegate::BeforeUnloadFired(ApplicationContents* application_contents,
                                            bool proceed,
                                            bool* proceed_to_fire_unload) {
  *proceed_to_fire_unload = true;
}

bool ApplicationContentsDelegate::ShouldFocusLocationBarByDefault(ApplicationContents* source) {
  return false;
}

bool ApplicationContentsDelegate::ShouldFocusPageAfterCrash() {
  return true;
}

bool ApplicationContentsDelegate::ShouldResumeRequestsForCreatedWindow() {
  return true;
}

bool ApplicationContentsDelegate::TakeFocus(ApplicationContents* source, bool reverse) {
  return false;
}

void ApplicationContentsDelegate::CanDownload(
    const GURL& url,
    const std::string& request_method,
    const base::Callback<void(bool)>& callback) {
  callback.Run(true);
}

bool ApplicationContentsDelegate::HandleContextMenu(
    const common::ContextMenuParams& params) {
  return false;
}

KeyboardEventProcessingResult ApplicationContentsDelegate::PreHandleKeyboardEvent(
    ApplicationContents* source,
    const NativeWebKeyboardEvent& event) {
  return KeyboardEventProcessingResult::NOT_HANDLED;
}

bool ApplicationContentsDelegate::PreHandleGestureEvent(
    ApplicationContents* source,
    const blink::WebGestureEvent& event) {
  return false;
}

bool ApplicationContentsDelegate::CanDragEnter(
    ApplicationContents* source,
    const common::DropData& data,
    blink::WebDragOperationsMask operations_allowed) {
  return true;
}

bool ApplicationContentsDelegate::OnGoToEntryOffset(int offset) {
  return true;
}

bool ApplicationContentsDelegate::ShouldCreateApplicationContents(
    ApplicationContents* application_contents,
    ApplicationWindowHost* opener,
//    SiteInstance* source_site_instance,
    int32_t route_id,
    int32_t main_frame_route_id,
    int32_t main_frame_widget_route_id,
    common::mojom::WindowContainerType window_container_type,
    const GURL& opener_url,
    const std::string& frame_name,
    const GURL& target_url) {
  return true;
}

//JavaScriptDialogManager* ApplicationContentsDelegate::GetJavaScriptDialogManager(
//    ApplicationContents* source) {
//  return nullptr;
//}

//std::unique_ptr<BluetoothChooser> ApplicationContentsDelegate::RunBluetoothChooser(
//    RenderFrameHost* frame,
//    const BluetoothChooser::EventHandler& event_handler) {
//  return nullptr;
//}

bool ApplicationContentsDelegate::EmbedsFullscreenWindow() const {
  return false;
}

bool ApplicationContentsDelegate::IsFullscreenOrPending(
    const ApplicationContents* application_contents) const {
  return false;
}

blink::WebDisplayMode ApplicationContentsDelegate::GetDisplayMode(
    const ApplicationContents* application_contents) const {
  return blink::kWebDisplayModeBrowser;
}

//content::ColorChooser* ApplicationContentsDelegate::OpenColorChooser(
//    ApplicationContents* application_contents,
//    SkColor color,
//    const std::vector<blink::mojom::ColorSuggestionPtr>& suggestions) {
//  return nullptr;
//}

void ApplicationContentsDelegate::RequestMediaAccessPermission(
    ApplicationContents* application_contents,
    const common::MediaStreamRequest& request,
    const common::MediaResponseCallback& callback) {
  LOG(ERROR) << "ApplicationContentsDelegate::RequestMediaAccessPermission: "
             << "Not supported.";
  callback.Run(common::MediaStreamDevices(), common::MEDIA_DEVICE_NOT_SUPPORTED,
               std::unique_ptr<common::MediaStreamUI>());
}

bool ApplicationContentsDelegate::CheckMediaAccessPermission(
    ApplicationWindowHost* render_frame_host,
    const GURL& security_origin,
    common::MediaStreamType type) {
  LOG(ERROR) << "ApplicationContentsDelegate::CheckMediaAccessPermission: "
             << "Not supported.";
  return false;
}

std::string ApplicationContentsDelegate::GetDefaultMediaDeviceID(
    ApplicationContents* application_contents,
    common::MediaStreamType type) {
  return std::string();
}

#if defined(OS_ANDROID)
base::android::ScopedJavaLocalRef<jobject>
ApplicationContentsDelegate::GetContentVideoViewEmbedder() {
  return base::android::ScopedJavaLocalRef<jobject>();
}

bool ApplicationContentsDelegate::ShouldBlockMediaRequest(const GURL& url) {
  return false;
}

void ApplicationContentsDelegate::SetOverlayMode(bool use_overlay_mode) {}
#endif

//bool ApplicationContentsDelegate::RequestPpapiBrokerPermission(
//    ApplicationContents* application_contents,
//    const GURL& url,
//    const base::FilePath& plugin_path,
//    const base::Callback<void(bool)>& callback) {
//  return false;
//}

ApplicationContentsDelegate::~ApplicationContentsDelegate() {
  while (!attached_contents_.empty()) {
    ApplicationContents* application_contents = *attached_contents_.begin();
    application_contents->SetDelegate(nullptr);
  }
  DCHECK(attached_contents_.empty());
}

void ApplicationContentsDelegate::Attach(ApplicationContents* application_contents) {
  DCHECK(attached_contents_.find(application_contents) == attached_contents_.end());
  attached_contents_.insert(application_contents);
}

void ApplicationContentsDelegate::Detach(ApplicationContents* application_contents) {
  DCHECK(attached_contents_.find(application_contents) != attached_contents_.end());
  attached_contents_.erase(application_contents);
}

gfx::Size ApplicationContentsDelegate::GetSizeForNewApplicationWindow(
    ApplicationContents* application_contents) const {
  // just a start.. fix with the real thing
  gfx::Size size = application_contents->GetContainerBounds().size();
  DLOG(INFO) << "ApplicationContentsDelegate::GetSizeForNewApplicationWindow -> w: " << size.width() << " h: " << size.height();
  return size;
}

bool ApplicationContentsDelegate::IsNeverVisible(ApplicationContents* application_contents) {
  return false;
}

//bool ApplicationContentsDelegate::SaveFrame(const GURL& url, const Referrer& referrer) {
//  return false;
//}

//blink::WebSecurityStyle ApplicationContentsDelegate::GetSecurityStyle(
//    ApplicationContents* application_contents,
//    SecurityStyleExplanations* security_style_explanations) {
//  return blink::kWebSecurityStyleUnknown;
//}

//void ApplicationContentsDelegate::RequestAppBannerFromDevTools(
//    content::ApplicationContents* application_contents) {
//}

bool ApplicationContentsDelegate::ShouldAllowRunningInsecureContent(
    ApplicationContents* application_contents,
    bool allowed_per_prefs,
    const url::Origin& origin,
    const GURL& resource_url) {
  return allowed_per_prefs;
}

int ApplicationContentsDelegate::GetTopControlsHeight() const {
  return 0;
}

int ApplicationContentsDelegate::GetBottomControlsHeight() const {
  return 0;
}

bool ApplicationContentsDelegate::DoBrowserControlsShrinkBlinkSize() const {
  return false;
}

void ApplicationContentsDelegate::UpdatePictureInPictureSurfaceId(
    const viz::SurfaceId& surface_id,
    const gfx::Size& natural_size) {}

void ApplicationContentsDelegate::ExitPictureInPicture() {}

}  // namespace host
