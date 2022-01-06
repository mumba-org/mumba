// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/application/window_manager_host.h"

namespace host {

WindowManagerHost::WindowManagerHost(): 
  window_manager_host_binding_(this) {
  
}

WindowManagerHost::~WindowManagerHost() {

}

common::mojom::WindowManagerClient* WindowManagerHost::GetWindowManagerClientInterface() {
  return window_manager_client_interface_.get();
}

void WindowManagerHost::AddBinding(common::mojom::WindowManagerHostAssociatedRequest request) {
  // bind here on IO or on UI?
  window_manager_host_binding_.Bind(std::move(request));
}

void WindowManagerHost::HostWindowLaunch(HostWindowLaunchCallback callback) {

}

void WindowManagerHost::HostWindowClose(common::mojom::WindowHandlePtr handle, HostWindowCloseCallback callback) {
  
}

void WindowManagerHost::HostWindowSetParent(common::mojom::WindowHandlePtr handle, common::mojom::WindowHandlePtr parent, HostWindowSetParentCallback callback) {

}

void WindowManagerHost::HostWindowMaximize(common::mojom::WindowHandlePtr handle, HostWindowMaximizeCallback callback) {

}

void WindowManagerHost::HostWindowMinimize(common::mojom::WindowHandlePtr handle, HostWindowMinimizeCallback callback) {

}

void WindowManagerHost::HostWindowRestore(common::mojom::WindowHandlePtr handle, HostWindowRestoreCallback callback) {

}

void WindowManagerHost::HostWindowSetFullscreen(common::mojom::WindowHandlePtr handle, bool fullscreen, HostWindowSetFullscreenCallback callback) {

}

void WindowManagerHost::HostWindowActivate(common::mojom::WindowHandlePtr handle, HostWindowActivateCallback callback) {

}

void WindowManagerHost::HostWindowSetTitle(common::mojom::WindowHandlePtr handle, const std::string& title, HostWindowSetTitleCallback callback) {

}

void WindowManagerHost::HostWindowSetIcon(common::mojom::WindowHandlePtr handle, const std::string& url, HostWindowSetIconCallback callback) {

}

void WindowManagerHost::HostWindowMove(common::mojom::WindowHandlePtr handle, HostWindowMoveCallback callback) {

}

void WindowManagerHost::HostWindowSetSize(common::mojom::WindowHandlePtr handle, HostWindowSetSizeCallback callback) {

}

void WindowManagerHost::HostWindowSetMinimumSize(common::mojom::WindowHandlePtr handle, HostWindowSetMinimumSizeCallback callback) {

}

void WindowManagerHost::HostWindowSetMaximumSize(common::mojom::WindowHandlePtr handle, HostWindowSetMaximumSizeCallback callback) {

}

void WindowManagerHost::HostWindowSetModal(common::mojom::WindowHandlePtr handle, HostWindowSetModalCallback callback) {

}

void WindowManagerHost::HostWindowSetActivatable(common::mojom::WindowHandlePtr handle, bool activatable, HostWindowSetActivatableCallback callback) {

}

void WindowManagerHost::HostWindowIsFullscreen(common::mojom::WindowHandlePtr handle, HostWindowIsFullscreenCallback callback) {

}

void WindowManagerHost::HostWindowCanMaximize(common::mojom::WindowHandlePtr handle, HostWindowCanMaximizeCallback callback) {

}

void WindowManagerHost::HostWindowCanMinimize(common::mojom::WindowHandlePtr handle, HostWindowCanMinimizeCallback callback) {

}

void WindowManagerHost::HostWindowGetTitle(common::mojom::WindowHandlePtr handle, HostWindowGetTitleCallback callback) {

}

void WindowManagerHost::HostWindowGetIcon(common::mojom::WindowHandlePtr handle, HostWindowGetIconCallback callback) {

}

void WindowManagerHost::HostWindowCanResize(common::mojom::WindowHandlePtr handle, HostWindowCanResizeCallback callback) {

}

void WindowManagerHost::HostWindowGetSize(common::mojom::WindowHandlePtr handle) {

}

void WindowManagerHost::HostWindowGetMinimumSize(common::mojom::WindowHandlePtr handle) {

}

void WindowManagerHost::HostWindowGetMaximumSize(common::mojom::WindowHandlePtr handle) {

}

void WindowManagerHost::HostWindowPageNew(common::mojom::WindowHandlePtr window, const std::string& title, HostWindowPageNewCallback callback) {

}

void WindowManagerHost::HostWindowPageClose(common::mojom::PageHandlePtr page, HostWindowPageCloseCallback callback) {

}

void WindowManagerHost::HostWindowPageList(common::mojom::WindowHandlePtr window, HostWindowPageListCallback callback) {

}


}