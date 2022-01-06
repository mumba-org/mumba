// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/application/launcher_host.h"

namespace host {

LauncherHost::LauncherHost(): launcher_host_binding_(this) {
  
}

LauncherHost::~LauncherHost() {

}
common::mojom::LauncherClient* LauncherHost::GetLauncherClientInterface() {
  return launcher_client_interface_.get();
}

void LauncherHost::AddBinding(common::mojom::LauncherHostAssociatedRequest request) {
  launcher_host_binding_.Bind(std::move(request));
}

void LauncherHost::WindowLaunch(WindowLaunchCallback callback) {
  
}

void LauncherHost::WindowClose(common::mojom::WindowHandlePtr window, WindowCloseCallback callback) {
  
}

void LauncherHost::PageNew(common::mojom::WindowHandlePtr window, const std::string& url, PageNewCallback callback) {
  
}

void LauncherHost::PageClose(common::mojom::PageHandlePtr page, PageCloseCallback callback) {
  
}

void LauncherHost::PageList(common::mojom::WindowHandlePtr window, PageListCallback callback) {
  
}


}