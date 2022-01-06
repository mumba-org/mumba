// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_BROWSER_ANDROID_JAVA_INTERFACES_IMPL_H_
#define CONTENT_BROWSER_ANDROID_JAVA_INTERFACES_IMPL_H_

#include "core/host/android/java_interfaces.h"
#include "services/service_manager/public/mojom/interface_provider.mojom.h"

namespace host {
class RenderFrameHostImpl;
class WebContents;

void BindInterfaceRegistryForWebContents(
    service_manager::mojom::InterfaceProviderRequest request,
    WebContents* web_contents);

void BindInterfaceRegistryForRenderFrameHost(
    service_manager::mojom::InterfaceProviderRequest request,
    RenderFrameHostImpl* render_frame_host);

}  // namespace host

#endif  // CONTENT_BROWSER_ANDROID_JAVA_INTERFACES_IMPL_H_
