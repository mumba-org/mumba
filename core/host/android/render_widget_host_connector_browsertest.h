// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_BROWSER_ANDROID_RENDER_WIDGET_HOST_CONNECTOR_BROWSERTEST_H_
#define CONTENT_BROWSER_ANDROID_RENDER_WIDGET_HOST_CONNECTOR_BROWSERTEST_H_

#include <string>

#include "base/macros.h"
#include "core/host/android/ime_adapter_android.h"
#include "core/host/application/application_window_host_view_android.h"
#include "core/host/web_contents/web_contents_impl.h"
#include "content/public/test/content_host_test.h"
#include "content/host/host/host.h"

namespace host {

class RenderWidgetHostConnectorTest : public ContentHostTest {
 public:
  RenderWidgetHostConnectorTest();

 protected:
  void SetUpOnMainThread() override;

  WebContentsImpl* web_contents() const {
    return static_cast<WebContentsImpl*>(host()->web_contents());
  }

  RenderWidgetHostViewAndroid* application_window_host_view_android() const {
    return static_cast<RenderWidgetHostViewAndroid*>(
        web_contents()->GetRenderWidgetHostView());
  }

  RenderWidgetHostConnector* application_window_host_connector() const {
    return connector_in_rwhva(application_window_host_view_android());
  }

  RenderWidgetHostConnector* connector_in_rwhva(
      RenderWidgetHostViewAndroid* rwhva) const {
    // Use ImeAdapterAndroid that inherits RenderWidgetHostConnector for
    // testing.
    return rwhva->ime_adapter_for_testing();
  }

 private:
  DISALLOW_COPY_AND_ASSIGN(RenderWidgetHostConnectorTest);
};

}  // namespace host

#endif  // CONTENT_BROWSER_ANDROID_RENDER_WIDGET_HOST_CONNECTOR_BROWSERTEST_H_
