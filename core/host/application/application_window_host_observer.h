// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_APPLICATION_APPLICATION_WINDOW_HOST_OBSERVER_H_
#define MUMBA_HOST_APPLICATION_APPLICATION_WINDOW_HOST_OBSERVER_H_

#include "core/shared/common/content_export.h"

namespace host {
class ApplicationWindowHost;

// An observer API implemented by classes which are interested
// in RenderWidgetHost events.
class CONTENT_EXPORT ApplicationWindowHostObserver {
 public:
  // This method is invoked when the visibility of the RenderWidgetHost changes.
  virtual void ApplicationWindowHostVisibilityChanged(
    ApplicationWindowHost* window_host,
    bool became_visible) {}

  // This method is invoked when the observed RenderWidgetHost is destroyed.
  // This is guaranteed to be the last call made to the observer, so if the
  // observer is tied to the observed RenderWidgetHost, it is safe to delete it.
  virtual void ApplicationWindowHostDestroyed(
    ApplicationWindowHost* window_host) {}

 protected:
  virtual ~ApplicationWindowHostObserver() {}
};

}  // namespace host

#endif  // CONTENT_PUBLIC_BROWSER_RENDER_PROCESS_HOST_OBSERVER_H_
