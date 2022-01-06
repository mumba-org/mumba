// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_APPLICATION_RENDER_WIDGET_HOST_VIEW_BASE_OBSERVER_H_
#define MUMBA_HOST_APPLICATION_RENDER_WIDGET_HOST_VIEW_BASE_OBSERVER_H_

#include "base/macros.h"
#include "core/shared/common/content_export.h"

namespace host {

class ApplicationWindowHostView;

class CONTENT_EXPORT ApplicationWindowHostViewObserver {
 public:
  // All derived classes must de-register as observers when receiving this
  // notification.
  virtual void OnApplicationWindowHostViewDestroyed(
      ApplicationWindowHostView* view);

 protected:
  ApplicationWindowHostViewObserver() = default;
  virtual ~ApplicationWindowHostViewObserver();

 private:
  DISALLOW_COPY_AND_ASSIGN(ApplicationWindowHostViewObserver);
};

}  // namespace host

#endif  // MUMBA_HOST_APPLICATION_RENDER_WIDGET_HOST_VIEW_BASE_OBSERVER_H_
