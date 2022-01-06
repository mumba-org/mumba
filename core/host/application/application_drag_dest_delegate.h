// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_APPLICATION_APPLICATION_DRAG_DEST_DELEGATE_H_
#define MUMBA_HOST_APPLICATION_APPLICATION_DRAG_DEST_DELEGATE_H_

#include "base/strings/string16.h"

namespace ui {
class OSExchangeData;
}

namespace host {
class ApplicationContents;

// An optional delegate that listens for drags of bookmark data.
class ApplicationDragDestDelegate {
 public:
  // Announces that a drag has started. It's valid that a drag starts, along
  // with over/enter/leave/drop notifications without receiving any bookmark
  // data.
  virtual void DragInitialize(ApplicationContents* contents) = 0;

  // Notifications of drag progression.
  virtual void OnDragOver() = 0;
  virtual void OnDragEnter() = 0;
  virtual void OnDrop() = 0;
  // This should also clear any state kept about this drag.
  virtual void OnDragLeave() = 0;

#if defined(USE_AURA)
  // Called at the start of every drag to supply the data associated with the
  // drag.
  virtual void OnReceiveDragData(const ui::OSExchangeData& data) = 0;
#endif  // USE_AURA

  virtual ~ApplicationDragDestDelegate() {}
};

}  // namespace host

#endif  // CONTENT_PUBLIC_BROWSER_WEB_DRAG_DEST_DELEGATE_H_
