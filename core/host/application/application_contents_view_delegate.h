// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_APPLICATION_APPLICATION_CONTENTS_VIEW_DELEGATE_H_
#define MUMBA_HOST_APPLICATION_APPLICATION_CONTENTS_VIEW_DELEGATE_H_

#if defined(__OBJC__)
#import <Cocoa/Cocoa.h>
#endif

#include "base/callback_forward.h"
#include "core/shared/common/content_export.h"
#include "ui/gfx/native_widget_types.h"

#if defined(__OBJC__)
@protocol ApplicationWindowHostViewMacDelegate;
#endif

namespace common {
struct ContextMenuParams;  
}

namespace host {
class ApplicationContents;
class ApplicationWindowHost;
class ApplicationDragDestDelegate;

// This interface allows a client to extend the functionality of the
// ApplicationContentsView implementation.
class CONTENT_EXPORT ApplicationContentsViewDelegate {
 public:
  virtual ~ApplicationContentsViewDelegate();

  // Returns the native window containing the ApplicationContents, or nullptr if the
  // ApplicationContents is not in any window.
  virtual gfx::NativeWindow GetNativeWindow();

  // Returns a delegate to process drags not handled by content.
  virtual ApplicationDragDestDelegate* GetDragDestDelegate();

  // Shows a context menu.
  virtual void ShowContextMenu(//RenderFrameHost* render_frame_host,
                               ApplicationWindowHost* application_window_host,
                               const common::ContextMenuParams& params);

  // Store the current focused view and start tracking it.
  virtual void StoreFocus();

  // Restore focus to stored view if possible, return true if successful.
  virtual bool RestoreFocus();

  // Clears any stored focus.
  virtual void ResetStoredFocus();

  // Allows the delegate to intercept a request to focus the ApplicationContents,
  // and focus something else instead. Returns true when intercepted.
  virtual bool Focus();

  // Advance focus to the view that follows or precedes the ApplicationContents.
  virtual bool TakeFocus(bool reverse);

  // Returns a newly-created delegate for the ApplicationWindowHostViewMac, to handle
  // events on the responder chain.
#if defined(__OBJC__)
  virtual NSObject<ApplicationWindowHostViewMacDelegate>*
  CreateApplicationWindowHostViewDelegate(ApplicationWindowHost* application_window_host,
                                          bool is_popup);
#else
  virtual void* CreateApplicationWindowHostViewDelegate(
      ApplicationWindowHost* application_window_host,
      bool is_popup);
#endif
};

ApplicationContentsViewDelegate* CreateApplicationContentsViewDelegate(
    ApplicationContents* application_contents);

}  // namespace host

#endif  // CONTENT_PUBLIC_BROWSER_WEB_CONTENTS_VIEW_DELEGATE_H_
