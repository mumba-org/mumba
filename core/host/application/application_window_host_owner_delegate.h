// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_APPLICATION_RENDER_WIDGET_HOST_OWNER_DELEGATE_H_
#define MUMBA_HOST_APPLICATION_RENDER_WIDGET_HOST_OWNER_DELEGATE_H_

#include "core/shared/common/content_export.h"

namespace IPC {
class Message;
}

namespace blink {
class WebMouseEvent;
}

namespace host {

struct NativeWebKeyboardEvent;

//
// ApplicationWindowHostOwnerDelegate
//
//  An interface implemented by an object owning a ApplicationWindowHost. This is
//  intended to be temporary until the RenderViewHostImpl and
//  ApplicationWindowHost classes are disentangled; see http://crbug.com/542477
//  and http://crbug.com/478281.
class CONTENT_EXPORT ApplicationWindowHostOwnerDelegate {
 public:
  // The ApplicationWindowHost received an IPC message. Return true if this delegate
  // handles it.
  virtual bool OnMessageReceived(const IPC::Message& msg) = 0;

  // The ApplicationWindowHost has been initialized.
  virtual void ApplicationWindowDidInit() = 0;

  // The ApplicationWindowHost will be setting its loading state.
  virtual void ApplicationWindowWillSetIsLoading(bool is_loading) = 0;

  // The ApplicationWindowHost got the focus.
  virtual void ApplicationWindowGotFocus() = 0;

  // The ApplicationWindowHost lost the focus.
  virtual void ApplicationWindowLostFocus() = 0;

  // The ApplicationWindowHost forwarded a mouse event.
  virtual void ApplicationWindowDidForwardMouseEvent(
      const blink::WebMouseEvent& mouse_event) = 0;

  // The ApplicationWindowHost wants to forward a keyboard event; returns whether
  // it's allowed to do so.
  virtual bool MayApplicationWindowForwardKeyboardEvent(
      const NativeWebKeyboardEvent& key_event) = 0;

  // Allow OwnerDelegate to control whether its ApplicationWindowHost contributes
  // priority to the RenderProcessHost.
  virtual bool ShouldContributePriorityToProcess() = 0;

 protected:
  virtual ~ApplicationWindowHostOwnerDelegate() {}
};

}  // namespace host

#endif  // MUMBA_HOST_APPLICATION_RENDER_WIDGET_HOST_OWNER_DELEGATE_H_
