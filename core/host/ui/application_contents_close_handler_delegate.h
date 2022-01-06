// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_UI_APPLICATION_CONTENTS_CLOSE_HANDLER_DELEGATE_H_
#define MUMBA_HOST_UI_APPLICATION_CONTENTS_CLOSE_HANDLER_DELEGATE_H_

namespace host {

// ApplicationContentsCloseHandler delegate.
class ApplicationContentsCloseHandlerDelegate {
 public:
  // Invoked to clone the layers of the WebContents. Should do nothing if there
  // is already a clone (eg CloneWebContentsLayer() has been invoked without a
  // DestroyClonedLayer()) or no WebContents. It is expected that when this is
  // invoked the cloned layer tree is drawn on top of the existing WebContents.
  virtual void CloneApplicationContentsLayer() = 0;

  // Invoked to destroy the cloned layer tree. This may be invoked when there is
  // no cloned layer tree.
  virtual void DestroyClonedLayer() = 0;

 protected:
  virtual ~ApplicationContentsCloseHandlerDelegate() {}
};

}

#endif  // CHROME_BROWSER_UI_VIEWS_FRAME_WEB_CONTENTS_CLOSE_HANDLER_DELEGATE_H_
