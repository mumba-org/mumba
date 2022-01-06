// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_APPLICATION_RENDER_WIDGET_HOST_ITERATOR_H_
#define MUMBA_HOST_APPLICATION_RENDER_WIDGET_HOST_ITERATOR_H_

namespace host {

class ApplicationWindowHost;

// RenderWidgetHostIterator is used to safely iterate over a list of
// RenderWidgetHosts.
class ApplicationWindowHostIterator {
 public:
  virtual ~ApplicationWindowHostIterator() {}

  // Returns the next RenderWidgetHost in the list. Returns nullptr if none is
  // available.
  virtual ApplicationWindowHost* GetNextHost() = 0;
};

}  // namespace host

#endif  // CONTENT_PUBLIC_BROWSER_RENDER_WIDGET_HOST_ITERATOR_H_
