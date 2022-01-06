// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public protocol ViewObserver : class {
  func onChildViewAdded(observed: View, child: View)
  func onChildViewRemoved(observed: View, child: View)
  func onViewVisibilityChanged(observed: View)
  func onViewEnabledChanged(observed: View)
  func onViewPreferredSizeChanged(observed: View)
  func onViewBoundsChanged(observed: View)
  func onChildViewReordered(observed: View, child: View)
  func onViewThemeChanged(observed: View)
  func onViewIsDeleting(observed: View)
}

extension ViewObserver {
  public func onChildViewAdded(observed: View, child: View) {}
  public func onChildViewRemoved(observed: View, child: View) {}
  public func onViewVisibilityChanged(observed: View) {}
  public func onViewEnabledChanged(observed: View) {}
  public func onViewPreferredSizeChanged(observed: View) {}
  public func onViewBoundsChanged(observed: View) {}
  public func onChildViewReordered(observed: View, child: View) {}
  public func onViewThemeChanged(observed: View) {}
  public func onViewIsDeleting(observed: View) {}
}