// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics

public protocol UIWidgetObserver : class {
 func onWidgetClosing(widget: UIWidget)
 func onWidgetCreated(widget: UIWidget)
 func onWidgetDestroying(widget: UIWidget)
 func onWidgetDestroyed(widget: UIWidget)
 func onWidgetVisibilityChanging(widget: UIWidget, visible: Bool)
 func onWidgetVisibilityChanged(widget: UIWidget, visible: Bool)
 func onWidgetActivationChanged(widget: UIWidget, active: Bool)
 func onWidgetBoundsChanged(widget: UIWidget, newBounds: IntRect)
}

public protocol UIWidgetRemovalsObserver : class {
 func onWillRemoveView(widget: UIWidget, view: View)
}

extension UIWidgetObserver {
	public func onWidgetClosing(widget: UIWidget) {}
 	public func onWidgetCreated(widget: UIWidget) {}
 	public func onWidgetDestroying(widget: UIWidget) {}
 	public func onWidgetDestroyed(widget: UIWidget) {}
 	public func onWidgetVisibilityChanging(widget: UIWidget, visible: Bool) {}
 	public func onWidgetVisibilityChanged(widget: UIWidget, visible: Bool) {}
 	public func onWidgetActivationChanged(widget: UIWidget, active: Bool) {}
 	public func onWidgetBoundsChanged(widget: UIWidget, newBounds: IntRect) {}
}


extension UIWidgetRemovalsObserver {
	public func onWillRemoveView(widget: UIWidget, view: View) {}	
}