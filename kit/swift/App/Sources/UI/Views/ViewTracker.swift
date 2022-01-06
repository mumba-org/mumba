// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public class ViewTracker : ViewObserver {

  public var view: View? {
    get {
      return _view
    }
    set {
      guard newValue !== _view else {
        return
      }

      if let v = _view {
        v.removeObserver(observer: self)
      }
  
      _view = newValue
    
      if let v = _view {
        v.addObserver(observer: self)
      }

    }
  }

  var _view: View?

  public init(view: View? = nil) {
    _view = view
  }

  deinit {
    view = nil
  }
  
  public func clear() { 
    view = nil
  }
 
  public func onViewIsDeleting(observed: View) {
    view = nil
  }
}