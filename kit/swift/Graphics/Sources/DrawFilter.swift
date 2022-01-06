// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims

public enum DrawFilterType {  
  case Paint
  case IntPoint
  case Line
  case Bitmap
  case IntRect
  case RRect
  case Oval
  case Path
  case Text
}

public protocol DrawFilter : class {
  // This is probably never used by us
  // but is good to make room for it anyway
  func filter(paint: Paint, type: DrawFilterType) -> Bool
}

public class DrawFilterSkia : DrawFilter {
   
   var reference: DrawFilterRef

   internal init(reference: DrawFilterRef) {
     self.reference = reference
   }

   deinit {
     //_DrawFilterDestroy(reference)
   }

   public func filter(paint: Paint, type: DrawFilterType) -> Bool {
     return false
   }

}