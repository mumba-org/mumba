// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims

public typealias GrGLInterfaceCallback = (_: GrGLInterface) -> Void

public class GrGLInterface {

  static var callback: GrGLInterfaceCallback? = nil

  // public var callbackData: UnsafeMutableRawPointer {
  //   return _GrGLInterfaceGetCallbackData(reference)
  // }

  var reference: GrGLInterfaceRef

  public init(reference: GrGLInterfaceRef) {
    self.reference = reference
  }

  public func setCallback(callback: @escaping GrGLInterfaceCallback) {
    GrGLInterface.callback = callback
  }

  // public func setCallbackData(callbackData: UnsafeRawPointer) {
  //   _GrGLInterfaceSetCallback(reference, { (reference: GrGLInterfaceRef?) in
  //     GrGLInterface.callback!(GrGLInterface(reference: reference!))
  //   }, callbackData)
  // }
}
