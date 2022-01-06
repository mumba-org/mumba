// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public protocol PlatformException {
  var code: Int { get }
  var message: String { get }
}

public enum PlatformError : Error {
  case OnInit(exception: PlatformException)
  case OnCreateWindow(exception: PlatformException)
}
