// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims

public struct Headers {

  let reference: HeadersRef
  
  init(reference: HeadersRef) {
    self.reference = reference
  }

  public subscript(key: String) -> String {
    get {
      return key.withCString { (cstr: UnsafePointer<Int8>?) -> String in
        var len: CInt = 0
        if let str = HeadersGet(reference, cstr, &len) {
          return String(bytesNoCopy: str, length: Int(len), encoding: String.Encoding.utf8, freeWhenDone: true)!
        }
        return String()
      }
    }
    set {
      key.withCString { kcstr in
        newValue.withCString { vcstr in
          HeadersSet(reference, kcstr, vcstr)
        }
      }
    }
  }

  public func has(_ key: String) -> Bool {
    return key.withCString { kcstr in
      return HeadersHas(reference, kcstr)
    } != 0
  }

  public func append(_ name: String, _ value: String) {
    name.withCString { ncstr in
      value.withCString { vcstr in
        HeadersAppend(reference, ncstr, vcstr)
      }
    }
  }

  public func remove(_ key: String) {
    key.withCString { kcstr in
      HeadersRemove(reference, kcstr)
    }
  }

}