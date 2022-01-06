// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims

public class WebData {
  
  public private(set) var size: Int
  public private(set) var data: UnsafeRawPointer?
  public private(set) var owned: Bool

  public static func fromAscii(_ str: String) -> WebData {
    let len = str.count
    let buf = UnsafeMutableRawPointer.allocate(byteCount: len, alignment: MemoryLayout<Character>.alignment)
    let bufCharView = buf.bindMemory(to: Character.self, capacity: len)
    var pos = str.startIndex//.utf8.startIndex
    for i in 0..<len {
      bufCharView[i] = str[pos]//.utf8[pos]
      pos = str.index(after: pos)//.utf8.index(after: pos)
    }
    return WebData(data: buf, size: len, owned: true)
  }

  public init(data: UnsafeRawPointer?, size: Int, owned: Bool = true) {
    self.data = data
    self.size = size
    self.owned = owned
  }

  deinit {  
    //if owned {
     // if let d = data  {
     //   //print("WebData: deallocating..")
     //   d.deallocate()
     // }
    //}
  }

}

public class WebDataSource {
  
  var reference: WebDataSourceRef

  init(reference: WebDataSourceRef) {
    self.reference = reference
  }

  deinit {
    
  }

}

public class WebDataSourceExtraData {
  
  var reference: WebDataSourceExtraDataRef

  init(reference: WebDataSourceExtraDataRef) {
    self.reference = reference
  }
   
}

public class WebDataConsumerHandle {
  public init() {}
}