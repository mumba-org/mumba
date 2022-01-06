// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Foundation
import MumbaShims

public class UrlBuffer {

  public var rawData: UnsafeMutableRawPointer? {
    return Cronet_Buffer_GetData(reference)
  }

  public var data: Data {
    guard size > 0 else {
      return Data()
    }
    return Data(bytesNoCopy: rawData!, count: Int(size), deallocator: Data.Deallocator.none)
  }

  public var size: UInt64 {
    return Cronet_Buffer_GetSize(reference)
  }

  var reference: Cronet_BufferPtr
  var callbackPtr: Cronet_BufferCallbackPtr?
  var _data: Data?

  public init(size: UInt64) {
    reference = Cronet_Buffer_Create()
    Cronet_Buffer_InitWithAlloc(reference, size)
    let statePtr = unsafeBitCast(Unmanaged.passUnretained(self).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    Cronet_Buffer_SetClientContext(reference, statePtr)
  }

  public init(data: Data) {
    _data = data
    reference = Cronet_Buffer_Create()
    callbackPtr =
      Cronet_BufferCallback_CreateWith({ (state: Cronet_BufferCallbackPtr?, buffer: Cronet_BufferPtr?) in
        let clientContext = Cronet_BufferCallback_GetClientContext(state)
        let this = unsafeBitCast(clientContext, to: UrlBuffer.self)
        this._data = nil  
    })
    let statePtr = unsafeBitCast(Unmanaged.passUnretained(self).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    Cronet_BufferCallback_SetClientContext(callbackPtr!, statePtr)
    Cronet_Buffer_SetClientContext(reference, statePtr)
    data.withUnsafeBytes { 
      Cronet_Buffer_InitWithDataAndCallback(reference, $0[0], UInt64(data.count), callbackPtr!)
    }
  }

  public init(data: UnsafeMutableRawPointer?, size: UInt64) {
    reference = Cronet_Buffer_Create()
    callbackPtr =
      Cronet_BufferCallback_CreateWith({ (state: Cronet_BufferCallbackPtr?, buffer: Cronet_BufferPtr?) in
        //let clientContext = Cronet_BufferCallback_GetClientContext(state)
        //let this = unsafeBitCast(clientContext, to: UrlBuffer.self)
        let data = Cronet_Buffer_GetData(buffer)
        free(data)
    })
    let statePtr = unsafeBitCast(Unmanaged.passUnretained(self).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    Cronet_BufferCallback_SetClientContext(callbackPtr!, statePtr)
    Cronet_Buffer_SetClientContext(reference, statePtr)
    Cronet_Buffer_InitWithDataAndCallback(reference, data, size, callbackPtr!)
  }

  deinit {
    if let cb = callbackPtr {
      Cronet_BufferCallback_Destroy(cb)
    }
    //Cronet_Buffer_Destroy(reference)
  }

  public func copy() -> Data {
    return copy(offset: 0, length: Int(self.size))
  }

  public func copy(length: Int) -> Data {
    return copy(offset: 0, length: length)
  }

  public func copy(offset: Int, length: Int) -> Data {
    guard size > 0 else {
      return Data()
    }
    return Data(bytes: rawData!, count: Int(size))
  }

}