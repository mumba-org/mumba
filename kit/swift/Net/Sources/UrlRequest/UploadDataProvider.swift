// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Foundation
import MumbaShims

public protocol UploadDataProvider {
  var length: Int64 { get }
  func read(sink: UploadDataSink, buffer: UrlBuffer)
  func rewind(sink: UploadDataSink)
  func close()
}

internal class UploadDataProviderWrapper {

  public var length: Int64 {
    return Cronet_UploadDataProvider_GetLength(reference)
  }

  var reference: Cronet_UploadDataProviderPtr?
  var impl: UploadDataProvider

  public init(provider: UploadDataProvider) {
    impl = provider
    reference = Cronet_UploadDataProvider_CreateWith(
      // GetLengthFunc
      { (ptr: Cronet_UploadDataProviderPtr?) -> Int64 in
        let context = Cronet_UploadDataProvider_GetClientContext(ptr)
        let this = unsafeBitCast(context, to: UploadDataProviderWrapper.self)
        return this.impl.length
      },
      // ReadFunc
      { (ptr: Cronet_UploadDataProviderPtr?, sinkPtr: Cronet_UploadDataSinkPtr?, bufferPtr: Cronet_BufferPtr?) in
        let context = Cronet_UploadDataProvider_GetClientContext(ptr)
        let this = unsafeBitCast(context, to: UploadDataProviderWrapper.self)
        let sinkContext = Cronet_UploadDataSink_GetClientContext(sinkPtr)
        let sink = unsafeBitCast(sinkContext, to: UploadDataSinkWrapper.self)
        let bufContext = Cronet_BufferCallback_GetClientContext(bufferPtr)
        let buf = unsafeBitCast(bufContext, to: UrlBuffer.self)
        this.impl.read(sink: sink.impl, buffer: buf)
      },
      // RewindFunc
      { (ptr: Cronet_UploadDataProviderPtr?, sinkPtr: Cronet_UploadDataSinkPtr?) in
        let context = Cronet_UploadDataProvider_GetClientContext(ptr)
        let this = unsafeBitCast(context, to: UploadDataProviderWrapper.self)
        let sinkContext = Cronet_UploadDataSink_GetClientContext(sinkPtr)
        let sink = unsafeBitCast(sinkContext, to: UploadDataSinkWrapper.self)
        this.impl.rewind(sink: sink.impl)
      },
      // CloseFunc
      { (ptr: Cronet_UploadDataProviderPtr?) in
        let context = Cronet_UploadDataProvider_GetClientContext(ptr)
        let this = unsafeBitCast(context, to: UploadDataProviderWrapper.self)
        this.impl.close()
      }
    )
    let thisPtr = unsafeBitCast(Unmanaged.passUnretained(self).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    Cronet_UploadDataProvider_SetClientContext(reference, thisPtr)
  }

  deinit {
    Cronet_UploadDataProvider_Destroy(reference!) 
  }
  
  // public func read(sink: UploadDataSink, buffer: UrlBuffer) {
  //   Cronet_UploadDataProvider_Read(reference, sink.reference, buffer.reference)
  // }

  // public func rewind(sink: UploadDataSink) {
  //   Cronet_UploadDataProvider_Rewind(reference, sink.reference)
  // }

  // public func close() {
  //   Cronet_UploadDataProvider_Close(reference)
  // }

}