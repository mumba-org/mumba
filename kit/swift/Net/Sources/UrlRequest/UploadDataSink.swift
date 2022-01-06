// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Foundation
import MumbaShims

public protocol UploadDataSink {
  func onReadSucceeded(finalChunk: Bool)
  func onReadError(error: UrlRequestError)
  func onRewindSucceeded()
  func onRewindError(error: UrlRequestError)
}

internal class UploadDataSinkWrapper {

  var reference: Cronet_UploadDataSinkPtr
  var impl: UploadDataSink

  public init(sink: UploadDataSink) {
    self.impl = sink
    reference = Cronet_UploadDataSink_CreateWith(
      // OnReadSucceededFunc
      {(ptr: Cronet_UploadDataSinkPtr?, finalChunk: CInt) in
        let context = Cronet_UploadDataSink_GetClientContext(ptr)
        let this = unsafeBitCast(context, to: UploadDataSinkWrapper.self)
        this.impl.onReadSucceeded(finalChunk: finalChunk != 0)
      },
      // OnReadErrorFunc
      {(ptr: Cronet_UploadDataSinkPtr?, errorPtr: Cronet_ErrorPtr?) in
        let context = Cronet_UploadDataSink_GetClientContext(ptr)
        let this = unsafeBitCast(context, to: UploadDataSinkWrapper.self)
        this.impl.onReadError(error: UrlRequestError(reference: errorPtr!))
      },
      // OnRewindSuccededFunc
      {(ptr: Cronet_UploadDataSinkPtr?) in
        let context = Cronet_UploadDataSink_GetClientContext(ptr)
        let this = unsafeBitCast(context, to: UploadDataSinkWrapper.self)
        this.impl.onRewindSucceeded()
      },
      // OnRewindErrorFunc
      {(ptr: Cronet_UploadDataSinkPtr?, errorPtr: Cronet_ErrorPtr?) in
        let context = Cronet_UploadDataSink_GetClientContext(ptr)
        let this = unsafeBitCast(context, to: UploadDataSinkWrapper.self)
        this.impl.onRewindError(error: UrlRequestError(reference: errorPtr!))
      }
    )
    let this = unsafeBitCast(Unmanaged.passUnretained(self).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    Cronet_UploadDataSink_SetClientContext(reference, this)
  }

  deinit {
    Cronet_UploadDataSink_Destroy(reference)
  }

  public func onReadSucceeded(finalChunk: Bool) {
    Cronet_UploadDataSink_OnReadSucceeded(reference, finalChunk ? 1 : 0)
  }

  public func onReadError(error: UrlRequestError) {
    Cronet_UploadDataSink_OnReadError(reference, error.reference)
  }

  public func onRewindSucceeded() {
    Cronet_UploadDataSink_OnRewindSucceded(reference)
  }

  public func onRewindError(error: UrlRequestError) {
    Cronet_UploadDataSink_OnRewindError(reference, error.reference)
  }

}