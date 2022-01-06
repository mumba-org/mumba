// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics
import MumbaShims

public class CopyOutputRequest {
  
  public static func createBitmapRequest(layerTreeHost: LayerTreeHost, callback: @escaping (_: Bitmap) -> Void) -> CopyOutputRequest {
    return CopyOutputRequest(layerTreeHost: layerTreeHost, callback: callback)
  }

  internal var reference: CopyOutputRequestRef?
  internal var callback: (_: Bitmap) -> Void

  init(layerTreeHost: LayerTreeHost, callback: @escaping (_: Bitmap) -> Void) {
    self.callback = callback
    let selfHandle = unsafeBitCast(Unmanaged.passUnretained(self).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    self.reference = _CopyOutputRequestCreateWithBitmapRequest(
      selfHandle, layerTreeHost.reference, {
        (handle: UnsafeMutableRawPointer?, bmp: BitmapRef?) in 
          let state = unsafeBitCast(handle, to: CopyOutputRequest.self)
          state.onBitmapAvailable(bmp!) 
      }
    )
  }

 deinit {
    _CopyOutputRequestDestroy(reference)
 }

 public func sendEmptyResult() {}

 private func onBitmapAvailable(_ bmp: BitmapRef) {
    callback(Bitmap(reference: bmp))
 }

}
