// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims
import Foundation

public struct TransformStreamController {

  public var desiredSize: Int? {
    var value: CInt = 0
    if TransformStreamControllerGetDesiredSize(reference, worker.reference, &value) != 0 {
      return Int(value)
    }
    return nil
  }

  let worker: WebWorker
  let reference: TransformStreamControllerRef

  init(reference: TransformStreamControllerRef, worker: WebWorker) {
    self.reference = reference
    self.worker = worker
  }
  
  public func enqueue() {
    TransformStreamControllerEnqueue(reference, worker.reference) 
  }

  public func enqueue(chunk: Data) {
    chunk.withUnsafeBytes { (bytes: UnsafePointer<UInt8>) -> Void in
      TransformStreamControllerEnqueueChunk(reference, worker.reference, bytes, CInt(chunk.count))
    }
  }

  public func error() {
    TransformStreamControllerError(reference, worker.reference)
  }
 
  public func terminate() {
    TransformStreamControllerTerminate(reference, worker.reference)
  }
}

public protocol TransformStreamTransformer : class {
  func transform(chunk: Data, controller: TransformStreamController)
  func flush(controller: TransformStreamController)
}

public class TransformStream {

  public var readable: ReadableStream {
    return ReadableStream(reference: TransformStreamGetReadable(reference, worker.reference), worker: worker)
  }

  public var writable: WritableStream {
    return WritableStream(reference: TransformStreamGetWritable(reference, worker.reference), worker: worker)
  }
  
  var reference: TransformStreamRef!
  let worker: WebWorker
  var transformer: TransformStreamTransformer?

  public init(transformer: TransformStreamTransformer, worker: WebWorker) {
    self.transformer = transformer
    self.worker = worker
    let state = unsafeBitCast(Unmanaged.passUnretained(self).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    reference = TransformStreamCreate( 
      worker.reference, 
      state, 
      { (handle: UnsafeMutableRawPointer?, bytes: UnsafePointer<UInt8>?, size: Int32, controller: UnsafeMutableRawPointer?) -> Void in
        let this = unsafeBitCast(handle, to: TransformStream.self)
        this.transformer!.transform(
          chunk: Data(bytesNoCopy: UnsafeMutableRawPointer(mutating: bytes!), count: Int(size), deallocator: .none), 
          controller: TransformStreamController(reference: controller!, worker: this.worker))
      }, 
      { (handle: UnsafeMutableRawPointer?, controller: UnsafeMutableRawPointer?) -> Void in 
        let this = unsafeBitCast(handle, to: TransformStream.self)
        this.transformer!.flush(
          controller: TransformStreamController(reference: controller!, worker: this.worker))
      })
  }
  
  init(reference: TransformStreamRef, worker: WebWorker) {
    self.reference = reference
    self.worker = worker
  }

}