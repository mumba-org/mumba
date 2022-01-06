// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims
import Foundation

public struct WritableStreamWriter {
  
  public var closed: Promise<None> {
    return Promise<None>(reference: WritableStreamWriterClosed(reference, worker.reference), worker: worker)
  }

  public var desiredSize: Int {
    return Int(WritableStreamWriterGetDesiredSize(reference, worker.reference))
  }

  public var ready: Promise<None> {
    return Promise<None>(reference: WritableStreamWriterReady(reference, worker.reference), worker: worker)
  }

  public func abort() -> Promise<None> {
    return Promise<None>(reference: WritableStreamWriterAbort(reference, worker.reference), worker: worker)
  }

  public func close() -> Promise<None> {
    return Promise<None>(reference: WritableStreamWriterClose(reference, worker.reference), worker: worker)
  }

  public func releaseLock() {
    WritableStreamWriterReleaseLock(reference, worker.reference)
  }

  public func write() -> Promise<None> {
    return Promise<None>(reference: WritableStreamWriterWrite(reference, worker.reference), worker: worker)
  }

  public func write(chunk: Data) -> Promise<None> {
    return chunk.withUnsafeBytes { (bytes: UnsafePointer<UInt8>) -> Promise<None> in
      return Promise<None>(reference: WritableStreamWriterWriteChunk(reference, worker.reference, bytes, CInt(chunk.count)), worker: worker)
    }
  }

  let reference: WritableStreamWriterRef
  let worker: WebWorker
  
  init(reference: WritableStreamWriterRef, worker: WebWorker) {
    self.reference = reference
    self.worker = worker
  }
}

public struct WritableStream {

  public var isLocked: Bool {
    return WritableStreamIsLocked(reference, worker.reference) != 0
  }

  public var writer: WritableStreamWriter {
    return WritableStreamWriter(reference: WritableStreamGetWriter(reference, worker.reference), worker: worker)
  }
  
  let reference: WritableStreamRef
  let worker: WebWorker
  
  init(reference: WritableStreamRef, worker: WebWorker) {
    self.reference = reference
    self.worker = worker
  }

  public func abort() -> Promise<None> {
    return Promise(reference: WritableStreamAbort(reference, worker.reference), worker: worker)
  }

  public func serialize(port: MessagePort) {
    WritableStreamSerialize(reference, worker.reference, port.reference)
  }
  
}