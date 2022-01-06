// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims
import Foundation

public struct ReadableStreamReader {
  
  let worker: WebWorker
  let reference: ReadableStreamReaderRef
  
  init(reference: ReadableStreamReaderRef, worker: WebWorker) {
    self.reference = reference
    self.worker = worker
  }
  
  public func closed() -> Promise<None> {
    return Promise(reference: ReadableStreamReaderClosed(reference, worker.reference), worker: worker)
  }

  public func cancel() -> Promise<None> {
    return Promise(reference: ReadableStreamReaderCancel(reference, worker.reference), worker: worker)
  }
  
  public func read() -> Promise<None> {
    return Promise(reference: ReadableStreamReaderRead(reference, worker.reference), worker: worker)
  }

  public func releaseLock() {
    return ReadableStreamReaderReleaseLock(reference, worker.reference)
  }

}

public struct ReadableStream {

  public var isLocked: Bool {
    return ReadableStreamLocked(reference, worker.reference) != 0
  }

  public var reader: ReadableStreamReader {
    return ReadableStreamReader(reference: ReadableStreamGetReader(reference, worker.reference), worker: worker)
  }

  let worker: WebWorker
  let reference: ReadableStreamRef
  
  init(reference: ReadableStreamRef, worker: WebWorker) {
    self.reference = reference
    self.worker = worker
  }

  public func cancel() {
    ReadableStreamCancel(reference, worker.reference)
  }

  public func pipeThrough(transformStream: TransformStream) -> ReadableStream {
    return ReadableStream(reference: ReadableStreamPipeThrough(reference, worker.reference, transformStream.reference), worker: worker)
  }
  
  public func pipeTo(destination: String)-> Promise<None> {
    return destination.withCString {
      return Promise(reference: ReadableStreamPipeTo(reference, worker.reference, $0), worker: worker)
    }
  }
  
  public func tee() -> (ReadableStream, ReadableStream) {
    var a: ReadableStreamRef?
    var b: ReadableStreamRef?
    ReadableStreamTee(reference, worker.reference, &a, &b)
    return (ReadableStream(reference: a!, worker: worker), ReadableStream(reference: b!, worker: worker))
  }

  public func tee(_ branch1: inout ReadableStream,
                  _ branch2: inout ReadableStream) {
    var a: ReadableStreamRef?
    var b: ReadableStreamRef?
    ReadableStreamTee(reference, worker.reference, &a, &b)
  }

}