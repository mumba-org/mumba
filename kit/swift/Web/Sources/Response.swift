// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims

public struct Response {

  public var arrayBuffer: Promise<ArrayBuffer> {
    // fixme: worker or window
    return Promise(reference: ResponseGetArrayBuffer(reference, worker!.reference), worker: worker!)
  }

  public var blob: Promise<Blob> {
    // fixme: worker or window
    return Promise(reference: ResponseGetBlob(reference, worker!.reference), worker: worker!)
  }

  public var formData: Promise<FormData> {
    // fixme: worker or window
    return Promise(reference: ResponseGetFormData(reference, worker!.reference), worker: worker!)
  }

  public var json: Promise<String> {
    // fixme: worker or window
    return Promise(reference: ResponseGetJson(reference, worker!.reference), worker: worker!)
  }

  public var text: Promise<String> {
    // fixme: worker or window
    return Promise(reference: ResponseGetText(reference, worker!.reference), worker: worker!)
  }

  public var body: ReadableStream {
    // fixme: worker or window
    return ReadableStream(reference: ResponseGetBody(reference), worker: worker!)
  }

  public var contentType: String {
    var len: CInt = 0
    if let str = ResponseGetContentType(reference, &len) {
      return String(bytesNoCopy: str, length: Int(len), encoding: String.Encoding.utf8, freeWhenDone: true)!
    }
    return String()
  }

  public var mimeType: String {
    var len: CInt = 0
    if let str = ResponseGetMimeType(reference, &len) {
      return String(bytesNoCopy: str, length: Int(len), encoding: String.Encoding.utf8, freeWhenDone: true)!
    }
    return String()
  }

  public var isOk: Bool {
    return ResponseGetOk(reference) != 0
  }

  public var statusText: String {
    var len: CInt = 0
    if let str = ResponseGetStatusText(reference, &len) {
      return String(bytesNoCopy: str, length: Int(len), encoding: String.Encoding.utf8, freeWhenDone: true)!
    }
    return String()
  }

  public var headers: Headers {
    return Headers(reference: ResponseGetHeaders(reference))
  }

  public var hasBody: Bool {
    return ResponseHasBody(reference) != 0
  }

  public var type: String {
    var len: CInt = 0
    if let str = ResponseGetType(reference, &len) {
      return String(bytesNoCopy: str, length: Int(len), encoding: String.Encoding.utf8, freeWhenDone: true)!
    }
    return String()
  }

  public var url: String {
    var len: CInt = 0
    if let str = ResponseGetUrl(reference, &len) {
      return String(bytesNoCopy: str, length: Int(len), encoding: String.Encoding.utf8, freeWhenDone: true)!
    }
    return String()
  }

  public var redirected: Bool {
    return ResponseRedirected(reference) != 0
  }

  public var status: UInt16 {
    return ResponseGetStatus(reference)
  }
  
  let reference: ResponseRef
  var worker: WebWorker?
  var window: WebWindow?
  var workerGlobalScope: ServiceWorkerGlobalScope?
  
  init(reference: ResponseRef, worker: WebWorker) {
    self.reference = reference
    self.worker = worker
  }
 
  init(reference: ResponseRef, window: WebWindow) {
    self.reference = reference
    self.window = window
  }

  init(reference: ResponseRef, workerGlobalScope: ServiceWorkerGlobalScope) {
    self.reference = reference
    self.workerGlobalScope = workerGlobalScope
  }

}