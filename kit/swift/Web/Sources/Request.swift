// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims

public struct Request {

  public var arrayBuffer: Promise<ArrayBuffer> {
    if let w = worker {
      let ref = RequestGetArrayBuffer(reference, w.reference)
      return Promise(reference: ref!, worker: w)
    }
    let ref = RequestGetArrayBufferFromServiceWorker(reference, scope!.reference)
    return Promise(reference: ref!, scope: scope!)
  }

  public var blob: Promise<Blob> {
    if let w = worker {
      let ref = RequestGetBlob(reference, w.reference)
      return Promise(reference: ref!, worker: w)
    }
    let ref = RequestGetBlobFromServiceWorker(reference, scope!.reference)
    return Promise(reference: ref!, scope: scope!)
  }

  public var formData: Promise<FormData> {
    if let w = worker {
      let ref = RequestGetFormData(reference, w.reference)
      return Promise(reference: ref!, worker: w)
    }
    let ref = RequestGetFormDataFromServiceWorker(reference, scope!.reference)
    return Promise(reference: ref!, scope: scope!)
  }

  public var json: Promise<String> {
    if let w = worker {
      let ref = RequestGetJson(reference, w.reference)
      return Promise(reference: ref!, worker: w)
    }
    let ref = RequestGetJsonFromServiceWorker(reference, scope!.reference)
    return Promise(reference: ref!, scope: scope!)
  }

  public var text: Promise<String> {
    if let w = worker {
      let ref = RequestGetText(reference, w.reference)
      return Promise(reference: ref!, worker: w)
    }
    let ref = RequestGetTextFromServiceWorker(reference, scope!.reference)
    return Promise(reference: ref!, scope: scope!)
  }

  public var body: ReadableStream {
    // FIXME: it will break for service workers
    return ReadableStream(reference: RequestGetReadableBodyStream(reference)!, worker: worker!)
  }

  //public var bodyBuffer: BodyStreamBuffer {}

  public var hasBody: Bool {
    return RequestHasBody(reference) != 0
  }

  public var method: String {
    var len: CInt = 0
    if let str = RequestGetMethod(reference, &len) {
      return String(bytesNoCopy: str, length: Int(len), encoding: String.Encoding.utf8, freeWhenDone: true)!
    }
    return String()
  }
  
  public var url: String {
    var len: CInt = 0
    if let str = RequestGetUrl(reference, &len) {
      return String(bytesNoCopy: str, length: Int(len), encoding: String.Encoding.utf8, freeWhenDone: true)!
    }
    return String()
  }
  
  public var headers: Headers {
    return Headers(reference: RequestGetHeaders(reference))
  }
  
  public var destination: String {
    var len: CInt = 0
    if let str = RequestGetDestination(reference, &len) {
      return String(bytesNoCopy: str, length: Int(len), encoding: String.Encoding.utf8, freeWhenDone: true)!
    }
    return String()
  }
  
  public var referrer: String {
    var len: CInt = 0
    if let str = RequestGetReferrer(reference, &len) {
      return String(bytesNoCopy: str, length: Int(len), encoding: String.Encoding.utf8, freeWhenDone: true)!
    }
    return String()
  }
  
  public var referrerPolicy: String {
    var len: CInt = 0
    if let str = RequestGetReferrerPolicy(reference, &len) {
      return String(bytesNoCopy: str, length: Int(len), encoding: String.Encoding.utf8, freeWhenDone: true)!
    }
    return String()
  }
  
  public var mode: String {
    var len: CInt = 0
    if let str = RequestGetMode(reference, &len) {
      return String(bytesNoCopy: str, length: Int(len), encoding: String.Encoding.utf8, freeWhenDone: true)!
    }
    return String()
  }
  
  public var credentials: String {
    var len: CInt = 0
    if let str = RequestGetCredentials(reference, &len) {
      return String(bytesNoCopy: str, length: Int(len), encoding: String.Encoding.utf8, freeWhenDone: true)!
    }
    return String()
  }
  
  public var cache: String {
    var len: CInt = 0
    if let str = RequestGetCache(reference, &len) {
      return String(bytesNoCopy: str, length: Int(len), encoding: String.Encoding.utf8, freeWhenDone: true)!
    }
    return String()
  }
  
  public var redirect: String {
    var len: CInt = 0
    if let str = RequestGetRedirect(reference, &len) {
      return String(bytesNoCopy: str, length: Int(len), encoding: String.Encoding.utf8, freeWhenDone: true)!
    }
    return String()
  }
  
  public var integrity: String {
    var len: CInt = 0
    if let str = RequestGetIntegrity(reference, &len) {
      return String(bytesNoCopy: str, length: Int(len), encoding: String.Encoding.utf8, freeWhenDone: true)!
    }
    return String()
  }
  
  public var keepalive: Bool {
    return RequestKeepalive(reference) != 0
  }

  public var isHistoryNavigation: Bool {
    return RequestIsHistoryNavigation(reference) != 0
  }

  let reference: RequestRef
  var scope: ServiceWorkerGlobalScope?
  var worker: WebWorker?
  
  init(reference: RequestRef, worker: WebWorker) {
    self.reference = reference
    self.worker = worker
  }

  init(reference: RequestRef, scope: ServiceWorkerGlobalScope) {
    self.reference = reference
    self.scope = scope
  }

 
}