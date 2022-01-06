// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims

//public typealias PreloadResponseCallback = () -> Void

public class FetchEvent {

  public var request: Request {
    return Request(reference: FetchEventGetRequest(reference), scope: scope)
  }

  public var clientId: String {
    var size: CInt = 0
    let buf = FetchEventGetClientId(reference, &size)
    return buf != nil ? String(bytesNoCopy: buf!, length: Int(size), encoding: String.Encoding.utf8, freeWhenDone: true)! : String()
  }

  public var isReload: Bool {
    return FetchEventIsReload(reference) != 0
  }

  let reference: WebDOMEventRef
  let scope: ServiceWorkerGlobalScope

  init(reference: WebDOMEventRef, scope: ServiceWorkerGlobalScope) {
    self.reference = reference
    self.scope = scope
  }

  public func respondWith(_ promise: Promise<None>) {
    FetchEventRespondWith(reference, scope.reference, promise.reference)
  }

  public func preloadResponse() -> Promise<None> {
    return Promise(reference: FetchEventPreloadResponse(reference, scope.reference), scope: scope)
  }

}