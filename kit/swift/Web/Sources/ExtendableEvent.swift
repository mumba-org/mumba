// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims
import Javascript

public typealias WaitUntilResolver = Promise<None>

public class ExtendableEvent {

  let reference: WebDOMEventRef
  let scope: ServiceWorkerGlobalScope

  init(reference: WebDOMEventRef, scope: ServiceWorkerGlobalScope) {
    self.reference = reference
    self.scope = scope
  }

  public func waitUntil(_ resolver: WaitUntilResolver) {
    ExtendableEventWaitUntil(reference, scope.reference, resolver.reference)
  }

}