// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims
import Javascript

public class ExtendableMessageEvent {

  public var serializedData: SerializedScriptValue? {
    if let ref = ExtendableMessageEventGetSerializedData(reference) {
      if let w = window {
        return SerializedScriptValue(reference: ref, window: w)
      }
      if let s = scope {
        return SerializedScriptValue(reference: ref, scope: s)
      }
    }
    return nil
  }

  public var stringData: String? {
    var len: CInt = 0
    if let str = ExtendableMessageEventGetDataString(reference, window!.reference, &len) {
      return String(bytesNoCopy: str, length: Int(len), encoding: String.Encoding.utf8, freeWhenDone: true)!
    }
    return nil
  }


  public var offscreenCanvas: OffscreenCanvas? {
    if let data = serializedData {
      return data.offscreenCanvas
    }
    return nil
  }

  public var ports: [MessagePort] {
    // if !portsBinded {
    //   var portCount: CInt = 0
    //   var portRefs: UnsafeMutablePointer<MessagePortRef?>
    //   ExtendableMessageEventGetPorts(reference, &portRefs, &portCount)
    //   for i in 0..<Int(portCount) {
    //     _ports.append(MessagePort(reference: portRefs[i]!))
    //   }
    //   portsBinded = true
    //   if portCount > 0 {
    //     free(portRefs)
    //   }
    // }
    return _ports
  }

  var reference: WebDOMEventRef
  var window: WebWindow?
  var scope: ServiceWorkerGlobalScope?
  var _ports: [MessagePort] = []
  var portsBinded: Bool = false

  init(reference: WebDOMEventRef, window: WebWindow) {
    self.reference = reference
    self.window = window
  }

  //init(reference: WebDOMEventRef) { self.reference = reference}

  init(reference: WebDOMEventRef, scope: ServiceWorkerGlobalScope, ports: [MessagePort] = []) {
    self.reference = reference
    self._ports = ports
    self.scope = scope
    portsBinded = true
  }

}