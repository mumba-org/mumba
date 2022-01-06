// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims

public enum MessageEventDataType : Int {
  case scriptValue = 0
  case serializedScriptValue = 1
  case string = 2
  case blob = 3
  case arrayBuffer = 4
}

public class MessageEvent {

  public var dataType: MessageEventDataType {
    return MessageEventDataType(rawValue: Int(MessageEventGetDataType(reference)))!
  }

  public var dataAsString: String? {
    var len: CInt = 0
    let type = dataType
    if type == .string {
      if let cstr = MessageEventGetDataAsString(reference, &len) {
        return String(bytesNoCopy: cstr, length: Int(len), encoding: String.Encoding.utf8, freeWhenDone: true)!
      }
      return nil
    } else if type == .serializedScriptValue {
      if let data = dataAsSerializedScriptValue {
        return data.stringValue
      }
      return nil
    }
    return nil
  }

  public var dataAsOffscreenCanvas: OffscreenCanvas? {
    var len: CInt = 0
    let type = dataType

    guard type == .serializedScriptValue else {
      print("MessageEvent.dataAsOffscreenCanvas: type != .serializedScriptValue. returning nil")
      return nil
    }
    if let data = dataAsSerializedScriptValue {
      return data.offscreenCanvas
    }
    return nil
  }

  public var dataAsSerializedScriptValue: SerializedScriptValue? {
    if let windowRef = window {
      if let ref = MessageEventGetDataAsSerializedScriptValue(reference)  {
        return SerializedScriptValue(reference: ref, window: windowRef)
      }
    }
    if let workerRef = worker {
      if let ref = MessageEventGetDataAsSerializedScriptValue(reference)  {
        return SerializedScriptValue(reference: ref, worker: workerRef)
      }
    }
    print("MessageEvent.dataAsSerializedScriptValue: returning nil")
    return nil
  }

  public var dataAsBlob: Blob? {
    if let ref = MessageEventGetDataAsBlob(reference) {
      return Blob(reference: ref)
    }
    return nil
  }

  public var dataAsArrayBuffer: ArrayBuffer? {
    if let ref = MessageEventGetDataAsArrayBuffer(reference) {
      return ArrayBuffer(reference: ref)
    }
    return nil
  }

  public var ports: [MessagePort]
  public var bitmaps: [ImageBitmap]

  let reference: WebDOMEventRef
  var window: WebWindow?
  var worker: WebWorker?

  init(reference: WebDOMEventRef, window: WebWindow, ports: [MessagePort] = [], bitmaps: [ImageBitmap] = []) {
    self.reference = reference
    self.window = window
    self.ports = ports
    self.bitmaps = bitmaps
  }

  init(reference: WebDOMEventRef, worker: WebWorker, ports: [MessagePort] = [], bitmaps: [ImageBitmap] = []) {
    self.reference = reference
    self.worker = worker
    self.ports = ports
    self.bitmaps = bitmaps
  }

  // FIXME: this should be temporary to support service workers
  init(reference: WebDOMEventRef, ports: [MessagePort] = [], bitmaps: [ImageBitmap] = []) {
    self.reference = reference
    self.ports = ports
    self.bitmaps = bitmaps
  }

}