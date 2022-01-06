// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims
import Foundation

public class SerializedScriptValue {

  public var rawData: UnsafePointer<UInt8>? {
    return SerializedScriptValueGetData(reference)
  }

  public var dataLength: Int {
    return Int(SerializedScriptValueGetDataLength(reference))
  }

  public var data: Data? {
    if let raw = rawData {
      return Data(bytesNoCopy: UnsafeMutableRawPointer(mutating: raw), count: dataLength, deallocator: .none)
    }
    return nil
  }

  // FIXME support other values
  public var stringValue: String? {
    var len: CInt = 0
    if let wind = window {
      if let cstr = SerializedScriptValueGetString(reference, wind.reference, &len) {
        return String(bytesNoCopy: cstr, length: Int(len), encoding: String.Encoding.utf8, freeWhenDone: true)!
      }
    }
    if let wrk = worker {
      if let cstr = SerializedScriptValueGetStringForWorker(reference, wrk.reference, &len) {
        return String(bytesNoCopy: cstr, length: Int(len), encoding: String.Encoding.utf8, freeWhenDone: true)!
      }
    }
    if let s = scope {
      if let cstr = SerializedScriptValueGetStringForServiceWorker(reference, s.reference, &len) {
        return String(bytesNoCopy: cstr, length: Int(len), encoding: String.Encoding.utf8, freeWhenDone: true)!
      }
    }
    return nil
  }

  public var offscreenCanvas: OffscreenCanvas? {
    if let wind = window {
      if let ref = SerializedScriptValueGetOffscreenCanvas(reference, wind.reference) {
        return OffscreenCanvas(reference: ref, window: wind)
      }
    }
    if let wrk = worker {
      if let ref = SerializedScriptValueGetOffscreenCanvasForWorker(reference, wrk.reference) {
        return OffscreenCanvas(reference: ref, worker: wrk)
      }
    }
    if let s = scope {
      if let ref = SerializedScriptValueGetOffscreenCanvasForServiceWorker(reference, s.reference) {
        return OffscreenCanvas(reference: ref, scope: s)
      }
    }
    return nil
  }

  var ownedReference: OwnedSerializedScriptValueRef?
  let reference: SerializedScriptValueRef
  var window: WebWindow?
  var worker: WebWorker?
  var scope: ServiceWorkerGlobalScope?

  public init(
    window: WebWindow,
    string: String,
    ports: [MessagePort] = [],
    arrays: [ArrayBuffer] = [], 
    offscreenCanvases: [OffscreenCanvas] = [], 
    imageBitmaps: [ImageBitmap] = []) {
    
    var arraysPtr = ContiguousArray<DOMArrayBufferRef?>()
    var offscreenCanvasesPtr = ContiguousArray<OffscreenCanvasRef?>()
    var portsPtr = ContiguousArray<MessagePortRef?>()
    var imageBitmapsPtr = ContiguousArray<WebImageBitmapRef?>()

    for arr in arrays {
      arraysPtr.append(arr.reference)
    }

    for canvas in offscreenCanvases {
      offscreenCanvasesPtr.append(canvas.reference)
    }

    for port in ports {
      portsPtr.append(port.reference)
    }

    for image in imageBitmaps {
      imageBitmapsPtr.append(image.reference)
    }
    
    ownedReference = arraysPtr.withUnsafeBufferPointer { arr in
      return offscreenCanvasesPtr.withUnsafeBufferPointer { canvas in
          return portsPtr.withUnsafeBufferPointer { ports in 
            return imageBitmapsPtr.withUnsafeBufferPointer { images in 
              string.withCString { cstr in
                return SerializedScriptValueCreateString(window.reference, cstr, arr.baseAddress, CInt(arr.count), canvas.baseAddress, CInt(canvas.count), ports.baseAddress, CInt(ports.count), images.baseAddress, CInt(images.count))
              }
            }
          }
      }
    }
    reference = SerializedScriptValueFromOwned(ownedReference!)
    self.window = window
  }

  public init(
    worker: WebWorker,
    string: String,
    ports: [MessagePort] = [], 
    arrays: [ArrayBuffer] = [], 
    offscreenCanvases: [OffscreenCanvas] = [], 
    imageBitmaps: [ImageBitmap] = []) {
    
    var arraysPtr = ContiguousArray<DOMArrayBufferRef?>()
    var offscreenCanvasesPtr = ContiguousArray<OffscreenCanvasRef?>()
    var portsPtr = ContiguousArray<MessagePortRef?>()
    var imageBitmapsPtr = ContiguousArray<WebImageBitmapRef?>()

    for arr in arrays {
      arraysPtr.append(arr.reference)
    }

    for canvas in offscreenCanvases {
      offscreenCanvasesPtr.append(canvas.reference)
    }

    for port in ports {
      portsPtr.append(port.reference)
    }

    for image in imageBitmaps {
      imageBitmapsPtr.append(image.reference)
    }
    
    ownedReference = arraysPtr.withUnsafeBufferPointer { arr in
      return offscreenCanvasesPtr.withUnsafeBufferPointer { canvas in
          return portsPtr.withUnsafeBufferPointer { ports in 
            return imageBitmapsPtr.withUnsafeBufferPointer { images in 
              string.withCString { cstr in
                return SerializedScriptValueCreateStringForWorker(worker.reference, cstr, arr.baseAddress, CInt(arr.count), canvas.baseAddress, CInt(canvas.count), ports.baseAddress, CInt(ports.count), images.baseAddress, CInt(images.count))
              }
            }
          }
      }
    }
    reference = SerializedScriptValueFromOwned(ownedReference!)
    self.worker = worker
  }

  public init(
    scope: ServiceWorkerGlobalScope,
    string: String,
    ports: [MessagePort] = [], 
    arrays: [ArrayBuffer] = [], 
    offscreenCanvases: [OffscreenCanvas] = [], 
    imageBitmaps: [ImageBitmap] = []) {
    
    var arraysPtr = ContiguousArray<DOMArrayBufferRef?>()
    var offscreenCanvasesPtr = ContiguousArray<OffscreenCanvasRef?>()
    var portsPtr = ContiguousArray<MessagePortRef?>()
    var imageBitmapsPtr = ContiguousArray<WebImageBitmapRef?>()

    for arr in arrays {
      arraysPtr.append(arr.reference)
    }

    for canvas in offscreenCanvases {
      offscreenCanvasesPtr.append(canvas.reference)
    }

    for port in ports {
      portsPtr.append(port.reference)
    }

    for image in imageBitmaps {
      imageBitmapsPtr.append(image.reference)
    }
    
    ownedReference = arraysPtr.withUnsafeBufferPointer { arr in
      return offscreenCanvasesPtr.withUnsafeBufferPointer { canvas in
          return portsPtr.withUnsafeBufferPointer { ports in 
            return imageBitmapsPtr.withUnsafeBufferPointer { images in 
              string.withCString { cstr in
                return SerializedScriptValueCreateStringForServiceWorker(scope.reference, cstr, arr.baseAddress, CInt(arr.count), canvas.baseAddress, CInt(canvas.count), ports.baseAddress, CInt(ports.count), images.baseAddress, CInt(images.count))
              }
            }
          }
      }
    }
    reference = SerializedScriptValueFromOwned(ownedReference!)
    self.scope = scope
  }

  public init(
    window: WebWindow,
    blob: Blob,
    ports: [MessagePort] = [], 
    arrays: [ArrayBuffer] = [], 
    offscreenCanvases: [OffscreenCanvas] = [], 
    imageBitmaps: [ImageBitmap] = []) {
    var arraysPtr = ContiguousArray<DOMArrayBufferRef?>()
    var offscreenCanvasesPtr = ContiguousArray<OffscreenCanvasRef?>()
    var portsPtr = ContiguousArray<MessagePortRef?>()
    var imageBitmapsPtr = ContiguousArray<WebImageBitmapRef?>()

    for arr in arrays {
      arraysPtr.append(arr.reference)
    }

    for canvas in offscreenCanvases {
      offscreenCanvasesPtr.append(canvas.reference)
    }

    for port in ports {
      portsPtr.append(port.reference)
    }

    for image in imageBitmaps {
      imageBitmapsPtr.append(image.reference)
    }
    
    ownedReference = arraysPtr.withUnsafeBufferPointer { arr in
      return offscreenCanvasesPtr.withUnsafeBufferPointer { canvas in
          return portsPtr.withUnsafeBufferPointer { ports in 
            return imageBitmapsPtr.withUnsafeBufferPointer { images in 
              return SerializedScriptValueCreateBlob(window.reference, blob.reference, arr.baseAddress, CInt(arr.count), canvas.baseAddress, CInt(canvas.count), ports.baseAddress, CInt(ports.count), images.baseAddress, CInt(images.count))
            }
          }
      }
    }
    reference = SerializedScriptValueFromOwned(ownedReference!)
    self.window = window
  }

  public init(
    worker: WebWorker,
    blob: Blob,
    ports: [MessagePort] = [], 
    arrays: [ArrayBuffer] = [], 
    offscreenCanvases: [OffscreenCanvas] = [], 
    imageBitmaps: [ImageBitmap] = []) {
    var arraysPtr = ContiguousArray<DOMArrayBufferRef?>()
    var offscreenCanvasesPtr = ContiguousArray<OffscreenCanvasRef?>()
    var portsPtr = ContiguousArray<MessagePortRef?>()
    var imageBitmapsPtr = ContiguousArray<WebImageBitmapRef?>()

    for arr in arrays {
      arraysPtr.append(arr.reference)
    }

    for canvas in offscreenCanvases {
      offscreenCanvasesPtr.append(canvas.reference)
    }

    for port in ports {
      portsPtr.append(port.reference)
    }

    for image in imageBitmaps {
      imageBitmapsPtr.append(image.reference)
    }
    
    ownedReference = arraysPtr.withUnsafeBufferPointer { arr in
      return offscreenCanvasesPtr.withUnsafeBufferPointer { canvas in
          return portsPtr.withUnsafeBufferPointer { ports in 
            return imageBitmapsPtr.withUnsafeBufferPointer { images in 
              return SerializedScriptValueCreateBlobForWorker(worker.reference, blob.reference, arr.baseAddress, CInt(arr.count), canvas.baseAddress, CInt(canvas.count), ports.baseAddress, CInt(ports.count), images.baseAddress, CInt(images.count))
            }
          }
      }
    }
    reference = SerializedScriptValueFromOwned(ownedReference!)
    self.worker = worker
  }

  public init(
    window: WebWindow,
    array: ArrayBuffer,
    ports: [MessagePort] = [], 
    arrays: [ArrayBuffer] = [], 
    offscreenCanvases: [OffscreenCanvas] = [], 
    imageBitmaps: [ImageBitmap] = []) {

    var arraysPtr = ContiguousArray<DOMArrayBufferRef?>()
    var offscreenCanvasesPtr = ContiguousArray<OffscreenCanvasRef?>()
    var portsPtr = ContiguousArray<MessagePortRef?>()
    var imageBitmapsPtr = ContiguousArray<WebImageBitmapRef?>()

    for arr in arrays {
      arraysPtr.append(arr.reference)
    }

    for canvas in offscreenCanvases {
      offscreenCanvasesPtr.append(canvas.reference)
    }

    for port in ports {
      portsPtr.append(port.reference)
    }

    for image in imageBitmaps {
      imageBitmapsPtr.append(image.reference)
    }
    
    ownedReference = arraysPtr.withUnsafeBufferPointer { arr in
      return offscreenCanvasesPtr.withUnsafeBufferPointer { canvas in
          return portsPtr.withUnsafeBufferPointer { ports in 
            return imageBitmapsPtr.withUnsafeBufferPointer { images in 
              return SerializedScriptValueCreateArrayBuffer(window.reference, array.reference, arr.baseAddress, CInt(arr.count), canvas.baseAddress, CInt(canvas.count), ports.baseAddress, CInt(ports.count), images.baseAddress, CInt(images.count))
            }
          }
      }
    }
    reference = SerializedScriptValueFromOwned(ownedReference!)
    self.window = window
  }


  public init(
    worker: WebWorker,
    array: ArrayBuffer,
    ports: [MessagePort] = [], 
    arrays: [ArrayBuffer] = [], 
    offscreenCanvases: [OffscreenCanvas] = [], 
    imageBitmaps: [ImageBitmap] = []) {
    var arraysPtr = ContiguousArray<DOMArrayBufferRef?>()
    var offscreenCanvasesPtr = ContiguousArray<OffscreenCanvasRef?>()
    var portsPtr = ContiguousArray<MessagePortRef?>()
    var imageBitmapsPtr = ContiguousArray<WebImageBitmapRef?>()

    for arr in arrays {
      arraysPtr.append(arr.reference)
    }

    for canvas in offscreenCanvases {
      offscreenCanvasesPtr.append(canvas.reference)
    }

    for port in ports {
      portsPtr.append(port.reference)
    }

    for image in imageBitmaps {
      imageBitmapsPtr.append(image.reference)
    }
    
    ownedReference = arraysPtr.withUnsafeBufferPointer { arr in
      return offscreenCanvasesPtr.withUnsafeBufferPointer { canvas in
          return portsPtr.withUnsafeBufferPointer { ports in 
            return imageBitmapsPtr.withUnsafeBufferPointer { images in 
              return SerializedScriptValueCreateArrayBufferForWorker(worker.reference, array.reference, arr.baseAddress, CInt(arr.count), canvas.baseAddress, CInt(canvas.count), ports.baseAddress, CInt(ports.count), images.baseAddress, CInt(images.count))
            }
          }
      }
    }
    reference = SerializedScriptValueFromOwned(ownedReference!)
    self.worker = worker
  }

  public init(
    window: WebWindow,
    offscreenCanvas: OffscreenCanvas,
    ports: [MessagePort] = [], 
    arrays: [ArrayBuffer] = [], 
    offscreenCanvases: [OffscreenCanvas] = [], 
    imageBitmaps: [ImageBitmap] = []) {

    var arraysPtr = ContiguousArray<DOMArrayBufferRef?>()
    var offscreenCanvasesPtr = ContiguousArray<OffscreenCanvasRef?>()
    var portsPtr = ContiguousArray<MessagePortRef?>()
    var imageBitmapsPtr = ContiguousArray<WebImageBitmapRef?>()

    for arr in arrays {
      arraysPtr.append(arr.reference)
    }

    for canvas in offscreenCanvases {
      offscreenCanvasesPtr.append(canvas.reference)
    }

    for port in ports {
      portsPtr.append(port.reference)
    }

    for image in imageBitmaps {
      imageBitmapsPtr.append(image.reference)
    }
    
    ownedReference = arraysPtr.withUnsafeBufferPointer { arr in
      return offscreenCanvasesPtr.withUnsafeBufferPointer { canvas in
          return portsPtr.withUnsafeBufferPointer { ports in 
            return imageBitmapsPtr.withUnsafeBufferPointer { images in 
              return SerializedScriptValueCreateOffscreenCanvas(window.reference, offscreenCanvas.reference, arr.baseAddress, CInt(arr.count), canvas.baseAddress, CInt(canvas.count), ports.baseAddress, CInt(ports.count), images.baseAddress, CInt(images.count))
            }
          }
      }
    }
    reference = SerializedScriptValueFromOwned(ownedReference!)
    self.window = window
  }


  public init(
    worker: WebWorker,
    offscreenCanvas: OffscreenCanvas,
    ports: [MessagePort] = [], 
    arrays: [ArrayBuffer] = [], 
    offscreenCanvases: [OffscreenCanvas] = [], 
    imageBitmaps: [ImageBitmap] = []) {
    var arraysPtr = ContiguousArray<DOMArrayBufferRef?>()
    var offscreenCanvasesPtr = ContiguousArray<OffscreenCanvasRef?>()
    var portsPtr = ContiguousArray<MessagePortRef?>()
    var imageBitmapsPtr = ContiguousArray<WebImageBitmapRef?>()

    for arr in arrays {
      arraysPtr.append(arr.reference)
    }

    for canvas in offscreenCanvases {
      offscreenCanvasesPtr.append(canvas.reference)
    }

    for port in ports {
      portsPtr.append(port.reference)
    }

    for image in imageBitmaps {
      imageBitmapsPtr.append(image.reference)
    }
    
    ownedReference = arraysPtr.withUnsafeBufferPointer { arr in
      return offscreenCanvasesPtr.withUnsafeBufferPointer { canvas in
          return portsPtr.withUnsafeBufferPointer { ports in 
            return imageBitmapsPtr.withUnsafeBufferPointer { images in 
              return SerializedScriptValueCreateOffscreenCanvasForWorker(worker.reference, offscreenCanvas.reference, arr.baseAddress, CInt(arr.count), canvas.baseAddress, CInt(canvas.count), ports.baseAddress, CInt(ports.count), images.baseAddress, CInt(images.count))
            }
          }
      }
    }
    reference = SerializedScriptValueFromOwned(ownedReference!)
    self.worker = worker
  }

  public init(
    scope: ServiceWorkerGlobalScope,
    offscreenCanvas: OffscreenCanvas,
    ports: [MessagePort] = [], 
    arrays: [ArrayBuffer] = [], 
    offscreenCanvases: [OffscreenCanvas] = [], 
    imageBitmaps: [ImageBitmap] = []) {
    var arraysPtr = ContiguousArray<DOMArrayBufferRef?>()
    var offscreenCanvasesPtr = ContiguousArray<OffscreenCanvasRef?>()
    var portsPtr = ContiguousArray<MessagePortRef?>()
    var imageBitmapsPtr = ContiguousArray<WebImageBitmapRef?>()

    for arr in arrays {
      arraysPtr.append(arr.reference)
    }

    for canvas in offscreenCanvases {
      offscreenCanvasesPtr.append(canvas.reference)
    }

    for port in ports {
      portsPtr.append(port.reference)
    }

    for image in imageBitmaps {
      imageBitmapsPtr.append(image.reference)
    }
    
    ownedReference = arraysPtr.withUnsafeBufferPointer { arr in
      return offscreenCanvasesPtr.withUnsafeBufferPointer { canvas in
          return portsPtr.withUnsafeBufferPointer { ports in 
            return imageBitmapsPtr.withUnsafeBufferPointer { images in 
              return SerializedScriptValueCreateOffscreenCanvasForServiceWorker(scope.reference, offscreenCanvas.reference, arr.baseAddress, CInt(arr.count), canvas.baseAddress, CInt(canvas.count), ports.baseAddress, CInt(ports.count), images.baseAddress, CInt(images.count))
            }
          }
      }
    }
    reference = SerializedScriptValueFromOwned(ownedReference!)
    self.scope = scope
  }

  init(reference: SerializedScriptValueRef, window: WebWindow) {
    self.reference = reference
    self.window = window
  }

  init(reference: SerializedScriptValueRef, worker: WebWorker) {
    self.reference = reference
    self.worker = worker
  }

  init(reference: SerializedScriptValueRef, scope: ServiceWorkerGlobalScope) {
    self.reference = reference
    self.scope = scope
  }

  public init(owned: OwnedSerializedScriptValueRef, scope: ServiceWorkerGlobalScope) {
    self.ownedReference = owned
    self.scope = scope
    self.reference = SerializedScriptValueFromOwned(ownedReference!)
  }

  public init(owned: OwnedSerializedScriptValueRef, window: WebWindow) {
    self.ownedReference = owned
    self.window = window
    self.reference = SerializedScriptValueFromOwned(ownedReference!)
  }

  public init(owned: OwnedSerializedScriptValueRef, worker: WebWorker) {
    self.ownedReference = owned
    self.worker = worker
    self.reference = SerializedScriptValueFromOwned(ownedReference!)
  }

  deinit {
    if let owned = ownedReference {
      SerializedScriptValueDestroy(owned)
    }
  }

}