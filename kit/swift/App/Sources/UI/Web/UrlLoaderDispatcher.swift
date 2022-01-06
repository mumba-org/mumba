// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Foundation
import Base
import Web
import MumbaShims

public struct UrlOutputStream {

  public var buffer: UnsafeMutablePointer<Int8>?
  public var size: Int = 0
  public var allocatedSize: Int = 0
  public var sealed: Bool = false
 
  public init() {}

  public mutating func writeOnce(string: String) -> Int {
    guard !sealed else {
      return -1
    }
    allocatedSize = string.count + 1
    buffer = malloc(allocatedSize).bindMemory(to: Int8.self, capacity: allocatedSize)
    string.withCString {
      memcpy(buffer!, $0, Int(string.count))
    }
    buffer![string.count] = 0
    self.size = string.count
    sealed = true
    return self.size
  }

  public mutating func writeOnce(data: Data) -> Int {
    guard !sealed else {
      return -1
    }
    allocatedSize = data.count
    buffer = malloc(allocatedSize).bindMemory(to: Int8.self, capacity: allocatedSize)
    data.withUnsafeBytes {
      memcpy(buffer!, $0, Int(data.count))
    }
    //buffer![Int(data.count)] = 0

    self.size = data.count
    sealed = true
    return self.size
  }

  public mutating func allocate(_ size: Int) -> Bool {
    if allocatedSize > 0 || sealed {
      return false
    }
    allocatedSize = size
    buffer = malloc(allocatedSize).bindMemory(to: Int8.self, capacity: allocatedSize)
    return true
  }

  // should always pre-allocate first when using this raw buffer version
  public mutating func write(raw: UnsafeRawPointer?, offset: Int, size: Int) -> Int {
    if allocatedSize == 0 || sealed || (self.size + size) > allocatedSize {
      return -1
    }

    let bufferOffset = buffer! + offset
    memcpy(bufferOffset, raw!, size)

    self.size += size
    return size
  }

  public mutating func writeOnce(raw: UnsafeRawPointer?, size: Int) -> Int {
    let _ = allocate(size)
    let wrote = write(raw: raw, offset: 0, size: size)
    seal()
    return wrote
  }

  public mutating func seal() {
    guard !sealed else {
      return
    }
    //buffer![Int(size)] = 0
    sealed = true
  }

}

public protocol UrlLoaderClient : class {
  func shouldHandleResponse(response: WebURLResponse) -> Bool
  func didSendData(bytesSent: Int, totalBytesToBeSent: Int)
  func didReceiveData(input: UnsafeMutableRawPointer, bytesReaded: Int) -> Int
  func writeOutput(output: inout UrlOutputStream) -> Bool
  func didFinishLoading(errorCode: Int, totalTransferSize: Int)
}

public class UrlLoaderDispatcher : WebResponseHandler {

  public var name: String {
    return "url-loader-handler"
  }

 // private var done: Bool = false
  private var handlers: [UrlLoaderClient] = []
  private var currentHandler: UrlLoaderClient?
  private var url: String = String()
  private var finishErrorCode: Int = 0
  private var finishTotalTransferSize: Int = 0
  private var bufferOffset: Int = 0
  private var outputStream: UrlOutputStream
  
  public var unmanagedSelf: UnsafeMutableRawPointer? {
     unsafeBitCast(Unmanaged.passUnretained(self).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
  }

  public init() {
    outputStream = UrlOutputStream()
  }

  public func addHandler(_ handler: UrlLoaderClient) {
    handlers.append(handler)
  }

  public func removeHandler(_ handler: UrlLoaderClient) {
    for (index, current) in handlers.enumerated() {
      if handler === current {
        handlers.remove(at: index)
        return
      }
    }
  }
     
  public func createCallbacks() -> CResponseHandler {
    var callbacks = CResponseHandler()
    memset(&callbacks, 0, MemoryLayout<CResponseHandler>.stride)

    // const char* (*GetName)(void* state);
    callbacks.GetName = { (handle: UnsafeMutableRawPointer?) -> UnsafePointer<Int8>? in
      let this = unsafeBitCast(handle, to: UrlLoaderDispatcher.self)
      return this.name.withCString {
        // its ok to hand this over, because the name wont change
        // so theres no inner buffer/heap change
        // and the lifetime of the callbacks struct is bound to this object
        return $0
      }
    }

    // int (*WillHandleResponse)(void* state, WebURLResponseRef web_url_response);
    callbacks.WillHandleResponse = { (handle: UnsafeMutableRawPointer?, response: UnsafeMutableRawPointer?) -> CInt in
      let this = unsafeBitCast(handle, to: UrlLoaderDispatcher.self)
      return this.willHandleResponse(response: WebURLResponse(reference: response!)) ? 1 : 0
    }

    // int (*OnDataAvailable)(void* state, const char* input, int input_len)
    callbacks.OnDataAvailable = { (handle: UnsafeMutableRawPointer?, input: UnsafePointer<Int8>?, inputLen: CInt) -> CInt in
      let this = unsafeBitCast(handle, to: UrlLoaderDispatcher.self)
      return CInt(this.onDataAvailable(input: input, inputSize: Int(inputLen)))
    }

    // int (*OnFinishLoading)(void* state, int error_code, int total_transfer_size)
    callbacks.OnFinishLoading = { (handle: UnsafeMutableRawPointer?, errorCode: CInt, totalTransferSize: CInt) -> CInt in
      let this = unsafeBitCast(handle, to: UrlLoaderDispatcher.self)
      return CInt(this.onFinishLoading(errorCode: Int(errorCode), totalTransferSize: Int(totalTransferSize)))
    }
    
    // void (*GetResult)(void* state, char** output, int* output_len)
    callbacks.GetResult = { (handle: UnsafeMutableRawPointer?, output: UnsafeMutablePointer<UnsafeMutablePointer<Int8>?>?, outputLen: UnsafeMutablePointer<CInt>?) in
      let this = unsafeBitCast(handle, to: UrlLoaderDispatcher.self)
      this.writeResult(output: output, outputSize: outputLen)
    }
      
    return callbacks
  }

  public func willHandleResponse(response: WebURLResponse) -> Bool {
    for elem in handlers {
      if elem.shouldHandleResponse(response: response) {
        currentHandler = elem
        return true
      }
    }
    
    return false
  }
  
  public func onDataAvailable(input: UnsafePointer<Int8>?, inputSize: Int) -> Int {
    let r = currentHandler!.didReceiveData(input: UnsafeMutableRawPointer(mutating: input!), bytesReaded: inputSize)
    //if r == 0 {
    //  done = true
   // }
    return r
  }

  public func onFinishLoading(errorCode: Int, totalTransferSize: Int) -> Int {
    //defer {
      // get it back to false, so this can be reused
    //  done = false
    //}
    finishErrorCode = errorCode
    finishTotalTransferSize = totalTransferSize
    //let wasDone = done
    // protobuf decoder is not streaming so if it was not done
    // return an err_failed
    // if let h = currentHandler {
    //   h.didFinishLoading(errorCode: errorCode, totalTransferSize: totalTransferSize)
    // }
    //reset()
    //return wasDone ? -1 : -2
    currentHandler!.didFinishLoading(errorCode: errorCode, totalTransferSize: totalTransferSize)
    
    return 0
  }

  public func writeResult(
    output: UnsafeMutablePointer<UnsafeMutablePointer<Int8>?>?, 
    outputSize: UnsafeMutablePointer<CInt>?) {
    //print("UrlLoaderDispatcher.writeResult: passing data to decoder. size = \(inputData!.count)")  
    
    if currentHandler!.writeOutput(output: &outputStream) {
      output!.pointee = outputStream.buffer
      outputSize!.pointee = CInt(outputStream.size)
    }
    
    reset()
  }

  private func reset() {
    outputStream = UrlOutputStream()
  }

}