// Copyright (c) 2021 World. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Base
import Net
import Engine
import Collection
import Data
import Foundation
import Python
import WorldApi
import Route
import ProtocolBuffers
import SwiftGlibc

public class NewHandler : RouteHandler {
  
  public var entry: RouteEntry
  public var lastCallId: Int  = 0
  public var writeCompletion: WriteCompletion?
  public var writeRawCompletion: WriteRawCompletion?
  public var closeCompletion: CloseCompletion?

  private var _iconData: Data?
  private weak var context: WorldContext?
  private var outputString: String = String()

  public init(context: WorldContext) {
    entry = RouteEntry(
      type: .Entry, 
      transportType: .Ipc, 
      transportMode: .ServerStream, 
      scheme: "world", 
      name: "new", 
      title: "New", 
      contentType: "text/html")
    entry.iconData = loadIcon()
    self.context = context
  }

  public func getRawBodyBytes(url: String) -> Int64 {
    return 0
  }

  public func getExpectedContentSize(url: String) -> Int64 {
    return 0
  }

  public func getResponseHeaders(url: String) -> String { 
    return String()
  }

  public func onResponseStarted(request: RouteRequest, info: RouteResponseInfo, completion: RouteCompletion?) {
    print("NewHandler.onResponseStarted")
    completion!(0)
  }

  public func onReadCompleted(request: RouteRequest, info: RouteResponseInfo, buffer: RouteBuffer, bytesRead: UInt64) {
   print("NewHandler.onReadCompleted")
  }

  public func onSucceeded(request: RouteRequest, info: RouteResponseInfo) {
    print("NewHandler.onSucceeded: writting output")
    outputString = "<!DOCTYPE html>\n" +
          "<html>\n" +
          "<head>\n" +
          "<meta charset=\"utf-8\">\n" +
          "<title>New Page</title>\n" +
          "</head>\n<body>\n" +
          "<div id=\"new-app\">new app</div>\n" +
          "</body>"
    writeRaw(call: request.callId, string: outputString)
    close(call: request.callId, status: .ok, completion: nil)
  }

  public func onFailed(request: RouteRequest, info: RouteResponseInfo, error: RouteRequestError) {
    print("NewHandler.onFailed")
  }

  public func onCanceled(request: RouteRequest, info: RouteResponseInfo) {
    print("NewHandler.onCanceled")
  }

  public func read(request: RouteRequest, buffer: UnsafeMutableRawPointer?, maxBytes: Int, completion: RouteCompletion) {

  }

  private func loadIcon() -> Data {
    let len = 3136
    let buf = malloc(len)
    var fd: Int32 = -1
    fd = open("/home/fabiok/pages/savory/assets/apple-icon-180x180.png", O_RDONLY)
    assert(fd != -1)
    let readed = SwiftGlibc.read(fd, buf, len)
    SwiftGlibc.close(fd)
    return Data(bytesNoCopy: buf!, count: readed, deallocator: .free)
  }

}

public class DevToolsHandler : RouteHandler {

  public var entry: RouteEntry
  public var lastCallId: Int  = 0
  public var writeCompletion: WriteCompletion?
  public var writeRawCompletion: WriteRawCompletion?
  public var closeCompletion: CloseCompletion?

  private var _iconData: Data?
  private weak var context: WorldContext?
  private var outputString: String = String()
  private let python: PythonInterface

  public init(context: WorldContext) {
    entry = RouteEntry(
      type: .Entry, 
      transportType: .Ipc, 
      transportMode: .ServerStream, 
      scheme: "world", 
      name: "devtools", 
      title: "DevTools", 
      contentType: "text/html")
    self.context = context
    var environment = PythonEnvironment()
    environment.libraryPath = "/workspace/source/Python-3.8.5/Lib"
    python = PythonInterface(environment: environment)
    entry.iconData = loadIcon()
  }

  public func getRawBodyBytes(url: String) -> Int64 {
    return 0
  }

  public func getExpectedContentSize(url: String) -> Int64 {
    return 0
  }

  public func getResponseHeaders(url: String) -> String { 
    return String()
  }

  public func onResponseStarted(request: RouteRequest, info: RouteResponseInfo, completion: RouteCompletion?) {
    print("NewHandler.onResponseStarted")
  }

  public func onReadCompleted(request: RouteRequest, info: RouteResponseInfo, buffer: RouteBuffer, bytesRead: UInt64) {
   print("NewHandler.onReadCompleted")
  }

  public func onSucceeded(request: RouteRequest, info: RouteResponseInfo) {
    print("DevToolsHandler.onSucceeded: writting output")

    let np = python.import("numpy")
    let x = np.array([10, 20, 30])
    let y = np.array([10, 20, 30])
    var z = x + y
    z = np.maximum(z, 0.0)

    outputString = "<!DOCTYPE html>\n" +
          "<html>\n" +
          "<head>\n" +
          "<meta charset=\"utf-8\">\n" +
          "<title>DevTools Page</title>\n" +
          "</head>\n<body>\n" +
          "<div id=\"new-app\">z = \(z)</div>\n" +
          "<div id=\"new-app\">new app2</div>\n" +
          "<div id=\"new-app\">new app3</div>\n" +
          "<div id=\"new-app\">new app4</div>\n" +
          "<div id=\"new-app\">new app5<br>new app5<br>new app5<br>new app5<br>new app5<br>new app5<br>new app5<br></div>\n" +
          "<div id=\"new-app\">new app5<br>new app5<br>new app5<br>new app5<br>new app5<br>new app5<br>new app5<br></div>\n" +
          "<div id=\"new-app\">new app5<br>new app5<br>new app5<br>new app5<br>new app5<br>new app5<br>new app5<br></div>\n" +
          "<div id=\"new-app\">new app5<br>new app5<br>new app5<br>new app5<br>new app5<br>new app5<br>new app5<br></div>\n" +
          "<div id=\"new-app\">new app5<br>new app5<br>new app5<br>new app5<br>new app5<br>new app5<br>new app5<br></div>\n" +
          "<div id=\"new-app\">new app5<br>new app5<br>new app5<br>new app5<br>new app5<br>new app5<br>new app5<br></div>\n" +
          "<div id=\"new-app\">new app5<br>new app5<br>new app5<br>new app5<br>new app5<br>new app5<br>new app5<br></div>\n" +
          "</body>"
    writeRaw(call: request.callId, string: outputString)
    close(call: request.callId, status: .ok, completion: nil)
  }

  public func onFailed(request: RouteRequest, info: RouteResponseInfo, error: RouteRequestError) {
    print("NewHandler.onFailed")
  }

  public func onCanceled(request: RouteRequest, info: RouteResponseInfo) {
    print("NewHandler.onCanceled")
  }

  public func read(request: RouteRequest, buffer: UnsafeMutableRawPointer?, maxBytes: Int, completion: RouteCompletion) {}

  private func loadIcon() -> Data {
    let len = 3136
    let buf = malloc(len)
    var fd: Int32 = -1
    fd = open("/home/fabiok/pages/savory/assets/apple-icon-180x180.png", O_RDONLY)
    assert(fd != -1)
    let readed = SwiftGlibc.read(fd, buf, len)
    SwiftGlibc.close(fd)
    return Data(bytesNoCopy: buf!, count: readed, deallocator: .free)
  }

}

public class MainHandler : RouteHandler {
  
  public var entry: RouteEntry
  private var page: Filebase?
  private weak var context: WorldContext?
  public var lastCallId: Int  = 0
  public var writeCompletion: WriteCompletion?
  public var writeRawCompletion: WriteRawCompletion?
  public var closeCompletion: CloseCompletion?

  public init(context: WorldContext) {
    self.context = context
    entry = RouteEntry(
      type: .Entry,
      transportType: .Ipc, 
      transportMode: .Unary, 
      scheme: "world", 
      name: "main", 
      title: "Any Title", 
      contentType: "text/html")
    entry.iconData = loadIcon()
  }

  public func onResponseStarted(request: RouteRequest, info: RouteResponseInfo, completion: RouteCompletion?) {
    guard let complete = completion else {
      return
    } 
    if page == nil {
      context!.storage.openFilebase("page", { [self, completion] (status, filebase) in
        if status == 0 {
          self.page = filebase
          completion!(0)
        } else {
          completion!(-2)
        }
      })
    } else {
      completion!(0)
    }
  }

  public func onReadCompleted(request: RouteRequest, info: RouteResponseInfo, buffer: RouteBuffer, bytesRead: UInt64) {
   print("MainHandler.onReadCompleted")
  }

  public func getRawBodyBytes(url: String) -> Int64 {
    print("MainHandler.getRawBodyBytes: url: \(url)")
    return 3072
  }

  public func getExpectedContentSize(url: String) -> Int64 {
    print("MainHandler.getExpectedContentSize: url: \(url)")
    return 3072
  }

  public func getResponseHeaders(url: String) -> String { 
    // fixed for now
    print("MainHandler.getResponseHeaders: url: \(url)")
    return String("HTTP 1.1 200 OK\n\nContent-Length: 3072\n Content-Type: \(self.contentType); charset=UTF-8")
  }

  public func read(request: RouteRequest, buffer: UnsafeMutableRawPointer?, maxBytes: Int, completion: RouteCompletion) {
    print("MainHandler.read: \(request.url)")
    var isMain = false
    if let offset = request.url.lastIndex(of: ":") {
      var path = String(request.url[request.url.index(offset, offsetBy: 3)..<request.url.endIndex])
      print(path)
      if path == "main/" || path == "main" {
        isMain = true
      }
    }
    if isMain {
      print("MainHandler.read: isMain = true => opening index.html")
      onFileAvailableRead(file: "index.html", request: request, buffer: buffer, maxBytes: maxBytes, completion: completion)
    } else {
      print("MainHandler.read: isMain = false => reading asset")
      processAsset(request: request, buffer: buffer, maxBytes: maxBytes, completion: completion)
    }
  }

  private func processAsset(request: RouteRequest, buffer: UnsafeMutableRawPointer?, maxBytes: Int, completion: RouteCompletion) {
    var assetPath = String(request.url[request.url.index(request.url.firstIndex(of: "/")!, offsetBy: 2)..<request.url.endIndex])
    assetPath = String(assetPath[assetPath.index(assetPath.firstIndex(of: "/")!, offsetBy: 1)..<assetPath.endIndex])
    onFileAvailableRead(file: assetPath, request: request, buffer: buffer, maxBytes: maxBytes, completion: completion)
  }

  private func onFileAvailableRead(file: String, request: RouteRequest, buffer: UnsafeMutableRawPointer?, maxBytes: Int, completion: RouteCompletion) {
    openFile(file: file, request: request, buffer: buffer, maxBytes: maxBytes, completion: completion)
  }

  private func openFile(file: String, request: RouteRequest, buffer: UnsafeMutableRawPointer?, maxBytes: Int, completion: RouteCompletion) {
    guard let files = page else {
      print("MainHandler.onResponseStarted: \(request.callId) - \(request.url) => site is not here. really bad")
      completion(-2)
      return
    }
    files.readAll(from: file, {[self] (fstatus, mmap) in  
      if fstatus == 0 {
        guard let mappedFile = mmap else {
          print("\n'/hello' => reading \(file) error: failed to mmap file")
          completion(-2)
          return
        }
        readMappedFile(mappedFile, request: request, buffer: buffer, maxBytes: maxBytes, completion: completion)           
      } else {
        print("\n'/hello' => reading \(file) error: readAll failed => \(fstatus)")
        completion(-2)
      }
    })
  }

  private func readMappedFile(_ file: SharedMemory, request: RouteRequest, buffer: UnsafeMutableRawPointer?, maxBytes: Int, completion: RouteCompletion) {
    file.map({ (buf, size) in
      if request.readSize == 0 {
        request.readSize = size
      }
      let amount = size - request.readOffset
      let wr = amount > maxBytes ? maxBytes : amount
      let readbuf = buf! + request.readOffset
      memcpy(buffer!, readbuf, wr)
      request.readOffset += wr
      completion(wr)
    })
  }

  // FIXME: this should go away now with read() converge RPC handler + IPC handler
  public func onSucceeded(request: RouteRequest, info: RouteResponseInfo) {}
  public func onFailed(request: RouteRequest, info: RouteResponseInfo, error: RouteRequestError) {}
  public func onCanceled(request: RouteRequest, info: RouteResponseInfo) {}
  private func loadIcon() -> Data {
    let len = 3136
    let buf = malloc(len)
    var fd: Int32 = -1
    /// FIXME: ugly and hackish.. now that we have the bundle.. its easiar to use it
    fd = open("/home/fabiok/pages/savory/assets/apple-icon-180x180.png", O_RDONLY)
    assert(fd != -1)
    let readed = SwiftGlibc.read(fd, buf, len)
    SwiftGlibc.close(fd)
    return Data(bytesNoCopy: buf!, count: readed, deallocator: .free)
  }
}