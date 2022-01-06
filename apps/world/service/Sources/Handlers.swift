// Copyright (c) 2021 World. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Base
import Net
import Engine
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