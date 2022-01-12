// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Base
import Net
import Engine
import Data
import Foundation
import Python
import TweedyApi
import ProtocolBuffers
import SwiftGlibc
import Route

public class HelloHandler : RouteHandler {
  
  public var entry: RouteEntry
  public var lastCallId: Int  = 0
  public var writeCompletion: WriteCompletion?
  public var writeRawCompletion: WriteRawCompletion?
  public var closeCompletion: CloseCompletion?

  private var urlRequest: UrlRequest?
  private var readBuffer: UrlBuffer?
  private var executor: UrlExecutor
  private var engine: UrlEngine
  private var readData: Data?
  private var assetData: Data?
  private var _iconData: Data?
  private var bytesRead: Int64 = 0
  private weak var context: TweedyContext?
  private var site: Filebase?
  private var outputString: String = String()
  //private var queryString: String = String()
  //private var files: [Int: [String: SharedMemory]] = [[:]]
 
  public init(context: TweedyContext) {
    entry = RouteEntry(
      type: .Entry, 
      transportType: .Ipc, 
      transportMode: .Unary, 
      scheme: "tweedy", 
      name: "hello", 
      title: "Hello Darkness My Old Friend", 
      contentType: "text/html")
    self.context = context
    var engineParams = UrlEngineParams()
    engineParams.storagePath = "/home/fabiok/.cache/mumba/tweedy"
    engine = UrlEngine(engineParams)
    executor = UrlExecutor()
    entry.iconData = loadIcon()
    //rpcClient = AnyServiceClient(channel: rpcChannel)
  }
  
  public func getRawBodyBytes(url: String) -> Int64 {
    print("HelloHandler.getRawBodyBytes: url: \(url)")
    return 3072
  }

  public func getExpectedContentSize(url: String) -> Int64 {
    print("HelloHandler.getExpectedContentSize: url: \(url)")
    return 3072
  }

  public func getResponseHeaders(url: String) -> String { 
    // fixed for now
    print("HelloHandler.getResponseHeaders: url: \(url)")
    return String("HTTP 1.1 200 OK\n\nContent-Length: 3072\n Content-Type: \(self.contentType); charset=UTF-8")
  }

  public func onResponseStarted(request: RouteRequest, info: RouteResponseInfo, completion: RouteCompletion?) {
    guard let complete = completion else {
      print("HelloHandler.onResponseStarted: null completion. exiting..")
      return
    } 
    if site == nil {
      context!.storage.openFilebase("site", { [self, completion] (status, filebase) in
        if status == 0 {
          self.site = filebase
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
   
  }

  public func onSucceeded(request: RouteRequest, info: RouteResponseInfo) {
    //print("HelloHandler.onSucceeded")
    var queryString = String()
    if let queryStart = request.url.lastIndex(of: "?") {
      // FIXME: hackish and dangerous
      queryString = String(request.url[request.url.index(queryStart, offsetBy: 1)..<request.url.endIndex])
    }
    if !queryString.isEmpty {
      switch queryString {
        case "path=1":
          var params = UrlRequestParams()
          params.httpMethod = "GET"
          let url = "https://news.ycombinator.com"
          urlRequest = UrlRequest(engine: engine, executor: executor, handler: self, url: url, params: params)
          urlRequest!.start()
        case "path=2":
          //print("\n'/hello' route => path=2 opening site..")
          context!.storage.openFilebase("site", { [self] (status, filebase) in
            if status == 0 {
              site = filebase
              filebase!.readAll(from: "index.html", {[self] (status, mem) in  
                if status == 0 {
                  if let m = mem {
                    m.map({ (buf, size) in
                      //let lastByte = buf! + size
                      //lastByte.pointee = 0
                      // format entry
                      //let data = Data(bytes: buf!, count: size)
                      let data = Data(bytesNoCopy: buf!, count: size, deallocator: .none)
                      writeRaw(call: request.callId, data: data)
                      close(call: request.callId, status: .ok, completion: nil)
                    })                      
                  } else {
                    let helloString = "error reading file 'site/index.html': NO DATA"
                    writeRaw(call: request.callId, string: helloString)
                    close(call: request.callId, status: .ok, completion: nil)
                  }
                } else {
                  let helloString = "error reading file 'site/index.html': FAILED"
                  writeRaw(call: request.callId, string: helloString)
                  close(call: request.callId, status: .ok, completion: nil)
                }
                //filebase!.close({print("closing filebase returned \($0)")})
              })
            } else {
              let helloString = "error opening filebase 'site': FAILED"
              writeRaw(call: request.callId, string: helloString)
              close(call: request.callId, status: .ok, completion: nil)
            }
          })
        case "path=3":
          outputString = "<!DOCTYPE html>\n" +
            "<html>\n" +
            "<head>\n" +
            "<style type=\"text/css\">\n" +
            "  body, canvas { padding: 0; margin: 0; background-color: #221eff; }\n" +
            " .checkerboxed { background-image: paint(checkerboard); }\n" +
            "</style>\n" +
            "<meta charset=\"utf-8\">\n" +
            "<title>Tapenade Recipe</title>\n" +
            "</head>\n<body>\n" +
            "<div id=\"available-button\">Checar Disponibilidade</div>\n" +
          // "<div id=\"gl-div\"><canvas id=\"gl-canvas\" width=\"300\" height=\"200\"></canvas></div>" +
            "<div id=\"canvas-div\" width=\"1900\" height=\"1000\"><canvas id=\"my-canvas\" width=\"1900\" height=\"1000\"></canvas></div>\n" +
            //"<div id=\"text-div\" class=\"checkerboxed\" width=\"300\" height=\"200\">" +
            //"<p>hello green div</p><p>how are you?</p><p>im fine, you?</p><p>im fine, too</p></div>\n</body>" +
            "</body>"
          writeRaw(call: request.callId, string: outputString)
          close(call: request.callId, status: .ok, completion: nil)
        case "path=4":
          writeRaw(call: request.callId, string: "rpc call done")
          close(call: request.callId, status: .ok, completion: nil)
        default:
          writeRaw(call: request.callId, string: "whatever")
          close(call: request.callId, status: .ok, completion: nil)
      }
    } else {
      guard let assets = site else {
        writeRaw(call: request.callId, string: "sorry")
        close(call: request.callId, status: .ok, completion: nil)
        return
      }
      var assetPath = String(request.url[request.url.index(request.url.firstIndex(of: "/")!, offsetBy: 2)..<request.url.endIndex])
      assetPath = String(assetPath[assetPath.index(assetPath.firstIndex(of: "/")!, offsetBy: 1)..<assetPath.endIndex])
    
      assets.readAll(from: "\(assetPath)", {[self] (status, mem) in  
        if status == 0 {
          if let m = mem {
            m.map({ (buf, size) in
              assetData = Data(bytesNoCopy: buf!, count: size, deallocator: .none)
              writeRaw(call: request.callId, data: assetData!)
            })                      
          } else {
            let helloString = "error reading file '\(assetPath)': NO DATA"
            writeRaw(call: request.callId, string: helloString)
            close(call: request.callId, status: .ok, completion: nil)
          }
        } else {
          let helloString = "error reading file '\(assetPath)': FAILED"
          writeRaw(call: request.callId, string: helloString)
          close(call: request.callId, status: .ok, completion: nil)
        }
      })
    }
  }

  public func onFailed(request: RouteRequest, info: RouteResponseInfo, error: RouteRequestError) {
    
  }

  public func onCanceled(request: RouteRequest, info: RouteResponseInfo) {
    
  }

  public func read(request: RouteRequest, buffer: UnsafeMutableRawPointer?, maxBytes: Int, completion: RouteCompletion) {
    var queryString = String()
    if let queryStart = request.url.lastIndex(of: "?") {
      // FIXME: hackish and dangerous
      queryString = String(request.url[request.url.index(queryStart, offsetBy: 1)..<request.url.endIndex])
    }
    if !queryString.isEmpty {
      switch queryString {
        case "path=1":  
          processPathOne(request: request, buffer: buffer, maxBytes: maxBytes, completion: completion)
        case "path=2":
          processPathTwo(request: request, buffer: buffer, maxBytes: maxBytes, completion: completion)
        case "path=3":
          processPathThree(request: request, buffer: buffer, maxBytes: maxBytes, completion: completion)
        case "path=4":
          processPathFour(request: request, buffer: buffer, maxBytes: maxBytes, completion: completion)
        default:
          processPathFour(request: request, buffer: buffer, maxBytes: maxBytes, completion: completion)
      }
    } else {
      processAsset(request: request, buffer: buffer, maxBytes: maxBytes, completion: completion)
    }
  }

  private func onFileAvailableRead(file: String, request: RouteRequest, buffer: UnsafeMutableRawPointer?, maxBytes: Int, completion: RouteCompletion) {
    // if let mappedFiles = files[request.callId] {
    //   if let buf = mappedFiles[file] {
    //     print("file \(file) already open. just mapping")
    //     readMappedFile(buf, request: request, buffer: buffer, maxBytes: maxBytes, completion: completion)           
    //   } else {
    //     openFile(file: file, request: request, buffer: buffer, maxBytes: maxBytes, completion: completion)
    //   }
    // } else {
    //   openFile(file: file, request: request, buffer: buffer, maxBytes: maxBytes, completion: completion)
    // }
    openFile(file: file, request: request, buffer: buffer, maxBytes: maxBytes, completion: completion)
  }

  private func openFile(file: String, request: RouteRequest, buffer: UnsafeMutableRawPointer?, maxBytes: Int, completion: RouteCompletion) {
    guard let files = site else {
      print("HelloHandler.onResponseStarted: \(request.callId) - \(request.url) => site is not here. really bad")
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
        //files[request.callId][file] = mappedFile
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

  private func processPathOne(request: RouteRequest, buffer: UnsafeMutableRawPointer?, maxBytes: Int, completion: RouteCompletion) {
    var params = UrlRequestParams()
    params.httpMethod = "GET"
    let url = "https://news.ycombinator.com"
    urlRequest = UrlRequest(engine: engine, executor: executor, handler: self, url: url, params: params)
    urlRequest!.start()
    // fixme: pass the completion over to the http success (or failure) completion
    completion(-1)
  }

  private func processPathTwo(request: RouteRequest, buffer: UnsafeMutableRawPointer?, maxBytes: Int, completion: RouteCompletion) {
    onFileAvailableRead(file: "index.html", request: request, buffer: buffer, maxBytes: maxBytes, completion: completion)
  }

  private func processPathThree(request: RouteRequest, buffer: UnsafeMutableRawPointer?, maxBytes: Int, completion: RouteCompletion) {
    if bytesRead == 0 {
      outputString = "<!DOCTYPE html>\n" +
        "<html>\n" +
        "<head>\n" +
        "<style type=\"text/css\">\n" +
        "  body, canvas { padding: 0; margin: 0; background-color: #dfddcf; }\n" +
        " .checkerboxed { background-image: paint(checkerboard); }\n" +
        "</style>\n" +
        "<meta charset=\"utf-8\">\n" +
        "<title>Tapenade Recipe</title>\n" +
        "</head>\n<body>\n" +
        "<div id=\"available-button\">Checar Disponibilidade</div>\n" +
      // "<div id=\"gl-div\"><canvas id=\"gl-canvas\" width=\"300\" height=\"200\"></canvas></div>" +
        "<div id=\"canvas-div\" width=\"1900\" height=\"1000\"><canvas id=\"my-canvas\" width=\"1900\" height=\"1000\"></canvas></div>\n" +
        "<div id=\"text-div\" class=\"checkerboxed\" width=\"300\" height=\"200\">" +
        "<p>hello green div</p><p>how are you?</p><p>im fine, you?</p><p>im fine, too</p></div>\n</body>\n" +
        "</html>" 
        //"</body>"
      outputString.withCString {
        memcpy(buffer!, $0, outputString.count)
      }
      bytesRead = Int64(outputString.count)
      completion(outputString.count)
    } else {
      bytesRead = 0
      completion(0)
    }
  }

  private func processPathFour(request: RouteRequest, buffer: UnsafeMutableRawPointer?, maxBytes: Int, completion: RouteCompletion) {
    let outputString = "rpc call done"
    outputString.withCString {
      memcpy(buffer!, $0, outputString.count)
    }
    completion(outputString.count)
  }

  private func processAsset(request: RouteRequest, buffer: UnsafeMutableRawPointer?, maxBytes: Int, completion: RouteCompletion) {
    var assetPath = String(request.url[request.url.index(request.url.firstIndex(of: "/")!, offsetBy: 2)..<request.url.endIndex])
    assetPath = String(assetPath[assetPath.index(assetPath.firstIndex(of: "/")!, offsetBy: 1)..<assetPath.endIndex])
    onFileAvailableRead(file: assetPath, request: request, buffer: buffer, maxBytes: maxBytes, completion: completion)
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

extension HelloHandler : UrlRequestHandler {

  public func onRedirectReceived(request: UrlRequest, info: UrlResponseInfo, locationUrl: String) {
    print("HelloHandler.onRedirectReceived\n url: \(info.url)\n status code: \(info.httpStatusCode)\n status text: \(info.httpStatusText)\n bytes: \(info.byteCount)\n new location: \(locationUrl)")
    let r = request.followRedirect()
    print("request.followRedirect() => \(r)")
  }

  public func onResponseStarted(request: UrlRequest, info: UrlResponseInfo) {
    print("HelloHandler.onResponseStarted\n url: \(info.url)\n status code: \(info.httpStatusCode)\n status text: \(info.httpStatusText)\n bytes: \(info.byteCount)\n wasCached: \(info.wasCached)\n headers: \(info.headers.count)\n")
    readData = nil
    bytesRead = 0
    //if readBuffer == nil {
    readBuffer = UrlBuffer(size: 32 * 1024)
    readData = Data()
    //}
    let r = request.read(buffer: readBuffer!)
    print("request.read() => \(r)")
  }

  public func onReadCompleted(request: UrlRequest, info: UrlResponseInfo, buffer: UrlBuffer, bytesRead: UInt64) {
    print("HelloHandler.onReadCompleted\n bytes: \(bytesRead)")
    //if readData == nil {
    //  readData = Data(bytes: buffer.data!, count: Int(bytesRead))
    //} else {
    readData!.append(buffer.rawData!.bindMemory(to: UInt8.self, capacity: Int(bytesRead)), count: Int(bytesRead))
    //}
    self.bytesRead += Int64(bytesRead)
    let r = request.read(buffer: readBuffer!)
    print("request.read() => \(r)")
  }

  public func onSucceeded(request: UrlRequest, info: UrlResponseInfo) {
    print("HelloHandler.onSucceeded\n status code: \(info.httpStatusCode)\n status text: \(info.httpStatusText)\n bytes: \(info.byteCount)\n wasCached: \(info.wasCached)\n")
    //readBuffer = nil
    urlRequest = nil
    //readData = nil
    writeRaw(data: readData!)
    close(status: .ok, completion: nil)
  }

  public func onFailed(request: UrlRequest, info: UrlResponseInfo, error: UrlRequestError) {
    print("HelloHandler.onFailed")
    //readBuffer = nil
    urlRequest = nil
    //readData = nil
    writeRaw(string: "failed request")
  }

  public func onCanceled(request: UrlRequest, info: UrlResponseInfo) {
    print("HelloHandler.onCanceled")
    //readBuffer = nil
    urlRequest = nil
    ///readData = nil
    writeRaw(string: "canceled request") 
  }

}

public struct GreetingsHandler : RouteHandler {

  public var entry: RouteEntry
  public var lastCallId: Int  = 0
  public var writeCompletion: WriteCompletion?
  public var writeRawCompletion: WriteRawCompletion?
  public var closeCompletion: CloseCompletion?
  private var bytesRead = 0
  private var outputString = "<!DOCTYPE html>\n" +
        "<html>\n" +
        "<head>\n" +
        "<style type=\"text/css\">\n" +
        "  body, canvas { padding: 0; margin: 0; background-color: #dfddcf; }\n" +
        " .checkerboxed { background-image: paint(checkerboard); }\n" +
        "</style>\n" +
        "<meta charset=\"utf-8\">\n" +
        "<title>Tapenade Recipe</title>\n" +
        "</head>\n<body>\n" +
        "<div id=\"available-button\">Checar Disponibilidade</div>\n" +
        "<div id=\"text-div\" class=\"checkerboxed\" width=\"300\" height=\"200\">" +
        "hello div" +
        "</div>\n" +
        "<div id=\"text-div\" class=\"checkerboxed\" width=\"300\" height=\"200\">" +
        "how are you?" +
        "</div>\n" +
        "<div id=\"text-div\" class=\"checkerboxed\" width=\"300\" height=\"200\">" +
        "im fine, you?" +
        "</div>\n" +
        "<div id=\"text-div\" class=\"checkerboxed\" width=\"300\" height=\"200\">" +
        "im fine, too" +
        "</div>\n" +
        "</body>\n" +
        "</html>" 

  public init() {
    entry = RouteEntry(
      type: .Entry, 
      transportType: .Ipc, 
      transportMode: .ServerStream, 
      scheme: "tweedy", 
      name: "greetings", 
      title: "Greetings", 
      contentType: "text/html")
  }

  public func getRawBodyBytes(url: String) -> Int64 {
    return Int64(outputString.count)
  }

  public func getExpectedContentSize(url: String) -> Int64 {
    return Int64(outputString.count)
  }

  public func getResponseHeaders(url: String) -> String { 
    return String("HTTP 1.1 200 OK\n\nContent-Length: \(outputString.count)\n Content-Type: \(self.contentType); charset=UTF-8")
  }

  public func onResponseStarted(request: RouteRequest, info: RouteResponseInfo, completion: RouteCompletion?) {
    completion!(0)
  }

  public func onReadCompleted(request: RouteRequest, info: RouteResponseInfo, buffer: RouteBuffer, bytesRead: UInt64) {
    print("Greetings.onReadCompleted")
  }

  public func onSucceeded(request: RouteRequest, info: RouteResponseInfo) {
    print("Greetings.onSucceeded")
  }

  public func onFailed(request: RouteRequest, info: RouteResponseInfo, error: RouteRequestError) {
    
  }

  public func onCanceled(request: RouteRequest, info: RouteResponseInfo) {
    print("Greetings.onCanceled")
  }

  public mutating func read(request: RouteRequest, buffer: UnsafeMutableRawPointer?, maxBytes: Int, completion: RouteCompletion) {
    if bytesRead == 0 {
      outputString.withCString {
        memcpy(buffer!, $0, outputString.count)
      }
      bytesRead = outputString.count
      completion(outputString.count)
    } else {
      bytesRead = 0
      completion(0)
    }
  }

}

public struct ResourcesHandler : RouteHandler {

  public var entry: RouteEntry
  public var lastCallId: Int  = 0
  public var writeCompletion: WriteCompletion?
  public var writeRawCompletion: WriteRawCompletion?
  public var closeCompletion: CloseCompletion?

  public init() {
   entry = RouteEntry(
      type: .Entry, 
      transportType: .Ipc, 
      transportMode: .ServerStream, 
      scheme: "tweedy", 
      name: "resources", 
      title: "Resources", 
      contentType: "text/html")
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
    
  }

  public func onReadCompleted(request: RouteRequest, info: RouteResponseInfo, buffer: RouteBuffer, bytesRead: UInt64) {
    
  }

  public func onSucceeded(request: RouteRequest, info: RouteResponseInfo) {
    
  }

  public func onFailed(request: RouteRequest, info: RouteResponseInfo, error: RouteRequestError) {
    
  }

  public func onCanceled(request: RouteRequest, info: RouteResponseInfo) {
    
  }

  public func read(request: RouteRequest, buffer: UnsafeMutableRawPointer?, maxBytes: Int, completion: RouteCompletion) {
    completion(-2)
  }
}

public struct PythonHandler : RouteHandler {

  public var entry: RouteEntry
  public var lastCallId: Int  = 0
  public var writeCompletion: WriteCompletion?
  public var writeRawCompletion: WriteRawCompletion?
  public var closeCompletion: CloseCompletion?
  private let python: PythonInterface

  public init() {
    print("PythonHandler.init")
    entry = RouteEntry(
      type: .Entry, 
      transportType: .Ipc, 
      transportMode: .ServerStream, 
      scheme: "tweedy", 
      name: "python", 
      title: "Python", 
      contentType: "text/html")
    var environment = PythonEnvironment()
    environment.libraryPath = "/workspace/source/Python-3.8.5/Lib"
    python = PythonInterface(environment: environment)
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
    print("PythonHandler.onResponseStarted: making call")
  }

  public func onReadCompleted(request: RouteRequest, info: RouteResponseInfo, buffer: RouteBuffer, bytesRead: UInt64) {
    print("PythonHandler.onReadCompleted: making call")
  }

  public mutating func onSucceeded(request: RouteRequest, info: RouteResponseInfo) {
    print("PythonHandler.onSucceeded: making call")
    let np = python.import("numpy")
    let x = np.array([10, 20, 30])
    let y = np.array([10, 20, 30])
    var z = x + y
    z = np.maximum(z, 0.0)
    // let messageBuilder = Tweedy.ChatMessage.Builder()
    // messageBuilder.message = "hello world"
    // let message = try! messageBuilder.build()

    // let rpcCall: UnaryCall<Tweedy.ChatMessage, Tweedy.ChatMessage> = rpcClient.makeUnaryCall(
    //   path: "/tweedy.Tweedy/Say",
    //   request: message)

    let outputString = "<!DOCTYPE html>\n" +
          "<html>\n" +
          "<head>\n" +
          "<style type=\"text/css\">\n" +
          "  body, canvas { padding: 0; margin: 0; }\n" +
          "</style>\n" +
          "<meta charset=\"utf-8\">\n" +
          "<title>Tapenade Recipe</title>\n" +
          "</head>\n<body>\n" +
          "<div id=\"gl-div\"><canvas id=\"gl-canvas\" width=\"800\" height=\"600\"></canvas></div>\n" +
          "z = \(z)\n" +
          "</body>\n"
    writeRaw(call: request.callId, string: outputString)
    close(call: request.callId, status: .ok, completion: nil)
  }

  public func onFailed(request: RouteRequest, info: RouteResponseInfo, error: RouteRequestError) {
    
  }

  public func onCanceled(request: RouteRequest, info: RouteResponseInfo) {
    
  }

  public func read(request: RouteRequest, buffer: UnsafeMutableRawPointer?, maxBytes: Int, completion: RouteCompletion) {
    completion(-2)
  }

}

// public struct SayHandler : RouteHandler {

//   public var rpcTransportMode: RouteRpcTransportMode { return RouteRpcTransportMode.BidirectionalStream }
//   public var scheme: String { return "tweedy" }
//   public var title: String { return "Say Something" }
//   public var contentType: String { return "text/html" }

//   public var writeCompletion: WriteCompletion?

//   public static func factory() -> RouteHandler {
//     return SayHandler()
//   }
  
//   public init() {
    
//   }

//   public func onResponseStarted(request: RouteRequest, info: RouteResponseInfo, _ completion: @escaping WriteCompletion) {
    
//   }

//   public func onReadCompleted(request: RouteRequest, info: RouteResponseInfo, buffer: RouteBuffer, bytesRead: UInt64) {
    
//   }

//   public func onSucceeded(request: RouteRequest, info: RouteResponseInfo) {
    
//   }

//   public func onFailed(request: RouteRequest, info: RouteResponseInfo, error: RouteRequestError) {
    
//   }

//   public func onCanceled(request: RouteRequest, info: RouteResponseInfo) {
    
//   }

// }