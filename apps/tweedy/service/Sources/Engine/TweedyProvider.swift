// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import TweedyApi
import Foundation
import Base
import Net
import Engine
import Channel
import Data
import SwiftGlibc
import Route
import Service
import Graphics
import Web
import Python
import PDF

public class HelloWorker : WebWorkerNative {

  public weak var worker: WebWorker? {
    return context?.worker
  }
  
  private var context: WebWorkerContext?
  private var initialized: Bool = false
  private var port: MessagePort?
  private var times: Int = 0
  private var promise: Promise<String>?
  
  public init() {}
  
  public func onInit(context: WebWorkerContext) {
    //print("HelloWorker initialized")
    self.context = context
    initialized = true
  }

  public func onMessage(event: MessageEvent) {
    if event.ports.count > 0 {
      port = MessagePort(owning: event.ports[0], worker: worker!)
    }
    //   if let message = event.dataAsString {
    //     port!.postMessage(string: "received '\(message)' \(times) times")
    //     times += 1
    //     worker!.fetch(url: "sw.js", { response in
    //       self.promise = response.text
    //       self.promise!.then({ text in
    //         print(" url: \(response.url)\n status: \(response.status)\n contentType: \(response.contentType)\n content size: \(text.count)\n content:\n\(text)")        
    //         self.promise = nil
    //       }, {
    //         print(" rejected ")
    //         self.promise = nil
    //       })
    //     })
    //   } 
    // }
  }

}

public class ServiceWorkerClient : ServiceWorkerContextClientDelegate, ChannelClient, PDFDocumentDelegate {
  
  var globalScope: ServiceWorkerGlobalScope?
  private var initialized: Bool = false
  private var port: MessagePort?
  private var counter: Int = 0
  private var wasmData: Data?
  private var offscreenCanvas: OffscreenCanvas?
  internal var context2d: OffscreenCanvasRenderingContext2d?
  private var gl: WebGLRenderingContext!
  private let paintFlags: PaintFlags
  private var lastColor: String
  private var lastColorIndex = 0
  private var times: Int = 0
  private var x: Int = 0
  private var y: Int = 0
  private let pngCodec: PNGCodec
  private var lenaImage: ImageSkia?
  //private var imageBitmap: Bitmap?
  private var imageBitmap: PDFBitmap?
  private var lenaImageBitmap: ImageBitmap?
  private var lenaBuffer: UnsafeMutablePointer<UInt8>?
  private var lenaBufferSize: Int = 0
  private var document: PDFDocument?
  private var canvas: Canvas?
  private var page: PDFPage?
  internal var pageIndex: Int
  private var channelHost: ChannelClient?
  private weak var context: TweedyContext?
  //private let python: PythonInterface

  let colors: [String] = [
    "yellow",
    "blue",
    "green",
    "red",
    "gray",
    "magenta"
  ]

  public init(context: TweedyContext) {
    paintFlags = PaintFlags()
    lastColor = colors[lastColorIndex]
    pngCodec = PNGCodec()
    PDFRuntime.initialize()
    self.context = context
    pageIndex = 45
  }

  deinit {
    PDFRuntime.shutdown()
  }
  
  public func onInit(global: ServiceWorkerGlobalScope) {
    guard !initialized else {
      //print("calling ServiceWorkerClient.onInit from the same ServiceWorkerClient instance twice!")
      return
    }
    
    globalScope = global

    global.onInstall { [self] ev in
      //print("ServiceWorkerClient: install done")
      self.globalScope!.skipWaiting()
    }

    global.onActivate { [weak self] ev in
      //print("ServiceWorkerClient: activate done")
      //print("ServiceWorkerClient: activate done => self.clients.claim()")
      let clients = self!.globalScope!.clients
      ev.waitUntil(clients.claim())
      // self!.globalScope!.fetch(url: "tweedy://hello?path=3", { r in
      //   print("ServiceWorkerClient: fetch response is here")
      //   r.text.then({ t in
      //     print(t)
      //   },
      //   {
      //     print("getting request text failed")
      //   })
      // })
    }
    global.onFetch { ev in
      print("ServiceWorkerClient: on fetch => clientId: \(ev.clientId)")
    }

    context!.channelRegistry.connectToChannel(delegate: self, scope: global, scheme: "tweedy", name: "navigator", onChannelConnect)

    if lenaBuffer == nil {
      lenaBuffer = loadPdf(size: &lenaBufferSize)
      document = PDFDocument.load(bytes: lenaBuffer!, lenght: lenaBufferSize, delegate: self)
      //document = PDFDocument.load(path: "/home/fabiok/Downloads/Probability_and_statistics_for_data_science_math_R_data.pdf", delegate: self)
      // imageBitmap = pngCodec.decode(lenaBuffer, size: lenaBufferSize)
    }
    loadPage(self.pageIndex)
    initialized = true
  }

  public func loadPage(_ number: Int) {
    //if number != pageIndex || page == nil {
      page = document!.loadPage(index: number)
      imageBitmap = page!.copyToBitmap()!
      //imageBitmap = pdfBmp.copy()
      //lenaImage = ImageSkia(bitmap: imageBitmap!)
    //}
    //if lenaImageBitmap == nil {
      //lenaImageBitmap = ImageBitmap(image: lenaImage!)  
    //}
    pageIndex = number
  }
  
  public func onMessage(message: SerializedScriptValue) {
    if let str = message.stringValue {
       print("Service: channel => '\(str)'")
    }
  }

  public func postMessage(_ string: String) {
    channelHost!.postMessage(string)
  }

  public func onPageLoaded(index: Int, page: PDFPage) { }//print("page \(index) loaded") }
  public func onPageAdded(index: Int, page: PDFPage, size: IntSize) { print("page \(index) added") }
  public func onPageRemoved(index: Int) { print("page \(index) removed")}

  public func onMessage(event: ExtendableMessageEvent) {
    if event.ports.count > 0 {
      if let scope = globalScope {
        port = MessagePort(owning: event.ports[0], globalScope: scope)
      }
    }
    print("message received: '" + event.stringData! + "'")
    /** client **/
    // let clients = globalScope!.clients
    // clients.get(uuid: "xispito", { client in
    //   if let c = client {
    //     c.postMessage(string: "the meaning of life is 43", ports: [])
    //   }
    // })
    /** post message **/
    // if let p = port {
    //   counter += 1
    //   let context = globalScope!.javascriptContext
    //   if wasmData == nil {
    //     var size = 0
    //     let bytes = loadWasm("/home/fabiok/hello.wasm", size: &size)!
    //     wasmData = Data(bytes: bytes, count: size)
    //   }
    //   let meaning = context.executeWasm(data: wasmData!, function: "meaning_of_life")
    //   p.postMessage(string: "the meaning of life is: \(meaning)")
    // }
    
    // ofscreen canvas

    // if offscreenCanvas == nil {
    //   if let offscreen = event.offscreenCanvas {
    //     offscreenCanvas = offscreen
    //     context2d = offscreenCanvas!.context2d
    //     canvas = Canvas(canvas: context2d!, imageScale: 1.0)
    //     //gl = offscreenCanvas!.glContext
    //     render()
    //     // canvas!.commit { [self]
    //     //   print("HelloWorker: canvas.commit() returned")
    //     //   //self.render(canvas: self.canvas!)
    //     // }
    //     // canvas!.commit { [self]
    //     //   print("HelloWorker.onMessage: canvas.commit() succeeded")
    //     //   self.render(canvas: self.canvas!)
    //     // }
    //     // print("HelloWorker.onMessage: drawing rect..")
    //     // canvas!.clearRect(IntRect(x: 0, y: 0, width: offscreen.width, height: offscreen.height))
    //     // paintFlags.color = Color.Red    
    //     // canvas!.drawRect(rect: FloatRect(x: 0, y: 0, width: Float(offscreen.width), height: Float(offscreen.height)), flags: paintFlags)
    //     // //canvas!.restore()
    //     //worker!.requestAnimationFrame { [self] time in
    //     //  print("HelloWorker.onMessage: worker.requestAnimationFrame callback called")
    //     //  self.render(canvas: self.canvas!)
    //     //}
    //     //canvas!.commit {
    //     //  print("HelloWorker.onMessage: canvas.commit() succeeded")
    //   // }
    //   }
    // } else if context2d != nil {
    //   pageIndex += 1
    //   loadPage(self.pageIndex)
    //   render()
    //   //print("ServiceWorkerClient.onMessage: no offscreen canvas received")
    // }
  }

  func onChannelConnect(_ client: ChannelClient?) {
    if client != nil {
      channelHost = client!
    } else {
      print("failed the connection to channel 'tweedy:navigator'")
    }
  }

  // public func render() {
  //   context!.clearRect(IntRect(x: 0, y: 0, width: offscreenCanvas!.width, height: offscreenCanvas!.height))
  //   if times % 20 == 0 {
  //     lastColorIndex += 1
  //     lastColor = colors[lastColorIndex]
  //     if lastColorIndex == 5 {
  //       lastColorIndex = 0
  //     }
  //   }
  //   context!.fillStyle = lastColor
  //   let rect = IntRect(x: x, y: y / 2, width: (offscreenCanvas!.width / 4) , height: (offscreenCanvas!.height / 4))
  //   context!.fillRect(rect)
  //   x += 4
  //   if x > offscreenCanvas!.width {
  //     x = 0
  //   }
  //   context!.commit { [self]
  //     self.render()    
  //   }
  //   times += 1
  //   // worker!.requestAnimationFrame { [weak self] time in
  //   //   self!.render()
  //   // }
  //   //   print("HelloWorker.render: worker.requestAnimationFrame callback called")
  //   // canvas.commit {
  //   //  print("HelloWorker.render: second canvas.commit() succeeded")
  //   // }
  //   //}
  // }

  // public func render() {
  //   context!.clearRect(IntRect(x: 0, y: 0, width: offscreenCanvas!.width, height: offscreenCanvas!.height))
  //   if times % 20 == 0 {
  //     lastColorIndex += 1
  //     lastColor = colors[lastColorIndex]
  //     if lastColorIndex == 5 {
  //       lastColorIndex = 0
  //     }
  //   }
  //   context!.beginPath()
  //   context!.moveTo(x: 75 + Float(x), y: 50)
  //   context!.lineTo(x: 100 + Float(x), y: 75)
  //   context!.lineTo(x: 100 + Float(x), y: 25)
  //   context!.fill(winding: nil)
  //   x += 4
  //   if x > offscreenCanvas!.width {
  //     x = 0
  //   }
  //   context!.commit { [self]
  //     self.render()    
  //   }
  //   times += 1
  //   // worker!.requestAnimationFrame { [weak self] time in
  //   //   self!.render()
  //   // }
  //   //   print("HelloWorker.render: worker.requestAnimationFrame callback called")
  //   // canvas.commit {
  //   //  print("HelloWorker.render: second canvas.commit() succeeded")
  //   // }
  //   //}
  // }

  public func render() {
    // image
    //context2d!.drawImage(lenaImageBitmap!, x: 0, y: 0)
    //context2d!.drawImage(lenaImage!, left: 0, top: 0)
    imageBitmap?.withBitmap { bmp in
      context2d!.clearRect(IntRect(x: 0, y: 0, width: offscreenCanvas!.width, height: offscreenCanvas!.height))
      //canvas!.drawBitmap(bitmap: bmp, x: 0, y: 0)
      context2d!.drawBitmap(bmp, left: 0, top: 0)
      //context2d!.drawImage(lenaImage!, left: 0, top: 0)
      context2d!.commit {}
    }

    // drawing
    // if let ctx = context2d {
    //   ctx.fillStyle = "#FD0"
    //   ctx.fillRect(0, 0, 75, 75)
    //   ctx.fillStyle = "#6C0"
    //   ctx.fillRect(75, 0, 75, 75)
    //   ctx.fillStyle = "#09F"
    //   ctx.fillRect(0, 75, 75, 75)
    //   ctx.fillStyle = "#F30"
    //   ctx.fillRect(75, 75, 75, 75)
    //   ctx.fillStyle = "#FFF"

    //   // set transparency value
    //   ctx.globalAlpha = 0.2

    //   // Draw semi transparent circles
    //   for i in 0..<7 {
    //     ctx.beginPath()
    //     ctx.arc(75, 75, 10 + 10 * Float(i), 0, Float.pi * 2, anticlockwise: true)
    //     ctx.fill()
    //   }
    //   ctx.commit { [self]
    //     print("image rendering commited to the offscreen canvas")
    //   }
    // }

    
    // 3D

    // let vertexShaderSource =
    //   "  attribute vec4 a_position;" +
    //   "  void main() {" +
    //   "    gl_Position = a_position;" +
    //   "  }"

    // let fragmentShaderSource =
    //   "  precision mediump float;\n" +
    //   "    void main() {\n" +
    //   "    gl_FragColor = vec4(1, 0, 0.5, 1);\n" +
    //   "  }\n"

    // let vertexShader = gl.createShader(type: gl.VERTEX_SHADER)
    // gl.shaderSource(vertexShader, source: vertexShaderSource)
    // gl.compileShader(vertexShader)
    
    // let fragmentShader = gl.createShader(type: gl.FRAGMENT_SHADER)
    // gl.shaderSource(fragmentShader, source: fragmentShaderSource)
    // gl.compileShader(fragmentShader)

    // // Link the two shaders into a program
    // let program = gl.createProgram()
    // gl.attachShader(program, shader: vertexShader)
    // gl.attachShader(program, shader: fragmentShader)
    // gl.linkProgram(program)
    
    // // look up where the vertex data needs to go.
    // var positionAttributeLocation = gl.getAttribLocation(program: program, name: "a_position")

    // // Create a buffer and put three 2d clip space points in it
    // let positionBuffer = gl.createBuffer()

    // // Bind it to ARRAY_BUFFER (think of it as ARRAY_BUFFER = positionBuffer)
    // gl.bindBuffer(gl.ARRAY_BUFFER, buffer: positionBuffer)

    // let positions: [Float] = [
    //   0, 0,
    //   0, 0.5,
    //   0.7, 0,
    // ]

    // gl.bufferData(gl.ARRAY_BUFFER, data: Float32Array(positions), usage: gl.STATIC_DRAW)

    // // code above this line is initialization code.
    // // code below this line is rendering code.

    // //webglUtils.resizeCanvasToDisplaySize(gl.canvas)
    // // Tell WebGL how to convert from clip space to pixels
    // gl.viewport(x: 0, y: 0, width: GLsizei(offscreenCanvas!.width), height: GLsizei(offscreenCanvas!.height))
    // // Clear the canvas
    // gl.clearColor(r: 0, g: 0, b: 0, a: 0)
    // gl.clear(gl.COLOR_BUFFER_BIT)
    // // Tell it to use our program (pair of shaders)
    // gl.useProgram(program)
    // // Turn on the attribute
    // gl.enableVertexAttribArray(index: GLuint(positionAttributeLocation))

    // // Bind the position buffer.
    // gl.bindBuffer(gl.ARRAY_BUFFER, buffer: positionBuffer)
    // gl.vertexAttribPointer(index: GLuint(positionAttributeLocation), size: 2, type: gl.FLOAT, normalized: false, stride: 0, offset: 0)
    // gl.drawArrays(mode: gl.TRIANGLES, first: 0, count: 3)

    // gl.commit {}
      //print("3d rendering commited to the offscreen canvas")
    //}
  }

  public func onTerminate() {
    // important: dont retain a ref count on the port or the GC might break on the final worker thread GC collection
    port = nil
    offscreenCanvas = nil
    globalScope = nil
    lenaImageBitmap = nil
  }

  fileprivate func loadWasm(_ name: String, size: inout Int) -> UnsafeMutablePointer<UInt8>? {
    let buf = malloc(326)
    var fd: Int32 = -1
    name.withCString {
      fd = open($0, O_RDONLY)
    }
    assert(fd != -1)
    let readed = read(fd, buf, 326)
    size = readed
    close(fd)
    //(buf! + 121200).storeBytes(of: 0, as: Int32.self)
    //print("loadBootstrap:\n\(data)")
    return buf!.bindMemory(to: UInt8.self, capacity: size)
  }

}  

internal class TweedyProviderImpl : tweedy_TweedyProvider {

  public var routes: RouteManager {
    return context!.routes
  }

  private weak var context: TweedyContext?
  private var sayCounter: Int
  private var serviceWorkerClient: ServiceWorkerClient
  private var wasActivate: Bool = false
  private var appId: Int = 0
  private var lenaBuffer: UnsafeMutablePointer<UInt8>?
  private var lenaBufferSize: Int = 0

  init(context: TweedyContext) {
    self.context = context
     
    sayCounter = 0
    
    let routeMap = makeRoutes {
      //Route({ return HelloHandler(context: context) })
      Route("/greet", { return GreetingsHandler() })
      Route("/resource", { return ResourcesHandler() })
      Route("/python", { return PythonHandler() })
    }

    serviceWorkerClient = ServiceWorkerClient(context: context)

    context.serviceWorkerContextClient = ServiceWorkerContextClientImpl(delegate: serviceWorkerClient)

    routes.bind(routeMap)
    context.storage.filebaseExists("burma", onFilebaseExists)
  }

  public func routeHandler(for route: String) -> RouteHandler? {
    return routes[route]?.handler
  }

  func onServiceList(_ maybeEntries: [ServiceEntry]?) {
    if let entries = maybeEntries {
      for entry in entries {
        print("  service '\(entry.name)' => scheme: \(entry.scheme) name: \(entry.name) host: \(entry.host) port: \(entry.port)")
      }
    } else {
      print("  entries not found")
    }
  }
  

  func say(callId: Int, request: Tweedy.ChatMessage, session: tweedy_TweedySaySession) throws -> ServerStatus? {
    // let waitev = WaitableEvent(resetPolicy: .manual, initialState: .notSignaled)
    appId += 1
    let msg = Tweedy.ChatMessage.getBuilder()

    if lenaBuffer == nil {
      lenaBuffer = loadLena(size: &lenaBufferSize)
    }
    //print("TweedyProvider.say(): processing app \(msg.message)")

    // if let id = Int(msg.message) {  
    //   print("TweedyProvider.say(): processing app \(id)")
    //   appId = id
    // } else {
    //   print("TweedyProvider.say(): did not received an id. using \(appId)")
    // }

    //app.setShowFPSCounter(true)
    //app.highlightRect(x: 20, y: 20, width: 500, height: 400, color: RGBA(r: 0, g: 255, b: 0, a: 0.0), outlineColor: RGBA(r: 255, g: 0, b: 0, a: 0.0))
    
    // change the html content
     //app.getFrameTree({ frameTree in
     //  print("getFrameTree returned => frame id: '\(frameTree.frame.id)'")
    //   var helloString = "<!DOCTYPE html>\n" +
    //     "<html>\n" +
    //     "<head>\n" +
    //     "<style type=\"text/css\">\n" +
    //     "  body, canvas { padding: 0; margin: 0; }\n" +
    //     "</style>\n" +
    //     "<meta charset=\"utf-8\">\n" +
    //     "<title>Hello world</title>\n" +
    //     "</head>\n<body>\n"
    //   helloString += "<div id=\"text1\" class=\"canvas\">\n"
    //   helloString += "let's dance"
    //   helloString += "</div>\n"
    //   helloString += "</body>\n"
    //   app.setDocumentContent(frameId: frameTree.frame.id, html: helloString)
         
    //})

    // app.requestCacheNames(origin: "tweedy", { caches in
    //   print("requestCacheNames returned => caches: '\(caches.count)'")
    // })

    for apphost in context!.applications {
      for app in apphost.instances {
        app.openCache("tweedy|main", { result in
          let resultStr = result == 0 ? "opened" : "opening failed"
          print("openCache returned => cache 'tweedy' \(resultStr)")
          let blob = Engine.BlobData()
          blob.appendBytes(Data(bytes: self.lenaBuffer!, count: self.lenaBufferSize))
          //blob.appendFile("/home/fabiok/Downloads/pnad_2015_relacoes_de_trabalho.xls", offset: 0, length: 5255168, expectedModificationTime: -1)
          app.requestCachedResponse("tweedy|main", url: "tweedy://hello", base64Encoded: false, { getResult in
            //let encData = Data(base64Encoded: getResult.body)!
            //let data = String(data: encData, encoding: .utf8)!
            //print("requestCache returned:\n'\(data)'")
            print("requestCache returned \(getResult.body.count) bytes of data")
            if getResult.body.isEmpty {
              app.putCacheEntry("tweedy|main", request: "tweedy://hello", blob: blob, { putResult in
                print("putCache returned => \(putResult)")
                // if putResult {
                //   app.requestCachedResponse("tweedy|main", url: "tweedy://hello", base64Encoded: false, { getResult in
                //     //let encData = Data(base64Encoded: getResult.body)!
                //     //let data = String(data: encData, encoding: .utf8)!
                //     //print("requestCache returned:\n'\(data)'")
                //     print("requestCache returned:\n'\(getResult.body)'")
                //   })
                // }
              })
            }
          })
        })
      }
    }

    msg.message = "some automation method was called"

    try session.send(try msg.build(), callId: callId)
    // for i in 0..<5 {
    //   self.sayCounter += 1  
    //   let index = self.sayCounter % array.count
    // //for i in 0..<3 {
    //   let msg = Tweedy.ChatMessage.getBuilder()
    //   msg.message = array[index]
    //   print("sending: array[\(index)] = '\(msg.message)'")
    //   try session.send(try msg.build())
    //   waitev.timedWait(waitDelta: TimeDelta.from(seconds: 7))
    // }
    // //}
    try session.close(callId: callId, withStatus: .ok, completion: nil)

    // serviceWorkerClient.globalScope?.postTask { [weak self] _ in
    //   if self!.serviceWorkerClient.context2d != nil {
    //     self!.serviceWorkerClient.pageIndex += 1
    //     self!.serviceWorkerClient.loadPage(self!.serviceWorkerClient.pageIndex)
    //     self!.serviceWorkerClient.render()
    //     //print("ServiceWorkerClient.onMessage: no offscreen canvas received")
    //   }
    // }

    // for app in context!.applications {
    //   //app.kill(id: context!.lastLaunchedApplicationId)
    //   if wasActivate {
    //     app.launch(id: context!.lastLaunchedApplicationId + 1, url: "tweedy://hello?path=2")
    //     wasActivate = false
    //   } else {
    //     app.activate(id: context!.lastLaunchedApplicationId)
    //     wasActivate = true
    //   }
    // }

    sayCounter += 1
    return .ok
  }

  // Fetch
  // public func fetchUnary(request: Tweedy.FetchRequest, session: tweedy_TweedyFetchUnarySession) throws -> ServerStatus? {
  //   let urlString = base64Decode(string: request.url)
  //   let replyDataDecoded = base64Decode(data: request.data)
  //   let route = String(urlString[urlString.lastIndex(of: "/")!..<urlString.firstIndex(of: "?")!])

  //   let routeRequest = RouteRequest(url: urlString, contentType: request.contentType, startedTime: request.startedTime, inputData: request.data)

  //   guard var handler = routeHandler(for: route) else {
  //     let reply = Tweedy.FetchReply.getBuilder()
  //     reply.size = Int64(replyDataDecoded.count)
  //     reply.data = Data(bytes: replyDataDecoded, count: replyDataDecoded.count)
  //     try session.send(reply.build())
  //     try session.close(withStatus: .ok, completion: nil)
  //     return nil
  //   }

  //   handler.onResponseStarted(request: routeRequest, info: RouteResponseInfo(), {
  //     let resultData = $0
  //     let reply = Tweedy.FetchReply.getBuilder()
  //     reply.size = Int64(resultData.count)
  //     reply.data = resultData
  //     try session.send(reply.build())
  //     try session.close(withStatus: .ok, completion: nil)
  //   })
  //   handler.onReadCompleted(request: routeRequest, info: RouteResponseInfo(), buffer: RouteBuffer(string: replyDataDecoded), bytesRead: UInt64(replyDataDecoded.count))
  //   handler.onSucceeded(request: routeRequest, info: RouteResponseInfo())
    
  //   return nil
  // }

  // func createHelloPage2() -> Tweedy.EntryContent {
  //   var helloString: String?

  //   let entry = Tweedy.EntryContent.getBuilder()
  //   entry.offset = 0
  //   entry.contentType = Tweedy.EntryContentType.textHtml
  //   let openev = WaitableEvent(resetPolicy: .manual, initialState: .notSignaled)
  //   let readev = WaitableEvent(resetPolicy: .manual, initialState: .notSignaled)
  //   context!.storage.openFilebase("burma", { [self] (status, filebase) in
  //     if status == 0 {
  //       filebase!.readAll(from: "index.html", {[self] (status, mem) in  
  //         print("readAll callback: status = \(status)")
  //         if status == 0 {
  //           if let m = mem {
  //             m.map({ (buf, size) in
  //               let lastByte = buf! + size
  //               lastByte.pointee = 0
  //               helloString = String(cString: buf!)
  //               print("index.html:\n\(helloString!)\n")
  //               // format entry
  //               let data = Data(bytes: helloString!, count: helloString!.count)
  //               entry.data = data
  //               entry.size = Int64(data.count)
  //               readev.signal()
  //             })                      
  //           } else {
  //             print("data is null")
  //             helloString = "error reading file 'burma/index.html': NO DATA"
  //             // format entry
  //             let data = Data(bytes: helloString!, count: helloString!.count)
  //             entry.data = data
  //             entry.size = Int64(data.count)
  //             readev.signal()
  //           }
  //         } else {
  //           print("reading file 'index.html' failed")
  //           helloString = "error reading file 'burma/index.html': FAILED"
  //           // format entry
  //           let data = Data(bytes: helloString!, count: helloString!.count)
  //           entry.data = data
  //           entry.size = Int64(data.count)
  //           readev.signal()
  //         }
  //         //filebase!.close({print("closing filebase returned \($0)")})
  //       })
  //     } else {
  //       print("opening filebase 'burma' failed")
  //       helloString = "error opening filebase 'burma': FAILED"
  //       let data = Data(bytes: helloString!, count: helloString!.count)
  //       entry.data = data
  //       entry.size = Int64(data.count)
  //       readev.signal()
  //     }
  //     openev.signal()
  //   })
  //   openev.wait()
  //   print("createHelloPage: open done!")
  //   readev.wait()
  //   print("createHelloPage: read done!")
  //   return try! entry.build()
  // }

  // func createHelloPage2Old() -> String {
  //   //let sys = Python.import("sys")

  //   let list: PythonObject = [1, 2, 3]
  //   //print(Python.len(list)) // Prints 3.

  //   var helloString = "<!DOCTYPE html>\n" +
  //     "<html>\n" +
  //     "<head>\n" +
  //     "<style type=\"text/css\">\n" +
  //     "  body, canvas { padding: 0; margin: 0; }\n" +
  //     "</style>\n" +
  //     "<meta charset=\"utf-8\">\n" +
  //     "<title>Python Baby</title>\n" +
  //     "</head>\n<body>\n"
      
  //   helloString += "<div id=\"text1\" class=\"canvas\">\n"
  //   helloString += "list count: \(Python.len(list))"
  //   helloString += "</div>\n"
  //   helloString += "<div id=\"text2\" class=\"canvas\">\n"
  //   helloString += "\(list)"
  //   helloString += "</div>\n"
  //   helloString += "</body>\n"
    
  //   return helloString
  // }

  func createAndPopulateDatabase(_ context: TweedyContext) {
    context.storage.createDatabase("petshop", keyspaces: ["cats", "dogs"], { status, db in
      print("creating db 'petshop' returned \(status)")
      if status == 0 {
        db!.put(keyspace: "cats", key: "frajola", value: "gato bobo", {
          print("put 'frajola' into db 'petshop' returned \($0)")
          if $0 == 0 {
            db!.get(keyspace: "cats", key: "frajola", { (status: Int, data: SharedMemory?) in 
              if status == 0 {
                if let value = data {
                  //value.withUnsafeBytes {
                  //  let strValue = String(cString: $0.baseAddress!.bindMemory(to: UInt8.self, capacity: value.count))
                  value.constMap({ (buf, size) in
                    let strValue = String(cString: buf!)
                    print("petshop: frajola => '\(strValue)'")
                  })
                  //}
                } else {
                  print("petshop: get failed - \(status) - Data is null")  
                }
              } else {
                print("petshop: get failed - \(status)")
              }
              // context.storage.createKeyspace(db: "petshop", keyspace: "rats", {
              //   print("create keyspace 'rats' on db 'petshop' returned \($0)")
              //   context.storage.listKeyspaces(db: "petshop", { (status, keyspaces) in
              //     if status == 0 {
              //       var str = String()
              //       for keyspace in keyspaces {
              //         str += " " + keyspace + "\n"
              //       }
              //       print("keyspaces: \n\(str)")
              //     }
              //     context.storage.close(db: "petshop", {
              //       print("close db 'petshop' returned \($0)")
              //     })
              //   })
              // })
              db!.put(keyspace: "cats", key: "ligeirinho", value: "miguelito", {
                print("put 'ligeirinho' into db 'petshop' returned \($0)")
                db!.put(keyspace: "cats", key: "pussycat", value: "gata manhosa", {
                  print("put 'pussycat' into db 'petshop' returned \($0)")
                  db!.put(keyspace: "cats", key: "dom corleaone", value: "rato mafioso", {
                    print("put 'dom corleone' into db 'petshop' returned \($0)")
                    db!.put(keyspace: "cats", key: "beluga", value: "na verdade uma baleia", {
                      print("put 'beluga' into db 'petshop' returned \($0)")
                      db!.put(keyspace: "cats", key: "deleteme", value: "this item is here just to be deleted", {
                        print("put 'deleteme' into db 'petshop' returned \($0)")
                      })
                    })
                  })
                })
              })
            })
          }
        })
      }
    })
  }

  // func openAndReadDatabase(_ context: TweedyContext) {
  //   context.storage.openDatabase("petshop", create: false, { opened, db in
  //     print("opening db 'petshop' returned \(opened)")
  //     if opened == 0 {
  //       db!.createCursor(keyspace: "cats", order: Order.ASC, write: true, { maybeCursor in
  //         guard let cursor = maybeCursor else {
  //           return
  //         }
  //         let (_, found) = cursor.seek("goodbye", op: .EQ)
  //         if !found {
  //           if cursor.insert(key: "goodbye", value: "goodbye lenin") {
  //             if cursor.commit() {
  //               print("inserting goodbye ok")
  //             } else {
  //               print("inserting goodbye failed: commit")
  //             }
  //           } else {
  //             print("inserting goodbye failed: insert")            
  //           }
  //         } else {
  //           cursor.first()
  //           let items = cursor.count()
  //           print("count: \(items)\n")
  //           while cursor.isValid {
  //             let (k, v) = cursor.getKeyValue()
  //             if k != nil && v != nil {
  //               let key = String(decoding: k!, as: UTF8.self)
  //               let value = String(decoding: v!, as: UTF8.self)
  //               print("\"\(key)\" -> \"\(value)\"")
  //             } else {
  //               print("oops.. theres a row but getting key value returned NULL")
  //             }
  //             cursor.next()
  //           }
  //           //cursor.commit()
  //           //context.storage.createCursor(db: "petshop", keyspace: "cats", order: Order.ANY, write: true, { maybeDeleteCursor in
  //           //  guard let deleteCursor = maybeDeleteCursor else {
  //           //    return
  //           //  }
  //           let (_, found) = cursor.seek("deleteme", op: .EQ)
  //           if found {
  //             print("'deleteme' found. deleting it")
  //             if cursor.delete() {
  //               print("'deleteme' deletion ok")
  //               cursor.commit()
  //             } else {
  //               print("'deleteme' deletion failed")
  //               cursor.rollback()
  //             }
  //           } else {
  //             print("'deleteme' was not found. nothing to delete")
  //             cursor.rollback()
  //           }
  //           //})
  //         }
  //       })
  //     } else {
  //       print("opening db 'petshop' failed")
  //     }
  //   })      
  // }

  func onFilebaseExists(_ exists: Bool) {
    if !exists {
      context!.storage.createFilebase("burma", path: "/home/fabiok/pages/burma/", { status, filebase in 
        print("creating file 'burma' returned \(status)")
        if status == 0 {
          print("closing 'burma'..")
          filebase!.close({
            print("closing status \($0)")
          })
        }
      })
    }
  }

}

fileprivate func loadLena(size: inout Int) -> UnsafeMutablePointer<UInt8>? {
  let buf = malloc(473831)
  var fd: Int32 = -1
  fd = open("/home/fabiok/Pictures/lena.png", O_RDONLY)
  assert(fd != -1)
  let readed = read(fd, buf, 473831)
  size = readed
  close(fd)
  //(buf! + 121200).storeBytes(of: 0, as: Int32.self)
  //print("loadBootstrap:\n\(data)")
  return buf!.bindMemory(to: UInt8.self, capacity: size)
}

fileprivate func loadPdf(size: inout Int) -> UnsafeMutablePointer<UInt8>? {
  let buf = malloc(26961491)
  var fd: Int32 = -1
  fd = open("/home/fabiok/Desktop/drawingwithquartz2d.pdf", O_RDONLY)
  assert(fd != -1)
  let readed = read(fd, buf, 26961491)
  size = readed
  close(fd)
  return buf!.bindMemory(to: UInt8.self, capacity: size)
}