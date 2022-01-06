import Base
import Graphics
import UI
import Web
import Javascript
import Platform
import Compositor
import Foundation
import ProtocolBuffers
import TweedyApi
import Channel
import Net

fileprivate let pieceSize = 16384

func nativeFunction(_ info: JavascriptFunctionCallbackInfo) {
  //print("nativeFunction() called. args: \(info.length)")
  let global = info.holder
  if info.length > 0 {
    if let str = info[0] {
      let helloDiv = global.document.getElementById("hello")
      helloDiv.innerHTML = "nativeFunction() said \(str)"
    } else {
      //print("argument 0 doesnt exists")
    }
  }
}

func FormatNumber(_ number: Int) -> String {
  let r = String(number)
  if r.count == 1 {
    return String("0" + r)
  }
  return r
}

public struct CheckerboardPainter : CSSPainter {

  public var name: String {
    return "checkerboard"
  }

  let colors = ["red", "green", "blue"]
  let csize = 32

  public init() {}
  
  public func paint(canvas: PaintCanvasRenderingContext2d, size: IntSize) {
    for y in 0..<size.height / csize {
      for x in 0..<size.width / csize {
        let color = colors[(x + y) % colors.count]
        let rect = IntRect(x: x * csize, y: y * csize, width: csize, height: csize)
        canvas.fillStyle = color
        canvas.fillRect(rect)
      }
    }
  }
}

public class BubblePainter : CSSPainter {
  
  public var name: String {
    return "checkerboard"
  }

  let colors: [Color] = [
    Color.Yellow,
    Color.Blue,
    Color.Green,
    Color.Red,
    Color.Gray,
    Color.Magenta
  ]

  //let path: Path
  let paintFlags: PaintFlags
  var counter = 0

  public init() {
    //path = Path()
    paintFlags = PaintFlags()
    paintFlags.style = .Fill
  }
  
  public func paint(canvas: PaintCanvasRenderingContext2d, size: IntSize) {
    //paintFlags.color = Color.Magenta

    // let positionPercent = 50 
    // let position = size.width * positionPercent / 100
    // let tooltipSize = 30

    // path.moveTo(x: position - tooltipSize, y: 0)
    // path.lineTo(x: position + tooltipSize, y: 0)
    // path.lineTo(x: position, y: size.height)
    // path.close()

    //canvas.drawPath(path: path, flags: paintFlags)
    //canvas.clearRect(IntRect(x: 0, y: 0, width: size.width, height: size.height))
    //canvas.drawDashedRect(rect: FloatRect(x: 0, y: 0, width: Float(size.width), height: Float(size.height)), color: Color.Magenta)
    paintFlags.color = colors[counter % colors.count]
    canvas.drawRect(FloatRect(x: 0, y: 0, width: Float(size.width), height: Float(size.height)), flags: paintFlags)
    counter += 1
  }

}

//import TweedyApi

public class HelloWorker : WebWorkerNative {

  public weak var worker: WebWorker? {
    return context?.worker
  }
  
  private var context: WebWorkerContext?
  private var initialized: Bool = false
  private var port: MessagePort?
  private var times: Int = 0
  private var x: Int = 0
  private var y: Int = 0
  private var promise: Promise<String>?
  private var offscreenCanvas: OffscreenCanvas?
  private var renderContext: OffscreenCanvasRenderingContext2d?
  private let paintFlags: PaintFlags
  private var lastColor: String
  private var lastColorIndex = 0
  let colors: [String] = [
    "yellow",
    "blue",
    "green",
    "red",
    "gray",
    "magenta"
  ]
  public init() {
    paintFlags = PaintFlags()
    lastColor = colors[lastColorIndex]
  }
  
  public func onInit(context: WebWorkerContext) {
    print("HelloWorker initialized")
    self.context = context
    initialized = true
  }

  public func onMessage(event: MessageEvent) {
    if event.ports.count > 0 {
      port = MessagePort(owning: event.ports[0], worker: worker!)
    }
    // if let message = event.dataAsString {
    //   port!.postMessage(string: "received '\(message)' \(times) times")
    //   times += 1
    //   worker!.fetch(url: "sw.js", { response in
    //     self.promise = response.text
    //     self.promise!.then({ text in
    //       print(" url: \(response.url)\n status: \(response.status)\n contentType: \(response.contentType)\n content size: \(text.count)\n content:\n\(text)")        
    //       self.promise = nil
    //     }, {
    //       print(" rejected ")
    //       self.promise = nil
    //     })
    //   })
    // }
    if let offscreen = event.dataAsOffscreenCanvas {
      print("HelloWorker.onMessage: received offscreen canvas")
      offscreenCanvas = offscreen
      print("HelloWorker.onMessage: creating 2d canvas..")
      renderContext = offscreenCanvas!.context2d
      render()
      // canvas!.commit { [self]
      //   print("HelloWorker: canvas.commit() returned")
      //   //self.render(canvas: self.canvas!)
      // }
      // canvas!.commit { [self]
      //   print("HelloWorker.onMessage: canvas.commit() succeeded")
      //   self.render(canvas: self.canvas!)
      // }
      // print("HelloWorker.onMessage: drawing rect..")
      // canvas!.clearRect(IntRect(x: 0, y: 0, width: offscreen.width, height: offscreen.height))
      // paintFlags.color = Color.Red    
      // canvas!.drawRect(rect: FloatRect(x: 0, y: 0, width: Float(offscreen.width), height: Float(offscreen.height)), flags: paintFlags)
      // //canvas!.restore()
      //worker!.requestAnimationFrame { [self] time in
      //  print("HelloWorker.onMessage: worker.requestAnimationFrame callback called")
      //  self.render(canvas: self.canvas!)
      //}
      //canvas!.commit {
      //  print("HelloWorker.onMessage: canvas.commit() succeeded")
     // }
    } else {
      print("HelloWorker.onMessage: no offscreen canvas received")
    }
  }

  public func render() {
    renderContext!.clearRect(IntRect(x: 0, y: 0, width: offscreenCanvas!.width, height: offscreenCanvas!.height))
    if times % 20 == 0 {
      lastColorIndex += 1
      lastColor = colors[lastColorIndex]
      if lastColorIndex == 5 {
        lastColorIndex = 0
      }
    }
    renderContext!.fillStyle = lastColor
    let rect = IntRect(x: x, y: y / 2, width: (offscreenCanvas!.width / 4) , height: (offscreenCanvas!.height / 4))
    renderContext!.fillRect(rect)
    x += 4
    if x > offscreenCanvas!.width {
      x = 0
    }
    renderContext!.commit { [self]
      self.render()    
    }
    times += 1
    // worker!.requestAnimationFrame { [weak self] time in
    //   self!.render()
    // }
    //   print("HelloWorker.render: worker.requestAnimationFrame callback called")
    // canvas.commit {
    //  print("HelloWorker.render: second canvas.commit() succeeded")
    // }
    //}
  }

}

public class PageLoader : UrlLoaderClient {

  public var contentEncoding: String = String()
  public var encodedMessageType: String = String()
  private var url: String = String()
  private var totalPayloadSize: Int = 0
  private var currentOffset: Int = 0
  private var inputData: Data?

  public init() {}

  public func shouldHandleResponse(response: WebURLResponse) -> Bool {
    //print("PageLoader.didReceiveResponse: url: \(response.url) status: \(response.httpStatusCode) \(response.httpStatusText) expectedContentLength: \(response.expectedContentLength)")
    self.url = response.url
    let bodySize = response.getHttpHeaderField(name: "Content-Length")
    
    totalPayloadSize = bodySize.isEmpty ? 0 : Int(bodySize)!

    if response.getHttpHeaderField(name: "RPC-Message-Encoding") == "protobuf-grpc" {
      contentEncoding = "protobuf"
      encodedMessageType = response.getHttpHeaderField(name: "Rpc-Service-Method-Output")
      return true
    }
    return false
  }

  public func didSendData(bytesSent: Int, totalBytesToBeSent: Int) {
    print("PageLoader.didSendData: \(bytesSent)")
  }

  public func didReceiveData(input: UnsafeMutableRawPointer, bytesReaded: Int) -> Int {
    if inputData == nil {
      // will write all at once.. we dont need copy
      if bytesReaded == totalPayloadSize && totalPayloadSize != 0 {
        inputData = Data(bytesNoCopy: input, count: bytesReaded, deallocator: .none)
      } else {
        // This will be buffered.. so prepare a Data that will get copied into
        inputData = Data(bytes: input, count: bytesReaded)
      }
    } else {
      let typedPtr = input.bindMemory(to: UInt8.self, capacity: bytesReaded)
      inputData!.append(typedPtr, count: bytesReaded)
    }

    currentOffset += bytesReaded
    if currentOffset < totalPayloadSize && totalPayloadSize != 0 {
      return -1
    }
    return 0
  }

  public func writeOutput(output: inout UrlOutputStream) -> Bool {
    var size: Int = 0

    defer {
      reset()
    }

    guard let input = inputData else {
      return false
    }
    
    if contentEncoding == "protobuf" && encodedMessageType == "ChatMessage" {
      let message = try! Tweedy.ChatMessage.Builder().mergeFrom(codedInputStream: CodedInputStream(data: input)).build()
      output.writeOnce(string: message.message!)
      return true
    } else if contentEncoding == "protobuf" && encodedMessageType == "FetchReply" {
      // fixme: temporary hack
      if input.count < pieceSize {
        print("\nDecoding reply 1 of 1. size: \(input.count)")
        let reply = try! Tweedy.FetchReply.Builder().mergeFrom(codedInputStream: CodedInputStream(data: input)).build()
        //output.writeOnce(data: reply.data)
        reply.data.withUnsafeBytes {
          output.writeOnce(raw: $0.baseAddress!, size: Int(reply.size))
        }
        return true
      } else {
        var fullDecodedSize = 0
        var pieces = (input.count / pieceSize)
        let rest = input.count - (pieces * pieceSize)
        let haveRest = rest > 0
        if haveRest {
          pieces += 1
        }
        var replies: [Tweedy.FetchReply] = []
        
        input.withUnsafeBytes {
          var startOffset = 0
          for i in 0..<pieces {
            startOffset = i * pieceSize
            let offsetPtr = UnsafeMutableRawPointer(mutating: $0.baseAddress! + startOffset)
            let size = i == (pieces - 1) && haveRest ? rest : pieceSize
            print("\nDecoding reply \(i+1) of \(pieces). offset: \(startOffset) size: \(size)")
            let pieceData = Data(bytesNoCopy: offsetPtr, count: size, deallocator: .none)
            let reply = try! Tweedy.FetchReply.Builder().mergeFrom(codedInputStream: CodedInputStream(data: pieceData)).build()
            fullDecodedSize += Int(reply.size)
            replies.append(reply)
          }
        }
        output.allocate(fullDecodedSize)
        //var outputBufferPtr = outputBuffer
        var offset: Int = 0
        for reply in replies {
          reply.data.withUnsafeBytes {
            output.write(raw: $0.baseAddress!, offset: offset, size: Int(reply.size))
            offset += Int(reply.size)
          }
        }
        output.seal()
        return true
      }
    }
    return false
  }

  public func didFinishLoading(errorCode: Int, totalTransferSize: Int) {
    print("PageLoader.didFinishLoading: code: \(errorCode) totalTransferSize: \(totalTransferSize)")
    //contentEncoding = String()
    //encodedMessageType = String()
  }

  private func reset() {
    inputData = nil
    currentOffset = 0
  }
}

public class TweedyApp : UIApplicationDelegate,
                         UIWebWindowDelegate,
                         UIWebFrameObserver,
                         ButtonListener,
                         WebSocketDelegate,
                         ChannelClient {

  public var app: UIApplication?
  public var window: UIWindow? {
    return webWindow
  }
  private var webWindow: UIWebWindow?
  private var imageView: ImageView?
  private var labelButton: LabelButton?//Label?
  private var label: Label?
  private var imageBitmap: Bitmap?
  private var image: ImageSkia?
  private var contentView: View
  private var mainView: View
  private var viewRect: IntRect
  private var textureLayer: UI.Layer?
  private var paintCanvas: CanvasRenderingContext2d?
  //private var childLayer: UI.Layer?
  private var bundleLoaded: Bool
  private var loaded: Bool
  private var eventsHooked: Bool = false
  //private var mainLoop: MessageLoop

  private var worker: WebWorker?
  private var serviceWorker: WebServiceWorkerContainer?
  
  private var promise: Promise<WebServiceWorkerRegistration>?
  private var workerPromise: Promise<WebServiceWorkerRegistration>?
  
  private var registration: WebServiceWorkerRegistration?
  private var messageChannel: MessageChannel?
  private var workerHandler: HelloWorker?

  private var loader: PageLoader
  private var fn: JavascriptFunction?
  private var editDiv: WebElement?
  private var btn: WebElement?
  private var audioBtn: WebElement?
  private var playBtn: WebElement?
  private var pauseBtn: WebElement?
  private var sendBtn: WebElement?
  private var availableBtn: WebElement?
  private var availableBtnClickAdded: Bool = false
  private var corretorDiv: WebElement?
  private var paintWorklet: PaintWorklet?
  
  private var imageElement: HtmlImageElement?
  private var audioElement: HtmlAudioElement!
  private var videoElement: HtmlVideoElement!
  private var videoElement0: HtmlVideoElement!
  private var counter: Int = 0
  private var audioMediaSource: MediaSource?
  private var videoMediaSource: MediaSource?
  private var imageSize: Int = 0
  private var moviePosterClicks: Int = 0
  private var document: WebDocument!
  private var request: XmlHttpRequest!
  private var mdRequest: XmlHttpRequest!
  private var chatRequest: XmlHttpRequest!
  private var sourceBuffer: SourceBuffer!
  private var isPlaying: Bool = false
  private var receivedResponse: Bool = false
  private var currentSegment: Int = 0
  private var videoUrl: String = String()
  private let checkerboardPainter: CheckerboardPainter
  private let bubblePainter: BubblePainter
  private var offscreenCanvas: OffscreenCanvas?
  private var html2DCanvas: HtmlCanvasElement?
  private var channelConnected: Bool = false
  private var isHeadless: Bool = false
  private let moviePosterUrls: [String] = [
    "http://upload.wikimedia.org/wikipedia/commons/8/8d/Mudhoney_poster_01.jpg",
    "http://upload.wikimedia.org/wikipedia/commons/d/db/Faster_pussycat_kill_kill_poster_%281%29.jpg",
    "http://upload.wikimedia.org/wikipedia/commons/8/80/Adventures_of_lucky_pierre_poster_01.jpg"
  ]

  // private var rpcClient: GRPCClient?
  private var rpcChannel: RpcChannel?

  private var webSocket: WebSocket?
  private var channelHost: ChannelClient?

  private let messages: [String] = [
    "ola mundo",
    "adeus mundo",
    "como vai", 
    "tudo bem",
    "vem meu amor",
    "vem com calor"
  ]

  let colors: [Color] = [
    Color.Yellow,
    Color.Blue,
    Color.Green,
    Color.Red,
    Color.Gray,
    Color.Magenta
  ]
  
  public init() {
    //var size: Int = 0
    bundleLoaded = false
    loaded = false
    mainView = View()
    contentView = View()
    viewRect = IntRect()
    loader = PageLoader()
    checkerboardPainter = CheckerboardPainter()
    bubblePainter = BubblePainter()
    //textureLayer.cclayer!.backgroundColor = Color.Yellow
    //textureLayer.cclayer!.contentsOpaque = true
    //textureLayer.masksToBounds = true
    //textureLayer.fillsBoundsOpaquely = true
    mainView.layoutManager = FillLayout()
    contentView.background = SolidBackground(color: colors[Int.random(in: 0..<colors.count)])
    contentView.layoutManager = FillLayout()
    //contentView.layoutManager = BoxLayout(orientation: BoxOrientation.Vertical)
    mainView.addChild(view: contentView)

    //mainView.layer = textureLayer

    // in theory if message loop calls bindToCurrent()
    // it will save its own instance on a TLS of the current thread (main)
    // so just by instantiating a MessageLoop here, we may have access
    // to the SingleThreadTaskRunner of the main thread, even if being another
    // instance on Swift side
    // the plain constructor is fine, because we want the IO kind here
    // as the real window events loop binded to GTK or Windows happens only
    // on the host process, who route those events back to this process

    // the only problem would be the worker pool, and possible problems if
    // some task will run on the same time in the C++ and Swift side.. 
    // but when we start here, we mostly call C++ runtime from the Swift 
    // side, without any further scheduling on the C++ side
    //mainLoop = try! MessageLoop()

    app = UIApplication(delegate: self)
    try! TaskScheduler.createAndStartWithDefaultParams()
  }

  deinit {
    
  }

  public func run() {
    app!.run()
  }

  public func createWindow(application: UIApplication, dispatcher: UIDispatcher) -> UIWindow {
    webWindow = UIWebWindow(application: application, dispatcher: dispatcher, delegate: self, headless: application.isHeadless)
    //let inputData = loadDoguinho("/workspace/mumba/tools/stats_viewer/Resources/kitten.png", size: &size)
    return webWindow!
  }
  
  public func initializeVisualProperties(params: VisualProperties) {
    //widget = UIWebWindow(application: self.application!, delegate: self, routingId: routingId, params: params)
    webWindow!.initializeVisualProperties(params: params)
  }

  public func onExternalTextureLayerRequested() {
    //print("Tweedy.onExternalTextureLayerRequested")
    //textureLayer = try! Layer(type: .TextureLayer)
    //childLayer = try! Layer(type: .PictureLayer)
    //childLayer!.cclayer!.bounds = IntSize(width: 100, height: 100)
    //childLayer!.cclayer!.masksToBounds = true
    //textureLayer!.cclayer!.addChild(child: childLayer!.cclayer!)
    //window!.setTextureLayerForHTMLCanvas(target: "canvas0", layer: textureLayer!.cclayer!, frame: nil)
  }

  public func onFrameAttached(_ frame: UIWebFrame) {
    frame.addObserver(self)
    frame.urlLoaderDispatcher.addHandler(self.loader)
  }

  public func onPageWasShown(_ window: UIWindow) {
    //print("Tweedy.onPageWasShown")
    mainView.isVisible = true
    if !bundleLoaded {
      postTask {
        let _ = ResourceBundle.addDataPack(path: "gen/mumba/mumba_unscaled_resources.pak")
        let imageView = self.createImageView()
        imageView.horizontalAlignment = ImageView.Alignment.Center
        imageView.verticalAlignment = ImageView.Alignment.Center
        self.contentView.addChild(view: imageView)
        self.bundleLoaded = true
      }
    }
    //labelButton = LabelButton(listener: self, text: "hello world")
    label = Label(text: "Hello Ubuntu")
    label!.isVisible = true
    //label!.bounds = IntRect(x: 0, y: 0, width: 100, height: 80)
    contentView.addChild(view: label!)
    //print("didStartLoading: setting the main view to (\(viewRect.width),\(viewRect.height))")
  }

  public func onPageWasHidden(_ window: UIWindow) {
    //print("Tweedy.onPageWasHidden")
    mainView.isVisible = false
  }

  public func onUpdateScreenRects(viewScreen: IntRect, windowScreen: IntRect) {
    //print("Tweedy.onUpdateScreenRects viewScreen: \(viewScreen) windowScreen: \(windowScreen)")
    // if let canvas = paintCanvas {
    //   mainView.bounds = viewScreen
    //   mainView.layout()
    //   renderPage()
    // }
  }

  // UIWebFrameObserver

  public func didInvalidateRect(frame: UIWebFrame, rect: IntRect) {
    //print("Tweedy.didInvalidateRect: \(rect)")
    mainView.bounds = rect
    mainView.layout()
    if let canvas = paintCanvas {
      renderView(mainView, displayList: canvas.displayItemList!, rect: rect)
    }
  }

  public func didMeaningfulLayout(frame: UIWebFrame, layout: WebMeaningfulLayout) {
    //print("TweedyMain.didMeaningfulLayout")
    if layout == .FinishedLoading {
      
      //transferOffscreenCanvas()
      
      //print("TweedyMain: calling UrlRegistry.listEntries() ..")
      //app!.placeRegistry.listEntries(onEntryList)
    }
  }

  // func onEntryList(_ maybeEntries: [PlaceEntry]?) {
  //   if let entries = maybeEntries {
  //     for entry in entries {
  //       //print("application: entry name: '\(entry.name)' url: '\(entry.url)'")
  //     }
  //   } else {
  //     //print("entries not found")
  //   }
  // }

  public func didStartNavigation(frame: UIWebFrame) {}
  public func didStartLoading(frame: UIWebFrame, toDifferentDocument: Bool) {
  }
  public func didStopLoading(frame: UIWebFrame) {}
  public func didFailProvisionalLoad(frame: UIWebFrame) {}
  public func didChangeScrollOffset(frame: UIWebFrame) {}
  public func onStop(frame: UIWebFrame) {}
  public func frameDetached(frame: UIWebFrame) {
    frame.removeObserver(self)
  }
  public func frameFocused(frame: UIWebFrame) {}
  public func didStartNavigation(frame: UIWebFrame, url: String, type: WebNavigationType?) {}
  public func didCreateNewDocument(frame: UIWebFrame) {
    viewRect = frame.window!.viewRect
    //print("didCreateNewDocument: setting the main view to (\(viewRect.width),\(viewRect.height))")
    //textureLayer.bounds = viewRect
    mainView.size = viewRect.size
    mainView.layout()

    if receivedResponse {
      paintWorklet = CSSPaintWorklet(window: webWindow!.mainFrame!.frame!.window)
      paintWorklet!.registerPaint(bubblePainter)
      receivedResponse = false
    }
  }
  public func didCreateDocumentElement(frame: UIWebFrame) {
    //print("TweedyMain.didCreateDocumentElement")
  }
  public func didClearWindowObject(frame: UIWebFrame) {}
  public func didFinishDocumentLoad(frame: UIWebFrame) {
    //print("TweedyMain.didFinishDocumentLoad")
    // let selector = frame.frame!.document.querySelector("#canvas0")
    // if let element = selector.first {
    //   let canvasElement = element.asHTMLElement(to: HTMLCanvasElement.self)!
    //   let _ = canvasElement.setAttribute(name: "width", value: viewRect.width.description)
    //   let _ = canvasElement.setAttribute(name: "height", value: viewRect.height.description)
    //   if paintCanvas == nil {
    //     let canvas = canvasElement.createCanvas()
    //     paintCanvas = canvas.paintCanvas as? WebPaintCanvas
    //   }
    //   renderPage(canvas: paintCanvas!)
    //   //renderLabel(label!, canvas: canvas, rect: viewRect)
    // }
  }
  public func didFinishLoad(frame: UIWebFrame) {
    //print("TweedyMain.didFinishLoad")
    loaded = true
  }

  public func didFailLoad(frame: UIWebFrame, error: WebURLError) {}

  public func setBackgroundOpaque(opaque: Bool) {

  }

  public func setActive(active: Bool) {

  }

  public func didStartLoading() {
    //print("TweedyMain.didStartLoading")
  }
  
  public func didStopLoading() {
    print("TweedyMain.didStopLoading")
  }

  public func didHandleOnloadEvents(frame: UIWebFrame) {}
  public func didCreateScriptContext(frame: UIWebFrame, context: JavascriptContext, worldId: Int) {}
  public func willReleaseScriptContext(frame: UIWebFrame, context: JavascriptContext, worldId: Int) {}
  public func readyToCommitNavigation(frame: UIWebFrame, loader: WebDocumentLoader) {}
  public func willCommitProvisionalLoad(frame: UIWebFrame) {}
  public func onWasShown(frame: UIWebFrame) {}
  public func onWasHidden(frame: UIWebFrame) {}
  public func willHandleMouseEvent(event: WebMouseEvent) {
    
  }
  public func willHandleGestureEvent(event: WebGestureEvent) {
  
  }
  public func willHandleKeyEvent(event: WebKeyboardEvent) {
    //print("TweedyMain: willHandleKeyEvent")
  }
  public func didChangeName(frame: UIWebFrame, name: String) {}
  public func didChangeLoadProgress(frame: UIWebFrame, loadProgress: Double) {}
  public func didChangeContents(frame: UIWebFrame) {}
  
  public func didReceiveResponse(frame: UIWebFrame, response: WebURLResponse) {
    //print("Tweedy.didReceiveResponse: url: \(response.url) status: \(response.httpStatusCode) \(response.httpStatusText) expectedContentLength: \(response.expectedContentLength)")
    receivedResponse = true
  }

  public func willSendRequest(frame: UIWebFrame, request: WebURLRequest) {
    //print("Tweedy.willSendRequest: \(String(describing: request.url))")
  }
  
  public func runScriptsAtDocumentElementAvailable(frame: UIWebFrame) {
    //print("Tweedy.runScriptsAtDocumentElementAvailable")
  }

  public func runScriptsAtDocumentReady(frame: UIWebFrame) {
    //print("Tweedy.runScriptsAtDocumentReady")
  }

  //public func runScriptsAtDocumentIdle(frame: UIWebFrame) {}

  public func runScriptsAtDocumentIdle(frame: UIWebFrame) {
    //print("Tweedy.runScriptsAtDocumentIdle")
    self.document = frame.frame!.document

    html2DCanvas = document.document!.querySelector("#my-canvas").first?.asHtmlCanvas() 
    if html2DCanvas == nil {
      //print("Unable to find my-canvas")
      //return
    }

    //print("Passing offscreen canvas from 2d-canvas so we can use it on the remote service worker width: \(html2DCanvas.width) height: \(html2DCanvas.height)")
    //offscreenCanvas = html2DCanvas.transferControlToOffscreen(window: frame.frame!.window)

    // let canvas = html2DCanvas!.createCanvas()
    // let paintFlags = PaintFlags()
    // paintFlags.color = Color.Red
    // canvas.clearRect(IntRect(x: 0, y: 0, width: html2DCanvas!.width, height: html2DCanvas!.height))
    // canvas.drawRect(rect: FloatRect(x: 0, y: 0, width: Float(html2DCanvas!.width), height: Float(html2DCanvas!.height)), flags: paintFlags)
    //canvas.fillStyle = "green"
    //canvas.fillRect(IntRect(x: 0, y: 0, width: html2DCanvas!.width, height: html2DCanvas!.height))

    /*
     * ServiceWorker
     */

    serviceWorker = frame.frame!.window.navigator.serviceWorker
    //print("worker.register(\"./sw.js\")")
    promise = serviceWorker!.register("./sw.js", type: .native)
    // FIXME: promises should go away
    workerPromise = promise!.then({ [self, serviceWorker] registration in
       //print("service worker registration succeeded")
       self.registration = registration
       workerPromise = nil
     },
     { [self] in
      print("service worker registration failed")
      workerPromise = nil
     })

    availableBtn = self.document.querySelector("#available-button").first
    // corretorDiv = self.document.querySelector("#location-div").first

    //var firstTime = false
    if self.messageChannel == nil {
      self.messageChannel = MessageChannel(window: frame.frame!.window)
      self.messageChannel!.port1.onMessage({ [self] ev in
        print("TweedyMain: receive message on port 1")
        //  resolve(event.data)
        var strMessage: String = ev.dataAsString ?? "<null>"
        if let div = self.document.querySelector("#location-div").first {
          div.innerHTML = strMessage
        } else {
          print("#location-div not found. message was '\(strMessage)'")
        }
      })
      //firstTime = true
    }

    // OffscreenCanvas and Channels

    // if !self.availableBtnClickAdded && availableBtn != nil {
    //   availableBtn?.addEventListener("click", { [self] ev in
    //     if offscreenCanvas == nil {
    //       transferOffscreenCanvas()
    //     } else {
    //       if let wrkr = registration?.active {
    //         // FIXME
    //         wrkr.window = frame.frame!.window
    //         wrkr.postMessage(string: "ola mundo", ports: [])
    //         if !channelConnected {
    //           app!.channelRegistry.connectToChannel(delegate: self, window: frame.frame!.window, scheme: "tweedy", name: "navigator", onChannelConnect)
    //           channelConnected = true
    //         } else {
    //           postMessage("hello")
    //         }
    //       } else {
    //         print("error: service worker registration.active is null")
    //       }
    //     }
    //   })
    //   self.availableBtnClickAdded = true
    // }

    // RPCClient 

    // if !self.availableBtnClickAdded && availableBtn != nil {
    //   availableBtn?.addEventListener("click", { [self] ev in
    //     if offscreenCanvas == nil {
    //        rpcChannel = RpcChannel(address: "127.0.0.1:8081", secure: false)
    //        transferOffscreenCanvas()
    //     } else {
    //       let messageBuilder = Tweedy.ChatMessage.Builder()
    //       messageBuilder.message = "hello world"
    //       let message = try! messageBuilder.build()

    //       let call = try! self.rpcChannel?.makeCall("/tweedy.Tweedy/Say")
    //       try! call?.start(.unary,
    //                       metadata: try! RpcMetadata(),
    //                       message: message.data()) { callResult in
    //         if let messageData = callResult.resultData {
    //           let message = try! Tweedy.ChatMessage.Builder().mergeFrom(codedInputStream: CodedInputStream(data: messageData)).build()
    //           //let messageString = String(data: messageData as Data, encoding: .utf8)
    //           print("'\(message.message!)'")
    //         }    
    //       }
    //     }
    //   })
    
    // }

    // 

    if !self.availableBtnClickAdded && availableBtn != nil {
      availableBtn?.addEventListener("click", { [self] ev in
        rpcChannel = RpcChannel(address: "127.0.0.1:8081", secure: false)
        let messageBuilder = Tweedy.ChatMessage.Builder()
        print("available-button clicked. sending message for app \(String(app!.routingId))") 
        messageBuilder.message = String(app!.routingId)
        let message = try! messageBuilder.build()
        let call = try! self.rpcChannel?.makeCall("/tweedy.Tweedy/Say")
        try! call?.start(.unary,
                        metadata: try! RpcMetadata(),
                        message: message.data()) { callResult in
          if let messageData = callResult.resultData {
            let message = try! Tweedy.ChatMessage.Builder().mergeFrom(codedInputStream: CodedInputStream(data: messageData)).build()
            //let messageString = String(data: messageData as Data, encoding: .utf8)
            if let msg = message.message {
              print("'\(msg)'")
            }
          }    
        }
      })
    
    }

    // WebSocket test

    // if !self.availableBtnClickAdded && availableBtn != nil {
    //   availableBtn?.addEventListener("click", { [self] ev in
    //     let url = "ws://127.0.0.1:6868/ws"
    //     webSocket = WebSocket(delegate: self, document: self.document!)
    //     print("connecting to \(url)")
    //     webSocket!.connect(url: url, protocol: "")
    //   })
    //   self.availableBtnClickAdded = true
    // }

    serviceWorker?.onMessage({ [self] ev in
      print("receive message on service worker general onmessage listener")
      var strMessage: String = ev.dataAsString ?? "<null>"
      self.corretorDiv!.innerHTML = strMessage
    })

    /*
     * Worker
     */

    // availableBtn = self.document.querySelector("#available-button").first
    // corretorDiv = self.document.querySelector("#location-div").first
    
    // if worker == nil {
    //   //worker = WebWorker(window: frame.frame!.window, url: "worker.js")
    //   //worker!.onMessage { [self] ev in
    //   //  print("received message from worker")
    //   // var strMessage: String = ev.dataAsString ?? "<null>"
    //   //  self.corretorDiv!.innerHTML = strMessage
    //   //}
    //   availableBtn?.addEventListener("click", { [self] ev in 
    //     var firstTime = false
    //     if self.messageChannel == nil {
    //       self.messageChannel = MessageChannel(window: frame.frame!.window)
    //       self.messageChannel!.port1.onMessage({ [self] ev in
    //         //  resolve(event.data)
    //         var strMessage: String = ev.dataAsString ?? "<null>"
    //         print("TweedyMain: receive message on port 1: \(strMessage)")
    //         if let div = self.document.querySelector("#location-div").first {
    //           div.innerHTML = strMessage
    //         } else {
    //           print("#location-div not found. message was '\(strMessage)'")
    //         }
    //       })
    //       firstTime = true
    //     }
    //     //self.worker?.postMessage("sw.js")
        
    //     if firstTime {
    //       //self.worker?.postMessage(messages[counter % messages.count], ports: [self.messageChannel!.port2])
    //       print("Passing offscreen canvas from 2d-canvas so we can use it on the remote service worker width: \(html2DCanvas!.width) height: \(html2DCanvas!.height)")
    //       self.offscreenCanvas = self.html2DCanvas!.transferControlToOffscreen(window: frame.frame!.window)
    //       let serializedScriptValue = SerializedScriptValue(
    //           window: frame.frame!.window,
    //           offscreenCanvas: offscreenCanvas!,
    //           ports: [messageChannel!.port2],
    //           arrays: [], 
    //           offscreenCanvases: [offscreenCanvas!], 
    //           imageBitmaps: [])
    //       print("SerializedScriptValue created: posting and destroying local offscreencanvas..")
    //       self.worker?.postSerializedScriptValue(serializedScriptValue)
    //       self.offscreenCanvas = nil
    //     }
    //     // } else {
    //     //   self.worker?.postMessage(messages[counter % messages.count])
    //     // }
    //     //self.worker?.postTask { context in  
    //       //let x = 42 + 2
    //       //print("ola mundo da worker thread: o significado da vida é \(x)")
    //     //}
    //     counter += 1
    //   })
    //   workerHandler = HelloWorker()
    //   worker = WebWorker(window: frame.frame!.window, native: workerHandler!)
    // }
    
    // if let scriptUrl = worker.controller?.scriptUrl {
    //   print("ServiceWorker script url = \(scriptUrl)")
    // } else {
    //   print("ServiceWorkerContainer: no controller")
    // }

    // GL
    guard let htmlCanvas = document.document!.querySelector("#gl-canvas").first?.asHtmlCanvas() else {
      //print("Unable to find gl-canvas")
      return
    }

    // Initialize the GL context
    // guard let gl = canvas.createCanvas3d() else {
    //   print("Unable to initialize WebGL. Your browser or machine may not support it.")
    //   return;
    // }
    // guard let gl = htmlCanvas.createCanvas3d(type: "webgl") else {
    //   print("creating webgl context failed")
    //   return
    // }
    let gl = htmlCanvas.glContext

    // let vertices: [Float] = [-0.5, 0.5, -0.5, -0.5, 0.0, -0.5]
    // // Create a new buffer object
    // let vertexBuffer = gl.createBuffer()
    // // Bind an empty array buffer to it
    // gl.bindBuffer(gl.ARRAY_BUFFER, buffer: vertexBuffer)
    // // Pass the vertices data to the buffer
    // gl.bufferData(gl.ARRAY_BUFFER, data: Float32Array(vertices), usage: gl.STATIC_DRAW)
    // // Unbind the buffer
    // gl.bindBuffer(gl.ARRAY_BUFFER, buffer: nil)

    // // Vertex shader source code
    // let vertCode =
    //   "attribute vec2 coordinates;\n" + 
    //   "void main(void) {\n" + " gl_Position = vec4(coordinates,0.0, 1.0);\n" + "}\n"
    // //Create a vertex shader object
    // let vertShader = gl.createShader(type: gl.VERTEX_SHADER)
    // //Attach vertex shader source code
    // gl.shaderSource(vertShader, source: vertCode)
    // //Compile the vertex shader
    // gl.compileShader(vertShader)
    // //Fragment shader source code
    // let fragCode = "void main(void) {\n" + " gl_FragColor = vec4(0.0, 0.0, 0.0, 0.1);\n" + "}\n"
    // // Create fragment shader object
    // let fragShader = gl.createShader(type: gl.FRAGMENT_SHADER)
    // // Attach fragment shader source code
    // gl.shaderSource(fragShader, source: fragCode)
    // // Compile the fragment shader
    // gl.compileShader(fragShader)
    // // Create a shader program object to store combined shader program
    // let shaderProgram = gl.createProgram()
    // // Attach a vertex shader
    // gl.attachShader(shaderProgram, shader: vertShader) 
    // // Attach a fragment shader
    // gl.attachShader(shaderProgram, shader: fragShader)
    // // Link both programs
    // gl.linkProgram(shaderProgram)
    // // Use the combined shader program object
    // gl.useProgram(shaderProgram)
    // /* Step 4: Associate the shader programs to buffer objects */

    // //Bind vertex buffer object
    // gl.bindBuffer(gl.ARRAY_BUFFER, buffer: vertexBuffer)
    // //Get the attribute location
    // let coord = GLuint(gl.getAttribLocation(program: shaderProgram, name: "coordinates"))
    // //point an attribute to the currently bound VBO
    // gl.vertexAttribPointer(index: coord, size: 2, type: gl.FLOAT, normalized: false, stride: 0, offset: 0)
    // //Enable the attribute
    // gl.enableVertexAttribArray(index: coord)
    // /* Step5: Drawing the required object (triangle) */

    // // Clear the canvas
    // gl.clearColor(r: 0.5, g: 0.5, b: 0.5, a: 0.9)

    // // Enable the depth test
    // gl.enable(gl.DEPTH_TEST)
    
    // // Clear the color buffer bit
    // gl.clear(gl.COLOR_BUFFER_BIT)

    // print("GL: setting viewport to (\(htmlCanvas.width), \(htmlCanvas.height))");
    // // Set the view port
    // gl.viewport(x: 0, y: 0, width: GLsizei(htmlCanvas.width), height: GLsizei(htmlCanvas.height))

    // // Draw the triangle
    // gl.drawArrays(mode: gl.TRIANGLES, first: 0, count: 3)

    // Get the strings for our GLSL shaders
  let vertexShaderSource =
    "  attribute vec4 a_position;" +
    "  void main() {" +
    "    gl_Position = a_position;" +
    "  }"

  let fragmentShaderSource =
    "  precision mediump float;\n" +
    "    void main() {\n" +
    "    gl_FragColor = vec4(1, 0, 0.5, 1);\n" +
    "  }\n"

  let vertexShader = gl.createShader(type: gl.VERTEX_SHADER)
  gl.shaderSource(vertexShader, source: vertexShaderSource)
  gl.compileShader(vertexShader)
  
  let fragmentShader = gl.createShader(type: gl.FRAGMENT_SHADER)
  gl.shaderSource(fragmentShader, source: fragmentShaderSource)
  gl.compileShader(fragmentShader)

  // Link the two shaders into a program
  let program = gl.createProgram()
  gl.attachShader(program, shader: vertexShader)
  gl.attachShader(program, shader: fragmentShader)
  gl.linkProgram(program)
  
  // look up where the vertex data needs to go.
  var positionAttributeLocation = gl.getAttribLocation(program: program, name: "a_position")

  // Create a buffer and put three 2d clip space points in it
  let positionBuffer = gl.createBuffer()

  // Bind it to ARRAY_BUFFER (think of it as ARRAY_BUFFER = positionBuffer)
  gl.bindBuffer(gl.ARRAY_BUFFER, buffer: positionBuffer)

  let positions: [Float] = [
    0, 0,
    0, 0.5,
    0.7, 0,
  ]

  gl.bufferData(gl.ARRAY_BUFFER, data: Float32Array(positions), usage: gl.STATIC_DRAW)

  // code above this line is initialization code.
  // code below this line is rendering code.

  //webglUtils.resizeCanvasToDisplaySize(gl.canvas)
  // Tell WebGL how to convert from clip space to pixels
  gl.viewport(x: 0, y: 0, width: GLsizei(htmlCanvas.width), height: GLsizei(htmlCanvas.height))
  // Clear the canvas
  gl.clearColor(r: 0, g: 0, b: 0, a: 0)
  gl.clear(gl.COLOR_BUFFER_BIT)
  // Tell it to use our program (pair of shaders)
  gl.useProgram(program)
  // Turn on the attribute
  gl.enableVertexAttribArray(index: GLuint(positionAttributeLocation))

  // Bind the position buffer.
  gl.bindBuffer(gl.ARRAY_BUFFER, buffer: positionBuffer)
  gl.vertexAttribPointer(index: GLuint(positionAttributeLocation), size: 2, type: gl.FLOAT, normalized: false, stride: 0, offset: 0)
  gl.drawArrays(mode: gl.TRIANGLES, first: 0, count: 3)

    // END

    guard !eventsHooked else {
      return
    }
    //let context = frame.frame!.mainWorldScriptContext
    btn = self.document.querySelector("#btn").first
    audioBtn = self.document.querySelector("#audio-btn").first
    playBtn = self.document.querySelector("#play-btn").first
    pauseBtn = self.document.querySelector("#pause-btn").first
    sendBtn = self.document.querySelector("#send-btn").first
    // let btnClickOk = btn!.addEventListener("click", { ev in
    //   //print("btn was clicked!. executing..")
    //   self.request = XmlHttpRequest(document: self.document)
    //   self.request.timeout = 120 * (60 * 1000)
    //   self.request.onReadyStateChange { executionContext in
    //   //print("xhr onReadyStateChange: \(self.request.readyState) \(self.request.status)")
    //     if self.request.readyState == .done && self.request.status == 200 {
    //       if let img = self.document.getElementById("image")?.asHtmlImage() {
    //         self.imageElement = img
    //         // using simply responseText and base64
    //         // imageSpan.innerHTML = "<image src=\"data:image/png;base64, \(request.responseText!)\">"
    //         let arrayBuffer = self.request.responseArrayBuffer!
    //         // using responseArrayBuffer and base64 string
    //         self.imageElement!.src = "data:image/jpeg;base64, \(arrayBuffer.base64EncodedString())"
            
    //         // using array buffer and blob
    //         //let uint8Array = arrayBuffer.data!.bindMemory(to: UInt8.self, capacity: Int(arrayBuffer.byteLength))
    //         //let blob = Blob(data: uint8Array, bytes: arrayBuffer.byteLength, contentType: "image/jpeg")
    //         //let imageUrl = URL.createObjectURL(document: document, blob: blob)
    //         //image.src = imageUrl
    //         //if let textfield = doc.getElementById("textme") {
    //         //  textfield.isFocused = true
    //         //  textfield.textContent = "hello world"
    //         //}
    //       } else {
    //         //print("element with id 'image' not found")
    //       }
    //     }
    //   }

    //   self.request.onProgress { ev in
    //     //print("xhr onProgress: total = \(ev.total) loaded: \(ev.loaded)")
    //     if let span = self.document.getElementById("loading") {
    //       let percent = (ev.loaded * 100) / ev.total
    //       span.innerHTML = "\(percent) %"
    //     }
    //   }

    //   self.request.onTimeout { ctx in
    //     //print("xhr onTimeout")
    //     if let span = self.document.getElementById("loading") {
    //       span.innerHTML = span.innerHTML + " aborted!"
    //     }
    //   }

    //   self.request.onError { ctx in
    //     //print("xhr onError")
    //     if let span = self.document.getElementById("loading") {
    //       span.innerHTML = span.innerHTML + " error!"
    //     }
    //   }

    //   self.request.onLoadStart { ctx in
    //     //print("xhr onLoadStart")
    //   }

    //   self.request.onLoadEnd { ctx in
    //     //print("xhr onLoadEnd")
    //   }

    //   let offset = self.moviePosterClicks
    //   let count = self.moviePosterUrls.count
    //   self.request.open(method: .get, url: self.moviePosterUrls[offset % count], async: true)//"tweedy://hello?path=image", async: true)
    //   self.request.responseType = .arrayBuffer
    //   self.request.send()
    //   self.moviePosterClicks += 1
    // })
    
    //print("adding result: btn click ? \(btnClickOk)")

    let selector = frame.frame!.document.querySelector("#editdiv")
    editDiv = selector.first
    if editDiv != nil {
      //print("editdiv found. adding listeners")
      //let keydownOk = editDiv!.addEventListener("keydown", { doc, ev in
      //  //print("editdiv: keydown event")
      //})
      //let keyupOk = editDiv!.addEventListener("keyup", { doc, ev in
      //  //print("editdiv: keyup event")
      //})
      let clickOk = editDiv!.addEventListener("click", { ev in
        //print("editdiv: click event")
        let elemDocument = self.editDiv!.document!
        if let helloDiv = elemDocument.getElementById("hello")?.asHtmlDiv() {
          //print("div 'hello' found. setting innerHTML")
          helloDiv.innerHTML = "ola mundo \(self.counter): event = \(ev.type)" 
          self.counter += 1
        } else {
          //print("div 'hello' not found")  
        }
          //if let editHere = frame.frame!.document.querySelector("#editdiv").first {
          //  editHere.innerHTML = "ola mundo"
          //} //else {
            //print("editdiv not found on click event handler")
          //}
          //print("editdiv: click event")
      })
      //print("adding result: 'click' ? \(clickOk)")
    }
    let textSelector = frame.frame!.document.querySelector("#audio-file")
    let inputElem = textSelector.first
    if inputElem != nil {
      let inputText = inputElem!.asHtmlInput()
      inputText!.value = "file:///home/fabiok/Music/travellers_640x360_1000k_cued.webm"//"http://stream.sfr1.de/audio/8000/musik/Falco%20-%20Der%20Kommissar%20%28Mousse%20T.%20Radio%20Edit%29.mp3"
    }

    //let videoSpan = frame.frame!.document.querySelector("#video-span").first!
    // let videoElement = HtmlVideoElement(document: frame.frame!.document)
    // videoElement.srcObject = MediaStreamDescriptor()
    // videoElement.height = 360
    // videoElement.width = 640
    // //videoElement.src = "https://bitdash-a.akamaihd.net/content/MI201109210084_1/m3u8s/f08e80da-bf1d-4e3d-8899-f0f6155f6efa.m3u8"
    // //videoElement.src = "file:///home/fabiok/Downloads/filmes/Showgirls (1995)/Showgirls.1995.720p.BluRay.x264.YIFY.mp4"
    // videoSpan.appendChild(videoElement)
    
    /*
     * Audio
     */
    guard let videoSpan = frame.frame!.document.querySelector("#video-span").first else {
      return
    }
    //self.audioElement = HtmlAudioElement(document: frame.frame!.document)
    self.videoElement0 = HtmlVideoElement(document: frame.frame!.document)
    videoSpan.appendChild(self.videoElement0)//audioElement)
    //let audioMime = "audio/mpeg"
    let audioMime = "video/webm; codecs=\"vp9\""

    audioBtn!.addEventListener("click", { [self] ev in
      self.audioMediaSource = MediaSource(document: self.document)
      //self.audioElement.src = Url.createObjectURL(document: self.document, source: self.audioMediaSource!)
      self.videoElement0.src = Url.createObjectURL(document: self.document, source: self.audioMediaSource!)
      self.audioMediaSource!.onSourceOpen { [self] openEv in
        //print("MediaSource.onSourceOpen called")
        self.sourceBuffer = self.audioMediaSource!.addSourceBuffer(type: audioMime)
        self.mdRequest = XmlHttpRequest(document: self.document)
        self.mdRequest.onReadyStateChange { executionContext in
          //print("mdRequest.onReadyStateChange: state = \(self.mdRequest.readyState) status = \(self.mdRequest.status)")
          if ((self.mdRequest.readyState == .loading || self.mdRequest.readyState == .done) && self.mdRequest.status == 200) || 
              self.mdRequest.readyState == .done && self.mdRequest.status == 0 {
            if let arrayBuffer = self.mdRequest.responseArrayBuffer {
              //print("mdRequest.onReadyStateChange: done -> arrayBuffer len: \(arrayBuffer.byteLength)")
              self.sourceBuffer.appendBuffer(data: arrayBuffer)
            }
            self.sourceBuffer.onUpdateStart { openEv in
              //print("sourceBuffer.onUpdateStart")
            }
            self.sourceBuffer.onUpdate { openEv in
              //print("sourceBuffer.onUpdate")
            }
            self.sourceBuffer.onUpdateEnd { [self] openEv in
              //print("sourceBuffer.onUpdateEnd")
              //self.audioMediaSource!.endOfStream()
              if !self.isPlaying {
                //self.audioElement.play()
                self.videoElement0.play()
                self.isPlaying = true
              }
              //self.mdRequest.open(method: .get, url: "tweedy://hello?path=mp3", async: true)
              //self.mdRequest.responseType = .arrayBuffer
              //self.mdRequest.send()
            }
          }
        }
        self.mdRequest.onProgress { ev in
          //print("xhr onProgress: total = \(ev.total) loaded: \(ev.loaded)")
        }
        //self.mdRequest.open(method: .get, url: "tweedy://greetings?path=mp3", async: true)
        //self.mdRequest.open(method: .get, url: "tweedy://hello?path=mp3", async: true)
        //self.mdRequest.open(method: .get, url: "https://www.avplay.com.br/musicas/playlists/graalpaloma/15%20-%20Technotronic%20-%20Move%20This.mp3") 
        let inputText = frame.frame!.document.querySelector("#audio-file").first!.asHtmlInput()
        self.mdRequest.open(method: .get, url: inputText!.value)
        self.mdRequest.responseType = .arrayBuffer
        self.mdRequest.send()
      }
    })

    // playBtn!.addEventListener("click", { [self] ev in
    //   //print("play")
    //   //if !self.isPlaying {
    //     self.audioElement.play()
    //   //  self.isPlaying = true
    //   //}
    // })

    // pauseBtn!.addEventListener("click", { [self] ev in
    //   //print("pause")
    //   //if self.isPlaying {
    //     self.audioElement.pause()
    //   //  self.isPlaying = false
    //   //}
    // })

    /*
     * End Audio
     */

    /*
     * Stream Video
     */

    // let videoSpan = frame.frame!.document.querySelector("#video-span").first!
    // self.videoElement = HtmlVideoElement(document: frame.frame!.document)
    // self.videoElement.width = 640
    // //self.videoElement.height = 360 
    // videoSpan.appendChild(videoElement)
    // //let mime = "video/mp4; codecs=\"avc1.42001e\""
    // let mime = "video/webm; codecs=\"vorbis,vp9\""
    // btn!.addEventListener("click", { [self] ev in
    //   self.videoMediaSource = MediaSource(document: self.document)
    //   self.videoElement.src = Url.createObjectURL(document: self.document, source: self.videoMediaSource!)
    //   self.videoMediaSource!.onSourceOpen { [self] openEv in
    //     //print("MediaSource.onSourceOpen called")
    //     self.sourceBuffer = self.videoMediaSource!.addSourceBuffer(type: mime)
    //     // TODO: add SourceBufferList to MediaSource
    //     self.sourceBuffer.onUpdateStart { openEv in
    //       //print("sourceBuffer.onUpdateStart")
    //     }
    //     self.sourceBuffer.onUpdate { openEv in
    //       //print("sourceBuffer.onUpdate")
    //     }
    //     self.sourceBuffer.onUpdateEnd { [self] openEv in
    //       //print("sourceBuffer.onUpdateEnd: currentSegment = \(currentSegment)")
    //       defer {
    //         self.currentSegment += 1
    //       }
    //       //self.videoMediaSource!.endOfStream()//error: "decode")
    //       if !self.isPlaying {
    //         self.videoElement.play()
    //         self.isPlaying = true
    //       }
    //       if self.currentSegment == 5 {
    //         //print("sourceBuffer.onUpdateEnd: calling endOfStream()")
    //         self.videoMediaSource!.endOfStream()
    //       }

    //       if self.currentSegment <= 4 {
    //         self.videoUrl = "media_000" + String(currentSegment) + ".segment"
    //         self.mdRequest.open(method: .get, url: "tweedy://hello?path=" + self.videoUrl, async: true)//"https://data.mohistory.org/molabplugins/videoviewer/tina.mp4")
    //         self.mdRequest.responseType = .arrayBuffer
    //         self.mdRequest.send()
    //       }
    //     }
    //     self.mdRequest = XmlHttpRequest(document: self.document)
    //     self.mdRequest.onReadyStateChange { executionContext in
    //       //print("mdRequest.onReadyStateChange: state = \(self.mdRequest.readyState) status = \(self.mdRequest.status)")
    //       if self.mdRequest.readyState == .done && self.mdRequest.status == 200 {
    //         if let arrayBuffer = self.mdRequest.responseArrayBuffer {
    //           //print("mdRequest.onReadyStateChange: done -> arrayBuffer len: \(arrayBuffer.byteLength)")
    //           self.sourceBuffer.appendBuffer(data: arrayBuffer)
    //         }
    //       }
    //     }
    //     self.mdRequest.onProgress { p in
    //       //print("xhr onProgress: total = \(p.total) loaded: \(p.loaded)")
    //       if let span = self.document.getElementById("loading") {
    //         guard p.total >= p.loaded else {
    //           return
    //         }
    //         let percent = (p.loaded * 100) / p.total
    //         span.innerHTML = "\(percent) %"
    //       }
    //     }
    //     //self.mdRequest.open(method: .get, url: "tweedy://greetings?path=mp3", async: true)
    //     //self.mdRequest.open(method: .get, url: "tweedy://hello?path=mp3", async: true)
    //     self.videoUrl = "init.segment"
    //     self.mdRequest.open(method: .get, url: "tweedy://hello?path=" + self.videoUrl, async: true)//"https://data.mohistory.org/molabplugins/videoviewer/tina.mp4")
    //     self.mdRequest.responseType = .arrayBuffer
    //     self.mdRequest.send()
    //   }
    // })
    /*
     * End Stream Video
     */

     /*
      * Video
      */

    //if let videoEl = frame.frame!.document.querySelector("#player").first {
    //  self.videoElement = videoEl.asHtmlVideo()
    //} else {
      //let videoSpan = frame.frame!.document.querySelector("#video-span").first!
      self.videoElement = HtmlVideoElement(document: frame.frame!.document)
      let _ = videoSpan.appendChild(videoElement)
      self.videoElement.width = 640
      //videoSpan.width = 640
    //}
    // works for sintel.mp4, Dark's ghosts.mp4 tina.mp4
    //let mime = "video/mp4; codecs=\"avc1.64001f, mp4a.40.2\""
    // sintel.webm fragmented
    let mime = "video/webm; codecs=\"vorbis,vp9\""
   
    //let mime = "video/webm; codecs=\"vorbis,vp8\""
    btn!.addEventListener("click", { [self] ev in
      self.videoMediaSource = MediaSource(document: self.document)
      self.videoElement.src = Url.createObjectURL(document: self.document, source: self.videoMediaSource!)
      self.videoMediaSource!.onSourceOpen { [self] openEv in
        //print("MediaSource.onSourceOpen called")
        self.sourceBuffer = self.videoMediaSource!.addSourceBuffer(type: mime)
        // TODO: add SourceBufferList to MediaSource
        self.sourceBuffer.onUpdateStart { openEv in
          //print("sourceBuffer.onUpdateStart")
        }
        self.sourceBuffer.onUpdate { openEv in
          //print("sourceBuffer.onUpdate")
        }
        self.sourceBuffer.onUpdateEnd { [self] openEv in
          //print("sourceBuffer.onUpdateEnd")
          if counter == 1 {
            //print("playing..")
            self.videoElement.play()
          }
          if counter == 5 {
            //print("closing..")
            self.videoMediaSource!.endOfStream()
            counter = 0
            return
          }
          fetch(url: "tweedy://resources?path=webm/media_00" + FormatNumber(counter) + ".segment",  { [self] (arrayBuffer: ArrayBuffer) in
            //print("mdRequest.onReadyStateChange: done -> arrayBuffer len: \(arrayBuffer.byteLength)")
            self.sourceBuffer.appendBuffer(data: arrayBuffer)
            self.counter += 1
          })
        }
        fetch(url: "tweedy://resources?path=webm/init.segment", { [self] (arrayBuffer: ArrayBuffer) in
          //print("mdRequest.onReadyStateChange: done -> arrayBuffer len: \(arrayBuffer.byteLength)")
          self.sourceBuffer.appendBuffer(data: arrayBuffer)
        })
      }
    })

    playBtn!.addEventListener("click", { [self] ev in
      //print("play")
      //if !self.isPlaying {
        self.videoElement.play()
      //  self.isPlaying = true
      //}
    })

    pauseBtn!.addEventListener("click", { [self] ev in
      //print("pause")
      //if self.isPlaying {
        self.videoElement.pause()
      //  self.isPlaying = false
      //}
    })

    sendBtn!.addEventListener("click", { [self] ev in 
      self.chatRequest = XmlHttpRequest(document: self.document)
      self.chatRequest.onReadyStateChange { executionContext in
        //print("chatRequest.onReadyStateChange: state = \(self.chatRequest.readyState) status = \(self.chatRequest.status)")  
        if self.chatRequest.readyState == .done && self.chatRequest.status == 200 ||
           self.chatRequest.readyState == .loading && self.chatRequest.status == 200 {
          //if let arrayBuffer = self.chatRequest.responseArrayBuffer {
          if let rtext = self.chatRequest.responseText {  
            //let rtext = String(bytesNoCopy: arrayBuffer.data!, length: Int(arrayBuffer.byteLength), encoding: String.Encoding.utf8, freeWhenDone: true)!
            //let rtext = String(cString: arrayBuffer.data!.bindMemory(to: Int8.self, capacity: Int(arrayBuffer.byteLength)), encoding: String.Encoding.utf8)!
            //print("received text: \(rtext)")
            let messageDiv = frame.frame!.document.querySelector("#chat-result").first!
            //var text = messageDiv.innerHTML
            //print("inner html: '\(text)'")
            //text = text + "<div>" + rtext + "</div>\n"
            messageDiv.innerHTML = "<div>" + rtext + " " + String(counter) + "</div>\n"//text
            counter += 1
          }
        }
      }
      let inputText = frame.frame!.document.querySelector("#chat-message").first!.asHtmlInput()
      self.chatRequest.open(
        method: .get,
        //url: "rpc://localhost/say?message=" + NSString(string: inputText!.value).addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed)!
        url: "tweedy://say?message=" + NSString(string: inputText!.value).addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed)!
        //url: "file:///home/fabiok/documents/ola.txt"
      )
      self.chatRequest.responseType = .text
      self.chatRequest.send()
    })


    eventsHooked = true
  }

  public func focusedNodeChanged(frame: UIWebFrame, node: WebNode?) {
    //print("TweedyMain.focusedNodeChanged")
  }

  // private func createImageView(imageData: UnsafeMutablePointer<UInt8>?, bytesSize: Int, size: IntSize) -> ImageView {
  //   let codec = PNGCodec()
  //   //imageBitmap = codec.decode(imageData, size: bytesSize)!
  //   image = ResourceBundle.getImage(15090) //ImageSkia(bitmap: imageBitmap!)
  //   imageView = ImageView(image: image!)
  //   //imageView!.layer = try! Layer(type: .Textured)
  //   //imageView!.layer!.masksToBounds = true
  //   //imageView!.layer!.fillsBoundsOpaquely = true
  //   //imageView.layer!.background = Color.Red
  //   //imageView!.layer!.delegate = imageView
  //   //imageView.text = "hello"
  //   //print("createImageView: image size (\(image!.size.width),\(image!.size.height))")
  //   imageView!.size = image!.size
  //   imageView!.imageSize = image!.size
  //   return imageView!
  // }

  private func createImageView() -> ImageView {
    //let codec = PNGCodec()
    //var imageData: UnsafePointer<UInt8>?
    //var bytesSize: Int = 0
    //let _ = ResourceBundle.getRawData(15090, bytes: &imageData, bytesSize: &bytesSize) //ImageSkia(bitmap: imageBitmap!)
    //imageBitmap = codec.decode(imageData, size: bytesSize)!
    //image = ImageSkia(bitmap: imageBitmap!)
    image = ResourceBundle.getImage(15090)!
    imageView = ImageView(image: self.image!)
    //print("\ncreateImageView: image size (\(self.image!.size.width),\(self.image!.size.height))")
    imageView!.size = IntSize(self.image!.size)
    imageView!.imageSize = IntSize(self.image!.size)
    return imageView!
  }

  private func fetch(url: String, _ cb: @escaping (_ : ArrayBuffer) -> Void) { 
    self.mdRequest = XmlHttpRequest(document: self.document)
    self.mdRequest.onReadyStateChange { executionContext in
      //print("mdRequest.onReadyStateChange: state = \(self.mdRequest.readyState) status = \(self.mdRequest.status)")
      if (self.mdRequest.readyState == .done && self.mdRequest.status == 200) || (self.mdRequest.readyState == .done && self.mdRequest.status == 0) {
        if let arrayBuffer = self.mdRequest.responseArrayBuffer {
          cb(arrayBuffer)
        }
      }
    }
    self.mdRequest.onProgress { p in
      //print("xhr onProgress: total = \(p.total) loaded: \(p.loaded)")
      if let span = self.document.getElementById("loading") {
        guard p.total >= p.loaded else {
          return
        }
        let percent = (p.loaded * 100) / p.total
        span.innerHTML = "\(percent) %"
      }
    }
    self.mdRequest.open(
      method: .get, 
      //url: "file:///workspace/mumba/lib/media/test/data/tulip2.webm", 
      //url: "file:///workspace/mumba/lib/media/test/data/bbb-320x240-2video-2audio.mp4",
      //url: "file:///home/fabiok/Downloads/Dark%20S02%20Season%2002%20Complete%20720p%20WEB-DL%20x264-XpoZ/ghosts.mp4",
      //url: "file:///home/fabiok/sintel.mp4",
      url: url,
      async: true)//"https://data.mohistory.org/molabplugins/videoviewer/tina.mp4")
    self.mdRequest.responseType = .arrayBuffer
    self.mdRequest.send()
  }

  private func renderPage(canvas: CanvasRenderingContext2d) {
    //print("renderView: getting displayItemList")
    let displayList = canvas.displayItemList!
    let rect = viewRect
    let view = mainView
    //print("renderPage: calling renderView")
    self.renderView(view, displayList: displayList, rect: rect)
  }

  private func renderView(_ target: View, displayList: DisplayItemList, rect invalidation: IntRect) {
    //print("renderView: calling onPaintLayer")
    //displayList.endPaintOfPairedBegin()
    target.onPaintLayer(context: PaintContext(
      list: displayList, 
      scaleFactor: 1.0, 
      invalidation: invalidation, 
      isPixelCanvas: false//,
      //externalDisplayList: true
    ))
    //print("---- renderView: Rect(\(invalidation.width),\(invalidation.height)) returning a display item list with \(displayList!.totalOpCount) ops")
    
    // In the case we are 'borrowing' the DisplayItemList from the 
    // canvas context, we dont need to do this as it will be done internally
    // by cc::PaintRecorder/cc::(Recorder)PaintCanvas and the web Canvas context

    // We just need to fill the display list with our content
    //displayList.startPaint()
    //displayList.finalize()
    //canvas.drawPicture(record: displayList.releaseAsRecord())
  }

  private func renderLabel(_ target: Label, canvas: Canvas, rect invalidation: IntRect) {
    canvas.save()
    target.onPaint(canvas: canvas)
    canvas.restore()
  }

  private func transferOffscreenCanvas() {
    let frame = webWindow!.mainFrame!.frame!
    if let wrkr = registration?.active {
      // FIXME
      wrkr.window = frame.window
      self.offscreenCanvas = self.html2DCanvas!.transferControlToOffscreen(window: frame.window)
      let serializedScriptValue = SerializedScriptValue(
          window: frame.window,
          offscreenCanvas: offscreenCanvas!,
          ports: [messageChannel!.port2],
          arrays: [], 
          offscreenCanvases: [offscreenCanvas!], 
          imageBitmaps: [])
      //self.worker?.postSerializedScriptValue(serializedScriptValue)
      wrkr.postMessage(serializedScriptValue: serializedScriptValue)
      //self.offscreenCanvas = nil
      // let serializedScriptValue = SerializedScriptValue(
      //   window: frame.window,
      //   string: "ola mundo",
      //   ports: [messageChannel!.port2])
      // print("SerializedScriptValue created: posting")
      // wrkr.postMessage(serializedScriptValue: serializedScriptValue)
      // print("Service worker message posted")
    } else {
      print("error: service worker registration.active is null")
    }
  }

  public func buttonPressed(sender: Button, event: Graphics.Event) { }

  // WebSocketDelegate

  public func onConnect(subprotocol: String, extensions: String) {
    print("websocket: connected. subprotocol = \(subprotocol) extensions = \(extensions)")
    webSocket!.send(text: "Ola mundo");
  }
  
  public func onReceiveTextMessage(_ t: String) {
    print("websocket: received text: '\(t)' => now closing connection..")
    webSocket!.close(code: 200, reason: "bye")
  }
  
  public func onReceiveBinaryMessage(_: Data) {
    print("websocket: received binary message")
  }
  
  public func onError() {
    print("websocket: error")
  }
  
  public func onConsumeBufferedAmount(consumed: UInt64) {
    print("websocket: onConsumeBufferedAmount consumed = \(consumed)")
  }
  
  public func onStartClosingHandshake() {
    print("websocket: onStartClosingHandshake")
  }
  
  public func onClose(status: ClosingHandshakeCompletionStatus, code: UInt16, reason: String) {
    print("websocket: onClose: code \(code) reason: \(reason)")
  }

  public func onMessage(message: SerializedScriptValue) {
    //if let str = message.stringValue {
      //print("App: channel => '\(str)'")
    //}
  }

  private func onChannelConnect(_ client: ChannelClient?) {
    if client != nil {
      print("TweedyMain: channel 'tweedy:navigator' connected sucesfully")
      channelHost = client!
    } else {
      print("TweedyMain: failed the connection to channel 'tweedy:navigator'")
    }
  }

  public func postMessage(_ string: String) {
    channelHost!.postMessage(string)
  }

}

let app = TweedyApp()
app.run()

fileprivate func loadDoguinho(_ name: String, size: inout Int) -> UnsafeMutablePointer<UInt8>? {
  let buf = malloc(36163)
  var fd: Int32 = -1
  name.withCString {
    fd = open($0, O_RDONLY)
  }
  assert(fd != -1)
  let readed = read(fd, buf, 36163)
  size = readed
  close(fd)
  //(buf! + 121200).storeBytes(of: 0, as: Int32.self)
  //print("loadBootstrap:\n\(data)")
  return buf!.bindMemory(to: UInt8.self, capacity: size)
}

