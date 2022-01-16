// Copyright (c) 2022 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/bundle/bundle_creator.h"

#include "base/sha1.h"
#include "base/task_scheduler/post_task.h"
#include "base/base_paths.h"
#include "base/path_service.h"
#include "base/command_line.h"
#include "base/at_exit.h"
#include "base/files/file_util.h"
#include "base/rand_util.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_util.h"
#include "core/host/bundle/bundle_utils.h"
#include "core/host/workspace/workspace.h"
#include "core/host/bundle/bundle_model.h"
#include "core/host/bundle/bundle_creator.h"
#include "core/host/bundle/bundle_utils.h"
#include "core/host/share/share_database.h"
#include "core/host/bundle/bundle.h"
#include "storage/storage_utils.h"
#include "third_party/msix/src/inc/public/AppxPackaging.hpp"
#include "third_party/msix/src/inc/shared/ComHelper.hpp"
#include "third_party/msix/src/inc/internal/StringStream.hpp"
#include "third_party/msix/src/inc/internal/VectorStream.hpp"

namespace host {

namespace {

std::vector<std::string> libraries = {
  "natives_blob.bin",
  "snapshot_blob.bin",
  "icudtl.dat",
  "icudtl55.dat",
};

const char kDEFAULT_BIN_MANIFEST[] = R"(<?xml version="1.0" encoding="utf8" ?>
<Package xmlns="http://schemas.microsoft.com/appx/2010/manifest">
  <Identity Name="__NAME__" 
     Version="0.0.0.1" 
     Publisher="CN=__NAME__, O=__NAME__, L=SanFrancisco, S=California, C=US" 
     ProcessorArchitecture="x64"/>
  <Properties>
    <DisplayName>__NAME__</DisplayName>
    <PublisherDisplayName>__NAME__</PublisherDisplayName>
    <Logo>images\icon-180x180.png</Logo>
  </Properties>
  <Prerequisites>
    <OSMinVersion></OSMinVersion>
    <OSMaxVersionTested></OSMaxVersionTested>
  </Prerequisites>
  <Resources>
    <Resource Language="en-us" />
  </Resources>
   <Dependencies>
    <TargetDeviceFamily Name="Linux.All" MinVersion="0.0.0.0" MaxVersionTested="0.0.0.0"/>
  </Dependencies>
  <Applications>
  <Application Id="__NAME__" Executable="__NAME__" StartPage="/">
    <VisualElements DisplayName="__NAME__" Description="application" 
         Logo="images\apple-icon-180x180.png" ForegroundText="dark" BackgroundColor="#FFFFFF" >
      <SplashScreen Image="images\splash.png" />
    </VisualElements>
  </Application>
</Applications>
</Package>)";

const char kDEFAULT_DOTGN_FILE[] = R"(
  import("//build/dotfile_settings.gni")
  buildconfig = "//build/config/BUILDCONFIG.gn"
)";

const char kDEFAULT_SWIFT_APPLICATION_BUILD_FILE[] = R"(
  swift_executable("__NAME___app") {
    deps = [
      "//resources/proto:__CAMELCASENAME__Api",
      "//runtime/MumbaShims",
      "//kit/swift/Base",
      "//kit/swift/Graphics",
      "//kit/swift/Data",
      "//kit/swift/Channel",
      "//kit/swift/App:Application",
      "//kit/swift/Compositor",
      "//kit/swift/Gpu",
      "//kit/swift/X11",
      "//kit/swift/Platform",
      "//kit/swift/App:Text",
      "//kit/swift/GL",
      "//kit/swift/App:UI",
      "//kit/swift/_C",
      "//kit/swift/Media",
      "//kit/swift/PDF",
      "//kit/swift/Web",
      "//kit/swift/Net",
      "//kit/swift/Engine",
      "//kit/swift/Service",
      "//kit/swift/Channel",
      "//kit/swift/Javascript",
      "//kit/swift/PosixShim",
      "//kit/swift/Route",
      "//kit/swift/ThirdParty/Libevent",
      "//kit/swift/ThirdParty/icu4c:icuuc",
      "//kit/swift/ThirdParty/icu4c:icui18n",
      "//kit/swift/ThirdParty/ProtocolBuffers",
      "//kit/swift/ThirdParty/CGRPCZlib",
      "//third_party/pytorch",
    ]
    sources = [
      "Sources/__CAMELCASENAME__Main.swift",
    ]
    ldflags = [
      "-licudataswift",
      "-licui18nswift",
      "-licuucswift",
      "-lffi"
    ]
  }

  executable("__NAME__") {
    output_name = "__NAME__"
    configs -= [ "//build/config/clang:find_bad_constructs" ]
    configs -= [ "//build/config/compiler:chromium_code" ]
    
    cflags = []
    cflags_cc = []
    defines = []

    sources = [
      "//kit/cpp/launcher/launcher.cc"
    ]
    deps = [
      ":__NAME___app",
      "//kit/cpp/launcher"
    ]
    cflags = [
      "-Wno-unused-variable"
    ]
    ldflags = [
      "-lz"
    ]
  }
)";

const char kDEFAULT_SWIFT_SERVICE_BUILD_FILE[] = R"(
  swift_shared("__NAME___service") {
    deps = [
      "//resources/proto:__CAMELCASENAME__Api",
      "//kit/swift/Base",
      "//kit/swift/Graphics",
      "//kit/swift/App",
      "//kit/swift/Net",
      "//kit/swift/Data",
      "//kit/swift/Engine",
      "//kit/swift/Channel",
      "//kit/swift/Javascript",
      "//kit/swift/Python",
      "//kit/swift/Service",
      "//kit/swift/PosixShim",
      "//kit/swift/Compositor",
      "//kit/swift/Route",
      "//kit/swift/Web",
      "//kit/swift/PDF",
      "//kit/swift/Gpu",
      "//kit/swift/GL",
      "//kit/swift/_C",
      "//kit/swift/ThirdParty/ProtocolBuffers",
      "//kit/swift/ThirdParty/Libevent",
      "//kit/swift/ThirdParty/icu4c:icuuc",
      "//kit/swift/ThirdParty/icu4c:icui18n",
      "//kit/swift/ThirdParty/CGRPCZlib",
      "//third_party/zlib",
      "//third_party/python"
    ]
    sources = [
      "Sources/Engine/__CAMELCASENAME__Handlers.swift",
      "Sources/Engine/__CAMELCASENAME__Service.swift"
    ]
    ldflags = [
      "-lffi",
    ]
  }
)";

const char kDEFAULT_SWIFT_PROTO_BUILD_FILE[] = R"(
  swift_protobuf("__CAMELCASENAME__Api") {
    deps = [
      "//kit/swift/Base",
      "//kit/swift/Net",
      "//kit/swift/Engine",
      "//kit/swift/Web",
      "//kit/swift/Compositor",
      "//kit/swift/Gpu",
      "//kit/swift/GL",
      "//kit/swift/_C",
    ]
    sources = [
      "Sources/Api/__CAMELCASENAME__.proto"
    ] 
  }
)";

const char kDEFAULT_SWIFT_MAIN_BUILD_FILE[] = R"(
  action("__NAME___bundle") {
    script = "//tools/bundle.py"
    deps = [
      "//apps/app:__NAME___app", 
      "//apps/service:__NAME___service"
    ]
    out_dir = rebase_path("//")
    args = [
      "__NAME__",
      "$out_dir",
    ]
    outputs = [
      "$out_dir/__NAME__/__NAME__.bundle",
      "$out_dir/__NAME__/__NAME___resources.appx",
    ]
    if (current_os == "linux") {
      outputs += [
        "$out_dir/__NAME__/__NAME___app-linux-x64.appx",
        "$out_dir/__NAME__/__NAME___service-linux-x64.appx"
      ]
    }
  }
)";

const char kDEFAULT_SWIFT_HELLO_PROTO[] = R"(
  syntax = "proto3";

  package __NAME__;

  message ChatMessage {
    string message = 1;
  }

  service __CAMELCASENAME__ {
    rpc Say(ChatMessage) returns (stream ChatMessage);
  }
)";

const char kDEFAULT_SWIFT_HELLO_SERVICE_HANDLER[] = R"( 
  import Base
  import Net
  import Engine
  import Data
  import Foundation
  import Python
  import __CAMELCASENAME__Api
  import ProtocolBuffers
  import SwiftGlibc
  import Route

  public class HelloHandler : RouteHandler {
    
    public var entry: RouteEntry
    public let message: String("Hello World")
  
    public init() {
      entry = RouteEntry(
        type: .Entry, 
        transportType: .Ipc, 
        transportMode: .Unary, 
        scheme: "__NAME__", 
        name: "hello", 
        title: "Hello World", 
        contentType: "text/html")
    }
    
    public func getRawBodyBytes(url: String) -> Int64 {
      return Int64(message.count)
    }

    public func getExpectedContentSize(url: String) -> Int64 {
      return Int64(message.count)
    }

    public func getResponseHeaders(url: String) -> String { 
      // fixed for now
      return String("HTTP 1.1 200 OK\n\nContent-Length: \(Int64(message.count))\n Content-Type: \(self.contentType); charset=UTF-8")
    }

    public func onResponseStarted(request: RouteRequest, info: RouteResponseInfo, completion: RouteCompletion?) {
      guard let complete = completion else {
        return
      } 
      complete(0)
    }

    public func read(request: RouteRequest, buffer: UnsafeMutableRawPointer?, maxBytes: Int, completion: RouteCompletion) {
      if request.readSize == 0 {
        // you can copy as much as `maxBytes` allows
        // the "hello world" message is way bellow the buffer limit
        // so we dont need to check on it
        // (but for more serious stuff, always keep your writes inside the buffer limit)
        message.withCString {
          memcpy(buffer!, $0, message.count)
        }
        completion(message.count)
        return
      }
      // returning 0, means theres nothing left to read
      // failing to do so when theres nothing else to read
      // will lead into a endless read loop
      // (which can be ok in case of streaming stuff, but you will need
      //  to use something like `fetch()` on the client so it uses 
      //  a `ThreadableDocumentLoader` on blink side that are meant for this kind of stuff)
      //  also: other cases like websocket and RTC could be adapted to re-use this
      //  maybe: XMLHTTPRequest can support streaming from this
      completion(0)
    }
  }
)";

const char kDEFAULT_SWIFT_HELLO_SERVICE_CONTEXT[] = R"(
  import Base
  import Engine
  import __CAMELCASENAME__Api
  import Net
  import Data
  import Graphics
  import Route

  public class __CAMELCASENAME__Context : EngineContext,
                                          StorageDelegate,
                                          ApplicationInstanceObserver,
                                          RouteRequestHandlerDelegate {

    public var storage: Storage {
      return _storage!
    }

    public var routeCount: Int { 
      return routes.count ?? 0
    }

    private var server: ServiceServer?
    private var _storage: Storage?
    private var requests: [Int: __CAMELCASENAME__RouteRequestHandler] = [:]
    
    public override init() {
      super.init()
      let routeMap = makeRoutes {
        Route("/hello", { return HelloHandler() })
      }
      routes.bind(routeMap)
    }

    open override func onInit(containerContext: ContainerContext) {
      _storage = createStorage(delegate: self)
      super.initialize(containerContext: containerContext, routeRequestHandler: self)
      server = try! ServiceServer(port: 8081, serviceProviders: [self])
      server!.start()
    }

    open override func onShutdown() {
      super.shutdown()
    }

    open override func onApplicationInstanceLaunched(instance: ApplicationInstance) {
      print("__CAMELCASENAME__Context: application was launched sucessfully. id: \(instance.id) name: \(instance.name) url: \(instance.url)\n")
      instance.addObserver(self)
    }

    open override func onApplicationInstanceLaunchFailed(status: Engine.Status, instance: ApplicationInstance) {
      print("__CAMELCASENAME__Context: application \(instance.id): \(instance.name) launch failed")
    }
    
    open override func onApplicationInstanceKilled(status: Engine.Status, instance: ApplicationInstance) {
      print("__CAMELCASENAME__Context: application \(instance.id): \(instance.name) was killed")
    }

    open override func onApplicationInstanceClosed(status: Engine.Status, instance: ApplicationInstance) {
      //print("__CAMELCASENAME__Context: application \(instance.id): \(instance.name) was closed")
    }

    open override func onApplicationInstanceActivated(instance: ApplicationInstance) {
      print("__CAMELCASENAME__Context: application \(instance.id): \(instance.name) was activated")
    }

    public func getRouteHeader(url: String) -> String {
      guard var handler = getRouteHandler(url: url) else {
        return String()
      }
      return handler.getResponseHeaders(url: url)
    }
    
    public func createRequestHandler(id: Int, url: String) -> RouteRequestHandler {
      let request = __CAMELCASENAME__RouteRequestHandler(context: self, id: id, url: url)
      requests[id] = request
      return request
    }

    public func getRouteHandler(url: String) -> RouteHandler? {
      var route = String(url[url.index(url.firstIndex(of: "/")!, offsetBy: 2)..<url.endIndex])
      route = "/" + String(route[route.startIndex..<route.firstIndex(of: "/")!])
      let handler = routes.handler(at: route)
      return handler
    }

    public func lookupRoute(path: String) -> RouteEntry? {
      print("__CAMELCASENAME__Context.lookupRoute => path:\(path) ")
      guard let handler = routes.handler(at: path) else {
        // if you want to create a route that is not registered
        // at the service init, but at runtime, you can do it so
        // like this

        // if path == "/hello" {  
        //   var greet = HelloHandler(context: self)
        //   greet.path = path
        //   greet.url = "__NAME__:/" + path
        //   routes.bind(path, greet)
        //   return greet.entry
        // }
        return nil
      }
      return handler.entry
    }
    
    public func lookupRoute(url: String) -> RouteEntry? {
      print("__CAMELCASENAME__Context.lookupRoute => url: \(url) ")
      guard let handler = routes.handler(at: url) else {
        // if you want to create a route that is not registered
        // at the service init, but at runtime, you can do it so
        // like this
        // if url == "__NAME__://hello" {  
        //   var greet = HelloHandler(context: self)
        //   greet.path = url
        //   greet.url = url
        //   routes.bind(url, greet)
        //   return greet.entry
        // }
        return nil
      }
      return handler.entry
    }
    
    public func lookupRoute(uuid: String) -> RouteEntry? {
      print("__CAMELCASENAME__Context.lookupRoute => uuid:\(uuid) ")
      return nil
    }
    
    public func onComplete(id: Int, status: Int) {
      print("__CAMELCASENAME__Context.onComplete: id: \(id) ")
    }

    public func getRequestHandler(id: Int) -> RouteRequestHandler? {
      return requests[id]
    }

    // RPC method call
    public func say(callId: Int, request: __CAMELCASENAME__.ChatMessage, session: __NAME_____CAMELCASENAME__SaySession) throws -> ServerStatus? {
      let msg = __CAMELCASENAME__.ChatMessage.getBuilder()
      // just pinging back the same message
      msg.message = "you have said: " + request.message
      try session.send(try msg.build(), callId: callId)
      try session.close(callId: callId, withStatus: .ok, completion: nil)
      return .ok
    }

    open func onShareDHTAnnounceReply(uuid: String, peers: Int) {
      print("__CAMELCASENAME__Context.onShareDHTAnnounceReply: \(uuid) peers: \(peers) ")
    }
    open func onShareMetadataReceived(uuid: String) {
      print("__CAMELCASENAME__Context.onShareMetadataReceived: \(uuid) ")
    }
    open func onShareMetadataError(uuid: String, error: Int) {
      print("__CAMELCASENAME__Context.onShareMetadataError: \(uuid) error: \(error) ")
    }
    open func onSharePieceReadError(uuid: String, piece: Int, error: Int) {
      print("__CAMELCASENAME__Context.onSharePieceReadError: \(uuid) error: \(error) ")
    }
    open func onSharePiecePass(uuid: String, piece: Int) {
      print("__CAMELCASENAME__Context.onSharePiecePass: \(uuid) piece: \(piece) ")
    }
    open func onSharePieceFailed(uuid: String, piece: Int) {
      print("__CAMELCASENAME__Context.onSharePieceFailed: \(uuid) piece: \(piece) ")
    }
    open func onSharePieceRead(uuid: String, piece: Int, offset: Int, size: Int, blockSize: Int, result: Int) {
      print("__CAMELCASENAME__Context.onSharePieceRead: \(uuid) piece: \(piece) size: \(size) ")
    }
    open func onSharePieceWrite(uuid: String, piece: Int, offset: Int, size: Int, blockSize: Int, result: Int) {
      print("__CAMELCASENAME__Context.onSharePieceWrite: \(uuid) piece: \(piece) size: \(size) ")
    }
    open func onSharePieceHashFailed(uuid: String, piece: Int) {
      print("__CAMELCASENAME__Context.onSharePieceHashFailed: \(uuid) piece: \(piece) ")
    }
    open func onShareCheckingFiles(uuid: String) {
      print("__CAMELCASENAME__Context.onShareCheckingFiles: \(uuid) ")
    }
    open func onShareDownloadingMetadata(uuid: String) {
      print("__CAMELCASENAME__Context.onShareDownloadingMetadata: \(uuid) ")
    }
    open func onShareFileRenamed(uuid: String, fileOffset: Int, name: String, error: Int) {
      print("__CAMELCASENAME__Context.onShareFileRenamed: \(uuid) ")
    }
    open func onShareResumed(uuid: String) {
      print("__CAMELCASENAME__Context.onShareResumed: \(uuid) ")
    }
    open func onShareChecked(uuid: String, result: Int) {
      print("__CAMELCASENAME__Context.onShareChecked: \(uuid) result: \(result) ")
    }
    open func onSharePieceComplete(uuid: String, piece: Int) {
      print("__CAMELCASENAME__Context.onSharePieceComplete: \(uuid) piece: \(piece) ")
    }
    open func onShareFileComplete(uuid: String, fileOffset: Int) {
      print("__CAMELCASENAME__Context.onShareFileComplete: \(uuid) file: \(fileOffset) ")
    }
    open func onShareDownloading(uuid: String) {
      print("__CAMELCASENAME__Context.onShareDownloading: \(uuid) ")
    }
    open func onShareComplete(uuid: String) {
      print("__CAMELCASENAME__Context.onTorretComplete: \(uuid) ")
    } 
    open func onShareSeeding(uuid: String) {
      print("__CAMELCASENAME__Context.onShareSeeding: \(uuid) ")
    } 
    open func onSharePaused(uuid: String) {
      print("__CAMELCASENAME__Context.onSharePaused: \(uuid) ")
    }

    // ApplicationInstanceObserver

    public func onApplicationStateChanged(oldState: ApplicationState, newState: ApplicationState) {
      print("__CAMELCASENAME__Context.onApplicationStateChanged")
    }
    public func onBoundsChanged(bounds: IntRect) {
      print("__CAMELCASENAME__Context.onBoundsChanged")
    }
    public func onVisible() {
      print("__CAMELCASENAME__Context.onVisible")
    }
    public func onHidden() {
      print("__CAMELCASENAME__Context.onHidden")
    }
    
    // Page
    public func onFrameAttached(frameId: String, parentFrameId: String) {
      print("__CAMELCASENAME__Context.onFrameAttached")
    }
    public func onDomContentEventFired(timestamp: Int64) {
      print("__CAMELCASENAME__Context.onDomContentEventFired")
    }
    public func onFrameClearedScheduledNavigation(frameId: String) {
      print("__CAMELCASENAME__Context.onFrameClearedScheduledNavigation")
    }
    public func onFrameDetached(frameId: String) {
      print("__CAMELCASENAME__Context.onFrameDetached")
    }
    public func onFrameNavigated(frame: Frame) {
      print("__CAMELCASENAME__Context.onFrameNavigated: frame: \(frame.id) ")
    }
    public func onFrameResized() {
      print("__CAMELCASENAME__Context.onFrameResized")
    }
    public func onFrameScheduledNavigation(frameId: String, delay: Int, reason: NavigationReason, url: String) {
      print("__CAMELCASENAME__Context.onFrameScheduledNavigation")
    }
    public func onFrameStartedLoading(frameId: String) {
      print("__CAMELCASENAME__Context.onFrameStartedLoading: \(frameId) ")
    }
    public func onFrameStoppedLoading(frameId: String) {
      print("__CAMELCASENAME__Context.onFrameStoppedLoading")
    }
    public func onInterstitialHidden() {
      print("__CAMELCASENAME__Context.onInterstitialHidden")
    }
    public func onInterstitialShown() {
      print("__CAMELCASENAME__Context.onInterstitialShown")
    }
    public func onJavascriptDialogClosed(result: Bool, userInput: String) {
      print("__CAMELCASENAME__Context.onJavascriptDialogClosed")
    }
    public func onJavascriptDialogOpening(url: String, message: String, type: DialogType, hasBrowserHandler: Bool, defaultPrompt: String?) {
      print("__CAMELCASENAME__Context.onJavascriptDialogOpening")
    }
    public func onLifecycleEvent(frameId: String, loaderId: Int, name: String, timestamp: TimeTicks) {
      print("__CAMELCASENAME__Context.onLifecycleEvent: frame: \(frameId) name: \(name) timestamp: \(timestamp.microseconds) ")
    }
    public func onLoadEventFired(timestamp: TimeTicks) {
      print("__CAMELCASENAME__Context.onLoadEventFired: timestamp: \(timestamp.microseconds) ")
    }
    public func onNavigatedWithinDocument(frameId: String, url: String) {
      print("__CAMELCASENAME__Context.onNavigatedWithinDocument: frame: \(frameId) url: \(url) ")
    }
    public func onScreencastFrame(base64Data: String, metadata: ScreencastFrameMetadata, sessionId: Int) {
      print("__CAMELCASENAME__Context.onScreencastFrame")
    }
    public func onScreencastVisibilityChanged(visible: Bool) {
      print("__CAMELCASENAME__Context.onScreencastVisibilityChanged")
    }
    public func onWindowOpen(url: String, windowName: String, windowFeatures: [String], userGesture: Bool) {
      print("__CAMELCASENAME__Context.onWindowOpen")
    }
    public func onPageLayoutInvalidated(resized: Bool) {
      print("__CAMELCASENAME__Context.onPageLayoutInvalidated: resized? \(resized) ")
    }
    // Overlay
    public func inspectNodeRequested(backendNode: Int) {
      print("__CAMELCASENAME__Context.inspectNodeRequested")
    }
    public func nodeHighlightRequested(nodeId: Int) {
      print("__CAMELCASENAME__Context.nodeHighlightRequested")
    }
    public func screenshotRequested(viewport: Viewport) {
      print("__CAMELCASENAME__Context.screenshotRequested")
    }
    // worker
    public func workerErrorReported(errorMessage: ServiceWorkerErrorMessage) {
      print("__CAMELCASENAME__Context.workerErrorReported")
    }
    public func workerRegistrationUpdated(registrations: [ServiceWorkerRegistration]) {
      print("__CAMELCASENAME__Context.workerRegistrationUpdated")
    }
    public func workerVersionUpdated(versions: [ServiceWorkerVersion]) {
      print("__CAMELCASENAME__Context.workerVersionUpdated")
    }
    public func onAttachedToTarget(sessionId: String, targetInfo: TargetInfo) {
      print("__CAMELCASENAME__Context.onAttachedToTarget")
    }
    public func onDetachedFromTarget(sessionId: String, targetId: String?) {
      print("__CAMELCASENAME__Context.onDetachedFromTarget")
    }
    public func onReceivedMessageFromTarget(sessionId: String, message: String, targetId: String?) {
      print("__CAMELCASENAME__Context.onReceivedMessageFromTarget")
    }
    // Storage
    public func onCacheStorageContentUpdated(origin: String, cacheName: String) {
      print("__CAMELCASENAME__Context.onCacheStorageContentUpdated")
    }
    public func onCacheStorageListUpdated(origin: String) {
      print("__CAMELCASENAME__Context.onCacheStorageListUpdated")
    }
    public func onIndexedDBContentUpdated(origin: String, databaseName: String, objectStoreName: String) {
      print("__CAMELCASENAME__Context.onIndexedDBContentUpdated")
    }
    public func onIndexedDBListUpdated(origin: String) {
      print("__CAMELCASENAME__Context.onIndexedDBListUpdated")
    }
    // Tethering
    public func onAccepted(port: Int, connectionId: String) {
      print("__CAMELCASENAME__Context.onAccepted")
    }
    // Network
    public func onDataReceived(requestId: String, timestamp: TimeTicks, dataLength: Int64, encodedDataLength: Int64) {
      print("__CAMELCASENAME__Context.onDataReceived")
    }
    public func onEventSourceMessageReceived(requestId: String, timestamp: Int64, eventName: String, eventId: String, data: String) {
      print("__CAMELCASENAME__Context.onEventSourceMessageReceived")
    }
    public func onLoadingFailed(requestId: String, timestamp: Int64, type: ResourceType, errorText: String, canceled: Bool, blockedReason: BlockedReason) {
      print("__CAMELCASENAME__Context.onLoadingFailed")
    }
    public func onLoadingFinished(requestId: String, timestamp: Int64, encodedDataLength: Int64, blockedCrossSiteDocument: Bool) {
      print("__CAMELCASENAME__Context.onLoadingFinished: request: \(requestId) timestamp: \(timestamp) encodedDataLength: \(encodedDataLength) ")
    }
    public func onRequestIntercepted(
      interceptionId: String, 
      request: Request, 
      frameId: String, 
      resourceType: ResourceType, 
      isNavigationRequest: Bool, 
      isDownload: Bool, 
      redirectUrl: String, 
      authChallenge: AuthChallenge, 
      responseErrorReason: ErrorReason, 
      responseStatusCode: Int, 
      responseHeaders: [String: String]) {

      print("__CAMELCASENAME__Context.onRequestIntercepted")
    }
    
    public func onRequestServedFromCache(requestId: String) {
      print("__CAMELCASENAME__Context.onRequestServedFromCache")
    }

    public func onRequestWillBeSent(
      requestId: String, 
      loaderId: String,
      documentUrl: String, 
      request: Request, 
      timestamp: Int64, 
      walltime: Int64, 
      initiator: Initiator, 
      redirectResponse: Response, 
      type: ResourceType, 
      frameId: String?, 
      hasUserGesture: Bool) {

      print("__CAMELCASENAME__Context.onRequestWillBeSent")
    }
    
    public func onResourceChangedPriority(requestId: String, newPriority: ResourcePriority, timestamp: Int64) {
      print("__CAMELCASENAME__Context.onResourceChangedPriority")
    }

    public func onResponseReceived(requestId: String, loaderId: String, timestamp: Int64, type: ResourceType, response: Response, frameId: String?) {
      print("__CAMELCASENAME__Context.onResponseReceived")
    }
    public func onWebSocketClosed(requestId: String, timestamp: Int64) {
      print("__CAMELCASENAME__Context.onWebSocketClosed")
    }
    public func onWebSocketCreated(requestId: String, url: String, initiator: Initiator) {
      print("__CAMELCASENAME__Context.onWebSocketCreated")
    }
    public func onWebSocketFrameError(requestId: String, timestamp: Int64, errorMessage: String) {
      print("__CAMELCASENAME__Context.onWebSocketFrameError")
    }
    public func onWebSocketFrameReceived(requestId: String, timestamp: Int64, response: WebSocketFrame) {
      print("__CAMELCASENAME__Context.onWebSocketFrameReceived")
    }
    public func onWebSocketFrameSent(requestId: String, timestamp: Int64, response: WebSocketFrame) {
      print("__CAMELCASENAME__Context.onWebSocketFrameSent")
    }
    public func onWebSocketHandshakeResponseReceived(requestId: String, timestamp: Int64, response: WebSocketResponse) {
      print("__CAMELCASENAME__Context.onWebSocketHandshakeResponseReceived")
    }
    public func onWebSocketWillSendHandshakeRequest(requestId: String, timestamp: Int64, walltime: Int64, request: WebSocketRequest) {
      print("__CAMELCASENAME__Context.onWebSocketWillSendHandshakeRequest")
    }
    public func flush() {
      print("__CAMELCASENAME__Context.flush")
    }
    // LayerTree
    public func onLayerPainted(layerId: String, clipX: Int, clipY: Int, clipW: Int, clipH: Int) {
      print("__CAMELCASENAME__Context.onLayerPainted")
    }
    public func onLayerTreeDidChange(layers: [Layer]) {
      print("__CAMELCASENAME__Context.onLayerTreeDidChange")
    }
    // Headless
    public func onNeedsBeginFramesChanged(needsBeginFrames: Bool) {
      print("__CAMELCASENAME__Context.onNeedsBeginFramesChanged")
    }
    // DOMStorage
    public func onDomStorageItemAdded(storageId: StorageId, key: String, newValue: String) {
      print("__CAMELCASENAME__Context.onDomStorageItemAdded")
    }

    public func onDomStorageItemRemoved(storageId: StorageId, key: String) {
      print("__CAMELCASENAME__Context.onDomStorageItemRemoved")
    }

    public func onDomStorageItemUpdated(storageId: StorageId, key: String, oldValue: String, newValue: String) {
      print("__CAMELCASENAME__Context.onDomStorageItemUpdated")
    }

    public func onDomStorageItemsCleared(storageId: StorageId) {
      print("__CAMELCASENAME__Context.onDomStorageItemsCleared")
    }

    // Database
    public func onAddDatabase(database: Engine.Database) {
      print("__CAMELCASENAME__Context.onAddDatabase")
    }
    // Emulation
    public func onVirtualTimeAdvanced(virtualTimeElapsed: Int) {
      print("__CAMELCASENAME__Context.onVirtualTimeAdvanced")
    }
    public func onVirtualTimeBudgetExpired() {
      print("__CAMELCASENAME__Context.onVirtualTimeBudgetExpired")
    }
    public func onVirtualTimePaused(virtualTimeElapsed: Int) {
      print("__CAMELCASENAME__Context.onVirtualTimePaused")
    }
    // DOM
    public func setChildNodes(parentId: Int, nodes: [DOMNode]) {
      print("__CAMELCASENAME__Context.setChildNodes")
    }
    public func onAttributeModified(nodeId: Int, name: String, value: String) {
      print("__CAMELCASENAME__Context.onAttributeModified")
    }
    public func onAttributeRemoved(nodeId: Int, name: String) {
      print("__CAMELCASENAME__Context.onAttributeRemoved")
    }
    public func onCharacterDataModified(nodeId: Int, characterData: String) {
      print("__CAMELCASENAME__Context.onCharacterDataModified")
    }
    public func onChildNodeCountUpdated(nodeId: Int, childNodeCount: Int) {
      print("__CAMELCASENAME__Context.onChildNodeCountUpdated")
    }
    public func onChildNodeInserted(parentNodeId: Int, previousNodeId: Int, node: DOMNode) {
      print("__CAMELCASENAME__Context.onChildNodeInserted")
    }
    public func onChildNodeRemoved(parentNodeId: Int, nodeId: Int) {
      print("__CAMELCASENAME__Context.onChildNodeRemoved")
    }
    public func onDistributedNodesUpdated(insertionPointId: Int, distributedNodes: [BackendNode]) {
      print("__CAMELCASENAME__Context.onDistributedNodesUpdated")
    }
    public func onDocumentUpdated() {
      print("__CAMELCASENAME__Context.onDocumentUpdated")
    }
    public func onInlineStyleInvalidated(nodeIds: [Int]) {
      print("__CAMELCASENAME__Context.onInlineStyleInvalidated")
    }
    public func onPseudoElementAdded(parentId: Int, pseudoElement: DOMNode) {
      print("__CAMELCASENAME__Context.onPseudoElementAdded")
    }
    public func onPseudoElementRemoved(parentId: Int, pseudoElementId: Int) {
      print("__CAMELCASENAME__Context.onPseudoElementRemoved")
    }
    public func onShadowRootPopped(hostId: Int, rootId: Int) {
      print("__CAMELCASENAME__Context.onShadowRootPopped")
    }
    public func onShadowRootPushed(hostId: Int, root: DOMNode) {
      print("__CAMELCASENAME__Context.onShadowRootPushed")
    }
    // CSS
    public func onFontsUpdated(font: FontFace) {
      print("__CAMELCASENAME__Context.onFontsUpdated")
    }
    public func onMediaQueryResultChanged() {
      print("__CAMELCASENAME__Context.onMediaQueryResultChanged")
    }
    public func onStyleSheetAdded(header: CSSStyleSheetHeader) {
      print("__CAMELCASENAME__Context.onStyleSheetAdded")
    }
    public func onStyleSheetChanged(styleSheetId: String) {
      print("__CAMELCASENAME__Context.onStyleSheetChanged")
    }
    public func onStyleSheetRemoved(styleSheetId: String) {
      print("__CAMELCASENAME__Context.onStyleSheetRemoved")
    }
    // ApplicationCache
    public func onApplicationCacheStatusUpdated(frameId: String, manifestUrl: String, status: Int) {
      print("__CAMELCASENAME__Context.onApplicationCacheStatusUpdated")
    }
    public func onNetworkStateUpdated(isNowOnline: Bool) {
      print("__CAMELCASENAME__Context.onNetworkStateUpdated")
    }
    // Animation
    public func onAnimationCanceled(id: String) {
      print("__CAMELCASENAME__Context.onAnimationCanceled")
    }
    public func onAnimationCreated(id: String) {
      print("__CAMELCASENAME__Context.onAnimationCreated")
    }
    public func onAnimationStarted(animation: Animation) {
      print("__CAMELCASENAME__Context.onAnimationStarted")
    }

  }

  class __CAMELCASENAME__RouteRequestHandler : RouteRequestHandler {

    public private(set) var id: Int
    public private(set) var url: String
    public var status: Int {
      return 0
    }

    public var responseInfo: String {
      return String()
    }
    
    public var method: String {
      return String("GET")
    }
    
    public var mimeType: String {
      return handler.contentType
    }
    
    public var creationTime: Int64 {
      return created.microseconds
    }
    
    public var totalReceivedBytes: Int64 = 0

    public var rawBodyBytes: Int64 {
      return handler.getRawBodyBytes(url: url)
    }

    public var expectedContentSize: Int64 {
      return handler.getExpectedContentSize(url: url)
    }

    public var responseHeaders: String {
      return handler.getResponseHeaders(url: url) 
    }
    
    private var firstTime: Bool = true
    private var handler: RouteHandler!
    private weak var context: __CAMELCASENAME__Context?
    private var routeRequest: RouteRequest?
    private let created: TimeTicks

    private let doneReadingEvent: WaitableEvent = WaitableEvent(resetPolicy: .manual, initialState: .notSignaled)

    public init(context: __CAMELCASENAME__Context, id: Int, url: String) {
      self.context = context
      self.id = id
      self.url = url
      self.created = TimeTicks.now
  
      self.handler = context.getRouteHandler(url: url)                            
      if self.handler == nil {
        print("no handler for \(url) found")
        return
      }
      let bufferSize = handler.bufferSize
      handler.lastCallId = id
    }

    public func start() -> Int {
      routeRequest = RouteRequest()
      routeRequest!.url = url
      routeRequest!.callId = id
      var result = -99
      let startCompletion = RouteCompletion({
        result = $0
      })
      postTask { [self] in
        self.handler.onResponseStarted(request: routeRequest!, info: RouteResponseInfo(), completion: startCompletion)
      }
      startCompletion.wait()
      return result
    }

    public func followDeferredRedirect() {

    }
    
    public func read(buffer: UnsafeMutableRawPointer?, maxBytes: Int, bytesRead: inout Int) -> Int { 
      var result = -99
      let readCompletion = RouteCompletion({
        result = $0
      })
      postTask { [self] in
        self.handler.read(request: self.routeRequest!, buffer: buffer, maxBytes: maxBytes, completion: readCompletion)
      }
      readCompletion.wait()
      bytesRead = result
      totalReceivedBytes += Int64(bytesRead)
      return bytesRead
    }

    public func cancelWithError(error: Int) -> Int { return 0 }
  }

  @_silgen_name("ApplicationInit")
  public func ApplicationInit() {
    let main = __CAMELCASENAME__Context()
    Engine.initialize(delegate: main)
  }

  @_silgen_name("ApplicationDestroy")
  public func ApplicationDestroy() {
    Engine.destroy()
  }

  @_silgen_name("ApplicationGetClient")
  public func ApplicationGetClient() -> UnsafeMutableRawPointer {
    return Engine.getClient()
  }
)";

const char kDEFAULT_SWIFT_HELLO_APPLICATION[] = R"(
  import Base
  import Graphics
  import UI
  import Web
  import Javascript
  import Platform
  import Compositor
  import Foundation
  import ProtocolBuffers
  import __CAMELCASENAME__Api
  import Channel
  import Net

  public class PageLoader : UrlLoaderClient {

    public var contentEncoding: String = String()
    public var encodedMessageType: String = String()
    private var url: String = String()
    private var totalPayloadSize: Int = 0
    private var currentOffset: Int = 0
    private var inputData: Data?

    public init() {}

    public func shouldHandleResponse(response: WebURLResponse) -> Bool {
      //print("PageLoader.didReceiveResponse: url: \(response.url) status: \(response.httpStatusCode) \(response.httpStatusText) expectedContentLength: \(response.expectedContentLength) ")
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
      print("PageLoader.didSendData: \(bytesSent) ")
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
        let message = try! __CAMELCASENAME__.ChatMessage.Builder().mergeFrom(codedInputStream: CodedInputStream(data: input)).build()
        output.writeOnce(string: message.message!)
        return true
      } else if contentEncoding == "protobuf" && encodedMessageType == "FetchReply" {
        // fixme: temporary hack
        if input.count < pieceSize {
          print("\nDecoding reply 1 of 1. size: \(input.count) ")
          let reply = try! __CAMELCASENAME__.FetchReply.Builder().mergeFrom(codedInputStream: CodedInputStream(data: input)).build()
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
          var replies: [__CAMELCASENAME__.FetchReply] = []
          
          input.withUnsafeBytes {
            var startOffset = 0
            for i in 0..<pieces {
              startOffset = i * pieceSize
              let offsetPtr = UnsafeMutableRawPointer(mutating: $0.baseAddress! + startOffset)
              let size = i == (pieces - 1) && haveRest ? rest : pieceSize
              print("\nDecoding reply \(i+1) of \(pieces). offset: \(startOffset) size: \(size) ")
              let pieceData = Data(bytesNoCopy: offsetPtr, count: size, deallocator: .none)
              let reply = try! __CAMELCASENAME__.FetchReply.Builder().mergeFrom(codedInputStream: CodedInputStream(data: pieceData)).build()
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
      print("PageLoader.didFinishLoading: code: \(errorCode) totalTransferSize: \(totalTransferSize) ")
      //contentEncoding = String()
      //encodedMessageType = String()
    }

    private func reset() {
      inputData = nil
      currentOffset = 0
    }
  }

  public class __CAMELCASENAME__App : UIApplicationDelegate,
                          UIWebWindowDelegate,
                          UIWebFrameObserver {

    public var app: UIApplication?
    public var window: UIWindow? {
      return webWindow
    }
    private var webWindow: UIWebWindow?
    private var rpcChannel: RpcChannel?

    public init() {
      loader = PageLoader()
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
      return webWindow!
    }
    
    public func initializeVisualProperties(params: VisualProperties) {
      webWindow!.initializeVisualProperties(params: params)
    }

    public func onFrameAttached(_ frame: UIWebFrame) {
      frame.addObserver(self)
      frame.urlLoaderDispatcher.addHandler(self.loader)
    }

    public func onPageWasShown(_ window: UIWindow) {
      
    }

    public func onPageWasHidden(_ window: UIWindow) {

    }

    public func onUpdateScreenRects(viewScreen: IntRect, windowScreen: IntRect) {
      
    }

    // UIWebFrameObserver

    public func didInvalidateRect(frame: UIWebFrame, rect: IntRect) {}
    public func didMeaningfulLayout(frame: UIWebFrame, layout: WebMeaningfulLayout) {}
    public func didStartNavigation(frame: UIWebFrame) {}
    public func didStartLoading(frame: UIWebFrame, toDifferentDocument: Bool) {}
    public func didStopLoading(frame: UIWebFrame) {}
    public func didFailProvisionalLoad(frame: UIWebFrame) {}
    public func didChangeScrollOffset(frame: UIWebFrame) {}
    public func onStop(frame: UIWebFrame) {}
    public func frameDetached(frame: UIWebFrame) {
      frame.removeObserver(self)
    }
    public func frameFocused(frame: UIWebFrame) {}
    public func didStartNavigation(frame: UIWebFrame, url: String, type: WebNavigationType?) {}
    public func didCreateNewDocument(frame: UIWebFrame) {}
    public func didCreateDocumentElement(frame: UIWebFrame) {}
    public func didClearWindowObject(frame: UIWebFrame) {}
    public func didFinishDocumentLoad(frame: UIWebFrame) {}
    public func didFinishLoad(frame: UIWebFrame) {}
    public func didFailLoad(frame: UIWebFrame, error: WebURLError) {}
    public func setBackgroundOpaque(opaque: Bool) {}
    public func setActive(active: Bool) {}
    public func didStartLoading() {}
    public func didStopLoading() {}
    public func didHandleOnloadEvents(frame: UIWebFrame) {}
    public func didCreateScriptContext(frame: UIWebFrame, context: JavascriptContext, worldId: Int) {}
    public func willReleaseScriptContext(frame: UIWebFrame, context: JavascriptContext, worldId: Int) {}
    public func readyToCommitNavigation(frame: UIWebFrame, loader: WebDocumentLoader) {}
    public func willCommitProvisionalLoad(frame: UIWebFrame) {}
    public func onWasShown(frame: UIWebFrame) {}
    public func onWasHidden(frame: UIWebFrame) {}
    public func willHandleMouseEvent(event: WebMouseEvent) {}
    public func willHandleGestureEvent(event: WebGestureEvent) {}
    public func willHandleKeyEvent(event: WebKeyboardEvent) {}
    public func didChangeName(frame: UIWebFrame, name: String) {}
    public func didChangeLoadProgress(frame: UIWebFrame, loadProgress: Double) {}
    public func didChangeContents(frame: UIWebFrame) {}
    public func didReceiveResponse(frame: UIWebFrame, response: WebURLResponse) {}
    public func willSendRequest(frame: UIWebFrame, request: WebURLRequest) {}
    public func runScriptsAtDocumentElementAvailable(frame: UIWebFrame) {}
    public func runScriptsAtDocumentReady(frame: UIWebFrame) {}
    public func runScriptsAtDocumentIdle(frame: UIWebFrame) {
      let document = frame.frame!.document
      availableBtn = document.querySelector("#available-button").first
      if self.messageChannel == nil {
        self.messageChannel = MessageChannel(window: frame.frame!.window)
        self.messageChannel!.port1.onMessage({ [self] ev in
          print("__CAMELCASENAME__Main: receive message on port 1")
          //  resolve(event.data)
          var strMessage: String = ev.dataAsString ?? "<null>"
          if let div = self.document.querySelector("#location-div").first {
            div.innerHTML = strMessage
          } else {
            print("#location-div not found. message was '\(strMessage)'")
          }
        })
      }

      if !self.availableBtnClickAdded && availableBtn != nil {
        availableBtn?.addEventListener("click", { [self] ev in
          rpcChannel = RpcChannel(address: "127.0.0.1:8081", secure: false)
          let messageBuilder = __CAMELCASENAME__.ChatMessage.Builder()
          print("button clicked. sending message for app \(String(app!.routingId)) ") 
          messageBuilder.message = String(app!.routingId)
          let message = try! messageBuilder.build()
          let call = try! self.rpcChannel?.makeCall("/__NAME__.__CAMELCASENAME__/Say")
          try! call?.start(.unary,
                          metadata: try! RpcMetadata(),
                          message: message.data()) { callResult in
            if let messageData = callResult.resultData {
              let message = try! __CAMELCASENAME__.ChatMessage.Builder().mergeFrom(codedInputStream: CodedInputStream(data: messageData)).build()
              if let msg = message.message {
                print("'\(msg)'")
              }
            }    
          }
        })
      
      }
    }

    public func focusedNodeChanged(frame: UIWebFrame, node: WebNode?) {}

  }

  let app = __CAMELCASENAME__App()
  app.run()

)";

std::vector<std::string> symlinks = {
  "build",
  "build_overrides",
  "runtime",
  "kit",
  "third_party",
  "tools",
  "core",
  "v8",
  "lib",
  "mumba",
  "buildtools"
};

}

BundleCreator::BundleCreator() {
  
}

BundleCreator::~BundleCreator() {
  
}

bool BundleCreator::InitBundle(const std::string& name, const base::FilePath& path) {
  base::FilePath src_out_path;

  if (name.empty()) {
    DLOG(ERROR) << "error: no project name informed";
    return false;
  }

  if (!path.IsAbsolute()) {
    DLOG(ERROR) << "error: path " << path << " is not absolute";
    return false;
  }

  if (base::PathExists(path)) {
    DLOG(ERROR) << "error: path " << path << " already exists";
    return false;
  }

  std::string name_lower = base::ToLowerASCII(name);
  if (!CreateBaseDirectories(name_lower, path, true, true)) {
    return false;
  }
  base::FilePath app_out_dir = path.AppendASCII(kAPPS_PATH).AppendASCII(kAPP_PATH);
  base::FilePath service_out_dir = path.AppendASCII(kAPPS_PATH).AppendASCII(kSERVICE_PATH);
  base::FilePath resources_out_dir = path.AppendASCII(kRESOURCES_PATH);
  
  if (!base::PathService::Get(base::DIR_SOURCE_ROOT, &src_out_path)) {
    DLOG(ERROR) << "error while getting executable path";
    return false;
  }

  // create a link from the build repository
#if defined(OS_POSIX)
  for (const auto& symlink : symlinks) {
    if (!base::CreateSymbolicLink(src_out_path.AppendASCII(symlink),
                                  path.AppendASCII(symlink))) {
      DLOG(ERROR) << "error while creating build symlink from '" << symlink << "'";
      return false;
    }
  }
#endif  
  
  base::FilePath app_manifest_out_file = app_out_dir.AppendASCII(kBUNDLE_MANIFEST);
  base::FilePath service_manifest_out_file = service_out_dir.AppendASCII(kBUNDLE_MANIFEST);
  base::FilePath resources_manifest_out_file = resources_out_dir.AppendASCII(kBUNDLE_MANIFEST);

  CreateDefaultManifest(name_lower, app_manifest_out_file);
  CreateDefaultManifest(name_lower, service_manifest_out_file);
  CreateDefaultManifest(name_lower, resources_manifest_out_file);
  
  // only swift for now, so..
  // but we need a SwiftProjectCreator : public ProjectCreator {} here
  
  // so this implementation have a proper encapsulation

  if (!CreateDotGNFile(name_lower, path)) {
    return false;
  }

  if (!CreateSwiftMainBuildFile(name_lower, path)) {
    return false;
  }
  
  if (!CreateSwiftServiceBuildFile(name_lower, service_out_dir)) {
    return false;
  }

  if (!CreateSwiftApplicationBuildFile(name_lower, app_out_dir)) {
    return false;
  }

  if (!CreateSwiftProtoBuildFile(name_lower, resources_out_dir.AppendASCII(kPROTO_PATH))) {
    return false;
  }

  if (!CreateSwiftProtoSourceFiles(name_lower, resources_out_dir.AppendASCII(kPROTO_PATH))) {
    return false;
  }

  if (!CreateSwiftApplicationSourceFiles(name_lower, app_out_dir)) {
    return false;
  }

  if (!CreateSwiftServiceSourceFiles(name_lower, service_out_dir)) {
    return false;
  }

  return true;
}

bool BundleCreator::CreateBaseDirectories(const std::string& identifier, const base::FilePath& base_dir, bool no_frontend, bool no_build) {
  base::FilePath bin_path = base_dir.AppendASCII(kBIN_PATH);
  base::FilePath applications_path = base_dir.AppendASCII(kAPPS_PATH);
  base::FilePath application_path = applications_path.AppendASCII(kAPP_PATH);
  base::FilePath service_path = applications_path.AppendASCII(kSERVICE_PATH);
  base::FilePath resources_path = base_dir.AppendASCII(kRESOURCES_PATH);
  base::FilePath proto_path = resources_path.AppendASCII(kPROTO_PATH);
  base::FilePath databases_path = resources_path.AppendASCII(kDATABASES_PATH);
  base::FilePath shares_path = resources_path.AppendASCII(kSHARES_PATH);
  base::FilePath files_path = resources_path.AppendASCII(kFILES_PATH);

  if (!base::CreateDirectory(base_dir)) {
    printf("error while creating temporary directory\n");
    return false;
  }

  if (!no_frontend) {
    if (!base::CreateDirectory(bin_path)) {
      printf("error while creating temporary directory '%s'\n", kBIN_PATH);
      return false;
    }
  }
  if (!base::CreateDirectory(applications_path)) {
    printf("error while creating temporary directory '%s'\n", kAPPS_PATH);
    return false;
  }
  if (!base::CreateDirectory(application_path)) {
    printf("error while creating temporary directory '%s/%s\n", kAPPS_PATH, kAPP_PATH);
    return false;
  }
  if (!base::CreateDirectory(service_path)) {
    printf("error while creating temporary directory '%s/%s'\n", kAPPS_PATH, kSERVICE_PATH);
    return false;
  }
  if (!base::CreateDirectory(resources_path)) {
    printf("error while creating temporary directory '%s'\n", kRESOURCES_PATH);
    return false;
  }
  if (!base::CreateDirectory(proto_path)) {
    printf("error while creating temporary directory '%s/%s'\n", kRESOURCES_PATH, kPROTO_PATH);
    return false;
  }
  if (!base::CreateDirectory(databases_path)) {
    printf("error while creating temporary directory '%s/%s'\n", kRESOURCES_PATH, kDATABASES_PATH);
    return false;
  }
  if (!base::CreateDirectory(shares_path)) {
    printf("error while creating temporary directory '%s/%s'\n", kRESOURCES_PATH, kSHARES_PATH);
    return false;
  }
  if (!base::CreateDirectory(files_path)) {
    printf("error while creating temporary directory '%s/%s'\n", kRESOURCES_PATH, kFILES_PATH);
    return false;
  }
  
  if (!no_build) {
    std::string target_arch = storage::GetIdentifierForHostOS();

    if (!base::CreateDirectory(bin_path.AppendASCII(target_arch))) {
      printf("error while creating temporary directory '%s/%s'\n", kBIN_PATH, target_arch.c_str());
      return false;
    }

    if (!base::CreateDirectory(application_path.AppendASCII(target_arch))) {
      printf("error while creating temporary directory '%s/%s/%s'\n", kAPPS_PATH, kAPP_PATH, target_arch.c_str());
      return false;
    }

    if (!base::CreateDirectory(service_path.AppendASCII(target_arch))) {
      printf("error while creating temporary directory '%s/%s/%s'\n", kAPPS_PATH, kSERVICE_PATH, target_arch.c_str());
      return false;
    }
  }

  return true;
}

bool BundleCreator::PackDirectory(const std::string& name, const base::FilePath& src_path, const base::FilePath& output_dir, bool no_frontend) {
  base::FilePath bundle_out_dir = output_dir.AppendASCII(name);

  if (base::PathExists(bundle_out_dir)) {
    base::DeleteFile(bundle_out_dir, true);
  }

  if (!base::CreateDirectory(bundle_out_dir)) {
    printf("error: failed while creating directory %s\n", bundle_out_dir.value().c_str());
    return false;
  }

  std::string host_os = storage::GetIdentifierForHostOS();

  base::FilePath bin_in_dir = src_path.AppendASCII(kBIN_PATH);
  base::FilePath bin_out_file = bundle_out_dir.AppendASCII(name + "_bin-" + host_os + kAPP_EXT);
  if (base::PathExists(bin_out_file)) {
    base::DeleteFile(bin_out_file, false);
  }

  base::FilePath app_in_dir = src_path.AppendASCII(kAPPS_PATH).AppendASCII(kAPP_PATH);
  base::FilePath app_out_file = bundle_out_dir.AppendASCII(name + "_app-" + host_os + kAPP_EXT);
  if (base::PathExists(app_out_file)) {
    base::DeleteFile(app_out_file, false);
  }

  base::FilePath service_in_dir = src_path.AppendASCII(kAPPS_PATH).AppendASCII(kSERVICE_PATH);
  base::FilePath service_out_file = bundle_out_dir.AppendASCII(name + "_service-" + host_os + kAPP_EXT);
  if (base::PathExists(service_out_file)) {
    base::DeleteFile(service_out_file, false);
  }

  base::FilePath resource_in_dir = src_path.AppendASCII(kRESOURCES_PATH);
  base::FilePath resource_out_file = bundle_out_dir.AppendASCII(name + "_resources" + kAPP_EXT);
  if (base::PathExists(resource_out_file)) {
    base::DeleteFile(resource_out_file, false);
  }

  base::FilePath bundle_out_file = output_dir.AppendASCII(name + kBUNDLE_EXT);
  if (base::PathExists(bundle_out_file)) {
    base::DeleteFile(bundle_out_file, false);
  }

  // special case for the 'world' bundle
  if (!no_frontend) {
    // bin
    if (!BundleUtils::PackPackage(bin_in_dir, bin_out_file)) {
      printf("error: failed while creating %s package\n", bin_out_file.value().c_str());
      return false; 
    }
  }

  // app
  if (!BundleUtils::PackPackage(app_in_dir, app_out_file)) {
    printf("error: failed while creating %s package\n", app_out_file.value().c_str());
    return false; 
  }
  
  // service
  if (!BundleUtils::PackPackage(service_in_dir, service_out_file)) {
    printf("error: failed while creating %s package\n", service_out_file.value().c_str());
    return false; 
  }
  
  // resource
  if (!BundleUtils::PackPackage(resource_in_dir, resource_out_file)) {
    printf("error: failed while creating %s package\n", resource_out_file.value().c_str());
    return false; 
  }
  
  // bundle
  if (!BundleUtils::PackBundle(bundle_out_dir, bundle_out_file)) {
    printf("error: failed while creating bundle\n");
    return false; 
  }
  
  base::FilePath move_bundle_to = bundle_out_dir.AppendASCII(name + kBUNDLE_EXT);
  if (!base::Move(bundle_out_file, move_bundle_to)) {
    printf("error: failed while moving bundle file\n");
    return false;
  }

   // special case for the 'world' bundle
  if (name == kWORLD_BUNDLE) {
    base::FilePath asset_path;
    base::PathService::Get(base::DIR_ASSETS, &asset_path);
    base::CopyFile(move_bundle_to, asset_path.Append(move_bundle_to.BaseName()));
    base::CopyFile(app_out_file, asset_path.Append(app_out_file.BaseName()));
    base::CopyFile(service_out_file, asset_path.Append(service_out_file.BaseName()));
    base::CopyFile(resource_out_file, asset_path.Append(resource_out_file.BaseName()));
  }

  return true; 
}

bool BundleCreator::PackBundle(const std::string& name, const base::FilePath& src, bool no_frontend) {
  base::FilePath home_path;
  base::FilePath binary_out_path;

  if (!base::PathService::Get(base::DIR_HOME, &home_path)) {
    DLOG(ERROR) << "error while getting home path";
    return false;
  }
  
  if (!base::PathService::Get(base::DIR_EXE, &binary_out_path)) {
    DLOG(ERROR) << "error while getting executable path";
    return false;
  }

  if (name.empty()) {
    return false;
  }
  std::string name_lower = base::ToLowerASCII(name);
  
  base::FilePath temp_dir = home_path.AppendASCII("tmp" + base::IntToString(base::RandInt(0, std::numeric_limits<int16_t>::max()))); 
  
  if (!CreateBaseDirectories(name_lower, temp_dir, no_frontend, false)) {
    return false;
  }

  if (!PackCopyFiles(name_lower, src, binary_out_path, temp_dir, no_frontend)) {
    return false;
  }

  base::FilePath mumba_out_dir = home_path.AppendASCII("mumba_out");

  if (!base::PathExists(mumba_out_dir)) {
    base::CreateDirectory(mumba_out_dir);
  }

  if (!PackDirectory(name_lower, temp_dir, mumba_out_dir, no_frontend)) {
    DLOG(ERROR) << "error while creating drop file";
    return false;
  }

  base::DeleteFile(temp_dir, true);
  return true;
}

bool BundleCreator::PackCopyFiles(const std::string& identifier, const base::FilePath& app_base_path, const base::FilePath& input_dir, const base::FilePath& base_dir, bool no_frontend) {
  base::FilePath bin_out_dir = base_dir.AppendASCII(kBIN_PATH);
  base::FilePath app_out_dir = base_dir.AppendASCII(kAPPS_PATH).AppendASCII(kAPP_PATH);
  base::FilePath service_out_dir = base_dir.AppendASCII(kAPPS_PATH).AppendASCII(kSERVICE_PATH);
  base::FilePath resources_out_dir = base_dir.AppendASCII(kRESOURCES_PATH);
  base::FilePath schema_out_dir = resources_out_dir.AppendASCII(kPROTO_PATH);
  
  base::FilePath bin_out_file = bin_out_dir.AppendASCII(storage::GetIdentifierForHostOS()).AppendASCII(identifier);

  base::FilePath service_out_file = service_out_dir.Append(storage::GetPathForArchitecture(identifier + "_service", storage::GetHostArchitecture(), storage_proto::LIBRARY));
  base::FilePath app_out_file = app_out_dir.Append(storage::GetPathForArchitecture(identifier + "_app", storage::GetHostArchitecture(), storage_proto::PROGRAM));
  base::FilePath schema_out_file = schema_out_dir.AppendASCII(identifier + ".proto");

  base::FilePath bin_in_file = input_dir.AppendASCII(identifier);
  base::FilePath service_in_file = input_dir.Append(storage::GetFilePathForArchitecture(identifier + "_service", storage::GetHostArchitecture(), storage_proto::LIBRARY));
  base::FilePath app_in_file = input_dir.Append(storage::GetFilePathForArchitecture(identifier + "_app", storage::GetHostArchitecture(), storage_proto::PROGRAM));
  
  std::string camel_case_identifier = std::string(base::ToUpperASCII(identifier[0]) + identifier.substr(1));
  
  base::FilePath schema_in_file = app_base_path.AppendASCII(kRESOURCES_PATH).
                                                AppendASCII(kPROTO_PATH).
                                                AppendASCII("Sources").
                                                AppendASCII("Api").
                                                AppendASCII(camel_case_identifier + ".proto");

  base::FilePath app_manifest_in_file = app_base_path.AppendASCII(kAPP_PATH).AppendASCII(kBUNDLE_MANIFEST);
  base::FilePath service_manifest_in_file = app_base_path.AppendASCII(kSERVICE_PATH).AppendASCII(kBUNDLE_MANIFEST);
  base::FilePath resources_manifest_in_file = app_base_path.AppendASCII(kRESOURCES_PATH).AppendASCII(kBUNDLE_MANIFEST);
  
  base::FilePath bin_manifest_out_file = bin_out_dir.AppendASCII(kBUNDLE_MANIFEST);
  base::FilePath app_manifest_out_file = app_out_dir.AppendASCII(kBUNDLE_MANIFEST);
  base::FilePath service_manifest_out_file = service_out_dir.AppendASCII(kBUNDLE_MANIFEST);
  base::FilePath resources_manifest_out_file = resources_out_dir.AppendASCII(kBUNDLE_MANIFEST);

  if (!no_frontend) {
    if (!base::CopyFile(bin_in_file, bin_out_file)) {
      printf("error while copying %s file\n", bin_in_file.value().c_str());
      return false;
    }
  }

  if (!base::CopyFile(service_in_file, service_out_file)) {
    printf("error while copying %s files\n", service_in_file.value().c_str());
    return false;
  }

  if (!base::CopyFile(app_in_file, app_out_file)) {
    printf("error while copying %s files\n", app_in_file.value().c_str());
    return false;
  }

  for (size_t i = 0; i < libraries.size(); ++i) {
    base::FilePath in_lib_file = input_dir.AppendASCII(libraries[i]);
    base::FilePath out_lib_file = app_out_dir.AppendASCII(storage::GetIdentifierForHostOS()).AppendASCII(libraries[i]);
    if (!base::CopyFile(in_lib_file, out_lib_file)) {
      printf("error while copying %s files\n", in_lib_file.value().c_str());
      return false;
    }
  }

  if (!base::CopyFile(schema_in_file, schema_out_file)) {
    printf("error while copying schema files from %s to %s\n", schema_in_file.value().c_str(), schema_out_file.value().c_str());
    return false;
  }

  base::FilePath resource_files = app_base_path.AppendASCII(kRESOURCES_PATH).AppendASCII(kFILES_PATH); 
  base::FilePath resource_files_out = resources_out_dir;
  
  if (!base::CopyDirectory(
        resource_files,
        resource_files_out,
        true)) {
    printf("error while copying %s\n", resource_files.value().c_str());
    return false;
  }

  base::FilePath resource_databases = app_base_path.AppendASCII(kRESOURCES_PATH).AppendASCII(kDATABASES_PATH);
  base::FilePath resource_databases_out = resources_out_dir;
  
  if (!base::CopyDirectory(
        resource_databases,
        resource_databases_out,
        true)) {
    printf("error while copying %s\n", resource_databases.value().c_str());
    return false;
  }

  base::FilePath resource_shares = app_base_path.AppendASCII(kRESOURCES_PATH).AppendASCII(kSHARES_PATH);
  base::FilePath resource_shares_out = resources_out_dir;
  
  if (!base::CopyDirectory(
        resource_shares,
        resource_shares_out,
        true)) {
    printf("error while copying %s\n", resource_shares.value().c_str());
    return false;
  }

  if (!no_frontend) {
    if (!CreateDefaultManifest(identifier, bin_manifest_out_file)) {
      return false;
    }
  }

  if (!base::CopyFile(app_manifest_in_file, app_manifest_out_file)) {
    printf("error while copying manifest file\n");
    return false;
  }

  if (!base::CopyFile(service_manifest_in_file, service_manifest_out_file)) {
    printf("error while copying manifest file\n");
    return false;
  }

  if (!base::CopyFile(resources_manifest_in_file, resources_manifest_out_file)) {
    printf("error while copying manifest file\n");
    return false;
  }

#if defined(OS_POSIX)
  int current_perm = 0;
  if (!base::GetPosixFilePermissions(service_out_file, &current_perm)) {
    printf("error while getting file permission for %s\n", service_out_file.value().c_str());
    return false;
  }
  current_perm = current_perm | 
    base::FILE_PERMISSION_EXECUTE_BY_USER |
    base::FILE_PERMISSION_EXECUTE_BY_GROUP |
    base::FILE_PERMISSION_EXECUTE_BY_OTHERS;
  if (!base::SetPosixFilePermissions(service_out_file, current_perm)) {
    printf("error while setting file permission for %s\n", service_out_file.value().c_str());
    return false;
  }

  if (!base::GetPosixFilePermissions(app_out_file, &current_perm)) {
    printf("error while getting file permission for %s\n", app_out_file.value().c_str());
    return false;
  }
  
  current_perm = current_perm | 
    base::FILE_PERMISSION_EXECUTE_BY_USER |
    base::FILE_PERMISSION_EXECUTE_BY_GROUP |
    base::FILE_PERMISSION_EXECUTE_BY_OTHERS;
  
  if (!base::SetPosixFilePermissions(app_out_file, current_perm)) {
    printf("error while setting file permission for %s\n", app_out_file.value().c_str());
    return false;
  }

#endif

  return true;
}

bool BundleCreator::CreateDotGNFile(const std::string& name, const base::FilePath& path) {
  std::string dot_gn_data(kDEFAULT_DOTGN_FILE);
  base::FilePath dotgn_file = path.AppendASCII(".gn");
  int wrote_len = base::WriteFile(dotgn_file, dot_gn_data.data(), dot_gn_data.size());
  if (wrote_len != static_cast<int>(dot_gn_data.size())) {
    printf("error while creating .gn file\n");
    return false;
  }
  return true;
}

bool BundleCreator::CreateDefaultManifest(const std::string& name, const base::FilePath& path) {
  std::string bin_manifest_data(kDEFAULT_BIN_MANIFEST);
  bin_manifest_data = Replace(bin_manifest_data, "__NAME__", name);
  int wrote_len = base::WriteFile(path, bin_manifest_data.data(), bin_manifest_data.size());
  if (wrote_len != static_cast<int>(bin_manifest_data.size())) {
    printf("error while creating bin manifest file\n");
    return false;
  }
  return true;
}

bool BundleCreator::CreateSwiftMainBuildFile(const std::string& name_lower, const base::FilePath& path) {
  std::string build_manifest_data(kDEFAULT_SWIFT_MAIN_BUILD_FILE);
  std::string name_camel = base::ToUpperASCII(name_lower[0]) + name_lower.substr(1);
  build_manifest_data = Replace(build_manifest_data, "__NAME__", name_lower);
  build_manifest_data = Replace(build_manifest_data, "__CAMELCASENAME__", name_camel);
  
  base::FilePath build_file = path.AppendASCII(kBUILD_FILE);
  int wrote_len = base::WriteFile(build_file, build_manifest_data.data(), build_manifest_data.size());
  if (wrote_len != static_cast<int>(build_manifest_data.size())) {
    printf("error while creating build file\n");
    return false;
  }
  return true;
}

bool BundleCreator::CreateSwiftServiceBuildFile(const std::string& name_lower, const base::FilePath& path) {
  std::string build_manifest_data(kDEFAULT_SWIFT_SERVICE_BUILD_FILE);
  std::string name_camel = base::ToUpperASCII(name_lower[0]) + name_lower.substr(1);
  build_manifest_data = Replace(build_manifest_data, "__NAME__", name_lower);
  build_manifest_data = Replace(build_manifest_data, "__CAMELCASENAME__", name_camel);
  
  base::FilePath build_file = path.AppendASCII(kBUILD_FILE);
  int wrote_len = base::WriteFile(build_file, build_manifest_data.data(), build_manifest_data.size());
  if (wrote_len != static_cast<int>(build_manifest_data.size())) {
    printf("error while creating build file\n");
    return false;
  }
  return true;
}

bool BundleCreator::CreateSwiftApplicationBuildFile(const std::string& name_lower, const base::FilePath& path) {
  std::string build_manifest_data(kDEFAULT_SWIFT_APPLICATION_BUILD_FILE);
  std::string name_camel = base::ToUpperASCII(name_lower[0]) + name_lower.substr(1);
  build_manifest_data = Replace(build_manifest_data, "__NAME__", name_lower);
  build_manifest_data = Replace(build_manifest_data, "__CAMELCASENAME__", name_camel);

  base::FilePath build_file = path.AppendASCII(kBUILD_FILE);
  int wrote_len = base::WriteFile(build_file, build_manifest_data.data(), build_manifest_data.size());
  if (wrote_len != static_cast<int>(build_manifest_data.size())) {
    printf("error while creating build file\n");
    return false;
  }
  return true;
}

bool BundleCreator::CreateSwiftProtoBuildFile(const std::string& name_lower, const base::FilePath& path) {
  std::string build_manifest_data(kDEFAULT_SWIFT_PROTO_BUILD_FILE);
  std::string name_camel = base::ToUpperASCII(name_lower[0]) + name_lower.substr(1);
  build_manifest_data = Replace(build_manifest_data, "__NAME__", name_lower);
  build_manifest_data = Replace(build_manifest_data, "__CAMELCASENAME__", name_camel);

  base::FilePath build_file = path.AppendASCII(kBUILD_FILE);
  int wrote_len = base::WriteFile(build_file, build_manifest_data.data(), build_manifest_data.size());
  if (wrote_len != static_cast<int>(build_manifest_data.size())) {
    printf("error while creating build file\n");
    return false;
  }
  return true;
}

bool BundleCreator::CreateSwiftProtoSourceFiles(const std::string& name, const base::FilePath& path) {
  base::FilePath sources = path.AppendASCII("Sources");
  base::FilePath api = sources.AppendASCII("Api");

  if (!base::CreateDirectory(sources)) {
    return false;
  }

  if (!base::CreateDirectory(api)) {
    return false;
  }

  std::string name_camel = base::ToUpperASCII(name[0]) + name.substr(1);

  std::string schema_data(kDEFAULT_SWIFT_HELLO_PROTO);
  schema_data = Replace(schema_data, "__NAME__", name);
  schema_data = Replace(schema_data, "__CAMELCASENAME__", name_camel);

  base::FilePath schema_out_file = api.AppendASCII(name_camel + ".proto");
  int wrote_len = base::WriteFile(schema_out_file, schema_data.data(), schema_data.size());
  if (wrote_len != static_cast<int>(schema_data.size())) {
    printf("error while creating schema file\n");
    return false;
  }
  return true;
}

bool BundleCreator::CreateSwiftApplicationSourceFiles(const std::string& name, const base::FilePath& path) {
  base::FilePath sources = path.AppendASCII("Sources");
  
  if (!base::CreateDirectory(sources)) {
    return false;
  }

  std::string name_camel = base::ToUpperASCII(name[0]) + name.substr(1);

  std::string app_data(kDEFAULT_SWIFT_HELLO_APPLICATION);
  app_data = Replace(app_data, "__NAME__", name);
  app_data = Replace(app_data, "__CAMELCASENAME__", name_camel);

  base::FilePath app_out_file = sources.AppendASCII(name_camel + "App.proto");
  int wrote_len = base::WriteFile(app_out_file, app_data.data(), app_data.size());
  if (wrote_len != static_cast<int>(app_data.size())) {
    printf("error while creating app file\n");
    return false;
  }
  return true;
}

bool BundleCreator::CreateSwiftServiceSourceFiles(const std::string& name, const base::FilePath& path) {
  base::FilePath sources = path.AppendASCII("Sources");
  
  if (!base::CreateDirectory(sources)) {
    return false;
  }

  std::string name_camel = base::ToUpperASCII(name[0]) + name.substr(1);

  std::string handler_data(kDEFAULT_SWIFT_HELLO_SERVICE_HANDLER);
  handler_data = Replace(handler_data, "__NAME__", name);
  handler_data = Replace(handler_data, "__CAMELCASENAME__", name_camel);

  std::string context_data(kDEFAULT_SWIFT_HELLO_SERVICE_CONTEXT);
  context_data = Replace(context_data, "__NAME__", name);
  context_data = Replace(context_data, "__CAMELCASENAME__", name_camel);

  base::FilePath handler_out_file = sources.AppendASCII(name_camel + "Context.swift");
  int wrote_len = base::WriteFile(handler_out_file, handler_data.data(), handler_data.size());
  if (wrote_len != static_cast<int>(handler_data.size())) {
    printf("error while creating service handler file\n");
    return false;
  }

  base::FilePath context_out_file = sources.AppendASCII(name_camel + "Handler.swift");
  wrote_len = base::WriteFile(context_out_file, context_data.data(), context_data.size());
  if (wrote_len != static_cast<int>(context_data.size())) {
    printf("error while creating service context file\n");
    return false;
  }

  return true;
}

std::string BundleCreator::Replace(const std::string& input, const std::string& source, const std::string& target) const {
  std::string output(input);
  size_t offset = output.find(source);
  while (offset != std::string::npos) {
    output = output.replace(offset, source.size(), target);
    offset = output.find(source);
  }
  return output;
}

}